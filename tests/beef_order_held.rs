//! A BEEF is valid whatever its order on the wire (bsv-rs#240, the keeper's
//! re-reading of 2026-10-26 on the owner's north star: a user moving between
//! the SDKs sees one verdict). A transaction is valid when every input names
//! a transaction of the BEEF or a proven txid, wherever it is written: the
//! stack's precedent, the atomic rule read on the graph and never on wire
//! position (the owner's ruling of 2026-10-22).
//!
//! The whole-BEEF path (`Beef::verify_structure`, `verify_valid`) sorts
//! before judging, as the reference's `Beef.verifyValid` does
//! (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts:1054-1073`,
//! `sortTxs` at `:1065`, `:1352-1406`). The stream (`verify_stream`,
//! `verify_stream_structure`) holds a child read ahead of its parent and
//! folds it in when the parent is in, refusing at the end only what is
//! still unresolved: `InputNamesNoElement` at the earliest held
//! transaction's earliest input that names nothing. One verdict across the
//! three readers, and the reference's on the same bytes
//! (`tests/vectors/beef_order_240.json`, recorded by
//! `tests/support/beef_order_240.mjs`).
//!
//! BRC-62 at `5119a9b` keeps the order on the writer's side
//! (`transactions/0062.md:43`, the order has streaming validation in mind;
//! `:72-74`, a transaction's inputs above it; `:172-191`, the validation
//! process): this crate's writer still writes parents before children, and
//! a BEEF so written holds nothing for a parent. The stream's holding is
//! under no bound: a valid BEEF is never refused for its size or its counts
//! (the stack's charter, `bsv-stack-lean docs/charters/beef-of-any-size.md`),
//! so a reversed BEEF of any size is judged as a parents-first one is.
//!
//! Through 0.9.0-beta.1 (bsv-rs#86) the three readers refused a child
//! written ahead of its parent (`InputNamesNoElement` at its input); 0.8's
//! `verify_valid` sorted and accepted it. This file was PR #243's pin of
//! that refusal; it pins the acceptance now.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;
use std::io::Read;

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput, TxOutput,
};
use bsv_rs::primitives::{sha256d, to_hex, PrivateKey, Writer};
use bsv_rs::transaction::beef_stream::SpendRefusal;
use bsv_rs::transaction::{
    verify_stream, verify_stream_async, verify_stream_structure, AsyncByteSource, Beef, BeefTx,
    Cursor, Kind, MerklePath, MockChainTracker, Progress, Reason, StreamVerifier, Timed,
    Transaction, Verdict, ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};

#[path = "support/beef_chain.rs"]
mod beef_chain;

use beef_chain::Hash32;

/// The txid in display order.
fn display(hash: &Hash32) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}

/// The parent (the deep chain's funding transaction) and the child that
/// spends its output 0 with an empty unlock of an `OP_TRUE` lock.
fn parent_and_child() -> (Vec<u8>, Vec<u8>) {
    let parent = beef_chain::funding();
    let child = beef_chain::spend(&sha256d(&parent), 1);
    (parent, child)
}

/// The funding transaction's BUMP, built by this crate: a one-transaction
/// block at the chain's height.
fn funding_bump() -> MerklePath {
    MerklePath::from_coinbase_txid(
        &display(&beef_chain::funding_root()),
        beef_chain::HEIGHT as u32,
    )
}

/// The headers: the funding transaction's root (its txid, the block of one)
/// at the height.
fn headers() -> HashMap<u64, Hash32> {
    HashMap::from([(beef_chain::HEIGHT, beef_chain::funding_root())])
}

/// The roots every accepted witness carries.
fn roots() -> Vec<(u64, Hash32)> {
    vec![(beef_chain::HEIGHT, beef_chain::funding_root())]
}

/// `raw` entries, in the order given, under the funding BUMP, written by
/// this crate's writer without its sort (`to_writer`): an entry is proven
/// when it is the funding transaction.
fn written(version: u32, raws: &[Vec<u8>]) -> Vec<u8> {
    let mut beef = Beef::with_version(version);
    beef.bumps.push(funding_bump());
    for raw in raws {
        let proven = sha256d(raw) == beef_chain::funding_root();
        beef.txs
            .push(BeefTx::from_raw_tx(raw.clone(), proven.then_some(0)));
    }
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    writer.into_bytes()
}

/// The same entries merged children-first into a `Beef`, written by
/// `to_binary`, which sorts: BRC-62's order.
fn brc62_order(version: u32) -> Vec<u8> {
    let (parent, child) = parent_and_child();
    let mut beef = Beef::with_version(version);
    let bump = beef.merge_bump(funding_bump());
    beef.merge_raw_tx(child, None);
    beef.merge_raw_tx(parent, Some(bump));
    beef.to_binary()
}

/// The child written ahead of its parent.
fn children_first(version: u32) -> Vec<u8> {
    let (parent, child) = parent_and_child();
    written(version, &[child, parent])
}

/// The chain of `n` links (the funding transaction and `n - 1` spends),
/// newest first.
fn chain_raws(n: usize) -> Vec<Vec<u8>> {
    let mut raws = vec![beef_chain::funding()];
    for _ in 1..n {
        let prev = sha256d(raws.last().unwrap());
        raws.push(beef_chain::spend(&prev, 1));
    }
    raws.reverse();
    raws
}

/// The chain of `n` links written newest first, the proven funding
/// transaction last.
fn reversed_chain(n: usize) -> Vec<u8> {
    written(BEEF_V2, &chain_raws(n))
}

/// The same under the Atomic prefix, its subject the newest link.
fn atomic_reversed_chain(n: usize) -> Vec<u8> {
    let mut bytes = ATOMIC_BEEF.to_le_bytes().to_vec();
    bytes.extend_from_slice(&beef_chain::subject(n));
    bytes.extend(reversed_chain(n));
    bytes
}

/// A stranger: a txid no entry of the witnesses carries.
const STRANGER: Hash32 = [0x5c; 32];

/// The child spending the funding output 0 and `STRANGER:0`.
fn child_with_a_stranger() -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.push(2);
    for prev in [beef_chain::funding_root(), STRANGER] {
        v.extend_from_slice(&prev);
        v.extend_from_slice(&0u32.to_le_bytes());
        v.push(0);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.push(1);
    v.extend_from_slice(&beef_chain::SATS.to_le_bytes());
    v.extend_from_slice(&[1, 0x51]);
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// That child written ahead of its parent: the parent arrives, the stranger
/// never does.
fn a_stranger_children_first() -> Vec<u8> {
    written(BEEF_V2, &[child_with_a_stranger(), beef_chain::funding()])
}

/// The stream offset of `raw`'s input `vin` in `bytes` (inputs with empty
/// unlocks: 41 bytes each, after the version and the one-byte count).
fn input_at(bytes: &[u8], raw: &[u8], vin: usize) -> u64 {
    let at = bytes
        .windows(raw.len())
        .position(|w| w == raw)
        .expect("the entry's bytes are in the BEEF");
    (at + 4 + 1 + 41 * vin) as u64
}

/// What the three readers say of `bytes`: the stream with its spend checks,
/// the stream on the structure, `verify_structure` and `verify_valid`.
struct Readers {
    stream: Verdict,
    structure: Verdict,
    whole: Result<(), Kind>,
    valid: bool,
}

fn read(bytes: &[u8]) -> Readers {
    let mut beef = Beef::from_binary(bytes).expect("the frame parses");
    let whole = beef.verify_structure().map(|_| ());
    let mut beef = Beef::from_binary(bytes).unwrap();
    Readers {
        stream: verify_stream(bytes, headers(), None).unwrap(),
        structure: verify_stream_structure(bytes, headers(), None).unwrap(),
        whole,
        valid: beef.verify_valid(false).valid,
    }
}

fn assert_valid(bytes: &[u8], subject: Option<Hash32>, what: &str) {
    let readers = read(bytes);
    let valid = Verdict::Valid {
        subject,
        roots: roots(),
    };
    assert_eq!(readers.stream, valid, "verify_stream: {what}");
    assert_eq!(readers.structure, valid, "verify_stream_structure: {what}");
    assert_eq!(readers.whole, Ok(()), "verify_structure: {what}");
    assert!(readers.valid, "verify_valid: {what}");
}

#[test]
fn the_writer_still_puts_the_parent_ahead_of_the_child_whatever_the_merge_order() {
    for version in [BEEF_V1, BEEF_V2] {
        let sorted = brc62_order(version);
        let held = children_first(version);
        assert_eq!(sorted.len(), held.len(), "the same entries");
        let (parent, child) = parent_and_child();
        let find = |bytes: &[u8], raw: &[u8]| {
            bytes
                .windows(raw.len())
                .position(|w| w == raw)
                .expect("the entry")
        };
        assert!(find(&sorted, &parent) < find(&sorted, &child));
        assert!(find(&held, &child) < find(&held, &parent));
    }
}

#[test]
fn a_beef_in_brc62_order_passes_the_three_readers_and_holds_nothing() {
    for version in [BEEF_V1, BEEF_V2] {
        let bytes = brc62_order(version);
        assert_valid(&bytes, None, &format!("version {version:#x}"));
        // Nothing is held at any step.
        let mut reader = StreamVerifier::new(bytes.as_slice(), headers(), None);
        while let Progress::Stepped = reader.step().unwrap() {
            assert_eq!(reader.index().deferred().0, 0);
        }
    }
}

/// RED on 0.9.0-beta.1: the three readers refused the child's input,
/// `InputNamesNoElement`; the reference sorts and accepts it.
#[test]
fn a_child_written_ahead_of_its_parent_is_valid_on_the_three_readers() {
    for version in [BEEF_V1, BEEF_V2] {
        assert_valid(
            &children_first(version),
            None,
            &format!("version {version:#x}"),
        );
    }
}

/// RED on 0.9.0-beta.1 at the newest link's input. Linear: the held chain
/// unwinds one link per step once the funding transaction arrives, the whole path's
/// sort is the work list of `sort_txs`.
#[test]
fn a_chain_written_newest_first_is_valid_on_the_three_readers() {
    for n in [2, 3, 40, 1_000] {
        assert_valid(&reversed_chain(n), None, &format!("chain of {n}"));
    }
    let n = 40;
    assert_valid(
        &atomic_reversed_chain(n),
        Some(beef_chain::subject(n)),
        "atomic chain of 40",
    );
}

/// The input that names nothing is refused at the end, by the three, with
/// the same kind; the stream names the stranger's input, not the parent's
/// (RED on 0.9.0-beta.1: the stream named input 0, the parent not yet read).
#[test]
fn an_input_naming_nothing_is_refused_at_the_end_by_the_three_readers() {
    let bytes = a_stranger_children_first();
    let refusal = Verdict::Invalid {
        offset: input_at(&bytes, &child_with_a_stranger(), 1),
        kind: Kind::InputNamesNoElement,
        reason: Reason::InputNamesNoElement { txid: STRANGER },
    };
    let readers = read(&bytes);
    assert_eq!(readers.stream, refusal, "verify_stream");
    assert_eq!(readers.structure, refusal, "verify_stream_structure");
    assert_eq!(
        readers.whole,
        Err(Kind::InputNamesNoElement),
        "verify_structure"
    );
    assert!(!readers.valid, "verify_valid");
}

/// A later refusal is the stream's own: what is held is judged at the end,
/// so a bad element after a held child is refused at its bytes, by the
/// stream and by the whole path alike (a raw transaction with no output).
#[test]
fn a_refusal_after_a_held_child_is_the_later_elements() {
    let (parent, child) = parent_and_child();
    let mut no_output = beef_chain::spend(&sha256d(&parent), 1);
    // The output count 0, the output gone: 4 + 1 + 41 bytes, then the count.
    no_output.truncate(46);
    no_output.push(0);
    no_output.extend_from_slice(&0u32.to_le_bytes());
    let bytes = written(BEEF_V2, &[child, parent, no_output.clone()]);
    let at = bytes
        .windows(no_output.len())
        .position(|w| w == no_output.as_slice())
        .unwrap() as u64;
    let readers = read(&bytes);
    for (verdict, what) in [(readers.stream, "stream"), (readers.structure, "structure")] {
        assert_eq!(
            verdict,
            Verdict::Invalid {
                offset: at,
                kind: Kind::NoOutputs,
                reason: Reason::NoOutputs,
            },
            "{what}"
        );
    }
    assert_eq!(readers.whole, Err(Kind::NoOutputs));
}

/// No bound (the charter: a valid BEEF is never refused for its size or its
/// counts): a chain of 2,000 newest first holds every unproven link until
/// the funding transaction arrives, 1,999 at the peak, and is judged, on
/// both modes of the stream, never declined (RED on the base `df6fb8a`:
/// `InputNamesNoElement` at the newest link's input; on `66eb2cc` a bound
/// the caller set declined it as an `io::Error`).
#[test]
fn a_reversed_beef_is_judged_whatever_its_size() {
    let n = 2_000;
    let bytes = reversed_chain(n);
    for structure in [false, true] {
        let mut reader = if structure {
            StreamVerifier::structure_only(bytes.as_slice(), headers(), None)
        } else {
            StreamVerifier::new(bytes.as_slice(), headers(), None)
        };
        let mut peak = 0;
        let verdict = loop {
            match reader.step().expect("never declined") {
                Progress::Stepped => peak = peak.max(reader.index().deferred().0),
                Progress::Verdict(verdict) => break verdict,
            }
        };
        assert_eq!(peak, n as u64 - 1, "structure {structure}");
        assert_eq!(
            verdict,
            Verdict::Valid {
                subject: None,
                roots: roots()
            },
            "structure {structure}"
        );
    }
}

/// A link spending both outputs of `prev` with empty unlocks, paying two
/// `OP_TRUE` outputs of the chain's value each: one input after another, so
/// the caller's budget is asked between its two scripts.
fn spend_both(prev: &Hash32) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.push(2);
    for vout in 0u32..2 {
        v.extend_from_slice(prev);
        v.extend_from_slice(&vout.to_le_bytes());
        v.push(0);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.push(2);
    for _ in 0..2 {
        v.extend_from_slice(&beef_chain::SATS.to_le_bytes());
        v.extend_from_slice(&[1, 0x51]);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// The funding transaction (two outputs) and `n - 1` links of two inputs,
/// newest first.
fn reversed_two_input_chain(n: usize) -> Vec<u8> {
    let mut raws = vec![beef_chain::funding()];
    for _ in 1..n {
        let prev = sha256d(raws.last().unwrap());
        raws.push(spend_both(&prev));
    }
    raws.reverse();
    written(BEEF_V2, &raws)
}

/// The review's fold (bsv-rs#240): the funding transaction, written last,
/// releases the whole chain, and the reader folds the released links one per
/// step, each under the caller's budget, a released link's own child
/// released the same way. A chain of 1,000 newest first: the budget is
/// asked inside at least the 999 released links, at most once per step (one
/// link's two scripts); under a budget spent at every ask the reading pauses
/// inside every released link, a cursor taken at a pause resumes it, and the
/// verdict is the reading's without a budget. RED on `6f52634` (the funding
/// transaction's step ran the 999 links' scripts with the budget asked 0
/// times).
#[test]
fn a_released_child_is_folded_one_per_step_under_the_callers_budget() {
    let n = 1_000;
    let bytes = reversed_two_input_chain(n);
    let valid = Verdict::Valid {
        subject: None,
        roots: roots(),
    };
    assert_eq!(
        verify_stream(bytes.as_slice(), headers(), None).unwrap(),
        valid
    );

    // A budget never spent, its asks counted per step.
    let mut reader = StreamVerifier::new(bytes.as_slice(), headers(), None);
    let (mut asks, mut most, mut steps) = (0usize, 0usize, 0usize);
    let verdict = loop {
        let mut here = 0usize;
        let timed = reader
            .step_until(&mut || {
                here += 1;
                false
            })
            .unwrap();
        asks += here;
        most = most.max(here);
        steps += 1;
        match timed {
            Timed::Progress(Progress::Verdict(verdict)) => break verdict,
            Timed::Progress(Progress::Stepped) => {}
            Timed::Paused => panic!("a budget never spent paused"),
        }
    };
    assert_eq!(verdict, valid);
    assert!(asks >= n - 1, "the budget was asked {asks} times");
    assert_eq!(most, 1, "one released link's two scripts per step");
    // The BUMP, n entries read, n - 1 links released, the verdict.
    assert_eq!(steps, 1 + n + (n - 1) + 1);

    // A budget spent at every ask: a pause inside every released link; every
    // hundredth pause through a cursor's bytes.
    let mut reader = StreamVerifier::new(bytes.as_slice(), headers(), None);
    let mut pauses = 0usize;
    let verdict = loop {
        match reader.step_until(&mut || true).unwrap() {
            Timed::Progress(Progress::Verdict(verdict)) => break verdict,
            Timed::Progress(Progress::Stepped) => {}
            Timed::Paused => {
                pauses += 1;
                if pauses.is_multiple_of(100) {
                    let cursor = reader.cursor();
                    assert_eq!(cursor.input_reached(), Some(1));
                    assert!(cursor.offset() as usize == bytes.len());
                    let decoded = Cursor::from_binary(&cursor.to_binary()).unwrap();
                    assert_eq!(decoded, cursor);
                    let rest = &bytes[decoded.offset() as usize..];
                    reader = StreamVerifier::resume(decoded, rest, headers());
                }
            }
        }
    };
    assert_eq!(verdict, valid);
    assert_eq!(pauses, n - 1);
}

/// A cursor taken while children are held carries them (BSC4) and resumes
/// to the verdict of the whole; a BEEF in BRC-62's order keeps BSC3.
#[test]
fn a_cursor_carries_the_held_children_and_resumes() {
    let n = 20;
    let bytes = reversed_chain(n);
    for k in [1u64, 2, 10, 20] {
        let mut reader = StreamVerifier::new(bytes.as_slice(), headers(), None);
        for _ in 0..k {
            assert_eq!(reader.step().unwrap(), Progress::Stepped);
        }
        let cursor = reader.cursor();
        let held = cursor.index().deferred().0;
        let encoded = cursor.to_binary();
        let magic: &[u8] = if k == 1 { b"BSC3" } else { b"BSC4" };
        assert_eq!(&encoded[..4], magic, "k = {k}");
        let decoded = Cursor::from_binary(&encoded).expect("the cursor reads back");
        assert_eq!(decoded, cursor, "k = {k}");
        assert_eq!(held, k - 1, "the BUMP, then k - 1 links held");
        let rest = &bytes[decoded.offset() as usize..];
        let verdict = StreamVerifier::resume(decoded, rest, headers())
            .run()
            .unwrap();
        assert_eq!(
            verdict,
            Verdict::Valid {
                subject: None,
                roots: roots()
            },
            "k = {k}"
        );
    }
    let mut ordered = Vec::new();
    beef_chain::ChainSource::new(n)
        .read_to_end(&mut ordered)
        .unwrap();
    let mut reader = StreamVerifier::new(ordered.as_slice(), headers(), None);
    for _ in 0..10 {
        reader.step().unwrap();
    }
    assert_eq!(&reader.cursor().to_binary()[..4], b"BSC3");
}

// ---------------------------------------------------------------------------
// A held child by its index entry, its signatures checked on release
// ---------------------------------------------------------------------------

/// The key every output of the signed family pays to (`<pubkey> OP_CHECKSIG`).
fn family_key() -> PrivateKey {
    PrivateKey::from_bytes(&[0x24; 32]).unwrap()
}

fn p2pk() -> Vec<u8> {
    let mut lock = vec![33];
    lock.extend_from_slice(&family_key().public_key().to_compressed());
    lock.push(0xac);
    lock
}

/// A raw transaction of `inputs` (outpoint, unlock) and `outputs` at
/// `version`, every sequence final, lock time 0.
fn raw_tx(version: i32, inputs: &[(Hash32, u32, Vec<u8>)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_i32_le(version);
    w.write_var_int(inputs.len() as u64);
    for (prev, vout, unlock) in inputs {
        w.write_bytes(prev);
        w.write_u32_le(*vout);
        w.write_var_bytes(unlock);
        w.write_u32_le(u32::MAX);
    }
    w.write_var_int(outputs.len() as u64);
    for (satoshis, script) in outputs {
        w.write_u64_le(*satoshis);
        w.write_var_bytes(script);
    }
    w.write_u32_le(0);
    w.into_bytes()
}

/// The transaction at `version` spending `spent` (each a parent's txid, vout
/// and value, a P2PK output of the family key) into `outputs`, input `i`
/// signed under hash type `types[i]` over the digest the interpreter
/// dispatches to (the original digest for the CHRONICLE bit).
fn signed(
    version: i32,
    spent: &[(Hash32, u32, u64)],
    types: &[u32],
    outputs: &[(u64, Vec<u8>)],
) -> Vec<u8> {
    let inputs: Vec<TxInput> = spent
        .iter()
        .map(|(txid, vout, _)| TxInput {
            txid: *txid,
            output_index: *vout,
            script: Vec::new(),
            sequence: u32::MAX,
        })
        .collect();
    let tx_outputs: Vec<TxOutput> = outputs
        .iter()
        .map(|(satoshis, script)| TxOutput {
            satoshis: *satoshis,
            script: script.clone(),
        })
        .collect();
    let lock = p2pk();
    let unlocks: Vec<(Hash32, u32, Vec<u8>)> = spent
        .iter()
        .enumerate()
        .map(|(i, (txid, vout, satoshis))| {
            let digest = compute_sighash_dispatched_for_signing(&SighashParams {
                version,
                inputs: &inputs,
                outputs: &tx_outputs,
                locktime: 0,
                input_index: i,
                subscript: &lock,
                satoshis: *satoshis,
                scope: types[i],
            });
            let mut sig = family_key().sign(&digest).unwrap().to_der();
            sig.push(types[i] as u8);
            let mut unlock = vec![sig.len() as u8];
            unlock.extend_from_slice(&sig);
            (*txid, *vout, unlock)
        })
        .collect();
    raw_tx(version, &unlocks, outputs)
}

/// The signed family: the proven funding `F` (three P2PK outputs, version
/// 1), the child `C` spending them under ALL|FORKID, SINGLE|FORKID and
/// ALL|CHRONICLE|FORKID (the original digest, over every output, a data
/// output among them), the grandchild `G` spending `C:0` under
/// NONE|CHRONICLE|FORKID and `C:1` under ALL|ANYONECANPAY|FORKID, `C` and
/// `G` at `version`. The CHRONICLE bit is legal in the default mode at a
/// version above 1 only (#397, the reference's `#isAfterChronicle()`,
/// `ts-stack@edf6e03` `Spend.ts:338-341`, `:586-591`), so the family that
/// verifies is written at version 2, where the dispatch to the original
/// digest (bsv-rs#22) is still what its signatures are made over. With
/// `tamper`, the last byte of `C`'s CHRONICLE signature's `s` is flipped.
fn signed_family(tamper: bool, version: i32) -> [Vec<u8>; 3] {
    let f = raw_tx(
        1,
        &[([0xBB; 32], 0, Vec::new())],
        &[(1_000, p2pk()), (1_000, p2pk()), (1_000, p2pk())],
    );
    let f_id = sha256d(&f);
    let mut data = vec![0x00, 0x6a, 0x4c, 200];
    data.extend_from_slice(&[0xD7; 200]);
    let mut c = signed(
        version,
        &[(f_id, 0, 1_000), (f_id, 1, 1_000), (f_id, 2, 1_000)],
        &[0x41, 0x43, 0x61],
        &[(900, p2pk()), (900, p2pk()), (0, data)],
    );
    if tamper {
        // The third input's unlock is the last push before the outputs: its
        // signature ends one byte (the hash type) before the sequence.
        let outputs_at = c.len() - 4 - 1 - 2 * (8 + 1 + 35) - (8 + 3 + 204);
        c[outputs_at - 4 - 2] ^= 0x01;
    }
    let c_id = sha256d(&c);
    let g = signed(
        version,
        &[(c_id, 0, 900), (c_id, 1, 900)],
        &[0x62, 0xC1],
        &[(1_500, p2pk())],
    );
    [f, c, g]
}

/// `raws` (the funding transaction proven by a one-transaction block) as a
/// V2 BEEF in the order given, and the headers that carry its root.
fn family_beef(raws: &[&Vec<u8>]) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let funding = raws.iter().find(|r| r.len() < 200).unwrap();
    let root = sha256d(funding);
    let mut beef = Beef::with_version(BEEF_V2);
    beef.bumps.push(MerklePath::from_coinbase_txid(
        &display(&root),
        beef_chain::HEIGHT as u32,
    ));
    for raw in raws {
        let proven = sha256d(raw) == root;
        beef.txs
            .push(BeefTx::from_raw_tx((*raw).clone(), proven.then_some(0)));
    }
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    (
        writer.into_bytes(),
        HashMap::from([(beef_chain::HEIGHT, root)]),
    )
}

/// A child held for its parent is held by its index entry (bsv-rs#240): per
/// input the outpoint, the sequence and the unlocking script, the version,
/// the lock time and the outputs, never its raw bytes. Released, its
/// signatures verify against the digests they were made over: BIP-143 from
/// the midstates (ALL, SINGLE, ANYONECANPAY, NONE) and the original digest
/// a CHRONICLE-bit signature dispatches to, which hashes every output after
/// the scriptCode the parent supplies (the family at version 2, where the
/// default mode admits the bit, #397). The verdict newest first is the
/// verdict parents first, valid and with one signature broken; a cursor
/// taken while both are held carries their entries (no transaction's bytes
/// are in it) and resumes to the same verdict. RED on `10dd8c5` (the cursor
/// carried each held transaction's raw bytes) and on the base `df6fb8a`
/// (`InputNamesNoElement` newest first).
#[test]
fn a_held_child_is_held_by_its_index_entry_and_its_signatures_verify_on_release() {
    for tamper in [false, true] {
        let [f, c, g] = signed_family(tamper, 2);
        let (ordered, headers) = family_beef(&[&f, &c, &g]);
        let (reversed, _) = family_beef(&[&g, &c, &f]);
        let expected = verify_stream(ordered.as_slice(), &headers, None).unwrap();
        let named = |v: &Verdict| match v {
            Verdict::SpendRefused {
                txid, input, why, ..
            } => Some((*txid, *input, why.clone())),
            _ => None,
        };
        if tamper {
            assert_eq!(
                named(&expected).map(|(txid, input, _)| (txid, input)),
                Some((sha256d(&c), Some(2))),
                "{expected:?}"
            );
        } else {
            assert!(expected.is_valid(), "{expected:?}");
        }
        let got = verify_stream(reversed.as_slice(), &headers, None).unwrap();
        assert_eq!(got.is_valid(), expected.is_valid(), "tamper {tamper}");
        assert_eq!(named(&got), named(&expected), "tamper {tamper}");
        assert!(
            verify_stream_structure(reversed.as_slice(), &headers, None)
                .unwrap()
                .is_valid(),
            "tamper {tamper}"
        );

        let mut reader = StreamVerifier::new(reversed.as_slice(), &headers, None);
        for _ in 0..3 {
            assert_eq!(reader.step().unwrap(), Progress::Stepped);
        }
        assert_eq!(reader.index().deferred().0, 2, "G and C held");
        let encoded = reader.cursor().to_binary();
        assert_eq!(&encoded[..4], b"BSC4");
        for raw in [&g, &c] {
            assert!(
                !encoded.windows(raw.len()).any(|w| w == raw.as_slice()),
                "the cursor carries a held transaction's bytes"
            );
        }
        let decoded = Cursor::from_binary(&encoded).unwrap();
        assert_eq!(decoded, reader.cursor());
        let rest = &reversed[decoded.offset() as usize..];
        let resumed = StreamVerifier::resume(decoded, rest, &headers)
            .run()
            .unwrap();
        assert_eq!(named(&resumed), named(&got), "tamper {tamper}");
        assert_eq!(resumed.is_valid(), got.is_valid(), "tamper {tamper}");
    }
}

/// The signed family at version 1: the CHRONICLE bit is illegal at version 1
/// in the default mode (#397), as the reference's default `Spend` refuses it
/// (`ts-stack@edf6e03` `Spend.ts:338-341`, `#isAfterChronicle()` false at
/// version 1 without flags; `:586-591`, the gate's words, rethrown at
/// `:622-625` as the DER wrapper's) on the `Transaction.verify` path
/// (`Transaction.ts:1441-1455`, `transactionVersion: tx.version`): `C`
/// refused at its input 2 (ALL|CHRONICLE|FORKID) in the reference's visible
/// words, parents first and newest first; `Transaction::verify` of `C` the
/// same at its input 2, and of the version-2 family `Ok(true)`. The
/// reference's answers on these bytes under Node 22.18.0 (`edf6e03` built
/// with bun): `verifyValid` true for both versions (it runs no script),
/// `Transaction.verify('scripts only')` of `C` and of `G` at version 1
/// `Script evaluation error: The signature format is invalid.`, at version 2
/// `true`. RED on the base `bfdd4e7f` (the family valid there).
#[test]
fn a_chronicle_bit_signature_in_a_version_1_family_is_refused_at_its_input_in_the_reference_words()
{
    let [f, c, g] = signed_family(false, 1);
    let (ordered, headers) = family_beef(&[&f, &c, &g]);
    let (reversed, _) = family_beef(&[&g, &c, &f]);
    for (bytes, order) in [(&ordered, "parents first"), (&reversed, "newest first")] {
        let verdict = verify_stream(bytes.as_slice(), &headers, None).unwrap();
        match verdict {
            Verdict::SpendRefused {
                txid, input, why, ..
            } => {
                assert_eq!((txid, input), (sha256d(&c), Some(2)), "{order}");
                assert_eq!(
                    why,
                    SpendRefusal::Script("The signature format is invalid.".to_string()),
                    "{order}"
                );
            }
            other => panic!("{order}: {other:?}"),
        }
    }
    let verify = |version: i32| {
        let [f, c, g] = signed_family(false, version);
        let (bytes, _) = family_beef(&[&f, &c, &g]);
        let tx = Transaction::from_beef(&bytes, Some(&display(&sha256d(&c)))).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(tx.verify(
                &MockChainTracker::always_valid(beef_chain::HEIGHT as u32),
                None,
                None,
            ))
    };
    let refused = verify(1).unwrap_err().to_string();
    assert!(
        refused.contains("input 2") && refused.contains("The signature format is invalid."),
        "{refused}"
    );
    assert_eq!(verify(2), Ok(true));
}

/// Rule 5 on the held entries a cursor carries: every proper prefix of a
/// BSC4 cursor holding the signed child and grandchild is refused, and every
/// single-byte change is refused or read, never a panic, and a cursor so
/// read resumes to a verdict, never a panic.
#[test]
fn a_cut_or_changed_bsc4_cursor_is_refused_or_read_never_a_panic() {
    let [f, c, g] = signed_family(false, 2);
    let (reversed, headers) = family_beef(&[&g, &c, &f]);
    let mut reader = StreamVerifier::new(reversed.as_slice(), &headers, None);
    for _ in 0..3 {
        reader.step().unwrap();
    }
    let encoded = reader.cursor().to_binary();
    assert_eq!(&encoded[..4], b"BSC4");
    for cut in 0..encoded.len() {
        assert!(
            Cursor::from_binary(&encoded[..cut]).is_err(),
            "a prefix of {cut} bytes read as a cursor"
        );
    }
    let mut read = 0;
    for at in 0..encoded.len() {
        for bit in [0x01u8] {
            let mut changed = encoded.clone();
            changed[at] ^= bit;
            let Ok(cursor) = Cursor::from_binary(&changed) else {
                continue;
            };
            read += 1;
            let Some(rest) = reversed.get(cursor.offset() as usize..) else {
                continue;
            };
            let _ = StreamVerifier::resume(cursor, rest, &headers).run();
        }
    }
    assert!(read > 0, "some change reads as a cursor");
}

// ---------------------------------------------------------------------------
// The reference's verdicts
// ---------------------------------------------------------------------------

/// The witnesses by name, as this crate's writer builds them.
fn witnesses() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("brc62_order_v1", brc62_order(BEEF_V1)),
        ("brc62_order_v2", brc62_order(BEEF_V2)),
        ("children_first_v1", children_first(BEEF_V1)),
        ("children_first_v2", children_first(BEEF_V2)),
        ("reversed_chain_40", reversed_chain(40)),
        ("atomic_reversed_chain_40", atomic_reversed_chain(40)),
        ("a_stranger_children_first", a_stranger_children_first()),
    ]
}

/// `BEEF_ORDER_240_PRINT=1` prints the witnesses' hex, the input of
/// `tests/support/beef_order_240.mjs`.
#[test]
fn the_three_readers_give_the_references_verdict_on_every_witness() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/beef_order_240.json"
    );
    let file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let recorded: HashMap<String, (String, bool)> = file["witnesses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| {
            (
                w["name"].as_str().unwrap().to_string(),
                (
                    w["hex"].as_str().unwrap().to_string(),
                    w["reference_valid"].as_bool().unwrap(),
                ),
            )
        })
        .collect();
    let witnesses = witnesses();
    if std::env::var("BEEF_ORDER_240_PRINT").is_ok() {
        for (name, bytes) in &witnesses {
            println!("{name} {}", to_hex(bytes));
        }
    }
    assert_eq!(recorded.len(), witnesses.len(), "one record per witness");
    for (name, bytes) in witnesses {
        let (hex, reference) = &recorded[name];
        assert_eq!(
            *hex,
            to_hex(&bytes),
            "{name}: the writer's bytes are the recorded ones"
        );
        let readers = read(&bytes);
        assert_eq!(
            readers.stream.is_valid(),
            *reference,
            "{name}: verify_stream"
        );
        assert_eq!(
            readers.structure.is_valid(),
            *reference,
            "{name}: structure"
        );
        assert_eq!(
            readers.whole.is_ok(),
            *reference,
            "{name}: verify_structure"
        );
        assert_eq!(readers.valid, *reference, "{name}: verify_valid");
    }
}

// ---------------------------------------------------------------------------
// The asynchronous reader
// ---------------------------------------------------------------------------

struct Chunks {
    bytes: Vec<u8>,
    at: usize,
    size: usize,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + self.size).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

/// A child whose finality needs the mining tip (lock time 1, sequence 0),
/// written ahead of its proven parent. The asynchronous reader asks the
/// tracker for the tip for an unproven element in hand; the child is
/// released by the parent, a proven element, so the tip is asked for the
/// transactions held as well (without it the child's spends ran with no tip:
/// `Unverifiable`, finality).
#[tokio::test]
async fn the_asynchronous_reader_gives_a_released_child_the_mining_tip() {
    let (parent, mut child) = parent_and_child();
    child[42..46].copy_from_slice(&0u32.to_le_bytes());
    let end = child.len();
    child[end - 4..].copy_from_slice(&1u32.to_le_bytes());
    let bytes = written(BEEF_V2, &[child, parent]);
    let mut tracker = MockChainTracker::new(900_000);
    tracker.add_root(
        beef_chain::HEIGHT as u32,
        display(&beef_chain::funding_root()),
    );
    let expected = verify_stream(bytes.as_slice(), &tracker, None).unwrap();
    assert_eq!(
        expected,
        Verdict::Valid {
            subject: None,
            roots: roots()
        }
    );
    for size in [1, 7, 4096] {
        let mut source = Chunks {
            bytes: bytes.clone(),
            at: 0,
            size,
        };
        let got = verify_stream_async(&mut source, &tracker, None)
            .await
            .unwrap();
        assert_eq!(got, expected, "chunks of {size}");
    }
}
