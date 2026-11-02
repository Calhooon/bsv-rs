//! #603, shard S4 of `src/transaction/beef_stream.rs`: the judge and the
//! remainder. Each test kills surviving mutants of the widened run
//! (`docs/census/mutants-2026-11-01.md`) from a rule and a vector the sibling
//! definitions state: the rows of bsv-script-lean@5dc337e1 `corpus/wire`
//! (`beef.jsonl`, `atomic-beef.jsonl`) with the reference's answers on them
//! (`tests/vectors/beef_reference_603.json`, the `s4_*` cases, recorded by
//! `tests/support/beef_reference_603.mjs` from `@bsv/sdk` at ts-stack@edf6e03
//! under Node 22), and the rows of bsv-stack-lean@5df1e0a3
//! `lean/BeefOfAnySize/Scenarios.lean` (the streaming reader's Lean).
//!
//! Every test names the mutants it kills. `atomic_unreached`'s `<` to `<=` is
//! declared equivalent in `.cargo/mutants.toml` on three reads, and its `<`
//! to `==` is killed on every seed (the seed fold of #645); the constant
//! `CHUNK`'s `*` to `+` is a stated survivor (a read size no rule or document
//! states, an internal parameter a pin would freeze: its test went under the
//! keeper's ruling of 2026-11-02). `Judge::check_named_subject`'s `||` to
//! `&&`, the lane's other candidate, is killed by the last test (the review
//! of #645). The two kills of `BeefIndex::note_raw` are crate-contract pins,
//! no sibling rule, stated (their test names the public line it pins).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::cell::Cell;
use std::collections::HashMap;
use std::io::Read;

use bsv_rs::primitives::{from_hex, sha256d};
use bsv_rs::transaction::beef_stream::{
    display_hex, AsyncByteSource, AsyncVerifyError, ChainTip, Hash32, HeadersFn, Reason,
    StreamError,
};
use bsv_rs::transaction::{
    referenced_outpoints, verify_stream_async, verify_stream_structure, BeefStream, ChainTracker,
    ChainTrackerError, Element, Kind, Progress, StreamVerifier, Timed, Verdict,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// The recording
// ---------------------------------------------------------------------------

fn recording() -> Value {
    serde_json::from_str(include_str!("vectors/beef_reference_603.json")).unwrap()
}

/// A row of the sibling's wire corpus, by id, as the recorder copied it.
fn row(id: &str) -> Vec<u8> {
    from_hex(recording()["rows"][id]["hex"].as_str().unwrap()).unwrap()
}

fn case(name: &str) -> Value {
    recording()["cases"][name].clone()
}

/// A display txid or root in the stream's wire order.
fn internal(display: &str) -> Hash32 {
    let mut h: Hash32 = from_hex(display).unwrap().try_into().unwrap();
    h.reverse();
    h
}

/// The roots the reference computed for a row's BUMPs, as headers.
fn recorded_headers(id: &str) -> HashMap<u64, Hash32> {
    case("s4_roots_against_the_tracker")["rows"][id]["bumps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                b["block_height"].as_u64().unwrap(),
                internal(b["root"].as_str().unwrap()),
            )
        })
        .collect()
}

fn elements(bytes: &[u8]) -> Vec<Element> {
    BeefStream::new(bytes).map(|e| e.unwrap()).collect()
}

// ---------------------------------------------------------------------------
// BRC-95's subject: the judge (check_named_subject, note_raw, is_valid)
// ---------------------------------------------------------------------------

/// Kills `Judge::check_named_subject` 3036:46 (the guard `named != prefixed`
/// replaced by `true`) and `Verdict::is_valid` 2448:9 (replaced by `true`).
///
/// The rule: BRC-95's subject is the 32 bytes after the prefix
/// (bsv-script-lean@5dc337e1 `lean/BsvChain/Views/Wire/AtomicBEEF.lean:38-42`,
/// `scoped` at :122-126), a raw transaction of the BEEF; a caller naming the
/// same subject asks the same question (bsv-stack-lean@5df1e0a3
/// `lean/BeefOfAnySize.lean:998-1003`: the subject is found, or
/// `subjectMissing` at offset 4). The vector: `atomic-beef-023`
/// (parent-and-child-v2), whose subject the reference's
/// `Transaction.fromAtomicBEEF` finds (`Transaction.ts:302-313`), and
/// `atomic-beef-025` (subject-missing), which it refuses.
#[test]
fn the_named_subject_brc95_wire_atomic_beef_023_and_025() {
    let recorded = case("s4_atomic_subject");
    let subject = internal(recorded["prefix_subject"].as_str().unwrap());
    assert_eq!(recorded["found"]["ok"], recorded["prefix_subject"]);
    let headers = recorded_headers("beef-023");
    let roots: Vec<(u64, Hash32)> = headers.iter().map(|(h, r)| (*h, *r)).collect();

    // The prefix's subject, named again by the caller: the same subject, found.
    let bytes = row("atomic-beef-023");
    for named in [None, Some(subject)] {
        let verdict = verify_stream_structure(bytes.as_slice(), &headers, named).unwrap();
        assert_eq!(
            verdict,
            Verdict::Valid {
                subject: Some(subject),
                roots: roots.clone()
            },
            "named {named:?}"
        );
        assert!(verdict.is_valid());
    }

    // atomic-beef-025: the reference refuses it; so does the stream, at the
    // prefix's 32 bytes, and its verdict is not valid.
    assert!(recorded["missing"]["error"].is_string());
    let missing = internal(recorded["missing_prefix_subject"].as_str().unwrap());
    let verdict =
        verify_stream_structure(row("atomic-beef-025").as_slice(), &headers, None).unwrap();
    assert!(
        matches!(
            verdict,
            Verdict::Invalid {
                offset: 4,
                kind: Kind::SubjectMissing,
                ..
            }
        ),
        "{verdict:?}"
    );
    assert!(!verdict.is_valid());

    // A caller naming another subject than the prefix's: refused at offset 4.
    let verdict = verify_stream_structure(bytes.as_slice(), &headers, Some(missing)).unwrap();
    assert!(
        matches!(
            verdict,
            Verdict::Invalid {
                offset: 4,
                kind: Kind::SubjectMissing,
                ..
            }
        ),
        "{verdict:?}"
    );
}

/// Kills `BeefIndex::note_raw` 2234:9 (replaced by `()`) and 2234:50 (`<=`
/// replaced by `>`), and `Verdict::is_valid` 2448:9.
///
/// The two `note_raw` kills are a crate-contract pin, no sibling rule,
/// stated: a [D] reading of this crate's own word, not a rule of the
/// sibling's or a recording of the reference's. The line pinned is the
/// public one on `Reason::SubjectMissing`
/// (`src/transaction/beef_stream/reason.rs:268-271`, and
/// `src/transaction/CLAUDE.md:21`): "a missing subject is named at the
/// prefix's 32 bytes; without a prefix, at the last raw transaction instead,
/// or at the stream's end when there is none", promoted from
/// `Judge::conclude`'s 0.8.1 comment by #645's fold under the keeper's word
/// of 2026-11-02. The Lean names a missing subject at offset 4 only
/// (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize.lean:1001-1003`, `finish` at
/// :990: `⟨4, .subjectMissing sub⟩` on every arm), and the reference reports
/// no offset. The day a sibling rule or a reference recording names this
/// offset, the pin is re-cited to it (or becomes a divergence row if they
/// disagree) and this paragraph goes.
///
/// The behaviour: without a prefix a missing subject is named at the last raw
/// transaction on the wire, a held one included (`conclude`, `note_raw`).
/// The vector: `beef-023` (parent-and-child-v1, two raw
/// transactions) asked for `atomic-beef-025`'s subject, which the reference's
/// `Transaction.fromBEEF(beef, txid)` does not find (`Transaction.ts:282-285`).
#[test]
fn a_missing_named_subject_is_named_at_the_last_raw_transaction_wire_beef_023() {
    let recorded = case("s4_named_subject_absent");
    assert!(recorded["found"]["error"].is_string());
    let bytes = row("beef-023");
    let raw: Vec<Hash32> = recorded["raw_txids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| internal(t.as_str().unwrap()))
        .collect();
    assert_eq!(raw.len(), 2);
    // The stream's offsets of the two raw transactions, parent then child.
    let offsets: Vec<u64> = elements(&bytes)
        .iter()
        .filter_map(|e| match e {
            Element::Tx { offset, txid, .. } => {
                assert!(raw.contains(txid));
                Some(*offset)
            }
            _ => None,
        })
        .collect();
    assert_eq!(offsets.len(), 2);
    assert!(offsets[0] < offsets[1]);

    let subject = internal(recorded["subject"].as_str().unwrap());
    let verdict = verify_stream_structure(
        bytes.as_slice(),
        recorded_headers("beef-023"),
        Some(subject),
    )
    .unwrap();
    match &verdict {
        Verdict::Invalid { offset, kind, .. } => {
            assert_eq!(*kind, Kind::SubjectMissing);
            assert_eq!(*offset, offsets[1], "the last raw transaction's offset");
        }
        other => panic!("expected SubjectMissing, got {other:?}"),
    }
    assert!(!verdict.is_valid());
}

// ---------------------------------------------------------------------------
// The headers: a function as the headers (HeadersFn::carries)
// ---------------------------------------------------------------------------

/// Kills `<impl Headers for HeadersFn<F>>::carries` 1531:9 (replaced by
/// `true`) and `Verdict::is_valid` 2448:9.
///
/// The rule: a BUMP whose root the headers do not carry is refused at the
/// BUMP (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize/Scenarios.lean:250-259`,
/// `root_not_carried_refused`: ⟨5, rootNotCarried⟩ on a V1 frame). The
/// vector: `beef-023`, which the reference's `Beef.verify` accepts with every
/// root carried and refuses with none (`Beef.ts:1020-1035`).
#[test]
fn a_root_the_function_does_not_carry_is_refused_wire_beef_023() {
    let recorded = &case("s4_roots_against_the_tracker")["rows"]["beef-023"];
    assert_eq!(recorded["carried"], true);
    assert_eq!(recorded["not_carried"], false);
    let headers = recorded_headers("beef-023");
    let bytes = row("beef-023");

    let carried = verify_stream_structure(
        bytes.as_slice(),
        HeadersFn(|h, r: &Hash32| headers.get(&h) == Some(r)),
        None,
    )
    .unwrap();
    assert!(carried.is_valid(), "{carried:?}");

    let refused =
        verify_stream_structure(bytes.as_slice(), HeadersFn(|_, _: &Hash32| false), None).unwrap();
    assert!(
        matches!(
            refused,
            Verdict::Invalid {
                offset: 5,
                kind: Kind::RootNotCarried,
                ..
            }
        ),
        "{refused:?}"
    );
    assert!(!refused.is_valid());
}

// ---------------------------------------------------------------------------
// The first pass: Referenced::is_empty
// ---------------------------------------------------------------------------

/// Kills `Referenced::is_empty` 1782:9 (replaced by `true`).
///
/// The rule: the outpoints a first pass names are the ones the unproven
/// transactions spend (`referenced_outpoints`). The vector: the reference's
/// unproven spends of `beef-023` (one outpoint, the child's input) and of
/// `beef-001` (none: its one transaction is proven).
#[test]
fn the_first_pass_names_the_unproven_spends_wire_beef_023_and_001() {
    let recorded = case("s4_unproven_spends");
    for id in ["beef-023", "beef-001"] {
        let expected = recorded["rows"][id].as_array().unwrap().len();
        let named = referenced_outpoints(row(id).as_slice()).unwrap();
        assert_eq!(named.len(), expected, "{id}");
        assert_eq!(named.is_empty(), expected == 0, "{id}");
    }
}

/// Kills `atomic_unreached` 2348:55 (`<` to `==`) on every seed (the seed
/// fold of #645: at 2348:66 the comparison walked the `HashMap`'s order, and
/// the `==` mutant answered the entry the seed put first, through in 16 of
/// 200 runs).
///
/// The rule: the entry an atomic refusal names is the least of the unreached
/// in the trie order, the txid's bytes with each byte's bits reversed
/// (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize.lean:363-376` `failing`,
/// :381-384 `key`; `src/transaction/CLAUDE.md`'s atomic paragraph). Beside a
/// proven subject, two txid-only entries its BUMP carries and nothing
/// spends: `01 00..` on the wire before `02 00..`. `01` is the earlier by
/// the bytes and by the wire, `02` (bits reversed `40`, against `80`) by the
/// trie order, so a walk that keeps the earliest it takes names `01`.
#[test]
fn the_entry_named_is_the_trie_earliest_not_the_byte_or_wire_earliest_on_every_seed() {
    let subject_raw = raw_tx(&[([0xAA; 32], 0, &[])], &[(1_000, OP_TRUE)]);
    let subject = sha256d(&subject_raw);
    let (mut low, mut high) = ([0u8; 32], [0u8; 32]);
    (low[0], high[0]) = (0x01, 0x02);
    let other = [0x33; 32];
    let trie_order = |txid: &Hash32| txid.map(u8::reverse_bits);
    assert!(low < high && trie_order(&high) < trie_order(&low));
    let pair = |l: &Hash32, r: &Hash32| sha256d(&[l.as_slice(), r.as_slice()].concat());
    let root = pair(&pair(&subject, &low), &pair(&high, &other));
    // One BUMP of height 2: the subject, `low` and `high` as txids at
    // offsets 0 to 2, a hash at 3; nothing at level 1.
    let mut v = 0xEFBE_0002u32.to_le_bytes().to_vec();
    v.push(1);
    v.push(0xFE);
    v.extend_from_slice(&(HEIGHT as u32).to_le_bytes());
    v.extend_from_slice(&[2, 4]);
    for (offset, flag, hash) in [(0, 2, subject), (1, 2, low), (2, 2, high), (3, 0, other)] {
        v.extend_from_slice(&[offset, flag]);
        v.extend_from_slice(&hash);
    }
    v.extend_from_slice(&[0, 3]);
    for txid in [low, high] {
        v.push(2);
        v.extend_from_slice(&txid);
    }
    v.extend_from_slice(&[1, 0]);
    v.extend_from_slice(&subject_raw);
    let offset_of = |wanted: &Hash32| {
        elements(&v)
            .into_iter()
            .find_map(|e| match e {
                Element::TxidOnly { txid, offset } if txid == *wanted => Some(offset),
                _ => None,
            })
            .unwrap()
    };
    assert!(offset_of(&low) < offset_of(&high));
    let headers = HashMap::from([(HEIGHT, root)]);
    assert_eq!(
        verify_stream_structure(v.as_slice(), &headers, Some(subject)).unwrap(),
        Verdict::Invalid {
            offset: offset_of(&high),
            kind: Kind::UnrelatedTransaction,
            reason: Reason::UnrelatedTransaction { txid: high },
        }
    );
}

// ---------------------------------------------------------------------------
// The cost model and the index's size (model_work, entries)
// ---------------------------------------------------------------------------

/// The Lean's `chain n atomic` (bsv-stack-lean@5df1e0a3
/// `lean/BeefOfAnySize/Scenarios.lean:100-136`), as `tests/beef_stream_deep.rs`
/// writes it: an anchor proven by a BUMP of height 1 at 800,000, then `n`
/// links each spending output 0 of the one before.
fn lean_chain(n: usize, atomic: bool) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let varint = |n: u64| -> Vec<u8> {
        if n < 0xFD {
            vec![n as u8]
        } else if n < 0x1_0000 {
            let mut v = vec![0xFD];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        } else {
            let mut v = vec![0xFE];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
    };
    let raw = |prev: &Hash32, n_out: usize| {
        let mut v = 1u32.to_le_bytes().to_vec();
        v.push(1);
        v.extend_from_slice(prev);
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
        v.push(n_out as u8);
        for _ in 0..n_out {
            v.extend_from_slice(&1u64.to_le_bytes());
            v.push(0);
        }
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    };
    let anchor = raw(&[0x2A; 32], 2);
    let anchor_txid = sha256d(&anchor);
    let mut links = Vec::new();
    let mut prev = anchor_txid;
    for _ in 0..n {
        let link = raw(&prev, 1);
        prev = sha256d(&link);
        links.push(link);
    }
    let mut bytes = Vec::new();
    if atomic {
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes());
        bytes.extend_from_slice(&prev);
    }
    bytes.extend_from_slice(&0xEFBE_0001u32.to_le_bytes());
    bytes.push(1);
    bytes.extend(varint(800_000));
    bytes.extend_from_slice(&[1, 2, 0, 2]);
    bytes.extend_from_slice(&anchor_txid);
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend(varint(n as u64 + 1));
    bytes.extend_from_slice(&anchor);
    bytes.extend_from_slice(&[1, 0]);
    for link in &links {
        bytes.extend_from_slice(link);
        bytes.push(0);
    }
    let root = sha256d(&[anchor_txid, anchor_txid].concat());
    (bytes, HashMap::from([(800_000, root)]))
}

/// Kills `BeefIndex::model_work` 1872:9 (replaced by `0` and by `1`) and
/// the index's size beside the Lean's.
///
/// The rule: the Lean's row `#eval summary (run stub chainHeaders (chain
/// 10000 true))` = (10002, 600112, 10002, 740145, 20005, true)
/// (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize/Scenarios.lean:145-150`,
/// under `#guard_msgs`): 740,145 units of work and an index of 20,005
/// entries, which keeps the anchor's txid twice (the BUMP's set and the
/// proven set, :138-141); this index keeps it once, so its `entries` is the
/// Lean's size less one: one BUMP, one proven txid, 10,001 transactions and,
/// under the subject, 10,001 edges.
#[test]
fn the_leans_atomic_chain_row_has_the_leans_work_and_size_bsv_stack_lean_chain_10000() {
    let (bytes, headers) = lean_chain(10_000, true);
    let mut reader = StreamVerifier::structure_only(bytes.as_slice(), &headers, None);
    let verdict = loop {
        if let Progress::Verdict(v) = reader.step().unwrap() {
            break v;
        }
    };
    assert!(verdict.is_valid(), "{verdict:?}");
    let index = reader.index();
    assert_eq!(index.steps(), 10_002);
    assert_eq!(index.model_work(), 740_145);
    assert_eq!(index.spec_size(), 20_005);
    assert_eq!(index.entries(), 20_005 - 1);
}

/// Kills `BeefIndex::entries` 1851:47 (the `+` before `proven_again`
/// replaced by `-`).
///
/// The rule: the Lean's `Index.size` is each BUMP once and once per level-0
/// txid it carries, the transactions, the edges and the proven set
/// (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize.lean:860-861`); `entries` is
/// that count without the proven set's copy and, with no subject, without the
/// edges (kept only under one: `entries`' own statement,
/// `src/transaction/beef_stream.rs:1846-1848`). The vector: the
/// recording's `two_bumps_one_root`, `beef-001` with its BUMP written twice
/// (one txid carried by two BUMPs of one root), which the reference's
/// `verifyValid` accepts (`Beef.ts:1112-1127,1153-1167`): two BUMPs of one
/// leaf each (4), one transaction, one input, one proven txid: the Lean's 7,
/// this index's 5.
#[test]
fn a_txid_two_bumps_carry_is_counted_once_per_bump_wire_beef_001_two_bumps_one_root() {
    let recorded = case("two_bumps_one_root");
    assert_eq!(recorded["row"], "beef-001");
    assert_eq!(recorded["valid"], true);
    let bytes = from_hex(recorded["hex"].as_str().unwrap()).unwrap();
    let headers = recorded_headers("beef-001");
    let mut reader = StreamVerifier::structure_only(bytes.as_slice(), &headers, None);
    let verdict = loop {
        if let Progress::Verdict(v) = reader.step().unwrap() {
            break v;
        }
    };
    assert!(verdict.is_valid(), "{verdict:?}");
    assert_eq!(reader.index().spec_size(), 7);
    assert_eq!(reader.index().entries(), 7 - 1 - 1);
}

// ---------------------------------------------------------------------------
// A paused reading resumed (Judge::start_of)
// ---------------------------------------------------------------------------

const HEIGHT: u64 = 800_000;
const OP_TRUE: u8 = 0x51;
const OP_RETURN: u8 = 0x6A;

/// `tests/beef_stream_pause.rs`'s raw transaction, with an unlocking script
/// per input.
fn raw_tx(inputs: &[(Hash32, u32, &[u8])], outputs: &[(u64, u8)]) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.push(inputs.len() as u8);
    for (prev, vout, unlock) in inputs {
        v.extend_from_slice(prev);
        v.extend_from_slice(&vout.to_le_bytes());
        v.push(unlock.len() as u8);
        v.extend_from_slice(unlock);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.push(outputs.len() as u8);
    for (satoshis, op) in outputs {
        v.extend_from_slice(&satoshis.to_le_bytes());
        v.push(1);
        v.push(*op);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// LOW's shape (`tests/beef_stream_pause.rs`, bsv-low #591) at two inputs: a
/// proven parent with two `OP_TRUE` outputs, then a child spending both, its
/// first unlock `first_unlock`. Returns the BEEF and the headers.
fn two_inputs(first_unlock: &[u8]) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let parent = raw_tx(
        &[([0xAA; 32], 0, &[])],
        &[(1_000, OP_TRUE), (1_000, OP_TRUE)],
    );
    let prev = sha256d(&parent);
    let child = raw_tx(&[(prev, 0, first_unlock), (prev, 1, &[])], &[(1, OP_TRUE)]);
    let mut v = 0xEFBE_0002u32.to_le_bytes().to_vec();
    v.push(1);
    v.push(0xFE);
    v.extend_from_slice(&(HEIGHT as u32).to_le_bytes());
    v.extend_from_slice(&[1, 1, 0, 2]);
    v.extend_from_slice(&prev);
    v.push(2);
    v.extend_from_slice(&[1, 0]);
    v.extend_from_slice(&parent);
    v.push(0);
    v.extend_from_slice(&child);
    (v, HashMap::from([(HEIGHT, prev)]))
}

/// Reads `bytes` until the reading pauses inside the child, after its first
/// input; returns the cursor.
fn paused_after_the_first_input(
    bytes: &[u8],
    headers: &HashMap<u64, Hash32>,
) -> bsv_rs::transaction::Cursor {
    let mut reader = StreamVerifier::new(bytes, headers, None);
    loop {
        match reader.step_until(&mut || true).unwrap() {
            Timed::Paused => break,
            Timed::Progress(Progress::Stepped) => {}
            other => panic!("expected a pause, got {other:?}"),
        }
    }
    let cursor = reader.cursor();
    assert_eq!(cursor.input_reached(), Some(1));
    cursor
}

/// Kills `Judge::start_of` 3013:9 (replaced by `0`), 3015:20 (the guard
/// replaced by `false`), 3015:29 and 3015:50 (an `==` replaced by `!=`).
///
/// The rule: a resumed reading runs the scripts of the transaction it paused
/// in from the input it reached; the inputs already checked never run again
/// (bsv-low #591; the cursor's `input_reached`; the Lean's resume at k gives
/// the reading of the whole, bsv-stack-lean@5df1e0a3
/// `lean/BeefOfAnySize/Scenarios.lean:316-323`). The vector: the two-input
/// shape of `tests/beef_stream_pause.rs`. Resumed under a budget always
/// spent, the reading runs the second input alone and steps (the budget is
/// asked between two inputs only); a reading that ran the first input again
/// would ask the budget and pause.
#[test]
fn a_resumed_reading_runs_from_the_input_reached_bsv_low_591() {
    let (bytes, headers) = two_inputs(&[]);
    let cursor = paused_after_the_first_input(&bytes, &headers);
    let rest = &bytes[cursor.offset() as usize..];
    let mut reader = StreamVerifier::resume(cursor, rest, &headers);
    let asked = Cell::new(0u32);
    let mut spent = || {
        asked.set(asked.get() + 1);
        true
    };
    assert_eq!(
        reader.step_until(&mut spent).unwrap(),
        Timed::Progress(Progress::Stepped)
    );
    assert_eq!(asked.get(), 0, "the first input ran again");
    assert_eq!(reader.cursor().input_reached(), None);
    let verdict = loop {
        if let Timed::Progress(Progress::Verdict(v)) = reader.step_until(&mut spent).unwrap() {
            break v;
        }
    };
    assert!(verdict.is_valid(), "{verdict:?}");
}

/// Kills `Judge::start_of` 3015:40 (`&&` replaced by `||`), 3015:20 (the
/// guard replaced by `true`) and 3015:50 (`==` replaced by `!=`).
///
/// The rule: the cursor names the transaction it paused in by offset and
/// txid; a source that carries another transaction at that offset is a new
/// transaction, its every input run (the cursor's `Pending`; the inputs
/// skipped are the ones of the transaction the reading checked, bsv-low
/// #591). The vector: the cursor paused in the two-input child, resumed over
/// a source whose child at the same offset has a first unlock of `OP_RETURN`
/// (not push-only: SIGPUSHONLY after Genesis, bsv-script-lean@5dc337e1
/// `lean/BsvScript/Flags.lean:159-164`; this crate's default mode holds the
/// unlocking script push-only always).
#[test]
fn a_resumed_source_carrying_another_transaction_runs_every_input_bsv_low_591() {
    let (bytes, headers) = two_inputs(&[]);
    let cursor = paused_after_the_first_input(&bytes, &headers);
    let (other, _) = two_inputs(&[OP_RETURN]);
    assert_eq!(
        bytes[..cursor.offset() as usize],
        other[..cursor.offset() as usize]
    );
    // The same source as a whole: the other child's first input is refused.
    let whole = bsv_rs::transaction::verify_stream(other.as_slice(), &headers, None).unwrap();
    assert!(
        matches!(whole, Verdict::SpendRefused { input: Some(0), .. }),
        "{whole:?}"
    );
    // Resumed over it from the cursor of the first child: the same verdict.
    let rest = &other[cursor.offset() as usize..];
    let verdict = StreamVerifier::resume(cursor, rest, &headers)
        .run()
        .unwrap();
    assert!(
        matches!(verdict, Verdict::SpendRefused { input: Some(0), .. }),
        "{verdict:?}"
    );
    assert!(!verdict.is_valid());
}

// ---------------------------------------------------------------------------
// The asynchronous reader: the tip asked for an unproven spend only
// ---------------------------------------------------------------------------

struct Chunks {
    bytes: Vec<u8>,
    at: usize,
    size: usize,
    fail: bool,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.fail {
            return Err(std::io::Error::other("the source is gone"));
        }
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + self.size).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

fn chunks(bytes: Vec<u8>) -> Chunks {
    Chunks {
        bytes,
        at: 0,
        size: 64,
        fail: false,
    }
}

/// The reference's tracker of the `s4_roots_against_the_tracker` recording:
/// it answers roots (or fails them), and a height or tip read fails.
struct RootsOnly {
    roots: HashMap<u64, Hash32>,
    fail_roots: bool,
}

#[async_trait::async_trait]
impl ChainTracker for RootsOnly {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        if self.fail_roots {
            return Err(ChainTrackerError::NetworkError("no header".into()));
        }
        Ok(self
            .roots
            .get(&u64::from(height))
            .is_some_and(|h| display_hex(h) == root))
    }
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "the height is not read".into(),
        ))
    }
    async fn mining_tip(&self) -> Result<Option<ChainTip>, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "the tip is not read".into(),
        ))
    }
}

/// Kills `AsyncStreamVerifier::run` 3483:29 (`&&` replaced by `||`).
///
/// The rule: the mining tip is context for checking an unproven spend in the
/// next block (bsv-script-lean@87f0461 `docs/BLOCK-CONSENSUS.md:83-88`, cited
/// at `Headers`); a BEEF of proven transactions asks the tracker for its
/// roots and nothing else, as the reference's `Beef.verify` does
/// (`Beef.ts:1020-1035`: the recording's tracker fails a height read and
/// `beef-001` verifies). The vector: `beef-001` (mainnet, one proven
/// transaction) under a tracker whose tip read fails.
#[tokio::test]
async fn a_proven_beef_never_asks_the_tip_wire_beef_001() {
    let recorded = &case("s4_roots_against_the_tracker")["rows"]["beef-001"];
    assert_eq!(recorded["carried"], true);
    let tracker = RootsOnly {
        roots: recorded_headers("beef-001"),
        fail_roots: false,
    };
    let verdict = verify_stream_async(&mut chunks(row("beef-001")), &tracker, None)
        .await
        .unwrap();
    assert!(verdict.is_valid(), "{verdict:?}");
}

// ---------------------------------------------------------------------------
// The two error texts (Display)
// ---------------------------------------------------------------------------

/// Kills `<impl fmt::Display for AsyncVerifyError>::fmt` 3383:9 (replaced by
/// `Ok(Default::default())`): the text names which of the two failed, and
/// the failure.
#[tokio::test]
async fn the_asynchronous_failures_say_which_failed_wire_beef_001() {
    let tracker = RootsOnly {
        roots: recorded_headers("beef-001"),
        fail_roots: true,
    };
    let err = verify_stream_async(&mut chunks(row("beef-001")), &tracker, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AsyncVerifyError::Headers(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "the header lookup failed: network error: no header"
    );

    let mut source = chunks(row("beef-001"));
    source.fail = true;
    let err = verify_stream_async(&mut source, &tracker, None)
        .await
        .unwrap_err();
    assert!(matches!(err, AsyncVerifyError::Source(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "the BEEF source failed: the source is gone"
    );
}

struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("the source is gone"))
    }
}

/// Kills `<impl fmt::Display for StreamError>::fmt` 1356:9 (replaced by
/// `Ok(Default::default())`): a source's failure says so; a refusal reads as
/// the refusal. The vector for the refusal: `beef-031` (truncated), which
/// the reference's reader refuses too (`s4_truncated`).
#[test]
fn the_stream_failures_say_what_stopped_the_stream_wire_beef_031() {
    let err = BeefStream::new(Failing).next_element().unwrap_err();
    assert!(matches!(err, StreamError::Io(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "the BEEF source failed: the source is gone"
    );

    assert!(case("s4_truncated")["read"]["error"].is_string());
    let bytes = row("beef-031");
    let err = BeefStream::new(bytes.as_slice())
        .find_map(|e| e.err())
        .expect("beef-031 is refused");
    let StreamError::Refused(refusal) = &err else {
        panic!("expected a refusal, got {err:?}")
    };
    assert!(!refusal.to_string().is_empty());
    assert_eq!(err.to_string(), refusal.to_string());
}

/// Kills `Judge::check_named_subject` 3026:33 (`||` replaced by `&&`), the
/// candidate the lane held equivalent (the review of #645).
///
/// The rule: the frame is cut before the subject is asked of it. The Lean's
/// `cutFrame` reads the prefix's 32 bytes and the version word and refuses a
/// version other than V1 or V2 at ⟨36, badVersion⟩ before anything else
/// (bsv-stack-lean@5df1e0a3 `lean/BeefOfAnySize.lean:1108-1124`); the subject
/// is asked by `finish` at the end (:990-1003); and the reading does not
/// depend on where the source's chunks end (the resume at every k,
/// `lean/BeefOfAnySize/Scenarios.lean:316-323`). The reference reads the
/// version in `Beef.fromReader` before `Transaction.fromAtomicBEEF` compares
/// a txid (`Transaction.ts:302-313`). The vector: `atomic-beef-023`'s prefix
/// (its subject) followed by a version word of zero, asked for
/// `atomic-beef-025`'s subject, read whole by the stream and by the
/// asynchronous reader in chunks of 36 bytes (the prefix alone, then the
/// rest): both refuse the version at 36.
#[tokio::test]
async fn a_bad_version_after_the_prefix_is_refused_whatever_the_chunks_wire_atomic_beef_023() {
    let recorded = case("s4_atomic_subject");
    let named = internal(recorded["missing_prefix_subject"].as_str().unwrap());
    let mut bytes = row("atomic-beef-023")[..36].to_vec();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let headers = recorded_headers("beef-023");

    let whole = verify_stream_structure(bytes.as_slice(), &headers, Some(named)).unwrap();
    assert!(
        matches!(
            whole,
            Verdict::Invalid {
                offset: 36,
                kind: Kind::BadVersion,
                ..
            }
        ),
        "{whole:?}"
    );

    let tracker = RootsOnly {
        roots: headers,
        fail_roots: false,
    };
    let mut source = chunks(bytes);
    source.size = 36;
    let verdict = verify_stream_async(&mut source, &tracker, Some(named))
        .await
        .unwrap();
    assert_eq!(verdict, whole);
}
