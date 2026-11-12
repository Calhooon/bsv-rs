//! A V1 BEEF holding a txid-only entry is refused by the writers in the
//! reference's words, where the writer panicked (#817).
//!
//! BRC-62's V1 carries raw transactions only; a txid-only entry is BRC-96's
//! V2 form. A V1 BEEF read from wire bytes takes one through the public merge
//! doors (`merge_txid_only`, `make_txid_only`, `merge_beef` of a V2 BEEF
//! holding one), and until #817 `to_binary` and `to_hex` then panicked in
//! `BeefTx::write_tx_data` (`BeefTx has no transaction data to write`); on
//! wasm32 an abort. The reference throws `a valid serialized Transaction is
//! expected` there (`ts-stack@edf6e03` `BeefTx.ts:253-258`) and go-sdk's
//! `Bytes` errs `BEEF V1 cannot serialize txid-only transaction <txid>`
//! (`go-sdk@2ca481c` `transaction/beef.go:1546-1548`). Since #817 every
//! writer returns `Result` and refuses it in the reference's words before any
//! byte is written; the remedy is `version = BEEF_V2` or dropping the entry.
//! The reference's words are recorded by `support/beef_v1_txid_only_writer_817.mjs`
//! in `vectors/beef_v1_txid_only_writer_817.json` (Node v22.18.0).
//!
//! Every fixture is this crate's own writer's bytes (`Transaction::to_beef_v1`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/beef_seeds_817.rs"]
mod beef_seeds_817;

use bsv_rs::primitives::{to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, MerklePath, Transaction, TransactionInput, TransactionOutput, BEEF_V1, BEEF_V2,
};
use bsv_rs::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_v1_txid_only_writer_817.json");

/// The reference writer's words for a txid-only entry outside V2.
const RAW_TX_EXPECTED: &str = "a valid serialized Transaction is expected";

/// The sweep's BEEFs `Beef::from_binary` reads, and of them the V1 ones
/// (321 and 113 until the doubled-txid cells, thirteen BEEFs and two V1, joined
/// the vector at the rebase onto the edit door, #817; 337 until #840's vector
/// brought its clean V2 BEEF of block 170's transaction, the suffixed copies
/// refused; 338 until #844's vector brought three V2 BEEFs of that
/// transaction with an output of 2^53 - 1, plain, atomic and unproven, the
/// 2^53 copies refused; 341 and 115 until #844's fold recorded the writers'
/// control cells, fifteen BEEFs of a three-output transaction at 2^53 - 1,
/// six of them V1: `Transaction.toBEEF` and the atomic `toAtomicBEEF` bodies).
const SWEPT: (usize, usize) = (356, 121);

/// A txid no fixture holds.
const FRESH: &str = "8170000000000000000000000000000000000000000000000000000000000817";

/// One transaction spending `(source, vout)` into one output of `sats`.
fn spend(source: &str, vout: u32, sats: u64) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new(source.to_string(), vout);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    tx.inputs_mut().push(input);
    tx.outputs_mut().push(TransactionOutput::new(
        sats,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    tx
}

/// A proven parent (a lone leaf at offset 0, its block's only transaction)
/// and its child, linked; the child's V1 BEEF by this crate's writer.
fn proven_parent_and_child() -> (Transaction, Transaction, Vec<u8>) {
    let mut parent = spend(&"81".repeat(32), 0, 2_000);
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 817_000));
    let mut child = spend(&parent.id(), 0, 1_000);
    child.inputs_mut()[0].source_transaction = Some(Box::new(parent.clone()));
    let v1 = child.to_beef_v1(false).unwrap();
    assert_eq!(&v1[..4], &BEEF_V1.to_le_bytes(), "the fixture is V1");
    (parent, child, v1)
}

/// The BEEF error's words, or a panic naming what came instead.
fn beef_words(result: bsv_rs::Result<impl std::fmt::Debug>) -> String {
    match result {
        Err(Error::BeefError(words)) => words,
        other => panic!("expected a BEEF error, got {other:?}"),
    }
}

/// Each writer refuses `beef` in `words`, a caller's writer untouched.
fn every_writer_refuses(beef: &mut Beef, words: &str) {
    let mut writer = Writer::new();
    writer.write_bytes(b"held");
    assert_eq!(beef_words(beef.to_writer(&mut writer)), words, "to_writer");
    assert_eq!(
        writer.into_bytes(),
        b"held",
        "the caller's writer untouched"
    );
    assert_eq!(beef_words(beef.to_binary()), words, "to_binary");
    assert_eq!(beef_words(beef.to_hex()), words, "to_hex");
}

#[test]
fn a_v1_beef_holding_a_txid_only_entry_is_refused_in_the_reference_words_817() {
    let (_, _, v1) = proven_parent_and_child();
    let mut beef = Beef::from_binary(&v1).unwrap();
    assert_eq!(beef.version, BEEF_V1);
    beef.merge_txid_only(FRESH.to_string());
    every_writer_refuses(&mut beef, RAW_TX_EXPECTED);
    assert_eq!(beef.version, BEEF_V1, "the held version is left as it is");
    // The migration's remedy: the V2 word carries it.
    beef.version = BEEF_V2;
    let read = Beef::from_binary(&beef.to_binary().expect("V2 carries a txid-only entry")).unwrap();
    assert!(read.find_txid(FRESH).unwrap().is_txid_only());
}

#[test]
fn a_v2_beef_merged_into_a_v1_beef_makes_a_beef_the_writers_refuse_817() {
    let (_, _, v1) = proven_parent_and_child();
    let mut target = Beef::from_binary(&v1).unwrap();
    let mut source = Beef::new();
    source.merge_txid_only(FRESH.to_string());
    // The V2 source writes and reads back: the merge is the reference's.
    target
        .merge_beef(&source)
        .expect("a V2 source holding a txid-only entry writes and reads back");
    every_writer_refuses(&mut target, RAW_TX_EXPECTED);
}

#[test]
fn a_v1_entry_made_txid_only_is_refused_and_written_under_v2_still_proven_817() {
    let (parent, _, v1) = proven_parent_and_child();
    let mut beef = Beef::from_binary(&v1).unwrap();
    beef.make_txid_only(&parent.id()).unwrap();
    every_writer_refuses(&mut beef, RAW_TX_EXPECTED);
    beef.version = BEEF_V2;
    let mut read = Beef::from_binary(&beef.to_binary().expect("V2 carries it")).unwrap();
    assert!(read.find_txid(&parent.id()).unwrap().is_txid_only());
    assert!(read.verify_valid(true).valid, "the BUMP proves the stub");
}

#[test]
fn a_v1_beef_without_a_txid_only_entry_is_still_written_v1_byte_for_byte_817() {
    let (_, _, v1) = proven_parent_and_child();
    let mut beef = Beef::from_binary(&v1).unwrap();
    assert_eq!(
        beef.to_binary()
            .expect("a V1 BEEF of raw entries is writable"),
        v1
    );
}

#[test]
fn the_atomic_writer_refuses_a_v1_closure_holding_a_txid_only_entry_817() {
    let (parent, child, v1) = proven_parent_and_child();
    let mut beef = Beef::from_binary(&v1).unwrap();
    beef.make_txid_only(&parent.id()).unwrap();
    assert_eq!(
        beef_words(beef.to_binary_atomic(&child.id())),
        RAW_TX_EXPECTED
    );

    // A V1 closure without one is written as before; a txid-only entry
    // outside the closure is dropped, so it writes too.
    let mut beef = Beef::from_binary(&v1).unwrap();
    beef.merge_txid_only(FRESH.to_string());
    let atomic = beef
        .to_binary_atomic(&child.id())
        .expect("the closure holds no txid-only entry");
    assert_eq!(&atomic[36..40], &BEEF_V1.to_le_bytes());
    let read = Beef::from_binary(&atomic).unwrap();
    assert!(read.find_txid(FRESH).is_none());
}

#[test]
fn beef_tx_to_writer_refuses_a_txid_only_entry_outside_v2_817() {
    let entry = BeefTx::from_txid(FRESH.to_string());
    for version in [BEEF_V1, 0, 0xEFBE_0003] {
        let mut writer = Writer::new();
        assert_eq!(
            beef_words(entry.to_writer(&mut writer, version)),
            RAW_TX_EXPECTED,
            "under {version:#x}"
        );
        assert!(
            writer.into_bytes().is_empty(),
            "nothing written under {version:#x}"
        );
    }
    let mut writer = Writer::new();
    entry
        .to_writer(&mut writer, BEEF_V2)
        .expect("V2 carries a txid-only entry");
    let mut expected = vec![2u8];
    let mut txid = bsv_rs::primitives::from_hex(FRESH).unwrap();
    txid.reverse();
    expected.extend_from_slice(&txid);
    assert_eq!(writer.into_bytes(), expected);
}

/// The sweep: every BEEF this tree's vectors hold that `Beef::from_binary`
/// reads is written `Ok` and read back to the same entries, BUMPs and bytes;
/// with a fresh txid-only entry merged, a V1 one is refused in the
/// reference's words and a V2 one written and read back with it.
#[test]
fn every_vector_beef_is_written_and_read_back_and_a_v1_one_refuses_a_stub_817() {
    let (mut read, mut v1) = (0, 0);
    for (name, bytes) in beef_seeds_817::seeds() {
        let Ok(mut beef) = Beef::from_binary(&bytes) else {
            continue;
        };
        read += 1;
        let shape = |b: &Beef| {
            let mut txids: Vec<String> = b.txs.iter().map(|t| t.txid()).collect();
            txids.sort();
            let bumps: Vec<Vec<u8>> = b.bumps.iter().map(|p| p.to_binary().unwrap()).collect();
            (txids, bumps, b.version)
        };
        let written = beef
            .to_binary()
            .unwrap_or_else(|e| panic!("{name}: a BEEF read is refused by the writer: {e}"));
        let mut back = Beef::from_binary(&written)
            .unwrap_or_else(|e| panic!("{name}: written bytes refused: {e}"));
        assert_eq!(
            shape(&back),
            shape(&beef),
            "{name}: the same BEEF read back"
        );
        assert_eq!(back.to_binary().unwrap(), written, "{name}: a fixed point");

        if beef.version == BEEF_V1 {
            v1 += 1;
        }
        beef.merge_txid_only(FRESH.to_string());
        if beef.version == BEEF_V1 {
            assert_eq!(beef_words(beef.to_binary()), RAW_TX_EXPECTED, "{name}");
        } else {
            let bytes = beef.to_binary().expect("V2 carries a txid-only entry");
            let back = Beef::from_binary(&bytes).unwrap();
            assert!(back.find_txid(FRESH).unwrap().is_txid_only(), "{name}");
        }
    }
    assert_eq!((read, v1), SWEPT, "BEEFs read, V1 BEEFs read");
}

/// The reference's side, recorded: at each sequence its writer throws, in
/// these words, and so does this crate's.
#[test]
fn the_reference_and_this_crate_refuse_in_the_same_words_recorded_817() {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    let (parent, child, v1) = proven_parent_and_child();
    assert_eq!(
        v["v1_hex"].as_str().unwrap(),
        to_hex(&v1),
        "the same fixture"
    );
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let thrown = case["reference"]["thrown"].as_str().unwrap();
        assert_eq!(thrown, RAW_TX_EXPECTED, "{name}");
        let mut beef = Beef::from_binary(&v1).unwrap();
        match name {
            "merge_txid_only" => {
                beef.merge_txid_only(FRESH.to_string());
            }
            "make_txid_only" => {
                beef.make_txid_only(&parent.id()).unwrap();
            }
            "merge_beef_v2_txid_only" => {
                let mut source = Beef::new();
                source.merge_txid_only(FRESH.to_string());
                beef.merge_beef(&source)
                    .expect("the V2 source writes and reads back");
            }
            "to_binary_atomic_make_txid_only" => {
                beef.make_txid_only(&parent.id()).unwrap();
                assert_eq!(
                    beef_words(beef.to_binary_atomic(&child.id())),
                    thrown,
                    "{name}"
                );
                continue;
            }
            other => panic!("no case {other}"),
        }
        assert_eq!(beef_words(beef.to_hex()), thrown, "{name}");
        // The recording's V2 bytes, the remedy's: the same state under V2.
        beef.version = BEEF_V2;
        assert_eq!(
            beef.to_hex().expect("V2 carries it"),
            case["ours_hex"].as_str().unwrap(),
            "{name}: the V2 form, the reference's own bytes"
        );
    }
}
