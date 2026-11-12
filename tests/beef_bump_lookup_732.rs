//! Which BUMP a BEEF attaches to a transaction two of its BUMPs hold (#732).
//!
//! The reference indexes the level-0 leaves of every BUMP with a `Map.set`
//! loop over the BUMPs in order, so the LAST BUMP holding a txid is the one
//! `findBump` answers and `#addInputProof` makes the transaction's
//! `merklePath` (`ts-stack@edf6e03` `Beef.ts:570-585`, `:649-680`). Its
//! reader pushes every BUMP as read and merges none (`:1257-1261`), and so
//! does this crate's (`beef/collect.rs`), so two proofs of one txid (two
//! blocks after a reorg, two roots at one height) reach both readers from the
//! wire. Until #732 `Beef::find_bump` and `add_input_proof`'s index kept the
//! EARLIEST, so `Transaction::from_beef` attached another path, and a tracker was
//! asked about another root, than the reference's `Transaction.fromBEEF`.
//!
//! Every BEEF is written by this crate's writer (`merge_raw_tx`, `merge_bump`,
//! `to_binary`) and equals the bytes the reference's writer recorded in
//! `vectors/beef_bump_lookup_732.json` (`support/beef_bump_lookup_732.mjs`,
//! Node v22.18.0), whose roots are the reference's answers on those bytes.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::to_hex;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_bump_lookup_732.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn one() -> LockingScript {
    LockingScript::from_hex("51").unwrap()
}

/// An input spending `txid:vout` with the unlocking script `OP_1`.
fn spend(txid: &str, vout: u32) -> TransactionInput {
    let mut input = TransactionInput::new(txid.to_string(), vout);
    input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
    input
}

/// The recorder's parent: spends `aa..aa:0`, two `OP_1` outputs of 1,000 and
/// 2,000 satoshis.
fn parent() -> Transaction {
    let mut tx = Transaction::new();
    tx.inputs_mut().push(spend(&"aa".repeat(32), 0));
    tx.outputs_mut().push(TransactionOutput::new(1_000, one()));
    tx.outputs_mut().push(TransactionOutput::new(2_000, one()));
    tx
}

/// The recorder's child: spends both outputs of `parent`, one output of 2,500.
fn child(parent: &str) -> Transaction {
    let mut tx = Transaction::new();
    tx.inputs_mut().push(spend(parent, 0));
    tx.inputs_mut().push(spend(parent, 1));
    tx.outputs_mut().push(TransactionOutput::new(2_500, one()));
    tx
}

/// The recorder's BUMPs by name, each holding `txid` at level 0.
fn bump(name: &str, txid: &str, sibling: &str) -> MerklePath {
    let level = match name {
        "alone_800000" => vec![MerklePathLeaf::new_txid(0, txid.to_string())],
        "left_800001" => vec![
            MerklePathLeaf::new_txid(0, txid.to_string()),
            MerklePathLeaf::new(1, sibling.to_string()),
        ],
        "right_800000" => vec![
            MerklePathLeaf::new(0, sibling.to_string()),
            MerklePathLeaf::new_txid(1, txid.to_string()),
        ],
        other => panic!("no BUMP named {other}"),
    };
    let height = if name == "left_800001" {
        800_001
    } else {
        800_000
    };
    MerklePath::new(height, vec![level]).unwrap()
}

/// A recorded path: `(block_height, root)`.
fn recorded(path: &Value) -> (u32, String) {
    (
        path["block_height"].as_u64().unwrap() as u32,
        path["root"].as_str().unwrap().to_string(),
    )
}

fn held(path: &MerklePath) -> (u32, String) {
    (path.block_height, path.compute_root(None).unwrap())
}

/// Each case's BEEF, built by this crate's writer, and the case.
fn cases() -> Vec<(Vec<u8>, Value)> {
    let v = vector();
    let parent = parent();
    let p = parent.id();
    assert_eq!(p, v["parent"]["txid"].as_str().unwrap());
    assert_eq!(parent.to_hex(), v["parent"]["raw"].as_str().unwrap());
    let child = child(&p);
    assert_eq!(child.to_hex(), v["child"]["raw"].as_str().unwrap());
    let sibling = v["sibling"].as_str().unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let mut beef = Beef::new();
            beef.merge_raw_tx(parent.to_binary(), None)
                .expect("the bytes are one transaction");
            if case["subject"].as_str().unwrap() == child.id() {
                beef.merge_raw_tx(child.to_binary(), None)
                    .expect("the bytes are one transaction");
            }
            for name in case["bumps"].as_array().unwrap() {
                beef.merge_bump(bump(name.as_str().unwrap(), &p, sibling));
            }
            let bytes = beef.to_binary().expect("the BEEF is writable");
            assert_eq!(
                to_hex(&bytes),
                case["beef"].as_str().unwrap(),
                "{}: this crate's writer writes the reference's bytes",
                case["name"]
            );
            (bytes, case.clone())
        })
        .collect()
}

/// `Transaction::from_beef` attaches the last BUMP holding the subject's
/// txid, the path the reference's `findAtomicTransaction` attaches, on two
/// heights in both orders and on two roots at one height.
#[test]
fn from_beef_attaches_the_last_bump_holding_the_txid_732() {
    for (bytes, case) in cases() {
        let name = case["name"].as_str().unwrap();
        if name == "a_parent_proven_twice" {
            continue;
        }
        let read = Beef::from_binary(&bytes).unwrap();
        assert_eq!(
            read.bumps.len() as u64,
            case["bumps_read"].as_u64().unwrap()
        );
        let last = read.bumps.last().map(held).unwrap();
        let earliest = read.bumps.first().map(held).unwrap();
        assert_ne!(earliest, last, "{name}: two proofs of one txid, two roots");
        let tx = Transaction::from_beef(&bytes, Some(case["subject"].as_str().unwrap())).unwrap();
        let attached = held(tx.merkle_path.as_ref().unwrap());
        assert_eq!(attached, recorded(&case["attached"][0]), "{name}");
        assert_eq!(attached, last, "{name}: the last BUMP, not the earliest");
    }
}

/// `Beef::find_bump` answers the last BUMP holding the txid, as the
/// reference's `findBump` does.
#[test]
fn find_bump_answers_the_last_bump_holding_the_txid_732() {
    for (bytes, case) in cases() {
        let read = Beef::from_binary(&bytes).unwrap();
        let p = vector()["parent"]["txid"].as_str().unwrap().to_string();
        let found = held(read.find_bump(&p).unwrap());
        assert_eq!(found, recorded(&case["find_bump"]), "{}", case["name"]);
    }
}

/// A parent two BUMPs prove, spent twice by an unproven child: the input
/// linked in full and the one given a stub both carry the last BUMP, as the
/// reference's one parent object does.
#[test]
fn a_parent_proven_twice_carries_the_last_bump_on_every_input_732() {
    let (bytes, case) = cases()
        .into_iter()
        .find(|(_, c)| c["name"] == "a_parent_proven_twice")
        .unwrap();
    let tx = Transaction::from_beef(&bytes, Some(case["subject"].as_str().unwrap())).unwrap();
    assert!(tx.merkle_path.is_none(), "the child is unproven");
    let attached: Vec<(u32, String)> = tx
        .inputs()
        .iter()
        .map(|i| {
            held(
                i.source_transaction
                    .as_ref()
                    .unwrap()
                    .merkle_path
                    .as_ref()
                    .unwrap(),
            )
        })
        .collect();
    let expected: Vec<(u32, String)> = case["attached"]
        .as_array()
        .unwrap()
        .iter()
        .map(recorded)
        .collect();
    assert_eq!(attached, expected);
}

/// The wire bump index is not what decides: both writers give the parent the
/// earliest BUMP's index (`merge_bump` after the transaction), and the
/// reference's reader keeps both BUMPs as this crate's does.
#[test]
fn both_bumps_are_read_and_the_wire_index_names_the_earliest_732() {
    for (bytes, case) in cases() {
        let read = Beef::from_binary(&bytes).unwrap();
        let p = vector()["parent"]["txid"].as_str().unwrap().to_string();
        let index = read.find_txid(&p).unwrap().bump_index();
        assert_eq!(
            index.map(|i| i as u64),
            case["parent_bump_index"].as_u64(),
            "{}",
            case["name"]
        );
        let roots: Vec<(u32, String)> = read.bumps.iter().map(held).collect();
        let expected: Vec<(u32, String)> = case["bump_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(recorded)
            .collect();
        assert_eq!(roots, expected, "{}", case["name"]);
    }
}
