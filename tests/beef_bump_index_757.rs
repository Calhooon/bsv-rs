//! The BUMP index written for a txid two BUMPs prove, and the path a BEEF
//! attaches to a transaction that already carries one (#757).
//!
//! Item 1: the reference's `#tryToValidateBumpIndex` reads its level-0 index
//! (`ts-stack@edf6e03` `Beef.ts:1329-1340`, `this.#ensureBumpTxidIndex().get(txid)`,
//! the index a `Map.set` over the BUMPs in order, `:576-585`), so an entry
//! merged after two BUMPs that hold its txid takes the LAST one's index, and
//! its writers write that index (`BeefTx.toWriter`) and carry that BUMP into
//! an atomic BEEF (`#copySelectedTransactions`, `:448-470`). Until #757
//! `merge_raw_tx` and `merge_txid_only` wrote the earliest's. An entry merged
//! before a BUMP keeps the BUMP present at its merge (`#mergeBumpEntry`,
//! `:774-786`, sets only an entry without an index), on both sides.
//!
//! Item 2: `#addInputProof` (`:649-668`) sets `current.merklePath = mp`
//! whenever `findBump` answers, over a path the caller set, and descends a
//! transaction only when it does not, a caller's path kept. Until #757
//! `add_input_proof` kept a caller's path and did not descend past it.
//!
//! The fold: a txid-only entry's BUMP in an atomic BEEF is the one its index
//! names (`#copySelectedTransactions`, `:448-470`; the earliest carrying the
//! txid until the fold), and `make_txid_only` sets the index again
//! (`makeTxidOnly`, `:550-565`). A BUMP holding the txid only as an unflagged
//! sibling leaf stays no proof at either merge site (`try_to_validate_bump_index`,
//! `update_bump_indices`), where the reference's `#tryToValidateBumpIndex`
//! (`:1334-1338`) and `#tryMarkTxProvenByBump` (`:813-822`) take it and flag
//! the leaf: the stated difference, pinned byte for byte.
//!
//! Every BEEF is rebuilt here by this crate's writer from the inputs the
//! vector carries and compared with the bytes the reference's writer
//! recorded (`vectors/beef_bump_index_757.json`,
//! `support/beef_bump_index_757.mjs`, Node v22.18.0).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::to_hex;
use bsv_rs::transaction::beef_stream::{verify_stream_structure, Hash32, HeadersFn};
use bsv_rs::transaction::{Beef, MerklePath, Transaction};
use serde_json::Value;
use std::collections::HashSet;

const VECTOR: &str = include_str!("vectors/beef_bump_index_757.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

/// The vector's transaction by name.
fn tx(v: &Value, name: &str) -> Transaction {
    let t = Transaction::from_hex(v["txs"][name]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(t.id(), v["txs"][name]["txid"].as_str().unwrap());
    t
}

/// The vector's BUMP by name.
fn bump(v: &Value, name: &str) -> MerklePath {
    let hex = v["bumps"][name].as_str().unwrap();
    let path = MerklePath::from_hex(hex).unwrap();
    assert_eq!(path.to_hex(), hex);
    path
}

/// A case's BEEF, merged step by step as the recorder merged it.
fn build(v: &Value, case: &Value) -> Beef {
    let mut beef = Beef::new();
    for step in case["steps"].as_array().unwrap() {
        let (kind, name) = step.as_str().unwrap().split_once(':').unwrap();
        match kind {
            "bump" => {
                beef.merge_bump(bump(v, name));
            }
            "raw" => {
                beef.merge_raw_tx(tx(v, name).to_binary(), None);
            }
            "txid" => {
                beef.merge_txid_only(tx(v, name).id());
            }
            "txidonly" => {
                beef.make_txid_only(&tx(v, name).id());
            }
            other => panic!("no step {other}"),
        }
    }
    beef
}

fn index_case(v: &Value, name: &str) -> Value {
    v["index_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

/// The case's written BEEF, the parent's index and every atomic BEEF equal
/// the reference's.
fn assert_written_as_recorded(v: &Value, name: &str) {
    let case = index_case(v, name);
    let mut beef = build(v, &case);
    let parent = v["txs"]["parent"]["txid"].as_str().unwrap();
    assert_eq!(
        beef.to_hex(),
        case["beef"].as_str().unwrap(),
        "{name}: the bytes the reference's toBinary writes"
    );
    assert_eq!(
        beef.find_txid(parent)
            .unwrap()
            .bump_index()
            .map(|i| i as u64),
        case["parent_bump_index"].as_u64(),
        "{name}: the parent's bump index"
    );
    for atomic in case["atomic"].as_array().unwrap() {
        let subject = v["txs"][atomic["subject"].as_str().unwrap()]["txid"]
            .as_str()
            .unwrap();
        assert_eq!(
            to_hex(&beef.to_binary_atomic(subject).unwrap()),
            atomic["beef"].as_str().unwrap(),
            "{name}: the bytes the reference's toBinaryAtomic({}) writes",
            atomic["subject"]
        );
    }
}

/// A raw transaction merged after two BUMPs that hold its txid takes the
/// last one's index, at two heights in both orders and at one height with
/// two roots, with a child beside it, and a txid-only entry the same; the
/// fold's two: a txid-only entry with a child, whose atomic BEEF carries the
/// BUMP its index names (`#copySelectedTransactions`, `:448-470`), and an entry
/// merged between the BUMPs then made txid-only, its index the last again
/// (`makeTxidOnly`, `:550-565`).
#[test]
fn an_entry_merged_after_two_bumps_of_its_txid_writes_the_last_bumps_index_757() {
    let v = vector();
    for name in [
        "raw_after_both",
        "raw_after_both_reversed",
        "raw_after_one_height_two_roots",
        "raw_after_both_with_child",
        "txid_only_after_both",
        "txid_only_after_both_with_child",
        "made_txid_only_between_with_child",
    ] {
        assert_eq!(index_case(&v, name)["parent_bump_index"], 1, "{name}");
        assert_written_as_recorded(&v, name);
    }
}

/// The atomic writers carry the BUMP the entry's index names, so an atomic
/// BEEF of the parent, or of a child spending it, carries the last BUMP.
#[test]
fn the_atomic_beef_carries_the_last_bump_of_a_txid_two_bumps_prove_757() {
    let v = vector();
    let case = index_case(&v, "raw_after_both_with_child");
    let mut beef = build(&v, &case);
    let last = bump(&v, "left_800001");
    for atomic in case["atomic"].as_array().unwrap() {
        let subject = v["txs"][atomic["subject"].as_str().unwrap()]["txid"]
            .as_str()
            .unwrap();
        let bytes = beef.to_binary_atomic(subject).unwrap();
        let read = Beef::from_binary(&bytes).unwrap();
        assert_eq!(read.bumps.len(), 1);
        assert_eq!(
            read.bumps[0].to_hex(),
            last.to_hex(),
            "{}",
            atomic["subject"]
        );
    }
}

/// An entry merged before a BUMP, or between two, keeps the BUMP present at
/// its merge, as the reference's `#mergeBumpEntry` sets only an entry
/// without an index: the agreement, green before #757 too.
#[test]
fn an_entry_merged_before_or_between_the_bumps_keeps_the_bump_present_at_its_merge_757() {
    let v = vector();
    for name in ["raw_between", "raw_before_both"] {
        assert_eq!(index_case(&v, name)["parent_bump_index"], 0, "{name}");
        assert_written_as_recorded(&v, name);
    }
}

/// The stated difference, older than #757, at both merge sites: a BUMP that
/// holds the txid as an unflagged sibling leaf is no proof of it here, where
/// the reference takes any level-0 hash and flags the leaf. Merged after it
/// (`try_to_validate_bump_index`; `#tryToValidateBumpIndex`, `:1334-1338`)
/// the entry keeps the flagged BUMP's index; merged before it
/// (`update_bump_indices`; `#tryMarkTxProvenByBump`, `:813-822`) the entry has
/// none. This crate's bytes are the reference's with the sibling leaf's flag
/// byte `00` for `02` and the entry's index byte `00` for `01`, or its format
/// byte `00` (no BUMP) for `01 00`, and nothing else; the reference's bytes
/// read valid here, this crate's where it holds a proof.
#[test]
fn a_bump_holding_the_txid_as_an_unflagged_sibling_is_no_proof_of_it_states_757() {
    let v = vector();
    let parent = v["txs"]["parent"]["txid"].as_str().unwrap();
    let raw = v["txs"]["parent"]["raw"].as_str().unwrap();
    let wire: String = (0..32).rev().map(|i| &parent[2 * i..2 * i + 2]).collect();
    let flag = (format!("0102{wire}"), format!("0100{wire}"));
    for (name, recorded, ours, entry) in [
        ("raw_after_a_sibling_leaf", 1, Some(0), ("0101", "0100")),
        ("raw_before_a_sibling_leaf", 0, None, ("0100", "00")),
    ] {
        let case = index_case(&v, name);
        assert_eq!(case["parent_bump_index"], recorded, "{name}: the reference");
        let mut beef = build(&v, &case);
        assert_eq!(beef.find_txid(parent).unwrap().bump_index(), ours, "{name}");
        let theirs = case["beef"].as_str().unwrap();
        assert_eq!(
            theirs.matches(&flag.0).count(),
            1,
            "{name}: the sibling leaf, flag 02"
        );
        let entry_at = (format!("{}{raw}", entry.0), format!("{}{raw}", entry.1));
        assert_eq!(theirs.matches(&entry_at.0).count(), 1, "{name}: the entry");
        let expected = theirs
            .replace(&flag.0, &flag.1)
            .replace(&entry_at.0, &entry_at.1);
        assert_eq!(
            beef.to_hex(),
            expected,
            "{name}: the flag and index bytes alone differ"
        );
        // Without the sibling's proof the parent here is unproven and its
        // input names no entry; the reference's bytes read valid here.
        let mut read = Beef::from_binary(&beef.to_binary()).unwrap();
        assert_eq!(read.verify_valid(false).valid, ours.is_some(), "{name}");
        let mut read = Beef::from_hex(theirs).unwrap();
        assert!(
            read.verify_valid(false).valid,
            "{name}: the reference's bytes"
        );
    }
}

/// A BEEF this crate wrote before #757 for `raw_after_both` carries the
/// earliest BUMP's index, the bytes `raw_between`'s (the reference's), which
/// differ from `raw_after_both`'s at that byte alone: both readers accept it,
/// as they accept the reference's.
#[test]
fn a_beef_written_with_the_earliest_index_before_757_is_read_by_both_readers_757() {
    let v = vector();
    let old = index_case(&v, "raw_between")["beef"]
        .as_str()
        .unwrap()
        .to_string();
    let new = index_case(&v, "raw_after_both")["beef"]
        .as_str()
        .unwrap()
        .to_string();
    let differ: Vec<usize> = (0..old.len())
        .filter(|&i| old.as_bytes()[i] != new.as_bytes()[i])
        .collect();
    assert_eq!(old.len(), new.len());
    assert_eq!(differ, vec![247], "one hex digit: the entry's index byte");
    assert_eq!((&old[246..248], &new[246..248]), ("00", "01"));
    let any = HeadersFn(|_: u64, _: &Hash32| true);
    for hex in [&old, &new] {
        let bytes = bsv_rs::primitives::from_hex(hex).unwrap();
        let mut read = Beef::from_binary(&bytes).unwrap();
        assert!(read.verify_valid(false).valid);
        assert!(verify_stream_structure(bytes.as_slice(), &any, None)
            .unwrap()
            .is_valid());
    }
}

/// A transaction's path and whether each input is linked, depth-first from
/// the subject, each txid once, as the recorder walks the reference's.
fn walk(subject: &Transaction) -> Vec<Value> {
    let mut seen = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![subject];
    while let Some(t) = stack.pop() {
        if !visited.insert(t.id()) {
            continue;
        }
        let path = t.merkle_path.as_ref().map(|mp| {
            serde_json::json!({
                "block_height": mp.block_height,
                "root": mp.compute_root(None).unwrap(),
            })
        });
        let linked: Vec<bool> = t
            .inputs
            .iter()
            .map(|i| i.source_transaction.is_some())
            .collect();
        seen.push(serde_json::json!({
            "txid": t.id(),
            "merkle_path": path,
            "inputs_linked": linked,
        }));
        for input in t.inputs.iter().rev() {
            if let Some(source) = input.source_transaction.as_deref() {
                stack.push(source);
            }
        }
    }
    seen
}

/// Each path case: its BEEF written as recorded, read back, the caller's
/// path set on one of its transactions, then the subject's walk.
fn path_case_walk(v: &Value, name: &str) -> (Vec<Value>, Value) {
    let case = v["path_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
        .clone();
    let mut written = build(v, &case);
    assert_eq!(written.to_hex(), case["beef"].as_str().unwrap(), "{name}");
    let mut read = Beef::from_hex(case["beef"].as_str().unwrap()).unwrap();
    let set_on = v["txs"][case["set_on"].as_str().unwrap()]["txid"]
        .as_str()
        .unwrap();
    read.find_txid_mut(set_on)
        .unwrap()
        .tx_mut()
        .unwrap()
        .merkle_path = Some(bump(v, case["set"].as_str().unwrap()));
    let subject = v["txs"][case["subject"].as_str().unwrap()]["txid"]
        .as_str()
        .unwrap();
    let atomic = read.find_atomic_transaction(subject).unwrap();
    (walk(&atomic), case["walk"].clone())
}

/// A caller's path on a transaction this BEEF proves is replaced by the
/// BEEF's BUMP, on the subject and on the subject's parent, as the
/// reference's `#addInputProof` replaces it.
#[test]
fn a_callers_path_on_a_transaction_the_beef_proves_is_replaced_by_its_bump_757() {
    let v = vector();
    for name in ["proven_parent_of_the_subject", "proven_subject"] {
        let (walked, recorded) = path_case_walk(&v, name);
        assert_eq!(Value::Array(walked), recorded, "{name}");
    }
}

/// A transaction this BEEF proves is not descended though the BEEF carries
/// its inputs raw: the caller's path on the child replaced by the child's
/// BUMP, the child's inputs unlinked, the parent unreached, as the reference's
/// `#addInputProof` stops at `findBump`'s answer (`:658-662`). Green before
/// the fold too: the agreement, RED with `enter` descending a proven
/// transaction.
#[test]
fn a_proven_transaction_is_not_descended_though_the_beef_carries_its_inputs_757() {
    let v = vector();
    let (walked, recorded) = path_case_walk(&v, "proven_parent_with_its_input_in_the_beef");
    assert_eq!(
        recorded[1]["inputs_linked"],
        serde_json::json!([false, false])
    );
    assert_eq!(Value::Array(walked), recorded);
}

/// A caller's path on a transaction this BEEF does not prove is kept, and
/// the walk goes on past it to the BUMP-proven parent, as the reference's
/// `#addInputProof` descends it.
#[test]
fn a_callers_path_on_a_transaction_the_beef_does_not_prove_is_kept_and_descended_757() {
    let v = vector();
    let (walked, recorded) = path_case_walk(&v, "unproven_parent_of_the_subject");
    assert_eq!(Value::Array(walked), recorded);
}
