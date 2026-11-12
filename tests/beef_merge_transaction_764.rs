//! `Beef::merge_transaction` merges the transaction's merkle path as a BUMP
//! and walks its source transactions, as both references do (#764).
//!
//! The reference's `mergeTransaction` (`ts-stack@edf6e03` `Beef.ts:875-901`)
//! pops each transaction off a stack and runs `#mergeTransactionEntry`
//! (`:849-856`): `current.merklePath` merged through `#mergeBumpEntry`
//! (`:774-786`), the returned index the entry's, else `#tryToValidateBumpIndex`
//! (`:1329-1340`); an entry that ends with no index queues its inputs'
//! `sourceTransaction`s (`#queueSourceTransactions`, `:858-863`, at `:897`).
//! go-sdk@2ca481c's `MergeTransaction` (`transaction/beef.go:875-912`) does
//! the same. Until #764 `merge_transaction` stored the transaction alone
//! (`let bump_index = None; // Could be set if tx has merklePath`).
//!
//! Each case rebuilds the graph the vector names (its transactions' bytes,
//! the paths they carry, the sources their inputs carry), merges it after the
//! case's prior steps, and compares this crate's `to_hex` and entries with
//! what the reference's `mergeTransaction` then `toHex` recorded
//! (`vectors/beef_merge_transaction_764.json`,
//! `support/beef_merge_transaction_764.mjs`, Node v22.18.0).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::transaction::{Beef, MerklePath, Transaction};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_merge_transaction_764.json");

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
    MerklePath::from_hex(v["bumps"][name].as_str().unwrap()).unwrap()
}

/// A graph node as a transaction: its path and the sources its inputs carry.
fn materialize(v: &Value, node: &Value) -> Transaction {
    let mut t = tx(v, node["tx"].as_str().unwrap());
    if let Some(path) = node["path"].as_str() {
        t.merkle_path = Some(bump(v, path));
    }
    for source in node["sources"].as_array().unwrap() {
        let input = source["input"].as_u64().unwrap() as usize;
        t.inputs_mut()[input].source_transaction = Some(Box::new(materialize(v, source)));
    }
    t
}

fn case(v: &Value, name: &str) -> Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

/// The case's BEEF after its prior steps and `merge_transaction` of its graph:
/// the bytes, the BUMP count and each entry's name, index and form the
/// reference's.
fn assert_merged_as_recorded(name: &str) {
    let v = vector();
    let c = case(&v, name);
    let mut beef = Beef::new();
    for step in c["steps"].as_array().unwrap() {
        let (kind, what) = step.as_str().unwrap().split_once(':').unwrap();
        match kind {
            "bump" => {
                beef.merge_bump(bump(&v, what));
            }
            "raw" => {
                beef.merge_raw_tx(tx(&v, what).to_binary(), None)
                    .expect("the bytes are one transaction");
            }
            other => panic!("no step {other}"),
        }
    }
    let mut returned = None;
    if !c["merge"].is_null() {
        for _ in 0..c["times"].as_u64().unwrap_or(1) {
            returned = Some(beef.merge_transaction(materialize(&v, &c["merge"])).txid());
        }
    }
    let recorded = c["returned"]
        .as_str()
        .map(|n| v["txs"][n]["txid"].as_str().unwrap());
    assert_eq!(returned.as_deref(), recorded, "{name}: the entry returned");
    assert_eq!(
        beef.to_hex().expect("the BEEF is writable"),
        c["beef"].as_str().unwrap(),
        "{name}: the bytes the reference's mergeTransaction then toHex writes"
    );
    assert_eq!(
        beef.bumps.len() as u64,
        c["bumps"].as_u64().unwrap(),
        "{name}: BUMPs"
    );
    let names: Vec<(String, Option<u64>, bool)> = c["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let n = e["tx"].as_str().unwrap();
            (
                v["txs"][n]["txid"].as_str().unwrap().to_string(),
                e["bump_index"].as_u64(),
                e["txid_only"].as_bool().unwrap(),
            )
        })
        .collect();
    let held: Vec<(String, Option<u64>, bool)> = beef
        .txs
        .iter()
        .map(|t| (t.txid(), t.bump_index().map(|i| i as u64), t.is_txid_only()))
        .collect();
    assert_eq!(held, names, "{name}: the entries, their indices and forms");
}

#[test]
fn a_lone_transaction_carrying_its_path_is_merged_with_its_bump_764() {
    assert_merged_as_recorded("lone_proven");
}

#[test]
fn a_lone_unproven_transaction_is_merged_alone_764() {
    assert_merged_as_recorded("lone_unproven");
}

#[test]
fn a_child_carrying_its_proven_parent_merges_the_parent_and_its_bump_764() {
    assert_merged_as_recorded("child_of_a_proven_parent");
}

#[test]
fn a_child_carrying_its_unproven_parent_merges_the_parent_764() {
    assert_merged_as_recorded("child_of_an_unproven_parent");
}

#[test]
fn the_walk_stops_at_a_proven_middle_transaction_764() {
    assert_merged_as_recorded("chain_stops_at_a_proven_middle");
}

#[test]
fn a_chain_proven_at_its_root_merges_every_transaction_764() {
    assert_merged_as_recorded("chain_proven_at_the_root");
}

#[test]
fn a_parent_the_beef_holds_raw_is_one_entry_still_764() {
    assert_merged_as_recorded("parent_already_raw");
}

#[test]
fn a_parent_and_bump_the_beef_holds_add_no_second_bump_764() {
    assert_merged_as_recorded("parent_already_proven");
}

#[test]
fn a_transaction_a_held_bump_proves_does_not_walk_its_sources_764() {
    assert_merged_as_recorded("subject_proven_by_a_held_bump");
}

/// The transaction given is the entry's, its links kept; an ancestor is held
/// without links of its own (its sources are entries of the BEEF).
#[test]
fn the_merged_transaction_keeps_its_links_and_an_ancestor_is_held_without_them_764() {
    let v = vector();
    let c = case(&v, "chain_proven_at_the_root");
    let mut beef = Beef::new();
    beef.merge_transaction(materialize(&v, &c["merge"]));
    let grandchild = beef.find_txid(&tx(&v, "grandchild").id()).unwrap();
    let held = grandchild.tx().unwrap();
    assert!(held.inputs()[0].source_transaction.is_some());
    let child = beef.find_txid(&tx(&v, "child").id()).unwrap();
    let child = child.tx().unwrap();
    assert!(child
        .inputs()
        .iter()
        .all(|i| i.source_transaction.is_none()));
    assert_eq!(child.id(), tx(&v, "child").id());
}

/// #764's fold: two distinct unproven parents, the first input's merged
/// before the second's (the reference pushes the sources reversed,
/// `#queueSourceTransactions`, `:858-863`), the sort keeping that order.
#[test]
fn two_distinct_unproven_parents_are_merged_first_input_first_764() {
    assert_merged_as_recorded("two_distinct_unproven_parents");
}

/// A grandparent reached through both parents, without a path under the
/// first and with one under the second, is merged once, on the first
/// input's branch (the once-per-call set, `:885`, `:893-894`): no BUMP.
#[test]
fn a_grandparent_reached_twice_is_merged_once_on_the_first_branch_764() {
    assert_merged_as_recorded("a_grandparent_reached_twice_is_merged_once");
}

/// Two unrelated unproven transactions held, the first merged again:
/// replaced in its place (`#replaceOrAppendTx`, `:531-540`), so written
/// first still. Until #764's fold the held entry was removed and appended,
/// the sort keeping that order: B then A.
#[test]
fn a_held_unproven_transaction_merged_again_keeps_its_place_764() {
    assert_merged_as_recorded("a_held_unproven_transaction_merged_again_keeps_its_place");
}

/// The same with both proven.
#[test]
fn a_held_proven_transaction_merged_again_keeps_its_place_764() {
    assert_merged_as_recorded("a_held_proven_transaction_merged_again_keeps_its_place");
}

/// The same through `merge_raw_tx` (`#mergeRawTxEntry`, `:842-847`).
#[test]
fn a_held_transaction_merged_raw_again_keeps_its_place_764() {
    assert_merged_as_recorded("a_held_raw_transaction_merged_raw_again_keeps_its_place");
}

/// A graph merged into a BEEF holding it replaces every entry in its place:
/// the entries' order after the second merge is the order after the first
/// (an index pin of the in-place replacement, the cost the reference pays,
/// no entry moved and no index rebuilt), and the bytes are one merge's.
#[test]
fn a_graph_merged_twice_moves_no_entry_and_writes_one_merges_bytes_764() {
    let v = vector();
    let once = case(&v, "chain_proven_at_the_root");
    let mut beef = Beef::new();
    beef.merge_transaction(materialize(&v, &once["merge"]));
    assert_eq!(
        beef.to_hex().expect("the BEEF is writable"),
        once["beef"].as_str().unwrap()
    );
    let order = |b: &Beef| b.txs.iter().map(|t| t.txid()).collect::<Vec<_>>();
    let first = order(&beef);
    beef.merge_transaction(materialize(&v, &once["merge"]));
    assert_eq!(order(&beef), first, "the second merge moved an entry");
    assert_eq!(
        beef.to_hex().expect("the BEEF is writable"),
        once["beef"].as_str().unwrap()
    );
    assert_merged_as_recorded("chain_proven_at_the_root_merged_twice");
}
