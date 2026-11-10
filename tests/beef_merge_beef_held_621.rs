//! #621's fold: `Beef::merge_beef` leaves an entry the target already holds
//! raw or parsed alone, as the reference's `mergeBeef` does
//! (`ts-stack@edf6e03` `Beef.ts:971-986`, each entry through
//! `#mergeBeefTxEntry`, `:950-967`: a txid-only entry appended only where
//! nothing is held, a raw or parsed one only where nothing or a txid alone is
//! held; go-sdk@2ca481c `MergeBeefTxWithTxid`, `transaction/beef.go:984-1000`,
//! the same conditions). Until the fold a held entry was replaced and its BUMP
//! index rescanned (the last BUMP holding it), and an entry
//! `merge_transaction` stored lost its source links.
//!
//! Each case rebuilds the target and the source from the steps the vector
//! names with this crate's writer (the source's bytes the reference's), merges
//! the source as built and as read back from its bytes (the reference merges a
//! byte snapshot), and compares `to_hex`, the BUMP count and each entry's
//! name, index and form with what the reference's `mergeBeef` then `toHex`
//! recorded, the read-back merge against the recorded `read_back_beef`
//! (`vectors/beef_merge_beef_held_621.json`,
//! `support/beef_merge_beef_held_621.mjs`, Node v22.18.0).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::transaction::{Beef, MerklePath, MerklePathLeaf, Transaction};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/beef_merge_beef_held_621.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn tx(v: &Value, name: &str) -> Transaction {
    let t = Transaction::from_hex(v["txs"][name]["raw"].as_str().unwrap()).unwrap();
    assert_eq!(t.id(), v["txs"][name]["txid"].as_str().unwrap());
    t
}

fn bump(v: &Value, name: &str) -> MerklePath {
    if let Some(u) = v["unsorted_bumps"].get(name) {
        // #621's third fold: built in memory with its levels as the vector
        // holds them (out of offset order), as the reference's recorder
        // builds it; its hex alone would read back sorted.
        let path = u["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| {
                level
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| {
                        assert!(l["txid"].as_bool().unwrap());
                        MerklePathLeaf::new_txid(
                            l["offset"].as_u64().unwrap(),
                            l["hash"].as_str().unwrap().to_string(),
                        )
                    })
                    .collect()
            })
            .collect();
        let mp = MerklePath::new(u["height"].as_u64().unwrap() as u32, path).unwrap();
        assert_eq!(mp.to_hex().unwrap(), v["bumps"][name].as_str().unwrap());
        return mp;
    }
    MerklePath::from_hex(v["bumps"][name].as_str().unwrap()).unwrap()
}

/// The vector's steps applied to `beef`: `bump:`, `raw:`, `txid:`,
/// `graph:c_of_t` (C carrying T, unproven, as its input's source) and
/// `link:c_to_t` (the held C's transaction given T as its source in memory)
/// and `reread:` (the BEEF replaced by its own bytes read back, #621's third
/// fold) and `edit:u_to_v` (the held U given a lock time of 1 through
/// `tx_mut`, so it is V; #621's fourth fold).
fn apply(v: &Value, beef: &mut Beef, steps: &Value) {
    for step in steps.as_array().unwrap() {
        let (kind, what) = step.as_str().unwrap().split_once(':').unwrap();
        match kind {
            "reread" => {
                *beef = Beef::from_hex(&beef.to_hex()).unwrap();
            }
            "bump" => {
                beef.merge_bump(bump(v, what));
            }
            "raw" => {
                beef.merge_raw_tx(tx(v, what).to_binary(), None);
            }
            "txid" => {
                beef.merge_txid_only(tx(v, what).id());
            }
            "edit" => {
                assert_eq!(what, "u_to_v");
                let u = tx(v, "u").id();
                beef.edit_tx(&u, |t| t.lock_time = 1).unwrap();
            }
            "link" => {
                // The held C given T as its input's source, in memory, T no
                // entry of the BEEF (#621's second fold).
                assert_eq!(what, "c_to_t");
                let c = tx(v, "c").id();
                let t = tx(v, "t");
                beef.edit_tx(&c, |c| c.inputs[0].source_transaction = Some(Box::new(t)))
                    .unwrap();
            }
            "graph" => {
                assert_eq!(what, "c_of_t");
                let mut child = tx(v, "c");
                child.inputs[0].source_transaction = Some(Box::new(tx(v, "t")));
                beef.merge_transaction(child);
            }
            other => panic!("no step {other}"),
        }
    }
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

/// The case's target after `merge_beef` of its source, the source as built
/// and as read back from its bytes: the bytes, BUMPs, entries and C's links
/// the reference's. The source as built is merged before anything sorts it
/// (no `to_hex` or `to_binary` ahead of the merge: #621's second fold, the
/// rule read's finding that such a call masked the order) and is left as it
/// was; its bytes are compared after.
fn assert_merged_as_recorded(name: &str) {
    let v = vector();
    let c = case(&v, name);
    let mut source = Beef::new();
    apply(&v, &mut source, &c["source"]);
    let held: Vec<String> = source.txs.iter().map(|t| t.txid()).collect();
    let read_back = Beef::from_hex(c["source_beef"].as_str().unwrap()).unwrap();
    for (how, source) in [("as built", &source), ("read back", &read_back)] {
        let mut target = Beef::new();
        apply(&v, &mut target, &c["target"]);
        target.merge_beef(source);
        let recorded = match how {
            "read back" => c["read_back_beef"].as_str().unwrap(),
            _ => c["beef"].as_str().unwrap(),
        };
        assert_eq!(
            target.to_hex(),
            recorded,
            "{name} ({how}): the bytes the reference's mergeBeef then toHex writes"
        );
        assert_eq!(
            target.bumps.len() as u64,
            c["bumps"].as_u64().unwrap(),
            "{name} ({how}): BUMPs"
        );
        let recorded: Vec<(String, Option<u64>, bool)> = c["entries"]
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
        let held: Vec<(String, Option<u64>, bool)> = target
            .txs
            .iter()
            .map(|t| (t.txid(), t.bump_index().map(|i| i as u64), t.is_txid_only()))
            .collect();
        assert_eq!(
            held, recorded,
            "{name} ({how}): the entries, their indices and forms"
        );
        if let Some(links) = c["c_links"].as_array() {
            let entry = target.find_txid(&tx(&v, "c").id()).unwrap();
            let linked: Vec<bool> = entry
                .tx()
                .expect("C held parsed")
                .inputs
                .iter()
                .map(|i| i.source_transaction.is_some())
                .collect();
            let recorded: Vec<bool> = links.iter().map(|l| l.as_bool().unwrap()).collect();
            assert_eq!(linked, recorded, "{name} ({how}): C's source links");
        }
    }
    let after: Vec<String> = source.txs.iter().map(|t| t.txid()).collect();
    assert_eq!(
        after, held,
        "{name}: merge_beef left the source's order as held"
    );
    assert_eq!(
        source.to_hex(),
        c["source_beef"].as_str().unwrap(),
        "{name}: the source's bytes"
    );
}

/// The rule read's scenario: T held raw under its 800000 BUMP, the source
/// carrying T raw and an 800001 BUMP that holds T too: index 0 kept.
#[test]
fn a_held_raw_entry_keeps_its_bump_index_621() {
    assert_merged_as_recorded("held_raw_keeps_its_bump_index");
}

/// T held raw and unproven: the source's BUMP proves it at its merge.
#[test]
fn a_held_unproven_raw_entry_takes_the_merged_bump_621() {
    assert_merged_as_recorded("held_unproven_raw_takes_the_merged_bump");
}

/// C held from `merge_transaction` with its link to T: kept, links and all.
#[test]
fn a_held_parsed_entry_keeps_its_source_links_621() {
    assert_merged_as_recorded("held_parsed_entry_keeps_its_links");
}

/// T held txid-only: upgraded in its place, its index found again.
#[test]
fn a_held_txid_only_entry_is_upgraded_621() {
    assert_merged_as_recorded("held_txid_only_is_upgraded");
}

/// A txid-only source entry over a held raw one: the raw one kept.
#[test]
fn a_txid_only_source_entry_keeps_the_held_raw_entry_621() {
    assert_merged_as_recorded("txid_only_source_keeps_the_held_raw");
}

/// Nothing held: appended, indexed by the merged BUMP.
#[test]
fn a_source_entry_the_target_does_not_hold_is_appended_621() {
    assert_merged_as_recorded("nothing_held_is_appended");
}

/// #621's second fold, the rule read's scenario: X held proven; the source
/// built in memory (A spending Y, B spending X, Y by its txid) and never
/// serialized before the merge. The reference merges its snapshot in the
/// order its `toBinary` sorts it (B, Y, A), so the target writes Y, X, B, A;
/// until the fold the source's held order (A, B, Y) gave Y, X, A, B.
#[test]
fn a_source_is_merged_in_the_order_its_serialization_writes_621() {
    assert_merged_as_recorded("source_merged_in_its_written_order");
}

/// #621's second fold: the source's C parsed and linked in memory to T, no
/// entry of the source. The reference's snapshot holds C's bytes alone: C
/// appended with no link and T not merged; until the fold C's transaction was
/// cloned into the target, its link with it.
#[test]
fn a_linked_parsed_source_entry_merges_its_bytes_alone_621() {
    assert_merged_as_recorded("linked_parsed_source_entry_merges_its_bytes_alone");
}

/// #621's second fold: a source read from bytes is merged in the order read,
/// as the reference's `toBinary` returns the bytes its `fromBinary` read
/// (`Beef.ts:360-364`, `:1268-1270`): read back, T is a txid alone with no
/// index after X proven, which a sort of the source would put first; the
/// target writes X, T, as the reference's does (RED with the source sorted).
#[test]
fn a_source_read_from_bytes_is_merged_in_its_wire_order_621() {
    assert_merged_as_recorded("read_source_merged_in_its_wire_order");
}

/// #621's third fold, the rule read's FIX: a source BUMP built in memory with
/// its level 0 out of offset order (T at 1 before U at 0) is merged as the
/// reference's snapshot reads it back, every level sorted by offset
/// (`ts-stack@edf6e03` `MerklePath.ts:148-149`): the target, holding no BUMP
/// of that root, writes U at 0 before T at 1; the source keeps its order.
/// Until the fold the BUMP was merged as held, its leaves unsorted.
#[test]
fn an_unsorted_source_bump_is_merged_with_its_levels_sorted_621() {
    assert_merged_as_recorded("unsorted_source_bump_merged_sorted");
}

/// #621's third fold, the cold read's FIX: a source read from bytes, then a
/// fresh txid merged into it, is merged in its sort's order, as the
/// reference's `toBinary` sorts once `mergeTxidOnly` ends its cache
/// (`Beef.ts:926`): the mark cleared by `merge_txid_only` (through
/// `mark_mutated`). Read back, the order read would give X, T, Y.
#[test]
fn a_source_read_then_given_a_txid_is_merged_in_its_sorted_order_621() {
    assert_merged_as_recorded("read_source_then_txid_merged_is_sorted");
}

/// #621's third fold: a source read from bytes, then given a BUMP of its own,
/// is merged in its sort's order, as `mergeBump` ends the reference's cache
/// (`#markMutated(false)`, `Beef.ts:690`) and the read BEEF needs a sort: the
/// mark cleared by `merge_bump`.
#[test]
fn a_source_read_then_given_a_bump_is_merged_in_its_sorted_order_621() {
    assert_merged_as_recorded("read_source_then_bump_merged_is_sorted");
}

/// #621's fourth fold, the rule read's FIX: the target holds U and edits it
/// through `tx_mut` to V; `merge_beef` re-keys the target first, as the
/// reference's `mergeBeef` synchronizes it (`Beef.ts:976`, `:342-352`), so
/// the source's V is found held and left alone. Until the fold a second V
/// was appended.
#[test]
fn an_entry_edited_in_the_target_is_found_held_by_its_new_txid_621() {
    assert_merged_as_recorded("edited_target_entry_held_raw");
}

/// The same with V a txid alone in the source.
#[test]
fn an_entry_edited_in_the_target_keeps_a_txid_only_source_out_621() {
    assert_merged_as_recorded("edited_target_entry_held_txid_only");
}
