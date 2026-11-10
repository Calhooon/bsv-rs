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
//! sibling leaf is the entry's proof at both merge sites (`try_to_validate_bump_index`,
//! `update_bump_indices`), the leaf flagged, as the reference's
//! `#tryToValidateBumpIndex` (`:1334-1338`) and `#tryMarkTxProvenByBump`
//! (`:813-822`) take it: the reference's bytes, since #765 (a stated
//! difference until then).
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
    assert_eq!(
        path.to_hex()
            .expect("the path holds only states a BUMP writes (#817)"),
        hex
    );
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
                beef.merge_raw_tx(tx(v, name).to_binary(), None)
                    .expect("the bytes are one transaction");
            }
            "tx" => {
                beef.merge_transaction(tx(v, name));
            }
            "txid" => {
                beef.merge_txid_only(tx(v, name).id());
            }
            "txidonly" => {
                beef.make_txid_only(&tx(v, name).id());
            }
            "mut" => {
                // The held entry mutated in place, as the recorder sets
                // `findTxid(..).tx.lockTime` (#798's second fold).
                let (name, lock_time) = name.split_once('=').unwrap();
                let lock_time = lock_time.parse().unwrap();
                beef.edit_tx(&tx(v, name).id(), |t| t.lock_time = lock_time)
                    .unwrap();
            }
            "index" => {
                let (name, index) = name.split_once('=').unwrap();
                let index = (index != "none").then(|| index.parse().unwrap());
                beef.find_txid_mut(&tx(v, name).id())
                    .unwrap()
                    .set_bump_index(index);
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
    // A case recorded with its atomic BEEFs taken before `toHex` (whose sort
    // reorders the source) is judged in that order here too.
    let before_hex = case["atomic_before_hex"].as_bool().unwrap_or(false);
    if before_hex {
        assert_atomic_as_recorded(v, &case, &mut beef, name);
    }
    assert_eq!(
        beef.to_hex().expect("the BEEF is writable"),
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
    if !before_hex {
        assert_atomic_as_recorded(v, &case, &mut beef, name);
    }
}

/// Every atomic BEEF of the case equals the reference's.
fn assert_atomic_as_recorded(v: &Value, case: &Value, beef: &mut Beef, name: &str) {
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
            read.bumps[0]
                .to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
            last.to_hex()
                .expect("the path holds only states a BUMP writes (#817)"),
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

/// A BUMP that holds the txid as an unflagged sibling leaf is its proof at
/// both merge sites, the leaf flagged on the way, as the reference takes any
/// level-0 hash. Merged after it (`try_to_validate_bump_index`;
/// `#tryToValidateBumpIndex`, `:1334-1338`) the entry takes its index, the
/// last; merged before it (`update_bump_indices`; `#tryMarkTxProvenByBump`,
/// `:813-822`) it takes it on the BUMP's merge. The bytes are the reference's:
/// the sibling leaf's flag byte `02` and the entry's index byte `01`, or its
/// `01 00`. Until #765 this crate wrote `00` for each (v0.3.5's strict match)
/// and its `raw_before_a_sibling_leaf` BEEF read invalid.
#[test]
fn a_bump_holding_the_txid_as_an_unflagged_sibling_leaf_is_its_proof_765() {
    let v = vector();
    let parent = v["txs"]["parent"]["txid"].as_str().unwrap();
    for (name, index) in [
        ("raw_after_a_sibling_leaf", 1),
        ("raw_before_a_sibling_leaf", 0),
    ] {
        assert_eq!(index_case(&v, name)["parent_bump_index"], index, "{name}");
        assert_written_as_recorded(&v, name);
        let mut beef = build(&v, &index_case(&v, name));
        assert!(beef.bumps[index as usize]
            .txids()
            .contains(&parent.to_string()));
        let mut read = Beef::from_binary(&beef.to_binary().expect("the BEEF is writable")).unwrap();
        assert!(read.verify_valid(false).valid, "{name}");
    }
}

/// A txid-only entry that reaches the atomic writer without an index (one
/// read from bytes carries none), or with an index naming a BUMP that does
/// not hold its txid, is copied into the atomic BEEF with no BUMP, as the
/// reference's `#copySelectedTransactions` (`Beef.ts:448-470`) copies a BUMP
/// only for an entry `#hasMatchingBump` (`:436-446`) proves: `0200beef00`,
/// no BUMP. Until #766 this crate copied the last BUMP holding the txid
/// (`0200beef01fe01350c...`, `0200beef01fe00350c...`).
#[test]
fn a_txid_only_entry_without_a_matching_index_carries_no_bump_into_the_atomic_beef_766() {
    let v = vector();
    let child = v["txs"]["child"]["txid"].as_str().unwrap();
    for name in [
        "txid_only_without_an_index_with_child",
        "txid_only_naming_a_bump_without_its_txid_with_child",
    ] {
        assert_written_as_recorded(&v, name);
        let mut beef = build(&v, &index_case(&v, name));
        let mut read = Beef::from_binary(&beef.to_binary_atomic(child).unwrap()).unwrap();
        assert!(read.bumps.is_empty(), "{name}");
        assert_eq!(read.txs.len(), 2, "{name}");
        assert!(
            read.txs.iter().all(|tx| tx.bump_index().is_none()),
            "{name}"
        );
        // The stub is unproven in the bytes written.
        assert_eq!(
            read.verify_structure().err().map(|k| format!("{k:?}")),
            Some("StubNotProven".to_string()),
            "{name}"
        );
        assert!(!read.verify_valid(false).valid, "{name}");
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
    assert_eq!(
        written.to_hex().expect("the BEEF is writable"),
        case["beef"].as_str().unwrap(),
        "{name}"
    );
    let mut read = Beef::from_hex(case["beef"].as_str().unwrap()).unwrap();
    let set_on = v["txs"][case["set_on"].as_str().unwrap()]["txid"]
        .as_str()
        .unwrap();
    let path = bump(v, case["set"].as_str().unwrap());
    read.edit_tx(set_on, |t| t.merkle_path = Some(path))
        .unwrap();
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

/// The case's atomic BEEF of its one subject, read back.
fn atomic_read(v: &Value, name: &str) -> Beef {
    let case = index_case(v, name);
    let mut beef = build(v, &case);
    let subject = v["txs"][case["atomic"][0]["subject"].as_str().unwrap()]["txid"]
        .as_str()
        .unwrap();
    Beef::from_binary(&beef.to_binary_atomic(subject).unwrap()).unwrap()
}

/// A raw entry whose index, set by hand, names a BUMP that does not hold its
/// txid, or no BUMP at all, is written into the atomic BEEF with no BUMP and
/// no index (format `00`), as the reference's `#copySelectedTransactions`
/// maps an index through matching entries' BUMPs alone (`Beef.ts:453-456`,
/// `:462`), and the walk stops at it (its `bumpIndex` setter empties its
/// `inputTxids`, `BeefTx.ts:90-92`, `:219-221`). Until #798 the first kept
/// the grandchild's BUMP and wrote `01 00` (a BEEF this crate's readers
/// refuse, `TxidNotInBump`) and the second was an `Err`.
#[test]
fn a_raw_entry_whose_index_names_no_matching_bump_is_written_without_a_bump_798() {
    let v = vector();
    for name in [
        "raw_naming_a_bump_without_its_txid_with_child",
        "raw_naming_no_bump_with_child",
    ] {
        assert_written_as_recorded(&v, name);
        let read = atomic_read(&v, name);
        assert!(read.bumps.is_empty(), "{name}");
        assert_eq!(read.txs.len(), 2, "{name}");
        assert!(
            read.txs.iter().all(|tx| tx.bump_index().is_none()),
            "{name}"
        );
    }
}

/// The atomic walk stops at an entry carrying an index, matching or not: a
/// child whose index names the parent's BUMP is copied without it, and the
/// parent, reached only through the child, is not written, nor its BUMP, as
/// the reference's walk (`Beef.ts:427-431`) finds no `inputTxids` to descend.
/// Until #798 the walk reached the parent and carried BUMP 0.
#[test]
fn the_atomic_walk_stops_at_an_entry_carrying_an_index_798() {
    let v = vector();
    let name = "raw_child_naming_a_bump_without_its_txid";
    assert_written_as_recorded(&v, name);
    let read = atomic_read(&v, name);
    let parent = v["txs"]["parent"]["txid"].as_str().unwrap();
    assert!(read.bumps.is_empty());
    assert!(read.find_txid(parent).is_none());
    assert_eq!(read.txs.len(), 2);
}

/// An entry whose index names a BUMP that does not hold its txid keeps that
/// index, renumbered, when another included entry the BUMP proves carries it
/// in: the reference's mapped index (`Beef.ts:462`), a BEEF the readers
/// refuse, still the reference's bytes. The guard against dropping too much.
#[test]
fn a_raw_entry_sharing_a_matching_entrys_bump_keeps_the_mapped_index_798() {
    let v = vector();
    let name = "raw_sharing_a_matching_entrys_bump";
    assert_written_as_recorded(&v, name);
    let read = atomic_read(&v, name);
    let uncle = v["txs"]["uncle"]["txid"].as_str().unwrap();
    assert_eq!(read.bumps.len(), 1);
    assert_eq!(read.find_txid(uncle).unwrap().bump_index(), Some(0));
}

/// The txids of an atomic BEEF's entries, in the order written.
fn atomic_order(v: &Value, name: &str) -> Vec<String> {
    atomic_read(v, name)
        .txs
        .iter()
        .map(|tx| tx.txid())
        .collect()
}

/// The vector's txids by name, in the order given.
fn txids(v: &Value, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .map(|n| v["txs"][*n]["txid"].as_str().unwrap().to_string())
        .collect()
}

/// An entry held raw whose hand-set index names no BUMP is copied with the
/// source's `input_txids`, which the index emptied (`Beef.ts:464-465`), so
/// the uncle sorts after the proven parent: parent, uncle, join, the
/// reference's bytes. The strength read of PR #809: without the copy's
/// restore the uncle gains its missing input and sorts ahead.
#[test]
fn a_raw_entry_naming_no_bump_keeps_the_sources_input_txids_798() {
    let v = vector();
    let name = "raw_uncle_naming_no_bump_beside_a_proven_parent";
    assert_written_as_recorded(&v, name);
    assert_eq!(
        atomic_order(&v, name),
        txids(&v, &["parent", "uncle", "join"])
    );
}

/// An entry held as a transaction alone (`merge_transaction`, no bytes)
/// whose hand-set index names no BUMP is copied as the reference's
/// `BeefTx.fromTx` copies one never serialized (`Beef.ts:466-467`): its
/// `input_txids` re-scanned, so the uncle, whose parent lies outside the
/// BEEF, sorts ahead: uncle, join, parent. The rule read and the cold read
/// of PR #809; until the fold parent, uncle, join.
#[test]
fn a_transaction_entry_naming_no_bump_is_copied_with_its_inputs_rescanned_798() {
    let v = vector();
    let name = "transaction_uncle_naming_no_bump_never_serialized";
    assert!(index_case(&v, name)["atomic_before_hex"].as_bool().unwrap());
    assert_written_as_recorded(&v, name);
    assert_eq!(
        atomic_order(&v, name),
        txids(&v, &["uncle", "join", "parent"])
    );
}

/// Stated: the reference's `toHex` fills each entry's `_rawTx`
/// (`BeefTx.getRawTxBytes`), so the same entries written atomic after it
/// copy through the raw branch (parent, uncle, join); this crate's writer
/// caches no bytes in the entries, so its atomic BEEF is the never-serialized
/// one whatever was written before (the root `CLAUDE.md` row).
#[test]
fn a_transaction_entry_after_to_hex_keeps_the_never_serialized_order_stated_798() {
    let v = vector();
    let name = "transaction_uncle_naming_no_bump_after_to_hex";
    let case = index_case(&v, name);
    let mut beef = build(&v, &case);
    assert_eq!(
        beef.to_hex().expect("the BEEF is writable"),
        case["beef"].as_str().unwrap()
    );
    let join = v["txs"]["join"]["txid"].as_str().unwrap();
    let ours = to_hex(&beef.to_binary_atomic(join).unwrap());
    assert_ne!(ours, case["atomic"][0]["beef"].as_str().unwrap());
    let never = index_case(&v, "transaction_uncle_naming_no_bump_never_serialized");
    assert_eq!(ours, never["atomic"][0]["beef"].as_str().unwrap());
    assert_eq!(
        atomic_order(&v, name),
        txids(&v, &["uncle", "join", "parent"])
    );
}

/// A txid-only entry no BUMP proves, read by `Beef::from_binary` (a stub
/// carries no index, `beef/collect.rs`), is written by `to_binary_atomic`
/// with no BUMP, and both readers refuse the bytes `StubNotProven`, as the
/// reference's writer writes them: the agreement, green before #798 too.
#[test]
fn a_stub_read_from_bytes_written_atomic_is_refused_as_stub_not_proven_798() {
    let v = vector();
    let case = index_case(&v, "txid_only_after_both_with_child");
    let child = v["txs"]["child"]["txid"].as_str().unwrap();
    let mut read =
        Beef::from_binary(&build(&v, &case).to_binary().expect("the BEEF is writable")).unwrap();
    let parent = v["txs"]["parent"]["txid"].as_str().unwrap();
    // Read from bytes, the stub has no index.
    assert_eq!(read.find_txid(parent).unwrap().bump_index(), None);
    let bytes = read.to_binary_atomic(child).unwrap();
    let any = HeadersFn(|_: u64, _: &Hash32| true);
    let streamed = verify_stream_structure(bytes.as_slice(), &any, None).unwrap();
    assert!(
        format!("{streamed:?}").contains("StubNotProven"),
        "{streamed:?}"
    );
    let mut again = Beef::from_binary(&bytes).unwrap();
    assert!(again.bumps.is_empty());
    assert_eq!(
        again.verify_structure().err().map(|k| format!("{k:?}")),
        Some("StubNotProven".to_string())
    );
    assert!(!again.verify_valid(false).valid);
}

/// The closure is taken from the entries as held, never from a sorted
/// source: the reference's `#getBeefForAtomic` copies `this.txs` in their
/// order and sorts the copy alone (`Beef.ts:375-390`). An uncle held as a
/// transaction ahead of the parent and the join, no BUMP, its hand-set index
/// naming none, written atomic before any `to_hex`: uncle, parent, join, the
/// reference's bytes. PR #809's rule read; until its second fold the source
/// was sorted first (parent, join, uncle) and the closure written parent,
/// uncle, join.
#[test]
fn the_atomic_closure_is_taken_from_the_entries_as_held_798() {
    let v = vector();
    let name = "transaction_uncle_held_first_naming_no_bump_never_serialized";
    assert!(index_case(&v, name)["atomic_before_hex"].as_bool().unwrap());
    assert_written_as_recorded(&v, name);
    assert_eq!(
        atomic_order(&v, name),
        txids(&v, &["uncle", "parent", "join"])
    );
}

/// An entry held raw and mutated in place through `BeefTx::tx_mut` after
/// its hand-set index named no BUMP is copied through the raw branch, as the
/// reference's is: `syncRawTxFromTransaction` keeps `_rawTx` with the new
/// bytes (`BeefTx.ts:160-169`) and `#copySelectedTransactions` copies it with
/// the inputs the index emptied (`Beef.ts:465`), so the mutated uncle sorts
/// after the proven parent: parent, uncle, join, the reference's bytes.
/// PR #809's rule read; until its second fold the copy re-scanned the
/// inputs (`tx_mut` drops the bytes) and the uncle, whose parent lies
/// outside, sorted ahead.
#[test]
fn a_raw_entry_mutated_through_tx_mut_is_copied_through_the_raw_branch_798() {
    let v = vector();
    let name = "raw_uncle_mutated_naming_no_bump_beside_a_proven_parent";
    assert_written_as_recorded(&v, name);
    assert_eq!(
        atomic_order(&v, name),
        txids(&v, &["parent", "uncle_mut", "join_mut"])
    );
}

/// The two shapes come from bytes: `Beef::from_binary` collects an entry's
/// index unjudged, as the reference's `Beef.fromBinary` does, so a BEEF of
/// the corpus naming BUMP 1 of 1 (`bad_index.bin`) and one naming a BUMP
/// without its txid (`not_in_bump.bin`) reach the atomic writer, which
/// writes the reference's `toBinaryAtomic` bytes: the entry with no BUMP and
/// no index. PR #809's cold read; before #798 the first was an `Err`
/// (`names BUMP 1 of 1`) and the second kept the BUMP.
#[test]
fn an_index_read_from_bytes_naming_no_matching_bump_is_written_atomic_as_the_reference_798() {
    let v = vector();
    let cases = v["from_bytes_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let path = format!(
            "{}/{}",
            env!("CARGO_MANIFEST_DIR"),
            case["file"].as_str().unwrap()
        );
        let mut read = Beef::from_binary(&std::fs::read(&path).unwrap()).unwrap();
        for atomic in case["atomic"].as_array().unwrap() {
            let subject = atomic["subject"].as_str().unwrap();
            assert_eq!(
                read.find_txid(subject)
                    .unwrap()
                    .bump_index()
                    .map(|i| i as u64),
                atomic["bump_index"].as_u64(),
                "{}: the index read",
                case["name"]
            );
            assert_eq!(
                to_hex(&read.to_binary_atomic(subject).unwrap()),
                atomic["beef"].as_str().unwrap(),
                "{}: the bytes the reference's toBinaryAtomic({subject}) writes",
                case["name"]
            );
        }
    }
}
