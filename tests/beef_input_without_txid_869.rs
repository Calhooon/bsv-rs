//! #869's fourth fold (the cold re-read of the third fold, `b603b27a`): the
//! BEEF linker skipped an input that names no txid (`source_txid` absent),
//! so a source linked through `TransactionInput::with_source_transaction`
//! came back from `find_atomic_transaction` without the merkle path the
//! BEEF's BUMP holds for it, and its own sources were not descended. The
//! reference's `#addInputProof` descends every linked source
//! (`ts-stack@edf6e03` `Beef.ts:649-679`), so the linker now keys such an
//! input by its source's id and walks it as any other.
//!
//! The expected answers are the reference's, recorded by
//! `support/beef_input_without_txid_869.mjs` into
//! `vectors/beef_input_without_txid_869.json` (Node v22.18.0): four states,
//! each built here with this crate's own transactions (the ids are the
//! recording's), merged by `merge_transaction` and linked by
//! `find_atomic_transaction` of the child's id; every source by id and
//! whether it carries a merkle path compared whole.
//!
//! Two cells are stated, not followed. The reference's `mergeTransaction`
//! writes each linked source's id into the input's `sourceTXID` across the
//! caller's graph (`materializeSourceTXIDs`, `Beef.ts:883`,
//! `Transaction.ts:254-271`); this crate stores the transaction as given, so
//! the input comes back naming no txid, its source and path the reference's.
//! An input that links nothing and names nothing (state c) is refused by the
//! reference before any BEEF door (`sourceTransaction is undefined`, at the
//! id and at the merge); here the id writes zeros for that outpoint (the
//! serializer's rule) and the linker leaves the input as it is.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::{json, Value};

const VECTOR: &str = include_str!("vectors/beef_input_without_txid_869.json");

fn reference(state: &str) -> Value {
    let doc: Value = serde_json::from_str(VECTOR).unwrap();
    let states = doc["states"].as_array().unwrap();
    states
        .iter()
        .find(|s| s["state"] == state)
        .cloned()
        .unwrap_or_else(|| panic!("state {state} recorded"))
}

fn empty_unlock() -> Option<UnlockingScript> {
    Some(UnlockingScript::from_binary(&[]).unwrap())
}

fn one(sats: u64) -> TransactionOutput {
    TransactionOutput::new(sats, LockingScript::from_binary(&[0x51]).unwrap())
}

/// The recorder's `root`: one input naming `fill` repeated, one output.
fn root(fill: &str, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    let mut i = TransactionInput::new(fill.repeat(32).parse().unwrap(), 0);
    i.unlocking_script = empty_unlock();
    t.inputs_mut().push(i);
    t.outputs_mut().push(one(sats));
    t
}

/// The recorder's `spend`: one input linking `src`, naming no txid.
fn spend(src: Transaction, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    let mut i = TransactionInput::with_source_transaction(src, 0);
    i.unlocking_script = empty_unlock();
    assert!(i.source_txid.is_none(), "the input names no txid");
    t.inputs_mut().push(i);
    t.outputs_mut().push(one(sats));
    t
}

fn bump(txid: String) -> MerklePath {
    MerklePath::new(100, vec![vec![MerklePathLeaf::new_txid(0, txid)]]).unwrap()
}

/// The recorder's `describe`, three levels of sources deep.
fn describe(t: Option<&Transaction>, depth: u32) -> Value {
    let Some(t) = t else { return Value::Null };
    let inputs: Vec<Value> = t
        .inputs()
        .iter()
        .map(|i| {
            let source = if depth > 0 {
                describe(i.source_transaction.as_deref(), depth - 1)
            } else {
                json!(i.source_transaction.is_some())
            };
            json!({ "sourceTXID": i.source_txid.map(|t| t.to_string()), "source": source })
        })
        .collect();
    json!({ "id": t.id(), "path": t.merkle_path.is_some(), "inputs": inputs })
}

/// The reference's answer with the stated text cell taken out: where this
/// crate's input names no txid and the reference's names its linked
/// source's id (written by `materializeSourceTXIDs` at the merge), the
/// reference's text is read as none. Returns the count of such cells.
fn without_materialized_texts(ours: &Value, theirs: &mut Value) -> usize {
    let mut n = 0;
    let (Some(a), Some(b)) = (ours["inputs"].as_array(), theirs["inputs"].as_array_mut()) else {
        return 0;
    };
    for (x, y) in a.iter().zip(b.iter_mut()) {
        let source_id = y["source"]["id"].clone();
        if x["sourceTXID"].is_null() && !source_id.is_null() && y["sourceTXID"] == source_id {
            y["sourceTXID"] = Value::Null;
            n += 1;
        }
        if y["source"].is_object() {
            n += without_materialized_texts(&x["source"], &mut y["source"]);
        }
    }
    n
}

/// Merges `c` into `beef`, runs `after`, links the child; this crate's
/// answer beside the reference's, the stated text cells taken out.
fn linked(
    state: &str,
    mut beef: Beef,
    c: Transaction,
    after: impl FnOnce(&mut Beef),
) -> (Value, Value, usize) {
    let recorded = reference(state);
    let cid = c.id();
    assert_eq!(
        recorded["childId"],
        json!(cid),
        "state {state}: the child's id"
    );
    beef.merge_transaction(c);
    after(&mut beef);
    let held: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    assert_eq!(
        recorded["held"],
        json!(held),
        "state {state}: the entries held"
    );
    let ours = describe(beef.find_atomic_transaction(&cid).as_ref(), 3);
    let mut theirs = recorded["atomic"].clone();
    let stated = without_materialized_texts(&ours, &mut theirs);
    (ours, theirs, stated)
}

#[test]
fn an_input_naming_no_txid_over_a_proven_source_is_linked_with_the_beefs_path_869() {
    let s = root("11", 1000);
    let mut beef = Beef::new();
    beef.merge_bump(bump(s.id()));
    let (ours, theirs, stated) = linked("a", beef, spend(s, 5), |_| {});
    assert_eq!(theirs["inputs"][0]["source"]["path"], json!(true));
    assert_eq!(ours, theirs, "state a: the source and its path");
    assert_eq!(
        stated, 1,
        "state a: the one input whose text the merge wrote"
    );
}

#[test]
fn an_input_naming_no_txid_over_unproven_sources_two_deep_is_descended_869() {
    let (ours, theirs, stated) = linked(
        "b",
        Beef::new(),
        spend(spend(root("22", 1000), 900), 5),
        |_| {},
    );
    assert_eq!(ours, theirs, "state b: both sources, no path");
    assert_eq!(stated, 2, "state b: two inputs whose text the merge wrote");

    let s0 = root("22", 1000);
    let mut beef = Beef::new();
    beef.merge_bump(bump(s0.id()));
    let (ours, theirs, stated) = linked("b2", beef, spend(spend(s0, 900), 5), |_| {});
    let deepest = &theirs["inputs"][0]["source"]["inputs"][0]["source"];
    assert_eq!(deepest["path"], json!(true));
    assert_eq!(
        ours, theirs,
        "state b2: the deepest source with the BEEF's path"
    );
    assert_eq!(stated, 2, "state b2: two inputs whose text the merge wrote");
}

#[test]
fn an_input_naming_no_txid_over_a_source_the_beef_does_not_hold_keeps_its_own_869() {
    let s = root("33", 1000);
    let sid = s.id();
    let (ours, theirs, stated) = linked("d", Beef::new(), spend(s, 5), |beef| {
        beef.txs.retain(|t| t.txid() != sid);
        beef.reindex();
    });
    assert_eq!(ours, theirs, "state d: its own source, descended, no path");
    assert_eq!(stated, 1);
}

#[test]
fn an_input_linking_nothing_and_naming_nothing_is_left_as_it_is_stated_869() {
    let recorded = reference("c");
    assert_eq!(
        recorded["mergeError"],
        json!("sourceTransaction is undefined")
    );
    assert_eq!(
        recorded["childIdError"],
        json!("sourceTransaction is undefined")
    );
    let mut c = Transaction::new();
    let i = TransactionInput {
        source_txid: None,
        source_transaction: None,
        unlocking_script: empty_unlock(),
        ..Default::default()
    };
    c.inputs_mut().push(i);
    c.outputs_mut().push(one(5));
    let cid = c.id();
    let mut beef = Beef::new();
    beef.merge_transaction(c);
    let a = beef.find_atomic_transaction(&cid).unwrap();
    assert_eq!(a.id(), cid);
    assert!(a.inputs()[0].source_txid.is_none());
    assert!(a.inputs()[0].source_transaction.is_none());
}

#[test]
fn the_reference_writes_the_sources_id_into_the_input_at_the_merge_stated_869() {
    let recorded = reference("a");
    let input = &recorded["atomic"]["inputs"][0];
    assert_eq!(input["sourceTXID"], input["source"]["id"]);
    let s = root("11", 1000);
    let mut beef = Beef::new();
    beef.merge_bump(bump(s.id()));
    let c = spend(s, 5);
    let cid = c.id();
    beef.merge_transaction(c);
    let a = beef.find_atomic_transaction(&cid).unwrap();
    assert!(a.inputs()[0].source_txid.is_none(), "stored as given");
    assert_eq!(
        json!(a.inputs()[0].source_transaction.as_ref().unwrap().id()),
        input["source"]["id"]
    );
}
