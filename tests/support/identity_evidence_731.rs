//! #731: the BEEFs of `tests/vectors/identity_evidence_731.json`, built by
//! this crate's writer as `tests/support/identity_evidence_731.mjs` builds
//! them with the reference's: an Atomic BEEF prefix naming the subject X
//! (`0x01010101`, X's txid reversed) by `primitives::Writer`, then
//! `Beef::to_writer` over `txs` set by hand, unsorted, X written raw and
//! txid-only in the order the shape names (no merge writes both entries:
//! `merge_raw_tx` and `merge_txid_only` deduplicate, as the reference's
//! do). Over #725's transactions: `alone` proven at 900 alone, or `parent`
//! proven at 900 and the unproven `subject` spending it. Shared by the door
//! test (`tests/identity_evidence_731.rs`, `use bsv_rs as sdk;`) and the
//! check's unit pins (`src/identity/evidence_731_tests.rs`,
//! `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::primitives::{from_hex, Writer};
use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_731.json")).unwrap()
}

/// The vector's shape `name`.
pub fn case(name: &str) -> Value {
    vector()["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no shape {name}"))
        .clone()
}

/// The vector's four shape names, in its order.
pub fn names() -> Vec<String> {
    vector()["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect()
}

/// The reference's own revelation token (#553's vector).
fn token() -> LockingScript {
    let v: Value = serde_json::from_str(include_str!(
        "../vectors/identity_certificate_record_553.json"
    ))
    .unwrap();
    LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap()).unwrap()
}

/// One input spending `txid:0` with `unlocking`, one 1-satoshi output.
fn spending(txid: String, unlocking: &str, lock: LockingScript) -> Transaction {
    let mut input = TransactionInput::new(txid, 0);
    input.set_unlocking_script(UnlockingScript::from_hex(unlocking).unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, lock)).unwrap();
    tx
}

/// A block of `txid` alone at `height`: its BUMP a lone leaf at offset 0.
fn lone_leaf(txid: &str, height: u32) -> MerklePath {
    MerklePath::new(
        height,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// #725's `alone`: `11..11:0` spent with `OP_TRUE`, locked by the token.
pub fn alone() -> Transaction {
    spending("11".repeat(32), "51", token())
}

/// #725's `parent`: `11..11:0` spent with `OP_TRUE`, locked by `OP_TRUE`.
pub fn parent() -> Transaction {
    spending(
        "11".repeat(32),
        "51",
        LockingScript::from_hex("51").unwrap(),
    )
}

/// #725's `subject`: `parent:0` spent with an empty script, locked by the
/// token.
pub fn subject() -> Transaction {
    spending(parent().id(), "", token())
}

/// A shape's BEEF and subject.
pub struct Built {
    /// The bytes.
    pub beef: Vec<u8>,
    /// X's txid.
    pub subject: String,
}

/// The shape `name` built.
pub fn build(name: &str) -> Built {
    let (proven_subject, raw_first) = match name {
        "proven_subject_raw_then_txid_only" => (true, true),
        "proven_subject_txid_only_then_raw" => (true, false),
        "unproven_subject_raw_then_txid_only" => (false, true),
        "unproven_subject_txid_only_then_raw" => (false, false),
        other => panic!("no shape {other}"),
    };
    let (proven, x) = if proven_subject {
        (alone(), alone())
    } else {
        (parent(), subject())
    };
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(&proven.id(), 900));
    // X's raw entry: proven by the BUMP when X is `alone`, unproven else.
    let x_raw = BeefTx::from_raw_tx(x.to_binary(), proven_subject.then_some(index))
        .expect("the bytes are one transaction");
    let x_txid_only = BeefTx::from_txid(x.id());
    if !proven_subject {
        beef.txs.push(
            BeefTx::from_raw_tx(proven.to_binary(), Some(index))
                .expect("the bytes are one transaction"),
        );
    }
    if raw_first {
        beef.txs.extend([x_raw, x_txid_only]);
    } else {
        beef.txs.extend([x_txid_only, x_raw]);
    }
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut reversed = from_hex(&x.id()).unwrap();
    reversed.reverse();
    writer.write_bytes(&reversed);
    beef.to_writer(&mut writer).expect("the BEEF is writable");
    Built {
        beef: writer.into_bytes(),
        subject: x.id(),
    }
}
