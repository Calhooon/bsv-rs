//! #736: the BEEFs of `tests/vectors/identity_evidence_736.json`, built by
//! this crate's writer as `tests/support/identity_evidence_736.mjs` builds
//! them with the reference's. Shared by the door test
//! (`tests/identity_evidence_736.rs`, `use bsv_rs as sdk;`) and the check's
//! unit pins (`src/identity/evidence_736_tests.rs`, `use crate as sdk;`).
//! The two shapes of one parent written twice are written by
//! `Beef::to_writer` over `txs` set by hand, unsorted, as the recorder
//! writes them by `Beef.toWriter`: no merge writes both entries.
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::primitives::Writer;
use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_736.json")).unwrap()
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

/// The reference's own revelation token (#553's vector).
pub fn token() -> LockingScript {
    let v: Value = serde_json::from_str(include_str!(
        "../vectors/identity_certificate_record_553.json"
    ))
    .unwrap();
    LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap()).unwrap()
}

/// One input spending `txid:vout` with `unlocking`.
fn input(txid: String, vout: u32, unlocking: &str) -> TransactionInput {
    let mut input = TransactionInput::new(txid, vout);
    input.set_unlocking_script(UnlockingScript::from_hex(unlocking).unwrap());
    input
}

/// One input spending `txid:0` with `unlocking`, one 1-satoshi output.
fn spending(txid: String, unlocking: &str, lock: LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.add_input(input(txid, 0, unlocking)).unwrap();
    tx.add_output(TransactionOutput::new(1, lock)).unwrap();
    tx
}

fn op_true() -> LockingScript {
    LockingScript::from_hex("51").unwrap()
}

/// A block of `txid` alone at `height`: its BUMP a lone leaf at offset 0.
fn lone_leaf(txid: &str, height: u32) -> MerklePath {
    MerklePath::new(
        height,
        vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
    )
    .unwrap()
}

/// `tx` merged raw with a BUMP of its own at `height`.
fn proven(beef: &mut Beef, tx: &Transaction, height: u32) {
    let index = beef.merge_bump(lone_leaf(&tx.id(), height));
    beef.merge_raw_tx(tx.to_binary(), Some(index));
}

/// A push of `n` zero bytes under OP_PUSHDATA4, as a locking script.
fn padding(n: usize) -> LockingScript {
    let mut writer = Writer::new();
    writer.write_u8(0x4e);
    writer.write_u32_le(n as u32);
    writer.write_bytes(&vec![0u8; n]);
    LockingScript::from_binary(&writer.into_bytes()).unwrap()
}

/// The recorder's grandparent, `22..22:0` spent with `OP_TRUE`.
pub fn grandparent() -> Transaction {
    spending("22".repeat(32), "51", op_true())
}

/// A shape's BEEF and subject.
pub struct Built {
    /// The bytes.
    pub beef: Vec<u8>,
    /// The subject's txid.
    pub subject: String,
}

/// `name`'s BEEF at the vector's `size`.
pub fn build(name: &str, size: Option<usize>) -> Built {
    let v = vector();
    let subject_inputs = v["subject_inputs"].as_u64().unwrap() as usize;
    let subject_padding = v["subject_padding"].as_u64().unwrap() as usize;
    let size = || size.unwrap();
    let (beef, subject) = match name {
        "graph_inputs_over_bound" | "graph_inputs_at_bound" => graph_inputs(subject_inputs, size()),
        "graph_script_bytes_over_bound" | "graph_script_bytes_at_bound" => {
            graph_script_bytes(subject_padding, size())
        }
        "parent_raw_then_txid_only" => parent_twice(true),
        "parent_txid_only_then_raw" => parent_twice(false),
        other => panic!("no shape {other}"),
    };
    Built { beef, subject }
}

/// A proven grandparent with no inputs and `parent_inputs` outputs, an
/// unproven parent spending each with `subject_inputs` outputs, the
/// unproven subject spending each of those.
fn graph_inputs(subject_inputs: usize, parent_inputs: usize) -> (Vec<u8>, String) {
    let mut g = Transaction::new();
    for _ in 0..parent_inputs {
        g.add_output(TransactionOutput::new(1, op_true())).unwrap();
    }
    let mut parent = Transaction::new();
    let g_txid = g.id();
    for i in 0..parent_inputs {
        parent
            .add_input(input(g_txid.clone(), i as u32, ""))
            .unwrap();
    }
    for _ in 0..subject_inputs {
        parent
            .add_output(TransactionOutput::new(1, op_true()))
            .unwrap();
    }
    let parent_txid = parent.id();
    let mut subject = Transaction::new();
    for i in 0..subject_inputs {
        subject
            .add_input(input(parent_txid.clone(), i as u32, ""))
            .unwrap();
    }
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    beef.merge_raw_tx(parent.to_binary(), None);
    proven(&mut beef, &g, 900);
    (beef.to_binary(), subject.id())
}

/// The unproven subject's scripts the token and `subject_padding` bytes
/// pushed; its proven parent's the unlocking `51`, the locking `51` and
/// `n` bytes pushed.
fn graph_script_bytes(subject_padding: usize, n: usize) -> (Vec<u8>, String) {
    let mut parent = spending("22".repeat(32), "51", op_true());
    parent
        .add_output(TransactionOutput::new(0, padding(n)))
        .unwrap();
    let mut subject = spending(parent.id(), "", token());
    subject
        .add_output(TransactionOutput::new(0, padding(subject_padding)))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    proven(&mut beef, &parent, 900);
    (beef.to_binary(), subject.id())
}

/// The proven grandparent, the parent raw and txid-only (`raw_before`
/// naming the order), the subject: `txs` set by hand and written by
/// `to_writer`, unsorted.
fn parent_twice(raw_before: bool) -> (Vec<u8>, String) {
    let g = grandparent();
    let parent = spending(g.id(), "", op_true());
    let subject = spending(parent.id(), "", token());
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(&g.id(), 900));
    let raw = BeefTx::from_raw_tx(parent.to_binary(), None);
    let txid_only = BeefTx::from_txid(parent.id());
    beef.txs
        .push(BeefTx::from_raw_tx(g.to_binary(), Some(index)));
    if raw_before {
        beef.txs.extend([raw, txid_only]);
    } else {
        beef.txs.extend([txid_only, raw]);
    }
    beef.txs
        .push(BeefTx::from_raw_tx(subject.to_binary(), None));
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    (writer.into_bytes(), subject.id())
}
