//! #730: the BEEFs of `tests/vectors/identity_evidence_730.json`, built by
//! this crate's writer as `tests/support/identity_evidence_730.mjs` builds
//! them with the reference's. Shared by the door test
//! (`tests/identity_evidence_730.rs`, `use bsv_rs as sdk;`) and the check's
//! unit pins (`src/identity/evidence_730_tests.rs`, `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::primitives::{from_hex, Writer};
use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_730.json")).unwrap()
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

/// An Atomic BEEF prefix naming `txid` by hand before `beef`'s bytes.
fn atomic(txid: &str, beef: &mut Beef) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut subject = from_hex(txid).unwrap();
    subject.reverse();
    writer.write_bytes(&subject);
    writer.write_bytes(&beef.to_binary());
    writer.into_bytes()
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
    let size = || size.unwrap();
    let (beef, subject) = match name {
        "second_spend_in_graph" => second_spend(),
        "unproven_no_inputs" => no_inputs(),
        "inputs_at_bound" | "inputs_over_bound" => inputs(size()),
        "script_bytes_at_bound" | "script_bytes_over_bound" => script_bytes(size()),
        "transactions_at_bound" | "transactions_over_bound" => transactions(size()),
        "candidate_bytes_at_bound" | "candidate_bytes_over_bound" => candidate_bytes(size()),
        "proven_parent_absent_grandparent" => proven_parent(),
        "bump_names_another_txid_grandparent_proven" => another_bump_grandparent_proven(),
        other => panic!("no shape {other}"),
    };
    Built { beef, subject }
}

fn second_spend() -> (Vec<u8>, String) {
    let g = grandparent();
    let a = spending(g.id(), "51", op_true());
    let b = spending(g.id(), "52", op_true());
    let mut subject = Transaction::new();
    for parent in [&a, &b] {
        subject.add_input(input(parent.id(), 0, "")).unwrap();
    }
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    beef.merge_raw_tx(a.to_binary(), None);
    beef.merge_raw_tx(b.to_binary(), None);
    proven(&mut beef, &g, 900);
    (beef.to_binary(), subject.id())
}

fn no_inputs() -> (Vec<u8>, String) {
    let mut subject = Transaction::new();
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    (beef.to_binary(), subject.id())
}

fn inputs(n: usize) -> (Vec<u8>, String) {
    let mut subject = Transaction::new();
    for i in 0..n {
        subject
            .add_input(input("11".repeat(32), i as u32, ""))
            .unwrap();
    }
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    proven(&mut beef, &subject, 900);
    (beef.to_binary(), subject.id())
}

fn script_bytes(n: usize) -> (Vec<u8>, String) {
    let mut subject = spending("11".repeat(32), "", token());
    subject
        .add_output(TransactionOutput::new(0, padding(n)))
        .unwrap();
    let mut beef = Beef::new();
    proven(&mut beef, &subject, 900);
    (beef.to_binary(), subject.id())
}

fn transactions(n: usize) -> (Vec<u8>, String) {
    let subject = spending("11".repeat(32), "", token());
    let mut beef = Beef::new();
    for i in 1..=n {
        beef.merge_txid_only(format!("{i:064x}"));
    }
    proven(&mut beef, &subject, 900);
    (atomic(&subject.id(), &mut beef), subject.id())
}

fn candidate_bytes(n: usize) -> (Vec<u8>, String) {
    let subject = spending("11".repeat(32), "", token());
    let mut outside = spending("44".repeat(32), "", op_true());
    outside
        .add_output(TransactionOutput::new(0, padding(n)))
        .unwrap();
    let mut beef = Beef::new();
    proven(&mut beef, &subject, 900);
    proven(&mut beef, &outside, 901);
    (atomic(&subject.id(), &mut beef), subject.id())
}

fn proven_parent() -> (Vec<u8>, String) {
    let g = grandparent();
    let subject = spending(g.id(), "", token());
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None);
    proven(&mut beef, &g, 900);
    (beef.to_binary(), subject.id())
}

/// #728's shape 4 with the grandparent present raw and proven by its own
/// BUMP: the parent's entry names a BUMP whose one leaf is `33..33`.
fn another_bump_grandparent_proven() -> (Vec<u8>, String) {
    let g = grandparent();
    let parent = spending(g.id(), "", op_true());
    let subject = spending(parent.id(), "", token());
    let mut beef = Beef::new();
    let index = beef.merge_bump(lone_leaf(&"33".repeat(32), 901));
    beef.merge_raw_tx(parent.to_binary(), Some(index));
    proven(&mut beef, &g, 900);
    beef.merge_raw_tx(subject.to_binary(), None);
    (beef.to_binary(), subject.id())
}
