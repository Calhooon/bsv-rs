//! #741: the BEEFs of `tests/vectors/identity_evidence_741.json`, built by
//! this crate's writer as `tests/support/identity_evidence_741.mjs` builds
//! them with the reference's: a subject of 2 inputs spending two unproven
//! parents P1 and P2, each spending its own outputs of one proven
//! grandparent with no inputs. Shared by the door test
//! (`tests/identity_evidence_741.rs`, `use bsv_rs as sdk;`) and the check's
//! unit pins (`src/identity/evidence_741_tests.rs`, `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_741.json")).unwrap()
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
fn token() -> LockingScript {
    let v: Value = serde_json::from_str(include_str!(
        "../vectors/identity_certificate_record_553.json"
    ))
    .unwrap();
    LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap()).unwrap()
}

fn op_true() -> LockingScript {
    LockingScript::from_hex("51").unwrap()
}

/// One input spending `txid:vout` with an empty unlocking script.
fn input(txid: &str, vout: u32) -> TransactionInput {
    let mut input = TransactionInput::new(txid.parse().unwrap(), vout);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    input
}

/// A shape's BEEF, its subject and the three transactions under it.
pub struct Built {
    /// The bytes.
    pub beef: Vec<u8>,
    /// The subject's txid.
    pub subject: String,
    /// The proven grandparent's txid.
    pub g: String,
    /// P1's txid.
    pub p1: String,
    /// P2's txid.
    pub p2: String,
}

/// The vector's shape `name`: P1 of the vector's `p1_inputs`, P2 of the
/// shape's `size`.
pub fn build(name: &str) -> Built {
    let p1 = vector()["p1_inputs"].as_u64().unwrap() as usize;
    let p2 = case(name)["size"].as_u64().unwrap() as usize;
    two_branches(p1, p2)
}

/// The proven grandparent with no inputs and `p1 + p2` outputs, P1 spending
/// its outputs 0 to `p1 - 1` and P2 the next `p2`, each parent one output,
/// the subject spending output 0 of P1 then of P2.
fn two_branches(p1: usize, p2: usize) -> Built {
    let mut g = Transaction::new();
    for _ in 0..p1 + p2 {
        g.add_output(TransactionOutput::new(1, op_true())).unwrap();
    }
    let g_txid = g.id();
    let parent = |from: usize, count: usize| {
        let mut tx = Transaction::new();
        for i in from..from + count {
            tx.add_input(input(&g_txid, i as u32)).unwrap();
        }
        tx.add_output(TransactionOutput::new(1, op_true())).unwrap();
        tx
    };
    let first = parent(0, p1);
    let second = parent(p1, p2);
    let mut subject = Transaction::new();
    subject.add_input(input(&first.id(), 0)).unwrap();
    subject.add_input(input(&second.id(), 0)).unwrap();
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(first.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(second.to_binary(), None)
        .expect("the bytes are one transaction");
    let leaf = MerklePathLeaf::new_txid(0, g_txid.clone());
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(g.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    Built {
        beef: beef.to_binary().expect("the BEEF is writable"),
        subject: subject.id(),
        g: g_txid,
        p1: first.id(),
        p2: second.id(),
    }
}
