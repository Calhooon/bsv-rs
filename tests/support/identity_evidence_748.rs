//! #748: the BEEFs of `tests/vectors/identity_evidence_748.json`, built by
//! this crate's writer as `tests/support/identity_evidence_748.mjs` builds
//! them with the reference's: a subject spending P1:0 and P2:0, both
//! unproven, P1 spending G:0 and P2 G:1, so the walk reaches G twice; G
//! unproven over a proven GG (`shared_unproven_grandparent`), or G proven
//! with 4092 inputs whose sources are absent
//! (`proven_grandparent_reached_twice`). Shared by the door test
//! (`tests/identity_evidence_748.rs`, `use bsv_rs as sdk;`) and the check's
//! unit pins (`src/identity/evidence_748_tests.rs`, `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_748.json")).unwrap()
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

/// A transaction spending each `(txid, vout)` of `sources` with an empty
/// unlocking script, with `outputs` outputs of `satoshis` to `OP_TRUE`.
fn spending(sources: &[(String, u32)], outputs: usize, satoshis: u64) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in sources {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
        tx.add_input(input).unwrap();
    }
    for _ in 0..outputs {
        let script = LockingScript::from_hex("51").unwrap();
        tx.add_output(TransactionOutput::new(satoshis, script))
            .unwrap();
    }
    tx
}

/// `tx` merged raw with a BUMP of its own at height 900: a lone leaf at
/// offset 0.
fn merge_proven(beef: &mut Beef, tx: &Transaction) {
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
}

/// A shape's BEEF, its subject and the transactions under it.
pub struct Built {
    /// The bytes.
    pub beef: Vec<u8>,
    /// The subject's txid.
    pub subject: String,
    /// P1's txid.
    pub p1: String,
    /// P2's txid.
    pub p2: String,
    /// G's txid, the grandparent both parents spend.
    pub g: String,
    /// GG's txid, under an unproven G; `None` where G is proven.
    pub gg: Option<String>,
}

/// The vector's shape `name`.
pub fn build(name: &str) -> Built {
    match name {
        "shared_unproven_grandparent" => {
            // GG's one output of 2 satoshis, G's two of 1.
            let gg = spending(&[], 1, 2);
            let g = spending(&[(gg.id(), 0)], 2, 1);
            two_parents_of(&g, Some(&gg))
        }
        "proven_grandparent_reached_twice" => {
            let v = vector();
            let absent = v["absent_source_txid"].as_str().unwrap().to_string();
            let count = v["g_inputs"].as_u64().unwrap() as u32;
            let sources: Vec<_> = (0..count).map(|i| (absent.clone(), i)).collect();
            two_parents_of(&spending(&sources, 2, 1), None)
        }
        _ => panic!("no shape {name}"),
    }
}

/// P1 spending G:0 and P2 G:1, the subject spending P1:0 then P2:0, its
/// output the reference's token; merged the subject, P1, P2, then G raw
/// over a proven `gg`, or G proven where `gg` is `None`.
fn two_parents_of(g: &Transaction, gg: Option<&Transaction>) -> Built {
    let g_txid = g.id();
    let p1_tx = spending(&[(g_txid.clone(), 0)], 1, 1);
    let p2_tx = spending(&[(g_txid.clone(), 1)], 1, 1);
    let mut subject = spending(&[(p1_tx.id(), 0), (p2_tx.id(), 0)], 0, 1);
    subject
        .add_output(TransactionOutput::new(1, token()))
        .unwrap();
    let mut beef = Beef::new();
    beef.merge_raw_tx(subject.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(p1_tx.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(p2_tx.to_binary(), None)
        .expect("the bytes are one transaction");
    match gg {
        Some(gg) => {
            beef.merge_raw_tx(g.to_binary(), None)
                .expect("the bytes are one transaction");
            merge_proven(&mut beef, gg);
        }
        None => merge_proven(&mut beef, g),
    }
    Built {
        beef: beef.to_binary().expect("the BEEF is writable"),
        subject: subject.id(),
        p1: p1_tx.id(),
        p2: p2_tx.id(),
        g: g_txid,
        gg: gg.map(Transaction::id),
    }
}
