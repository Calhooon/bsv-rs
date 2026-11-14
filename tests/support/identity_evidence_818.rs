//! #818: the BEEFs of `tests/vectors/identity_evidence_818.json`, built by
//! this crate's writer as `tests/support/identity_evidence_818.mjs` builds
//! them with the reference's: an Atomic BEEF prefix naming the subject
//! (`0x01010101`, its txid reversed) by `primitives::Writer`, then
//! `Beef::to_writer` over `txs` set by hand, unsorted: `n` txid-only entries
//! (`00..01` up), the entry `00..01` again, then #730's subject raw under a
//! BUMP of its own at 900 (no merge writes one txid twice: `merge_txid_only`
//! deduplicates, as the reference's does). Read by the check's unit pin
//! (`src/identity/evidence_818_tests.rs`, `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::primitives::{from_hex, Writer};
use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::Value;

/// The vector.
pub fn vector() -> Value {
    serde_json::from_str(include_str!("../vectors/identity_evidence_818.json")).unwrap()
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

/// #730's subject: `11..11:0` spent with an empty script, one 1-satoshi
/// output locked by the reference's own revelation token (#553's vector).
pub fn subject() -> Transaction {
    let v: Value = serde_json::from_str(include_str!(
        "../vectors/identity_certificate_record_553.json"
    ))
    .unwrap();
    let token = LockingScript::from_hex(v["cases"][0]["locking_script"].as_str().unwrap()).unwrap();
    let mut input = TransactionInput::new("11".repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, token)).unwrap();
    tx
}

/// The BEEF of `n` txid-only entries, the entry `00..01` again and the
/// proven subject, under an Atomic prefix naming the subject.
pub fn build(n: usize) -> Vec<u8> {
    let subject = subject();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, subject.id())]]).unwrap(),
    );
    beef.txs
        .extend((1..=n).map(|i| BeefTx::from_txid(format!("{i:064x}"))));
    beef.txs.push(BeefTx::from_txid(format!("{:064x}", 1)));
    beef.txs.push(
        BeefTx::from_raw_tx(subject.to_binary(), Some(index))
            .expect("the bytes are one transaction"),
    );
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut reversed = from_hex(&subject.id()).unwrap();
    reversed.reverse();
    writer.write_bytes(&reversed);
    beef.to_writer(&mut writer).expect("the BEEF is writable");
    writer.into_bytes()
}
