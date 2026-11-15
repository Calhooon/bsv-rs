//! #818: the BEEFs of `tests/vectors/identity_evidence_818.json`, built by
//! this crate's writer as `tests/support/identity_evidence_818.mjs` builds
//! them with the reference's: an Atomic BEEF prefix naming the subject
//! (`0x01010101`, its txid reversed) by `primitives::Writer`, then the
//! frame written element by element (`MerklePath::to_writer`,
//! `BeefTx::to_writer`), unsorted: `n` txid-only entries (`00..01` up), the
//! entry `00..01` again, then #730's subject raw under a BUMP of its own at
//! 900 (no merge writes one txid twice: `merge_txid_only` deduplicates, as
//! the reference's does; until #843b the entries were set by hand on the
//! public `txs` and written by `Beef::to_writer`). Read by the check's unit pin
//! (`src/identity/evidence_818_tests.rs`, `use crate as sdk;`).
#![allow(dead_code, clippy::unwrap_used)]

use super::sdk::primitives::{from_hex, Writer};
use super::sdk::script::{LockingScript, UnlockingScript};
use super::sdk::transaction::{
    BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
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
    build_repeating(n, false)
}

/// A V2 BEEF frame of `bumps` and `entries` as given, each written by this
/// crate's own writer (`MerklePath::to_writer`, `BeefTx::to_writer`), in
/// the order given: the form that carries one txid twice, which no merge
/// door holds (#843b: until then the entries were pushed by hand onto the
/// public `txs` and written by `Beef::to_writer`).
fn frame(writer: &mut Writer, bumps: &[MerklePath], entries: &[BeefTx]) {
    const BEEF_V2: u32 = 0xEFBE_0002;
    writer.write_u32_le(BEEF_V2);
    writer.write_var_int(bumps.len() as u64);
    for bump in bumps {
        bump.to_writer(writer).expect("the BUMP is writable");
    }
    writer.write_var_int(entries.len() as u64);
    for entry in entries {
        entry
            .to_writer(writer, BEEF_V2)
            .expect("the entry is writable");
    }
}

/// As [`build`], the entry written twice the proven subject, raw, when `raw`
/// (#907's two shapes), else the txid-only `00..01`.
pub fn build_repeating(n: usize, raw: bool) -> Vec<u8> {
    let subject = subject();
    let bump = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, subject.id())]]).unwrap();
    let index = 0;
    let numbered = |i: usize| BeefTx::from_txid(format!("{i:064x}").parse().unwrap());
    let mut entries: Vec<BeefTx> = (1..=n).map(numbered).collect();
    entries.push(if raw {
        BeefTx::from_raw_tx(subject.to_binary(), Some(index))
            .expect("the bytes are one transaction")
    } else {
        numbered(1)
    });
    entries.push(
        BeefTx::from_raw_tx(subject.to_binary(), Some(index))
            .expect("the bytes are one transaction"),
    );
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut reversed = from_hex(&subject.id()).unwrap();
    reversed.reverse();
    writer.write_bytes(&reversed);
    frame(&mut writer, &[bump], &entries);
    writer.into_bytes()
}
