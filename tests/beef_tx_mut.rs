//! An entry mutated through `BeefTx::tx_mut` is one thing to every reader
//! (#171).
//!
//! `BeefTx` caches the txids its inputs spend (`input_txids`) and keeps the
//! bytes and the txid it was read with. Until #171 `tx_mut` refreshed none of
//! them: after a caller pointed an input elsewhere, `sort_txs` and
//! `verify_structure` read the old list, `to_binary_atomic`'s closure read the
//! new transaction under the old name, and the writer emitted the bytes the
//! entry was read with. Now the mutated transaction is the entry's only
//! reading, as `@bsv/sdk` 3 makes it (`ts-stack@4d0ea63`
//! `BeefTx.ts:160-177` `syncRawTxFromTransaction`, `Beef.ts:342-351`): the
//! entry is named by the mutated transaction's hash, the wire carries its
//! serialization, and each whole-BEEF reader refreshes the input list and the
//! BEEF's index ahead of its walk.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::Kind;
use bsv_rs::transaction::{
    Beef, MerklePath, Transaction, TransactionInput, TransactionOutput, BEEF_V1,
};

/// A transaction with one `OP_TRUE` output of 1,000 satoshis spending
/// output 0 of `spends`, with an empty unlocking script.
fn tx(spends: &str) -> Transaction {
    let mut t = Transaction::new();
    let mut input = TransactionInput::new(spends.to_string(), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    t.inputs.push(input);
    t.outputs.push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// A BEEF V1 with `bumps` and the raw `entries` in the order given, by the
/// crate's own writer; `proven` pairs an entry with the BUMP that proves it.
fn write(bumps: &[MerklePath], entries: &[&[u8]], proven: &[(usize, u64)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32_le(BEEF_V1);
    w.write_var_int(bumps.len() as u64);
    for bump in bumps {
        w.write_bytes(&bump.to_binary());
    }
    w.write_var_int(entries.len() as u64);
    for (i, raw) in entries.iter().enumerate() {
        w.write_bytes(raw);
        if let Some(&(_, bump)) = proven.iter().find(|(entry, _)| *entry == i) {
            w.write_u8(1);
            w.write_var_int(bump);
        } else {
            w.write_u8(0);
        }
    }
    w.into_bytes()
}

/// `P` and `Q` spend two placeholders, each proven by a BUMP of its own;
/// `C` spends `P`. Read from bytes in the order `P, C, Q`, then `C`'s input
/// pointed at `Q` through `tx_mut`. Returns the BEEF, `P`, `Q`, `C` as read,
/// and `C` as mutated.
fn repointed() -> (Beef, Transaction, Transaction, Transaction, Transaction) {
    let p = tx(&"e5".repeat(32));
    let q = tx(&"e6".repeat(32));
    let c = tx(&p.id());
    let raws = [p.to_binary(), c.to_binary(), q.to_binary()];
    let entries: Vec<&[u8]> = raws.iter().map(Vec::as_slice).collect();
    let bumps = [
        MerklePath::from_coinbase_txid(&p.id(), 900_000),
        MerklePath::from_coinbase_txid(&q.id(), 900_001),
    ];
    let mut beef = Beef::from_binary(&write(&bumps, &entries, &[(0, 0), (2, 1)])).unwrap();
    assert!(beef.clone().verify_structure().is_ok());
    let entry = beef.find_txid_mut(&c.id()).unwrap();
    entry.tx_mut().unwrap().inputs[0].source_txid = Some(q.id());
    let mut mutated = c.clone();
    mutated.inputs[0].source_txid = Some(q.id());
    // `Transaction` caches its hash; a direct field edit asks for this.
    mutated.invalidate_caches();
    (beef, p, q, c, mutated)
}

#[test]
fn an_input_repointed_through_tx_mut_is_what_every_reader_reads() {
    let (beef, p, q, c, mutated) = repointed();
    assert_ne!(mutated.id(), c.id());

    // The entry is named by the mutated transaction's hash and spends `Q`.
    let mut sorted = beef.clone();
    let sr = sorted.sort_txs();
    assert!(sr.missing_inputs.is_empty(), "{:?}", sr.missing_inputs);
    assert!(sr.not_valid.is_empty(), "{:?}", sr.not_valid);
    let entry = sorted
        .find_txid(&mutated.id())
        .expect("found by its new txid");
    assert_eq!(
        entry.input_txids,
        vec![q.id()],
        "the cache reads the new input"
    );
    assert!(sorted.find_txid(&c.id()).is_none(), "the old name is gone");
    // The sort places it after `Q`, the parent it now has.
    let order: Vec<String> = sorted.txs.iter().map(|t| t.txid()).collect();
    let at = |id: &str| order.iter().position(|t| t == id).unwrap();
    assert!(at(&q.id()) < at(&mutated.id()), "{order:?}");

    // The whole-path judge reads the new input: `C` now names `Q`, held
    // after it, which the sort reads whatever the order (bsv-rs#240; from
    // #86 to #240 `InputNamesNoElement` in the order held). Sorted or not,
    // the BEEF is well formed; the refresh itself is pinned by the cache and
    // the order above, and by the input repointed outside the BEEF below.
    assert!(beef.clone().verify_structure().is_ok());
    assert!(sorted.verify_structure().is_ok());

    // The atomic writer finds the subject by its new txid, and its closure
    // is `Q` (proven) and the subject: `P` is no longer an ancestor.
    let atomic = beef.clone().to_binary_atomic(&mutated.id()).unwrap();
    let reread = Beef::from_binary(&atomic).unwrap();
    let ids: Vec<String> = reread.txs.iter().map(|t| t.txid()).collect();
    assert_eq!(ids, vec![q.id(), mutated.id()]);
    assert!(Transaction::from_atomic_beef(&atomic).unwrap().id() == mutated.id());

    // The written bytes carry the mutated transaction, and read back they
    // are the BEEF the readers judged.
    let bytes = beef.clone().to_binary();
    let hex = to_hex(&bytes);
    assert!(
        hex.contains(&mutated.to_hex()),
        "the wire carries the mutation"
    );
    assert!(!hex.contains(&c.to_hex()), "and not the bytes read");
    let mut back = Beef::from_binary(&bytes).unwrap();
    assert!(back.verify_structure().is_ok());
    assert_eq!(
        back.find_txid(&mutated.id()).unwrap().input_txids,
        vec![q.id()]
    );
    assert!(back.find_txid(&p.id()).is_some());
}

#[test]
fn an_input_repointed_outside_the_beef_through_tx_mut_is_missing() {
    let (mut beef, _, _, c, mutated) = repointed();
    // The old name finds nothing; the new one is indexed by the next
    // whole-BEEF reader.
    assert!(beef.find_txid(&c.id()).is_none());
    assert!(beef.find_txid(&mutated.id()).is_none());
    assert!(beef.sort_txs().missing_inputs.is_empty());
    // A second mutation of the same entry, found by its new name.
    let outside = "f0".repeat(32);
    let entry = beef.find_txid_mut(&mutated.id()).unwrap();
    entry.tx_mut().unwrap().inputs[0].source_txid = Some(outside.clone());
    let sr = beef.clone().sort_txs();
    assert_eq!(sr.missing_inputs, vec![outside]);
    assert_eq!(
        beef.verify_structure().err(),
        Some(Kind::InputNamesNoElement)
    );
}

#[test]
fn a_proven_entry_mutated_through_tx_mut_keeps_its_bump_index_and_is_not_proven() {
    // `P` proven by BUMP 0; mutated, its hash leaves the BUMP's leaf, and
    // the pinned index names a BUMP that does not carry it.
    let p = tx(&"e5".repeat(32));
    let bump = MerklePath::from_coinbase_txid(&p.id(), 900_000);
    let raw = p.to_binary();
    let mut beef = Beef::from_binary(&write(&[bump], &[raw.as_slice()], &[(0, 0)])).unwrap();
    assert!(beef.clone().verify_structure().is_ok());
    let entry = beef.find_txid_mut(&p.id()).unwrap();
    entry.tx_mut().unwrap().outputs[0].satoshis = Some(999);
    assert_eq!(entry.bump_index(), Some(0));
    assert_eq!(
        beef.clone().verify_structure().err(),
        Some(Kind::TxidNotInBump)
    );
    let bytes = beef.to_binary();
    assert_eq!(
        Beef::from_binary(&bytes).unwrap().verify_structure().err(),
        Some(Kind::TxidNotInBump),
        "the wire carries the mutated bytes under the same BUMP index"
    );
}
