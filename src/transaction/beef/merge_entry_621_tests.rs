#![cfg(test)]
//! #621: `Beef::merge_beef` stores a source raw entry under the txid the
//! entry holds, no second hash of its bytes.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test code: a failed unwrap is the test failing

use crate::primitives::{sha256d, to_hex};
use crate::script::LockingScript;
use crate::transaction::beef_tx::BeefTx;
use crate::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};

/// A one-input, one-output transaction's bytes.
fn raw() -> Vec<u8> {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1_000, LockingScript::new()))
        .unwrap();
    tx.to_binary()
}

/// The display txid of `bytes`.
fn hash_of(bytes: &[u8]) -> String {
    let mut h = sha256d(bytes);
    h.reverse();
    to_hex(&h)
}

/// The source entry holds a sentinel txid that is NOT its bytes' hash, an
/// entry no reachable state carries (`with_txid` is crate-private and every
/// caller passes the bytes' hash): it breaks the invariant on purpose, the
/// one observable proof that the merge took the entry's txid and ran no
/// hash. On the base, `merge_beef` re-hashed the bytes and filed the entry
/// under the hash, so the sentinel was not found.
#[test]
fn merge_beef_keeps_the_source_entrys_txid_621() {
    let bytes = raw();
    let hash = hash_of(&bytes);
    let sentinel = "ab".repeat(32);
    assert_ne!(sentinel, hash);

    let mut source = Beef::new();
    source.push_tx(
        BeefTx::from_raw_tx(bytes.clone(), None)
            .expect("the bytes are one transaction")
            .with_txid(sentinel.clone()),
        sentinel.clone(),
    );

    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");

    let entry = merged
        .find_txid(&sentinel)
        .expect("merged under the source's txid");
    assert_eq!(entry.raw_tx(), Some(bytes.as_slice()));
    assert!(merged.find_txid(&hash).is_none());
    assert_eq!(merged.txs.len(), 1);
}

/// The strength read's FIX (#621's fold), restated under #843's law: an
/// entry whose id is read inside the `tx_mut` borrow, a field then edited,
/// and given bytes by `raw_tx_or_compute`. Until #843 those bytes were the
/// stale pre-edit serialization (the cache the id filled) and `merge_beef`
/// filed them under the edited `txid()` (`abbda405`); since #843 the edit
/// clears the transaction's caches at its door, so the bytes are the edited
/// fields' and the merged entry's bytes hash to the txid it is filed under.
#[test]
#[allow(deprecated)] // the edit inside the deprecated `tx_mut` borrow
fn an_entry_edited_inside_tx_mut_is_filed_under_its_fields_hash_843() {
    let bytes = raw();
    let old = hash_of(&bytes);
    let mut source = Beef::new();
    source
        .merge_raw_tx(bytes.clone(), None)
        .expect("the bytes are one transaction");
    let entry = source.find_txid_mut(&old).unwrap();
    {
        let tx = entry.tx_mut().unwrap();
        // The id read inside the borrow fills the caches; the edit clears them.
        assert_eq!(tx.id(), old);
        tx.set_lock_time(7);
    }
    let written = entry.raw_tx_or_compute().unwrap();
    assert_ne!(
        written, bytes,
        "the edited fields' serialization, never the stale one"
    );
    assert!(entry.held_txid().is_none());
    assert_eq!(entry.txid(), hash_of(&written), "txid() is the bytes' hash");

    let mut merged = Beef::new();
    merged
        .merge_beef(&source)
        .expect("the source BEEF writes and reads back");
    for e in &merged.txs {
        let held = e.raw_tx().expect("a raw entry");
        assert_eq!(
            e.txid(),
            hash_of(held),
            "the merged entry's bytes hash to the txid it is filed under"
        );
    }
    assert!(merged.find_txid(&old).is_none());
    assert!(merged.find_txid(&hash_of(&written)).is_some());
}

/// #621's fold, the `to_writer` change's pin, restated under #843's law:
/// an entry edited through the deprecated `tx_mut` after its caches were
/// filled is written from its fields by `Beef::to_writer` and
/// `BeefTx::to_writer`, as `to_binary` and `merge_beef` write it. On
/// `7df16cf6` `to_writer` wrote a stale cache (planted here through the
/// crate's test door until #843; since #843 a door clears the caches before
/// every edit, so the cache is the fields' whatever the order).
#[test]
#[allow(deprecated)] // the edit inside the deprecated `tx_mut` borrow
fn to_writer_writes_a_tx_mut_entry_from_its_fields_843() {
    use crate::primitives::Writer;
    use crate::transaction::BEEF_V2;
    let bytes = raw();
    let mut edited = Transaction::from_binary(&bytes).unwrap();
    edited.set_lock_time(7);
    let fields = edited.to_binary();
    assert_ne!(fields, bytes);

    let mut beef = Beef::new();
    beef.merge_raw_tx(bytes.clone(), None).unwrap();
    {
        let tx = beef.txs[0].tx_mut().unwrap();
        assert_eq!(tx.to_binary(), bytes, "the caches filled before the edit");
        tx.set_lock_time(7);
    }

    let mut entry = Writer::new();
    beef.txs[0].to_writer(&mut entry, BEEF_V2).unwrap();
    let entry = entry.into_bytes();
    assert_eq!(
        &entry[1..],
        fields.as_slice(),
        "BeefTx::to_writer: the fields"
    );

    let mut writer = Writer::new();
    beef.to_writer(&mut writer).unwrap();
    let written = writer.into_bytes();
    let back = Beef::from_binary(&written).unwrap();
    assert_eq!(
        back.txs[0].raw_tx().unwrap(),
        fields.as_slice(),
        "Beef::to_writer"
    );
    assert_eq!(beef.to_binary().unwrap(), written, "to_binary the same");
    let mut merged = Beef::new();
    merged.merge_beef(&beef).unwrap();
    assert_eq!(merged.to_binary().unwrap(), written, "merge_beef the same");
}
