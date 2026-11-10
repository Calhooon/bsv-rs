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

/// The strength read's FIX (#621's fold): an entry whose id is read inside
/// the `tx_mut` borrow, a field then edited, and given bytes by
/// `raw_tx_or_compute` holds the stale pre-edit serialization (the cache the
/// id filled), no txid, and a `txid()` that hashes the edited fields. On
/// `abbda405` `merge_beef` filed those bytes under that `txid()`, so the
/// merged entry's bytes did not hash to the txid it was filed under; the
/// merge hashes the bytes of an entry that holds no txid.
#[test]
#[allow(deprecated)] // the stale cache is a state of the deprecated `tx_mut` alone
fn a_stale_cached_entry_is_filed_under_its_bytes_hash_621() {
    let bytes = raw();
    let old = hash_of(&bytes);
    let mut source = Beef::new();
    source
        .merge_raw_tx(bytes.clone(), None)
        .expect("the bytes are one transaction");
    let entry = source.find_txid_mut(&old).unwrap();
    {
        let tx = entry.tx_mut().unwrap();
        // The id read inside the borrow fills the serialization cache.
        assert_eq!(tx.id(), old);
        tx.lock_time = 7;
    }
    let stale = entry.raw_tx_or_compute().unwrap();
    assert_eq!(stale, bytes, "the stale serialization cached");
    assert!(entry.held_txid().is_none());
    assert_ne!(entry.txid(), old, "txid() hashes the edited fields");

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
    assert!(merged.find_txid(&old).is_some());
}

/// #621's fold, the `to_writer` change's lasting pin (Calhooon/bsv-rs#843's
/// break will make the public stale state unbuildable): an entry edited
/// through the deprecated `tx_mut` whose transaction caches bytes other
/// than its fields' (here the bytes before the edit, set through the crate's
/// cache door) is written from its fields by `Beef::to_writer` and
/// `BeefTx::to_writer`, as `to_binary` and `merge_beef` write it. On
/// `7df16cf6` `to_writer` wrote the cache.
#[test]
#[allow(deprecated)] // the stale cache is a state of the deprecated `tx_mut` alone
fn to_writer_writes_a_tx_mut_entry_from_its_fields_not_its_cache_621() {
    use crate::primitives::Writer;
    use crate::transaction::BEEF_V2;
    let bytes = raw();
    let mut edited = Transaction::from_binary(&bytes).unwrap();
    edited.lock_time = 7;
    let fields = {
        let fresh = edited.clone();
        fresh.invalidate_caches();
        fresh.to_binary()
    };
    assert_ne!(fields, bytes);
    let stale = edited.with_cached_bytes_for_test(bytes.clone());

    let mut beef = Beef::new();
    beef.merge_raw_tx(bytes, None).unwrap();
    *beef.txs[0].tx_mut().unwrap() = stale;

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
