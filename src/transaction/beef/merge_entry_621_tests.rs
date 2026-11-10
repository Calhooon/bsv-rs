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
        BeefTx::from_raw_tx(bytes.clone(), None).with_txid(sentinel.clone()),
        sentinel.clone(),
    );

    let mut merged = Beef::new();
    merged.merge_beef(&source);

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
    source.merge_raw_tx(bytes.clone(), None);
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
    merged.merge_beef(&source);
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
