//! `Script`'s caches are `OnceLock`s behind one write door and `chunks()`
//! lends a slice (#843d1, the freeze plan's row 1;
//! `docs/design/843-identity-and-framing.md`, sections 8 and 9), so a
//! `Script`, and every type holding one, is `Send` and `Sync`, and a future
//! that awaits `Transaction::verify` can be spawned on a multi-threaded
//! runtime. Until #843d1 the chunks and caches were `RefCell`s
//! (`src/script/script.rs:22-30` at `3e1ade84`): this file did not compile
//! there (E0277 naming `RefCell`, E0308 at the slice).
//!
//! The reference's getter lends its held array (`ts-stack@edf6e03`
//! `Script.ts:195-198`); here the lent slice is shared, an edit going through
//! the write methods or `Script::from_chunks`.

#![cfg(feature = "transaction")]

use bsv_rs::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, ChainTracker, MerklePath, MockChainTracker, Transaction, TransactionInput,
    TransactionOutput,
};

/// The outside view of the ten types, held at compile time.
const _: fn() = || {
    fn assert<T: Send + Sync>() {}
    assert::<Script>();
    assert::<LockingScript>();
    assert::<UnlockingScript>();
    assert::<ScriptChunk>();
    assert::<Transaction>();
    assert::<TransactionInput>();
    assert::<TransactionOutput>();
    assert::<MerklePath>();
    assert::<BeefTx>();
    assert::<Beef>();
    // the eight more that gained `Sync` with #843d1 (its fold)
    assert::<bsv_rs::script::Spend>();
    assert::<bsv_rs::script::SpendParams>();
    assert::<bsv_rs::script::TxSpendParams>();
    assert::<bsv_rs::script::SigningContext<'static>>();
    assert::<bsv_rs::script::SimpleUtxo>();
    assert::<bsv_rs::transaction::TransactionParts>();
    assert::<bsv_rs::transaction::TransactionPartsMut<'static>>();
    assert::<bsv_rs::transaction::Utxo>();
};

#[test]
fn the_three_types_are_send_and_sync_843d1() {
    fn shareable<T: Send + Sync>() {}
    shareable::<Transaction>();
    shareable::<Script>();
    shareable::<Beef>();
    // shared by reference across threads: every read fills its cache through `&self`
    let script = Script::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
    std::thread::scope(|s| {
        let readers: Vec<_> = (0..4)
            .map(|_| s.spawn(|| (script.chunks().len(), script.to_hex(), script.to_asm())))
            .collect();
        for reader in readers {
            let (len, hex, asm) = reader.join().unwrap();
            assert_eq!(len, 5);
            assert_eq!(hex, "76a914000000000000000000000000000000000000000088ac");
            assert!(asm.starts_with("OP_DUP OP_HASH160"));
        }
    });
}

#[test]
fn a_future_awaiting_verify_is_send_843d1() {
    fn spawnable<F: std::future::Future + Send>(_: F) {}
    let tx = Transaction::new();
    let tracker = MockChainTracker::always_valid(800_000);
    // never polled: the claim is the future's type, no network is asked
    spawnable(async move {
        let tracker: &dyn ChainTracker = &tracker;
        tx.verify(tracker, None, None).await
    });
}

#[test]
fn chunks_lends_the_held_slice_843d1() {
    let hex = "76a914000000000000000000000000000000000000000088ac";
    let script = Script::from_hex(hex).unwrap();
    let c: &[ScriptChunk] = script.chunks();
    assert!(std::ptr::eq(c, script.chunks()), "Script: the same slice");
    assert_eq!(c.len(), 5);

    let lock = LockingScript::from_hex(hex).unwrap();
    let c: &[ScriptChunk] = lock.chunks();
    assert!(
        std::ptr::eq(c, lock.chunks()),
        "LockingScript: the same slice"
    );
    assert_eq!(c.len(), 5);

    let unlock = UnlockingScript::from_hex("0100").unwrap();
    let c: &[ScriptChunk] = unlock.chunks();
    assert!(
        std::ptr::eq(c, unlock.chunks()),
        "UnlockingScript: the same slice"
    );
    assert_eq!(c.len(), 1);

    // the lent slice is the script's own: a clone lends its own copy
    let copy = script.clone();
    assert_eq!(copy.chunks(), script.chunks());
    assert!(!std::ptr::eq(copy.chunks(), script.chunks()));
}
