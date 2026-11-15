//! #817: `Beef::edit_tx`, the eager edit door; and since #843b the law of
//! the rows it rests on.
//!
//! `edit_tx` edits a copy of the entry's transaction and repairs the entry
//! at once (its bytes, txid, `input_txids`, the index re-keyed, the BEEF
//! marked for a sort, its BUMP index kept), so every door after it, the
//! `&self` lookups included, holds one entry under the new txid and writes
//! it once. The reference edits its object in place and re-keys at its next
//! synchronizing door (`ts-stack@edf6e03` `BeefTx.ts:160-175`,
//! `Beef.ts:342-352`); its answers after each door are the recorded cells of
//! `tests/beef_door_sync_817.rs`.
//!
//! Until #843b the entries were a public field and the index noticed a hand
//! edit of it only where it could (a moved entry count, a hit naming another
//! entry), with a stated window in which a lookup missed a held txid and a
//! merge stored it twice; `reindex` was its door, and the deprecated
//! `BeefTx::tx_mut` kept the #171 window. A `Beef` owns its rows now: an
//! entry changes through a door alone (`retain_txs`, `edit_tx`, the merges),
//! each of which leaves the index the rows' own. The law the tests named
//! `_843b` hold: after any door `find_txid(t)` is the LAST entry holding `t`
//! and `None` for a txid no entry holds, and an edit is seen at once by
//! every door. A hand edit, `find_txid_mut`, `tx_mut` and `reindex` do not
//! compile (`src/transaction/beef/rows.rs`' `compile_fail` doc tests).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::panic::{catch_unwind, AssertUnwindSafe};

use bsv_rs::primitives::Writer;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, MerklePath, Transaction, TransactionInput, TransactionOutput, BEEF_V2,
};
use bsv_rs::Error;

/// A transaction with one `OP_TRUE` output of `sats` spending output 0 of
/// `spends`, with an empty unlocking script.
fn tx(spends: &str, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    let mut input = TransactionInput::new(spends.parse().unwrap(), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    t.inputs_mut().push(input);
    t.outputs_mut().push(TransactionOutput::new(
        sats,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// `tx` with the lock time `lock`, its hash computed from the fields.
fn locked(mut t: Transaction, lock: u32) -> Transaction {
    t.set_lock_time(lock);
    t
}

/// The entries' txids, in the order held.
fn ids(beef: &Beef) -> Vec<String> {
    beef.txs().iter().map(BeefTx::id).collect()
}

/// U held raw (read from bytes), and U with lock time 1 (V).
fn held_raw() -> (Beef, Transaction, Transaction) {
    let u = tx(&"bb".repeat(32), 2_000);
    let v = locked(u.clone(), 1);
    let mut beef = Beef::new();
    beef.merge_raw_tx(u.to_binary(), None)
        .expect("the bytes are one transaction");
    let beef = Beef::from_binary(&beef.to_binary().expect("the BEEF writes")).unwrap();
    (beef, u, v)
}

#[test]
fn edit_tx_on_a_raw_entry_rekeys_it_at_once_and_keeps_it_raw_817() {
    let (mut beef, u, v) = held_raw();
    let lock = beef.edit_tx(u.txid(), |t| {
        t.set_lock_time(1);
        t.lock_time()
    });
    assert_eq!(lock, Ok(1), "the closure's value comes back");
    assert_eq!(ids(&beef), vec![v.id()]);
    assert!(beef.find_txid(u.txid()).is_none());
    let entry = beef
        .find_txid(v.txid())
        .expect("found by its new txid at once");
    assert_eq!(
        entry.raw_tx(),
        Some(v.to_binary().as_slice()),
        "raw, re-written"
    );
    assert_eq!(entry.input_txids(), ["bb".repeat(32)]);
    let bytes = beef.to_binary().expect("the BEEF writes");
    assert_eq!(Beef::from_binary(&bytes).unwrap().txs().len(), 1);
    assert_eq!(ids(&Beef::from_binary(&bytes).unwrap()), vec![v.id()]);
}

#[test]
fn edit_tx_on_a_parsed_entry_rekeys_it_and_keeps_it_parsed_817() {
    let u = tx(&"bb".repeat(32), 2_000);
    let v = locked(u.clone(), 1);
    let mut beef = Beef::new();
    beef.merge_transaction(u.clone());
    assert!(beef.find_txid(u.txid()).unwrap().raw_tx().is_none());
    beef.edit_tx(u.txid(), |t| t.set_lock_time(1)).unwrap();
    let entry = beef.find_txid(v.txid()).unwrap();
    assert!(entry.raw_tx().is_none(), "parsed, as held");
    assert_eq!(entry.tx().unwrap().lock_time(), 1);
    assert_eq!(beef.txs().len(), 1);
}

#[test]
fn edit_tx_on_a_txid_only_entry_or_an_unknown_txid_is_refused_unchanged_817() {
    let (mut beef, u, _) = held_raw();
    let other = "cc".repeat(32);
    beef.merge_txid_only(other.parse().unwrap());
    let before = beef.clone().to_hex().expect("the BEEF writes");
    let mut ran = false;
    let refused = beef.edit_tx(other.parse().unwrap(), |_| ran = true);
    assert!(
        matches!(refused, Err(Error::BeefError(ref m)) if m.contains("txid alone")),
        "{refused:?}"
    );
    let unknown = beef.edit_tx("dd".repeat(32).parse().unwrap(), |_| ());
    assert!(
        matches!(unknown, Err(Error::BeefError(ref m)) if m.contains("does not exist")),
        "{unknown:?}"
    );
    assert!(!ran, "no closure runs on a refusal");
    assert_eq!(beef.clone().to_hex().expect("the BEEF writes"), before);
    assert!(beef.find_txid(u.txid()).is_some());
}

#[test]
fn edit_tx_onto_a_txid_another_entry_holds_is_refused_byte_for_byte_unchanged_817() {
    let (mut beef, u, v) = held_raw();
    beef.merge_raw_tx(v.to_binary(), None)
        .expect("the bytes are one transaction");
    let before = beef.clone().to_binary().expect("the BEEF writes");
    let order = ids(&beef);
    let refused = beef.edit_tx(u.txid(), |t| t.set_lock_time(1));
    assert!(
        matches!(refused, Err(Error::BeefError(ref m)) if m.contains("already held")),
        "{refused:?}"
    );
    assert_eq!(ids(&beef), order);
    assert_eq!(beef.clone().to_binary().expect("the BEEF writes"), before);
    assert!(beef.find_txid(u.txid()).is_some() && beef.find_txid(v.txid()).is_some());
}

#[test]
fn an_edit_that_keeps_the_txid_moves_nothing_and_is_kept_817() {
    let (mut beef, u, _) = held_raw();
    let read = beef.clone().to_binary().expect("the BEEF writes");
    assert_eq!(beef.edit_tx(u.txid(), |_| 7), Ok(7));
    assert_eq!(
        beef.clone().to_binary().expect("the BEEF writes"),
        read,
        "no byte moves"
    );
    // A field the bytes do not carry is kept, under the same key.
    let path = MerklePath::from_coinbase_txid(&u.id(), 900_000);
    beef.edit_tx(u.txid(), |t| t.merkle_path = Some(path.clone()))
        .unwrap();
    let held = beef.find_txid(u.txid()).unwrap().tx().unwrap();
    assert_eq!(held.merkle_path.as_ref().unwrap().block_height, 900_000);
    assert_eq!(beef.to_binary().expect("the BEEF writes"), read);
}

#[test]
fn a_panic_in_the_edit_leaves_the_beef_untouched_817() {
    let (mut beef, u, v) = held_raw();
    let before = beef.clone().to_hex().expect("the BEEF writes");
    let caught = catch_unwind(AssertUnwindSafe(|| {
        beef.edit_tx(u.txid(), |t| {
            t.set_lock_time(1);
            panic!("the caller's edit fails half way");
        })
    }));
    assert!(caught.is_err());
    assert!(beef.find_txid(u.txid()).is_some(), "U still held");
    assert!(beef.find_txid(v.txid()).is_none());
    assert_eq!(
        beef.find_txid(u.txid()).unwrap().tx().unwrap().lock_time(),
        0
    );
    assert_eq!(beef.to_hex().expect("the BEEF writes"), before);
}

/// Every door after an edit holds one entry under the new txid, finds it
/// and writes it once. Since #843b the per-entry `&mut` door is
/// `set_bump_index` (`find_txid_mut` does not compile), and the three doors
/// of the rows (`retain_txs`, `retain_bumps`, `edit_bump` on a BUMP merged
/// for it) are in the list.
#[test]
fn every_door_after_an_edit_holds_one_entry_and_writes_it_once_817() {
    type Door = fn(&mut Beef, &Transaction);
    let doors: [(&str, Door); 17] = [
        ("merge_raw_tx", |b, v| {
            b.merge_raw_tx(v.to_binary(), None)
                .expect("the bytes are one transaction");
        }),
        ("merge_txid_only", |b, v| {
            b.merge_txid_only(v.txid());
        }),
        ("merge_transaction", |b, v| {
            b.merge_transaction(v.clone());
        }),
        ("merge_bump", |b, v| {
            b.merge_bump(MerklePath::from_coinbase_txid(&v.id(), 900_002));
            assert_eq!(b.find_txid(v.txid()).unwrap().bump_index(), Some(0));
        }),
        ("merge_beef", |b, v| {
            let mut other = Beef::new();
            other
                .merge_raw_tx(v.to_binary(), None)
                .expect("the bytes are one transaction");
            b.merge_beef(&other)
                .expect("the source writes and reads back");
        }),
        ("find_txid", |b, v| assert!(b.find_txid(v.txid()).is_some())),
        ("set_bump_index", |b, v| {
            b.set_bump_index(v.txid(), None).unwrap();
        }),
        ("retain_txs", |b, _| b.retain_txs(|_| true)),
        ("retain_bumps", |b, _| b.retain_bumps(|_, _| true)),
        ("edit_bump", |b, v| {
            let at = b.merge_bump(MerklePath::from_coinbase_txid(&v.id(), 900_003));
            b.edit_bump(at, |bump| bump.block_height).unwrap();
        }),
        ("find_transaction_for_signing", |b, v| {
            assert_eq!(
                b.find_transaction_for_signing(v.txid()).unwrap().id(),
                v.id()
            );
        }),
        ("find_atomic_transaction", |b, v| {
            assert_eq!(b.find_atomic_transaction(v.txid()).unwrap().id(), v.id());
        }),
        ("make_txid_only", |b, v| {
            assert!(b.make_txid_only(v.txid()).unwrap().is_txid_only());
        }),
        ("to_binary", |b, _| {
            b.to_binary().expect("the BEEF writes");
        }),
        ("to_binary_atomic", |b, v| {
            b.to_binary_atomic(v.txid()).unwrap();
        }),
        ("verify_valid", |b, _| {
            b.verify_valid(true);
        }),
        ("sort_txs", |b, _| {
            b.sort_txs();
        }),
    ];
    for (door, run) in doors {
        let (mut beef, u, v) = held_raw();
        beef.edit_tx(u.txid(), |t| t.set_lock_time(1)).unwrap();
        run(&mut beef, &v);
        assert_eq!(
            ids(&beef),
            vec![v.id()],
            "{door}: one entry, the edited one"
        );
        assert!(beef.find_txid(v.txid()).is_some(), "{door}");
        assert!(beef.find_txid(u.txid()).is_none(), "{door}");
        let back = Beef::from_binary(&beef.to_binary().expect("the BEEF writes")).unwrap();
        assert_eq!(ids(&back), vec![v.id()], "{door}: written once");
    }
}

/// X, U, W held raw.
fn three() -> (Beef, [Transaction; 3]) {
    let x = tx(&"dd".repeat(32), 3_000);
    let u = tx(&"bb".repeat(32), 2_000);
    let w = tx(&"ee".repeat(32), 5_000);
    let mut beef = Beef::new();
    for t in [&x, &u, &w] {
        beef.merge_raw_tx(t.to_binary(), None)
            .expect("the bytes are one transaction");
    }
    (beef, [x, u, w])
}

/// A V2 BEEF read from a frame of the raw `entries` in the order given, no
/// BUMP, each entry written by this crate's own writer
/// (`BeefTx::to_writer`): the one way to a BEEF that holds a txid twice, or
/// holds its entries in an order no merge left them in, since no door pushes
/// or reorders an entry (#843b). Such a BEEF is as read (its `merge_beef`
/// as a source walks the read order) and each entry holds its bytes and
/// its parse, where a hand push of `BeefTx::from_raw_tx` held the bytes
/// alone in a BEEF marked for a sort.
fn read(entries: &[&Transaction]) -> Beef {
    let mut frame = Writer::new();
    frame.write_u32_le(BEEF_V2);
    frame.write_var_int(0);
    frame.write_var_int(entries.len() as u64);
    for t in entries {
        BeefTx::from_raw_tx(t.to_binary(), None)
            .expect("one transaction")
            .to_writer(&mut frame, BEEF_V2)
            .expect("the entry is writable");
    }
    Beef::from_binary(&frame.into_bytes()).expect("the frame reads back")
}

/// The toolbox's pattern (`wallet.rs:1505`) through its door: `retain_txs`,
/// then the lookups and a merge. Every held entry is found, the dropped one
/// is not, and a merge of a held txid replaces it in its place.
///
/// Replaces `a_hand_retain_then_find_txid_and_merge_raw_tx_holds_each_txid_once_817`,
/// whose `retain` was a hand edit of the public `txs` (RED on beta
/// `cfbe3c98`: `find_txid(W)` `None` and W stored twice). The hand edit does
/// not compile since #843b; `retain_txs` empties the index before it lends
/// the entries, so the lookups after it read the rows as they stand.
#[test]
fn a_retain_then_find_txid_and_merge_raw_tx_holds_each_txid_once_843b() {
    let (mut beef, [x, u, w]) = three();
    beef.retain_txs(|t| t.txid() != x.txid());
    assert!(beef.find_txid(u.txid()).is_some());
    assert!(
        beef.find_txid(w.txid()).is_some(),
        "W found after the shift"
    );
    assert!(beef.find_txid(x.txid()).is_none(), "the dropped X is gone");
    beef.merge_raw_tx(w.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(ids(&beef), vec![u.id(), w.id()], "W held once");
    assert_eq!(beef.find_txid(w.txid()).unwrap().txid(), w.txid());
}

/// An entry a merge appends is found at once, and each merge door of the
/// same txid after it keeps one entry.
///
/// Replaces `a_hand_push_then_a_lookup_finds_the_pushed_entry_817`: a push
/// onto the public `txs` does not compile since #843b, and an entry enters
/// through a merge door, which keys it as it appends it.
#[test]
fn an_appended_entry_is_found_at_once_and_merged_into_its_place_843b() {
    let (mut beef, [x, _, _]) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    assert!(beef.find_txid(y.txid()).is_none(), "not held yet");
    beef.merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    assert!(std::ptr::eq(
        beef.find_txid(y.txid()).unwrap(),
        &beef.txs()[3]
    ));
    assert!(beef.find_txid(x.txid()).is_some());
    let held = beef.txs().len();
    beef.merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_transaction(y.clone());
    beef.merge_txid_only(y.txid());
    assert_eq!(beef.txs().len(), held, "Y held once");
    assert!(std::ptr::eq(
        beef.find_txid(y.txid()).unwrap(),
        &beef.txs()[3]
    ));
}

/// A BEEF holding its entries in another order finds each at its place,
/// and a merge of one replaces it there, the others kept.
///
/// Replaces `a_hand_swap_then_a_lookup_of_each_finds_it_817` and
/// `reindex_after_a_hand_reorder_finds_every_entry_817`: a hand `swap` or
/// `reverse` of the public `txs` does not compile since #843b, no door
/// reorders the entries, and there is no `reindex`; the other order is read
/// from a frame written in it.
#[test]
fn a_beef_read_in_another_order_finds_each_entry_and_merges_into_its_place_843b() {
    let (_, [x, u, w]) = three();
    let mut beef = read(&[&u, &x, &w]);
    assert!(std::ptr::eq(
        beef.find_txid(x.txid()).unwrap(),
        &beef.txs()[1]
    ));
    assert!(std::ptr::eq(
        beef.find_txid(u.txid()).unwrap(),
        &beef.txs()[0]
    ));
    beef.merge_raw_tx(x.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(
        ids(&beef),
        vec![u.id(), x.id(), w.id()],
        "U kept, X in its place"
    );
    let reversed = read(&[&w, &u, &x]);
    for (at, t) in [&w, &u, &x].into_iter().enumerate() {
        assert!(std::ptr::eq(
            reversed.find_txid(t.txid()).unwrap(),
            &reversed.txs()[at]
        ));
    }
}

/// A transaction replaced in place, the entry count kept, is found at once
/// by its new txid and not by the old one, a merge of it holds it once, and
/// a copy of the BEEF answers the same.
///
/// Replaces `a_hand_replace_keeping_the_count_misses_until_reindex_stated_817`,
/// which pinned the stated window: after a hand replacement of an entry the
/// new txid's lookup missed, a merge of it stored it twice (as the
/// reference does too), and `reindex` closed it. The hand replacement and
/// `reindex` do not compile since #843b; the replacement goes through
/// `edit_tx`, which re-keys the entry, and the window is closed.
#[test]
fn a_replacement_in_place_is_found_at_once_and_held_once_843b() {
    let (mut beef, [x, u, _]) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    let replacement = y.clone();
    beef.edit_tx(x.txid(), |t| *t = replacement).unwrap();
    assert_eq!(beef.txs().len(), 3, "the count kept");
    assert!(std::ptr::eq(
        beef.find_txid(y.txid()).unwrap(),
        &beef.txs()[0]
    ));
    assert!(beef.find_txid(x.txid()).is_none(), "the replaced X is gone");
    let copy = beef.clone();
    assert!(
        copy.find_txid(y.txid()).is_some(),
        "the copy's index is its own"
    );
    assert!(copy.find_txid(x.txid()).is_none());
    beef.merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(beef.txs().len(), 3, "Y held once");
    let once = beef.txs().iter().filter(|t| t.txid() == y.txid()).count();
    assert_eq!(once, 1);
    assert!(beef.find_txid(u.txid()).is_some());
}

// Removed: `reindex_rekeys_an_entry_edited_through_the_deprecated_tx_mut_817`.
// It pinned the #171 window of `BeefTx::tx_mut` (an edit unseen by
// `find_txid` until `reindex`). `tx_mut`, `find_txid_mut` and `reindex` do
// not compile since #843b: `src/transaction/beef/rows.rs`' `compile_fail`
// doc tests. The law it left is pinned above by
// `edit_tx_on_a_raw_entry_rekeys_it_at_once_and_keeps_it_raw_817` (the
// entry found by its new txid at once, its input list read).

/// `Beef` and `BeefTx` are `Send` and not `Sync`, exactly as on beta
/// `cfbe3c98`: every `Transaction` holds a `Script`, whose chunks and
/// caches are `RefCell`s. The txid index is a `OnceLock` since #843b
/// (filled through `&self` on the lookup after a door emptied it), which is
/// `Sync` where what it holds is, so it changes neither answer.
/// Compile-time: the second impl makes the path ambiguous when the type is
/// `Sync`.
#[test]
fn beef_and_beef_tx_are_send_and_not_sync_as_on_beta_817() {
    fn send<T: Send>() {}
    send::<Beef>();
    send::<BeefTx>();
    trait AmbiguousIfSync<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    #[allow(dead_code)]
    struct IsSync;
    impl<T: ?Sized + Sync> AmbiguousIfSync<IsSync> for T {}
    let _ = <Beef as AmbiguousIfSync<_>>::some_item;
    let _ = <BeefTx as AmbiguousIfSync<_>>::some_item;
}

/// An append, a lookup (the index filled, the appended entry keyed), then a
/// `retain_txs` back to the earlier count: the appended entry is found at
/// its new place and a merge of it holds it once.
///
/// Replaces `a_hand_push_a_door_then_a_retain_back_to_the_count_finds_the_pushed_entry_817`
/// (the cold read's case of #817's fold of the rebuild), whose push and
/// `retain` were hand edits and whose `&mut` door was `find_txid_mut`: none
/// compiles since #843b. An index that kept its keys across the retain
/// would answer the appended txid with a position past the entries.
#[test]
fn an_append_a_lookup_then_a_retain_back_to_the_count_finds_the_appended_entry_843b() {
    let (mut beef, [x, u, _]) = three();
    let z = tx(&"cc".repeat(32), 7_000);
    beef.merge_raw_tx(z.to_binary(), None).unwrap();
    assert!(beef.find_txid(u.txid()).is_some());
    beef.retain_txs(|t| t.txid() != x.txid());
    assert_eq!(beef.txs().len(), 3);
    assert!(std::ptr::eq(
        beef.find_txid(z.txid()).unwrap(),
        &beef.txs()[2]
    ));
    let held = beef.txs().len();
    beef.merge_raw_tx(z.to_binary(), None).unwrap();
    assert_eq!(beef.txs().len(), held, "Z held once");
}

/// A txid a BEEF holds twice is answered by the later entry, before any
/// door and after one; both entries stay.
///
/// Replaces `a_hand_push_of_a_held_txid_is_answered_by_the_later_entry_after_a_door_stated_817`,
/// which stated a hole: after a hand push of a held txid a `&self` lookup
/// answered the EARLIER entry until a `&mut` door ran, the later after it.
/// No door holds a txid twice since #843b but the reader, and the answer is
/// the last entry in every state.
#[test]
fn a_txid_held_twice_is_answered_by_the_later_entry_before_and_after_a_door_843b() {
    let (_, [x, u, w]) = three();
    let mut beef = read(&[&x, &u, &w, &x]);
    let found = beef.find_txid(x.txid()).unwrap();
    assert!(
        std::ptr::eq(found, &beef.txs()[3]),
        "the later, before any door"
    );
    beef.merge_txid_only("ab".repeat(32).parse().unwrap());
    let found = beef.find_txid(x.txid()).unwrap();
    assert!(
        std::ptr::eq(found, &beef.txs()[3]),
        "the later after a door"
    );
    assert_eq!(
        beef.txs().iter().filter(|t| t.txid() == x.txid()).count(),
        2
    );
}

/// The two states of #817's fold that only unframed raw bytes reach (bytes
/// that do not parse, a byte after the lock time) are no longer reachable
/// through a public door since the writers' change of #817: `merge_raw_tx`
/// and `BeefTx::from_raw_tx` refuse such bytes, pinned here; `edit_tx`'s
/// answers on them are the unit module `src/transaction/beef/index_817_tests.rs`
/// (`edit_tx_on_raw_bytes_that_do_not_parse_is_a_beef_error_817`,
/// `a_no_op_edit_of_raw_bytes_with_a_trailing_byte_moves_nothing_817`), the
/// entries built there by the crate-private `BeefTx::from_framed_raw_tx`.
#[test]
fn the_unframed_raw_states_are_refused_at_the_public_doors_817() {
    let mut beef = Beef::new();
    let mut raw = tx(&"bb".repeat(32), 2_000).to_binary();
    raw.push(0x00);
    for bytes in [vec![0xde, 0xad], raw] {
        assert!(matches!(
            beef.merge_raw_tx(bytes.clone(), None),
            Err(Error::BeefError(_))
        ));
        assert!(matches!(
            BeefTx::from_raw_tx(bytes, None),
            Err(Error::BeefError(_))
        ));
    }
    assert!(beef.txs().is_empty());
}

/// The no-op edit keeps the sort's word on the entry (the strength read's
/// S4), and an edit that moves the txid drops it.
///
/// Replaces `a_no_op_edit_keeps_the_entrys_is_valid_817`, which wrote
/// `is_valid = Some(true)` by hand through `find_txid_mut`: the write does
/// not compile since #843b (`src/transaction/beef/rows.rs`' `compile_fail`
/// doc tests). The sort alone says whether an entry is valid, so the word
/// is the sort's here: `Some(true)` for an entry a BUMP proves.
#[test]
fn a_no_op_edit_keeps_the_sorts_word_on_the_entry_843b() {
    let (mut beef, u, _) = held_raw();
    let word = |beef: &Beef, t: &Transaction| beef.find_txid(t.txid()).unwrap().is_valid();
    assert_eq!(word(&beef, &u), None, "no sort has run");
    beef.merge_bump(MerklePath::from_coinbase_txid(&u.id(), 900_000));
    beef.sort_txs();
    assert_eq!(word(&beef, &u), Some(true), "proven, as the sort found it");
    beef.edit_tx(u.txid(), |_| ()).unwrap();
    assert_eq!(
        word(&beef, &u),
        Some(true),
        "kept by an edit moving nothing"
    );
    let edited = beef
        .edit_tx(u.txid(), |t| {
            t.set_lock_time(1);
            t.txid()
        })
        .unwrap();
    assert_eq!(
        beef.find_txid(edited).unwrap().is_valid(),
        None,
        "another transaction: the sort has not judged it"
    );
}

/// A closure returning an `Err` as its value still has its edit stored.
#[test]
fn a_closure_returning_an_err_value_still_has_its_edit_stored_817() {
    let (mut beef, u, v) = held_raw();
    let value: Result<(), &str> = beef
        .edit_tx(u.txid(), |t| {
            t.set_lock_time(1);
            Err("the caller's own")
        })
        .unwrap();
    assert_eq!(value, Err("the caller's own"));
    assert!(beef.find_txid(v.txid()).is_some());
}

/// The rule read's two cells of #817's fold of the rebuild, on the law:
/// `edit_tx`'s collision check sees every held txid, and after an edit of U
/// to V the new txid is found at once and the old one names nothing.
///
/// Replaces `the_two_edit_tx_cells_inside_the_window_stated_817`, which
/// stated both inside the hand-edit window: after a hand replacement
/// keeping the count the collision check missed the held Y and an edit onto
/// Y stored it twice; after a `tx_mut` edit of U to V, `edit_tx(V)` refused
/// (a miss) until `edit_tx(U)`'s mismatched hit rebuilt the index. Neither
/// state can be built since #843b.
#[test]
fn the_two_edit_tx_cells_of_the_closed_window_843b() {
    let (mut beef, [x, u, _]) = three();
    let y = locked(x.clone(), 5);
    let replacement = y.clone();
    beef.edit_tx(u.txid(), |t| *t = replacement).unwrap();
    let refused = beef.edit_tx(x.txid(), |t| t.set_lock_time(5));
    assert!(
        matches!(refused, Err(Error::BeefError(ref m)) if m.contains("already held")),
        "{refused:?}"
    );
    let held = beef.txs().iter().filter(|t| t.txid() == y.txid()).count();
    assert_eq!(held, 1, "the collision seen: Y held once");
    assert!(beef.find_txid(x.txid()).is_some(), "X unchanged");

    let (mut beef, u, v) = held_raw();
    beef.edit_tx(u.txid(), |t| t.set_lock_time(1)).unwrap();
    assert_eq!(beef.edit_tx(v.txid(), |_| 3), Ok(3), "V found at once");
    let gone = beef.edit_tx(u.txid(), |_| ());
    assert!(
        matches!(gone, Err(Error::BeefError(ref m)) if m.contains("does not exist")),
        "{gone:?}"
    );
}

/// A `retain_txs` of an early entry then two appends: each appended entry
/// is found at its place and a merge of it holds it once.
///
/// Replaces `a_hand_removal_then_two_pushes_finds_each_pushed_entry_817`
/// (the cold read's attack C on the second fold of the rebuild), whose
/// removal and pushes were hand edits of the public `txs`; they do not
/// compile since #843b and the index has no prefix to check: it is emptied
/// by the retain and filled from the rows.
#[test]
fn a_retain_then_two_appends_finds_each_appended_entry_843b() {
    let (mut beef, [x, u, w]) = three();
    beef.retain_txs(|t| t.txid() != x.txid());
    let p = tx(&"ab".repeat(32), 7_000);
    let q = tx(&"cd".repeat(32), 9_000);
    beef.merge_raw_tx(p.to_binary(), None).unwrap();
    beef.merge_raw_tx(q.to_binary(), None).unwrap();
    for (at, t) in [&u, &w, &p, &q].into_iter().enumerate() {
        assert!(std::ptr::eq(
            beef.find_txid(t.txid()).unwrap(),
            &beef.txs()[at]
        ));
    }
    beef.merge_raw_tx(p.to_binary(), None).unwrap();
    beef.merge_raw_tx(q.to_binary(), None).unwrap();
    assert_eq!(ids(&beef), vec![u.id(), w.id(), p.id(), q.id()]);
}

/// Two entries of one txid at the end of a BEEF are answered by the later.
///
/// Replaces `two_hand_pushed_twins_are_answered_by_the_later_817` (the
/// strength read's F4), whose twins were pushed by hand past the indexed
/// count; since #843b they come from the reader alone.
#[test]
fn two_twins_read_from_bytes_are_answered_by_the_later_843b() {
    let (_, [x, u, w]) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    let beef = read(&[&x, &u, &w, &y, &y]);
    let found = beef.find_txid(y.txid()).unwrap();
    assert!(std::ptr::eq(found, &beef.txs()[4]), "the later twin");
}

/// The second fold of the rebuild, the strength read's F1, with two raw
/// twins: U held twice, `edit_tx(U)` edits the entry the index names (the
/// later) to V; the U still held is found and not merged again, as the
/// reference's index rebuilt after the edit finds it
/// (`Beef.ts:342-352,516-524`). The twin held as a txid alone and then raw
/// is the recorded cell of `tests/beef_door_sync_817.rs`.
///
/// Replaces `an_edit_of_a_hand_pushed_twin_keeps_the_other_entry_found_817`,
/// whose twin was pushed by hand; since #843b it is read from bytes.
#[test]
fn an_edit_of_a_twin_read_from_bytes_keeps_the_other_entry_found_843b() {
    let (_, [x, u, w]) = three();
    let mut beef = read(&[&x, &u, &w, &u]);
    let v = locked(u.clone(), 1);
    beef.edit_tx(u.txid(), |t| t.set_lock_time(1)).unwrap();
    assert!(std::ptr::eq(
        beef.find_txid(u.txid()).unwrap(),
        &beef.txs()[1]
    ));
    assert!(std::ptr::eq(
        beef.find_txid(v.txid()).unwrap(),
        &beef.txs()[3]
    ));
    beef.merge_txid_only(u.txid());
    assert_eq!(beef.txs().len(), 4, "U not stored again");
    assert!(std::ptr::eq(
        beef.find_txid(u.txid()).unwrap(),
        &beef.txs()[1]
    ));
}

/// The same twin on a copy of a BEEF whose index is filled: the copy
/// carries the index with its note of the twin, so `edit_tx` on the copy
/// keeps the U still held found, and the BEEF copied is untouched.
///
/// Replaces `an_edit_of_a_twin_after_reindex_keeps_the_other_entry_found_817`,
/// which reached the whole rebuild through `reindex`; `reindex` does not
/// compile since #843b, and the other way to an index not filled by this
/// BEEF's own lookups is a copy.
#[test]
fn an_edit_of_a_twin_on_a_copy_keeps_the_other_entry_found_843b() {
    let (_, [x, u, w]) = three();
    let beef = read(&[&x, &u, &w, &u]);
    assert!(std::ptr::eq(
        beef.find_txid(u.txid()).unwrap(),
        &beef.txs()[3]
    ));
    let mut copy = beef.clone();
    copy.edit_tx(u.txid(), |t| t.set_lock_time(1)).unwrap();
    assert!(std::ptr::eq(
        copy.find_txid(u.txid()).unwrap(),
        &copy.txs()[1]
    ));
    copy.merge_txid_only(u.txid());
    assert_eq!(copy.txs().len(), 4, "U not stored again");
    assert!(
        std::ptr::eq(beef.find_txid(u.txid()).unwrap(), &beef.txs()[3]),
        "the BEEF copied is untouched"
    );
}
