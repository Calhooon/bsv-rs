//! #817: `Beef::edit_tx`, the eager edit door, and the index noticing a hand
//! edit of the public `txs`.
//!
//! `edit_tx` edits a copy of the entry's transaction and repairs the entry
//! at once (its bytes, txid, `input_txids`, the index re-keyed, the BEEF
//! marked for a sort, its BUMP index kept), so every door after it, the
//! `&self` lookups included, holds one entry under the new txid and writes
//! it once. The reference edits its object in place and re-keys at its next
//! synchronizing door (`ts-stack@edf6e03` `BeefTx.ts:160-175`,
//! `Beef.ts:342-352`); its answers after each door are the recorded cells of
//! `tests/beef_door_sync_817.rs`. The deprecated `BeefTx::tx_mut` keeps the
//! #171 window (an edit seen by the whole-BEEF doors alone).
//!
//! The index notices a hand edit of `txs` in constant time where it can: an
//! entry count other than the one it was built for, or a hit naming an
//! entry that holds another txid. A `&self` lookup then scans (the pushed
//! tail alone after hand pushes, `txs` whole after a shrink or a mismatched
//! hit); the next `&mut` door indexes the pushed tail alone, or rebuilds
//! the index whole after a shrink or a hit naming another entry. The stated
//! window: hand edits that leave a txid the index was never given below the
//! entry count it was built for (a replacement inside the indexed prefix,
//! whatever pushes follow it; a `truncate` or a `retain` with pushes back
//! past it) make a lookup of that txid miss while the count is back at the
//! indexed one, or past it with the indexed prefix's last position in
//! place (a reorder misses nothing); `Beef::reindex` closes it. Two entries
//! of one txid are noted when indexed, so `edit_tx` keeps the other found. On beta `cfbe3c98` a hand `retain` (the toolbox's `wallet.rs:1505`)
//! made `find_txid` answer `None` for a held entry and `merge_raw_tx` store
//! it twice.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::panic::{catch_unwind, AssertUnwindSafe};

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefTx, MerklePath, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

/// A transaction with one `OP_TRUE` output of `sats` spending output 0 of
/// `spends`, with an empty unlocking script.
fn tx(spends: &str, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    let mut input = TransactionInput::new(spends.to_string(), 0);
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
    beef.txs.iter().map(BeefTx::txid).collect()
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
    let lock = beef.edit_tx(&u.id(), |t| {
        t.set_lock_time(1);
        t.lock_time()
    });
    assert_eq!(lock, Ok(1), "the closure's value comes back");
    assert_eq!(ids(&beef), vec![v.id()]);
    assert!(beef.find_txid(&u.id()).is_none());
    let entry = beef
        .find_txid(&v.id())
        .expect("found by its new txid at once");
    assert_eq!(
        entry.raw_tx(),
        Some(v.to_binary().as_slice()),
        "raw, re-written"
    );
    assert_eq!(entry.input_txids, vec!["bb".repeat(32)]);
    let bytes = beef.to_binary().expect("the BEEF writes");
    assert_eq!(Beef::from_binary(&bytes).unwrap().txs.len(), 1);
    assert_eq!(ids(&Beef::from_binary(&bytes).unwrap()), vec![v.id()]);
}

#[test]
fn edit_tx_on_a_parsed_entry_rekeys_it_and_keeps_it_parsed_817() {
    let u = tx(&"bb".repeat(32), 2_000);
    let v = locked(u.clone(), 1);
    let mut beef = Beef::new();
    beef.merge_transaction(u.clone());
    assert!(beef.find_txid(&u.id()).unwrap().raw_tx().is_none());
    beef.edit_tx(&u.id(), |t| t.set_lock_time(1)).unwrap();
    let entry = beef.find_txid(&v.id()).unwrap();
    assert!(entry.raw_tx().is_none(), "parsed, as held");
    assert_eq!(entry.tx().unwrap().lock_time(), 1);
    assert_eq!(beef.txs.len(), 1);
}

#[test]
fn edit_tx_on_a_txid_only_entry_or_an_unknown_txid_is_refused_unchanged_817() {
    let (mut beef, u, _) = held_raw();
    let other = "cc".repeat(32);
    beef.merge_txid_only(other.clone());
    let before = beef.clone().to_hex().expect("the BEEF writes");
    let mut ran = false;
    let refused = beef.edit_tx(&other, |_| ran = true);
    assert!(
        matches!(refused, Err(Error::BeefError(ref m)) if m.contains("txid alone")),
        "{refused:?}"
    );
    let unknown = beef.edit_tx(&"dd".repeat(32), |_| ());
    assert!(
        matches!(unknown, Err(Error::BeefError(ref m)) if m.contains("does not exist")),
        "{unknown:?}"
    );
    assert!(!ran, "no closure runs on a refusal");
    assert_eq!(beef.clone().to_hex().expect("the BEEF writes"), before);
    assert!(beef.find_txid(&u.id()).is_some());
}

#[test]
fn edit_tx_onto_a_txid_another_entry_holds_is_refused_byte_for_byte_unchanged_817() {
    let (mut beef, u, v) = held_raw();
    beef.merge_raw_tx(v.to_binary(), None)
        .expect("the bytes are one transaction");
    let before = beef.clone().to_binary().expect("the BEEF writes");
    let order = ids(&beef);
    let refused = beef.edit_tx(&u.id(), |t| t.set_lock_time(1));
    assert!(
        matches!(refused, Err(Error::BeefError(ref m)) if m.contains("already held")),
        "{refused:?}"
    );
    assert_eq!(ids(&beef), order);
    assert_eq!(beef.clone().to_binary().expect("the BEEF writes"), before);
    assert!(beef.find_txid(&u.id()).is_some() && beef.find_txid(&v.id()).is_some());
}

#[test]
fn an_edit_that_keeps_the_txid_moves_nothing_and_is_kept_817() {
    let (mut beef, u, _) = held_raw();
    let read = beef.clone().to_binary().expect("the BEEF writes");
    assert_eq!(beef.edit_tx(&u.id(), |_| 7), Ok(7));
    assert_eq!(
        beef.clone().to_binary().expect("the BEEF writes"),
        read,
        "no byte moves"
    );
    // A field the bytes do not carry is kept, under the same key.
    let path = MerklePath::from_coinbase_txid(&u.id(), 900_000);
    beef.edit_tx(&u.id(), |t| t.merkle_path = Some(path.clone()))
        .unwrap();
    let held = beef.find_txid(&u.id()).unwrap().tx().unwrap();
    assert_eq!(held.merkle_path.as_ref().unwrap().block_height, 900_000);
    assert_eq!(beef.to_binary().expect("the BEEF writes"), read);
}

#[test]
fn a_panic_in_the_edit_leaves_the_beef_untouched_817() {
    let (mut beef, u, v) = held_raw();
    let before = beef.clone().to_hex().expect("the BEEF writes");
    let caught = catch_unwind(AssertUnwindSafe(|| {
        beef.edit_tx(&u.id(), |t| {
            t.set_lock_time(1);
            panic!("the caller's edit fails half way");
        })
    }));
    assert!(caught.is_err());
    assert!(beef.find_txid(&u.id()).is_some(), "U still held");
    assert!(beef.find_txid(&v.id()).is_none());
    assert_eq!(
        beef.find_txid(&u.id()).unwrap().tx().unwrap().lock_time(),
        0
    );
    assert_eq!(beef.to_hex().expect("the BEEF writes"), before);
}

/// Every door after an edit holds one entry under the new txid, finds it
/// and writes it once.
#[test]
fn every_door_after_an_edit_holds_one_entry_and_writes_it_once_817() {
    type Door = fn(&mut Beef, &Transaction);
    let doors: [(&str, Door); 14] = [
        ("merge_raw_tx", |b, v| {
            b.merge_raw_tx(v.to_binary(), None)
                .expect("the bytes are one transaction");
        }),
        ("merge_txid_only", |b, v| {
            b.merge_txid_only(v.id());
        }),
        ("merge_transaction", |b, v| {
            b.merge_transaction(v.clone());
        }),
        ("merge_bump", |b, v| {
            b.merge_bump(MerklePath::from_coinbase_txid(&v.id(), 900_002));
            assert_eq!(b.find_txid(&v.id()).unwrap().bump_index(), Some(0));
        }),
        ("merge_beef", |b, v| {
            let mut other = Beef::new();
            other
                .merge_raw_tx(v.to_binary(), None)
                .expect("the bytes are one transaction");
            b.merge_beef(&other)
                .expect("the source writes and reads back");
        }),
        ("find_txid", |b, v| assert!(b.find_txid(&v.id()).is_some())),
        ("find_txid_mut", |b, v| {
            assert!(b.find_txid_mut(&v.id()).is_some())
        }),
        ("find_transaction_for_signing", |b, v| {
            assert_eq!(
                b.find_transaction_for_signing(&v.id()).unwrap().id(),
                v.id()
            );
        }),
        ("find_atomic_transaction", |b, v| {
            assert_eq!(b.find_atomic_transaction(&v.id()).unwrap().id(), v.id());
        }),
        ("make_txid_only", |b, v| {
            assert!(b.make_txid_only(&v.id()).unwrap().is_txid_only());
        }),
        ("to_binary", |b, _| {
            b.to_binary().expect("the BEEF writes");
        }),
        ("to_binary_atomic", |b, v| {
            b.to_binary_atomic(&v.id()).unwrap();
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
        beef.edit_tx(&u.id(), |t| t.set_lock_time(1)).unwrap();
        run(&mut beef, &v);
        assert_eq!(
            ids(&beef),
            vec![v.id()],
            "{door}: one entry, the edited one"
        );
        assert!(beef.find_txid(&v.id()).is_some(), "{door}");
        assert!(beef.find_txid(&u.id()).is_none(), "{door}");
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

/// The toolbox's pattern (`wallet.rs:1505`): a hand `retain`, then the
/// lookups and a merge. Every held entry is found, the dropped one is not,
/// and a merge of a held txid replaces it in its place. RED on beta
/// `cfbe3c98`: `find_txid(W)` `None` and W stored twice.
#[test]
fn a_hand_retain_then_find_txid_and_merge_raw_tx_holds_each_txid_once_817() {
    let (mut beef, [x, u, w]) = three();
    beef.txs.retain(|t| t.txid() != x.id());
    assert!(beef.find_txid(&u.id()).is_some());
    assert!(beef.find_txid(&w.id()).is_some(), "W found after the shift");
    assert!(beef.find_txid(&x.id()).is_none(), "the dropped X is gone");
    beef.merge_raw_tx(w.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(ids(&beef), vec![u.id(), w.id()], "W held once");
    // The `&mut` door rebuilt the index: plain hits again.
    assert_eq!(beef.find_txid(&w.id()).unwrap().txid(), w.id());
}

/// A hand push: the pushed entry is found, and a merge of it replaces it.
#[test]
fn a_hand_push_then_a_lookup_finds_the_pushed_entry_817() {
    let (mut beef, [x, _, _]) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).expect("one transaction"));
    assert!(beef.find_txid(&y.id()).is_some());
    assert!(beef.find_txid(&x.id()).is_some());
    let held = beef.txs.len();
    beef.merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(beef.txs.len(), held, "Y held once");
}

/// A hand swap of two entries: each is found at its new place (the hit
/// names the other entry, a scan answers), and a merge of either replaces
/// it there, the other kept.
#[test]
fn a_hand_swap_then_a_lookup_of_each_finds_it_817() {
    let (mut beef, [x, u, w]) = three();
    beef.txs.swap(0, 1);
    assert_eq!(beef.find_txid(&x.id()).unwrap().txid(), x.id());
    assert_eq!(beef.find_txid(&u.id()).unwrap().txid(), u.id());
    beef.merge_raw_tx(x.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(
        ids(&beef),
        vec![u.id(), x.id(), w.id()],
        "U kept, X in its place"
    );
}

/// The stated window: a hand replacement that keeps the count makes the
/// new entry's lookup miss (a miss cannot be told from an absent txid
/// without a scan on every miss), so a merge of it stores it twice, as the
/// reference does too; `reindex` closes it.
#[test]
fn a_hand_replace_keeping_the_count_misses_until_reindex_stated_817() {
    let (mut beef, [x, u, _]) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    beef.txs[0] = BeefTx::from_raw_tx(y.to_binary(), None).expect("one transaction");
    assert!(beef.find_txid(&y.id()).is_none(), "the window: a miss");
    assert!(
        beef.find_txid(&x.id()).is_none(),
        "the replaced X: its hit names Y"
    );
    let mut windowed = beef.clone();
    windowed
        .merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    let twice = windowed.txs.iter().filter(|t| t.txid() == y.id()).count();
    assert_eq!(twice, 2, "stored twice inside the window");
    beef.reindex();
    assert!(beef.find_txid(&y.id()).is_some(), "reindex: found");
    let held = beef.txs.len();
    beef.merge_raw_tx(y.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(beef.txs.len(), held, "after reindex, held once");
    assert!(beef.find_txid(&u.id()).is_some());
}

/// A hand reorder that keeps the count with no miss is noticed by the hit
/// check alone; `reindex` after it leaves every lookup a plain hit.
#[test]
fn reindex_after_a_hand_reorder_finds_every_entry_817() {
    let (mut beef, txs) = three();
    beef.txs.reverse();
    beef.reindex();
    for t in &txs {
        assert_eq!(beef.find_txid(&t.id()).unwrap().txid(), t.id());
    }
}

/// The deprecated `tx_mut` keeps the #171 window, and `reindex` re-keys an
/// entry edited through it.
#[test]
#[allow(deprecated)] // the deprecated path itself is what this pins
fn reindex_rekeys_an_entry_edited_through_the_deprecated_tx_mut_817() {
    let (mut beef, u, v) = held_raw();
    beef.find_txid_mut(&u.id())
        .unwrap()
        .tx_mut()
        .unwrap()
        .set_lock_time(1);
    assert!(beef.find_txid(&v.id()).is_none(), "the #171 window");
    beef.reindex();
    assert_eq!(
        beef.find_txid(&v.id()).unwrap().input_txids,
        vec!["bb".repeat(32)]
    );
    beef.merge_raw_tx(v.to_binary(), None)
        .expect("the bytes are one transaction");
    assert_eq!(ids(&beef), vec![v.id()]);
}

/// `Beef` and `BeefTx` are `Send` and `Sync`: this change added no interior
/// mutability (the index's count is a plain `usize`), and since #843d1 the
/// `Script` every `Transaction` holds keeps its caches in `OnceLock`s, so the
/// last `RefCell` under them is gone (until #843d1 this test pinned them as
/// `Send` and not `Sync`, as on beta `cfbe3c98`).
#[test]
fn beef_and_beef_tx_are_send_and_sync_with_no_interior_mutability_of_their_own_817() {
    fn shareable<T: Send + Sync>() {}
    shareable::<Beef>();
    shareable::<BeefTx>();
}

/// The cold read's case (#817's fold of the rebuild): a hand push, a `&mut`
/// door (which indexes the pushed entry), a hand `retain` back to the old
/// count, then a lookup of the pushed txid: found, as the door's index
/// noticed the push and the hit check notices the shift. RED with the
/// door's index left unsynced (the count then matches the stale index and
/// the lookup misses).
#[test]
fn a_hand_push_a_door_then_a_retain_back_to_the_count_finds_the_pushed_entry_817() {
    let (mut beef, [x, u, _]) = three();
    let z = tx(&"cc".repeat(32), 7_000);
    beef.txs
        .push(BeefTx::from_raw_tx(z.to_binary(), None).unwrap());
    beef.find_txid_mut(&u.id()).unwrap();
    beef.txs.retain(|t| t.txid() != x.id());
    assert_eq!(beef.txs.len(), 3);
    assert_eq!(beef.find_txid(&z.id()).map(BeefTx::txid), Some(z.id()));
    let held = beef.txs.len();
    beef.merge_raw_tx(z.to_binary(), None).unwrap();
    assert_eq!(beef.txs.len(), held, "Z held once");
}

/// A hand push of a txid the BEEF already holds (stated): a `&self` lookup
/// answers the earlier entry until a `&mut` door runs, the later after it
/// (the door indexes the pushed entry, the last position winning as the
/// rebuild has it); both entries stay.
#[test]
fn a_hand_push_of_a_held_txid_is_answered_by_the_later_entry_after_a_door_stated_817() {
    let (mut beef, [x, _, _]) = three();
    beef.txs
        .push(BeefTx::from_raw_tx(x.to_binary(), None).unwrap());
    let found = beef.find_txid(&x.id()).unwrap();
    assert!(
        std::ptr::eq(found, &beef.txs[0]),
        "the earlier before a door"
    );
    beef.merge_txid_only("ab".repeat(32));
    let found = beef.find_txid(&x.id()).unwrap();
    assert!(std::ptr::eq(found, &beef.txs[3]), "the later after a door");
    assert_eq!(beef.txs.iter().filter(|t| t.txid() == x.id()).count(), 2);
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
    assert!(beef.txs.is_empty());
}

/// The no-op edit keeps the entry's `is_valid` (the strength read's S4).
#[test]
fn a_no_op_edit_keeps_the_entrys_is_valid_817() {
    let (mut beef, u, _) = held_raw();
    beef.find_txid_mut(&u.id()).unwrap().is_valid = Some(true);
    beef.edit_tx(&u.id(), |_| ()).unwrap();
    assert_eq!(beef.find_txid(&u.id()).unwrap().is_valid, Some(true));
}

/// A closure returning an `Err` as its value still has its edit stored.
#[test]
fn a_closure_returning_an_err_value_still_has_its_edit_stored_817() {
    let (mut beef, u, v) = held_raw();
    let value: Result<(), &str> = beef
        .edit_tx(&u.id(), |t| {
            t.set_lock_time(1);
            Err("the caller's own")
        })
        .unwrap();
    assert_eq!(value, Err("the caller's own"));
    assert!(beef.find_txid(&v.id()).is_some());
}

/// The rule read's two cells inside the stated window (#817's fold of the
/// rebuild). After a hand replacement keeping the count, `edit_tx`'s
/// collision check misses the held Y (its lookup misses), so an edit of X'
/// onto Y stores Y twice. After a deprecated `tx_mut` edit of U to V,
/// `edit_tx(V)` refuses (a miss, the count standing) and `edit_tx(U)`
/// refuses too (its hit names V); that mismatched hit rebuilds the index,
/// so `edit_tx(V)` then finds V, as it does after `reindex`.
#[test]
#[allow(deprecated)] // the deprecated path's cell
fn the_two_edit_tx_cells_inside_the_window_stated_817() {
    let (mut beef, [x, _, _]) = three();
    let y = locked(x.clone(), 5);
    beef.txs[1] = BeefTx::from_raw_tx(y.to_binary(), None).unwrap();
    beef.edit_tx(&x.id(), |t| t.set_lock_time(5)).unwrap();
    let held = beef.txs.iter().filter(|t| t.txid() == y.id()).count();
    assert_eq!(held, 2, "the collision missed inside the window");

    let (mut beef, u, v) = held_raw();
    beef.find_txid_mut(&u.id())
        .unwrap()
        .tx_mut()
        .unwrap()
        .set_lock_time(1);
    assert!(beef.edit_tx(&v.id(), |_| ()).is_err(), "V missed");
    assert!(beef.edit_tx(&u.id(), |_| ()).is_err(), "U's hit names V");
    assert_eq!(
        beef.edit_tx(&v.id(), |_| 3),
        Ok(3),
        "found after the rebuild"
    );
}

/// The second fold of the rebuild, the cold read's attack C (the pin of
/// `indexed_prefix_holds`, and of `index_of`'s and `sync_index`'s use of
/// it): a hand removal of an early entry then two pushes leaves the count
/// grown past the indexed one with the indexed prefix moved (P sits where W
/// was), so a `&self` lookup scans `txs` whole and the next `&mut` door
/// rebuilds the index whole: P and Q each found, and each merged into its
/// place, held once. RED with the prefix check forced true (P missed and
/// stored twice), with it dropped from `index_of` (P missed), and with the
/// rebuild deleted from `sync_index` (P stored twice).
#[test]
fn a_hand_removal_then_two_pushes_finds_each_pushed_entry_817() {
    let (mut beef, [x, u, w]) = three();
    beef.txs.retain(|t| t.txid() != x.id());
    let p = tx(&"ab".repeat(32), 7_000);
    let q = tx(&"cd".repeat(32), 9_000);
    beef.txs
        .push(BeefTx::from_raw_tx(p.to_binary(), None).unwrap());
    beef.txs
        .push(BeefTx::from_raw_tx(q.to_binary(), None).unwrap());
    for t in [&u, &w, &p, &q] {
        assert_eq!(beef.find_txid(&t.id()).map(BeefTx::txid), Some(t.id()));
    }
    beef.merge_raw_tx(p.to_binary(), None).unwrap();
    beef.merge_raw_tx(q.to_binary(), None).unwrap();
    assert_eq!(ids(&beef), vec![u.id(), w.id(), p.id(), q.id()]);
}

/// The second fold of the rebuild, the strength read's F4: two entries of
/// one txid pushed by hand past the indexed count are answered by the
/// later, the last position winning as the index's rebuild has it (the
/// tail scanned from the end down). RED with the tail scanned from its
/// start (the earlier answered).
#[test]
fn two_hand_pushed_twins_are_answered_by_the_later_817() {
    let (mut beef, _) = three();
    let y = tx(&"cc".repeat(32), 7_000);
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).unwrap());
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).unwrap());
    let found = beef.find_txid(&y.id()).unwrap();
    assert!(std::ptr::eq(found, &beef.txs[4]), "the later twin");
}

/// The second fold of the rebuild, the strength read's F1 by a hand push:
/// U pushed by hand beside the U held, then `edit_tx(U)` edits the entry
/// the index names (the pushed one, the last position) to V; the U still
/// held is found and not merged again, as the reference's index rebuilt
/// after the edit finds it (`Beef.ts:342-352,516-524`). The twin read
/// from bytes is the recorded cell of `tests/beef_door_sync_817.rs`. RED
/// on `ba0dc50e` (`edit_tx` removed U's key: U not found, stored again).
#[test]
fn an_edit_of_a_hand_pushed_twin_keeps_the_other_entry_found_817() {
    let (mut beef, [_, u, _]) = three();
    beef.txs
        .push(BeefTx::from_raw_tx(u.to_binary(), None).unwrap());
    let v = locked(u.clone(), 1);
    beef.edit_tx(&u.id(), |t| t.set_lock_time(1)).unwrap();
    assert!(std::ptr::eq(beef.find_txid(&u.id()).unwrap(), &beef.txs[1]));
    assert!(std::ptr::eq(beef.find_txid(&v.id()).unwrap(), &beef.txs[3]));
    beef.merge_txid_only(u.id());
    assert_eq!(beef.txs.len(), 4, "U not stored again");
    assert!(std::ptr::eq(beef.find_txid(&u.id()).unwrap(), &beef.txs[1]));
}

/// The same twin seen by a whole rebuild (`reindex`) rather than by the
/// pushed tail: the rebuild notes it, so `edit_tx` keeps the U still held
/// found. RED with the rebuild's twin note removed.
#[test]
fn an_edit_of_a_twin_after_reindex_keeps_the_other_entry_found_817() {
    let (mut beef, [_, u, _]) = three();
    beef.txs
        .push(BeefTx::from_raw_tx(u.to_binary(), None).unwrap());
    beef.reindex();
    beef.edit_tx(&u.id(), |t| t.set_lock_time(1)).unwrap();
    assert!(std::ptr::eq(beef.find_txid(&u.id()).unwrap(), &beef.txs[1]));
    beef.merge_txid_only(u.id());
    assert_eq!(beef.txs.len(), 4, "U not stored again");
}
