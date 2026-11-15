#![cfg(test)]
//! The index and the marks at the rows' own doors (#843b), where #817's fold
//! of the rebuild pinned the index's state after a hand edit of the public
//! `txs`.
//!
//! Those pins read the private fields (`indexed_len`, `txid_index`) for what
//! each path cost after a hand push, `retain`, swap or replacement, and one
//! of them pinned the stated window's miss. The fields live in `rows.rs`'
//! `sealed` module now, no code outside it can edit a row but through its
//! functions, and the window is gone, so the six tests are restated on the
//! law: after any door the index names, for every txid a row holds, the
//! last row holding it, and nothing else. Replaced, each by the test named:
//! `a_mut_door_after_a_hand_push_or_retain_indexes_every_entry_817`,
//! `a_grown_count_indexes_the_tail_alone_817`,
//! `a_grown_count_with_a_moved_prefix_rebuilds_whole_817`,
//! `a_mut_door_hitting_another_entry_after_a_hand_swap_rebuilds_817` and
//! `a_self_lookup_after_a_retain_and_pushes_scans_whole_817` by
//! `the_index_is_the_rows_after_the_general_door_843b`;
//! `a_miss_while_the_count_stands_reads_no_entry_817` (the window's miss)
//! by `a_replacement_in_place_is_found_at_once_843b`.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test code: a failed unwrap is the test failing

use super::super::beef_tx::{BeefTx, BEEF_V2};
use super::Beef;
use crate::script::{LockingScript, UnlockingScript};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput, Txid};

/// A transaction with one `OP_TRUE` output of `sats` spending output 0 of
/// `"<byte>" x 32`.
fn tx(byte: &str, sats: u64) -> Transaction {
    let mut t = Transaction::new();
    let mut input = TransactionInput::new(byte.repeat(32).parse().unwrap(), 0);
    input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
    t.inputs_mut().push(input);
    t.outputs_mut().push(TransactionOutput::new(
        sats,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// A raw entry of `t`, as a merge door builds it.
fn entry(t: &Transaction) -> BeefTx {
    BeefTx::from_raw_tx(t.to_binary(), None)
        .unwrap()
        .with_txid(t.txid())
}

/// X, U, W merged raw through the doors.
fn three() -> (Beef, [Transaction; 3]) {
    let txs = [tx("dd", 3_000), tx("bb", 2_000), tx("ee", 5_000)];
    let mut beef = Beef::new();
    for t in &txs {
        beef.merge_raw_tx(t.to_binary(), None).unwrap();
    }
    (beef, txs)
}

/// The law: every row's txid is found at the last row holding it, through
/// the index and through a copy's, and a txid no row holds is not found.
fn assert_law(beef: &Beef, absent: &[Txid]) {
    let copy = beef.clone();
    for (i, row) in beef.txs().iter().enumerate() {
        let last = beef
            .txs()
            .iter()
            .rposition(|t| t.txid() == row.txid())
            .unwrap();
        assert_eq!(beef.position(&row.txid()), Some(last), "row {i}");
        assert_eq!(copy.position(&row.txid()), Some(last), "row {i}, a copy");
    }
    for txid in absent {
        assert_eq!(beef.position(txid), None);
        assert_eq!(copy.position(txid), None);
    }
}

/// The edits #817's fold made by hand on the public `txs` (a push, a
/// `retain`, pushes back past the old count, a swap), each through the
/// rows' general door, with a lookup between them so that the index is
/// filled when the door empties it: the index is the rows' after each.
#[test]
fn the_index_is_the_rows_after_the_general_door_843b() {
    let (mut beef, [x, u, w]) = three();
    let (y, z) = (tx("cc", 7_000), tx("ab", 9_000));
    assert_law(&beef, &[y.txid(), z.txid()]);

    beef.rows_mut().0.push(entry(&y));
    assert_law(&beef, &[z.txid()]);
    assert_eq!(beef.position(&y.txid()), Some(3));

    beef.rows_mut().0.retain(|t| t.txid() != x.txid());
    assert_law(&beef, &[x.txid(), z.txid()]);

    beef.rows_mut().0.push(entry(&z));
    assert_law(&beef, &[x.txid()]);
    for (i, t) in [&u, &w, &y, &z].iter().enumerate() {
        assert_eq!(beef.position(&t.txid()), Some(i));
    }

    beef.rows_mut().0.swap(0, 1);
    assert_law(&beef, &[x.txid()]);
    assert_eq!(beef.position(&u.txid()), Some(1));
    assert_eq!(beef.position(&w.txid()), Some(0));

    // The doors after it read the same rows.
    beef.merge_txid_only(x.txid());
    assert_law(&beef, &[]);
    assert_eq!(beef.txs().len(), 5);
}

/// The stated window of #817 is closed: an entry replaced in place, the
/// count kept, is found at once and merged once, and the txid it replaced
/// is no longer found. Until #843b the lookup missed (`None`) and a
/// `merge_raw_tx` of the new entry stored it twice.
#[test]
fn a_replacement_in_place_is_found_at_once_843b() {
    let (mut beef, [x, _, _]) = three();
    let y = tx("cc", 7_000);
    beef.rows_mut().0[0] = entry(&y);
    assert_eq!(beef.position(&y.txid()), Some(0));
    assert_eq!(beef.position(&x.txid()), None);
    beef.merge_raw_tx(y.to_binary(), None).unwrap();
    assert_eq!(beef.txs().len(), 3, "merged once");
    assert_law(&beef, &[x.txid()]);
}

/// The constant-time doors keep a filled index: an append, a replacement by
/// another txid (re-keyed), a replacement by the same txid, and the two
/// that make or meet a twin, after which the last row holding a txid is
/// the one found.
#[test]
fn append_and_replace_keep_the_index_the_rows_843b() {
    let (mut beef, [x, u, w]) = three();
    let (y, z) = (tx("cc", 7_000), tx("ab", 9_000));
    assert_law(&beef, &[y.txid()]); // the index is filled

    assert_eq!(beef.append_entry(entry(&y)), 3);
    assert_law(&beef, &[z.txid()]);

    // Another txid, no twin: the old key goes, the new one is there.
    let old = beef.replace_entry(1, entry(&z));
    assert_eq!(old.txid(), u.txid());
    assert_eq!(beef.position(&z.txid()), Some(1));
    assert_law(&beef, &[u.txid()]);

    // The same txid: nothing moves.
    beef.replace_entry(1, BeefTx::from_tx(z.clone(), None).with_txid(z.txid()));
    assert_eq!(beef.position(&z.txid()), Some(1));
    assert_law(&beef, &[u.txid()]);

    // A replacement by a txid another row holds: twins, the later found.
    beef.replace_entry(0, entry(&w));
    assert_eq!(beef.position(&w.txid()), Some(2));
    assert_law(&beef, &[x.txid(), u.txid()]);

    // An appended twin is the last.
    assert_eq!(beef.append_entry(entry(&w)), 4);
    assert_eq!(beef.position(&w.txid()), Some(4));
    assert_law(&beef, &[x.txid()]);

    // With twins held, a replacement of the last twin by another txid leaves
    // the earlier one found.
    beef.replace_entry(4, entry(&u));
    assert_eq!(beef.position(&w.txid()), Some(2));
    assert_eq!(beef.position(&u.txid()), Some(4));
    assert_law(&beef, &[x.txid()]);
}

/// The marks at each door: every door that changes an entry asks for a sort
/// and clears the wire mark; a BUMP's door and an entry's BUMP position
/// clear the wire mark alone, as the reference's `mergeBump` marks no sort
/// (`Beef.ts:690`); `swap_parse` of the same transaction moves neither.
#[test]
fn each_door_sets_the_marks_it_owes_843b() {
    let read = || {
        let (mut beef, [x, _, _]) = three();
        let bytes = beef.to_binary().unwrap();
        (Beef::from_binary(&bytes).unwrap(), x)
    };
    let sorted = |mut beef: Beef| {
        beef.sort_txs();
        beef
    };
    let (beef, x) = read();
    assert!(beef.wire_order() && beef.needs_sort(), "as read");
    let beef = sorted(beef);
    assert!(!beef.wire_order() && !beef.needs_sort(), "sorted");

    // The entries' doors: both marks.
    type EntryDoor = fn(&mut Beef, &Transaction);
    let doors: [(&str, EntryDoor); 4] = [
        ("append", |b, _| {
            b.append_entry(entry(&tx("cc", 1)));
        }),
        ("replace", |b, x| {
            b.replace_entry(0, entry(x));
        }),
        ("the general door", |b, _| {
            let _ = b.rows_mut();
        }),
        ("retain_bumps", |b, _| b.retain_bumps(|_, _| true)),
    ];
    for (name, door) in doors {
        let mut beef = sorted(read().0);
        door(&mut beef, &x);
        assert!(!beef.wire_order() && beef.needs_sort(), "{name}");
        let mut beef = read().0;
        door(&mut beef, &x);
        assert!(!beef.wire_order() && beef.needs_sort(), "{name}, as read");
    }

    // The BUMP's doors and an entry's BUMP position: the wire mark alone.
    let bump = crate::transaction::MerklePath::from_coinbase_txid(&x.id(), 7);
    type BumpDoor = Box<dyn Fn(&mut Beef)>;
    let wire_only: [(&str, BumpDoor); 3] = [
        ("push_bump", {
            let bump = bump.clone();
            Box::new(move |b| {
                b.push_bump(bump.clone());
            })
        }),
        (
            "bump_mut",
            Box::new(|b| {
                let _ = b.bump_mut(0);
            }),
        ),
        ("point", Box::new(|b| b.point_entry(0, Some(3)))),
    ];
    for (name, door) in &wire_only {
        let mut beef = sorted(read().0);
        door(&mut beef);
        assert!(!beef.wire_order() && !beef.needs_sort(), "{name}");
        let mut beef = read().0;
        door(&mut beef);
        assert!(!beef.wire_order() && beef.needs_sort(), "{name}, as read");
    }

    // `swap_parse`: the same transaction moves no mark; another, a txid-only
    // entry's and a transaction of another id are handed back.
    let (mut beef, x) = read();
    let at = beef.position(&x.txid()).unwrap();
    let mut linked = x.clone();
    linked.merkle_path = Some(bump);
    assert!(beef.swap_parse(at, linked).is_none());
    assert!(beef.wire_order() && beef.needs_sort(), "swap_parse");
    assert!(beef.txs()[at].tx().unwrap().merkle_path.is_some(), "stored");
    assert!(beef.swap_parse(at, tx("cc", 1)).is_some(), "another id");
    assert!(beef.txs()[at].tx().unwrap().merkle_path.is_some());
    let mut stub = Beef::new();
    stub.merge_txid_only(x.txid());
    assert!(stub.swap_parse(0, x.clone()).is_some(), "a txid alone");
    assert!(stub.txs()[0].is_txid_only());
}

/// `retain_bumps` re-points every entry: one whose BUMP moved names its new
/// position, one whose BUMP was dropped names none (its input list read
/// again), one that named no BUMP keeps the index it was given.
#[test]
fn retain_bumps_re_points_every_entry_843b() {
    let (a, b, c, d) = (tx("a1", 1), tx("b2", 2), tx("c3", 3), tx("d4", 4));
    let path = |t: &Transaction, height| {
        crate::transaction::MerklePath::from_coinbase_txid(&t.id(), height)
    };
    let mut beef = Beef::new();
    for (t, height) in [(&a, 10), (&b, 11), (&c, 12)] {
        beef.merge_bump(path(t, height));
        beef.merge_raw_tx(t.to_binary(), None).unwrap();
    }
    beef.merge_raw_tx(d.to_binary(), Some(9)).unwrap();
    let named =
        |beef: &Beef| -> Vec<Option<usize>> { beef.txs().iter().map(BeefTx::bump_index).collect() };
    assert_eq!(named(&beef), [Some(0), Some(1), Some(2), Some(9)]);
    assert!(beef.txs()[1].input_txids().is_empty(), "proven: none read");

    let mut asked = Vec::new();
    beef.retain_bumps(|i, bump| {
        asked.push((i, bump.block_height));
        i != 1
    });
    assert_eq!(asked, [(0, 10), (1, 11), (2, 12)], "in order, by position");
    assert_eq!(named(&beef), [Some(0), None, Some(1), Some(9)]);
    assert_eq!(
        beef.bumps()
            .iter()
            .map(|p| p.block_height)
            .collect::<Vec<_>>(),
        [10, 12]
    );
    assert_eq!(beef.txs()[1].input_txids().len(), 1, "read again");
    // Every entry that names a BUMP names the one that holds it.
    assert!(beef.bumps()[1].contains(&c.id()));
    assert_law(&beef, &[]);
}

/// Each entry's txid and raw bytes in order: what the two unframed-bytes
/// pins compare, as the writers refuse an entry held raw that is not one
/// transaction (#817's writers, `beef_raw_frame.rs`).
fn held(beef: &Beef) -> Vec<(String, Option<Vec<u8>>)> {
    beef.txs()
        .iter()
        .map(|t| (t.id(), t.raw_tx().map(<[u8]>::to_vec)))
        .collect()
}

/// `edit_tx` on raw bytes that do not parse is refused as `BeefError`, the
/// BEEF unchanged and the closure not run, as its rustdoc says (#817's fold:
/// the parser's own error until then, `ReaderUnderflow`). Built by the
/// crate-private `from_framed_raw_tx` through the test door: the public
/// doors refuse such bytes since the writers' change of #817.
#[test]
fn edit_tx_on_raw_bytes_that_do_not_parse_is_a_beef_error_817() {
    let rows = vec![BeefTx::from_framed_raw_tx(vec![0xde, 0xad], None)];
    let mut beef = Beef::with_rows_for_test(BEEF_V2, rows, Vec::new());
    let id = beef.txs()[0].txid();
    let before = held(&beef);
    let mut ran = false;
    let refused = beef.edit_tx(id, |_| ran = true).unwrap_err();
    assert!(
        matches!(&refused, crate::Error::BeefError(m)
            if m.starts_with(&format!("{id} is held in this Beef as raw bytes that do not parse as a transaction: "))),
        "{refused:?}"
    );
    assert!(!ran);
    assert_eq!(held(&beef), before);
}

/// An edit of an entry whose raw bytes carry a byte after the transaction
/// (a crate-only state: no public door holds such bytes since #817) is
/// refused and moves nothing, as an entry whose bytes do not parse is:
/// since #840 `Transaction::from_binary` refuses the byte after the lock
/// time, as the reference's `BeefTx` throws reading it through `Transaction.fromBinaryView`
/// (`BeefTx.ts:121`, `Transaction.ts:532-535`). Until #840 the edit ran on the prefix and the
/// entry kept its txid, the hash of every byte (#817's fold).
#[test]
fn an_edit_of_raw_bytes_with_a_trailing_byte_is_refused_840() {
    let t = tx("bb", 2_000);
    let mut raw = t.to_binary();
    raw.push(0x00);
    let rows = vec![BeefTx::from_framed_raw_tx(raw.clone(), None)];
    let mut beef = Beef::with_rows_for_test(BEEF_V2, rows, Vec::new());
    let id = beef.txs()[0].txid();
    assert_ne!(id, t.txid());
    let before = held(&beef);
    let mut ran = false;
    let refused = beef.edit_tx(id, |_| ran = true).unwrap_err();
    assert_eq!(
        refused,
        crate::Error::BeefError(format!(
            "{id} is held in this Beef as raw bytes that do not parse as a transaction: \
             transaction error: Serialized transaction contains trailing data"
        ))
    );
    assert!(!ran);
    assert_eq!(held(&beef), before, "no byte moves");
    assert_eq!(beef.find_txid(id).unwrap().raw_tx(), Some(&raw[..]));
}

/// An edit that moves nothing leaves the marks as they stood and stores
/// what the bytes do not carry; an edit of the bytes re-keys the entry, and
/// on a BEEF read with a txid twice the other entry stays found (#817's
/// second fold, held by the rows since #843b).
#[test]
fn edit_tx_keeps_a_twin_found_and_a_no_op_moves_no_mark_843b() {
    let (mut beef, [x, u, _]) = three();
    let bytes = beef.to_binary().unwrap();
    let mut read = Beef::from_binary(&bytes).unwrap();
    read.edit_tx(u.txid(), |tx| tx.metadata.insert("k".into(), 1.into()))
        .unwrap();
    assert!(read.wire_order(), "a no-op edit leaves the BEEF as read");
    let kept = read.find_txid(u.txid()).unwrap().tx().unwrap();
    assert_eq!(kept.metadata.get("k"), Some(&1.into()), "stored");

    // A twin of X, then an edit of the later X: the earlier one is found.
    beef.rows_mut().0.push(entry(&x));
    assert_eq!(beef.position(&x.txid()), Some(3));
    let edited = beef
        .edit_tx(x.txid(), |tx| {
            tx.set_lock_time(9);
            tx.txid()
        })
        .unwrap();
    assert_eq!(beef.position(&edited), Some(3));
    assert_eq!(beef.position(&x.txid()), Some(0), "the twin");
    assert_law(&beef, &[]);
}
