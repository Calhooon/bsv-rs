#![cfg(test)]
//! #817's fold of the rebuild: the index's state after a hand edit of the
//! public `txs` (the strength read's S1 and S2, and the rule read's FIX-2),
//! read on the private fields the doors keep, where the public answers are
//! the same whichever path ran and only the cost differs.
#![allow(clippy::unwrap_used, clippy::expect_used)] // #134: test code: a failed unwrap is the test failing

use super::super::beef_tx::BeefTx;
use super::Beef;
use crate::script::{LockingScript, UnlockingScript};
use crate::transaction::{Transaction, TransactionInput, TransactionOutput};

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

/// X, U, W merged raw through the doors.
fn three() -> (Beef, [Transaction; 3]) {
    let txs = [tx("dd", 3_000), tx("bb", 2_000), tx("ee", 5_000)];
    let mut beef = Beef::new();
    for t in &txs {
        beef.merge_raw_tx(t.to_binary(), None).unwrap();
    }
    (beef, txs)
}

/// S1: a `&mut` door after a hand push indexes up to the entries, and so
/// does one after a hand `retain`: the indexed length is the entry count
/// and every entry a plain hit.
#[test]
fn a_mut_door_after_a_hand_push_or_retain_indexes_every_entry_817() {
    let (mut beef, [x, _, _]) = three();
    let y = tx("cc", 7_000);
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).unwrap());
    assert_eq!(beef.indexed_len, 3, "the hand push is not indexed yet");
    beef.find_txid_mut(&x.id());
    assert_eq!(beef.indexed_len, beef.txs.len());
    assert_eq!(beef.txid_index.get(&y.id()), Some(&3));
    beef.txs.retain(|t| t.txid() != x.id());
    beef.merge_txid_only(y.id());
    assert_eq!(beef.indexed_len, beef.txs.len());
    for (i, t) in beef.txs.iter().enumerate() {
        assert_eq!(beef.txid_index.get(&t.txid()), Some(&i));
    }
}

/// S2: a miss while the count stands reads no entry. A hand replacement
/// keeping the count holds Y in X's place: a scan would find it, so the
/// miss is the guard's (the stated window).
#[test]
fn a_miss_while_the_count_stands_reads_no_entry_817() {
    let (mut beef, _) = three();
    let y = tx("cc", 7_000);
    beef.txs[0] = BeefTx::from_raw_tx(y.to_binary(), None).unwrap();
    assert_eq!(beef.index_of(&y.id()), None);
}

/// A `&mut` door that finds the count grown with the prefix in place
/// indexes the pushed entries alone: an earlier count-keeping replacement
/// (the window) stays unindexed, where a whole rebuild would index it.
#[test]
fn a_grown_count_indexes_the_tail_alone_817() {
    let (mut beef, [x, _, _]) = three();
    let y = tx("cc", 7_000);
    let z = tx("ab", 9_000);
    beef.txs[0] = BeefTx::from_raw_tx(y.to_binary(), None).unwrap();
    beef.txs
        .push(BeefTx::from_raw_tx(z.to_binary(), None).unwrap());
    beef.find_txid_mut(&z.id());
    assert_eq!(beef.txid_index.get(&z.id()), Some(&3));
    assert_eq!(beef.txid_index.get(&y.id()), None, "the tail alone");
    assert_eq!(beef.txid_index.get(&x.id()), Some(&0), "not rebuilt");
}

/// A grown count whose prefix moved (a `retain` then pushes back past the
/// old count) rebuilds whole at the next `&mut` door. The door looks up Y,
/// which the index never held (the strength read's F2 of the second fold:
/// a lookup of an indexed txid hits the wrong entry and rebuilds anyway),
/// so the rebuild in `sync_index`'s else branch is the one that finds it;
/// RED with that rebuild deleted (`None`).
#[test]
fn a_grown_count_with_a_moved_prefix_rebuilds_whole_817() {
    let (mut beef, [x, u, w]) = three();
    beef.txs.retain(|t| t.txid() != x.id());
    let y = tx("cc", 7_000);
    let z = tx("ab", 9_000);
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).unwrap());
    beef.txs
        .push(BeefTx::from_raw_tx(z.to_binary(), None).unwrap());
    assert_eq!(
        beef.find_txid_mut(&y.id()).map(|e| e.txid()),
        Some(y.id()),
        "Y, never indexed, found by the rebuild"
    );
    assert_eq!(
        beef.txid_index.get(&x.id()),
        None,
        "X dropped from the index"
    );
    for (i, id) in [u.id(), w.id(), y.id(), z.id()].iter().enumerate() {
        assert_eq!(beef.txid_index.get(id), Some(&i));
    }
}

/// The rule read's FIX-2: after a hand swap a `&mut` door whose lookup
/// hits the other entry rebuilds the index, so the lookups after it are
/// plain hits.
#[test]
fn a_mut_door_hitting_another_entry_after_a_hand_swap_rebuilds_817() {
    let (mut beef, [x, u, _]) = three();
    beef.txs.swap(0, 1);
    assert_eq!(
        beef.txid_index.get(&x.id()),
        Some(&0),
        "stale before a door"
    );
    beef.find_txid_mut(&x.id());
    assert_eq!(beef.txid_index.get(&x.id()), Some(&1));
    assert_eq!(beef.txid_index.get(&u.id()), Some(&0));
}

/// The second fold of the rebuild (the strength read's F3): the same
/// `retain` and pushes, then a `&self` lookup of Y, which the index never
/// held: the moved prefix sends it to the whole scan, where the unindexed
/// tail alone would miss Y. RED with `indexed_prefix_holds` dropped from
/// `index_of`.
#[test]
fn a_self_lookup_after_a_retain_and_pushes_scans_whole_817() {
    let (mut beef, [x, _, _]) = three();
    beef.txs.retain(|t| t.txid() != x.id());
    let y = tx("cc", 7_000);
    let z = tx("ab", 9_000);
    beef.txs
        .push(BeefTx::from_raw_tx(y.to_binary(), None).unwrap());
    beef.txs
        .push(BeefTx::from_raw_tx(z.to_binary(), None).unwrap());
    assert_eq!(beef.index_of(&y.id()), Some(2));
    assert_eq!(beef.indexed_len, 3, "a &self lookup writes no index");
}

/// Each entry's txid and raw bytes in order: what the two unframed-bytes
/// pins compare, as the writers refuse an entry held raw that is not one
/// transaction (#817's writers, `beef_raw_frame.rs`).
fn held(beef: &Beef) -> Vec<(String, Option<Vec<u8>>)> {
    beef.txs
        .iter()
        .map(|t| (t.txid(), t.raw_tx().map(<[u8]>::to_vec)))
        .collect()
}

/// `edit_tx` on raw bytes that do not parse is refused as `BeefError`, the
/// BEEF unchanged and the closure not run, as its rustdoc says (#817's fold:
/// the parser's own error until then, `ReaderUnderflow`). Built by the
/// crate-private `from_framed_raw_tx`: the public doors refuse such bytes
/// since the writers' change of #817.
#[test]
fn edit_tx_on_raw_bytes_that_do_not_parse_is_a_beef_error_817() {
    let mut beef = Beef::new();
    beef.txs
        .push(BeefTx::from_framed_raw_tx(vec![0xde, 0xad], None));
    beef.reindex();
    let id = beef.txs[0].txid();
    let before = held(&beef);
    let mut ran = false;
    let refused = beef.edit_tx(&id, |_| ran = true).unwrap_err();
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
    let mut beef = Beef::new();
    beef.txs.push(BeefTx::from_framed_raw_tx(raw.clone(), None));
    beef.reindex();
    let id = beef.txs[0].txid();
    assert_ne!(id, t.id());
    let before = held(&beef);
    let mut ran = false;
    let refused = beef.edit_tx(&id, |_| ran = true).unwrap_err();
    assert_eq!(
        refused,
        crate::Error::BeefError(format!(
            "{id} is held in this Beef as raw bytes that do not parse as a transaction: \
             transaction error: Serialized transaction contains trailing data"
        ))
    );
    assert!(!ran);
    assert_eq!(held(&beef), before, "no byte moves");
    assert_eq!(beef.find_txid(&id).unwrap().raw_tx(), Some(&raw[..]));
}
