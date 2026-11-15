//! The rows of a [`Beef`] and the doors to them (#843, its second pull
//! request).
//!
//! A BEEF's entries (`txs`) and its BUMPs (`bumps`) live in [`Rows`],
//! declared in the inline module `sealed` below beside what is derived from
//! them: the txid index (each held txid's last position), the two marks
//! (`needs_sort`, `wire_order`) and, in each entry, the position of the BUMP
//! it names. Every field is private to `sealed`, so no other code can name
//! one: a change of a row goes through a function of `sealed`, which does the
//! derived value's part itself, or does not compile (E0616, E0451). The
//! functions are of three kinds. Those that change one row and its index key
//! in constant time (`append`, `replace`, `swap_parse`, `point`, `push_bump`,
//! `bump_mut`). One that removes BUMPs and re-points every entry
//! (`retain_bumps`). And ONE general door, `write`, which empties the index
//! and sets both marks BEFORE it lends the entries mutably; the index is
//! filled again through `&self`, on the next lookup, from the rows as they
//! then stand, and no `&self` lookup can run while `write`'s borrow lives.
//! No function lends `&mut Vec<MerklePath>`, so no BUMP changes its position
//! but through `retain_bumps`. The IDENTITY law for the BEEF
//! (`docs/design/843-identity-and-framing.md`, section 2, Part O), held by
//! the compiler; `tests/arch_field_writes_843.rs` pins `sealed`'s text.
//!
//! What the compiler does not hold, and a property does
//! (`tests/beef_rows_843b.rs`, `fuzz_beef_parser`): that an entry's txid is
//! the hash of the bytes it writes (an entry is filed under
//! [`BeefTx::txid`], which the crate's doors set from the bytes).
//!
//! Until #843b `txs` and `bumps` were public fields, the index a
//! `HashMap<String, usize>` beside them that noticed a hand edit only where
//! it could (the stated window of #817), and an entry was lent mutably by
//! `find_txid_mut` and `BeefTx::tx_mut`.
//!
//! The holes as they stood, each a compile error now (the error number the
//! one `nightly-2026-10-19` gives):
//!
//! ```compile_fail,E0615
//! // A hand write of the entries (`txs` is a read now, no field).
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.txs.clear();
//! ```
//!
//! ```compile_fail,E0615
//! // A hand removal of a BUMP, which left every later entry naming another.
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.bumps.remove(0);
//! ```
//!
//! ```compile_fail,E0596
//! // The read lends nothing mutable.
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.txs().first_mut();
//! ```
//!
//! ```compile_fail,E0599
//! // No door lends a held entry mutably.
//! use bsv_rs::transaction::{Beef, Txid};
//! let mut beef = Beef::new();
//! let txid = Txid::from_wire_bytes([7; 32]);
//! beef.find_txid_mut(txid);
//! ```
//!
//! ```compile_fail,E0599
//! // There is nothing left to repair by hand.
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.reindex();
//! ```
//!
//! ```compile_fail,E0599
//! // An entry's transaction is edited through `Beef::edit_tx` alone.
//! use bsv_rs::transaction::{BeefTx, Transaction};
//! let mut entry = BeefTx::from_tx(Transaction::new(), None);
//! entry.tx_mut();
//! ```
//!
//! ```compile_fail,E0616
//! // An entry's input list is read, never written (it moved the sort).
//! use bsv_rs::transaction::{BeefTx, Transaction};
//! let mut entry = BeefTx::from_tx(Transaction::new(), None);
//! entry.input_txids = Vec::new();
//! ```
//!
//! ```compile_fail,E0616
//! // The sort alone says whether an entry is valid.
//! use bsv_rs::transaction::{BeefTx, Transaction};
//! let mut entry = BeefTx::from_tx(Transaction::new(), None);
//! entry.is_valid = Some(true);
//! ```
//!
//! ```compile_fail,E0308
//! // A text is no txid: it is parsed where it enters (`Txid::from_hex`).
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.merge_txid_only("abcd".to_string());
//! ```
//!
//! ```compile_fail,E0308
//! // The same at a lookup.
//! let beef = bsv_rs::transaction::Beef::new();
//! beef.find_txid("abcd");
//! ```
//!
//! ```compile_fail,E0308
//! // And at the subject of an Atomic BEEF.
//! let mut beef = bsv_rs::transaction::Beef::new();
//! beef.atomic_txid = Some("abcd".to_string());
//! ```
//!
//! ```compile_fail,E0451
//! // No struct literal builds a BEEF around rows of the caller's.
//! use bsv_rs::transaction::Beef;
//! let _ = Beef { version: 1, atomic_txid: None, rows: todo!() };
//! ```

use super::super::beef_tx::BeefTx;
use super::super::merkle_path::MerklePath;
use super::super::transaction::Transaction;
use super::super::txid::Txid;
use super::Beef;
use crate::{Error, Result};

pub(super) use sealed::Rows;

/// A BEEF's entries and BUMPs and what is derived from them (#843b). Every
/// field is private to this module; its functions are the whole of what can
/// change a row. No macro, no derive and no attribute but doc comments
/// inside, so nothing expands into it.
mod sealed {
    use std::collections::HashMap;
    use std::sync::OnceLock;

    use crate::transaction::{BeefTx, MerklePath, Transaction, Txid};

    /// The txid index: the LAST position of each txid an entry holds, as the
    /// reference's `#rebuildTxIndexes` keeps it (`Beef.ts:516-524` at
    /// `ts-stack@edf6e03`), and whether two entries have shared a txid since
    /// it was filled.
    struct Index {
        at: HashMap<Txid, usize>,
        twins: bool,
    }

    /// The rows and what is derived from them; the name visible to `Beef`'s
    /// module, every field private to `sealed`.
    pub(in crate::transaction::beef) struct Rows {
        txs: Vec<BeefTx>,
        bumps: Vec<MerklePath>,
        index: OnceLock<Index>,
        needs_sort: bool,
        wire_order: bool,
    }

    impl Rows {
        /// The rows as given, no index yet (the next lookup fills it), to
        /// be sorted when written; `as_read` says they are a reader's, in
        /// the order read.
        pub(super) fn of(txs: Vec<BeefTx>, bumps: Vec<MerklePath>, as_read: bool) -> Self {
            Self {
                txs,
                bumps,
                index: OnceLock::new(),
                needs_sort: true,
                wire_order: as_read,
            }
        }

        /// A copy: the rows, the marks and, when filled, the index, which is
        /// the copied rows' own.
        pub(super) fn copy(&self) -> Self {
            let index = OnceLock::new();
            if let Some(filled) = self.index.get() {
                let _ = index.set(Index {
                    at: filled.at.clone(),
                    twins: filled.twins,
                });
            }
            Self {
                txs: self.txs.clone(),
                bumps: self.bumps.clone(),
                index,
                needs_sort: self.needs_sort,
                wire_order: self.wire_order,
            }
        }

        /// The entries, shared.
        pub(super) fn txs(&self) -> &[BeefTx] {
            &self.txs
        }

        /// The BUMPs, shared.
        pub(super) fn bumps(&self) -> &[MerklePath] {
            &self.bumps
        }

        /// Whether the entries are to be sorted before they are written.
        pub(super) fn needs_sort(&self) -> bool {
            self.needs_sort
        }

        /// Whether the rows are a reader's, untouched since.
        pub(super) fn wire_order(&self) -> bool {
            self.wire_order
        }

        /// The index, filled from the rows when it is empty: through
        /// `&self`, so never while an exclusive borrow of the rows lives.
        fn index(&self) -> &Index {
            self.index.get_or_init(|| {
                let mut at = HashMap::with_capacity(self.txs.len());
                let mut twins = false;
                for (position, entry) in self.txs.iter().enumerate() {
                    twins |= at.insert(entry.txid(), position).is_some();
                }
                Index { at, twins }
            })
        }

        /// The last position of an entry holding `txid`.
        pub(super) fn position(&self, txid: &Txid) -> Option<usize> {
            self.index().at.get(txid).copied()
        }

        /// Appends `entry`, its txid keyed at its position when the index is
        /// filled; both marks set. Constant time.
        pub(super) fn append(&mut self, entry: BeefTx) -> usize {
            let position = self.txs.len();
            if let Some(index) = self.index.get_mut() {
                index.twins |= index.at.insert(entry.txid(), position).is_some();
            }
            self.needs_sort = true;
            self.wire_order = false;
            self.txs.push(entry);
            position
        }

        /// Stores `entry` at `position` and returns the entry it held; both
        /// marks set. The same txid moves no key. Another txid is re-keyed in
        /// constant time where no two entries share a txid and no other
        /// entry holds the new one; else the index is emptied, to be filled
        /// from the rows on the next lookup (the last position of each txid,
        /// a twin's found). Panics when `position` is no entry's.
        pub(super) fn replace(&mut self, position: usize, entry: BeefTx) -> BeefTx {
            let (old, new) = (self.txs[position].txid(), entry.txid());
            if old != new {
                let rekeyed = match self.index.get_mut() {
                    Some(index) if !index.twins && !index.at.contains_key(&new) => {
                        index.at.remove(&old);
                        index.at.insert(new, position);
                        true
                    }
                    Some(_) => false,
                    None => true,
                };
                if !rekeyed {
                    self.index.take();
                }
            }
            self.needs_sort = true;
            self.wire_order = false;
            std::mem::replace(&mut self.txs[position], entry)
        }

        /// Stores `tx` as the parse of the entry at `position` when the
        /// entry holds a transaction of the same id, and hands it back
        /// otherwise. The same id is the same written bytes, so no key, no
        /// order and no mark moves. Panics when `position` is no entry's.
        pub(super) fn swap_parse(
            &mut self,
            position: usize,
            tx: Transaction,
        ) -> Option<Transaction> {
            let entry = &mut self.txs[position];
            if entry.is_txid_only() || entry.txid() != tx.txid() {
                return Some(tx);
            }
            entry.set_parse(tx);
            None
        }

        /// Sets the BUMP position the entry at `position` names (its input
        /// list read again, as the reference's `bumpIndex` setter reads it,
        /// `BeefTx.ts:90-93`); the rows are no longer as read. The sort mark
        /// is left as it stands, as the reference's `mergeBump` leaves it
        /// (`#markMutated(false)`, `Beef.ts:690`). Panics when `position` is
        /// no entry's.
        pub(super) fn point(&mut self, position: usize, bump: Option<usize>) {
            self.wire_order = false;
            self.txs[position].set_bump_index(bump);
        }

        /// Appends a BUMP and returns its position; the rows are no longer
        /// as read.
        pub(super) fn push_bump(&mut self, bump: MerklePath) -> usize {
            self.wire_order = false;
            self.bumps.push(bump);
            self.bumps.len() - 1
        }

        /// The BUMP at `index`, exclusive: its content, never its position;
        /// the rows are no longer as read.
        pub(super) fn bump_mut(&mut self, index: usize) -> Option<&mut MerklePath> {
            self.wire_order = false;
            self.bumps.get_mut(index)
        }

        /// Keeps the BUMPs `keep` answers true for (asked in order, with
        /// each BUMP's position), and re-points every entry: one whose BUMP
        /// moved names its new position, one whose BUMP was dropped names
        /// none, one that named no BUMP (an index past them) is left as it
        /// is. Both marks set.
        pub(super) fn retain_bumps(&mut self, mut keep: impl FnMut(usize, &MerklePath) -> bool) {
            let mut moved: Vec<Option<usize>> = Vec::with_capacity(self.bumps.len());
            let mut kept = 0;
            self.bumps.retain(|bump| {
                let stays = keep(moved.len(), bump);
                moved.push(if stays { Some(kept) } else { None });
                if stays {
                    kept += 1;
                }
                stays
            });
            for entry in &mut self.txs {
                let Some(old) = entry.bump_index() else {
                    continue;
                };
                if let Some(new) = moved.get(old) {
                    if *new != Some(old) {
                        entry.set_bump_index(*new);
                    }
                }
            }
            self.needs_sort = true;
            self.wire_order = false;
        }

        /// The one general door: empties the index and sets both marks, then
        /// lends the entries mutably, the BUMPs shared beside them.
        pub(super) fn write(&mut self) -> (&mut Vec<BeefTx>, &[MerklePath]) {
            self.index.take();
            self.needs_sort = true;
            self.wire_order = false;
            (&mut self.txs, &self.bumps)
        }

        /// The entries are written as they stand, without a sort.
        pub(super) fn hold_order(&mut self) {
            self.needs_sort = false;
        }

        /// Sets both marks: the entries to be sorted, the rows not as read.
        pub(super) fn touch(&mut self) {
            self.needs_sort = true;
            self.wire_order = false;
        }
    }
}

impl Beef {
    /// The entries, in the order held.
    pub fn txs(&self) -> &[BeefTx] {
        self.rows.txs()
    }

    /// The BUMPs (merkle paths), in the order held.
    pub fn bumps(&self) -> &[MerklePath] {
        self.rows.bumps()
    }

    /// Keeps the entries `keep` answers true for, their order kept, as the
    /// reference's `removeExistingTxid` cuts one (`Beef.ts:907-917` at
    /// `ts-stack@edf6e03`); the BUMPs are left as they are and the BEEF is
    /// marked for a sort.
    ///
    /// ```
    /// use bsv_rs::transaction::{Beef, Transaction};
    ///
    /// let mut beef = Beef::new();
    /// let kept = beef.merge_raw_tx(Transaction::new().to_binary(), None)?.txid();
    /// let mut other = Transaction::new();
    /// other.set_lock_time(7);
    /// let dropped = beef.merge_raw_tx(other.to_binary(), None)?.txid();
    /// beef.retain_txs(|entry| entry.txid() == kept);
    /// assert!(beef.find_txid(kept).is_some());
    /// assert!(beef.find_txid(dropped).is_none());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn retain_txs(&mut self, keep: impl FnMut(&BeefTx) -> bool) {
        self.rows.write().0.retain(keep);
    }

    /// Keeps the BUMPs `keep` answers true for (asked in order, with each
    /// BUMP's position) and re-points every entry, as the reference's
    /// `trimKnownTxids` re-points them (`Beef.ts:1670-1680`): an entry whose
    /// BUMP moved names its new position; one whose BUMP was dropped names
    /// none, its input list read again; one whose index named no BUMP (a
    /// position past them) keeps the index it was given. The BEEF is marked
    /// for a sort.
    pub fn retain_bumps(&mut self, keep: impl FnMut(usize, &MerklePath) -> bool) {
        self.rows.retain_bumps(keep);
    }

    /// Edits the BUMP at `index` and returns the closure's value.
    ///
    /// The closure runs on a copy, so a panic in it leaves the BEEF as it
    /// was. The BUMP keeps its position and every entry the index it names;
    /// what the edited BUMP proves is the readers' and
    /// [`verify_structure`](Self::verify_structure)'s to judge, as after
    /// [`edit_tx`](Self::edit_tx). The BEEF is marked for a sort.
    ///
    /// # Errors
    ///
    /// [`Error::BeefError`], the BEEF unchanged, when `index` names no BUMP.
    pub fn edit_bump<R>(
        &mut self,
        index: usize,
        edit: impl FnOnce(&mut MerklePath) -> R,
    ) -> Result<R> {
        let Some(mut bump) = self.rows.bumps().get(index).cloned() else {
            return Err(Error::BeefError(format!(
                "BUMP index {index} names no BUMP of this Beef"
            )));
        };
        let value = edit(&mut bump);
        if let Some(held) = self.rows.bump_mut(index) {
            *held = bump;
        }
        self.rows.touch();
        Ok(value)
    }

    /// Sets the BUMP position the entry held under `txid` names, its input
    /// list read again, as the reference's `bumpIndex` setter does
    /// (`BeefTx.ts:90-93`). The index is stored as given, checked against
    /// nothing, as [`merge_raw_tx`](Self::merge_raw_tx) stores one: the
    /// readers and [`verify_structure`](Self::verify_structure) judge it.
    /// The BEEF is marked for a sort and is no longer as read (until #843b
    /// the same edit through `find_txid_mut` left both marks as they stood).
    ///
    /// # Errors
    ///
    /// [`Error::BeefError`], the BEEF unchanged, when no entry holds `txid`.
    pub fn set_bump_index(&mut self, txid: Txid, index: Option<usize>) -> Result<()> {
        let position = self
            .position(&txid)
            .ok_or_else(|| Error::BeefError(format!("{txid} does not exist in this Beef")))?;
        self.rows.point(position, index);
        self.rows.touch();
        Ok(())
    }

    /// A BEEF of the rows given, to be sorted when written; `as_read` for a
    /// reader's rows in the order read.
    pub(super) fn of_rows(
        version: u32,
        txs: Vec<BeefTx>,
        bumps: Vec<MerklePath>,
        as_read: bool,
    ) -> Self {
        Self {
            version,
            atomic_txid: None,
            rows: Rows::of(txs, bumps, as_read),
        }
    }

    /// A BEEF holding the rows as given, whatever they are (a txid twice, an
    /// index naming no BUMP, any order): for this repository's unit tests
    /// and fuzz crate alone, no part of the API (`internal-test-doors`,
    /// `tests/arch_test_doors_869.rs`). The index and the marks are the
    /// given rows' own, as after any door.
    #[cfg(any(test, feature = "internal-test-doors"))]
    #[doc(hidden)]
    pub fn with_rows_for_test(version: u32, txs: Vec<BeefTx>, bumps: Vec<MerklePath>) -> Self {
        Self::of_rows(version, txs, bumps, false)
    }

    /// The last position of an entry holding `txid`.
    pub(super) fn position(&self, txid: &Txid) -> Option<usize> {
        self.rows.position(txid)
    }

    /// Appends `entry` and returns its position.
    pub(super) fn append_entry(&mut self, entry: BeefTx) -> usize {
        self.rows.append(entry)
    }

    /// Stores `entry` at `position`, returning the entry it held.
    pub(super) fn replace_entry(&mut self, position: usize, entry: BeefTx) -> BeefTx {
        self.rows.replace(position, entry)
    }

    /// Stores `tx` as the parse of the entry at `position` when it is the
    /// same transaction, moving nothing; hands it back otherwise.
    pub(super) fn swap_parse(&mut self, position: usize, tx: Transaction) -> Option<Transaction> {
        self.rows.swap_parse(position, tx)
    }

    /// Sets the BUMP position the entry at `position` names; the sort mark
    /// is the caller's (`mark_mutated`).
    pub(super) fn point_entry(&mut self, position: usize, bump: Option<usize>) {
        self.rows.point(position, bump);
    }

    /// Appends a BUMP and returns its position.
    pub(super) fn push_bump(&mut self, bump: MerklePath) -> usize {
        self.rows.push_bump(bump)
    }

    /// The BUMP at `index`, exclusive.
    pub(super) fn bump_mut(&mut self, index: usize) -> Option<&mut MerklePath> {
        self.rows.bump_mut(index)
    }

    /// The general door: the entries, exclusive, the index emptied and both
    /// marks set before they are lent; the BUMPs shared beside them.
    pub(super) fn rows_mut(&mut self) -> (&mut Vec<BeefTx>, &[MerklePath]) {
        self.rows.write()
    }

    /// Marks the BEEF as needing a sort and no longer as read.
    pub(super) fn mark_mutated(&mut self) {
        self.rows.touch();
    }

    /// Whether [`to_binary`](Self::to_binary) sorts before it writes.
    pub(super) fn needs_sort(&self) -> bool {
        self.rows.needs_sort()
    }

    /// Whether the rows are a reader's, untouched since.
    pub(super) fn wire_order(&self) -> bool {
        self.rows.wire_order()
    }

    /// Holds the entries as they stand for writing, without the dependency
    /// sort [`to_binary`](Self::to_binary) runs when a BEEF needs one: the
    /// ancestry a transaction door collects is written in the order it was
    /// collected, each entry's sources above it and the subject last
    /// (BRC-62's rule), as the reference's transaction door writes what it
    /// collects without a sort (`ts-stack@edf6e03` `Transaction.ts:
    /// 1787-1839`, its `toBEEF`). A BEEF a caller assembles by hand keeps
    /// the sort, as the reference's `Beef.toBinary` and this crate's still
    /// sort it.
    pub(crate) fn hold_order(&mut self) {
        self.rows.hold_order();
    }
}

/// Every row and the marks, copied; the index the copy's own.
impl Clone for Beef {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            atomic_txid: self.atomic_txid,
            rows: self.rows.copy(),
        }
    }
}

impl std::fmt::Debug for Beef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Beef")
            .field("bumps", &self.rows.bumps())
            .field("txs", &self.rows.txs())
            .field("version", &self.version)
            .field("atomic_txid", &self.atomic_txid)
            .field("needs_sort", &self.rows.needs_sort())
            .field("wire_order", &self.rows.wire_order())
            .finish()
    }
}
