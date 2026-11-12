//! The BEEF's txid index, the edit door and the refresh of entries mutated
//! through the deprecated [`BeefTx::tx_mut`] (bsv-rs#171, #817).
//!
//! The index is true for every state the doors make. A hand edit of the
//! public `txs` is noticed in constant time where it can be (#817): an entry
//! count other than the one the index was built for, or a hit naming an
//! entry that holds another txid. The response costs what the edit was. A
//! `&mut` door that finds the count grown, the indexed prefix still ending
//! where it did (its last entry still the index's at its position), indexes
//! the entries past it alone; one that finds the count shrunk or the prefix
//! moved, or whose lookup hits an entry holding another txid, rebuilds the
//! index whole. A `&self` lookup cannot write the index: with the count
//! grown and the prefix in place it answers from the index and then scans
//! the unindexed tail alone; with the count shrunk, the prefix moved or a
//! mismatched hit it scans `txs` whole. The window: hand edits that leave a
//! txid the index was never given below the entry count the index was
//! built for (a replacement of an entry inside the indexed prefix, whatever
//! pushes follow it; a `truncate` then pushes back to the count; a push
//! then a `retain` that moves a pushed entry into the prefix) make a lookup
//! of that txid miss while the count is back at the indexed one, or past it
//! with the indexed prefix's last position still holding the txid the
//! index names there, and that is not noticed (a miss cannot be told from
//! an absent txid without a scan on every miss); [`Beef::reindex`] is its
//! door. Two entries of one txid (a BEEF read with a txid twice, a hand
//! push of a held txid) are noted when indexed, so [`Beef::edit_tx`] keeps
//! the other entry found after it edits one (#817's second fold). A hand
//! replacement that puts a second entry of a txid the index holds at a
//! position below its own is not noted (no entry is indexed), so
//! `edit_tx` of that txid drops its key and the copy is not found until
//! [`Beef::reindex`], where the reference's next synchronizing door
//! rebuilds its index and finds it (`Beef.ts:342-352,516-524`; stated).

use super::super::beef_tx::BeefTx;
use super::super::transaction::Transaction;
use super::Beef;
use crate::{Error, Result};

impl Beef {
    /// Rebuilds the txid index, the last position of each txid winning, as
    /// the reference's `#rebuildTxIndexes` does (`Beef.ts:516-524`).
    pub(super) fn rebuild_index(&mut self) {
        self.txid_index.clear();
        self.holds_twins = false;
        for (i, tx) in self.txs.iter().enumerate() {
            self.holds_twins |= self.txid_index.insert(tx.txid(), i).is_some();
        }
        self.indexed_len = self.txs.len();
    }

    /// Indexes `txid` at `idx`, noting a twin: a key it replaces that
    /// names another entry still holding the txid (#817's second fold).
    fn index_entry(&mut self, txid: String, idx: usize) {
        let twin = self
            .txid_index
            .get(&txid)
            .is_some_and(|&j| j != idx && self.txs.get(j).is_some_and(|t| t.has_txid(&txid)));
        self.holds_twins |= twin;
        self.txid_index.insert(txid, idx);
    }

    /// True when the entries the index was built for still end where they
    /// did: the last of them holds a txid the index names at its position.
    /// One lookup, constant in the entry count (#817).
    fn indexed_prefix_holds(&self) -> bool {
        let Some(last) = self.indexed_len.checked_sub(1) else {
            return true;
        };
        self.txs
            .get(last)
            .is_some_and(|tx| self.txid_index.get(&tx.txid()) == Some(&last))
    }

    /// Brings the index up to the entries after a hand edit of `txs`: the
    /// entries past the indexed length indexed alone when the count grew and
    /// the indexed prefix still ends where it did (a hand push), the whole
    /// index rebuilt when the count shrank or the prefix moved (a `retain`,
    /// a `truncate`); constant time when the count stands. Every `&mut` door
    /// that looks an entry up calls it first (#817).
    fn sync_index(&mut self) {
        let len = self.txs.len();
        if self.indexed_len == len {
            return;
        }
        if self.indexed_len < len && self.indexed_prefix_holds() {
            for i in self.indexed_len..len {
                let txid = self.txs[i].txid();
                self.index_entry(txid, i);
            }
            self.indexed_len = len;
        } else {
            self.rebuild_index();
        }
    }

    /// Appends `tx` under `txid` and returns its index.
    pub(super) fn push_tx(&mut self, tx: BeefTx, txid: String) -> usize {
        let in_step = self.indexed_len == self.txs.len();
        self.txs.push(tx);
        let idx = self.txs.len() - 1;
        self.index_entry(txid, idx);
        if in_step {
            self.indexed_len = self.txs.len();
        }
        idx
    }

    /// Reads each entry mutated through [`BeefTx::tx_mut`] again: its input
    /// list from the mutated transaction, the index by its new txid, the
    /// order to be sorted (bsv-rs#171). The whole-BEEF readers call it ahead
    /// of their walk; the index is rebuilt too when a hand edit of `txs`
    /// moved the entry count (#817).
    pub(super) fn refresh_mutated(&mut self) {
        let mut refreshed = false;
        for tx in &mut self.txs {
            refreshed |= tx.refresh();
        }
        if refreshed {
            self.rebuild_index();
            self.mark_mutated();
        } else {
            self.sync_index();
        }
    }

    /// Rebuilds the txid index after a hand edit of the public `txs` field
    /// (a replacement, a reorder, a `retain`), and re-reads every entry
    /// mutated through the deprecated [`BeefTx::tx_mut`].
    ///
    /// The doors keep the index true without it, and a hand edit that moves
    /// the entry count, or makes a lookup hit an entry holding another txid,
    /// is noticed without it (#817). The window is not: hand edits that leave
    /// a txid the index was never given below the entry count it was built
    /// for (a replacement of an entry inside the indexed prefix, whatever
    /// pushes follow it; a `truncate` then pushes back to the count; a push
    /// then a `retain` that moves a pushed entry into the prefix) make a
    /// lookup of that txid miss while the count is back at the indexed one,
    /// or past it with the indexed prefix's last position still holding the
    /// txid the index names there, so a `merge_raw_tx` of it would store it
    /// twice. Two costs stay with the caller: after hand pushes with only
    /// `&self` lookups and no `&mut` door between them, each lookup that
    /// misses the index scans the entries pushed since; and a hand `retain`
    /// before every door makes each door rebuild the index whole. Call
    /// `reindex` (or any `&mut` door) after editing `txs` in place. The BEEF
    /// is marked for a sort, as any hand edit may have moved the dependency
    /// order.
    pub fn reindex(&mut self) {
        for tx in &mut self.txs {
            tx.refresh();
        }
        self.rebuild_index();
        self.mark_mutated();
    }

    /// The position of the entry named `txid`, for a `&self` door. A hit is
    /// checked against the entry's txid. A miss while the count stands is a
    /// miss. A miss while the count has grown and the indexed prefix ends
    /// where it did (a hand push) scans the unindexed tail alone, from the
    /// end down, the last position winning as the index's rebuild has it. A
    /// hit naming another entry, or a miss after the count shrank or the
    /// prefix moved (a `retain`), scans `txs` whole, from the hit's position
    /// down first (a `retain` moves an entry down, so the scan is as short
    /// as the entries removed before it), then from the end down to it
    /// (#817). A miss inside the window (a txid the index was never given
    /// left by hand edits below the indexed count, the count back at it or
    /// past it with the prefix in place) is not seen
    /// ([`reindex`](Self::reindex)).
    pub(super) fn index_of(&self, txid: &str) -> Option<usize> {
        let hit = self.txid_index.get(txid).copied();
        let len = self.txs.len();
        match hit {
            Some(i) if self.txs.get(i).is_some_and(|tx| tx.has_txid(txid)) => return Some(i),
            None if self.indexed_len == len => return None,
            None if self.indexed_len < len && self.indexed_prefix_holds() => {
                return (self.indexed_len..len)
                    .rev()
                    .find(|&j| self.txs[j].has_txid(txid));
            }
            _ => {}
        }
        let top = hit.map_or(0, |i| (i + 1).min(len));
        (0..top)
            .rev()
            .chain((top..len).rev())
            .find(|&j| self.txs[j].has_txid(txid))
    }

    /// The position of the entry named `txid`, for a `&mut` door: the index
    /// brought up to the entries first ([`sync_index`](Self::sync_index)),
    /// and rebuilt whole when the lookup hits an entry holding another txid
    /// (a hand swap or reorder), so the doors after it read the index alone
    /// (#817).
    pub(super) fn position(&mut self, txid: &str) -> Option<usize> {
        self.sync_index();
        match self.txid_index.get(txid).copied() {
            Some(i) if self.txs.get(i).is_some_and(|tx| tx.has_txid(txid)) => Some(i),
            None => None,
            Some(_) => {
                self.rebuild_index();
                self.txid_index.get(txid).copied()
            }
        }
    }

    /// Stores `tx` under `txid` in the place of the entry held for the txid,
    /// else appends it, as the reference's `#replaceOrAppendTx` does
    /// (`ts-stack@edf6e03` `Beef.ts:531-540`): a held entry keeps its
    /// position, so a re-merge moves no entry and costs no re-index. Until
    /// #764's fold the held entry was removed and the new one appended.
    pub(super) fn replace_or_append(&mut self, tx: BeefTx, txid: String) -> usize {
        match self.position(&txid) {
            Some(idx) => {
                self.txs[idx] = tx;
                idx
            }
            None => self.push_tx(tx, txid),
        }
    }

    /// Finds a BeefTx by txid.
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx> {
        self.index_of(txid).map(|i| &self.txs[i])
    }

    /// Finds a BeefTx by txid (mutable).
    ///
    /// To edit the entry's transaction use [`edit_tx`](Self::edit_tx), which
    /// re-keys the entry at once; the entry handed back here is for its BUMP
    /// index (`set_bump_index`) and its bytes (`raw_tx_or_compute`).
    pub fn find_txid_mut(&mut self, txid: &str) -> Option<&mut BeefTx> {
        self.position(txid).map(|i| &mut self.txs[i])
    }

    /// Edits the transaction held under `txid` and repairs its entry at once,
    /// returning the closure's value.
    ///
    /// The closure runs on a copy of the entry's transaction, so a panic in
    /// it leaves the BEEF untouched. On return the entry holds the edited
    /// transaction and its bytes (an entry held raw stays raw, re-written),
    /// its txid is the edited transaction's, its `input_txids` are read from
    /// it, the index is re-keyed under the new txid and the BEEF is marked
    /// for a sort (the old txid's key dropped, unless another entry of the
    /// BEEF may hold that txid: a BEEF read with it twice, a hand push of
    /// it, where the other entry stays found). Its BUMP index is kept: a
    /// proven entry whose hash moved is
    /// refused by the readers and by `verify` (`TxidNotInBump`). An edit
    /// that leaves the transaction's bytes as they were (nothing changed, or
    /// only what the bytes do not carry: a `merkle_path`, a
    /// `source_transaction` link, `metadata`) is stored and moves nothing:
    /// the entry keeps its txid and the bytes it holds (raw bytes read with
    /// bytes after the transaction included), no key, no order, no byte
    /// written; the edited copy is compared with the original before
    /// anything is rewritten. The closure's value is returned as it is: a
    /// closure that returns an `Err` as its value still has its edit stored.
    /// The transaction's serialization caches are cleared before the
    /// closure runs and after it. The reference edits its entry in place and
    /// re-keys it at the next door that synchronizes (`BeefTx.ts:160-175`, `Beef.ts:342-352`);
    /// here the repair is eager, so every door, the `&self` lookups
    /// included, sees the edit (#817).
    ///
    /// # Errors
    ///
    /// [`Error::BeefError`], the BEEF unchanged, when nothing is held under
    /// `txid` as a transaction (an unknown txid, an entry holding a txid
    /// alone, raw bytes that do not parse, the parser's words after
    /// `do not parse as a transaction: `), and when the edited transaction's
    /// txid is held by another entry of the BEEF (the reference keeps both
    /// entries there, the last position winning its index; a stated row).
    ///
    /// # Example
    ///
    /// ```
    /// use bsv_rs::transaction::{Beef, Transaction};
    ///
    /// let mut beef = Beef::new();
    /// let txid = beef.merge_raw_tx(Transaction::new().to_binary(), None)?.txid();
    /// let edited = beef.edit_tx(&txid, |tx| {
    ///     tx.set_lock_time(7);
    ///     tx.id()
    /// })?;
    /// assert!(beef.find_txid(&txid).is_none());
    /// assert_eq!(beef.find_txid(&edited).unwrap().tx().unwrap().lock_time(), 7);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn edit_tx<R>(
        &mut self,
        txid: &str,
        edit: impl FnOnce(&mut Transaction) -> R,
    ) -> Result<R> {
        let idx = self
            .position(txid)
            .ok_or_else(|| Error::BeefError(format!("{} does not exist in this Beef", txid)))?;
        let entry = &self.txs[idx];
        let mut tx = match (entry.tx(), entry.raw_tx()) {
            (Some(tx), _) => tx.clone(),
            (None, Some(raw)) => Transaction::from_binary(raw).map_err(|e| {
                Error::BeefError(format!(
                    "{} is held in this Beef as raw bytes that do not parse as a transaction: {}",
                    txid, e
                ))
            })?,
            (None, None) => {
                return Err(Error::BeefError(format!(
                    "{} is held in this Beef as a txid alone, with no transaction to edit",
                    txid
                )))
            }
        };
        // The bytes before the edit; the closure edits through the
        // transaction's doors, which clear its caches (#843).
        let before = tx.to_binary();
        let value = edit(&mut tx);
        let entry = &self.txs[idx];
        let bump = entry.bump_index();
        let is_valid = entry.is_valid;
        if tx.to_binary() == before {
            // The same transaction bytes: the entry keeps its txid and the
            // bytes it holds, so no key, order or wire byte moves (raw bytes
            // with a byte after the transaction are refused above, #840).
            let edited = if entry.held_raw() {
                let raw = entry
                    .raw_tx()
                    .map_or_else(|| tx.to_binary(), <[u8]>::to_vec);
                BeefTx::from_parts(tx, raw, bump)
            } else {
                BeefTx::from_tx(tx, bump)
            };
            self.txs[idx] = edited.with_txid(txid.to_string());
            self.txs[idx].is_valid = is_valid;
            return Ok(value);
        }
        let new_txid = tx.id();
        if self.index_of(&new_txid).is_some_and(|other| other != idx) {
            return Err(Error::BeefError(format!(
                "the edited transaction {} is already held in this Beef by another entry",
                new_txid
            )));
        }
        let edited = if entry.held_raw() {
            let raw = tx.to_binary();
            BeefTx::from_parts(tx, raw, bump)
        } else {
            BeefTx::from_tx(tx, bump)
        };
        self.txs[idx] = edited.with_txid(new_txid.clone());
        // The old txid's key goes, unless another entry may still hold the
        // txid (a twin read from bytes or pushed by hand): then it stays,
        // stale, so a lookup of it hits this entry, finds another txid and
        // scans (`&self`) or rebuilds (`&mut`) to the twin, as the
        // reference's index rebuilt after the edit finds it
        // (`Beef.ts:342-352,516-524`). Dropping the key always would lose
        // the twin; keeping it always would make every later lookup of an
        // edited-away txid scan or rebuild; a scan for a twin on every edit
        // would make each edit linear. The flag keeps the edit and the
        // lookups constant on a BEEF without twins (#817's second fold).
        if !self.holds_twins && self.txid_index.get(txid) == Some(&idx) {
            self.txid_index.remove(txid);
        }
        self.txid_index.insert(new_txid, idx);
        self.mark_mutated();
        Ok(value)
    }
}
