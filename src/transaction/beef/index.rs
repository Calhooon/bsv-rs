//! The BEEF's lookups by txid and the edit door (bsv-rs#171, #817, #843b).
//!
//! The index lives with the rows in `rows.rs`' `sealed` module and is always
//! theirs (#843b): for every txid an entry holds it names the last position
//! holding it, in every state, since no code outside `sealed` can change a
//! row. Until #843b the rows were public fields and the index noticed a hand
//! edit only where it could (an entry count that moved, a hit naming another
//! entry), with a stated window in which a lookup missed a held txid and a
//! merge stored it twice; `reindex` was its door, `find_txid_mut` and
//! `BeefTx::tx_mut` lent an entry mutably, and every whole-BEEF door scanned
//! the entries for one edited that way (`refresh_mutated`). All of that is
//! gone: there is nothing left to repair.

use super::super::beef_tx::BeefTx;
use super::super::transaction::Transaction;
use super::super::txid::Txid;
use super::Beef;
use crate::{Error, Result};

impl Beef {
    /// Stores `tx` in the place of the entry held for its txid, else appends
    /// it, as the reference's `#replaceOrAppendTx` does (`ts-stack@edf6e03`
    /// `Beef.ts:531-540`): a held entry keeps its position, so a re-merge
    /// moves no entry and costs no re-index. Until #764's fold the held
    /// entry was removed and the new one appended.
    pub(super) fn replace_or_append(&mut self, tx: BeefTx) -> usize {
        match self.position(&tx.txid()) {
            Some(idx) => {
                self.replace_entry(idx, tx);
                idx
            }
            None => self.append_entry(tx),
        }
    }

    /// Finds a BeefTx by txid: the last entry holding it.
    ///
    /// The txid is a [`Txid`] since #843b (`beef.find_txid(tx.txid())`, or
    /// from text `beef.find_txid(Txid::from_hex(&text)?)`); until then a
    /// text, compared as text, so an upper-case text missed a held entry.
    pub fn find_txid(&self, txid: Txid) -> Option<&BeefTx> {
        self.position(&txid).map(|i| &self.txs()[i])
    }

    /// Edits the transaction held under `txid` and repairs its entry at once,
    /// returning the closure's value.
    ///
    /// The closure runs on a copy of the entry's transaction, so a panic in
    /// it leaves the BEEF untouched. On return the entry holds the edited
    /// transaction and its bytes (an entry held raw stays raw, re-written),
    /// its txid is the edited transaction's, its `input_txids` are read from
    /// it, the index is re-keyed under the new txid and the BEEF is marked
    /// for a sort; another entry holding the old txid (a BEEF read with it
    /// twice) stays found. Its BUMP index is kept: a
    /// proven entry whose hash moved is
    /// refused by the readers and by `verify` (`TxidNotInBump`). An edit
    /// that leaves the transaction's bytes as they were (nothing changed, or
    /// only what the bytes do not carry: a `merkle_path`, a
    /// `source_transaction` link, `metadata`) is stored and moves nothing:
    /// the entry keeps its txid and the bytes it holds, no key, no order, no
    /// byte written; the edited copy is compared with the original before
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
    /// let edited = beef.edit_tx(txid, |tx| {
    ///     tx.set_lock_time(7);
    ///     tx.txid()
    /// })?;
    /// assert!(beef.find_txid(txid).is_none());
    /// assert_eq!(beef.find_txid(edited).unwrap().tx().unwrap().lock_time(), 7);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn edit_tx<R>(
        &mut self,
        txid: Txid,
        edit: impl FnOnce(&mut Transaction) -> R,
    ) -> Result<R> {
        let idx = self
            .position(&txid)
            .ok_or_else(|| Error::BeefError(format!("{} does not exist in this Beef", txid)))?;
        let entry = &self.txs()[idx];
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
        let same = tx.to_binary() == before;
        let tx = if same {
            // The same transaction bytes: the entry keeps its txid and the
            // bytes it holds, so no key, order, mark or wire byte moves (raw
            // bytes with a byte after the transaction are refused above,
            // #840). The rows check the id themselves (`Rows::swap_parse`).
            match self.swap_parse(idx, tx) {
                None => return Ok(value),
                // An entry filed under a txid its bytes do not hash to (no
                // public door builds one): stored as any other edit.
                Some(tx) => tx,
            }
        } else {
            tx
        };
        let entry = &self.txs()[idx];
        let (bump, held_raw) = (entry.bump_index(), entry.held_raw());
        let (new_txid, is_valid) = if same {
            (txid, entry.is_valid())
        } else {
            (tx.txid(), None)
        };
        if self.position(&new_txid).is_some_and(|other| other != idx) {
            return Err(Error::BeefError(format!(
                "the edited transaction {} is already held in this Beef by another entry",
                new_txid
            )));
        }
        let edited = if held_raw {
            let raw = tx.to_binary();
            BeefTx::from_parts(tx, raw, bump)
        } else {
            BeefTx::from_tx(tx, bump)
        };
        // The rows re-key the entry: the old txid's key goes, and where
        // another entry may hold that txid (a twin read from bytes) the index
        // is filled again from the rows, the twin found, as the reference's
        // index rebuilt after the edit finds it (`Beef.ts:342-352,516-524`;
        // #817's second fold kept a stale key for it).
        self.replace_entry(idx, edited.with_txid(new_txid).with_valid(is_valid));
        Ok(value)
    }
}
