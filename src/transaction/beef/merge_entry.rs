//! The per-entry door of [`Beef::merge_beef`] (#621 and its fold): a source
//! entry merged by the reference's conditions, a raw one under the txid it
//! holds, hashed no second time.

use super::super::beef_tx::BeefTx;
use super::Beef;
use crate::primitives::{sha256d, to_hex};

impl Beef {
    /// Merges one source entry of [`merge_beef`](Self::merge_beef) as the
    /// reference's `#mergeBeefTxEntry` does (`ts-stack@edf6e03`
    /// `Beef.ts:950-967`; go-sdk@2ca481c `MergeBeefTxWithTxid`,
    /// `transaction/beef.go:984-1000`): a txid-only entry is appended only
    /// where the target holds nothing under its txid; a raw or parsed one
    /// only where the target holds nothing or holds the txid alone (that
    /// entry replaced in its place, `#replaceOrAppendTx`, `:531-540`). An
    /// entry the target holds raw or parsed is left as it is, its BUMP index
    /// and the source links a [`merge_transaction`](Self::merge_transaction)
    /// gave it kept; until #621's fold it was replaced and its index
    /// rescanned (the last BUMP holding it).
    ///
    /// A raw entry is filed under the txid the source entry holds
    /// ([`BeefTx::held_txid`]: the decoder's hash of the same bytes, or
    /// `merge_raw_tx`'s), else under the hash of its bytes, never under
    /// `txid()`'s reading of its fields, which a stale serialization cached
    /// after `tx_mut` can part from. Until #621 every raw entry was hashed
    /// again (one `sha256d` and one clone of the body per entry); the
    /// reference hashes twice per entry (`:842-846`, `BeefTx.ts:105-115`),
    /// go-sdk keeps the map's txid (`beef.go:1010-1017`).
    pub(super) fn merge_beef_entry(&mut self, tx: &BeefTx) {
        if tx.is_txid_only() {
            // `merge_txid_only` keeps a held entry, as `:952-957` does.
            self.merge_txid_only(tx.txid());
            return;
        }
        // The entry's written form (#621's second fold): its bytes, a
        // parsed entry's serialization included, as the reference's snapshot
        // holds every entry raw (`BeefTx.fromReader`, `BeefTx.ts:288-311`),
        // so `#mergeBeefTxEntry`'s `_tx` branch is never reached from
        // `mergeBeef`; no transaction object, link or path of its own.
        let Some(raw) = tx.written_tx_bytes() else {
            return;
        };
        let txid = match tx.held_txid() {
            Some(txid) => txid.to_owned(),
            None => {
                let mut hash = sha256d(&raw);
                hash.reverse();
                to_hex(&hash)
            }
        };
        if self.holds_a_transaction(&txid) {
            return;
        }
        // No source bump index: the BUMP is found by scanning
        // self.bumps, as `#mergeRawTxEntry(btx._rawTx)` passes none.
        // Framed: `merge_beef`'s verdict checked them as the writers' check
        // does (a raw entry held without its parse scanned, `one_transaction`;
        // every other a parse's bytes or its serialization; #817, #621).
        self.store_raw_entry(BeefTx::from_framed_raw_tx(raw.into_owned(), None), txid);
    }

    /// The positions of the source's entries in the order the reference's
    /// `toBinary` would write them (`#getSerializedBytes`, `Beef.ts:360-373`),
    /// the source unchanged: held order for a BEEF read from bytes and not
    /// touched since (the reference returns the bytes it read, `:363-364`,
    /// `:1268-1270`; `wire_order`), else the sort when it needs one (an entry
    /// mutated through `tx_mut` read with the input txids its refresh would
    /// give it, its mutation a reason to sort, as
    /// `synchronizeNestedTransactionMutations` makes it, `:342-352`), else
    /// the held order (`:354-358`). #621's second fold; held order always
    /// until then.
    pub(super) fn written_order(&self) -> Vec<usize> {
        let refreshed: Vec<Option<Vec<String>>> =
            self.txs.iter().map(BeefTx::refreshed_input_txids).collect();
        let mutated = refreshed.iter().any(Option::is_some);
        if !mutated && (self.wire_order || !self.needs_sort) {
            return (0..self.txs.len()).collect();
        }
        let inputs: Vec<&[String]> = self
            .txs
            .iter()
            .zip(&refreshed)
            .map(|(tx, fresh)| fresh.as_deref().unwrap_or(&tx.input_txids))
            .collect();
        super::dependency_order(&self.txs, &inputs).0
    }

    /// True when the BEEF holds `txid` raw or parsed, not as a txid alone.
    fn holds_a_transaction(&self, txid: &str) -> bool {
        self.index_of(txid)
            .is_some_and(|i| !self.txs[i].is_txid_only())
    }

    /// Stores a raw entry built under `txid` (the display hex of its bytes'
    /// double SHA-256, the caller's word, not checked here) with its index,
    /// else the last BUMP holding it, in the place of an entry of the txid
    /// ([`replace_or_append`](Self::replace_or_append), #764): the one body of
    /// both raw doors.
    pub(super) fn store_raw_entry(&mut self, new_tx: BeefTx, txid: String) -> usize {
        let idx = self.replace_or_append(new_tx.with_txid(txid.clone()), txid);
        self.try_to_validate_bump_index(idx);
        self.mark_mutated();
        idx
    }
}
