//! The BEEF's txid index and the refresh of entries mutated through
//! [`BeefTx::tx_mut`] (bsv-rs#171): a renamed entry is re-keyed by the next
//! whole-BEEF reader, and an index hit is checked against the entry's txid.

use super::super::beef_tx::BeefTx;
use super::Beef;

impl Beef {
    /// Rebuilds the txid index.
    pub(super) fn rebuild_index(&mut self) {
        self.txid_index.clear();
        for (i, tx) in self.txs.iter().enumerate() {
            self.txid_index.insert(tx.txid(), i);
        }
    }

    /// Reads each entry mutated through [`BeefTx::tx_mut`] again: its input
    /// list from the mutated transaction, the index by its new txid, the
    /// order to be sorted (bsv-rs#171). The whole-BEEF readers call it ahead
    /// of their walk.
    pub(super) fn refresh_mutated(&mut self) {
        let mut refreshed = false;
        for tx in &mut self.txs {
            refreshed |= tx.refresh();
        }
        if refreshed {
            self.rebuild_index();
            self.mark_mutated();
        }
    }

    /// The position of the entry named `txid`: an index entry whose
    /// transaction has been renamed by [`BeefTx::tx_mut`] since is no hit.
    pub(super) fn index_of(&self, txid: &str) -> Option<usize> {
        self.txid_index
            .get(txid)
            .copied()
            .filter(|&i| self.txs.get(i).is_some_and(|tx| tx.has_txid(txid)))
    }

    /// Finds a BeefTx by txid.
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx> {
        self.index_of(txid).map(|i| &self.txs[i])
    }

    /// Finds a BeefTx by txid (mutable).
    pub fn find_txid_mut(&mut self, txid: &str) -> Option<&mut BeefTx> {
        self.index_of(txid).map(|i| &mut self.txs[i])
    }
}
