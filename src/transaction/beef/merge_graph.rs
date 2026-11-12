//! `merge_transaction`: a transaction and the graph it carries, merged as
//! the reference's `mergeTransaction` merges it (#764).

use std::collections::HashSet;

use super::super::beef_tx::BeefTx;
use super::super::transaction::Transaction;
use super::Beef;

impl Beef {
    /// Merges a transaction, its merkle path and the source transactions its
    /// inputs carry into this BEEF, as the reference's `mergeTransaction`
    /// does (`ts-stack@edf6e03` `Beef.ts:875-901`; go-sdk@2ca481c
    /// `transaction/beef.go:875-912`).
    ///
    /// The walk is a stack, the transaction first and then each input's
    /// `source_transaction` from the first input on (`#queueSourceTransactions`,
    /// `:858-863`), each txid merged once per call. A transaction carrying a
    /// `merkle_path` has it merged through [`merge_bump`](Self::merge_bump)
    /// and takes the index that returns (`#mergeTransactionEntry`,
    /// `:849-856`): a path whose BUMP this BEEF holds (the same height and
    /// root) is combined into it, no second BUMP. One without a path takes
    /// the last BUMP holding its txid as any level-0 leaf (flagged on the way, #765), as [`merge_raw_tx`](Self::merge_raw_tx)
    /// does. A transaction whose entry ends with an index stops the walk; one
    /// that ends with none has its sources merged and walked in turn
    /// (`:897`). An entry of the same txid already held is replaced in its
    /// place, as `merge_raw_tx` replaces it (`#replaceOrAppendTx`,
    /// `:531-540`), so an ancestor merged by hand before is one entry still
    /// and a graph merged again moves no entry.
    ///
    /// The transaction given is stored as given; each ancestor is stored as
    /// a copy without its own source links (they are entries of this BEEF),
    /// so the walk is linear in the graph's size, where the reference holds
    /// the caller's objects (the #764 parity note). Until #764 the
    /// transaction alone was stored, its path never written as a BUMP and no
    /// ancestor merged: a caller that re-merges an in-memory entry meant to
    /// stand alone (a root to prune or split from its ancestry) keeps that
    /// one-entry merge with `merge_raw_tx(tx.to_binary(), None)`.
    pub fn merge_transaction(&mut self, tx: Transaction) -> &BeefTx {
        let root = tx.id();
        let mut visited = HashSet::new();
        let mut stack = vec![&tx];
        while let Some(current) = stack.pop() {
            let txid = current.id();
            if !visited.insert(txid.clone()) {
                continue;
            }
            let bump = current.merkle_path.clone().map(|p| self.merge_bump(p));
            let idx = self.push_transaction(txid, current.clone_for_beef(), bump);
            if self.txs[idx].bump_index().is_none() {
                let sources = current.inputs().iter().rev();
                stack.extend(sources.filter_map(|i| i.source_transaction.as_deref()));
            }
        }
        let idx = self.index_of(&root).unwrap_or(self.txs.len() - 1);
        let bump = self.txs[idx].bump_index();
        self.txs[idx] = BeefTx::from_tx(tx, bump).with_txid(root);
        &self.txs[idx]
    }
}
