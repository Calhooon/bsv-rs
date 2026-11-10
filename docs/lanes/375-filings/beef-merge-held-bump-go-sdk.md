keeper's word first

# Beef.MergeTransaction does not attach a BUMP the Beef already holds for the transaction, so the transaction is stored unproven and its sources are walked

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`Beef::merge_transaction` (#764)" ("Go at `2ca481c` keeps a held proven entry and walks the sources of a pathless transaction a held BUMP proves"; "Theirs: go-sdk, not filed"). Drafted by the filings-1109 lane on 2026-11-09.

A go-sdk user who merges a block's BUMP into a `Beef` and then merges a transaction of that block whose `MerklePath` field is unset (the common case when the proof arrives separately from the transaction) gets the transaction stored as a raw, unproven entry, and its linked source transactions merged after it. Where the sources are not linked, the BEEF holds the transaction as a raw entry with no BUMP index and none of its parents; go-sdk's own `ValidateTransactions` still reads it as proven, by the held BUMP's flagged leaf (`beef.go:1070-1080`, `:1136-1140`), so the difference is the entry's form on the wire and the sources walked, not a verdict of go-sdk's reader; the TypeScript reference attaches the held BUMP and stops.

go-sdk's `tryToValidateBumpIndex` only clears a path that does not hold the txid; it never looks for a held BUMP that does:

```go
func (b *Beef) tryToValidateBumpIndex(tx *BeefTx, txid *chainhash.Hash) {
	if tx.DataFormat == TxIDOnly || tx.Transaction == nil || tx.Transaction.MerklePath == nil {
		return
	}
	...
	tx.Transaction.MerklePath = nil
}
```

and `MergeTransactionWithTxid` walks the sources whenever the incoming transaction carried no path (`if bumpIndex == nil { for _, input := range tx.Inputs { ... b.MergeTransaction(input.SourceTransaction) ...`).

The reference's `#tryToValidateBumpIndex` looks the txid up among the held BUMPs, sets the entry's index and flags the leaf (`Beef.ts:1329-1340`: `const i = this.#ensureBumpTxidIndex().get(txid); ... newTx.bumpIndex = i; ... leaf.txid = true`), and `#mergeTransactionGraph` queues the sources only when the entry ends up with no index (`:897`, `if (newTx.bumpIndex === undefined) this.#queueSourceTransactions(current, stack)`).

Steps to reproduce (read from the code at 2ca481c, not run; the bytes are the recorded vector's):

1. A `Beef` holding the BUMP `child_800003` of `tests/vectors/beef_merge_transaction_764.json` (block 800003, a level-0 leaf carrying the child's txid).
2. `MergeTransaction(child)` where `child.MerklePath == nil` and both inputs link the unproven `parent`.
3. The reference's `Beef` holds one entry, the child with BUMP index 0, and writes `0200beef01fe03350c0001010002094a74f1a0e0c3c4cafcc8b63e8062c0dfc48edda92acbe16662e367f9c26fa3010100010000000262b05fec8e8aee6e0c03973bcb20f71f87fa206d5edcbb298b564296a13ebd86000000000151ffffffff62b05fec8e8aee6e0c03973bcb20f71f87fa206d5edcbb298b564296a13ebd86010000000151ffffffff01c409000000000000015100000000` (case `subject_proven_by_a_held_bump`). go-sdk holds the child as `RawTx` with no index, plus the parent, unproven.
4. The same with no source linked: go-sdk's BEEF holds the child alone, unproven, with no parents.

Expected: a transaction merged without a path is proven by a held BUMP that carries its txid, as the reference merges it, and its sources are not walked.

Actual: the held BUMP is ignored for the incoming transaction.

bsv-rs merges as the reference does (`a_transaction_a_held_bump_proves_does_not_walk_its_sources_764`).

Witness:

- [tests/beef_merge_transaction_764.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/beef_merge_transaction_764.rs) (`a_transaction_a_held_bump_proves_does_not_walk_its_sources_764`)
- [tests/vectors/beef_merge_transaction_764.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/beef_merge_transaction_764.json) (case `subject_proven_by_a_held_bump`, recorded from the reference under Node 22.18.0)

Pinned reference reading:

- [go-sdk@2ca481c59 transaction/beef.go:858-915](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/beef.go#L858-L915) (`tryToValidateBumpIndex`, `MergeTransactionWithTxid`)

Sibling reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:849-901](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L849-L901) (`#mergeTransactionEntry`, `#mergeTransactionGraph`) and [:1329-1340](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L1329-L1340) (`#tryToValidateBumpIndex`)

Requested maintainer action: when a merged transaction carries no path, look its txid up among the held BUMPs' level-0 leaves, set its BUMP index (and flag the leaf) on a match, and walk its sources only when no BUMP holds it, as the reference does.

Evidence status: source-read at the pins in this lane; go-sdk was not run; the reference's bytes are the recorded vector. This draft contains no private-key literal.
