keeper's word first

# Beef's txid index is never rebuilt after a hand edit of `txs`: a dropped entry is still found, a pushed one is stored twice, and after a swap `mergeRawTx` overwrites another entry

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "A hand edit of the public `txs` (#817, the dependents read's finding)". Drafted by the review-rule-fix-817-door-sync-rebuild read on 2026-11-10, from bsv-rs PR #832's four recorded hand-edit cells.

`Beef.txs` is a public array. The class keeps two lazy maps over it, txid to object (`#txidIndex`) and txid to position (`#txPositionIndex`), built by `#rebuildTxIndexes` and rebuilt only by `synchronizeNestedTransactionMutations` when an entry's own transaction changed (`syncRawTxFromTransaction`). A caller that edits the array itself (`splice`, `push`, a reorder, an assignment) leaves both maps stale, and every later door reads them:

```ts
#replaceOrAppendTx(tx: BeefTx): void {
  const position = this.#ensureTxPositionIndex().get(tx.txid)
  if (position === undefined) {
    this.txs.push(tx)
    this.#addToIndex(tx)
  } else {
    this.txs[position] = tx
    this.#addToIndex(tx, position)
  }
}
```

Steps to reproduce (recorded from the unmodified SDK at the pin under Node v22.23.3 by bsv-rs's recorder; X, U, W unrelated raw transactions):

1. Drop: `mergeRawTx(X)`, `mergeRawTx(U)`, `mergeRawTx(W)`, then `beef.txs.splice(0, 1)` (X removed). `findTxid(X)` still returns X's object; `mergeRawTx(W)` writes W at its stale position 2 and the BEEF holds `[U, W, W]` (case `a_hand_drop_then_the_lookups_and_merge_raw_tx`).
2. Push: `mergeRawTx(X)`, `beef.txs.push(new BeefTx(W))`. `findTxid(W)` is `undefined`; `mergeRawTx(W)` appends a second W, `[X, W, W]` (case `a_hand_push_then_find_txid_and_merge_raw_tx`).
3. Swap: `mergeRawTx(X)`, `mergeRawTx(U)`, `beef.txs.reverse()` (`[U, X]`). `mergeRawTx(X)` writes X at X's old position 0, over U: `[X, X]`, U lost (case `a_hand_swap_then_find_each_and_merge_raw_tx`).
4. Replace keeping the length: `mergeRawTx(X)`, `mergeRawTx(U)`, `beef.txs[0] = new BeefTx(W)`. `findTxid(W)` is `undefined`, `findTxid(X)` returns the replaced object, and `mergeRawTx(W)` appends a second W (case `a_hand_replace_keeping_the_count_then_find_and_merge_raw_tx`).

In each case `toBinary` then writes one txid twice (1, 2, 3 save the U lost, 4), or a BEEF without U (3).

Expected: a lookup answers from the entries `txs` holds, and a merge of a held txid replaces the one entry holding it.

bsv-rs keeps the entry count its index was built for and checks each hit against the entry's txid, so a drop, a push or a swap is noticed and answered from the entries; a replacement that keeps the length (or is followed by pushes that leave the last indexed entry in place) and makes a lookup miss is not noticed there either (it would take a scan on every miss) and has an explicit `Beef::reindex()`.

Witness:

- [tests/beef_door_sync_817.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/beef_door_sync_817.rs) `a_hand_drop_then_the_lookups_and_merge_raw_tx_stated_817`, `a_hand_push_then_find_txid_and_merge_raw_tx_stated_817`, `a_hand_swap_then_find_each_and_merge_raw_tx_stated_817`, `a_hand_replace_keeping_the_count_is_the_window_stated_817` (the reference's bytes and answers recorded beside this crate's)
- [tests/vectors/beef_door_sync_817.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/beef_door_sync_817.json), recorded by [tests/support/beef_door_sync_817.mjs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/support/beef_door_sync_817.mjs) (steps `drop:`, `push:`, `swap:`, `replace:`)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:497-529](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L497-L529) (`findTxid`, the two maps, `#rebuildTxIndexes`)
- [Beef.ts:531-540](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L531-L540) (`#replaceOrAppendTx`, the stale position written)
- [Beef.ts:342-352](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L342-L352) (`synchronizeNestedTransactionMutations`: the maps rebuilt only when an entry's transaction changed)
- [Beef.ts:835-840](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L835-L840) (`mergeRawTx`)

Sibling reading: go-sdk@2ca481c keeps `Transactions` as a map keyed by txid (`transaction/beef.go`), so it has no array a caller can reorder apart from its key.

Existing related filing(s): none known. Search ts-stack's issues for `txPositionIndex` or `replaceOrAppendTx` before opening.

Requested maintainer action: either check a position hit against `this.txs[position].txid` and rebuild the maps when it does not match or when `txs.length` moved since they were built, or document that `txs` must not be edited by hand and expose a public reindex.

Evidence status: the reference was run by the linked recorder (Node v22.23.3, two runs byte-identical); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
