keeper's word first

# Beef's txid-to-BUMP map answers by which doors ran: a combine into an earlier BUMP overwrites a txid a later BUMP holds, and the map's own rebuild disagrees with it

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The BUMP an entry names (#817, stated)" ("Ours: the last BUMP holding the txid, read live. Theirs: a draft on the queue"). Drafted by the fix-817-edit-door lane on 2026-11-10, from the five design reads of bsv-rs #817.

`Beef` keeps a txid-to-BUMP-index map (`#bumpIndexByTxid`). Built fresh it maps each level-0 hash to the LAST BUMP holding it (`#ensureBumpTxidIndex`). When `#findOrInsertBump` combines a new path into an existing BUMP, `indexBumpTxids` sets every level-0 hash of the combined BUMP to that BUMP's index, over a later BUMP that holds the same hash. The map is dropped only where `#synchronizeNestedBumpMutations` finds the BUMPs changed since its snapshot, and on a `new Beef()` its first call only takes the snapshot. So, with one txid at level 0 of two BUMPs (a reorg, or two roots at one height), the BUMP an entry is given depends on which doors ran before, not on the BEEF's contents: `findBump` and the index `mergeRawTx`, `mergeTxidOnly` and `mergeTransaction` write. A combine of an unrelated proof (a sibling's) changes another txid's answer.

```ts
function indexBumpTxids(bump: MerklePath, index: number, byTxid: Map<string, number>): void {
  for (const leaf of bump.path[0]) {
    if (typeof leaf.hash === 'string') byTxid.set(leaf.hash, index)
  }
}
```

Steps to reproduce (recorded from the unmodified SDK at the pin under Node v22.23.3 by bsv-rs's recorder):

1. `const beef = new Beef()`. `beef.mergeBump(b0)`: X and its sibling W at height 900000, X flagged. `beef.mergeBump(b1)`: X alone at 900001.
2. `beef.mergeBump(b0w)`: the same block's path with W flagged; it combines into b0.
3. `beef.mergeRawTx(x.toBinary())`.

Actual: X is written with BUMP index 0 (case `a_combine_through_merge_bump_survives_merge_raw_tx`). With `beef.findBump(X)` called between steps 2 and 3, X is written with index 1 (case `a_combine_is_forgotten_at_find_bump`): the lookup's BUMP synchronization dropped the map and its rebuild answers the last BUMP. Built from the same BUMPs through `mergeTransaction` with no synchronizing door, `findBump(X)` answers b0 and keeps answering it after a `sortTxs` (cases `a_combine_before_any_bump_sync_survives_the_first`, `a_combine_before_any_bump_sync_survives_a_sort`); after `clone()` it answers b1.

Expected: one answer for one BEEF, whatever doors ran before; the map's incremental update equal to its own rebuild. Either rule is a proof of X (both BUMPs hold it), so no verdict moves; the written index byte and the path `findAtomicTransaction` attaches do.

bsv-rs names the last BUMP holding the txid, read live from `bumps` (a function of the BUMPs alone, equal to this map's rebuild), and states the seven recorded cells where the map answers otherwise.

Witness:

- [tests/beef_door_sync_817.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/beef_door_sync_817.rs) `a_combine_through_merge_bump_then_merge_raw_tx_names_the_last_bump_stated_817` and the six other `_stated_817` BUMP cells (the reference's bytes and answers recorded beside this crate's)
- [tests/vectors/beef_door_sync_817.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/beef_door_sync_817.json), recorded by [tests/support/beef_door_sync_817.mjs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/support/beef_door_sync_817.mjs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:60-64](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L60-L64) (`indexBumpTxids`)
- [Beef.ts:791-811](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L791-L811) (`#findOrInsertBump`, the combine and its `indexBumpTxids`)
- [Beef.ts:576-586](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L576-L586) (`#ensureBumpTxidIndex`, the rebuild: the last BUMP)
- [Beef.ts:297-309](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L297-L309) (`#synchronizeNestedBumpMutations`: no drop on the first snapshot)
- [Beef.ts:1613](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L1613) (`clone()` drops the map)

Sibling reading: go-sdk@2ca481c's `FindBump` answers the EARLIEST BUMP proving the txid (`transaction/beef.go:620-638`), a third rule, also a function of the BUMPs alone.

Existing related filing(s): none known. Search ts-stack's issues for `bumpIndexByTxid` or `indexBumpTxids` before opening.

Requested maintainer action: make the map a function of `bumps` alone. In `#findOrInsertBump`, after a combine, set a hash to the combined BUMP only where no later BUMP holds it (or drop the map, `this.#bumpIndexByTxid = undefined`, and let `#ensureBumpTxidIndex` rebuild it), so the incremental update equals the rebuild.

Evidence status: the reference was run by the linked recorder (Node v22.23.3, two runs byte-identical); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
