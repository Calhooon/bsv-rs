keeper's word first

# Beef.makeTxidOnly does not synchronize nested edits, so after an entry's transaction is edited in place it replaces the edited entry with the old txid alone

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`Beef::make_txid_only` after an edit (#817, stated)" ("Ours: the edited entry kept. Theirs: a draft on the queue"). Drafted by the fix-817-door-sync-fold lane on 2026-11-09, from the rule read of bsv-rs PR #832.

`Beef.findTxid` synchronizes the entries edited in place before it answers (`synchronizeNestedTransactionMutations`, then the rebuilt indexes), and so do `mergeBump`, `mergeRawTx`, `mergeTransaction`, `mergeTxidOnly` and `mergeBeef`. `makeTxidOnly` does not: it reads its position index as it stood before the edit. A caller who edits a held transaction (the documented way to adjust a transaction found in a BEEF, `findTxid(A).tx`) and then trims by the old txid loses the edited transaction and writes a txid the BEEF no longer holds.

```ts
makeTxidOnly(txid: string): BeefTx | undefined {
  const i = this.#ensureTxPositionIndex().get(txid)
  if (i === undefined) return undefined
  let btx = this.txs[i]
  if (btx.isTxidOnly) {
    return btx
  }
  btx = BeefTx.fromTxid(txid)
  this.txs[i] = btx
```

Steps to reproduce (recorded from the unmodified SDK at the pin under Node v22.23.3 by bsv-rs's recorder, case `an_edit_then_make_txid_only_of_the_old_txid`):

1. `const beef = new Beef(); beef.mergeRawTx(u.toBinary())` for a transaction U.
2. `beef.findTxid(u.id('hex')).tx.lockTime = 1`: the held entry is now V, a different txid.
3. `beef.makeTxidOnly(u.id('hex'))`.

Expected: `undefined`, the BEEF unchanged (it no longer holds U; `findTxid(U)` answers `undefined` at this point, `findTxid(V)` the edited entry), as for any txid the BEEF does not hold; or the synchronization `findTxid` runs, with the same answer.

Actual: the entry U's position held is replaced by `BeefTx.fromTxid(U)`: V's transaction is lost and `toHex()` writes a txid-only U, a txid no entry of the BEEF carried any more. `makeTxidOnly(V)` answers `undefined` (V is not in the stale index).

bsv-rs answers `None` for U and keeps V (its index checks a hit against the entry's txid). Since its edit door's lane, an edit there goes through `Beef::edit_tx`, which re-keys the edited entry at once, so its `make_txid_only(V)` makes V a txid alone where the reference's misses (the recorded case `an_edit_then_make_txid_only_of_the_new_txid`, `an_edit_then_make_txid_only_of_the_new_txid_is_stated_817`).

Witness:

- [tests/beef_door_sync_817.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/beef_door_sync_817.rs) `an_edit_then_make_txid_only_of_the_old_txid_is_stated_817` (the reference's bytes and answer recorded beside this crate's)
- [tests/vectors/beef_door_sync_817.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/beef_door_sync_817.json), recorded by [tests/support/beef_door_sync_817.mjs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/support/beef_door_sync_817.mjs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:552-565](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L552-L565) (`makeTxidOnly`, no synchronization)

Sibling reading: [Beef.ts:497-500](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L497-L500) (`findTxid` synchronizes first), [Beef.ts:342-352](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L342-L352) (`synchronizeNestedTransactionMutations`). go-sdk@2ca481c keys `Transactions` by the txid at merge and re-keys nothing (`transaction/beef.go:801-818`), so its `MakeTxidOnly(A)` replaces the edited entry too.

Existing related filing(s): none known. Search ts-stack's issues for `makeTxidOnly` before opening.

Requested maintainer action: call `this.synchronizeNestedTransactionMutations()` at the top of `makeTxidOnly`, as `findTxid` does, so a txid the BEEF no longer holds answers `undefined`.

Evidence status: the reference was run by the linked recorder (Node v22.23.3); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
