keeper's word first

# MerklePath.verify refuses an offset-0 proof one block before the node would mine its spend, and refuses a proven coinbase that nothing spends

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "An offset-0 proof under 100 blocks deep is not proven" (#734). Drafted by the filings-1109 lane on 2026-11-09.

A user who verifies a BEEF with `Transaction.verify` whose proven ancestor sits at offset 0 of its block gets `Invalid merkle path for transaction <txid>` at a chain tip of `h + 99`, although the node accepts a spend of that coinbase in the next block. A user who verifies a proof of the coinbase itself (a miner checking its own block reward, or any BEEF whose subject is the coinbase) gets `false` from `MerklePath.verify` until the tip reaches `h + 100`, although the proof is valid and no spend is being judged.

`MerklePath.verify` applies the coinbase maturity rule to the proof, and compares it against the tip rather than the spend height:

```ts
if (index === 0) {
  // Coinbase transaction outputs can only be spent once they're 100 blocks deep.
  const height = await currentHeight.call(chainTracker)
  ...
  if (blockHeight + 100 > height) {
    return false
  }
}
```

The node's rule is a rule on a spend, at the spend height, which is the tip plus one: `GetSpendHeightAndMTP` returns `pindexPrev->GetHeight() + 1`, and `CheckTxInputs` refuses only when `nSpendHeight - coin->GetHeight() < COINBASE_MATURITY` (100). So at a tip of `h + 99` the spend height is `h + 100`, the depth is 100, and the node admits the spend in the next block. The node has no maturity rule at all on a proof of inclusion.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0, a stub `ChainTracker` whose `isValidRootForHeight` answers `true` for the recorded root at 800000 and whose `currentHeight` answers the tip):

1. The BUMP `fe00350c00010100023ccf505c696ae57525f26e7afdb84f0622ce510c6e00a79baff524881540abbb` (block 800000, one leaf at offset 0, txid `bbab4015...50cf3c`). The recorded parent is a synthetic offset-0 entry with a non-null input under the stub tracker's root; the reference's rule reads the offset alone, so it is the same check a real block's coinbase (always at offset 0) meets, and the node comparison below is about that coinbase.
2. `MerklePath.verify(txid, tracker)` at tip 800099: `false`, and `isValidRootForHeight` is never called. At tip 800100: `true`.
3. `Transaction.verify` on a child spending that transaction, the parent carrying this proof, at tip 800099: throws `Invalid merkle path for transaction bbab40158824f5af9ba7006e0c51ce22064fb8fd7a6ef22575e56a695c50cf3c`. The node would mine the child in block 800100.
4. `Transaction.verify` on the proven transaction itself (no spend judged), at tips 800000 and 800099: the same throw. `Beef.verify` on the same bytes answers `true` (it has no depth rule).

Expected: a proof is valid when its root is the block's root, whatever the tip; where a caller wants the maturity rule for a spend, it is `spendHeight - blockHeight >= 100` with the spend height the tip plus one, applied to the input that spends a coinbase output.

Actual: `blockHeight + 100 > currentHeight` returns `false` at a tip of `blockHeight + 99`, and for a subject that nothing spends.

go-sdk at 2ca481c verifies the proof with no depth rule (`MerklePath.Verify`, `transaction/merklepath.go:423-429`) and applies the node's figure to a coinbase source of a spend, `int64(tip)+1-int64(height) >= maturity` (`spv/verify.go:674-714`), as the node does. bsv-rs follows the reference at `Transaction::verify` by the keeper's word, and its streaming reader keeps the node's reading; the two cells above are stated as the reference's, stricter than the node.

Witness:

- [tests/transaction_coinbase_depth_734.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/transaction_coinbase_depth_734.rs) (`a_lone_leaf_under_100_blocks_deep_is_refused_by_transaction_verify_734`, `an_offset_1_proof_asks_no_height_and_is_proven_at_every_tip_734`, `the_stream_keeps_its_verdict_on_the_same_beef_at_the_four_tips_734`)
- [tests/vectors/coinbase_depth_734.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/coinbase_depth_734.json) (recorded from the reference under Node v22.18.0: bump `lone_800000`, cells at tips 800000, 800099, 800100, 800101 on the doors `merklePath`, `child`, `parent`, `beef`; the `left` path the same, the `right` path, offset 1, valid at every tip)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:476-500](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L476-L500)

Node reading: bitcoin-sv v1.2.2 `src/validation.cpp:2546-2550` (`GetSpendHeightAndMTP`, the tip plus one), `:2617-2625` (`if (nSpendHeight - coin->GetHeight() < COINBASE_MATURITY)`, on a spent coin), `src/consensus/consensus.h:75` (`COINBASE_MATURITY = 100`).

Sibling reading: [go-sdk@2ca481c59 transaction/merklepath.go:423-429](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L423-L429) and [spv/verify.go:674-714](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/spv/verify.go#L674-L714).

Requested maintainer action: move the maturity check out of `MerklePath.verify` to the input that spends a coinbase output, judged as `currentHeight + 1 - blockHeight >= 100`, so a proof verifies by its root alone.

Evidence status: the reference was run (the recorder of #734 under Node 22.18.0) and its outputs are the recorded vector; the node's rule is source-read at v1.2.2, not a running node; go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal.
