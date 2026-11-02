FILE — twenty-fourth in the keeper's order, on the keeper's word of 2026-11-02 05:1xZ (from #628's cold read); in ts-stack's turn after row 23, pending its day of the owner's cadence (b).

# Combine a longer MerklePath into a shorter receiver over the union of levels so the root is the checked root

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on `MerklePath` (the 54-level bound and `combine`).

`MerklePath.combine(other)` checks that both paths have the same block height and compute the same root (`MerklePath.ts:509-516`), then merges them level by level, but only over the receiver's levels:

```ts
for (let h = 0; h < this.path.length; h++) {
  combinedPath.push([])
  for (const leaf of this.path[h]) {
    combinedPath[h].push({ ...leaf })
  }
  for (const otherLeaf of other.path[h]) {
```

When `other` has more levels than `this`, its levels above `this.path.length - 1` are dropped, and `trim()` (`:536`) then cuts the result to the nodes the merged level-0 txids need. The combined path has the receiver's height and computes a root other than the one `combine` just checked. Nothing throws, so a caller holding the result has a proof that no longer proves inclusion in the block.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0). Block 100,000, merkle root `f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766`:

1. `other` is the two-level BUMP of that block's transactions at offsets 2 and 3 (`fea0860100020203001d0cb8…fbdacc`, from WhatsOnChain). `other.computeRoot()` is `f3e94742…a95766`.
2. `this` is `new MerklePath(100000, [[{ offset: 0, hash: 'ccdafb73d8dcd0173d5d5c3c9a0770d0b3953db889dab99ef05b1907518cb815' }, { offset: 1, hash: '8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49' }]])`: `other`'s level-1 node at offset 0 and the node `other` computes at level 1 offset 1 (`findOrComputeLeaf(1, 1)`), as one level. `this.computeRoot()` is the same `f3e94742…a95766`, so `combine`'s two checks pass.
3. `this.combine(other)` returns without an error. `this` now has one level, `[{ offset: 2, txid: true, hash: '6359f086…236ec4' }, { offset: 3, hash: 'e9a66845…b80c1d' }]`, written `fea086010001020202c46e23…a6e9`, and `this.computeRoot()` for either txid is `cf4f9d1fa6bf596ae0b2d15b46afede7292bc0ca5e74f319c78a2bcaabc7b897`, not the block's root: the walk climbs to the height the highest offset implies, two levels (`:396-397`), finds no sibling at level 1 and pairs the two transactions' node, `8e308990…df4ae49`, with itself (`:57`).

The receiver in step 2 is contrived: in one block every path has the same height. But `combine`'s own checks are the only guard on its input, and they admit this pair, so the result should still prove what both inputs proved.

The other order fails differently: with the longer path as the receiver, `other.path[h]` is `undefined` for `h` at or above `other.path.length`, and `for (const otherLeaf of other.path[h])` throws `TypeError: other.path[h] is not iterable` rather than combining or refusing in `combine`'s words.

Expected: `combine` merges over the union of both paths' levels (the receiver extended to `other`'s height), then trims, so the result computes the root both inputs were checked against. For the pair above that is `other`'s two levels in ascending offset order, `fea086010002020202c46e23…fbdacc`, with root `f3e94742…a95766` for both txids. Either order of the pair gives that result.

Actual: at edf6e03 the loop runs over `this.path.length` alone (`MerklePath.ts:520`), so step 3 yields a one-level path with root `cf4f9d1f…c7b897`.

bsv-rs's `combine` extends the receiver with empty levels to `other`'s height, merges every level, then sorts and trims, so the pair above combines to `other`'s bytes with root `f3e94742…a95766`. go-sdk at 2ca481c also sizes the merged path by the receiver alone (`combinedPath := make([]map[uint64]*PathElement, len(m.Path))`, `transaction/merklepath.go:454`) and then indexes it over `other`'s levels (`:463-467`), so with the pair above as `m` and `other` its `Combine` panics, `runtime error: index out of range [1] with length 1`.

Witness:

- [src/transaction/merkle_path_603_tests.rs:252-273](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/src/transaction/merkle_path_603_tests.rs#L252-L273) (`combine_extends_a_shorter_path_to_the_others_levels_wire_bump_005`: the pair above combined to `other`'s bytes and the checked root, and the reference's recorded result asserted to be one level with another root)
- [tests/vectors/merkle_path_603.json](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/tests/vectors/merkle_path_603.json) (entry `bump-005-under-its-level-1` under `combine`: `a_path`, `a_root`, `b_hex`, `b_root`, and the reference's `result_hex`, `result_path` and `result.root` `cf4f9d1fa6bf596ae0b2d15b46afede7292bc0ca5e74f319c78a2bcaabc7b897`), recorded from the reference by [tests/support/merkle_path_603.mjs](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/tests/support/merkle_path_603.mjs#L174-L198)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:508-537](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L508-L537) (`combine`; the loop at `:520`, the merge of `other.path[h]` at `:525`, `trim()` at `:536`)
- [go-sdk@2ca481c59 transaction/merklepath.go:453-467](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L453-L467) (`combineVerified`)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:45-51](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L45-L51) gives a BUMP one tree height for its block; it does not define `combine`, so this is the API's own contract: the result of combining two proofs of one root should prove that root.

Requested maintainer action: in `combine`, iterate over `Math.max(this.path.length, other.path.length)` levels, treating a missing level on either side as empty, before `trim()`; or, if paths of different heights are not meant to be combined, refuse them in `combine`'s words before merging. Add the pair above in both orders as a regression whose combined root is `f3e94742…a95766`.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder for the order in steps 1 to 3, and its outputs are the recorded vector; the other order was run once from the same bundle, and go-sdk once in a scratch copy of 2ca481c (go1.27.0, `MerklePath.Combine` on the same pair), with the words given above. The linked Rust test is the reproducible witness. This draft contains no private-key literal.
