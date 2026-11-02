FILE — twenty-fifth in the keeper's order, on the keeper's word of 2026-11-02 08:1xZ (from #637's cold read); in go-sdk's turn after rows 23 and 24, pending its day of the owner's cadence (b).

# Combine files the receiver's level-1 nodes under level 0 when the receiver is the longer path and returns no error

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on `MerklePath` (the 54-level bound and `combine`).

`MerklePath.Combine(other)` checks that both paths have the same block height and compute the same root (`transaction/merklepath.go:431-447`), then calls `combineVerified` (`:449`), which merges `other` into the receiver level by level by index:

```go
for h := 0; h < len(other.Path); h++ {
	for l := 0; l < len(other.Path[h]); l++ {
		combinedPath[h][other.Path[h][l].Offset] = other.Path[h][l]
	}
}
```

(`:463-467`; the merged path is sized by the receiver alone at `:454`). Index `h` is taken as the same tree level in both paths. When `other` has fewer levels than the receiver and its lowest level holds nodes of a higher tree level, those nodes are filed under the receiver's level 0, beside the transactions, at their own offsets. The trim (`:469-482`) then drops the receiver's own level-1 node, because the two level-0 offsets under it (`:474-479`) are now occupied, and the walk in `ComputeRoot` (`:393-409`) synthesizes level 1 from the misfiled nodes. `Combine` returns `nil`, and the receiver now computes a root other than the one `Combine` just checked: a caller holding the result has a proof that no longer proves inclusion in the block.

Steps to reproduce (go-sdk at 2ca481c, go1.27.0, a `main` package in a scratch copy of the module calling `NewMerklePathFromHex`, `Combine`, `ComputeRoot` and `Bytes`). Block 100,000, merkle root `f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766`:

1. `m` is the two-level BUMP of that block's transactions at offsets 2 and 3 (from WhatsOnChain): `fea0860100020203001d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e90202c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f0596301000015b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc`. `m.ComputeRoot(nil)` is `f3e94742…a95766`.
2. `other` is one level holding `m`'s level-1 node at offset 0 (`ccdafb73d8dcd0173d5d5c3c9a0770d0b3953db889dab99ef05b1907518cb815`) and the node `m` computes at level 1 offset 1 (`8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49`): `fea08601000102000015b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc010049aef42d78e3e9999c9e6ec9e1dddd6cb880bf3b076a03be1318ca789089308e`. `other.ComputeRoot(nil)` is the same `f3e94742…a95766`, so `Combine`'s two checks pass.
3. `m.Combine(other)` returns `<nil>`. The output:

```
m.Combine(other) err: <nil>
levels: 2
  level 0 offset 0 hash ccdafb73d8dcd0173d5d5c3c9a0770d0b3953db889dab99ef05b1907518cb815
  level 0 offset 1 hash 8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49
  level 0 offset 2 hash 6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4
  level 0 offset 3 hash e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d
  level 1 empty
hex: fea08601000204000015b88c5107195bf09eb9da89b83d95b3d070079a3c5c5d3d17d0dcd873fbdacc010049aef42d78e3e9999c9e6ec9e1dddd6cb880bf3b076a03be1318ca789089308e0202c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f0596303001d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e900
root for txid 6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4 0a1c0549527d48c4d2cbef2860b4737bcccd88dac613304dc7454e3304e9bcc2 <nil>
```

The two level-1 nodes sit at level 0 offsets 0 and 1, level 1 is empty, and the root for the transaction at offset 2 is `0a1c0549527d48c4d2cbef2860b4737bcccd88dac613304dc7454e3304e9bcc2`, not the checked `f3e94742…a95766`: the walk hashes the two level-1 nodes as if they were transactions and pairs that result with the level-1 node of offsets 2 and 3.

The pair in step 2 is contrived: in one block every path has the same height. But `Combine`'s own checks are the only guard on its input, and they admit this pair, so the result should still prove what both inputs proved.

The other order fails differently: with `other` from step 2 as the receiver and the BUMP from step 1 as the argument, `combineVerified` indexes `combinedPath[1]` of a one-level slice at `:465` and panics, `runtime error: index out of range [1] with length 1`.

Expected: `Combine` merges each of `other`'s levels into the receiver's level of the same tree height, so that every node keeps its own height (BRC-74 encodes each level's leaves at that level and increments the height after each, `0074.md:53-62`, up to the block's one tree height, `:51`), then trims, so the result computes the root both inputs were checked against. For the pair above that is the BUMP of step 1 with its level 0 in ascending offset order, `fea086010002020202c46e23…fbdacc`, with root `f3e94742…a95766`. Alternatively, if paths of different heights are not meant to be combined, `Combine` refuses them with an error before merging.

Actual: at 2ca481c `combineVerified` merges `other.Path[h]` into the receiver's `Path[h]` by index (`merklepath.go:463-467`), so step 3 yields the two-level path above with root `0a1c0549…e9bcc2` and no error.

bsv-rs's `combine` takes the union over both paths' levels (the receiver extended to the other's height), merges every level, then sorts and trims, so the pair above combines to the BUMP of step 1 in ascending offset order with root `f3e94742…a95766`. The TypeScript reference at ts-stack edf6e03 merges over the receiver's levels alone (`MerklePath.ts:520`); with the longer path as the receiver, as in step 3, `other.path[h]` is `undefined` above `other`'s levels and `for (const otherLeaf of other.path[h])` (`:525`) throws `TypeError: other.path[h] is not iterable`.

Witness:

- [src/transaction/merkle_path_603_tests.rs:252-273](https://github.com/Calhooon/bsv-rs/blob/9c55f0054922c74ef450eeec025c8473a6b2ffd5/src/transaction/merkle_path_603_tests.rs#L252-L273) (`combine_extends_a_shorter_path_to_the_others_levels_wire_bump_005`: the pair above combined to the step-1 BUMP's sorted bytes and the checked root)
- [tests/vectors/merkle_path_603.json](https://github.com/Calhooon/bsv-rs/blob/9c55f0054922c74ef450eeec025c8473a6b2ffd5/tests/vectors/merkle_path_603.json) (entry `bump-005-under-its-level-1` under `combine`: `a_path`, the one-level path of step 2; `b_hex`, the BUMP of step 1; `b_sorted_hex`; `a_root` and `b_root` `f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766`)

Pinned reference reading:

- [go-sdk@2ca481c59 transaction/merklepath.go:431-484](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L431-L484) (`Combine` and `combineVerified`; the merged path sized at `:454`, the merge by index at `:463-467`, the trim at `:469-482`)
- [go-sdk@2ca481c59 transaction/merklepath.go:339-411](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L339-L411) (`ComputeRoot`; the walk at `:393-409`)
- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:508-537](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L508-L537) (`combine`; the loop at `:520`, the merge of `other.path[h]` at `:525`)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:45-62](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L45-L62) gives a BUMP one tree height for its block (`:51`) and its leaves level by level, each at its own height (`:53-62`); it does not define `combine`, so this is the API's own contract: the result of combining two proofs of one root should prove that root, with every node at its own level.

Requested maintainer action: in `combineVerified`, size the merged path by `max(len(m.Path), len(other.Path))` and merge each of `other`'s nodes at its own tree level, or, if paths of different heights are not meant to be combined, return an error from `Combine` before merging. Add the pair above in both orders as a regression whose combined root is `f3e94742…a95766` and whose `Combine` does not panic.

Evidence status: go-sdk was run in a scratch copy of 2ca481c (go1.27.0, offline module cache) by a `main` package calling the public API on the two paths above, in both orders; the outputs above are that run's. The TypeScript `TypeError` is from a separate run of a bun bundle of ts-stack@edf6e03 `packages/sdk` under Node 22.18.0, not repeated for this draft. The linked Rust test is the reproducible witness. This draft contains no private-key literal.
