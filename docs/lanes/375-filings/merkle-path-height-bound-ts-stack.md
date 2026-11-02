FILE — twenty-third in the keeper's order, on the keeper's word of 2026-11-02 05:1xZ (from #628's cold read); in ts-stack's turn after row 22, pending its day of the owner's cadence (b).

# Bound MerklePath height at BRC-74's 64 levels rather than 54

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on `MerklePath` (the 54-level bound and `combine`).

BRC-74 gives a BUMP's tree height one byte with the description "The height of the Merkle Tree in this block, max 64". The reference's `MerklePath` constructor refuses any path of more than 54 levels:

```ts
if (!Array.isArray(path) || path.length === 0 || path.length > 54) {
  throw new Error('Merkle Path must contain between 1 and 54 levels')
}
```

`MerklePath.fromBinary`, `fromHex` and `fromReader` build through that constructor (`:104-168`, `fromReader` at `:151`), so a BUMP of 55 to 64 levels, well formed under BRC-74, is refused by every TypeScript reader in these words, whatever `legalOffsetsOnly` and `validateRoots` say. No block today has a tree near 54 levels (that is more than 2^53 transactions), so no live proof is refused. The problem is that SDKs disagree on what a well-formed BUMP is. A reader built to BRC-74 accepts paths the reference refuses, and a conformance vector at the specification's limit cannot be shared.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0). Take a block-1 coinbase txid `0e3e2357…512098` at offset 0 of level 0 with a duplicate marker at offset 1, and add a duplicate marker at offset 1 on each further level:

1. 54 levels: `new MerklePath(1, path)` is accepted, and `computeRoot` returns `f41005a88fe7ab74c6a59bdb23c7e580036a2a1138b61a40dc7937e9aab8e2fb`.
2. 64 levels: `new MerklePath(1, path)` throws `Merkle Path must contain between 1 and 54 levels`, both with `legalOffsetsOnly` true and with it false. The root of that path, climbed one level at a time by the reference's own walk (a one-level `MerklePath` whose duplicate sibling pairs the working hash with itself, `MerklePath.ts:60`, applied 64 times), is `84a49187861af1878b1e1f0a03f2a118f846fd8c9277b2af05c66319fb8ff52a`.
3. 65 levels (a BUMP of block 900,000's eleven levels with empty levels appended to a tree height of 65, `fea0bb0d0041…`): `MerklePath.fromHex` throws the same 54-level words. BRC-74 refuses it too, so every reader should refuse this one; only the words' bound is wrong.

Expected: a path of 1 to 64 levels is accepted (subject to the offset and root checks), and a path of 65 or more is refused, as BRC-74 reads. The 64-level path in step 2 constructs and computes the root given there.

Actual: at edf6e03 the bound is 54 (`MerklePath.ts:198-199`), so step 2 is refused.

bsv-rs bounds a path at 64 levels (`MAX_TREE_HEIGHT`) in its constructor and its BUMP reader. It accepts the 54- and 64-level paths with the roots above and refuses the 65-level BUMP as `Invalid tree height: 65, over the maximum height 64`. go-sdk at 2ca481c checks no bound in `NewMerklePath` (`transaction/merklepath.go:149-155`); its binary reader takes the tree height as a `uint8` (`:209-210`), so it reads up to 255 levels.

Witness:

- [src/transaction/merkle_path_603_tests.rs:178-224](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/src/transaction/merkle_path_603_tests.rs#L178-L224) (`the_tree_height_bound_is_64_levels_bump_lean_66_wire_bump_001_029`: the three paths above, read from the recorded vector)
- [tests/vectors/merkle_path_603.json](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/tests/vectors/merkle_path_603.json) (entries `bump-001-duplicates-54-levels`, `bump-001-duplicates-64-levels` and `bump-029` under `construct`, and `duplicate_fold_roots`), recorded from the reference by [tests/support/merkle_path_603.mjs](https://github.com/Calhooon/bsv-rs/blob/10b88ea3ec6221ca7c9803700c7827599b08cc9d/tests/support/merkle_path_603.mjs#L109-L130)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:198-199](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L198-L199) (the bound) and [:104-168](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L104-L168) (`fromHex`, `fromReader`, `fromBinary` through the constructor)
- [go-sdk@2ca481c59 transaction/merklepath.go:149-155,209-210](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L149-L155)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:51](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L51) ("tree height | The height of the Merkle Tree in this block, max 64 | 1 byte"). The specification's bound is 64; nothing in BRC-74 names 54.

Requested maintainer action: raise the constructor's bound to 64 levels and its words with it (`between 1 and 64 levels`), and add the 64-level path above as an accepted regression and the 65-level BUMP as a refused one. If 54 is a deliberate implementation limit (for example, offsets held as JavaScript numbers), please say so in the code and in BRC-74, so that other SDKs can follow the same bound.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder, and its outputs are the recorded vector; go-sdk was source-read at the pin, not run. The linked Rust test is the reproducible witness. This draft contains no private-key literal.
