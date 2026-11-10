keeper's word first

# MerklePath.toBinary writes a hashless leaf, a hash of the wrong length, a duplicate's hash or txid flag and a 256-level path as bytes no reader reads back as the path written

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's five divergence rows on `MerklePath`'s writer (#817). Drafted by the fix-817-merkle-writers lane on 2026-11-09.

`MerklePath`'s fields are public, and a caller who builds or edits a path through them (or through `fromCoinbaseTxidAndHeight`, or a one-leaf path whose root the constructor returns unread) can hold a state `toWriter` cannot write. The writer refuses one such state: a hash with a non-hex character throws `Invalid hex string` (`assertValidHex`). Five others it writes without a word, and the bytes either do not frame or read back as another path:

```ts
writer.writeUInt8(treeHeight)                 // n & 0xff
...
if ((flags & 1) === 0) {
  writer.write(toArray(leaf.hash, 'hex').reverse())
}
```

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0). Each path is held as `Object.create(MerklePath.prototype)` with `blockHeight = 800000` and `path` set, then written with `toHex()`; `H(0)` is `96a296d2...cfc7`:

1. A leaf that is not a duplicate and has no hash: `[[{offset: 0, hash: H(0), txid: true}, {offset: 1}]]`. `toHex()` writes the second leaf's offset and flag `00` and then nothing (`toArray(undefined)` is `[]`), ending `...0100`. A reader takes the next 32 bytes as its hash.
2. A hash of other than 64 hex digits. 62 digits are written as 31 bytes and 66 as 33 (neither frames); the empty text is written as nothing; 63 digits are padded with a leading zero (`hexToUint8Array`) to 32 bytes, which read back as a different hash text, `0` followed by the 63 digits.
3. A path of 256 levels: the tree height is written `00` (`writeUInt8` keeps the low byte), so a reader sees no levels and the rest of the bytes as trailing data.
4. A leaf flagged duplicate that also carries a hash: `{offset: 1, hash: H(1), duplicate: true}`. The flag `01` is written and the hash is not, so the path read back has no hash there; the reference's own walk reads that hash where such a leaf is a left child (`findOrComputeLeaf`, `MerklePath.ts:437`), so the written path can compute another root than the held one.
5. A leaf flagged duplicate that is also flagged txid: `[[{offset: 0, hash: H(0), txid: true}, {offset: 1, txid: true, duplicate: true}]]`. `toHex()` writes the flag `03` (`MerklePath.ts:284-286`), ending `...0103`; `fromReader` reads `flags & 1` and sets `duplicate` alone (`:133-140`), so the path read back has lost the txid flag. (Found by bsv-rs's #817 fold.)

Expected: `toWriter` (and so `toBinary`, `toBinaryUint8Array`, `toHex`) throws for a state its bytes cannot carry, as it already throws for a non-hex hash, and writes every other state, valid or not, unchanged.

Actual: at edf6e03 the five are written as above, with no error.

bsv-rs refuses all five before writing any byte, in its own words (`Missing hash at height H, offset O`; `Invalid hash at height H, offset O: expected 64 hex digits, got N`; `Invalid tree height: N, over the 255 levels a BUMP's tree height byte writes`; `Duplicate leaf at height H, offset O carries a hash, which a BUMP's duplicate flag cannot write`; `Duplicate leaf at height H, offset O is flagged txid, which a BUMP's duplicate flag cannot write`), keeps the reference's `Invalid hex string` for a non-hex hash wherever it sits in the path (ahead of any of the five, as the reference's writer throws there), and writes every other state as the reference does (no level, 65 to 255 levels, an empty level 0, repeated and illegal offsets, mismatched roots, an upper-case hash). go-sdk at 2ca481c holds a hash as a 32-byte array, so state 2 cannot arise; its `Bytes()` dereferences a nil hash in state 1 and panics (`transaction/merklepath.go:311`), and writes `byte(treeHeight)` (`:297`) and the flag alone for state 4 (`:310`).

Witness (bsv-rs, the #817 landing; links to be pinned at filing):

- `tests/merkle_path_writer_refusals_817.rs` (one test per cell, and `every_recorded_cell_is_written_or_refused_as_the_reference_save_the_stated_rows_817`)
- `tests/vectors/merkle_path_writer_refusals_817.json` (cells `hashless_leaf`, `hash_of_62_digits`, `hash_of_63_digits`, `hash_of_66_digits`, `empty_hash`, `levels_256`, `duplicate_carrying_a_hash`, `duplicate_flagged_txid`), recorded from the reference by `tests/support/merkle_path_writer_refusals_817.mjs`

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:271-293](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L271-L293) (`toWriter`) and [:437](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L437)
- [ts-stack@edf6e03da packages/sdk/src/primitives/utils.ts:93,127-128,470-475](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/utils.ts#L93) (`toArray(undefined)`, the odd-length pad, `writeUInt8`)
- [go-sdk@2ca481c59 transaction/merklepath.go:293-317](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L293-L317)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:51](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L51) gives the tree height one byte, and [:66-77](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L66-L77) a 32-byte hash after every leaf whose duplicate bit is clear (as cited by bsv-rs's reader rows; the keeper confirms the lines at filing); a writer that emits another length, or a height its byte cannot hold, produces no BUMP.

Requested maintainer action: in `toWriter`, before writing, throw for a leaf whose duplicate bit is clear and whose hash is absent or not 64 hex digits, for a duplicate leaf carrying a hash or the txid flag, and for more than 255 levels (or for more than the constructor's bound, if the writer should hold the same bound); add the cells above as regressions.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0, two runs byte-identical) by the linked recorder, and its outputs are the recorded vector; go-sdk was source-read at the pin, not run. This draft contains no private-key literal.
