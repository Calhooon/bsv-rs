keeper's word first

# MerklePath.toBinary writes a leaf with txid: false as a txid leaf

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on the reference writer's txid flag (#817). Drafted by the fix-817-merkle-writers lane on 2026-11-09.

`toWriter` sets the txid flag when the leaf's `txid` member is present, not when it is true:

```ts
if (leaf?.txid !== undefined && leaf.txid !== null) {
  flags |= 2
}
```

So a leaf a caller marks `txid: false` (a sibling, by intent) is written with flag `02` and read back by `fromBinary` as `txid: true`. A path written and read again then names that leaf among its txids, and code that keys on the flag (BEEF's proven-txid checks, `trim`) treats a sibling hash as a proven transaction.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0): hold `[[{offset: 0, hash: H(0), txid: false}]]` at block height 800000 and call `toHex()`. The result is `fe00350c0001010002...`, the flag byte `02`; the same leaf with the member absent writes `00`.

Expected: `txid: false` is written `00`, as an absent member is.

Actual: at edf6e03 it is written `02`.

bsv-rs's `txid: false` is written `00`; go-sdk at 2ca481c tests the value (`leaf.Txid != nil && *leaf.Txid`, `transaction/merklepath.go:306`).

Witness (bsv-rs, the #817 landing; links to be pinned at filing): `tests/merkle_path_writer_refusals_817.rs` (`a_leaf_not_flagged_txid_is_written_00_where_the_reference_writes_02_817`) and the cell `explicit_txid_false` of `tests/vectors/merkle_path_writer_refusals_817.json`, recorded by `tests/support/merkle_path_writer_refusals_817.mjs`.

Pinned reference reading: [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:284-286](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L284-L286); [go-sdk@2ca481c59 transaction/merklepath.go:306](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L306).

BRC reading: [BRCs@5119a9b51 transactions/0074.md:66-77](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L66-L77) defines the flag byte, `02` marking a client txid; a leaf marked otherwise is not one (the lines as cited by bsv-rs's reader rows; the keeper confirms them at filing).

Requested maintainer action: test `leaf.txid === true` in `toWriter`, and add the cell above as a regression.

Evidence status: the reference was run (Node 22.18.0, two runs byte-identical) by the linked recorder; go-sdk source-read at the pin, not run. This draft contains no private-key literal.
