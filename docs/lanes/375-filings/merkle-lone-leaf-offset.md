keeper's word first

# Reject a one-transaction Merkle proof with a nonzero leaf offset

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 32: The whole-BEEF path follows the streaming reader where the reference…

A one-level path containing exactly one hashed leaf at offset 1 must not return that leaf as a root. MerklePath.ts:345,390-391 short-circuits on element count without checking offset. The same witness reaches Beef.verifyValid. Offset 0 remains the valid one-transaction-block case; the strict-vs-prefix parser and allowTxidOnly API choices are not this requested fix.

Witness:

- [tests/merkle_path_lone_leaf.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/merkle_path_lone_leaf.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:345,390-391](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L345)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:1101-1104,1286-1309](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L1101)

BRC reading: [BRCs@5119a9b51 transactions/0074.md:59-77](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0074.md#L59).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
