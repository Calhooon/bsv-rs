keeper's word first

# Reject reserved BEEF discriminators and repeated BUMP offsets

Repository: bsv-blockchain/ts-stack, bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 36: One reader for both paths (Unreleased, bsv-rs#86): Beef::from_binary is the…

For TypeScript, mutate a V1 has-BUMP byte to 2 or a V2 format byte to 3; the current decoder treats them as ordinary forms. For Go, repeat a BUMP offset with a different hash; its last-wins lookup discards the contradiction. The linked tests construct these bytes with the crate writer and pin duplicate-offset refusals. BUMP bit-field permissiveness is a separately documented Rust reading, not a claim that every unused flag bit is forbidden by BRC-74.

Witness:

- [tests/beef_two_readers_agree.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/beef_two_readers_agree.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/BeefTx.ts:291-310](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/BeefTx.ts#L291)
- [ts-stack@edf6e03da packages/sdk/src/transaction/MerklePath.ts:133-140,221](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/MerklePath.ts#L133)
- [go-sdk@2ca481c59 transaction/merklepath.go:87-110](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/merklepath.go#L87)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:63-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L63).  Also see [BRC-96 transactions/0096.md:46-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0096.md#L46) for V2 data formats.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
