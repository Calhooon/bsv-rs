# Preserve an abortAction refusal over the wallet wire

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 42: A refused abort on the wallet wire (Unreleased, bsv-rs#206): the…

Return Aborted false from the wallet. Go serializes success and deserializes Aborted true; TypeScript emits code 8 and the current reader maps it back to false. The wallet has already broadcast the action, so the wire must not claim it was aborted.

Witness:

- [tests/wire_error_frames.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_error_frames.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/serializer/abort_action.go:33-43](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/abort_action.go#L33)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:797-804](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L797)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:336-339](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L336)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:777-804](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L777).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
