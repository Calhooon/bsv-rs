keeper's word first

# Use the linkage reason width and validate returned linkage context

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 72: The wire transceiver's two linkage calls (Unreleased, bsv-rs#406) write the…

A reason of 253 bytes exposes the varint-string versus i8 length divergence; a level outside 0..2 and a result key different from the request expose missing result validation. The six normal fixture frames already match. Align the valid reason domain and bind returned prover/verifier/counterparty/protocol/keyID to the request.

Witness:

- [tests/wire_linkage_calls_406.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_linkage_calls_406.rs)
- [tests/vectors/wallet_wire/linkage_calls_406.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_wire/linkage_calls_406.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:790-924](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L790)
- [go-sdk@2ca481c59 wallet/serializer/reveal_counterparty_key_linkage.go:11-29](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/reveal_counterparty_key_linkage.go#L11)
- [go-sdk@2ca481c59 wallet/serializer/reveal_specific_key_linkage.go:11-35](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/reveal_specific_key_linkage.go#L11)
- [go-sdk@2ca481c59 wallet/serializer/serializer.go:165-190](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/serializer.go#L165)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:2052-2057,2088-2095](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L2052).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
