keeper's word first

# Validate discovery certificate trust on read and write

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 38: A discovery entry's trust byte outside 1 to 10 is…

A discovery certificate with trust 0 or 11 is invalid even though one byte can represent it. Go writes and reads that byte without checking 1 through 10, including the zero-value absent-info case. Reject it at both boundaries; the Rust field-prime key parser diagnostics are not part of this filing.

Witness:

- [tests/wire_reader_strictness.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_reader_strictness.rs)
- [tests/wire_identity_certificate_roundtrip.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_identity_certificate_roundtrip.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/serializer/identity_certificate.go:20-26,60-66](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/identity_certificate.go#L20)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1710](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts#L1710)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:2520](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L2520)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:274-277,1401-1411](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L274).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
