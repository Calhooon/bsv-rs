FILE — first in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); pending the owner's cadence word.

# Prevent originator length wrapping and normalize wallet wire originators

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 9: The wallet wire bounds an originator at 250 bytes and…

A 256-byte originator is written with length zero by the byte cast, leaving its bytes to become parameters. Refuse above 250 before writing or dispatch; validate and normalize a named hostname, and strip the leading UTF-8 BOM consistently with TextDecoder. The 251/256-byte and BOM witnesses are in the linked tests.

Witness:

- [tests/wallet_wire_originator_338.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_wire_originator_338.rs)
- [tests/wallet_wire_originator_bom_471.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_wire_originator_bom_471.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:286-294](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L286)
- [go-sdk@2ca481c59 wallet/serializer/frame.go:20-68](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/frame.go#L20)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:1629-1646](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L1629). The byte-length wire field does not justify a wrapping cast.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
