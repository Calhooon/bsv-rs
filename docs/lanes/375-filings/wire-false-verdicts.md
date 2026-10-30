# Do not serialize false wallet verification results as success

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 40: A false verdict on the wallet wire (Unreleased, bsv-rs#197): verifyHmac,…

Return Valid false from verifyHmac or verifySignature, or Authenticated false from waitForAuthentication. The Go serializers discard the result and its readers always return true. The reference emits an error frame for false and the zero error byte only for true. A round trip must never turn refusal into authentication.

Witness:

- [tests/wire_error_frames.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_error_frames.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/serializer/verify_hmac.go:71-77](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/verify_hmac.go#L71)
- [go-sdk@2ca481c59 wallet/serializer/verify_signature.go:102-110](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/verify_signature.go#L102)
- [go-sdk@2ca481c59 wallet/serializer/authenticated.go:36-44](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/authenticated.go#L36)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:1520-1525,1597-1602,1636-1643](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L1520)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:289-309](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L289). The BRC requires failures to remain failures; the exact binary error mapping is the SDK wire contract.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
