# Validate requested certificate policies before signing and on receipt

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 62: Peer refuses a malformed requested certificate set where the reference…

Pass duplicate certifiers, more than 100 certifiers/types/fields or unsafe/repeated field names through the Peer doors. The reference snapshots and bounds the policy before signing and checks incoming sets; Go defines ValidateRequestedCertificateSet but its Peer does not call it. Keep typed 32-byte type-ID rejection distinct from validating the full set.

Witness:

- [tests/auth_requested_set_validation_294.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_requested_set_validation_294.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/AuthMessageValidation.ts:107-162](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/AuthMessageValidation.ts#L107)
- [ts-stack@edf6e03da packages/sdk/src/auth/Peer.ts:158,332](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L158)
- [go-sdk@2ca481c59 auth/peer.go:1074-1110](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L1074)
- [go-sdk@2ca481c59 auth/utils/validate_certificates.go:20-51,312-336](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/utils/validate_certificates.go#L20)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:145-172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L145). The concrete limits are SDK safeguards; the BRC describes the requested-set message shape.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
