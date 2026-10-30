# Read the default TypeScript certificate revocation outpoint consistently

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 52: A certificate's field value is its base64 text (Certificate.fields: IndexMap<String,…

MasterCertificate issuance defaults the revocation string to a txid without a dot/index. The TypeScript binary writer treats that as index zero. Go OutpointFromString rejects strings shorter than 66 bytes, so it cannot read this default certificate form. Please align the adapter or require the explicit .0 form consistently at issuance; do not change signed certificate text silently.

Witness:

- [tests/auth_certificate_json_268.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_certificate_json_268.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/certificates/MasterCertificate.ts:442](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/MasterCertificate.ts#L442)
- [ts-stack@edf6e03da packages/sdk/src/auth/certificates/Certificate.ts:257-270](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/Certificate.ts#L257)
- [go-sdk@2ca481c59 transaction/outpoint.go:49-65](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/outpoint.go#L49)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0052.md:85-103](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0052.md#L85).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
