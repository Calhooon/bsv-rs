keeper's word first

# Apply certificate byte bounds and preserve DER signature bytes

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 60: A certificate field value is bounded at 1 MiB on…

Use the over-1-MiB field, over-16-MiB frame, 73-byte signature, over-2048-byte keyring entry and noncanonical-base64 witnesses. Go has no corresponding read/write bounds, parses signatures as BER and normalizes high S when serializing; a signed certificate must not be reinterpreted or rewritten by the binary adapter. Distinguish ECDSA scalar validity from preserving the transmitted DER encoding.

Witness:

- [tests/auth_certificate_bounds_297.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_certificate_bounds_297.rs)
- [tests/vectors/auth_certificate_signature_der_305.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_certificate_signature_der_305.json)
- [tests/auth_certificate_frame_bounds_301.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_certificate_frame_bounds_301.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/certificates/Certificate.ts:57-91,300-319,377-397](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/Certificate.ts#L57)
- [ts-stack@edf6e03da packages/sdk/src/auth/certificates/MasterCertificate.ts:63-74](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/certificates/MasterCertificate.ts#L63)
- [go-sdk@2ca481c59 wallet/serializer/certificate.go:27-66,118-124](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/certificate.go#L27)
- [go-sdk@2ca481c59 primitives/ec/signature.go:77-102,297-299](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/primitives/ec/signature.go#L77)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0052.md:97-105](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0052.md#L97). Preserve signed bytes; the numeric allocation limits are reference safeguards, not additional BRC numbers.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
