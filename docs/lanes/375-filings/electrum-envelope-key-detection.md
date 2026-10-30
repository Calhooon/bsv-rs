# Detect Electrum embedded keys from prefix and framing rather than envelope length

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 66: An Electrum ECIES envelope's embedded key is found by the…

A no-key envelope of 32 plaintext bytes or more with the expected sender is valid. Go cuts ciphertext at byte 37 solely because the envelope exceeds 69 bytes, corrupting that case; it also fails the uncompressed embedded-key case and does not compare an embedded key with the expected sender. Use the reference prefix/framing decision and mismatch refusal.

Witness:

- [tests/compat_ecies_envelope_109.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/compat_ecies_envelope_109.rs)
- [tests/vectors/compat_ecies_envelope_109.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/compat_ecies_envelope_109.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/compat/ECIES.ts:607-656](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/ECIES.ts#L607)
- [go-sdk@2ca481c59 compat/ecies/ecies.go:117-153](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/ecies/ecies.go#L117)

BRC reading: No BRC defines this compatibility format or its limits; this is an SDK parity request.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
