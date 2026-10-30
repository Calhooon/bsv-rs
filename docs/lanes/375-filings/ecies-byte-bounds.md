# Bound ECIES inputs before hashing, encryption and decryption

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 8: ECIES byte bounds (#333): both Rust readers reject envelopes over…

Apply the reference 16 MiB plaintext and 16 MiB + 160 byte envelope caps before work. ElectrumDecrypt has a minimum but no maximum; BitcoreDecrypt and both writers have neither upper cap. Also review short Bitcore inputs before slicing. This filing requests the bounds, not identical Rust error wording.

Witness:

- [tests/compat_ecies_bounds_333.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/compat_ecies_bounds_333.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/compat/ECIES.ts:589-594,704-711](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/ECIES.ts#L589)
- [ts-stack@edf6e03da packages/sdk/src/compat/CompatValidation.ts:1-15](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/compat/CompatValidation.ts#L1)
- [go-sdk@2ca481c59 compat/ecies/ecies.go:62-153,157-214](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/compat/ecies/ecies.go#L62)

BRC reading: No BRC defines this compatibility format or its limits; this is an SDK parity request.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
