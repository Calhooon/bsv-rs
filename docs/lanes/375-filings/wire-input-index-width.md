FILE — eleventh in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); pending the owner's cadence word.

# Bound internalizeAction outputIndex consistently with PositiveIntegerOrZero

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 44: Three wallet wire readers the reference bounds only after the…

Use an internalizeAction outputIndex of 4294967296 with an otherwise valid selected remittance. The wire reads a safe JS integer, and validatePositiveIntegerOrZero checks only the lower bound; the BRC-100 type has an upper bound of 2^32-1. SignAction already applies MAX_UINT32 after decoding; align the internalize path. The Go truncating reader is already covered by go-sdk #387.

Witness:

- [tests/wire_method_roundtrip_tests.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_method_roundtrip_tests.rs)
- [tests/wire_u32_field_bounds_tests.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_u32_field_bounds_tests.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/validationHelpers.ts:306-335,840-856,979](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/validationHelpers.ts#L306)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:662-671,1082](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L662)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:274,1040-1070](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L274).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Existing related filing(s): go-sdk #387. Keep these numbers; confirm their scope before opening a duplicate.
