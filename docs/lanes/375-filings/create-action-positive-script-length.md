keeper's word first

# Refuse zero unlockingScriptLength as BRC-100 specifies

Repository: bsv-blockchain/ts-stack, bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 57: A createAction input's unlockingScriptLength of 0 is refused (Unreleased, bsv-rs#282)…

With unlockingScript omitted and unlockingScriptLength 0, TypeScript validateCreateActionInput uses a zero minimum and Go has no equivalent validation. The linked witness expects WERR_INVALID_PARAMETER. An actual empty unlockingScript is already refused by the reference; keep those two cases distinct.

Witness:

- [tests/wallet_create_action_unlocking_script_282.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_create_action_unlocking_script_282.rs)
- [tests/vectors/wallet_create_action_unlocking_script_282.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_create_action_unlocking_script_282.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/validationHelpers.ts:574-603](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/validationHelpers.ts#L574)
- [go-sdk@2ca481c59 wallet/serializer/create_action_args.go:56](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/create_action_args.go#L56)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:649](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L649).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
