keeper's word first

# Validate positive createAction unlockingScriptLength

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 57: A createAction input's unlockingScriptLength of 0 is refused (Unreleased, bsv-rs#282)…

With unlockingScript omitted and unlockingScriptLength 0, Go writes the value without checking BRC-100's positive-integer range. The linked witness expects WERR_INVALID_PARAMETER. Validate the supplied length before serialization, with the BRC-100 range 1 through 4294967295. The TypeScript zero-minimum validator has its own draft.

Witness:

- [tests/wallet_create_action_unlocking_script_282.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_create_action_unlocking_script_282.rs)
- [tests/vectors/wallet_create_action_unlocking_script_282.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/wallet_create_action_unlocking_script_282.json)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/serializer/create_action_args.go:56](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/create_action_args.go#L56)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:649](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L649).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
