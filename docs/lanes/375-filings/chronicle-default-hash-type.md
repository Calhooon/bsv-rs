# Document or align the version-1 Chronicle hash-type default

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 30: The Chronicle gates in the default mode (Unreleased, bsv-rs#397, the…

Use a version-1 transaction with the recorded Chronicle signature and no explicit epoch/flags. TypeScript refuses it, although its default runs Chronicle opcodes; Go adds UTXOAfterChronicle then Chronicle and admits the type. Distinguish the SDK default from an explicit node coin-era word. The existing ts-stack #1437 concerns its own gate and does not file the Go difference.

Witness:

- [tests/script_chronicle_default_397.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/script_chronicle_default_397.rs)
- [tests/vectors/script_signature_words_417.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/script_signature_words_417.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:338-341,586-591,827-828](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L338)
- [go-sdk@2ca481c59 script/interpreter/thread.go:370-374,504-506,807-812](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/script/interpreter/thread.go#L370)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:50-57](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L50). This BRC requires verification but does not choose a JavaScript-style default epoch; this filing asks the SDKs to state/align that distinction.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Existing related filing(s): ts-stack #1437. Keep these numbers; confirm their scope before opening a duplicate.
