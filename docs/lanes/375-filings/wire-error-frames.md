# Frame wallet failures and bound error text in the wire processor

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 41: The processor's error frame is the reference's (Unreleased, bsv-rs#202), in…

Make the wallet return a code-6 parameter refusal, then an untyped error with more than 4096 message bytes and a stack. Go returns a transport error instead of a wire frame; its standalone WriteResultFrame also writes unbounded message/stack. Match the code and bounded-message envelope contract without exposing the stack. The original Rust no-logging sentence is stale after #212; this draft covers only the continuing Go finding.

Witness:

- [tests/wire_error_frames.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_error_frames.rs)
- [tests/wire_wallet_refusal_class.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wire_wallet_refusal_class.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/substrates/wallet_wire_processor.go:94-97](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/wallet_wire_processor.go#L94)
- [go-sdk@2ca481c59 wallet/serializer/frame.go:71-87](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/serializer/frame.go#L71)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:2387-2418](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts#L2387)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:289-309](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L289). The exact code/message/stack wire profile is implemented by the TypeScript reference.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

The source row stays unchanged because part of it is stale: The no-logging assertion was superseded by #212/#137: src/wallet/wire/processor.rs:228-260 has opt-in tracing. Leave the entire mixed row unchanged; retain the live Go error-frame finding in the linked draft.
