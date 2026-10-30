# Return a script verdict or a typed resource refusal for arithmetic engine limits

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 65: Transaction::verify takes the caller's memory budget as the reference's third…

The increment and sum witnesses at 536870888 bits plus one, and the numeric-left-shift BigInt limit, escape the reference verify call as RangeError instead of a script verdict or local-budget refusal. Wrap engine failure at the correct phase and retain the distinction between invalid input and a caller resource decline. Do not impose node limits on the SDK default: the explicit node word remains separate.

Witness:

- [tests/script_reference_read_limit_331.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/script_reference_read_limit_331.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/primitives/BigNumber.ts:450,771-781](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/BigNumber.ts#L450)
- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:525-535,1066](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L525)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:1685-1697](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L1685)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:50-57](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L50). The BRC does not define V8 limits or Rust error classes; this is a request to classify an SDK evaluation failure.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
