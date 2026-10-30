FILE — fourth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); pending the owner's cadence word.

# Reject raw zero-input and zero-output transactions in BEEF structure validation

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 31: TS's Beef.verifyValid reads a BEEF carrying a raw transaction with…

Call Beef.verifyValid on the no-input and no-output BEEF witnesses. It sorts links but never applies the raw transaction structure checks. Transaction.verify applies those checks only on unmined transactions. A known proof does not make a malformed raw transaction structure valid. Keep parse-only entry points separate from this structural verdict.

Witness:

- [tests/vectors/beef_of_any_size/no_input_atomic.bin](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/beef_of_any_size/no_input_atomic.bin)
- [tests/vectors/beef_of_any_size/no_output_atomic.bin](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/beef_of_any_size/no_output_atomic.bin)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:1054-1075](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L1054)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:1336-1342,1654](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L1336)
- [bitcoin-sv@879fc8b42 src/validation.cpp:523-534](https://github.com/bitcoin-sv/bitcoin-sv/blob/879fc8b42168dd0e608dafd51b39c6dabad37d4d/src/validation.cpp#L523)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:50-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L50).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
