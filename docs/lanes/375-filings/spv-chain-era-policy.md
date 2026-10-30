keeper's word first

# Separate unmined relay policy from block validation and explicit network context

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 12: The live chain-parameter verifier (#440) adds per-input word derivation over…

Review the use of MaxUint32 for unmined spend height and BlockValidationFlags in SPV verification. It activates future eras and omits standard policy. The Rust witness exercises explicit activation heights, tip plus one and source proof heights. The zero-height and unproven-P2SH behavior are separately documented API choices; do not silently substitute a network when chain context is unavailable.

Witness:

- [tests/beef_stream_word_440.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/beef_stream_word_440.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:1391-1456](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L1391)
- [go-sdk@2ca481c59 spv/script_flags.go:15-36,51-57](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/spv/script_flags.go#L15)
- [go-sdk@2ca481c59 spv/verify.go:531-575](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/spv/verify.go#L531)
- [bitcoin-sv@879fc8b42 src/validation.cpp:1032](https://github.com/bitcoin-sv/bitcoin-sv/blob/879fc8b42168dd0e608dafd51b39c6dabad37d4d/src/validation.cpp#L1032)
- [bitcoin-sv@879fc8b42 src/configscriptpolicy.cpp:310-321,353-364](https://github.com/bitcoin-sv/bitcoin-sv/blob/879fc8b42168dd0e608dafd51b39c6dabad37d4d/src/configscriptpolicy.cpp#L310)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:50-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L50). The BEEF verification context must be distinguished from a local relay-policy decision; zero network heights are an SDK configuration question.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
