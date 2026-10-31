FILE — fifth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); filed as bsv-blockchain/go-sdk#396 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending.

# Enforce the subject dependency graph when validating parsed Atomic BEEF

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Filed as bsv-blockchain/go-sdk#396 on 2026-10-31 under the owner's name (cadence (b), the owner's word of 16:2xZ through the keeper); answer pending. Census row 33: The atomic rule on the subject's graph (0.8.1, BRC-95; beef_stream::atomic_unreached,…

The unrelated-transaction witness includes a present subject and an unrelated raw entry. Go NewBeefFromAtomicBytes only binds the subject (as its comment explicitly says), and the subsequent Beef.IsValid/Verify path uses verifyValid without an atomic graph check. Keep parsing and validation separate if desired, but preserve and enforce the Atomic BEEF constraint at the validation boundary. Do not confuse this with the separately authorized Rust choice to admit raw ancestors behind proofs. Historical TS 2.1.4 behavior is evidence, not a new finding against current TypeScript.

Witness:

- [tests/beef_atomic_graph.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/beef_atomic_graph.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 transaction/beef.go:318-337](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/beef.go#L318)
- [go-sdk@2ca481c59 transaction/beef.go:1030-1045,1240-1298](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/transaction/beef.go#L1030)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Beef.ts:420-434,482-491](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Beef.ts#L420)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:302-311](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L302)

BRC reading: [BRCs@5119a9b51 transactions/0095.md:41-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0095.md#L41).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
