FILE — eighth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6517160425); pending the owner's cadence word.

# Provide a canonical CompactSize reader for protocol parsing

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 15: Varint readers are canonical from 0.6.0, as node and TS…

fd fc 00 encodes 252 non-minimally; fe ff ff 00 00 and ff ff ff ff ff 00 00 00 00 likewise select an unnecessarily wide representation. The Go reader accepts them. Preserve an explicitly named lenient reader if needed, but make canonical validation available to transaction/BEEF callers, matching the node and TypeScript strict reader.

Witness:

- [tests/canonical_varint.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/canonical_varint.rs)

Pinned reference reading:

- [go-sdk@2ca481c59 util/varint.go:71-105](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/util/varint.go#L71)
- [bitcoin-sv@6504a3aff src/serialize.h:315-340](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/serialize.h#L315)
- [ts-stack@edf6e03da packages/sdk/src/primitives/readVarIntNumStrict.ts:13-40](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/readVarIntNumStrict.ts#L13)

BRC reading: [BRCs@5119a9b51 transactions/0062.md:63-69](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/transactions/0062.md#L63). This uses transaction VarInts; the canonical encoding rule is supplied by the node reader cited above.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
