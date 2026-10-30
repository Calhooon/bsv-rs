# Specify an unambiguous signed-header comparator for HTTP token punctuation

Repository: bsv-blockchain/BRCs

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 78: On HTTP token punctuation in a header name (_, !…

BRC-104 requires lexicographic lowercase-header ordering at lines 105, 196 and 209. TypeScript localeCompare and Go byte sorting give different orders for legal ASCII token punctuation; Rust currently follows TypeScript. The linked vector records that disagreement. Please define the exact comparator and migration behavior so both sides derive one signature preimage. This is a BRC clarification request, not an allegation that Go byte ordering violates a settled profile.

Witness:

- [tests/transport_header_collation_369.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/transport_header_collation_369.rs)
- [tests/vectors/transport_header_collation_369.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/transport_header_collation_369.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:264-286](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L264)
- [go-sdk@2ca481c59 auth/authpayload/http.go:324-351](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/authpayload/http.go#L324)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0104.md:105,196-210](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0104.md#L105). The protocol needs identical signature preimages; the exact collation profile is the implementation question.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

Filing route: This BRC-104 comparator clarification touches none of BRC-95, the BEEF rules or BRC-100 widths; it follows the captain's filing path.
