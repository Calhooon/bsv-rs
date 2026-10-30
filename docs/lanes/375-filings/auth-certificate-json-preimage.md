keeper's word first

# Specify certificate-message JSON signature preimages across SDKs

Repository: bsv-blockchain/BRCs

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 58: BRC-103's signed certificate texts (Unreleased, bsv-rs#280): a certificateRequest is signed…

Please specify whether a certificateResponse authenticates the transmitted certificates text or a reserialization, and if reserialized, define its ordering and escaping. A compact certificate with unsorted field names or reordered class members is signed over different bytes by TypeScript JSON.stringify, Go json.Marshal and the Rust received-text path. The same ambiguity for certificateRequest was resolved locally by #426 following TypeScript; it remains important to specify the cross-language contract. This asks for a BRC clarification, not an assertion that the current BRC mandates the Rust choice.

Witness:

- [tests/auth_signed_text_280.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_signed_text_280.rs)
- [tests/vectors/auth_signed_text_280.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_signed_text_280.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/Peer.ts:341-357,453,1068,1140,1203](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L341)
- [go-sdk@2ca481c59 auth/peer.go:829,898,1109,1189](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L829)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:133-137,172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L133).

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
