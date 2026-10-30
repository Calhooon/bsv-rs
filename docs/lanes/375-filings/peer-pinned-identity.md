# Reject an initial response signed by a different identity than the pinned peer

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 24: Peer verifies an initial response and a general message on…

Initiate a session pinned to identity A, then supply an otherwise valid initial response signed by B with the correct initiator nonce. Go overwrites PeerIdentityKey at auth/peer.go:680 without comparing A. TypeScript and Rust reject it. Preserve the originally requested identity until that check succeeds.

Witness:

- [tests/auth_peer_client_verifies_353.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_peer_client_verifies_353.rs)
- [tests/vectors/auth_peer_client_verifies_353.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_peer_client_verifies_353.json)

Pinned reference reading:

- [go-sdk@2ca481c59 auth/peer.go:624-680](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L624)
- [ts-stack@edf6e03da packages/sdk/src/auth/Peer.ts:880-935](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L880)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:93-118](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L93). The selected identity must remain bound to the handshake.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.

The source row stays unchanged because part of it is stale: The missing-yourNonce sentence is superseded by #445 intake validation (AuthMessageValidation.ts:359-360,365-366,388-389). Leave the whole mixed row unchanged; the live Go pinned-identity finding has the linked draft.
