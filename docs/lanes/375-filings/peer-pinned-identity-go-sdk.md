keeper's word first

# Peer accepts an initialResponse signed by another identity than the one the handshake was started with

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`Peer` verifies an initial response and a general message on both `start` paths" (#353; "Go does not compare an initial response's identity with the pinned one"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `peer-pinned-identity.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk user who calls `ToPeer` or `GetAuthenticatedSession` for identity A gets a session authenticated as identity B when B answers the initialRequest with a valid initialResponse of its own: the session is keyed by the nonce, and the identity it was opened for is overwritten without a comparison. Every later message on that session is then sent to, and accepted from, a peer the caller never asked for.

```go
// initiateHandshake (auth/peer.go:341-346): the session is pinned to the caller's key
session := &PeerSession{
	IsAuthenticated: false,
	SessionNonce:    sessionNonce,
	PeerIdentityKey: peerIdentityKey,
	...
}
// handleInitialResponse (auth/peer.go:679-680): replaced by whatever the answer names
session.PeerNonce = message.InitialNonce
session.PeerIdentityKey = message.IdentityKey
```

The signature check above it (`:655-672`) verifies the answer against `message.IdentityKey`, the key the answer itself names, so B's own signature passes. The reference refuses the answer before it verifies the signature:

```ts
if (
  typeof peerSession.peerIdentityKey === 'string' &&
  peerSession.peerIdentityKey !== message.identityKey
) {
  throw new Error('initialResponse identity does not match the requested peer identity.')
}
```

Steps to reproduce (the reference run by the #353 recorder under Node 22.18.0; go-sdk read from the code at 2ca481c, not run): keys 41 (client), 42 (server A, `02fe8d1e...`), 43 (B, `03d528ec...`), as in the linked vector.

1. The client starts a handshake pinned to A.
2. B answers with an initialResponse carrying `identityKey = 03d528ec...`, the client's session nonce as `yourNonce`, and B's own valid signature.
3. The reference answers `initialResponse identity does not match the requested peer identity.` (case `initial_response_another_identity`); go-sdk authenticates the session as B.

Expected: the answer refused when its identity is not the identity the session was opened for.

Actual: the session's identity is replaced by the answer's.

bsv-rs refuses it in the reference's words since #353.

Witness:

- [tests/auth_peer_client_verifies_353.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/auth_peer_client_verifies_353.rs) (`a_handshake_pinned_to_one_identity_refuses_another_353`)
- [tests/vectors/auth_peer_client_verifies_353.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/auth_peer_client_verifies_353.json) (case `initial_response_another_identity`, recorded from the reference)

Pinned reference reading:

- [go-sdk@2ca481c59 auth/peer.go:334-346](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L334-L346) (the pinned session) and [:624-680](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L624-L680) (the answer handled; the identity overwritten at `:680`)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/auth/Peer.ts:899-908](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L899-L908).

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:95,142](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L95) (the session holds the peer's identity key; the receiver verifies "with the alleged identityKey").

Existing related filing(s): none found (`gh issue list --repo bsv-blockchain/go-sdk --state all --search "initial response identity"` and `"PeerIdentityKey"`, 2026-11-10: no result; #233, closed, is the general-message gate before certificates, another path).

Requested maintainer action: refuse an initialResponse whose identity key differs from the session's pinned `PeerIdentityKey` before verifying its signature, as the reference does.

Evidence status: the reference's verdict is the recorded vector (Node 22.18.0); go-sdk source-read at 2ca481c, not run. This draft contains no private-key literal (the vector's keys are the scalars 41 to 43, named, not written).
