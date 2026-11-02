FILE — tenth in [the keeper's order](https://github.com/Calhooon/bsv-rs/issues/375#issuecomment-6528735229); filed as bsv-blockchain/go-sdk#402 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending.

# Preserve certificate-response property order when signing and verifying

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Filed as bsv-blockchain/go-sdk#402 on 2026-11-02 under the owner's name (cadence (b), the keeper's detached script at 00:00Z from the draft as it stood on beta); answer pending.
Tenth in the queue, after `certificate-bounds-der`. Census row 61.

Go's certificate-response preimage sorts map keys where the TypeScript
reference signs property order, so a certificate with names out of byte
order verifies between the reference and bsv-rs and fails against Go.

The witness is built by bsv-rs's own certificate writer using deterministic
test keys and IVs, then signed by its real `Peer::send_certificate_response`
at the #400 signing site. It contains four valid encrypted fields and a
verifier keyring inserted as `zeta,alpha,10,2`. The reference's signed order
is `2,10,zeta,alpha`; Go's re-marshalling produces `10,2,alpha,zeta`.
Every scalar value and outer certificate property agrees in this witness;
the nested property order changes the signed bytes.

| Response | bsv-rs | TypeScript reference | go-sdk |
|---|---|---|---|
| Out-of-byte-order fields/keyring | true | true | false (`signature is not valid`) |
| Byte-ordered `alpha,beta,gamma,zeta` control | true | true | true |

Both certificates' own signatures verify in all three SDKs. Rust additionally
accepts the complete responses through its receiving Peer; Node decrypts all
fields successfully. The foreign recorders run the response-signature path
directly, isolating it from the independent nonce-handshake conventions.
This is a signed-preimage witness, with no live transport or handshake claim.

Witness:

- [Rust test](../../../tests/auth_certificate_preimage_375.rs): reproduces
  both certificates and exercises the sending and receiving Peer, pins all
  three verdicts and rejects a changed keyring order with the same signature.
- [Vector](../../../tests/vectors/auth_certificate_preimage_375.json): both
  certificates, complete response text, signed text, signature hex and each
  verifier's observed preimage/verdict.
- [Node recorder](../../../tests/support/certificate_preimage_375.mjs) and
  [Go recorder](../../../tests/support/certificate_preimage_375/main.go), with
  [reproduction instructions](../../../tests/support/certificate_preimage_375/README.md).
  Node v22.18.0 and Go 1.27.0; two runs each are byte-identical.
  SHA-256 of the recorded vector by the README's procedure:
  `4f7ad3ea77790232ae8c47b2189c6b885defffe10245141d4fe10bfb87e03875` (the Node and
  Go runs alike; the lane's first Node run hashed an input that is not committed).

Pinned reference reading:

- [ts-stack@edf6e03 Peer.ts:1140](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L1140):
  `sendCertificateResponse` signs `JSON.stringify(certificates)`.
- [Peer.ts:1203-1213](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/Peer.ts#L1203):
  `processCertificateResponse` verifies `JSON.stringify(message.certificates)`
  with protocol `[2, 'auth message signature']` and the response/session nonces
  in its key ID. The Node recorder executes these arguments against the
  unmodified reference's `ProtoWallet.verifySignature`.

Pinned Go reading at `2ca481c5931b987a0c8f48bb341c70b7477b6b07` (v1.7.2):

- [auth/peer.go:1189](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L1189):
  `SendCertificateResponse` signs `json.Marshal(certificates)`.
- [auth/peer.go:898-926](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/peer.go#L898):
  `handleCertificateResponse` re-marshals parsed certificates before verification.
  The recorder uses the same `AuthMessage`/certificate types and passes that
  preimage through [wallet.ProtoWallet.VerifySignature:224-280](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/proto_wallet.go#L224).
- [certificate.go:34-52](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/certificates/certificate.go#L34)
  and [verifiable.go:19-28](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/certificates/verifiable.go#L19):
  the outer struct order agrees, but `fields` and `keyring` are maps whose
  keys `encoding/json` sorts. The control proves matching nested order verifies.

BRC reading: [BRC-103 at 5333fd4, peer-to-peer/0103.md:161-180](https://github.com/bsv-blockchain/BRCs/blob/5333fd449c70fd5982029876376dcf1ed9c64ffe/peer-to-peer/0103.md#L161)
requires recomputing the same message preimage and describes certificate
responses, but specifies no canonical JSON serialization or map ordering.
The interoperability claim therefore follows the reference's executed
signing/verification bytes, rather than a BRC-mandated JSON order.

Requested maintainer action: retain the reference's property order through
certificate-response parsing and serialization, including JavaScript's
integer-index property ordering, and use that representation for both
signing and verification. Add the out-of-order witness and sorted control
above as cross-SDK regressions. Do not canonicalize map keys independently
on only one side of a signature exchange.
