keeper's word first

# SimplifiedFetchTransport maps a certificateRequest response without initialNonce, which the same SDK's Peer intake then refuses, so a server's HTTP certificate request never reaches its handler

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`SimplifiedFetchTransport` follows the newer reference's six response bounds and mappings" (#416; "The newer reference's HTTP certificateRequest fails its full intake's required initialNonce"; "Theirs: ts-stack, filing pending"). Rewritten from the short batch-1 form of this file. Drafted by the filings-older-1110 lane on 2026-11-10.

A server behind BRC-104 that answers a general request with `x-bsv-auth-message-type: certificateRequest` (asking the client for certificates before it serves) is mapped by `SimplifiedFetchTransport` into an `AuthMessage` with `messageType: 'certificateRequest'` and no `initialNonce`; the same SDK's `Peer` intake requires `initialNonce` on every certificateRequest and refuses it before the certificate handler runs. So with `@bsv/sdk` at edf6e03 an HTTP certificate request is dropped where the older `ts-sdk@9e3ede6b` delivered it.

```ts
// SimplifiedFetchTransport.ts:340-352, the mapping
const message: AuthMessage = {
  version: response.headers.get('x-bsv-auth-version'),
  messageType:
    response.headers.get('x-bsv-auth-message-type') === 'certificateRequest'
      ? 'certificateRequest'
      : 'general',
  identityKey: response.headers.get('x-bsv-auth-identity-key'),
  nonce: response.headers.get('x-bsv-auth-nonce') ?? undefined,
  yourNonce: response.headers.get('x-bsv-auth-your-nonce') ?? undefined,
  requestedCertificates: this.#parseRequestedCertificates(url, response),
  ...
}
// AuthMessageValidation.ts:363-365, the intake
case 'certificateRequest':
  assertCanonicalBase64(message.nonce, 'certificateRequest.nonce', 32)
  assertCanonicalBase64(message.initialNonce, 'certificateRequest.initialNonce', 48)
```

Steps to reproduce (ts-stack at edf6e03 and ts-sdk at 9e3ede6b, each bundled and run under Node 22.18.0 by the linked recorder): a response with `x-bsv-auth-message-type: certificateRequest`, the signature over the `x-bsv-certificates` header's requested set `{"types":{"BwcH…Bwc=":["name"]},"certifiers":["03d528ec…c3ffc9"]}`, handed to a client `Peer` holding the session.

1. edf6e03: the intake refuses `certificateRequest.initialNonce must be canonical base64.` (case `property_order`, `intake_error`); the handler is not called.
2. 9e3ede6b: `intake_error` is `null` and the handler receives the request.

Expected: the producer and the consumer agree, either the transport filling `initialNonce` from the session (or a header) for an HTTP certificateRequest, or the intake not requiring it on that path.

Actual: the transport's message is refused by the intake on every HTTP certificateRequest.

bsv-rs keeps the type and delivers the request to its handler (#416, `issue_416_certificate_request_response_keeps_its_type`); its recorder calls `processCertificateRequest` directly to record the reference's verdicts past the intake.

Witness:

- [tests/auth_transport_bounds_416.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/auth_transport_bounds_416.rs) (`issue_416_certificate_request_response_keeps_its_type`)
- [tests/vectors/auth_http_certificate_request_416.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/auth_http_certificate_request_416.json) (23 cases per reference, each with `intake_error`: the edf6e03 refusal above on every case, `null` at 9e3ede6b)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:340-356](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L340-L356) (the mapping)
- [ts-stack@edf6e03da packages/sdk/src/auth/AuthMessageValidation.ts:340-375](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/AuthMessageValidation.ts#L340-L375) (the intake's certificateRequest arm)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:145-172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L145) (the certificateRequest message) and [peer-to-peer/0104.md](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0104.md) (its HTTP mapping); the BRC's message and the SDK's intake should name the same members on this path.

Existing related filing(s): none found (`--search "certificateRequest initialNonce"`, `"SimplifiedFetchTransport certificateRequest"`, 2026-11-10). The #426 preimage difference is closed and not asked here.

Requested maintainer action: make the HTTP transport's certificateRequest mapping carry what the Peer intake requires (or relax the intake for that path), and add a regression where a server's certificateRequest response reaches `processCertificateRequest`.

Evidence status: both references were run by the linked recorder under Node 22.18.0 and their verdicts are the recorded vector; the lines read at edf6e03. This draft contains no private-key literal.
