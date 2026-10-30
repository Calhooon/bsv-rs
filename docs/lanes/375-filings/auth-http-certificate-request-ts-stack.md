# Reconcile HTTP certificateRequest mapping with full Peer intake

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 75: SimplifiedFetchTransport follows the newer reference's six response bounds and mappings…

The HTTP certificateRequest mapping omits initialNonce, while the same SDK's full Peer intake requires it. The linked fixture records the exact intake refusal before the certificate handler is invoked. Reconcile the producer and consumer so a mapped certificateRequest reaches its handler. The #426 whitespace/preimage difference is already closed and is not being refiled; Go response limits have their own draft.

Witness:

- [tests/auth_transport_bounds_416.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_transport_bounds_416.rs)
- [tests/vectors/auth_http_certificate_request_416.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_http_certificate_request_416.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:234-428](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L234)
- [ts-stack@edf6e03da packages/sdk/src/auth/AuthMessageValidation.ts:363-367](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/AuthMessageValidation.ts#L363)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:145-172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L145). The BRC message shape and the SDK intake must agree; the concrete byte caps are reference safeguards.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
