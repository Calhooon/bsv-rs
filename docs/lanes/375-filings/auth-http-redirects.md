# Refuse redirects by default for authenticated HTTP requests

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 68: SimplifiedFetchTransport takes a caller's reqwest::Client (with_client, the reference's fetchClient, ts-stack@edf6e03…

Exercise both handshake and general-message paths using an injected 307 response and an ephemeral second endpoint. Go constructs http.Client without CheckRedirect and follows the redirect. The reference sets redirect:error per request. Set a rejecting default and document the contract for caller-supplied clients without contacting public/default endpoints.

Witness:

- [tests/transport_client_hook_320.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/transport_client_hook_320.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:64-67,128,212](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L64)
- [go-sdk@2ca481c59 auth/transports/simplified_http_transport.go:31-44,111,175](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/transports/simplified_http_transport.go#L31)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:133-137](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L133). The per-request redirect refusal is the reference transport policy, not a numeric rule in this BRC.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
