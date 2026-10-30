# Bound authenticated HTTP responses and match the returned request ID

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 76: SimplifiedFetchTransport follows the newer reference's six response bounds and mappings…

Go reads bodies and signed headers without the six TypeScript reference caps, does not bind the returned request ID and rejects certificateRequest as nongeneral. Apply the reference's certificate-header, signature, body, request-ID and signed-header checks before accepting a response, and support the authenticated certificateRequest response type. The TypeScript producer/intake disagreement has its own draft; it is not part of this Go request.

Witness:

- [tests/auth_transport_bounds_416.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/auth_transport_bounds_416.rs)
- [tests/vectors/auth_http_certificate_request_416.json](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/vectors/auth_http_certificate_request_416.json)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:234-428](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L234)
- [go-sdk@2ca481c59 auth/transports/simplified_http_transport.go:125-237](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/transports/simplified_http_transport.go#L125)
- [go-sdk@2ca481c59 auth/authpayload/http.go:165-178,226-251,381-395](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/authpayload/http.go#L165)

BRC reading: [BRCs@5119a9b51 peer-to-peer/0103.md:145-172](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/peer-to-peer/0103.md#L145). The BRC message shape and the SDK intake must agree; the concrete byte caps are reference safeguards.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
