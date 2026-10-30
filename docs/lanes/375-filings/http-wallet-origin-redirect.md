# Validate wallet HTTP originators and refuse redirects before forwarding

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census row 53: The HTTP wallet substrates (Unreleased, bsv-rs#323) take the reference's originator…

Use the injected-client tests for an invalid/ported hostname, a base URL with path/trailing slash, and a redirect response. Go sends the originator text directly and uses the default redirect-following policy. The wire substrate also trusts the frame originator rather than binding it to configuration. Match the reference hostname/header and redirect behavior; use only injected clients or ephemeral loopback URLs.

Witness:

- [tests/wallet_http_originator_323.rs](https://github.com/Calhooon/bsv-rs/blob/49789b2712d2c4eeb3e4d2776a047dc27c9314fe/tests/wallet_http_originator_323.rs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:280-314](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts#L280)
- [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/HTTPWalletWire.ts:17-20,43-66](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/HTTPWalletWire.ts#L17)
- [go-sdk@2ca481c59 wallet/substrates/http_wallet_json.go:22-58](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_json.go#L22)
- [go-sdk@2ca481c59 wallet/substrates/http_wallet_wire.go:20-31,51-83](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_wire.go#L20)

BRC reading: [BRCs@5119a9b51 wallet/0100.md:280-309](https://github.com/bsv-blockchain/BRCs/blob/5119a9b5148e9ec90eb4865b16f9f732a29703df/wallet/0100.md#L280). The exact hostname and redirect profile is an SDK transport rule.

Evidence status: source-read at the pins in this lane; the linked Rust tests/recorded fixtures are the reproducible witness, not a claim that Go or TypeScript was rerun here. Any new upstream regression test should construct its keys using a deterministic fixture helper; this draft contains no private-key literal.
