keeper's word first

# The HTTP wallet substrates send the originator unnormalized and follow redirects, so a wallet sees another originator than the TypeScript client's and a call can be replayed to another host

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "The HTTP wallet substrates (Unreleased, bsv-rs#323)" ("go-sdk@2ca481c validates nothing, sends the originator raw and follows redirects"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `http-wallet-origin-redirect.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk app talking to a local wallet over `HTTPWalletJSON` with originator `example.com` sends `Originator: example.com` and no `Origin`, where the TypeScript client sends `Origin` and `Originator` both as the normalized origin `http://example.com`, so a wallet that keys its permission grants by originator sees two apps where there is one. Both go-sdk substrates use Go's default `http.Client`, which follows a redirect from the wallet's port to any other host with the request body (the action's arguments) attached.

```go
if httpClient == nil {
	httpClient = http.DefaultClient
}
...
if h.originator != "" {
	req.Header.Set("Originator", h.originator)
}
```

The reference validates the originator at construction (`validateOriginator`), refuses to send without one outside a browser, writes `Origin` and `Originator` as `toOriginHeader(originator, 'http')`, normalizes the base URL, and passes `redirect: 'error'` (`HTTPWalletJSON.ts:280-316`); its wire substrate refuses a frame whose originator is not the configured one (`HTTPWalletWire.ts:43-66`). go-sdk's wire substrate sends the frame's originator raw as `Origin` (`http_wallet_wire.go:74-83`).

Steps to reproduce (go-sdk read from the code at 2ca481c, not run; the reference's headers pinned by the Rust tests below against an injected local server):

1. `NewHTTPWalletJSON("example.com:8080", base, nil)`, then `GetVersion`: go-sdk sends `Originator: example.com:8080`; the reference sends `Origin: http://example.com` and `Originator: http://example.com` (the port dropped).
2. The wallet answers `307 Location: http://127.0.0.1:<other>/getVersion`: go-sdk re-sends the POST there; the reference's fetch throws.

Expected: the originator validated and sent in the reference's origin form on both headers, and redirects refused, on both substrates.

Actual: the raw text sent on one header, and redirects followed.

bsv-rs follows the reference on both substrates (#323).

Witness:

- [tests/wallet_http_originator_323.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/wallet_http_originator_323.rs) (`the_json_substrate_sends_both_headers_in_the_origin_form_with_the_port_dropped`, `an_originator_that_is_not_a_hostname_is_refused_at_construction_by_both_substrates`, `the_wire_refuses_a_frame_whose_originator_is_not_the_configured_one`, `a_redirect_is_answered_and_not_followed_by_either_substrate`)

Pinned reference reading:

- [go-sdk@2ca481c59 wallet/substrates/http_wallet_json.go:22-53](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_json.go#L22-L53)
- [go-sdk@2ca481c59 wallet/substrates/http_wallet_wire.go:20-30](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_wire.go#L20-L30) and [:74-86](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/wallet/substrates/http_wallet_wire.go#L74-L86)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:280-316](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts#L280-L316) and [HTTPWalletWire.ts:15-66](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/wallet/substrates/HTTPWalletWire.ts#L15-L66).

Existing related filing(s): go-sdk #399 (ours, open) normalizes the originator inside the binary wire frame, not the HTTP substrates' headers; the auth-transport-redirects draft (this lane's, unfiled) is the same redirect policy at the auth transport. Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: validate the originator and send it in the reference's origin form as `Origin` and `Originator`, and refuse redirects in both HTTP wallet substrates.

Evidence status: go-sdk source-read at 2ca481c, not run; the reference read at edf6e03; the Rust tests use injected local servers only, no default wallet port. This draft contains no private-key literal.
