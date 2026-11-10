keeper's word first

# SimplifiedHTTPTransport follows redirects, so an authenticated message and its signed headers are replayed to whatever host the server names

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`SimplifiedFetchTransport` takes a caller's `reqwest::Client`" (#320; "go-sdk@2ca481c takes a caller's `*http.Client` and follows up to ten redirects"; "Theirs: go-sdk, filing pending"). Supersedes the short batch-1 draft `auth-http-redirects.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A go-sdk `AuthFetch` or `Peer` over `SimplifiedHTTPTransport` that receives a 307 or 308 from the server re-sends the handshake or the general message, body and `x-bsv-auth-*` headers included, to the redirect's target: Go's default `http.Client` follows up to ten redirects and keeps non-credential headers across hosts. The message, its signature and any certificate material reach a host the caller never configured, and an answer from that host is processed as the configured peer's.

```go
client := options.Client
if client == nil {
	client = &http.Client{}
}
```

The reference passes `redirect: 'error'` on both paths, with the reason in the code:

```ts
// Authentication messages, signatures, certificate material, and
// request bodies are scoped to the configured peer. Native fetch
// follows redirects by default and can replay them elsewhere.
redirect: 'error',
```

Steps to reproduce (go-sdk read from the code at 2ca481c, not run; the refusal pinned by the Rust tests below against an ephemeral local server): answer the handshake POST to `/.well-known/auth` with `307 Location: http://127.0.0.1:<other>/.well-known/auth`. go-sdk's client POSTs the same body and headers to the other port; the reference throws `Network error while sending authenticated request to {url}` and sends nothing further.

Expected: a redirect answer refused on the handshake and the general path when go-sdk builds the client, and the policy documented for a caller-supplied client.

Actual: followed.

bsv-rs refuses a redirect status on both paths (#320); a caller's own client keeps its own policy, as here.

Witness:

- [tests/transport_client_hook_320.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/transport_client_hook_320.rs) (`a_handshake_answered_with_a_redirect_is_refused_and_not_replayed`, `a_general_message_answered_with_a_redirect_is_refused_and_not_replayed`)

Pinned reference reading:

- [go-sdk@2ca481c59 auth/transports/simplified_http_transport.go:31-46](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/auth/transports/simplified_http_transport.go#L31-L46) (the default client, no `CheckRedirect`)

Sibling reading: [ts-stack@edf6e03da packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:124-129](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L124-L129) and [:208-214](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts#L208-L214).

Existing related filing(s): the wallet-http-originator-redirect draft (this lane's, unfiled) asks the same of the wallet HTTP substrates. No upstream issue found (`--search "redirect"`, 2026-11-10).

Requested maintainer action: give the transport's default client a `CheckRedirect` that refuses every redirect, as the reference's `redirect: 'error'` does.

Evidence status: go-sdk source-read at 2ca481c, not run; the reference's two call sites read at edf6e03; the Rust tests use injected local servers only. This draft contains no private-key literal.
