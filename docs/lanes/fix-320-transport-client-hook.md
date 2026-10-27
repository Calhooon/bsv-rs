# #320: SimplifiedFetchTransport takes a caller's client, as the reference takes a fetchClient, and refuses a redirect

Branch `lane/fix-320-transport-client-hook` from beta's tip. Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/transports/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #320, the toolbox's ask from its #263 lane)

`SimplifiedFetchTransport::new` (`src/auth/transports/http.rs:507-524`) builds its private `reqwest::Client` inside (the 30 s and 10 s timeouts and `pool_max_idle_per_host(0)` of the Cloudflare Containers hang, in the comment above it: keep them as the default client's), so a wrapper over `Peer<W, T: Transport>` can check the configured base URL before a send but cannot set a redirect, proxy or resolution policy on this crate's own requests, the general-message URL built from the payload's suffix at `:685-686` included. The builder sets no redirect policy, so reqwest follows up to ten hops, and a redirect can replay an authenticated request elsewhere.

## The reference (`ts-stack@edf6e03`)

`packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:62-76`: the constructor's second parameter is `fetchClient: typeof fetch = defaultFetch` (`:16-19` selects the global fetch), the reference's own signature; `AuthFetch.ts:191-207` takes an optional `fetchClient` and `:568-569` passes it to the transport it builds (this crate has no `AuthFetch`: the transport is the one site). The authentication fetch at `:121-129` and the general fetch at `:208-213` set `redirect: 'error'` unconditionally, the comment saying why (a fetch follows redirects by default and can replay them elsewhere). Go: `go-sdk@2ca481c` `auth/transports/` (name the file and lines): what its HTTP transport takes and whether it follows redirects, for the parity note.

## What to do

1. A constructor beside `new` taking the caller's `reqwest::Client` (`with_client(base_url, client)`, behind `http` as the field is), the reference's own parameter; `new` keeps building its client, now with `redirect(reqwest::redirect::Policy::none())`, so a 3xx answer is an error of the transport's fault class, not a followed hop (read how `transport_fault_auth.rs` classifies answers and name the class a redirect falls in; a redirect is a bad answer from the named host, not a transport fault, unless the reference's `redirect: 'error'` reads otherwise: say which). A caller's client is used as given; the doc says the default client's policy and that a supplied one carries its own. On wasm32 reqwest's builder has no redirect policy (`reqwest-0.12.28/src/wasm/client.rs`, the browser's fetch follows): say so in the doc and the changelog; the `http` feature's wasm build must still compile with the native-only call under `#[cfg(not(target_arch = "wasm32"))]`.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`), hermetic (rule 4, wiremock): `tests/transport_client_hook_320.rs`: a handshake answered `302` to a second wiremock server is refused and the second server sees no request, where the old client followed it (the RED); a general message the same; a client supplied through `with_client` is the one used (a `default_headers` marker the mock matches on); `transport_fault_auth` and `auth_integration_tests` unchanged.
3. The toolbox's use: its `StorageClient` wrapper (`~/bsv/bsv-wallet-toolbox-rs`, the `remote` module under `cfg(test)` or `bench-support`) will pass a client built with its #182 policy (`no_proxy`, `resolve`, `redirect`): write the migration line for it and check `~/bsv/bsv-wallet-cli` and `~/bsv/bsv-overlay-cloudflare` for every `SimplifiedFetchTransport::new` call (unchanged by this).
4. The changelog entry under `[Unreleased]` with the parity note; the rows in `src/auth/CLAUDE.md`, `src/auth/transports/CLAUDE.md` and `tests/CLAUDE.md`; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transport_*`, `auth_integration_tests`, `auth_peer_e2e_tests`; `--lib auth::transports`; the doc tests; the wasm32 build of the CLAUDE.md feature set and the same set with `http`; `cargo semver-checks --release-type minor`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's signature beside the new constructor, the redirect class and its text, the wasm32 reading, the downstream readings, RED counts then green, the gate's results, anything unverified.
