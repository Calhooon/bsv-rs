# #354: `SimplifiedFetchTransport` refuses a general response without valid BSV authentication in the reference's words

Branch `lane/fix-354-unsigned-response-refused` from beta's tip. Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/transports/CLAUDE.md`, `tests/CLAUDE.md`, #320's and #73's changelog entries (the transport's fault classes), and issue #354. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL; every HTTP test binds its own wiremock server.

## The finding (issue #354, from the toolbox's issuance design read, verified at beta's tip and `ts-stack@edf6e03`)

`src/auth/transports/http.rs:755-802`: a general response whose auth headers are absent is read as optional ("Auth headers on response are optional") and becomes an `AuthMessage` carrying the client's own identity key as the sender (`:794-802`), so a caller sees a message it cannot tell from a signed one. The reference's `SimplifiedFetchTransport.ts:220-232` (`#validateResponseAuthentication`) refuses a response missing any of `x-bsv-auth-version`, `x-bsv-auth-identity-key`, `x-bsv-auth-signature`, with `#createUnauthenticatedResponseError`'s text (`Received HTTP <status> from <url> without valid BSV authentication (missing headers: ...)`: read the function and quote its exact text and which headers it lists), before the body becomes a message.

## What to do

1. The transport refuses in the reference's words, naming the missing headers in the reference's order, before building a message; the class the crate's fault rules give it (#73's and #320's: the named host answered, so `AuthError`, `transport_fault()` `None`; say so in the doc); read whether the reference applies the same check to the handshake's response (`:115-140`) and conform there too if it does.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): `tests/transport_unsigned_response_354.rs` with wiremock: a 200 with a body and no auth headers refused in those words; a 200 with two of the three headers refused naming the missing one; a response with the three headers read as before; `transport_fault_auth` and `auth_integration_tests` unchanged; the reference's text recorded by a Node script at `edf6e03` driving `SimplifiedFetchTransport` against a local server if at hand (the form of the #280 recorder), else say so.
3. The changelog entry under `[Unreleased]` with the migration line (a caller that read unsigned answers now gets a refusal; name any downstream that relied on it: `bsv-wallet-toolbox-rs`, `bsv-wallet-cli`, `bsv-overlay-cloudflare`, `rust-message-box` grepped) and the parity note (Go's `SimplifiedHTTPTransport` at `2ca481c`: what it does with an unsigned answer, the lines); the rows in `src/auth/CLAUDE.md`, `src/auth/transports/CLAUDE.md`, `tests/CLAUDE.md`; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transport_*`, `auth_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib auth::transports`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <base sha>`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's text beside this crate's, the class, the handshake path's reading, RED counts then green, the downstream readings, the gate's results, anything unverified.
