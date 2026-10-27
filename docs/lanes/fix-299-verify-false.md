# #299: Certificate::verify answers false, never an error, as the reference's verify does

Branch `lane/fix-299-verify-false` from beta's tip, after #297 has landed (both touch `Certificate::verify`; read #275's and #297's changelog entries). Read `CLAUDE.md`, `src/auth/CLAUDE.md`, `src/auth/certificates/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #299, from the #275 fold's cold review)

The reference's `verify` catches every failure under it and answers `false` (`ts-stack@edf6e03` `packages/sdk/src/auth/certificates/Certificate.ts:435-439`: "Preserve the historical boolean verification contract. Malformed or absent signatures are invalid credentials, not exceptional control flow."). This crate's `Certificate::verify` (`src/auth/certificates/certificate.rs`) answers `Err(InvalidSignature("Certificate not signed"))` for an absent signature and `Err` for a signature that is not DER or a key that does not derive; #275 made an over-bound field answer `Ok(false)`, the rest still errors. Go's `Verify` (`go-sdk@2ca481c` `auth/certificates/certificate.go:176-186`) returns errors: read it and name which cases.

## What to do

1. Read the reference's `verify` in full and every failure it can reach (an absent signature, a non-hex or non-DER signature, a key that does not derive, the bound), and Go's. Decide the shape with the reference (rule 1): `verify` answers `Ok(false)` for every failure the reference answers `false` to. Keep the `Result` type (a wallet or derivation failure that is not a verdict may still be an `Err`; say which, if any, and why the reference cannot reach it). The one-line migration for a caller that matched on `Err(InvalidSignature)` goes in the changelog; grep the downstreams (`~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/rust-message-box`, `~/bsv/bsv-overlay-cloudflare`) and name every `verify()` caller and what it does with an `Err` (the toolbox discards the bool, the #275 review noted). Record the public behaviour change on #299 under ruling (c) (the reference's own contract).
2. `VerifiableCertificate` and `MasterCertificate`'s `verify` paths and the auth validators that call `verify` (`validate_certificates`, `get_verifiable_certificates`): what they do with `Ok(false)` versus `Err` today, and what the reference's equivalents do (`validateCertificates` throws its own message on `false`: match its words where a message is produced).
3. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): an unsigned certificate, a non-DER signature, a certificate signed by another key, each `Ok(false)`; the reference's verdicts on the same recorded by a Node script at `edf6e03` (bun build, Node 22) into a vector and compared; the existing pins that expected `Err` rewritten with the finding in their names. The #249, #251, #261, #262, #268, #275 vectors unchanged.
4. The changelog entry under `[Unreleased]` with the parity note (Go's errors stated); the rows in `src/auth/certificates/CLAUDE.md` and `tests/CLAUDE.md`; the divergence list entry removed if one names this, or added for the Go side if the stack follows the reference.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `auth_*`, `identity_*`, `wire_*`, `arch_*` (not the `arch_support` module); `--lib auth identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; the ratchet.

## Report

A REPORT: base and tip, each commit, the reference's and Go's cases, the downstream callers, RED counts then green, the gate's results, anything unverified.
