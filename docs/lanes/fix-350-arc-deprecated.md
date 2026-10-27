# #350: the ARC client surface is marked deprecated and is nowhere a default (the owner's word of 2026-10-27)

Branch `lane/fix-350-arc-deprecated` from beta's tip. Read `CLAUDE.md`, `src/transaction/CLAUDE.md`, `src/transaction/broadcasters/CLAUDE.md`, `tests/CLAUDE.md`, and issue #350 in full. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe reaches a live service: the broadcasters' tests are wiremock's.

## The word and the finding (issue #350)

The owner, 2026-10-27 12:4xZ: "arc is just deprecated, arcade is the standard"; for this crate, any ARC client surface is marked deprecated, never a default. This crate's ARC surface: `ArcBroadcaster` and `ArcConfig` (`src/transaction/broadcasters/arc.rs`) with `ArcBroadcaster::default()` on gorillapool, the broadcasters' CLAUDE.md calling it "recommended for production"; `LivePolicy`'s `DEFAULT_POLICY_URL` on ARC's policy endpoint, so `LivePolicy::new()` reads ARC by default; `to_beef_v1` documented "for ARC". The reference keeps ARC undeprecated and as its default (`ts-stack@edf6e03` `DefaultBroadcaster.ts:1-12`, `ARC.ts`, `LivePolicy.ts:10`); ARCade is a toolbox and overlay service there, not an SDK broadcaster: this crate adds no ARCade client. The deprecation is a divergence from the reference under the owner's word, recorded in CLAUDE.md's divergence list and the changelog's parity note.

## What to do

1. `#[deprecated(since = "0.9.0", note = "ARC is deprecated; ARCade is the standard (the owner's word of 2026-10-27)")]` on `ArcBroadcaster`, `ArcConfig`, their constructors and `impl Default for ArcBroadcaster` (a deprecated type's `Default` stays with it, deprecated); `LivePolicy`: `DEFAULT_POLICY_URL` deprecated, `LivePolicy::new()` deprecated in favour of `with_url` (or made to take the URL: say which reads as the reference's shape minus the ARC default, and why); the broadcasters' and transaction's CLAUDE.md no longer recommend ARC; the `to_beef_v1` sentence names the format, not ARC.
2. The crate's own uses of the deprecated items (tests, examples, the fee model, docs' code blocks) carry `#[allow(deprecated)]` with a one-line reason, or move off ARC where another broadcaster serves the same test (prefer the move where the test is about broadcasting, not about ARC's wire); `cargo clippy --all-targets --all-features -- -D warnings` green; `cargo doc` with no broken links; the README's examples unchanged unless one uses ARC (`tests/readme_examples.rs` pins them).
3. The downstreams' uses in the migration line: grep `ArcBroadcaster`, `ArcConfig`, `LivePolicy` in `~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/bsv-overlay-cloudflare`, `~/bsv/rust-message-box` at their tips; name each site and what the warning asks of it.
4. A test RED before green that pins the surface: the deprecation attributes present on the named items (a compile-time witness, `#[deny(deprecated)]` in a scratch test that fails to build on the tip and builds on the base; or the arch test's reading of the attributes, as `tests/arch_*` reads other surface rules), and `LivePolicy` built without a URL refused or deprecated as decided.
5. The changelog entry under `[Unreleased]` (the owner's word quoted, the reference's default stated, the parity note, the migration line); the divergence line in `CLAUDE.md`; the rows.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transaction_*`, `broadcaster_*`, `live_policy_*`, `transport_fault_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib transaction`; the doc tests; `cargo build --examples --all-features`; `cargo test --test readme_examples`; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <base sha>`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the items deprecated and the `LivePolicy` decision, the crate's own call sites moved or allowed, the downstream sites, RED then green, the gate's results, anything unverified.
