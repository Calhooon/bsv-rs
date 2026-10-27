# #307: publicly_reveal_attributes verifies the master certificate as the reference does

Branch `lane/fix-307-reveal-verifies` from beta's tip, after #299 has landed (`Certificate::verify` answers `false` for every failure; read its changelog entry). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #307, from the #299 cold review)

The reference's `publiclyRevealAttributes` verifies the master certificate's signature before it builds the PushDrop and refuses with its own words when the verification fails (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:451-467`); this crate's `publicly_reveal_attributes` (`src/identity/client.rs`) publishes without the check. A certificate whose signature does not verify is published here and refused there.

## What to do

1. Read the reference's function in full and Go's equivalent (`~/bsv/go-sdk/identity/client.go`; name the lines): the check's place in the sequence (before the keyring for anyone, before the PushDrop), its words, and what else the reference checks there that this crate does not (the certificate's `fields` non-empty? the revealed keys a subset? say each and conform or state). Conform at the same site in the same words, in the error class the identity client's other refusals use.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): an unsigned master certificate refused before any wallet call (a mock wallet that counts its calls), a wrongly signed one refused, a signed one published as before; the reference's verdicts on the same recorded by a Node script at `edf6e03` (bun build, Node 22) into a vector and compared; the #105 and #261 identity witnesses unchanged.
3. The changelog entry under `[Unreleased]` with the parity note (Go's reading); the rows in `src/identity/CLAUDE.md` and `tests/CLAUDE.md`; the ratchet (`client.rs` is already over 800 and recorded; it may not grow past its recorded count without a real move).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `auth_certificate_*`, `arch_*` (not the `arch_support` module); `--lib identity auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's and Go's sites and words, RED counts then green, the gate's results, anything unverified.
