# #310: the reveal path's remaining reference checks

Branch `lane/fix-310-reveal-rest` from beta's tip, after #307 has landed (`publicly_reveal_attributes` verifies the master certificate before any wallet call; read its changelog entry and `tests/identity_reveal_verifies_307.rs`, whose counting wallet and recorder you extend). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #310, from the #307 lane)

Three readings of the reference's `publiclyRevealAttributes` (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:420-520`) this crate's `publicly_reveal_attributes` (`src/identity/client.rs`) does not follow:

1. each keyring value checked as base64 of 1 to 2048 bytes and trimmed (`:492-499`); this crate publishes the wallet's values as given;
2. the PushDrop locking script signed (`createSignature` with `forSelf: true`; name the protocol and key ID the reference passes); this crate's PushDrop is unsigned and asks for its key with `for_self: false`;
3. `failed to create action!` thrown when `createAction` returns no transaction; this crate returns `Ok(Failure CREATE_ACTION_FAILED)`.

## What to do

1. Read the reference's function in full and Go's (`go-sdk@2ca481c` `identity/client.go:73-140`; name the lines) and conform at the same sites in the same words. For (2), the PushDrop's signature is the reference's exactly: the same protocol, key ID, counterparty and `for_self`, so the reference's reader (the overlay's identity topic manager at `ts-stack`, `packages/overlay-services/...`; name it) accepts this crate's reveal; record the locking script the reference builds for a fixed certificate and keyring and compare byte for byte (the signature's randomness aside: compare the script with the signature's slot masked, and verify this crate's signature with the reference's reader). For (3), the public result shape changes (a thrown failure where a returned failure was): record it on #310 under ruling (c) with the one-line migration and the downstream callers grepped (`~/bsv/bsv-wallet-toolbox-rs`, `~/bsv/bsv-wallet-cli`, `~/bsv/rust-message-box`, `~/bsv/bsv-overlay-cloudflare`); if the reference's own result type carries failures as values anywhere else in this path, say so and keep the shape that matches it.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): a keyring value that is not base64, one over 2048 bytes, one with surrounding whitespace (trimmed as the reference trims), each refused or normalized as the reference does; the PushDrop signed and verifying under the reference's reader; a `createAction` with no transaction refused in the reference's words; the reference's verdicts recorded by the script at `edf6e03` (bun build, Node 22) into the #307 vector or a new one; the #105, #261 and #307 identity witnesses unchanged.
3. The changelog entry under `[Unreleased]` (the #307 parity note's three items closed), the rows in `src/identity/CLAUDE.md` and `tests/CLAUDE.md`, the ratchet (`client.rs` recorded over 800; a real move if it must grow past its recorded count).

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `auth_certificate_*`, `arch_*` (not the `arch_support` module); `--lib identity auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's and Go's sites and words, the public change recorded, RED counts then green, the gate's results, anything unverified.
