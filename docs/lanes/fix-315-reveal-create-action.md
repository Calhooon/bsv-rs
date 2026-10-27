# #315: the reveal's createAction sends what the reference's call sends

Branch `lane/fix-315-reveal-create-action` from beta's tip, after #310 has landed (the reveal's token the reference's signed PushDrop; the counting wallet in `tests/support/identity_reveal_wallet.rs`; read #307's and #310's changelog entries). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #315, from the #310 lane)

This crate's `publicly_reveal_attributes` calls `createAction` with labels, a tag, `signAndProcess` and `acceptDelayedBroadcast: false`, where the reference's call (`ts-stack@edf6e03` `IdentityClient.ts:513-528`) sends none of them. Extra arguments change what the wallet does: a label and tag persist on the record; `acceptDelayedBroadcast: false` forces an immediate broadcast where the reference lets the wallet decide.

## What to do

1. Read the reference's call in full (`:513-537`) and Go's (`go-sdk@2ca481c` `identity/client.go:160-182`): every argument each sends (the description, the output's locking script, satoshis, basket, output description, the options) and what each omits. Conform to the reference's arguments exactly; where Go differs from the reference, the reference decides and Go's reading goes in the parity note. If an argument this crate sent has no counterpart in the reference and dropping it changes a documented behaviour of the toolbox's or the CLI's wallet (grep `~/bsv/bsv-wallet-toolbox-rs` and `~/bsv/bsv-wallet-cli` for the label, the tag and `acceptDelayedBroadcast` on the reveal's path), say what changes for them in the changelog's migration line.
2. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): the counting wallet records the `createAction` arguments it receives; the test pins them to the reference's (recorded by a Node script at `edf6e03` from a wallet that records its `createAction` call, into a vector, compared member by member); the #307 and #310 witnesses unchanged.
3. The changelog entry under `[Unreleased]` with the parity note; the rows in `src/identity/CLAUDE.md` and `tests/CLAUDE.md`; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `arch_*` (not the `arch_support` module); `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's and Go's arguments side by side, the downstream readings, RED counts then green, the gate's results, anything unverified.
