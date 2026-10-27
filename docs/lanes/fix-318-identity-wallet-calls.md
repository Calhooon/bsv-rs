# #318: the identity client's wallet calls send what the reference sends

Branch `lane/fix-318-identity-wallet-calls` from beta's tip, after #315 has landed (the reveal's createAction the reference's; the recording wallet in `tests/support/identity_reveal_wallet.rs`; read #307's, #310's and #315's changelog entries). Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `tests/CLAUDE.md`. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The finding (issue #318, from the #315 lane)

1. `revoke_certificate_revelation`'s createAction sends labels `identity` and `revocation` and `signAndProcess: false`; the reference's call (`ts-stack@edf6e03` `IdentityClient.ts:845-863`) sends neither.
2. The client passes `"identity-client"` as the originator on every wallet call when none is configured; the reference passes none unless the caller set one.

Three nuances from the #315 cold review: the revocation's `signAndProcess: false` changes the wire only, since the reference's input lacks its unlocking script (read what the wallet does with the flag on an input it must unlock itself); `get_identity_key` and the contacts manager pass `""` as the originator rather than `"identity-client"`, so the default differs call by call (conform every call: none unless configured); the revocation's `signAction` leaves `returnTXIDOnly` absent where the reference sends `false` (match the reference's member, since a wallet may read the member's presence).

## What to do

1. Read the reference's revocation call in full (`:830-870`) and Go's (`go-sdk@2ca481c` `identity/client.go`; name the lines): every argument each sends and omits; conform to the reference's. Read how the reference carries an originator through `IdentityClient` (its constructor and every `wallet.*` call) and Go: when none is configured, send none; when one is configured, send it as before. Where Go differs from the reference, the reference decides and Go's reading goes in the parity note.
2. For each extra this crate sent (the two labels, `signAndProcess: false`, the default originator): what the Rust toolbox and the CLI did with it (grep `~/bsv/bsv-wallet-toolbox-rs` and `~/bsv/bsv-wallet-cli`: a label persisted; `signAndProcess: false` leaving the action unsigned for the caller; an originator keying permissions or records), and what its absence changes for them, in the changelog's migration line. If `signAndProcess: false` was load-bearing for a caller that processed the action itself, say so and keep the behaviour the reference has (its wallet signs and processes).
3. Tests, RED before green (a scratch copy without the fix, its own `CARGO_TARGET_DIR`): the recording wallet pins the revocation call's arguments and the originator on every call (none by default, the configured one when set) against the reference's recorded by a Node script at `edf6e03` into a vector; the #307, #310 and #315 witnesses unchanged.
4. The changelog entry under `[Unreleased]` with the parity note (#315's note's two items closed); the rows in `src/identity/CLAUDE.md` and `tests/CLAUDE.md`; the divergence line if a difference remains; the ratchet.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `arch_*` (not the `arch_support` module); `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor`; the ratchet against `origin/beta`.

## Report

A REPORT: base and tip, each commit, the reference's and Go's arguments side by side, the originator's handling, the downstream readings, RED counts then green, the gate's results, anything unverified.
