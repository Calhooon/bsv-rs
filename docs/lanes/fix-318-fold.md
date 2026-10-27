# #318 fold: the cold review's two items on `lane/fix-318-identity-wallet-calls` (at 6905ab37)

Work in this worktree on the branch as it stands (one commit on beta's 2e079d7; beta is at 5f3fa1a, docs only; do not rebase). Read `CLAUDE.md`, `tests/CLAUDE.md`, the branch's changelog entry, and the review's two findings below. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push.

## The review's findings (Fable, verdict FIX; the code is right and needs no change)

1. The changelog's #318 entry cites `src/wallet/wire/transceiver.rs:733` for the signAction reference's decode; `:733` is abortAction's decode, signAction's is `:667-668`. Fix the citation (read both sites and cite what you read).
2. `tests/vectors/identity_wallet_calls_318.json` carries 6,432 lines of one-byte-per-line arrays, duplicated across identical witnesses. The recorder (`tests/support/identity_wallet_calls_318.mjs`) writes byte fields as hex text, once, and the test (`tests/identity_wallet_calls_318.rs`) reads them as hex; identical witnesses are not repeated (a shared field, or one witness referenced). Re-record from the reference at `edf6e03` under Node v22.18.0 (the randomness #310's SHA-256 counter stream; two runs byte for byte); the verdicts and every argument compared must be unchanged by the reshaping: stop and report if any verdict or argument changes.

## What to do

One commit (or two, one per item) on top of 6905ab37. The vector's row in `tests/CLAUDE.md` says the new size. Then the gate.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `arch_*` (not the `arch_support` module); `--lib identity`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 2e079d7`; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit, the citation's two sites, the vector's size before and after, the re-record's result (two runs byte for byte, no verdict or argument changed), the gate's results, anything unverified.
