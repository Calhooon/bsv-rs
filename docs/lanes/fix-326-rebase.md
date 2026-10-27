# #326 rebase: `lane/fix-326-signaction-reference-text` onto beta after #327 (PR #337) landed

Work in this worktree on the branch as it stands (four commits on f0f236e6: the code, the docs, two docs folds; reviewed MERGE on Fable, `cca runs --show review-326`). The sequencer's in-place rebase stopped on a code conflict in `tests/support/identity_reveal_wallet.rs` (both #326 and #327, landed at e0f1c447, extended the recording wallet) and aborted; the worktree is clean at df154073. Rebase onto `origin/beta` (e0f1c447 or later), resolve every conflict keeping both branches' extensions (the recording wallet of #318 extended by #326 for the contacts manager and the kvstores, and by #327 for the revocation's checks: every method, field and helper of both, no assertion weakened), the CHANGELOG with #326's entry above #327's under `[Unreleased]` (keep both sides, no heading split, no line lost: diff the result against `origin/beta`'s CHANGELOG and show only #326's own sections added), then re-gate. Read `CLAUDE.md`, `src/identity/CLAUDE.md`, `src/kvstore/CLAUDE.md`, `tests/CLAUDE.md`, both changelog entries. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `identity_*`, `kvstore_*`, `contacts_*`, `wire_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib identity`; `--lib kvstore`; `--lib wallet`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev <origin/beta's sha>`; the ratchet against `origin/beta`.

## Report

A REPORT: the base sha rebased onto, the tip, each conflict and the text taken, the diff of the rebased tip against the reviewed df154073 (the conflict resolutions only), the gate's results, anything unverified.
