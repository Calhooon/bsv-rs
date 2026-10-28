# #385 fold: the wallet certificate writer's bound checks in map order, the migration's `indexmap` line (`lane/fix-385-ordered-maps` at 63d3e858 on 1791d2f8; PR #392)

Work in this worktree on the branch as it stands (two commits). The cold review (Opus, `review-385`; its REPORT in `cca runs --show review-385` on this host and on PR #392) is FIX on one hunk: "`src/wallet/wire/encoding.rs:1433-1448`: run the bound checks in map order and sort only for writing (the reference's `Certificate.ts:44-84`), plus a RED test and a line in `CHANGELOG.md:201`. Add to the migration: `indexmap` isn't re-exported, so a downstream needs its own `indexmap = "2"` or builds with `collect()`." The rest holds (nine fields and four signatures changed; the signer sorts with `localeCompare`, `Certificate.ts:282`; the integer-like row right; RED 8 of 8; the fixtures unchanged because their maps are already sorted; the gate green). Read `src/wallet/wire/encoding.rs:1400-1460` (the wallet certificate writer: the fields' bound checks and the sorted write), `ts-stack@edf6e03` `packages/sdk/src/auth/certificates/Certificate.ts:44-84` (the order the reference checks a field's bounds in, and where it sorts), the branch's entry and test file. Do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL. `CARGO_TARGET_DIR=~/bsv/targets/bsv-rs-lanes/fix-385` (warm; nothing else uses it now); Node 22 under nvm is on this host.

## What to do

1. `encoding.rs:1433-1448`: the bound checks walk the map in its order (the refusal names the first bad field in insertion order, as the reference's `Certificate.ts:44-84` does: read and say which check comes first there and whether the reference checks before or after sorting), the sort kept for the write alone (the signed preimage's `localeCompare` order unchanged). One commit.
2. A RED test (a scratch copy of 63d3e858 without the hunk, its own target dir): two bad field names where the sorted order and the insertion order disagree (the review's 51-against-52 shape), the refusal naming the insertion-first one; green after.
3. The entry: the line at `CHANGELOG.md:201` for the writer's order; the migration adds that `indexmap` is not re-exported (a downstream names `indexmap = "2"` in its own manifest, or builds the map with `collect()` from pairs); the rows if a count moves.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `wallet_*`, `wire_*`, `identity_*`, `auth_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib wallet`; `--lib auth`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1791d2f8`; `tools/ratchet/run --check --against origin/beta` (beta is at 3a9ab12c now; rebase if the ratchet asks; the CHANGELOG conflict keeps this entry above #384's).

## Report

A REPORT: the tip, the commit, the reference's check order beside the writer's before and after, RED then green, the gate's results, anything unverified.
