# #383 fold: the order pin (the count refused before the value is read), the entry's count of inputs, the brief filed (`lane/fix-383-shift-count` at e07d65e6 on 1791d2f8; PR #395)

Work in this worktree on the branch as it stands (two commits). The cold review (Opus, `review-383`; its REPORT in `cca runs --show review-383` on this host and on PR #395) is FIX on one point: "the claim 'refused before the value is read' is unpinned: with the check moved after the read, all 20 pins stay green. Fix: add the 67,108,863-byte value test from `/Volumes/Lanes/out/bsv-rs/review-383/zz_order_383.rs` to `tests/script_shift_count_int_max_383.rs`." The rest holds (the reference's words and order under Node 22, the node's v1.2.2 sites, the five moved pins right, the 383 file red 4 of 6 on the base, the eight inputs clean, the replay and a ten-minute fuzz clean, the gate green). Notes to take: `CHANGELOG.md:165`'s heading says five inputs where the body says eight; `splice.rs:327`'s element bound is unreachable in the default mode and unpinned (say so in a comment or the entry, or pin it under a word if it is reachable there); the brief goes on the branch (`docs/lanes/fix-383-shift-crashes-int-max.md`, the captain's copy is at the path this brief came from). The fuzz target's default-mode variant is the captain's follow-up issue, not yours. Do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. A MetaNet Client listens on 3301, 3321 and 2121 on this host: no test or probe on a default URL. `CARGO_TARGET_DIR=~/bsv/targets/bsv-rs-lanes/fix-383` (warm; nothing else uses it now).

## What to do

1. The order test from the reviewer's file into `tests/script_shift_count_int_max_383.rs` (a shift whose count is above INT_MAX and whose value is 67,108,863 bytes, unreadable in the default mode: the count's refusal must come first, with its words), RED on a scratch copy of the tip with the check moved after the read (the mutation the reviewer describes; your own copy, its own target dir), green on the tip. One commit.
2. The entry's heading count (eight inputs); the `splice.rs:327` bound's reachability said where the reviewer looked; the brief filed. A docs commit.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `script_*`, `conformance_*` (with `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance`), `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib script`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1791d2f8`; `tools/ratchet/run --check --against origin/beta` (beta is at 5f8fc526 now; rebase first if it asks: the CHANGELOG conflict keeps this entry above the landed ones).

## Report

A REPORT: the tip, the commits, the order test and its mutation RED, the notes taken, the gate's results, anything unverified.
