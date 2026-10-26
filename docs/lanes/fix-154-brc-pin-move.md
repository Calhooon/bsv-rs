# Lane: fix-154-brc-pin-move. The BRCs pin of record moves from `ed1b015` to `5119a9b` (#154)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (version 0.9.0). Read `CLAUDE.md`, `docs/FIXTURES.md`, `docs/lanes/README.md` (rule 4 and rule 11), `tests/CLAUDE.md`, `tests/support/fixtures/mod.rs` and issue #154 (`gh issue view 154 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (split long runs; never background a gate and end your turn).

## The word

The keeper's of 2026-10-24 17:0xZ on the owner's of 15:4xZ (bsv-stack-lean DECISIONS 15.3): the line's pin of `bsv-blockchain/BRCs` moves from `ed1b015` (2026-10-05) to `5119a9b` (2026-10-19); this crate's citations move together in the next prerelease, 0.9.0-beta.1, which this lane precedes. The BRCs clone is `~/bsv/brcs`; `git -C ~/bsv/brcs cat-file -t 5119a9b` must say `commit` (fetch if it does not; never a different pin).

## The work (the issue's four points, in this order, one commit each)

1. **The fixtures.** `BRC_PIN` in `tests/support/fixtures/mod.rs` to `5119a9b`'s full sha; every fixture under `tests/fixtures/` whose recorded commit line cites the old pin re-recorded by `docs/FIXTURES.md`'s procedure (`BSV_FIXTURES_RECORD=1 cargo test --features "full,http" --test fixtures_replay`, then the replay). The proof: `git diff --stat` shows one changed line per fixture file and `git diff` shows only the pin line moving; a byte under test that moves is a finding: STOP and report it, re-record nothing by hand.
2. **The citations.** Every line range this crate cites at `ed1b015` (`git grep -n ed1b015` over `src/`, `tests/`, `docs/FIXTURES.md`, `docs/lanes/README.md`, `README.md`; `CHANGELOG.md`, `HANDOFF.md` and the filed briefs under `docs/lanes/*.md` other than `README.md` are historical records and stay as written) is re-read at `5119a9b` (`git -C ~/bsv/brcs show 5119a9b:wallet/0100.md`, and the other BRC files cited) and carries the new number where the file's edits above it shifted the line (the `5119a9b` twins the #122 review listed: `:1750, :1819, :1834-1835, :1861, :1950, :2294, :2378, :2471` against `ed1b015`'s `:1741, :1810, :1825-1826, :1852, :1941, :2271, :2355, :2448`; verify each yourself, do not copy). A range whose words differ at the new pin is a finding: say so in the REPORT and leave the behavior alone. `docs/lanes/README.md` rule 4 drops its `5119a9b` clause and names the new pin and its date. No `ed1b015` remains outside the historical files when you are done (`git grep -n ed1b015 -- . ':!CHANGELOG.md' ':!HANDOFF.md' ':!docs/lanes/*.md'` empty, `docs/lanes/README.md` checked by hand).
3. **The three wire-shape differences** at `5119a9b`, already on the line by the owner's word, change nothing here; the changelog entry lists each with its issue: `listOutputs`' `totalOutputs` as a decimal string for a BRC-112 balance query and `spendable` under BRC-207 (#105), `internalizeAction`'s 1,000-byte `customInstructions` bound (#117).
4. **The changelog.** Under `## [Unreleased]`, a `### Changed` line: the pin move, the date, that no fixture byte moved, the three items of point 3.

Public shape: nothing moves. If a renumbered citation reveals the words changed under a behavior this crate pins, STOP and report (the reference decides; a divergence is the owner's word).

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --test fixtures_replay --test wire_u32_field_bounds_tests --test wallet_wire_cross_sdk_tests --test beef_stream`; `cargo test --doc --features full`; the arch tests (`cargo test --features full --test 'arch_*'` if the glob is not accepted, each `--test arch_<name>` by name from `tests/`); `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-154-brc-pin-move` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#154)`; bodies say what and why in the repo's voice; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the fixture count re-recorded and the proof that only the pin line moved (the `git diff --stat` tail and a sample `git diff` hunk); every citation renumbered as `file:line old -> new` (one per line); any range whose words differ at the new pin; the green run (every gate command with its result line); anything you could not do and why.
