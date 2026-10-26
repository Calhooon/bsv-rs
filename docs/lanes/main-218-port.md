# Lane: main-218-port. Port #218 (MockChainTracker's synthetic mining tip) from beta onto main for 0.8.4

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), working in your own worktree cut from `origin/main` (0.8.3's line, tip f063f7a). Read `CLAUDE.md`, `RELEASING.md` ("The direction rule"), `docs/RATCHETS.md`, `src/transaction/CLAUDE.md`, `tests/CLAUDE.md` before touching anything. You never push, never tag, never open a PR: you commit on your branch and end with the REPORT below. Every command you run is foreground, under ten minutes (split a long test run into `--test` halves; never background a gate and end your turn).

## What lands

Beta landed #218 in two commits, which main (the stable line) takes for 0.8.4 under its quick-fix class rule, a break in a live dependent (the toolbox's internalize door; RELEASING.md "The direction rule"), on the toolbox's ask (issue #218); no keeper ruling exists on #218, the nearest reading is the stack's 10-24 one on the toolbox's Unverifiable verdict:

- `893052c` mock chain tracker: a synthetic mainnet mining tip at its height, with_mining_tip to set another or none (#218)
- `42b4c16` the review's folds: the mock's mainnet tip is pre-Genesis below 620,537, stated in the changelog and the rustdoc and pinned on both paths (#218)

Read both on beta before anything else (`git show 893052c`, `git show 42b4c16`, and `gh pr view 219 --repo Calhooon/bsv-rs` with its review thread). Then `git cherry-pick -x 893052c` and `git cherry-pick -x 42b4c16` onto your branch. Each conflicts: beta's `src/transaction/beef_stream.rs`, `src/transaction/chain_tracker.rs` and `CHANGELOG.md` moved past main's (DuplicateOffset #86/#167, #138 and the rest of 0.9.0 are beta-only and must NOT come to main). Resolve by hand to main's tree: the same behavior #218 gives beta, nothing of 0.9.0. Keep each commit's message and its `(cherry picked from commit <sha>)` line exactly (main's `beta-born` check reads it; `git commit --amend` keeps the message when you resolve). The changelog entry goes under main's `## [Unreleased]` heading as a `### Added` (or the heading beta used) with the same words, in main's shape; no 0.9.0 heading, no version bump (the release commit is a separate PR, the owner's).

## The tests

Rule 2: the tests #218 added (`tests/beef_stream.rs`, the mock tip tests including `the_mock_tracker_below_genesis_is_a_pre_genesis_tip`) must be RED on main's tree before the port and green after. Show it: a scratch copy of main's tree with the test file alone added fails to compile or fails; your branch passes. Then on your branch, foreground, each under ten minutes: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --features "full,http" --test beef_stream`, `cargo test --lib transaction::chain_tracker`, `cargo test --doc --features full`, `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (set `CC_wasm32_unknown_unknown` per the repo notes if ring needs it), and `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/main` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/main-218-port` (a fresh dir; never the shared one; never re-record a baseline). `cargo semver-checks` is run by CI; a new `pub fn with_mining_tip` and a new `pub const` are additive and patch-safe, say so; if any public shape of main changes otherwise, STOP and report it.

## Rules

- Never read `~/bsv/bsv-low/` or `~/vault/`.
- No em dash anywhere; never the word "first" as an ordinal in prose; never "conformant" without a run.
- Commit messages: the subject names the issue `(#218)`; the body says what and why in the repo's voice; end with the Co-Authored-By line the session gives you. The pick's `-x` line stays.
- If a conflict's resolution would need a 0.9.0 change to come along (a type, a Reason variant, a renamed field), STOP: do not invent a main-only shape; report which and why.

## REPORT (the last thing you print)

`REPORT` then: the branch name and tip sha; each commit's sha, subject and its cherry-pick line; the RED proof (the command and its failing line on main's tree) and the green run (every command above with its result line); the conflicts and how each was resolved in one line each; any public API added (name and signature); anything you could not do and why.
