# Lane: fix-213-spend-refusal-display. `SpendRefusal` gains a `Display` impl (#213)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (version 0.9.0, tip at or after `25875bb`). Read `CLAUDE.md`, `src/transaction/CLAUDE.md`, `tests/CLAUDE.md` and issue #213 (`gh issue view 213 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (split long test runs into `--test` halves; never background a gate and end your turn).

## The ask (the toolbox's captain, 2026-10-25; additive, no owner's word needed)

A host wants to print the verifier's refusal as a sentence. `beef_stream::SpendRefusal` (`src/transaction/beef_stream.rs`, the enum after `live_of`; nine arms: `ParentIsTxidOnly`, `OutputNotAvailable { vout }`, `Script(String)`, `Resource(ScriptResourceLimit)`, `CreatesValue`, `InputValueOutOfRange`, `P2shOutput { vout }`, `NonFinal { lock_time }`, `PrematureCoinbase { height }`) has no `Display`. Add `impl core::fmt::Display for SpendRefusal` (and nothing else on the type: its shape, exhaustiveness and arms do not move; do not add `std::error::Error` unless the sibling types in the module carry it, and say which you followed). Place it beside `Reason`'s `Display` in `src/transaction/beef_stream/reason.rs` if `Reason` has one there, else in `beef_stream.rs` directly under the enum.

The words: `Script(reason)` prints the interpreter's sentence verbatim (the `String` as it is, no prefix); `Resource(limit)` prints the limit's own `Display` (read `ScriptResourceLimit`'s impl in `src/script/` and reuse it); every other arm one sentence naming its rule, the words taken from the arm's rustdoc and `CLAUDE.md`'s BEEF contract (never invented), with the field named in the sentence (`vout`, `lock_time`, `height`). No trailing period, as the crate's `Error` texts go (read `src/error.rs`'s `Display` to match the house style; say what it is).

## The tests (rule 2)

A test per arm pinning the exact text, in `tests/beef_stream.rs` (the file that pins the verifier's refusals; find the test that builds each refusal and add the `to_string()` assertion beside it, or one new test per arm that constructs the value directly where no path exists). RED before: the impl absent, `to_string()` does not compile; show the compile error on the pre-fix tree. The changelog's `### Added` line under `## [Unreleased]` says the text is pinned (a downstream will match on it, so it is a wire of sorts) and names the test. `src/transaction/CLAUDE.md`'s row for `SpendRefusal` names the impl.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --test beef_stream`; `cargo test --lib transaction::beef_stream`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-213-spend-refusal-display` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#213)`; bodies say what and why in the repo's voice; end with the Co-Authored-By line the session gives you. Two commits: the impl with its tests; the docs.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the nine texts, one per line; the RED proof and the green run (every gate command with its result line); where the impl lives and why; anything you could not do and why.
