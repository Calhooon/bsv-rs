# Lane: fix-228-resource-limit-display. `ScriptResourceLimit` gains a `Display`; the interpreter and `SpendRefusal::Resource` print one sentence from one place (#228)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (0.9.0-beta.1 is published from `060e7e0`; the line keeps moving). Read `CLAUDE.md`, `src/script/CLAUDE.md`, `src/transaction/CLAUDE.md`, `tests/CLAUDE.md` and issue #228 (`gh issue view 228 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (split long runs; never background a gate and end your turn).

## The work (additive; no owner's word)

`ScriptResourceLimit` (`src/script/`, find its definition) has no `Display`. The interpreter builds its resource sentences in `src/script/spend/limits.rs` (`resource_error`, `work_error`), and #213's `impl Display for SpendRefusal` (`src/transaction/beef_stream.rs`, the `Resource(limit)` arm) copies those words and fills them from the limit's fields. Add `impl core::fmt::Display for ScriptResourceLimit` carrying the interpreter's sentences byte for byte as `limits.rs` builds them today (the three memory labels "Stack memory usage" / "Alt stack memory usage" / "Script element allocation" "has exceeded {limit} bytes"; "Work budget exhausted: spent {work_spent} units, budget {limit}"); then `limits.rs` and the `Resource` arm both print through it, so one place holds the words. Decide what a `Work` limit with `work_spent: None` prints (the interpreter never builds one; the #213 review noted "spent 0 units") and say why. The texts do not change: every interpreter test and #213's nine tests pass unchanged, which is the proof.

Rule 2: a test per limit kind pinning the `Display` text (`tests/` beside the interpreter's resource tests; find where `ScriptResourceLimit` is asserted today), RED before (no `Display`, `to_string()` does not compile: show the error on a scratch copy with its own target dir). The changelog's `### Added` line under `## [Unreleased]`; `src/script/CLAUDE.md`'s row.

Public shape: a trait impl on an existing public type, nothing else; if `ScriptResourceLimit`'s fields or variants would need to move, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --test beef_stream`; the script tests that name resource limits (`grep -l ScriptResourceLimit tests/*.rs`, each `--test`); `cargo test --lib script::spend --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-228-resource-limit-display` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#228)`; bodies say what and why in the repo's voice; end with the Co-Authored-By line the session gives you. Two commits: the impl with its tests and the two call sites; the docs.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the texts, one per kind; the RED proof and the green run (every gate command with its result line); the `work_spent: None` decision; anything you could not do and why.
