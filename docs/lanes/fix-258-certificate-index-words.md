# Lane: fix-258-certificate-index-words. The certificate reader's revocation outpoint index refusal takes the bound refusal's one form (#258)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (PR #257 for #255 may or may not have landed: read `integer_refusal` in `src/wallet/wire/mod.rs` on your base; if it is not there, STOP and report, the lane runs after #257). Read `CLAUDE.md` (rules 1, 2, 3), `src/auth/CLAUDE.md`, `tests/CLAUDE.md`, issues #122, #255 and #258 with their comments (the keeper's reading of 2026-10-26) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The reading

`src/auth/certificates/certificate.rs:422-431` (its test at `:612`) refuses a revocation outpoint index above `u32::MAX` in #122's words (`invalid ...: expected at most 4294967295, got N`). The reference's `Certificate.fromBinary` at `ts-stack@edf6e03` (`~/bsv/ts-stack/packages/sdk/src/auth/certificates/Certificate.ts`, find the line) reads that index with `readVarIntNumStrict(false)` and no `#requireInteger`, so it has no words for the bound. The keeper: one shape for every bound refusal; the form is the helper's, `Invalid <name>: expected an integer from 0 to 4294967295, received N`, with a name of this crate's (say which: `revocation outpoint index` or the like) stated as ours; the bound stands under #122 (never a cast; BRC-12's outpoint index is four bytes on the wire); the divergence list carries a line saying the reference's reader accepts the oversized index there. Read every cited line yourself and cite them.

## The work

1. The refusal goes through `integer_refusal` (or the shared helper's name on your base; if it is wire-private, lift it to a crate-private place both modules can call, no copy), with the name chosen and the bound unchanged.
2. Rule 2: the test at `:612` (and any other pinning the old words) pins the new words (RED by construction); no vector or recording moves (`git diff -- tests/vectors tests/fixtures` empty).
3. Docs: the changelog line; `CLAUDE.md`'s divergence list gains the line (the reference's reader accepts an oversized revocation outpoint index; this crate refuses it with the bound refusal's form under a name of its own); `src/auth/CLAUDE.md`'s row.

Public shape: nothing moves.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every auth test file: `for f in $(ls tests | grep -i -E '^(auth|certif|identity)' | sed 's/\.rs$//'); do cargo test --features "full,http" --test $f || exit 1; done`; every wire test file if the helper moved: `for f in $(ls tests | grep -E '^(wire_|wallet_wire|wallet_tests|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib auth --features full`; `cargo test --doc --features full`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-258-certificate-index-words` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#258)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference line read; the name chosen and the words; the RED proof and the green run (every gate command with its result line); anything you could not do and why.
