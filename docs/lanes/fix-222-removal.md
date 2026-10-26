# Lane: fix-222-removal. The three deprecated processor accessors are removed in 0.9.0 (#222)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 7, 9), `src/wallet/wire/CLAUDE.md`, `docs/DEPENDENTS.md` and issue #222 with its comments (the owner's word of 2026-10-26: removal in 0.9.0, the grep zero) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The work

1. Remove `WalletWireProcessor::with_config`, `network()` and `version()` (`src/wallet/wire/processor.rs`, marked `#[deprecated]` since #222) and the fields only they used; every in-tree caller moves to `new` and to the wallet's own `get_network`/`get_version` (the two roundtrip tests under `#[allow(deprecated)]` among them: read them and give them the wallet's answers). No other public item moves (`git diff origin/beta..HEAD -- src | grep -E "^[-+]\s*pub "` shows only the three removals).
2. Rule 2's form here: the tests that used the accessors now assert the same frames through the wallet's answers; a test that the removed names are gone is not needed (the compiler is the proof); RED is by construction.
3. Docs: the changelog's `### Removed` line with the migration (`WalletWireProcessor::new` in place of `with_config`; the wallet's `get_network`/`get_version` in place of the accessors); `src/wallet/wire/CLAUDE.md`'s row; `CLAUDE.md`'s divergence list and `README.md` lose any mention.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every wire test file: `for f in $(ls tests | grep -E '^(wire_|wallet_wire|wallet_tests|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; `cargo build --examples --all-features`; `cargo test --test readme_examples --all-features`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-222-removal` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#222)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the public lines removed (the grep); the callers moved; the green run (every gate command with its result line); anything you could not do and why.
