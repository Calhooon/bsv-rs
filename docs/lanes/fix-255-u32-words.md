# Lane: fix-255-u32-words. The nine u32 fields refuse above `u32::MAX` in the reference's words (#255)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (#190 is on the tip). Read `CLAUDE.md` (rules 1, 2, 3), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md`, issue #122 and issue #255 with its comments (`gh issue view 255 --repo Calhooon/bsv-rs --comments`: the keeper's reading) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The reading (the keeper's, 2026-10-26: the reference's words, one rule for every refusal)

The nine u32 fields #122 bounded (`tests/wire_u32_field_bounds_tests.rs` names each: a total, a count, an index, ... read them) are refused above `u32::MAX` with #122's words (`invalid <name>: expected at most 4294967295, got N`). The reference at `ts-stack@edf6e03` reads each with `readVarIntNumStrict` then `#requireInteger(value, '<call> <field>', 0, 0xffffffff)` (`~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1501-1506`, `:1676-1681` for the two certificate totals; find the other seven sites and cite each) and the words at `:2020-2021` are `Invalid <fieldName>: expected an integer from <minimum> to <maximum>, received <value>`. Read every site yourself; the field name string is the reference's per site (`'listCertificates totalCertificates'`, ...), exact.

## The work

1. Each of the nine refusals carries the reference's words with the reference's field name for that site, through one helper (the `#requireInteger` form may already exist from #216/#236: reuse it, never a copy). The bound and the order of checks do not move.
2. Rule 2: the nine tests in `tests/wire_u32_field_bounds_tests.rs` pin the new words (RED by construction on the old words: show one on a scratch copy); every recording that carries one of these refusals is re-recorded in its own commit with the diff explained (`docs/FIXTURES.md`; `BSV_FIXTURES_RECORD=1 cargo test --features "full,http" --test fixtures_replay`); no vector edited; the allowlists move only if a vector now passes or fails (say which).
3. Docs: the changelog entry (the words moved to the reference's, the citations, "no behavior beyond the words"); `src/wallet/wire/CLAUDE.md`'s rows; `CLAUDE.md`'s divergence list loses any line that recorded #122's wording as a divergence (if one exists).

Public shape: nothing moves.

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every wire test file: `for f in $(ls tests | grep -E '^(wire_|wallet_wire|wallet_tests|fixtures_replay)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-255-u32-words` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#255)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the nine sites with the reference's line and field name each; the RED proof and the green run (every gate command with its result line, every wire test file named with its count); recordings changed and why; anything you could not do and why.
