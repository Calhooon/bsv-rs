# Lane: fix-190-transceiver-frame-end. listCertificates and discovery results read to the end of the frame; the reference's page limits enforced (#190)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (#206's abortAction reading and #192's checked lengths are on the tip). Read `CLAUDE.md` (rules 1, 2, 3), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md` and issue #190 (`gh issue view 190 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The rule (the keeper's on #183: a reader refuses what the reference's reader refuses)

The reference's transceiver (`~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts` at `edf6e03`) reads a listCertificates or discovery result to the end of the frame and refuses bytes left over, and enforces the page limits on the totals (`#requireResponseLength` and the result readers' neighbours: find and cite the exact lines for both calls, and the page-limit constants and their source). This crate's transceiver (`src/wallet/wire/transceiver.rs`) reads the declared total and ignores bytes after the last entry, and takes any total. Read the reference's lines yourself, then Go, and cite them; the words of each refusal are the reference's.

## The work

1. The two readers (listCertificates' result; the discovery results, both calls) refuse bytes after the last entry (the existing `require_response_length`/`header_result` helpers of #183 if they fit: read `mod.rs`) and a total past the reference's page limit, as typed refusals with the reference's words; nothing else about a valid frame moves.
2. Rule 2: RED-before tests with hand-assembled frames (a valid result with one trailing byte; a total one past the limit; a total at the limit accepted) in `tests/wire_reader_strictness.rs`; the recordings and vectors unchanged (`git diff -- tests/fixtures tests/vectors` empty; a moved one is a finding, STOP); the every-result allowlist (13) moves only if a vector now passes or fails: say which.
3. Docs: the changelog line per refusal with the citations; `src/wallet/wire/CLAUDE.md`'s rows.

Public shape: nothing moves. If a new `Error` variant is needed, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_reader_strictness --test wire_identity_certificate_roundtrip --test wire_processor_validation --test wire_error_frames --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-190-transceiver-frame-end` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#190)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference and Go lines read, the page limits and their source; the RED proof per refusal and the green run (every gate command with its result line); recordings changed (none expected); the allowlist rows; anything you could not do and why.
