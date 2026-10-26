# Lane: fix-206-abort-code-8. An abort refusal is code 8; the client reads 8 as `aborted: false` (#206)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (the processor's `invoke_wallet` wrapper and error frame of #202, the validation step of #216 and the forwarded calls of #222 are on the tip). Read `CLAUDE.md` (rules 1, 2, 3), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md` and issue #206 (`gh issue view 206 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The rule (the keeper's on #197 and #202: the reference's bytes are the wire; a verdict the reference frames as an error code is an error frame here)

The reference decides: `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts:797-804` at `edf6e03` frames an abort refusal with code 8 (`abortRefused`; the code table in `WalletError.ts`); its client turns code 8 into `{ aborted: false }` rather than an error (`WalletWireTransceiver.ts:337`): the one code the reference's client acts on. Read those lines yourself, then Go (`~/bsv/go-sdk`), and cite them.

## The work

1. Read what `WalletInterface::abort_action` returns for a refusal today (`src/wallet/interface.rs`; `Ok(AbortActionResult { aborted: false })` or an error) and what `handle_abort_action` does on the processor (a refusal stub, code 1 "requires a full wallet implementation"). The processor goes through `invoke_wallet` to the wallet like the other calls (the stub gives way), and frames the wallet's `aborted: false` as code 8 with the reference's words, as the reference does for its own; a true `aborted` as the reference's success frame. The transceiver reads code 8 as `Ok(AbortActionResult { aborted: false })`, every other error frame as the error it is today.
2. Rule 2: RED-before tests with the reference's bytes (`08 <varint len> "<the reference's words>" 00`): the processor's frame for a wallet's refusal; the transceiver's reading of code 8; a success frame still `aborted: true`. The `abortAction` recording re-recorded in its own commit with the diff explained (`docs/FIXTURES.md`); the every-args and every-result allowlists move only if the stub's row gave way to a real handler: say which row and the new counts.
3. Docs: the changelog entry with the citations; `src/wallet/wire/CLAUDE.md`'s row for abortAction; the error-code table if the module documents one.

Public shape: nothing moves (the result type exists; the error frame is the processor's). If a new public type or variant is needed, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_processor_validation --test wire_error_frames --test wire_reader_strictness --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-206-abort-code-8` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#206)`; bodies say what and why; end with the Co-Authored-By line the session gives you. One commit per concern (the processor, the transceiver, the recording, the docs).

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference and Go lines read and what they say; the RED proof and the green run (every gate command with its result line); the recording's diff explained; the allowlist rows moved; anything you could not do and why.
