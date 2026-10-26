# Lane: fix-192-wire-residuals. Two residual leniencies of the wire readers: a repeated keyring key; `read_string`'s length cast on wasm32 (#192)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 1, 2, 5), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md` and issue #192 (`gh issue view 192 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The rule (the keeper's on #183: a reader refuses what the reference's reader refuses; rule 5: a bad count is `Err`, never a truncation)

The reference decides: `~/bsv/ts-stack/packages/sdk/src/auth/certificates/Certificate.ts:373-374` at `edf6e03` (a repeated field name refused) and the discovery reader's map reads in `WalletWireTransceiver.ts`; read them and cite them.

## The work (one commit each, then docs)

1. **A repeated keyring key.** `WireReader::read_identity_certificate` and `read_identity_certifier`'s callers in `src/wallet/wire/encoding.rs` keep a later duplicate key in the keyring and the decrypted fields; the transceiver's `parse_discovery_result` refuses one since #183 (read how, and refuse the same way with the same typed error and words). RED-before tests with the repeated key in the writer's layout (hand-assembled bytes as #184's zero-value tests do; `tests/wire_identity_certificate_roundtrip.rs` and `tests/wire_reader_strictness.rs` are the homes).
2. **`read_string`'s length cast.** `WireReader::read_string` casts the varint length `as usize`: lossless on 64-bit, on wasm32 a length at or above 2^32 truncates. Take the checked form the #184 readers use (`read_var_int_num` and `usize::try_from`, a refusal on overflow), and sweep every other `as usize` on a wire length in `src/wallet/wire/` (list them in the REPORT with what each became). A host test that the length path is the checked one (a length of 2^32 refused with the typed error on the host as it would be on wasm32; the wasm32 build of rule 6 compiles it).
3. **Docs:** the changelog entry under `## [Unreleased]` with the reference citations; `src/wallet/wire/CLAUDE.md`'s rows.

Public shape: nothing moves (readers tighten; error variants reused). If a new `Error` variant is needed, STOP and report which and why (the one `Error` enum is public).

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_identity_certificate_roundtrip --test wire_reader_strictness --test wire_processor_validation --test wire_error_frames --test fixtures_replay --test wallet_wire_cross_sdk_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-192-wire-residuals` (fresh; never re-record a baseline). Any recording that changes is re-recorded in its own commit with the diff explained (`docs/FIXTURES.md`); none is expected.

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#192)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference lines read; the RED proof per item and the green run (every gate command with its result line); the `as usize` sweep's list; recordings changed (none expected); anything you could not do and why.
