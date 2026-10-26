# Lane: fix-236-identity-reader-readings. `read_identity_certificate` takes the transceiver's three readings: key length, unsafe keys, strict counts; the satoshis cast stated (#236)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (#192 is on the tip: `read_identity_certificate` refuses a repeated key; every wire length is checked before narrowing). Read `CLAUDE.md` (rules 1, 2, 5), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md` and issue #236 with its comment (`gh issue view 236 --repo Calhooon/bsv-rs --comments`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The rule (the keeper's on #183: a reader refuses what the reference's reader refuses; T2: one frame, one reading)

The reference at `ts-stack@edf6e03`: `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1979-2002` (`#readRecordKey`, `#setUniqueWireRecordEntry`: the key's length bounds, the reserved names, the unique entry) and `~/bsv/ts-stack/packages/sdk/src/auth/certificates/Certificate.ts:365-378` (the field name 1 to 50 bytes, safe, unique). This crate's transceiver (`src/wallet/wire/transceiver.rs`, `parse_discovery_result` and its helpers since #183) already makes those readings; `WireReader::read_identity_certificate` (`src/wallet/wire/encoding.rs`) makes only the repeated-key one (#192). Read every cited line yourself and cite them.

## The work

1. **One helper, one reading.** The three readings (key length bounds; an unsafe or reserved key; a declared count read to its end with bytes left over refused) move into one crate-private helper that both the transceiver's discovery reader and `read_identity_certificate` call, with the same typed error and the same words (the transceiver's words today, which came from the reference under #183: confirm, and if they are this crate's own, say so in the changelog as the stated divergence). No reading is loosened anywhere.
2. **The satoshis cast** (`encoding.rs`, the `as i64` on a satoshis value the #192 review named): read how the reference reads satoshis in the same frame (a 64-bit value; `WalletWireTransceiver.ts` or `WalletWireProcessor.ts`, cite the line) and either make the read a checked one with the reference's bound and a RED-before test, or state in the changelog why the cast stands (lossless for the wire's range, the bound named).
3. **Rule 2:** a RED-before test per reading in `tests/wire_identity_certificate_roundtrip.rs` or `tests/wire_reader_strictness.rs` (hand-assembled bytes in the writer's layout, as #184's and #192's tests do): a key over the bound, a reserved key, a count whose entries stop short or run long; each refused by the reader with the words, and the transceiver's reading unchanged (its existing tests stay green). Any recording that changes is re-recorded in its own commit (none expected).
4. **Docs:** the changelog entry with the citations; `src/wallet/wire/CLAUDE.md`'s rows; `tests/CLAUDE.md`'s rows.

Public shape: nothing moves (readers tighten; errors reused). If a new `Error` variant is needed, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_identity_certificate_roundtrip --test wire_reader_strictness --test wire_processor_validation --test wire_error_frames --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-236-identity-reader-readings` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#236)`; bodies say what and why; end with the Co-Authored-By line the session gives you. Another lane (#189) edits `WireWriter::write_wallet_certificate` in the same file at the same time: touch nothing in the writer.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference lines read; the RED proof per reading and the green run (every gate command with its result line); the satoshis decision; recordings changed (none expected); anything you could not do and why.
