# Lane: fix-247-trust-byte. `read_identity_certificate` refuses a trust byte outside 1 to 10 in the reference's words (#247)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (#236 is on the tip: the identity reader reads its maps through the transceiver's helper). Read `CLAUDE.md` (rules 1, 2, 3), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md` and issue #247 with its comments (`gh issue view 247 --repo Calhooon/bsv-rs --comments`: the keeper's reading) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The reading (the keeper's, 2026-10-26, under the #183 rule: a reader refuses what the reference's reader refuses)

The reference bounds the byte: `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireTransceiver.ts:1710` at `edf6e03`, `this.#requireInteger(resultReader.readUInt8(), 'discovery trust', 1, 10)` (and `:1712`); `WalletResultValidation.ts:1900`, `rangedInteger(info.trust, call, ..., 1, 10)`; the type `PositiveIntegerMax10` (`Wallet.interfaces.ts:874`, `:1669`, `:1694`). This crate's transceiver already refuses it there (#183) and its writer refuses a trust outside 1 to 10 before writing; `WireReader::read_identity_certificate` (`src/wallet/wire/encoding.rs`) accepts any byte (#184's reading, so Go's zero value read as trust 0). Go at `~/bsv/go-sdk` `2ca481c` writes the byte as is (`wallet/serializer/identity_certificate.go:26`) and reads any byte (`:66`): Go's zero value is Go's acceptance, the divergence row #183 carries. Read every cited line yourself and cite them.

## The work

1. `read_identity_certificate` refuses a trust byte outside 1 to 10 with the reference's words, through the same check the transceiver uses (one reading; a shared helper if the transceiver's check is not already one, never a copy).
2. Rule 2: RED-before tests in `tests/wire_identity_certificate_roundtrip.rs` or `tests/wire_reader_strictness.rs` (hand-assembled bytes in the writer's layout): trust 0 (Go's zero value) refused with the words; trust 11 refused; trust 1 and 10 accepted. Every recorded certificate already carries a trust in 1 to 10 (`git diff -- tests/fixtures tests/vectors` empty; a moved one is a finding, STOP).
3. Docs: the changelog entry with the citations and the Go divergence (a pinned refusal of Go's zero value, the divergence line in `CLAUDE.md`'s list extended or the #183 row cited); `src/wallet/wire/CLAUDE.md`'s row; the #184 words that said any byte is accepted corrected where they stand.

Public shape: nothing moves. If a new `Error` variant is needed, STOP and report.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_identity_certificate_roundtrip --test wire_reader_strictness --test wire_identity_certificate_writer --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-247-trust-byte` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#247)`; bodies say what and why; end with the Co-Authored-By line the session gives you.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference and Go lines read; the RED proof and the green run (every gate command with its result line); recordings changed (none expected); anything you could not do and why.
