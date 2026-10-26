# Lane: fix-189-certificate-writer-refusals. `write_wallet_certificate` refuses what the reference's writer refuses (#189)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 1, 2, 3), `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md` and issue #189 (`gh issue view 189 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The rule (the keeper's on #183: the writer never makes a frame the reference's reader refuses)

Since #183 this crate's readers refuse a certificate whose subject or certifier is not a compressed point, whose field name is outside 1 to 50 bytes, unsafe or repeated, or whose signature is not DER (`~/bsv/ts-stack/packages/sdk/src/auth/certificates/Certificate.ts:342-397` at `edf6e03`). `WireWriter::write_wallet_certificate` (`src/wallet/wire/encoding.rs`) still writes all three unchecked. The reference's writer refuses them before writing (`Certificate.ts:310` for the signature; the key and field checks beside it): read those lines yourself, then Go (`~/bsv/go-sdk`), and cite them.

## The work

1. `write_wallet_certificate` refuses each (a non-point subject or certifier; a field name outside 1 to 50 bytes, unsafe or repeated; a non-DER signature) as a typed error before any byte is written, with the words the readers use for the same refusal (one reading for the writer and the readers; reuse the readers' checks, do not copy them: a shared crate-private helper if one does not exist). The same for the discovery writer if it writes certificates and lacks the checks (read it; say).
2. Rule 2: a RED-before test per refusal (`tests/wire_identity_certificate_roundtrip.rs` or `tests/wire_reader_strictness.rs`: the writer given each bad certificate refuses and writes nothing); every recorded certificate and vector already passes the readers, so no recording or vector moves (`git diff -- tests/fixtures tests/vectors` empty: a moved one is a finding, STOP).
3. Docs: the changelog's line per refusal with the citations; `src/wallet/wire/CLAUDE.md`'s row for the writer.

Public shape: `write_wallet_certificate`'s signature returns a `Result` today? If it does not and must (a refusal needs one), that is a public shape change: STOP and report with the signature; do not change it.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_identity_certificate_roundtrip --test wire_reader_strictness --test fixtures_replay --test wallet_wire_cross_sdk_tests --test wire_method_roundtrip_tests`; `cargo test --lib wallet::wire --features full`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-189-certificate-writer-refusals` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#189)`; bodies say what and why; end with the Co-Authored-By line the session gives you. Another lane (#236) edits `read_identity_certificate` and the discovery reader's helpers in the same file at the same time: touch nothing in the readers beyond calling an existing check.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the reference and Go lines read; the RED proof per refusal and the green run (every gate command with its result line); whether a public signature would have had to move; anything you could not do and why.
