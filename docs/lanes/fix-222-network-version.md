# Lane: fix-222-network-version. getNetwork and getVersion are the wallet's answers forwarded (#222)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (version 0.9.0; #216's validation step is on the tip: `src/wallet/wire/validation.rs`, `invoke_wallet` in `src/wallet/wire/processor.rs`). Read `CLAUDE.md`, `src/wallet/CLAUDE.md`, `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md` and issue #222 (`gh issue view 222 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (split long test runs into `--test` halves; never background a gate and end your turn).

## The rule (the keeper's, 2026-10-25 19:4xZ, on #222)

getNetwork and getVersion are the wallet's answers forwarded by the processor, never the processor's own. The reference decides: `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts` at `edf6e03` calls `this.wallet.getNetwork({}, originator)` (`:1704`) and `this.wallet.getVersion({}, originator)` (`:1724`); its result validation (`WalletResultValidation.ts:2299-2306`) wants `network` in {mainnet, testnet} and `version` a string of 7 to 30 bytes; BRC-100 section 28 (`~/bsv/BRCs` at `5119a9b`, `wallet/0100.md:2517`) names the version "the wallet's version string (e.g., vendor-1.0.0)". Read those lines yourself, then Go (`~/bsv/go-sdk`), and cite them in the changelog entry.

## The work

1. The two calls go through `invoke_wallet` to the `Wallet` trait (`src/wallet/interface.rs:277-280`, which already has `get_network` and `get_version`) like the other 13, and their results through #216's result validation (`validation.rs`) with the reference's rules and words: a network outside the two and a version outside 7 to 30 bytes are refused as the reference refuses them (its code and words; read `WalletResultValidation.ts` and the error path #216 built).
2. `ProtoWallet`'s answers (`src/wallet/proto_wallet.rs:920-934`) satisfy the validator: the version in the vendor-1.0.0 shape from `CARGO_PKG_VERSION` (`bsv-rs-0.9.0` fits), the network its chain. The old answer "0.1.0" (5 bytes) is a behavior change on 0.9.0: the changelog carries a one-line migration for a consumer that read it.
3. RED-before tests (rule 2): the processor forwards a mock wallet's network and version byte for byte; the result validation refuses a 5-byte version and a network outside the two, with the reference's words; the recordings of the two calls re-recorded (`BSV_FIXTURES_RECORD=1 cargo test --features "full,http" --test fixtures_replay`) in their own commit, the diff explained in that commit's body (`docs/FIXTURES.md`). The every-result-vector allowlist (`results.rs`'s test) moves only if a vector now passes; say which.
4. Docs: the changelog entry under `## [Unreleased]` with the parity citations; `src/wallet/wire/CLAUDE.md`'s table row for the two calls; `CLAUDE.md`'s divergence list loses any line that said the processor answered itself (if one exists).

Public shape: no trait method is added (both exist). If you find a public shape must change to do this, STOP and report it; do not invent one.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_processor_validation --test wire_error_frames --test wire_reader_strictness --test wire_tracing_sink --test fixtures_replay --test wallet_tests`; `cargo test --lib wallet::wire`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-222-network-version` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#222)`; bodies say what and why in the repo's voice; end with the Co-Authored-By line the session gives you. One commit per concern (the code, the tests, the recordings, the docs).

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the RED proof (command, failing line, on the pre-fix tree) and the green run (every gate command with its result line); the reference lines read and what they say; every recording changed and why; any public API touched; anything you could not do and why.
