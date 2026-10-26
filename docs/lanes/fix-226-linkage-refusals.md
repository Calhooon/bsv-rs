# Lane: fix-226-linkage-refusals. The linkage keys' refusals move to validation with the reference's code and words; the security level's words (#226)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta` (version 0.9.0; #216's validation step is on the tip: `src/wallet/wire/validation.rs`, `invoke_wallet` in `src/wallet/wire/processor.rs`). Read `CLAUDE.md`, `src/wallet/wire/CLAUDE.md`, `tests/CLAUDE.md`, `docs/FIXTURES.md` and issue #226 (`gh issue view 226 --repo Calhooon/bsv-rs`) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes (split long test runs into `--test` halves; never background a gate and end your turn).

## The rule (the keeper's on #216: a refused argument carries the reference's code and words)

The reference decides: `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/WalletWireProcessor.ts` at `edf6e03` reads revealCounterpartyKeyLinkage's two keys and revealSpecificKeyLinkage's verifier raw (`paramsReader.read(33)` then `toHex`, `:1742-1747`, `:1796`), and `validateWalletArgs` (`~/bsv/ts-stack/packages/sdk/src/wallet/validationHelpers.ts`) refuses a non-point as code 6, `The counterparty parameter must be a valid compressed secp256k1 public key` (`:1736-1738`, `:1745`; `validatePublicKey` `:182-188`), the same words for `verifier`; revealSpecificKeyLinkage's absent counterparty (flag 0) is refused there too, code 6, `The counterparty parameter must be a hexadecimal string` (`:1744`, `:190-193`, `:523`). Its decoder refuses a security level with `Invalid security level: expected 0, 1, or 2, received N` (`WalletWireProcessor.ts:2440-2443`). Read those lines yourself, then Go, and cite them.

## The work

1. The four refusals move from the request reader (`src/wallet/wire/requests.rs:104-105`, `:125-128`, code 1 and this crate's words) to `validation.rs` as the reference's code 6 and words, through the step #216 built (class 3, the error frame as #202 frames it). The reader reads the 33 bytes raw, as the reference does, and the type that carries them keeps its shape (if the request type holds a parsed `PublicKey` and must become bytes or a string, that is a public shape change: STOP and report; the owner's word).
2. The security level's words: one line to the reference's.
3. RED-before tests (rule 2) with the reference's frames: each of the four refusals answers the reference's code and words; the security level refusal answers the reference's words; the existing reader-strictness tests that pinned code 1 move with the refusal (say which). Re-record any recording the move changes, in its own commit, the diff explained (`docs/FIXTURES.md`). The every-args-vector allowlist (14, `requests.rs`'s test) moves only if a vector now passes; say which.
4. Docs: the changelog entry; the divergence #216 recorded in `CLAUDE.md`'s clause and in #216's changelog entry is withdrawn (the lines named in #226's body); `src/wallet/wire/CLAUDE.md`'s rows.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http,tracing" --test wire_processor_validation --test wire_error_frames --test wire_reader_strictness --test wire_tracing_sink --test fixtures_replay --test wallet_tests`; `cargo test --lib wallet::wire`; `cargo test --doc --features full`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-226-linkage-refusals` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#226)`; bodies say what and why in the repo's voice; end with the Co-Authored-By line the session gives you. One commit per concern.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the RED proof (command, failing line, on the pre-fix tree) and the green run (every gate command with its result line); the reference lines read; every recording changed and why; any public API touched; anything you could not do and why.
