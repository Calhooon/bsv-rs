# Lane: fix-137-wallet-refusal-class. A wallet refusal carries its class: `Error::WalletRefusal { class, message }` with the reference's error classes (#137)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in your own worktree cut from `origin/beta`. Read `CLAUDE.md` (rules 1, 2, 9; "Downstreams to keep in mind"), `src/error.rs` and its CLAUDE.md if any, `src/wallet/CLAUDE.md`, `src/wallet/wire/CLAUDE.md` (the #202 error frame: a coded error keeps its code and words; an un-coded wallet error is "Wallet operation failed" code 1), `docs/DEPENDENTS.md`, and issue #137 with its comments (the owner's word of 2026-10-26) before touching anything. You never push, tag or open a PR; you commit on your branch and end with the REPORT. Every command is foreground and under ten minutes.

## The ask

Every toolbox refusal reaches this crate as `Error::WalletError(String)`: words, no class. A host serving BRC-100 over HTTP needs the class (400 a bad argument, 402 insufficient funds, 404 not found, 409 an invalid BEEF or a refused spend, 503 a transport fault); the CLI matches message prefixes today as a named exception to its own rule. The reference's `WalletError` carries a numeric code (`~/bsv/ts-stack/packages/sdk/src/wallet/WalletError.ts` at `edf6e03`: read the code table; BRC-100 at `5119a9b`, `~/bsv/brcs/wallet/0100.md`, its error section: read and cite the codes and their names).

## The work

1. **The variant.** A new variant on `Error` beside `WalletError(String)` (the enum is public; adding a variant is additive on 0.9.0 under the owner's word; read whether `Error` is `#[non_exhaustive]` and say so): `WalletRefusal { class: WalletRefusalClass, message: String }` (names the lane settles, in the repo's voice), with `WalletRefusalClass` a `#[non_exhaustive]` enum of the reference's classes exactly (one variant per reference code the interface's calls can raise, each carrying its reference code as `fn code(&self) -> u8` or the type the reference uses, and its reference name), never classes of our own. `Display` for the variant prints the message (the class in the typed form, not the words). `Clone + PartialEq + Eq` as the enum has.
2. **The processor's frame.** The wire processor frames a `WalletRefusal` with the class's reference code and the message's words (the #202 reading: a coded error keeps its code and words), where an un-coded `WalletError` stays `Wallet operation failed` code 1; the tracing sink (#212) logs the class. RED-before: a mock wallet returning each class reaches the frame with that code (the reference's bytes), the transceiver reads it back as the typed class (if the transceiver maps codes to errors today, read how and extend it; the reference's client throws `WalletError` with the code: cite).
3. **The HTTP JSON substrate**: if it serves error bodies today (`src/wallet/substrates/http_json.rs`), the class maps to the body the reference's `HTTPWalletJSON` sends (read it; cite); if it does not serve errors, say so and leave it.
4. **Rule 2**: tests for the variant's `Display`, `Clone`/`Eq`, the code per class against the reference's table (a table test), the frame per class, the read-back; every recording that changes is re-recorded in its own commit with the diff explained (`docs/FIXTURES.md`); no vector edited.
5. **Docs**: the changelog's `### Added` entry (the classes and codes with the citations; the consumer note: the toolbox's `From<Error>` maps each of its variants to a class, the CLI deletes its prefix matching; both told); `src/error.rs` docs; `src/wallet/wire/CLAUDE.md`'s rows; `CLAUDE.md`'s `Error` paragraph (the variant count moves).

Public shape: one new variant on `Error` and one new public enum, additive; nothing removed or renamed; if `Error` is not `#[non_exhaustive]`, say in the REPORT that a downstream's exhaustive match breaks (the 0.9.0 word covers it; the migration line names it).

## The gate (foreground, each under ten minutes), named by glob

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; every wire and wallet test file: `for f in $(ls tests | grep -E '^(wire_|wallet_|fixtures_replay|error)' | sed 's/\.rs$//'); do cargo test --features "full,http,tracing" --test $f || exit 1; done`; `cargo test --lib --features full error`; `cargo test --lib wallet --features full`; `cargo test --doc --features full`; `cargo build --examples --all-features`; the wasm32 build `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` with `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/fix-137-wallet-refusal-class` (fresh; never re-record a baseline).

## Rules

Never read `~/bsv/bsv-low/` or `~/vault/`. No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name `(#137)`; bodies say what and why; end with the Co-Authored-By line the session gives you. Another lane (#222's removal) will touch `processor.rs` after PR #257 lands: keep your processor diff to the frame of the new variant.

## REPORT (the last thing you print)

`REPORT` then: branch and tip sha; each commit's sha and subject; the classes and codes with the reference lines; the variant's and enum's exact public shape; whether `Error` is non_exhaustive and what a downstream's exhaustive match does; the RED proof and the green run (every gate command with its result line); recordings changed and why; anything you could not do and why.
