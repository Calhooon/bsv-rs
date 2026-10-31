Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #532: the three remaining copies of the substrates' 256 MiB byte bound read the one definition (after #526)

Branch `lane/fix-532-three-bound-copies` from `origin/beta`'s tip after PR #531 (#526) has landed (name the base sha in your REPORT). One commit. Never push.

## The finding (PR #531's cold review, by meaning)

After #526 made `src/wallet/substrates/byte_fields.rs`'s `MAX_BYTES` the one definition of the substrates' bound (the reference's `MAX_WALLET_WIRE_FRAME_BYTES`), three constants under `src/wallet` still hold the same bound under their own names and literals: `src/wallet/substrates/http_wire.rs:61`, `src/wallet/validation/crypto.rs:17`, `src/wallet/wire/validation.rs:40` (the reference's copies at `HTTPWalletWire.ts:28`, `validationHelpers.ts:150`, `WalletResultValidation.ts:873`, named in #531's changelog entry). A fourth, `src/wallet/substrates/http_json.rs:95` (`MAX_WALLET_JSON_REQUEST_BYTES`, the reference's own request bound, `HTTPWalletJSON.ts:60`), is a different bound that shares the value and stays its own constant.

## The shape

The three read the one definition: either a `pub(crate)` path to `byte_fields::MAX_BYTES` (today `pub(super)` in a `pub(crate) mod` of `substrates`), or the one definition moved to a site all the readers see; the choice with the fewest visibility changes, said why in the REPORT. The three sites keep their own names if a name carries meaning at its site (`const MAX_WALLET_WIRE_FRAME_BYTES: usize = <the one definition>;` is fine; a bare `use` is fine too); no literal `256 * 1024 * 1024` or `268435456` remains under `src/wallet` except the one definition and `http_json.rs:95`. `http_json.rs:95` untouched except that its doc line says which bound it is and that it is not the frame bound. No behaviour change: every refusal's words and every recorded wire frame unchanged byte for byte.

## Pins (RED before the fix, on a scratch copy of the base with its own target dir)

- `tests/arch_one_wallet_byte_bound.rs` (landed with #531): its enumerated list of other definitions shrinks to `http_json.rs`'s one; the test fails on the base (the three still defined with the literal) and passes on the tip; say the counts.
- `cargo test --features "full,http" --lib wallet` and every `--test wallet_*` binary green, unchanged.

## Docs

- `CHANGELOG.md`, under `## [Unreleased]`, a `### Changed: the three remaining copies of the substrates' byte bound read the one definition (#532)` section (never a bare bullet): the finding, the site chosen and why, the pin's new count, `http_json.rs`'s bound named as different, no behaviour change.
- `src/wallet/substrates/CLAUDE.md` (the `http_wire.rs`, `http_json.rs` and `byte_fields.rs` rows) and, if they carry a row for the two other files, `src/wallet/CLAUDE.md` / `src/wallet/wire/CLAUDE.md`: the one definition named where the bound is described.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib wallet`; one `--test` per file matching `wallet_*`, `arch_*` (the `.rs` files; `arch_support` is a directory) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base sha> --release-type patch` (no public change: say what it reports); `tools/ratchet/run --check --against <base sha>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; `grep -rn -E '256 \* 1024 \* 1024|268435456' src/wallet` on the tip, every hit named (expected: the one definition and `http_json.rs:95`).

## REPORT

Tip sha and message; the base sha; the files changed with line ranges; the site chosen and why; the RED evidence (the arch test's counts on the base and the tip); the grep's hits; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
