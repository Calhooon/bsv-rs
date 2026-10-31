Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #526: one definition of the wallet substrates' 256 MiB byte bound (after #502 and #512)

Branch `lane/fix-526-one-byte-bound` from `origin/beta` (`aeb92b01`). One commit. Never push.

## The finding (PR #525's cold review)

Two definitions of the same bound live in sibling modules, each `pub(super)`, neither visible to the other: `src/wallet/substrates/result_values/boundary.rs:9` (`pub(super) const MAX_BYTES: usize = 256 * 1024 * 1024;`, read by `boundary.rs` itself, `raw_tree.rs` and `wire.rs`, and the source of `MAX_WIRE_REQUEST_BYTES`) and `src/wallet/substrates/byte_fields.rs:15` (`pub(super) const MAX_BYTES: usize = 256 * 1024 * 1024;`, its doc line "`MAX_WALLET_WIRE_FRAME_BYTES`, `bytes`'s default bound", read by `byte_fields.rs:130` and `result_values/bytes.rs:46,63`). The value is the reference's `MAX_WALLET_WIRE_FRAME_BYTES`.

## The shape

One definition at one site, the other a use of it; nothing else changes. Pick the site with the fewest visibility changes and say why in the REPORT (either `boundary.rs`'s constant made visible to `byte_fields.rs`, or `byte_fields.rs`'s made the one and `boundary.rs` reading it; `substrates/mod.rs:41-42` declares both modules `pub(crate)`; `result_values` is a file module with a directory of submodules, read it before choosing). The doc comment on the one definition names the reference's constant and where it is read from (`ts-stack@edf6e03`, the file and lines, read in the reference clone at `~/bsv/ts-stack/packages/sdk/src/wallet/substrates/`). No behaviour change: every refusal's words and every recorded wire frame unchanged byte for byte; `MAX_WIRE_REQUEST_BYTES` stays equal to the bound.

## Pins (RED before the fix on a scratch copy of `aeb92b01` with its own target dir, never a `git checkout` of a dirty tree)

- A new arch test `tests/arch_one_wallet_byte_bound.rs` (crate doc line first: the crate denies `missing_docs` on test targets) that reads every `.rs` file under `src/wallet` and asserts exactly one line defines the bound (a `const` whose initializer is `256 * 1024 * 1024` or the literal `268435456`); RED on the base (two), green on the tip. Register nothing else: integration tests are discovered by file.
- The existing tests that exercise the bound: `cargo test --features "full,http" --lib wallet` and every `--test wallet_*` binary (one `--test` per file) green, unchanged.

## Docs

- `CHANGELOG.md`, under `## [Unreleased]`, a `### Changed: one definition of the wallet substrates' byte bound (#526)` section (every entry of the file is a `### Kind: title (#N)` section; never a bare bullet): the finding, the site chosen and why, the pin, no behaviour change.
- `src/wallet/substrates/CLAUDE.md`: the module table's rows for `byte_fields.rs` and for `boundary.rs` say where the one bound lives (the #512 row text names "the byte cap in `boundary.rs`, shared by `raw_tree.rs` and `wire.rs`": make it true for the chosen site).

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib wallet`; one `--test` per file matching `wallet_*`, `arch_*` (the `.rs` files; `arch_support` is a directory) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev aeb92b01 --release-type patch` (no public change: say what it reports); `tools/ratchet/run --check --against aeb92b01` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; `grep -rn -E '256 \* 1024 \* 1024|268435456' src/wallet` on the tip, every hit named.

## REPORT

Tip sha and message; the files changed with line ranges; the site chosen and why; the RED evidence (the arch test's count on the base and the tip); the grep's hits; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
