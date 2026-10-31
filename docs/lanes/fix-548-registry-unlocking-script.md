Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #548: the registry client's revoke and update unlock the definition token as the reference does (`RegistryClient.ts:540-548`, `:633-641`), not with an empty unlocking script

Branch `lane/fix-548-registry-unlocking-script` from `origin/beta` (name the base sha in your REPORT; #543 landed at f47f231f and #544 before you start: read both, `git log origin/beta -10`). One commit. Never push. Nothing is filed on any tracker. A parity row at the pin, 0.9.0 (`gh issue view 548`; the row is census Row 85 and the last root `CLAUDE.md` row, stated by #543's landing).

## The finding (PR #547's cold review)

`src/registry/client.rs` (revoke, around the old 652-653; update, around 876-877: find them on the tip) sends an empty unlocking script for the definition token's spend, where the reference's `RegistryClient.ts:540-548` (revoke) and `:633-641` (update) at edf6e03 unlock the token with the PushDrop template's unlocker (the operator's `anyone`-linked key, the protocol and key ID, the signature over the spend with the reference's sighash; read the whole of both sites and `PushDrop.ts`'s `unlock`), so a revoke or update built here does not spend the token as the reference does.

## The shape

1. The spend's unlocking script is built as the reference builds it: the PushDrop unlocker with the same key derivation, protocol, key ID, counterparty and sighash flags as the reference's call, through the wallet's `createSignature` as the reference does (read how this crate's PushDrop template unlocks today and what the kvstore's remove uses: `src/kvstore/` after #483; reuse the one unlocker); the `createAction` inputs carry the unlocking script length and the signed script as the reference's do.
2. The witness, recorded, never by hand: a recorder `tests/support/registry_unlocking_548.mjs` (Node 22 against the edf6e03 bundle, a `ProtoWallet` on a fixed key, a fixed token and a fixed spending transaction) recording the reference's unlocking script bytes for revoke and for update into `tests/vectors/registry_unlocking_548.json` (deterministic nonces as the reference's wallet signs them, or the signature's verification recorded if the reference's nonces are random: say which); the test builds the same spend here and compares (or verifies the signature under the reference's locking key as the vector's verdict): RED on the base (the empty script).
3. Hermetic (rule 4): a `ProtoWallet` in process, an injected resolver; no network, no default port.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: the registry client unlocks a definition token as the reference does on revoke and update (#548)` section (never a bare bullet) carrying old and new (a revoke or update built before this landing did not spend the token: said plainly for the toolbox's and the CLI's tables), the recorder and vector; the root `CLAUDE.md`'s #548 row rewritten as closed by this landing, its census line (Row 85) rewritten identically in every copy (`grep -c '^- Row 85:'`); `src/registry/CLAUDE.md`'s row.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib registry`; one `--test` per file matching `registry_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the base; the unlocker's derivation against the reference's lines; the recorder's command and the vector's cases; the RED evidence; the rows (Row 85's copies counted); the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
