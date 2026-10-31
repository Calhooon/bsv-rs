Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #543: the registry client reads and writes definition tokens with the reference's field layout (7/7/8 fields, the last a signature) and the reference's locking key

Branch `lane/fix-543-registry-token-fields` from `origin/beta` (name the base sha in your REPORT; #541 landed at b51cbea7). One commit. Never push. Nothing is filed on any tracker. The keeper's reading (2026-10-31 07:1xZ, recorded in issue #543: `gh issue view 543`): a parse divergence that drops the reference's signature from the record; a parity row at the pin, the second of three.

## The finding (PR #541's review, verified against ts-stack edf6e03)

The reference (`~/bsv/ts-stack/packages/sdk/src/registry/`: `registryTokenValidation.ts:13-16,29` and `RegistryClient.ts`, read whole) expects 7/7/8 fields for the three definition types (basket, protocol, certificate: the data fields plus a signature as the last field) and locks the token with the `anyone`-derived key (`RegistryClient.ts:37-44`); this crate's `src/registry/types.rs:98-104` and `src/registry/client.rs:438,461,484` expect 6/6/7, and the writer at `client.rs:226` adds no signature and locks with the identity key. A token written here is refused by the reference's validator; the reference's token is skipped here (the lock-before read of #537 lands the shape; the field count still differs).

## The shape

1. The reader: each type's field count and order as the reference's validator defines them, the signature field read (and, where the reference verifies it at that site, verified as the reference does: read `registryTokenValidation.ts` whole and say what it checks); the refusal words for a wrong count the reference's words, recorded.
2. The writer: the token's fields as the reference writes them (the signature over the fields the reference signs, with the key and protocol the reference uses: read `RegistryClient.ts`'s token creation whole), locked with the `anyone`-derived key as `RegistryClient.ts:37-44` does; nothing else changes.
3. The witness, recorded, never by hand: a recorder `tests/support/registry_token_fields_543.mjs` (the pattern of `tests/support/kvstore_local_parser_words_489.mjs`, Node 22 against the edf6e03 bundle) that, with a `ProtoWallet` on a fixed key, builds the reference's three definition tokens (the locking scripts, the fields, the signature) and records the reference validator's verdict on a 6-field token (this crate's base shape) into `tests/vectors/registry_token_fields_543.json`; the tests: the port reads the reference's tokens (RED on the base: skipped or refused), the port's written tokens equal the reference's bytes on the tip (RED on the base: 6 fields, the identity key), the base's 6-field token refused by the reference's recorded verdict.
4. Hermetic (rule 4): a `ProtoWallet` in process and an injected resolver; no network, no default port.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: the registry client uses the reference's definition-token layout and locking key (#543)` section (never a bare bullet) carrying old and new (the counts, the signature, the key; a token written before this landing is not the reference's token: say so plainly for the toolbox's and the CLI's tables), the keeper's reading, the recorder and vector; the root `CLAUDE.md` divergence list: a row closed by this landing (at the END of the list), its census line under the entry; `src/registry/CLAUDE.md`'s rows.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib registry`; one `--test` per file matching `registry_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch` (say what it reports: a changed public struct of the definition types is a finding to state, not to hide); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the base; the reader's and writer's changes with the reference's lines per type; the recorder's command and the vector's cases; the RED evidence; the rows; semver's reading; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
