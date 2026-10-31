Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #545: PushDrop pushes a wallet's public-key bytes as the wallet returned them, as the reference does (`PushDrop.ts:168-169`), not re-encoded compressed

Branch `lane/fix-545-pushdrop-key-bytes` from `origin/beta` (name the base sha in your REPORT; #544 landed at 69d315fc; PRs #554 (#552), #555 (#548) and #556 (#550) are open beside you on disjoint files: read `git log origin/beta -8`). One commit. Never push. Nothing is filed on any tracker. A parity row at the pin, 0.9.0 (`gh issue view 545`).

## The finding (PR #538's second fold and its scoped read)

The reference's PushDrop template pushes the wallet's public-key bytes as the wallet returned them (`~/bsv/ts-stack/packages/sdk/src/script/templates/PushDrop.ts:168-169` at edf6e03: read the whole `lock`), while this crate's template re-encodes the key compressed before pushing it (`src/script/templates/pushdrop.rs:156,177`), at `src/kvstore/local_token.rs:41`, `src/kvstore/global_actions.rs:192` and `src/identity/contacts_actions.rs:69` (the lines as of #538's tip; find them on the tip). For a wallet returning a compressed key the bytes agree; for an uncompressed (`04`) key, or the lenient forms #498's parser now reads, the token's first field differs.

## The shape

1. The template pushes the key's bytes as given (the reference's rule: read what `PushDrop.ts` does with `publicKey` exactly: the hex the wallet returned, decoded as bytes, pushed as the first field; and what the unlocker signs with); nothing else about the template changes; the three sites pass the wallet's bytes through.
2. The witness, recorded, never by hand: a recorder `tests/support/pushdrop_key_bytes_545.mjs` (Node 22 against the edf6e03 bundle, a `ProtoWallet` on a fixed key whose `getPublicKey` answer is set to an uncompressed form and to one lenient form, if the reference's wallet can return such; else the recorder feeds the template's `lock` the key text directly, as the reference's template takes it) recording the reference's locking script bytes for a compressed, an uncompressed and a lenient-form key, into `tests/vectors/pushdrop_key_bytes_545.json`; the test compares this crate's locking script bytes byte for byte (RED on the base for the uncompressed and lenient forms, equal for the compressed).
3. Hermetic (rule 4); no network; no default port.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Fixed: PushDrop pushes the wallet's key bytes as returned, as the reference does (#545)` section (never a bare bullet) carrying old and new (a compressed-key wallet's token unchanged, said plainly for the toolbox's and the CLI's tables), the recorder and vector; the root `CLAUDE.md` divergence row closed by this landing (at the END of the list) with its census line under the entry; `src/script/templates/CLAUDE.md`'s row for `pushdrop.rs`.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib script`, `--lib kvstore`, `--lib identity` (one filter per run); one `--test` per file matching `script_*`, `kvstore_*`, `identity_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## REPORT

Tip sha and message; the base; the template's change with the reference's lines; the three sites; the recorder's command and the vector's cases; the RED evidence; the rows; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
