Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #499: the local store's token decode is lock-before alone, as the reference decodes it; a lock-after token's refusal in the reference's words

Branch `lane/fix-499-local-store-lock-before` from `origin/beta` (name the base sha in your REPORT). One commit. Never push. Nothing is filed on any tracker.

## The word (the keeper's, 2026-10-30 05:1xZ, in issue #499; `gh issue view 499`)

Lock-before alone, as the reference decodes it (`PushDropValidation.ts:59`, `PushDrop.ts:74-75` at edf6e03): a lock-after token is not the reference's local token, and a decoder that reaches a later check on it tells a different refusal than the reference's.

## The reference (rule 1: read it first)

`~/bsv/ts-stack/packages/sdk/src/kvstore/LocalKVStore.ts:278-282` (the decode call), `PushDropValidation.ts:59`, `script/templates/PushDrop.ts:74-75` (the decode's first-chunk read: `script.chunks[0].data must have value`, then `PublicKey.fromString` whose refusal for a data push that is no key is `Unknown point format` or the words `Point.ts` throws): say which words each lock-after shape reaches in the reference. The general `PushDrop.decode` of the reference: does it accept lock-after anywhere (read `PushDrop.ts` whole and the other call sites under `packages/sdk/src`)? The issue says the general decoder's lock-after acceptance elsewhere in this crate stays unless the reference's other sites say otherwise: read them and say.

## The port today

`src/kvstore/local_lookup.rs:265-266` (the comment names the difference) calls the general `PushDrop::decode` (`src/script/templates/pushdrop.rs:254-277`: lock-before if the first chunk is a 33 or 65 byte push, else lock-after), so `51 75 <G> ac` reaches `Unexpected PushDrop token field count` and `51 52 6d <G> ac` reaches the canonical-envelope refusal; the #489 landing (PR #494) states the difference with pins (`tests/kvstore_local_parser_words_489.rs`, its recorder `tests/support/kvstore_local_parser_words_489.mjs`, the vector `tests/vectors/kvstore_local_454.json`; the rows in the root `CLAUDE.md`, grep `#489` and `#494`).

## The shape

1. The local store's decode (`local_lookup.rs`) is lock-before alone: it reads the first chunk as the reference does (a data push that is a key, else the refusal), never the lock-after layout; the refusal for a lock-after token is the reference's words from its lock-before parse of the first chunk, with this crate's error class for a local token refusal (the same variant the #489 words use; name it).
2. The words are recorded, never written by hand: extend the #489 recorder (`tests/support/kvstore_local_parser_words_489.mjs`, run under Node 22, `nvm use 22`, against the reference bundle as its header says) with the lock-after shapes (`51 75 <G> ac`, `51 52 6d <G> ac`, a first chunk that is a data push but no key, and the shapes the #494 rows name), re-record the vector (or a new `tests/vectors/kvstore_local_lock_after_499.json` if the 489 vector's shape does not fit; say which), and the test asserts the port's words equal the vector's. RED on the base: the port's words differ (the later checks' words).
3. The general `PushDrop::decode` and its lock-after path untouched (unless the reference's other sites say otherwise, see above; then say what and why, and stop short of changing them in this lane: a second issue).
4. The #494 rows for this difference become the new behaviour's rows (the root `CLAUDE.md` divergence list; every copy of a census line for the row rewritten identically, counted with `grep -c '^- Row N:'`); the entry carries old and new (the toolbox and the CLI read it for their tables).

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib kvstore` and `--lib script` (one filter per run); one `--test` per file matching `kvstore_*`, `script_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch` (say what it reports); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. Tests are hermetic (rule 4): the local store's tests inject their resolver; no network.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Changed: the local store decodes lock-before alone, as the reference does (#499)` section carrying old and new (the shapes, the old words, the new words, the reference's sites), the keeper's word, the recorder and vector named; the root `CLAUDE.md` row; `src/kvstore/CLAUDE.md`'s row for `local_lookup.rs`.

## REPORT

Tip sha and message; the base; the reference reading (each lock-after shape's words; the other call sites' verdict on lock-after); the files changed with line ranges; the recorder's command and the vector's count; the RED evidence; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
