Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #498: `PublicKey::from_hex` accepts the public-key forms the reference accepts (an odd-length key padded, a hybrid key with the right parity, an x above p reduced), one parser; the strict forms' tests kept for return

Branch `lane/fix-498-public-key-forms` from `origin/beta` (name the base sha in your REPORT). One commit. Never push. Nothing is filed on any tracker (the captain files; the reference-tracker filing the issue names is the keeper's and the owner's, not this lane's).

## The word (the keeper's, 2026-10-30 05:1xZ, in issue #498; read the issue with `gh issue view 498`)

Accept as the reference does, one parser, under the reading of record of 10-26: accept what the reference accepts, refuse what the standard forbids and the reference refuses, the question upstream, the pinned tests kept so strictness can return. A token read by the reference and refused by the port is two verdicts for one user.

## The reference (rule 1: read it first)

`~/bsv/ts-stack/packages/sdk/src/primitives/PublicKey.ts:49-51`, `Point.ts:303-325,345-348,365-384`, `primitives/utils/hex.ts:27-29` (or `hex.ts` where `toArray` lives) at `edf6e03` (`git -C ~/bsv/ts-stack log -1 --format=%h` says the clone's commit; say which you read). The forms: an odd-length hex string padded with a leading `0` (`2`+Gx, `3`+Gx, `4`+Gx+Gy, `6`+Gx+Gy); a hybrid key (`06`/`07` + Gx + Gy) accepted when the prefix's parity matches y; an x at or above p reduced mod p (compressed, uncompressed or hybrid). Then go-sdk (`~/bsv/go-sdk`, `primitives/ec/publickey.go` and its point parsing) and py-sdk (`~/bsv/py-sdk`) at their pins: for each form say whether that SDK accepts or refuses, so the REPORT states whether the ecosystem is split or agrees with the reference's tolerance (the issue asks this first; the captain carries the reading to the keeper).

## The port today

`src/primitives/ec/public_key.rs:63` `PublicKey::from_hex` refuses every form above; the #489 landing (PR #494, its changelog entry and the divergence rows in the root `CLAUDE.md`, grep `#489` and `#494`) states the difference with pins that record the reference's acceptance (find them: `git grep -n -i -E 'odd-length|hybrid|above p' tests src`).

## The shape

1. One parser: `PublicKey::from_hex` (and whatever `from_str`/`FromStr` path shares it) accepts the three forms exactly as the reference does, producing the same point the reference does (a hybrid key with the WRONG parity is refused as the reference refuses it; an x at or above p reduced the way `Point.ts` reduces it; the padded odd-length string read as the reference's `toArray` reads it). Every refusal the reference makes stays a refusal with this crate's error class (name the variant; no new `Error` variant unless the reference's distinct refusal needs one, and then say so).
2. The serialisation side unchanged: `to_hex`/`to_der` still emit the strict compressed or uncompressed form; a round trip of an accepted lenient form yields the strict form (pin it).
3. The tests that pin the strict refusal today are KEPT, re-pointed to the new behaviour, and marked for return: each such test keeps a comment naming #498 and the words "strictness returns on the upstream's answer", so a future lane can flip them back; the #494 rows become the new behaviour's rows (the root `CLAUDE.md` divergence list: the row's reading changes to "accepts as the reference does" with the three forms named; every copy of a census line for that row rewritten identically, counted with `grep -c '^- Row N:'`).
4. Vectors: a JSON vector `tests/vectors/public_key_forms_498.json` recorded by a Node script of this crate's own under `tests/support/` against the reference bundle (as `tests/support/kvstore_local_parser_words_489.mjs` does for #489: read it and follow its shape; run under Node 22, `nvm use 22`), never written by hand: for each form, the input hex, the reference's verdict (accepted with the resulting compressed hex, or the refusal's words), and the port asserts the same verdict and the same point. RED on the base: the accepted forms refused.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib primitives`; one `--test` per file matching `ec_*`, `primitives_*`, `chain_*`, `compat_*`, `script_*`, `arch_*` (the `.rs` files) and `fixtures_replay`, plus every test file your grep found; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type minor` (no public shape change expected: say what it reports); `cargo fuzz` is not required, but `cargo test` on `fuzz/`'s corpus if a parser test target exists for the hex path (say); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root.

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Changed: \`PublicKey::from_hex\` accepts the reference's lenient forms (#498)` section carrying old and new (a table of the three forms: before, now, the reference's site) for the toolbox's and the CLI's tables, the keeper's word, the ecosystem reading (go-sdk, py-sdk), the pins, the "strictness returns" marker; the root `CLAUDE.md` row; `src/primitives/CLAUDE.md`'s row for the key parser.

## REPORT

Tip sha and message; the base; the ecosystem reading per form per SDK (a table); the files changed with line ranges; the vector's recording command and its count; the RED evidence; every test re-pointed, named; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
