Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #537: six call sites decode PushDrop tokens with the lock position their reference counterpart passes (lock-before), the other position no longer accepted there; one lane, six commits (the keeper's word, 2026-10-31 06:1xZ)

Branch `lane/fix-537-lock-position-per-site` from `origin/beta` (name the base sha in your REPORT). SIX commits, one per site, each with its test RED on the base, and the changelog entry and the rows in the LAST commit only (a multi-commit branch that rewrites its own changelog entry in several commits lands every version under the sequencer's keep-both: the entry is written once, in the sixth commit). Never push. Nothing is filed on any tracker. No public shape moves (no new `pub` item; a crate-visible path if the decoder needs one).

## The word (the keeper's, recorded as the last comment on issue #537; `gh issue view 537 --comments`)

Parity per site. `PushDrop.decode(script, lockPosition = 'before')` at `~/bsv/ts-stack/packages/sdk/src/script/templates/PushDrop.ts:63-78` (edf6e03) reads the key from `chunks[0]` at a before-site and never tries the other position, so each of the six sites decodes with the position its reference counterpart passes, cited by line, and the general decoder stops accepting the other position at those call sites. A lock-after token at a before-site takes the reference's outcome there: the key parse of a field's bytes fails for every field that is not a valid point encoding; the corner where a field IS a valid point encoding is a reading row: record what the reference does with it at each site, its later validation included, as the witness. `src/kvstore/revoke.rs:191` is the pattern (read how it refuses a lock-after token today). The divergence rows are closed by the landing sha.

## The six sites (this crate) and their reference counterparts (read each counterpart's `PushDrop.decode` call and its position argument; cite the file and line)

| Site | This crate | Reference counterpart (find the call) |
|---|---|---|
| 1 identity client | `src/identity/client.rs:938,1080` | `packages/sdk/src/identity/IdentityClient.ts` |
| 2 contacts cache | `src/identity/contacts_cache.rs:74` | the contacts manager under `packages/sdk/src/identity/` |
| 3 registry client | `src/registry/client.rs:435,458,481,544` | `packages/sdk/src/registry/RegistryClient.ts` |
| 4 kvstore interpreter | `src/kvstore/interpreter.rs:249,261,271` (and the test at `:387`) | `packages/sdk/src/kvstore/` (the global store's token reading) |
| 5 overlay admin token | `src/overlay/overlay_admin_token_template.rs:94` | `packages/sdk/src/overlay-tools/OverlayAdminTokenTemplate.ts` |
| 6 storage downloader | `src/storage/downloader.rs:121` | `packages/sdk/src/storage/StorageDownloader.ts` |

## Each commit (sites 1 to 6, one commit each)

1. The site decodes with the reference's position only (today the general `PushDrop::decode` at `src/script/templates/pushdrop.rs:254-277` tries lock-before then lock-after): call the lock-before path (make `decode_lock_before` `pub(crate)` if needed, or a `pub(crate) fn decode_with_position(script, LockPosition)`; `PushDrop::decode` itself and its public shape unchanged, the template's own users and tests untouched).
2. The refusal for a lock-after token at the site is the reference's outcome there, recorded: extend the recorder pattern of `tests/support/kvstore_local_parser_words_489.mjs` (a Node 22 script against the reference bundle: `~/bsv/ts-stack` archived at edf6e03 and built with bun, the captain's memory `run-ts-reference-at-a-commit`) with one recorder for the six sites, `tests/support/pushdrop_lock_position_537.mjs`, recording for each site what the reference's counterpart does with (a) a lock-after token whose first chunk is not a valid point encoding and (b) the corner: a lock-after token whose first field IS a valid point encoding (the reference reads it as a key and continues; record its later validation's verdict and words at that site); the vector `tests/vectors/pushdrop_lock_position_537.json`, never written by hand; the test per site asserts the port's outcome equals the vector's.
3. A test RED on the base per site: the lock-after token accepted (or read differently) on the base, the reference's outcome on the tip.
4. The sixth commit also carries: `CHANGELOG.md` under `## [Unreleased]`, a `### Changed: six call sites decode PushDrop tokens with the reference's lock position (#537)` section (never a bare bullet) with the per-site table (site, reference line, old outcome, new outcome, the corner's reading), the keeper's word, the recorder and vector; the root `CLAUDE.md` divergence rows for these sites rewritten as closed (grep `lock-after` and `lock position` in `CLAUDE.md`; every copy of a changed census line in `CHANGELOG.md` rewritten identically, counted with `grep -c '^- Row N:'`); the module `CLAUDE.md` rows (`src/identity/`, `src/registry/`, `src/kvstore/`, `src/overlay/`, `src/storage/`).

## Gate (foreground, on the sixth commit, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib identity`, `--lib registry`, `--lib kvstore`, `--lib overlay`, `--lib storage`, `--lib script` (one filter per run); one `--test` per file matching `identity_*`, `registry_*`, `kvstore_*`, `overlay_*`, `storage_*`, `script_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch` (no public change: say what it reports); `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; hermetic (rule 4; no default URL or port).

## REPORT

The base; the six commits' shas and messages; per site: the reference's call and line, the old and new outcome, the corner's recorded reading; the recorder's command and the vector's case count; the RED evidence per site; the rows rewritten (counted); the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
