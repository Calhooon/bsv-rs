Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #491: R56 lets an `unsigned` action's input carry no `unlockingScript` under `includeInputUnlockingScripts`, as the reference wallet answers; nothing else relaxes (the stack's word, 2026-10-31 05:1xZ; milestone 0.9.0-beta.5)

Branch `lane/fix-491-unsigned-input-unlocking-script` from `origin/beta` (name the base sha in your REPORT). One commit. Never push. Nothing is filed on any tracker.

## The word (the keeper's, recorded as the last comment on issue #491: `gh issue view 491 --comments`; read it whole before anything)

Narrow form (a), read at ts-stack edf6e03: R56 (`src/wallet/validation/lists.rs:187-201`) requires `unlockingScript` under `includeInputUnlockingScripts` for every input except an input of an action whose status is `unsigned`, where the key may be absent; nothing else relaxes. A signed action with status unprocessed, nonfinal or failed stays strict, recorded as a [D] residue row until the reference answers (ts-stack #1451, the reference's own inconsistency: `listActionsIdb.ts:77-91` leaves the key absent when `getRawTxOfKnownValidTransaction` returns nothing; `StorageKnex.ts:189-209` defines known valid; `WalletResultValidation.ts:2027-2035` demands the key; `WalletClient.ts:113-118` runs that validator on every answer). Re-pinned both ways on #1451's outcome, so the strict rule is kept as a test for return.

## The reference (rule 1: read it first, at `~/bsv/ts-stack`, the clone's commit named in the REPORT)

`packages/sdk/src/wallet/WalletResultValidation.ts:2027-2035` (the demand), `packages/sdk/src/wallet/WalletClient.ts:113-118` (the validator on every answer), `packages/wallet/wallet-toolbox/src/storage/methods/listActionsIdb.ts:77-91` (the key left absent), `packages/wallet/wallet-toolbox/src/storage/StorageKnex.ts:189-209` (known valid). Say in the REPORT, from the files, that the `unsigned` status is outside the known-valid set and that no other action status is decidable from the answer alone.

## The shape

1. `lists.rs:187-201` (R56): under `includeInputUnlockingScripts`, an input of an action whose `status` is exactly `"unsigned"` may omit `unlockingScript`; every other action status keeps the demand, with the same refusal words as today. The action's status is read from the same action object the input belongs to (the row's scope); nothing else in R56 or any other row changes.
2. The pin: a test RED on the base with the fixture-145 shape, recorded through the #408 recorder (`tests/support/http_json_result_values_408.mjs`, the vector `tests/vectors/http_json_result_values_408.json`, the test `tests/wallet_http_json_result_values_408.rs`: read how a case is recorded under Node 22 against the reference bundle and extend it with a listActions answer carrying an `unsigned` action whose input has no `unlockingScript` and, as the strict side, a `completed` action's input with none; the recorder's verdict column records the reference validator's words (it refuses both: that is the inconsistency; the vector records what the reference says and the test asserts what the port does, with the divergence stated in the test's words for the unsigned case). The shape of fixture 145 is in `~/bsv/bsv-wallet-cli/tests/wire/145-listActions.afterOverlongSpend.json` (read it by that path; the CLI's issue #371 describes it: `gh issue view 371 --repo Calhooon/bsv-wallet-cli`); build the test's input from this crate's own writer or a literal JSON body, never by copying the CLI's file into this repo.
3. The strict rule kept as a test for return: the test that pins the old refusal for an unsigned action's input stays, re-pointed to the new behaviour, with a comment naming #491, ts-stack #1451 and the words "strictness returns on the upstream's answer".
4. The entry carries old and new (the toolbox's and the CLI's tables): the row's reading before and after, the residue row [D] for the signed statuses (unprocessed, nonfinal, failed) that stay strict.
5. The inventory's R56 row (find it: `git grep -n 'R56' CHANGELOG.md docs src/wallet`; the 71 rows R03 to R88 of #432/#461's entry and wherever they are listed as an inventory) names the reference's own inconsistency with #491, bsv-wallet-cli#371 and ts-stack #1451 as witnesses; the root `CLAUDE.md` divergence list gets a row for the residue (at the END of the list, so the census numbers hold), with its census line under the new entry.

## Gate (foreground, each result in the REPORT)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http" --lib wallet`; one `--test` per file matching `wallet_*`, `arch_*` (the `.rs` files) and `fixtures_replay`; `cargo test --doc --all-features`; `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"` (`CC_wasm32_unknown_unknown` to LLVM clang if ring asks); `cargo semver-checks check-release --baseline-rev <base> --release-type patch`; `tools/ratchet/run --check --against <base>` with `CARGO_TARGET_DIR` outside the checkout; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root; hermetic (no default URL or port).

## Docs

`CHANGELOG.md` under `## [Unreleased]`: a `### Changed: R56 lets an unsigned action's input carry no unlockingScript, as the reference wallet answers (#491)` section (never a bare bullet) with old and new, the word, the witnesses, the residue row, the pins; the inventory row; the root `CLAUDE.md` row; `src/wallet/CLAUDE.md`'s row for `lists.rs`.

## REPORT

Tip sha and message; the base; the reference reading (the four sites); the files changed with line ranges; the recorder's command and the vector's new cases; the RED evidence; the rows rewritten (counted); the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
