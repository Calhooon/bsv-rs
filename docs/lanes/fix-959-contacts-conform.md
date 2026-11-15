# Lane fix-959-contacts-conform: the contacts cache answers as the reference's does (#959, D6 and D7)

Opened from `origin/beta` at `5ad961d7` (2026-11-14) and rebased before the
gate onto `228d4f34` (two documentation commits had landed; one `CHANGELOG.md`
conflict and one in the root `CLAUDE.md`, both sides kept). The captain's
ruling on the two questions of `docs/lanes/fix-identity-buckets.md` (D6, D7):
conform both, root rule 1. The reference is `ts-stack@edf6e03`
`packages/sdk/src/identity/ContactsManager.ts`, bundled with bun by the #326
recorder's recipe and run under Node v22.18.0.

## The base

Pull request #991's branch (`origin/lane/fix-identity-buckets`) held one
commit over `cb950611` when this lane opened, `0be8829b`, and no test named
`_stated_` for D6 or D7. That commit is picked under this lane as its base
(it carries the recorder's second pass, the corpus and the replay this lane
turns), and the D6 and D7 cells are written here from the reference's
recorded answers. The pick was `2785f4b8` after that rebase; it is gone since
the second one (below), beta's `f3aa5ff3` standing in its place.

## D6: the cold cache

The reference's `saveContact` validates, then, when its cache item is absent,
awaits `getContacts()` (`:528-531`), and `getContacts(identityKey)` loads when
the cache is absent (`:331-338`). Here:

- `ContactsManager::ensure_loaded` (`src/identity/contacts.rs`): the plain
  read's own load when the cache is not loaded; a failed listing is the
  caller's error and the cache stays cold.
- `add_contact`: `record_of`, `ensure_loaded`, then its calls as before.
- `get_contact`: a text `validateIdentityKey` refuses answers `None` with no
  call (stated: the reference throws at `:316-317`); else `ensure_loaded`,
  then the cache.
- `update_contact`: over a cold cache `record_of(&updates)` and
  `ensure_loaded`; then `ContactNotFound` when the loaded cache lacks the key
  (its own refusal, no reference twin); then `add_contact`.

`IdentityClient::resolve_by_identity_key` with contacts and
`IdentityClient::get_contact` read through `get_contact`, so they load too
(`IdentityClient.ts:575`); a failed load is still dropped at the by-key door
(`if let Ok(Some(..))`, the #751 row's older clause).

## D7: what a save caches

The reference stores the array holding `contactToStore`, the validator's
answer (`:527-534`, `:566`). Here `add_contact` caches
`record::contact_of(record, contact.added_at)`. `contact_of` now gives a
`Contact` whose record is the record read: an empty `metadata` object stays
`Some({})` (it read as `None`, after a load too), empty `tags` stay inside the
metadata, a metadata of `notes` and `tags` alone reads as `None` with the two
members set.

## The recorder and the corpus

Before any edit the recorder reproduced the committed corpus byte for byte.
Two directed sequences added (`save_caches_the_validated_record_959`,
`cold_save_caches_the_validated_record_959`), recorded twice byte-identical,
the diff of the vector additions alone (and one comma): click URLs
`https://example.com`, `HTTPS://EXAMPLE.com:443/a b?q=1#f` and
`http://localhost`, answered `https://example.com/`,
`https://example.com/a%20b?q=1#f` and `http://localhost/` from the cache and
after a refresh; `metadata` `{}` answered `{}`; `{ tags: [] }` answered so;
`{ notes: '', tags: ['Work'], alias: 'c' }` answered so. The corpus: 520
generated and 20 directed sequences, 5,333 steps, 233 of them cold (222
generated, 11 directed; 230 before the two sequences).

## RED

The lane's test commit (`17af9dab` since the rebase onto #991's landing) holds the tests over the
unchanged source: the replay with `load_as_the_reference_does` removed, the
two recorded sequences, six tests (and since that rebase the fold's pins
turned over, one of them in `tests/contacts_wallet_failures.rs`). `cargo test --features "full,http" --test
contacts_replay` there: 6 failed, 3 passed; 157 of 540 sequences differ.

| Test | RED on the unchanged source |
|---|---|
| `the_cache_replays_every_recorded_sequence_as_the_reference_answers_904` | 157 of 540: `save: the calls: this crate ["createHmac", "listOutputs", ..], the reference ["listOutputs", "createHmac", "listOutputs", ..]`; `by_key: the calls: this crate [], the reference ["listOutputs"]`; `plain: the answer: .. "badge_click_url": "https://example.com"` |
| `a_cold_save_loads_the_basket_ahead_of_its_own_calls_959` | the leading call `createHmac` |
| `a_cold_read_by_key_and_a_cold_update_find_a_contact_the_basket_holds_959` | `None` |
| `a_cold_call_whose_listing_fails_returns_the_wallets_error_and_stays_cold_959` | the save went on past the load |
| `a_cold_call_whose_listing_hangs_is_pending_and_dropped_without_harm_959` | the read answered at once |
| `a_save_caches_the_validated_record_959` | `https://example.com` |

Green after the fix: 9 of 9, 540 of 540. The stated test
(`a_read_by_a_text_that_is_no_key_asks_the_wallet_nothing_stated_959`) is
green on both, an agreement pin of this crate's own cell.

Seven tests of two other files leaned on the unported load and were RED
after the fix until turned to the reference's recorded call lists
(`tests/vectors/contacts_listed_spend.json`, whose cold cells always held the
leading `listOutputs`): six of `tests/contacts_wallet_failures.rs` and
`the_identity_tag_is_the_reference_hmac_542`.

## The honest caller's cost, measured

Wallet calls of one `add_contact` over a new manager (the basket wallet of
the replay, `tests/contacts_replay.rs`):

| Basket | Before | After |
|---|---|---|
| empty | 6 (`createHmac`, `listOutputs`, `encrypt`, `getPublicKey`, `createSignature`, `createAction`) | 7 (`listOutputs` ahead of them) |
| two contacts | 6 | 13 (the listing, three reads for each contact, then the 6) |
| any, the cache loaded | 6 | 6 |

A cold `get_contact`: 0 before (and `None`), 1 listing and three reads a
contact after. A cold call whose listing fails: the wallet's error after that
one call, the cache cold; before, the save made its other calls and the read
answered `None`.

## Rules 4 and 5

No panic on the new path: `ensure_loaded` returns the listing's `Err` as the
forced read does (`WalletError("listOutputs failed")` on the double, asserted
equal to the forced read's). A listing that never answers leaves the call
pending, as it leaves a forced read; the manager has no clock, the caller
bounds it, and a dropped call leaves the cache cold and usable (the double's
`hang` mode, polled once and dropped). Every test runs over a wallet double;
none opens a socket.

## Stated, not conformed

- `get_contact` of a text that is no canonical compressed key: `None`, no
  call; the reference throws `Invalid contact: identityKey ..` before its
  load. Two tests on beta read `get_contact("nonexistent")` as `Ok(None)`;
  an `Err` there is a caller-visible change the ruling did not name. Put to
  the captain.
- `update_contact`'s `ContactNotFound` (no reference twin).
- Two cold calls at once each load; the reference shares one load in flight
  (`:333-336`). No wrong answer: the later load overwrites with the same
  listing.
- `list_contacts`, `search_contacts`, `get_contacts_by_tag` and the identity
  client's attribute door read the cache alone.
- The load's `listOutputs` carries no `tags` member where the reference
  sends `tags: []`; the replay reads both as none (older than this lane).

## The rebase onto #991's landing (lane fix-959-contacts-conform-rebase, 2026-11-14)

Pull request #991 landed on beta as `f3aa5ff3` with a fold this lane's base
pick did not hold: tests named `_stated_959` that pinned D6 and D7 as they
stood, and three cells recorded beside the sequences (`stated_959`). The
branch was rebased with `git rebase --onto origin/beta 2785f4b8`: the pick is
dropped (beta's commit is the same work with the fold), and the three
commits after it are replayed, the tests' commit `17af9dab` (beta moved to
`006a8e58` during the gate, #104's and #817's lines; the three were replayed
onto it, one `CHANGELOG.md` conflict, both entries kept).

One set of tests, each cell once:

| #991's stated pin | after the rebase |
|---|---|
| `a_save_answers_the_callers_form_until_a_refresh_stated_959` (`tests/contacts_replay.rs`, three cells) | `a_save_caches_the_validated_record_959`: the fold's test turned over on its three recorded cells, the reference's record at each of the four reads the expected value; this lane's hand-typed test of that name is gone, its cells these |
| `a_cold_add_makes_no_listing_of_the_basket_stated_959` (`tests/contacts_wallet_failures.rs`) | `a_cold_add_lists_the_basket_ahead_of_its_own_calls_959`, in place: the call list the recorded `cold_save_959` step 0 whole; this lane's `a_cold_save_loads_the_basket_ahead_of_its_own_calls_959` loses its assertion of the leading listing and keeps the cost (the warm save's calls behind it, three reads a contact held) |
| `a_cold_get_contact_answers_none_for_a_key_the_basket_holds_stated_959`, `a_cold_update_refuses_contact_not_found_for_a_key_the_basket_holds_stated_959` (`tests/contacts_wallet_failures.rs`) | folded into this lane's `a_cold_read_by_key_and_a_cold_update_find_a_contact_the_basket_holds_959` (`tests/contacts_replay.rs`), which reads the recorded steps `cold_read_by_key_959` 4 and `cold_save_959` 6 as its expected answers; moved because the failures file's double lists no BEEF, so an update there cannot spend and could not be turned to the reference's `ok` |

The one `_stated_` name left in the contacts tests is this lane's own,
`a_read_by_a_text_that_is_no_key_asks_the_wallet_nothing_stated_959`: the
difference stands (the opening item of "Stated, not conformed").

The recorder holds both sides (the two directed sequences and `STATED_959`,
its name kept so the recorded line is beta's). The vector was recorded again
at the pin (`ts-stack@edf6e03` bundled with bun, Node v22.18.0): beta's
recorder reproduced beta's file byte for byte before the merge (SHA-256
`b00ee1cc...e960b71a`); the merged recorder's two runs are identical (SHA-256
`2045c906...4cb7fd6d`); against beta's file the diff is one replaced line and
two added (`four_contacts_959` gaining its comma, then the two directed
sequences), every top-level member but `directed` and each of beta's 18
directed sequences equal, the two added equal to this lane's earlier
recording. 520 generated and 20 directed sequences, 5,333 steps.

RED on `17af9dab`: `contacts_replay` 6 of 9 failed and 157 of 540 sequences
differ, as before the rebase; `contacts_wallet_failures` 1 of 30 (the cold
add). Green on the fix: 9 of 9, 540 of 540; 30 of 30.

The other conflicts: the root `CLAUDE.md`'s #904 row is this lane's (both
residues closed) with the turned tests named; `tests/CLAUDE.md`'s two rows
hold both sides, the fold's sentences rewritten as what was held and what it
became; `CHANGELOG.md` keeps #991's entry as it landed and this lane's with
the turnover said; `docs/lanes/fix-identity-buckets.md` is beta's, untouched.

## The gate (on the tip after the earlier rebase, own target dir; the gate after the second is in the rebase lane's report)

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check`, `--manifest-path fuzz/Cargo.toml`, `--manifest-path fuzz/corpus-gen/Cargo.toml` | clean, all three |
| `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo check --all-targets --all-features` | clean |
| the wasm32 slice of root rule 6 | built |
| `cargo test --features "full,http" --lib identity::`, three runs, one with `--test-threads=1` | 120 passed each |
| the 53 binaries (`tests/identity_*.rs`, `tests/contacts_*.rs` and every file naming `ContactsManager` or `IdentityClient`), three runs, one with `--test-threads=1` | 350 passed, 0 failed each (53 of 53 binaries) |
| `--test 'arch_*'` | 37 binaries, 195 passed |
| `--test fixtures_replay`, `--test readme_examples`, `--test front_page` | 1, 1 and 10 passed |
| `cargo +1.95.0 semver-checks check-release --baseline-rev origin/beta --all-features --release-type minor` (0.51.0) | 202 checks pass, 58 skip, no update required |
| `tools/ratchet/run --check --against origin/beta` | all 7 counters, oversized-file limits and mutation floors pass |
| `mutants_entries.py` | PASS, 28 entries |
| `rows_from_sources.py --check` | 0 refusals |
| gitleaks, git mode, `origin/beta..HEAD` | no leaks |

Not run: the whole suite (`--tests`), the Linux and Windows cells and the
other five wasm32 slices are CI's; no `cargo mutants` run over the two
changed files (the nightly's surfaces do not name `src/identity/`).

## Files under `src/`

`src/identity/contacts.rs`, `src/identity/contacts_record.rs`, and the manual
`src/identity/CLAUDE.md`.

## The fold of the three reads (lane fix-959-contacts-conform-fold)

Three items, one commit on the rebase lane's `dff3a547`, both rebased onto
beta `6b09e265` (beta moved from `006a8e58` during the gate; no conflict).

| Item | The change | The reference | RED (a scratch copy of the tip, the line put back) |
|---|---|---|---|
| The by-key door drops a failed cold listing (the rule read) | `src/identity/client.rs`: `get_contact(..).await?` in `resolve_by_identity_key` with contacts | `IdentityClient.ts:331-334` (a boolean option is `contactErrorMode: 'throw'`), `:398` (`throw error`), `:575` | `the_by_key_door_answers_a_failed_cold_listing_with_the_wallets_error_959`: `unwrap_err()` on `Ok` |
| The cold update's validation has no test (the strength read) | no source change: `a_cold_update_the_validator_refuses_asks_the_wallet_nothing_959` | `ContactsManager.ts:528` (`validateContact`) before `:529-531` (the cache, then `getContacts()`): validate before the load, as `update_contact` already did | `record::record_of(&updates)?;` deleted: `(ContactNotFound(..), ["listOutputs"])` |
| Notes alone, tags alone (the same read's minor) | no source change: two cells added to the recorder's `STATED_959` and `a_metadata_of_notes_alone_or_tags_alone_reads_as_no_metadata_959` | the recorded record: `metadata` `{"notes": ..}` and `{"tags": [..]}` at the four reads | `before != 0` changed to `before > 1`: `Some(Object {})` where `None` |

The vector: the recorder reproduced the committed file byte for byte before
the edit (SHA-256 `2045c906...b7fd6d`); with the two cells its two runs are
identical (SHA-256 `06f19a8d...26e073`), one line of the file differs (the
`stated_959` line), its three older cells and every other member equal.
`ts-stack@edf6e03` bundled with bun by the #326 recipe, Node v22.18.0.

