# Lane fix-818b: the identity client's by-key, attribute and discovery doors make the reference wallet's argument check

#818 line 2, filed as #905 (PR #897's rule read, row R1); blocks-cut. Started
from beta `5a87392e` (`origin/beta`'s tip at the start). The base holds PR
#897 (`src/identity/client_attributes_818_tests.rs` present); `js_order`'s
body moved unchanged, no case added to `identity_attributes_751.json` or
`identity_query_bounds_756.json`.

## The site, side by side

| | Door | Argument check | Words |
|---|---|---|---|
| `ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:569`, `:614` | `resolveByIdentityKey`, `resolveByAttributes` | handed to the wallet | |
| `packages/sdk/src/wallet/WalletClient.ts:509-511`, `:524` | `discoverByIdentityKey`, `discoverByAttributes` | `validateDiscoverByIdentityKeyArgs`, `validateDiscoverByAttributesArgs` before `connectToSubstrate` | `WERR_INVALID_PARAMETER`, code 6 |
| `packages/wallet/wallet-toolbox/src/Wallet.ts:971`, `:1004`, `:1012`, `:1029` | the toolbox wallet | the same two; asks with the text as given, filters by the validated key | the same |
| `packages/sdk/src/identity/ContactsManager.ts:316-317`, `:69-94` | `getContacts(identityKey)`, with contacts, ahead of the wallet (`IdentityClient.ts:575`) | `validateIdentityKey` | `Invalid contact: identityKey ...` |
| this crate at `5a87392e` `src/identity/client.rs:603-638`, `:665-727`, `:754-761`, `:783-798` | the four doors | none | `Ok([])`, one question sent, the host charged |
| this crate after the lane | the four doors | `client_door_args.rs` over `wallet::validate_discover_by_identity_key_args` / `_attributes_args`; with contacts `contacts::contact_identity_key`; the by-type door's type `query_bounds::certificate_type` | the reference's |

## The recording

`tests/support/identity_door_args_818b.mjs`, Node v22.18.0 (`~/.nvm/versions/node/v22.18.0/bin/node`), on a bun bundle of `ts-stack@edf6e03`'s `packages/sdk` and the toolbox's `filterCertificatesByIdentityKey` (the recipe in the script's header; bundle under `/Volumes/Lanes/out/bsv-rs/fix-818b/ref`). Two runs byte-identical. 46 cases (17 keys, 25 maps, 4 limits) and 2 subject cells. Cells that read otherwise than the brief expected, the recording the port: `key_x_p_minus_1` is refused (p - 1 is no point's x); U+FEFF is trimmed by JavaScript's `trim` and the padded key read; U+0085 is kept and refused `even length, not 67.`; with contacts the reference's `resolveByAttributes` loads the contacts (one `listOutputs`) before its wallet refuses, the same words (stated, not followed: here the map is judged before the contacts load).

## RED

A scratch copy of `5a87392e` (`git archive`), the two test files and the vector overlaid, target `/Volumes/Lanes/targets/fix-818b-red` (removed with the copy):

- `tests/identity_door_args_818b.rs`: 7 of 7 RED. `resolve_by_identity_key_refuses_a_key_the_wallet_door_refuses_before_any_host_818b`, `with_contacts_the_contact_rule_refuses_ahead_in_its_words_818b`, `discover_certificates_refuses_a_key_the_wallet_door_refuses_before_any_host_818b`, `discover_certificates_by_type_refuses_a_key_the_wallet_door_refuses_818b`, `discover_certificates_by_type_refuses_a_type_query_refuses_818b`, `resolve_by_attributes_refuses_a_map_the_wallet_door_refuses_before_any_host_818b`: `Ok([]), 1 sent` on every refused cell; `a_padded_or_upper_case_key_keeps_its_subjects_certificate_818b`: `left: 0, right: 1` at the padded key.
- `tests/wallet_discovery_args_818b.rs`: compile-RED (E0432, neither validator).

Pins moved to the refusal: `tests/identity_query_attributes_751.rs` (the empty map), `tests/identity_discover_type_744.rs` `the_asked_type_is_compared_as_its_canonical_text_744` (the unpadded type), `tests/identity_lock_position_537.rs`' key-only case (asked under `02aa` until now, the generator's key since; its skip unchanged).

## The gate

Every `test result:` line summed: 710 passed, 0 failed, 4 ignored (lib `identity` 117; lib `wallet` 206; 44 integration binaries, every `tests/identity_*.rs`, the two new files, `wallet_wire_discovery_validation_495`, `fixtures_replay`, `auth_identity_certificate_field_order_394`, 259 passed and 4 ignored; 27 `arch_*` binaries 125; `readme_examples` 1; the two new doc tests 2). The three fmt lines, clippy `-D warnings` on all targets and features, rustdoc `-D warnings`, the wasm32 slice (and `identity,wasm`), `cargo build --examples --all-features`, the ratchet against `5a87392e` (7 counters pass), `mutants_entries.py` (28 entries), `rows_from_sources.py --check` (0 refusals) and gitleaks over the lane's commit. No conformance run (no script or BEEF path touched).

`rows_from_sources.py` (without `--check`) rewrites a code span holding `|` or `||` as `` ` | ` `` in two rows it does not own (`front_page.rs`, `shamir_backup_854.rs`): restored by hand here, a finding for the captain.

## Not this lane's

The wallet's own sending doors call neither validator: `src/wallet/wire/discovery.rs:14-70`, `src/wallet/substrates/http_json.rs:536-551` (its trait arm at `:792-806` forwards to it), `src/wallet/client.rs:433-445`, and `src/auth/clients/shared_wallet.rs:161-168` (a forwarder the brief did not name). A row with the captain.
