# Lane fix-843d8c: eighteen configuration structs take `#[non_exhaustive]`

#843, the freeze plan's row 8, part c; BREAKING, on the captain's rulings of
2026-11-12 (three independent design reads, the split 3 of 3; not reopened).
Run on 2026-11-15 from `1eda0808` (`origin/lane/fix-843d8b-2`, pull request
#1005, part b of the row, one commit on beta `d892e206`), by the captain's
word for this run: no reset to `origin/beta`. No reference line decides the
row: the shape is Rust's own, and no wire byte, verdict, default value or
error text moves.

## The base check (step 1), at `1eda0808`

| Figure | The brief, at `6bc872d7` | The captain, at `d892e206` | Measured at `1eda0808` | Traced to |
|---|---|---|---|---|
| all-public `Config`, `Options`, `Params`, `Limits` structs | 34, 3 attributed | 34, 6 | 34, 8 | part a (`b93f81bd`, three) and part b (`1eda0808`, two) |
| top-level public enums | 70, 18 attributed | 74, 18 | 74, 18 | the captain's restated figure |
| `#[deprecated` grep lines | 13 | 13 | 13 | unchanged |
| the names grep under `tests`, `examples`, `benches`, `fuzz` | 35 lines in 15 files (31 sites in 12 files, 4 no sites) | | 37 lines in 15 files (33 sites in 12 files, 4 no sites) | `550123eb` (#815: a second `StorageDownloaderConfig` literal in `tests/storage_advertisement_envelope_544.rs`) and `b31fa910` (#98: a third `BlockHeadersServiceConfig` literal in `tests/transport_fault_trackers.rs`) |
| the machine's pending list | the 19 names | | 18 rows, `PENDING_LEN` 18 | part a (`b93f81bd`) classed `ValidCreateActionOptions` as a `Record` row already, with the reference's lines |

The 19 names of the brief's `N` were each present and unattributed. Both
machines are on the base (`tests/arch_non_exhaustive_843d.rs`,
`tests/arch_non_exhaustive_pins_819.rs`, #896's reader with part a's generic
form), and both were taught. The four lines of the grep that are no sites:
two strings (`tests/arch_arc_deprecated.rs:102`, `tests/secret_debug.rs`'s
`Debug` text) and two return types (`tests/identity_reveal_create_action_315.rs:53`,
`tests/identity_wallet_calls_318.rs:114`).

## The decision built

`ValidCreateActionOptions` as briefed (the ruling's sentence): no attribute,
a `Record` row beside its six `Valid*` siblings. The row was on the base
already (part a), its reason the reference's lines
(`packages/sdk/src/wallet/validationHelpers.ts:683-689` over `:676-681` at
`edf6e03`, read again in this run: nine members, eight of them this crate's,
no `trust_self`). `src/wallet/validation.rs` is untouched (1,113 of 1,113
lines).

## Each struct, before and after

Before: `pub struct` with every field `pub`, built by a struct expression
anywhere. After: `#[non_exhaustive]` on its own line above `pub struct`, the
`compile_fail,E0639` `rebuilt` block and its `kept` twin in its doc at its
public path, `assert_no_drop!` after it, every field still `pub` with its
type, every default value, constructor and setter that existed unchanged.

| Struct | File (tip) | Public path of its pin | New doors |
|---|---|---|---|
| `ReputationConfig` | `src/overlay/reputation_config.rs` (moved) | `bsv_rs::overlay::ReputationConfig` | 7 setters |
| `HistorianConfig<T, C>` | `src/overlay/historian.rs` | `bsv_rs::overlay::HistorianConfig<u8, u8>` | 4 setters; `impl<T, C> Default` written out, no bound on `T` or `C`, the derive's values |
| `StorageDownloaderConfig` | `src/storage/downloader.rs` | `bsv_rs::storage::StorageDownloaderConfig` | 3 setters |
| `StorageUploaderConfig` | `src/storage/uploader.rs` | `bsv_rs::storage::StorageUploaderConfig` | none (`new(storage_url)`, `with_retention_minutes`) |
| `RegistryClientConfig` | `src/registry/client.rs` | `bsv_rs::registry::RegistryClientConfig` | none (`with_network`, `with_resolver`, `with_originator`, `with_delayed_broadcast`) |
| `KVStoreConfig` | `src/kvstore/types.rs` | `bsv_rs::kvstore::KVStoreConfig` | none (six setters) |
| `KVStoreGetOptions`, `KVStoreSetOptions`, `KVStoreRemoveOptions` | `src/kvstore/options.rs` (moved) | `bsv_rs::kvstore::<Name>` | none (three, five, two setters) |
| `IdentityClientConfig` | `src/identity/types.rs` | `bsv_rs::identity::IdentityClientConfig` | 3 setters (`protocol_id`, `key_id`, `output_index`) |
| `ContactsManagerConfig` | `src/identity/types.rs` | `bsv_rs::identity::ContactsManagerConfig` | 2 setters (`protocol_id`, `basket`) |
| `TotpOptions` | `src/totp/options.rs` (moved) | `bsv_rs::totp::TotpOptions` | 4 setters |
| `TotpValidateOptions` | `src/totp/options.rs` (moved) | `bsv_rs::totp::TotpValidateOptions` | 2 setters |
| `TeranodeConfig` | `src/transaction/broadcasters/teranode.rs` | `bsv_rs::transaction::TeranodeConfig` | `new(url: impl Into<String>)` (no key, 30,000 ms), 2 setters |
| `WocBroadcastConfig` | `src/transaction/broadcasters/whatsonchain.rs` | `bsv_rs::transaction::WocBroadcastConfig` | 4 setters |
| `BlockHeadersServiceConfig` | `src/transaction/chain_trackers/block_headers_service.rs` | `bsv_rs::transaction::BlockHeadersServiceConfig` | 3 setters |
| `LivePolicyConfig` | `src/transaction/fee_models/live_policy.rs` | `bsv_rs::transaction::LivePolicyConfig` | 5 setters (`impl Default for LivePolicyConfig {` as written) |
| `CacheConfig` | `src/wallet/cached_key_deriver.rs` | `bsv_rs::wallet::CacheConfig` | 1 setter |

Forty setters and one `new`, each setter `#[must_use]`, one `///` line,
`with_<field>(mut self, <field>: <the field's own type>) -> Self`, in field
order (`with_ctx_key_fn` also `#[allow(clippy::type_complexity)]`, as the
struct). The trailing comment of the four `#[derive(Clone)] // Debug redacts
...` lines is a `//` line of its own above the derive. The literals inside
the crate stay.

The moves, each for its old file's line ceiling, each re-exported where it
was (the rustdoc JSON's public paths: 1,740 on the base, 1,740 on the tip,
none lost, none gained):

- `ReputationConfig` and its `Default`: `host_reputation_tracker.rs` to
  `reputation_config.rs` (a private module of `overlay`), `pub use` in
  `host_reputation_tracker.rs`, so `overlay::ReputationConfig` and
  `overlay::host_reputation_tracker::ReputationConfig` both name it.
- `TotpOptions`, `TotpValidateOptions` and their `Default`s: `totp/core.rs`
  (a private module) to `totp/options.rs` (private), `totp`'s `pub use` reads
  them there.
- the three KVStore option records with their impls: `kvstore/types.rs` to
  `kvstore/options.rs` (private), `pub use` in `types.rs`, so
  `kvstore::<Name>` and `kvstore::types::<Name>` both name each.

## The two machines

- `tests/arch_non_exhaustive_pins_819.rs`: `DOC_PINS` 26 to 44 (the eighteen
  doc names, sorted). The reader is unchanged: part a's generic form reads
  `HistorianConfig<T, C>` pinned at `<u8, u8>`.
- `tests/arch_non_exhaustive_843d.rs`: the 18 `Pending` rows removed,
  `PENDING_LEN` 18 to 0 (the variant kept, `#[allow(dead_code)]`, so the
  class and its pin stay for the file's other lane); attributed 14 to 32;
  `NAMED_SETTERS`, four `(file:Name, field, setter)` rows for the setters that
  existed under another name than `with_<field>` (`IdentityClientConfig` and
  `RegistryClientConfig` `network_preset` by `with_network`,
  `RegistryClientConfig` `accept_delayed_broadcast` by
  `with_delayed_broadcast`, `StorageUploaderConfig`
  `default_retention_minutes` by `with_retention_minutes`), read by
  `unset_fields`, and a seventh test,
  `every_named_setter_names_a_field_and_its_method_843d8c`, which refuses a
  row whose struct, field or method is gone or whose field has a
  `with_<field>` too. The two associated `with_originator(o)` pass by name.
  `ASSIGNED` is unchanged (six). Only the rows and lists these structs need
  were touched (row 9's lane edits the same file).

## The sites (step 4)

33 struct expressions in 12 files under `tests/`, by
`rewrite_843d8c.py` (sha256
`047212764350bddfcc6741eb744b4b3e1cbb12e7ec4ddb949f05261d2658a1a1`, kept
under the lane's out folder; Python 3, standard library alone; then
`cargo fmt --all`): `field: v,` becomes `.with_field(v)`, the value's text
untouched. Three hunks by hand, stated:

- `tests/broadcaster_http_tests.rs`: the script left a trailing comment as an
  empty setter; the comment was put back after `.with_timeout_ms(100);`.
- `tests/secret_debug.rs:617`: `url: "https://teranode.invalid".into()`
  became `TeranodeConfig::new("https://teranode.invalid")` (an `.into()` into
  `impl Into<String>` does not infer); the `String` is the same.
- `tests/kvstore_options_342.rs:26`, the full literal of `KVStoreConfig`: its
  setters take `impl Into<String>` and `with_originator` cannot say `None`,
  so `protocol_id`, `service_name` and `originator` are assigned on the value
  built by `default()` and the three setters whose type is the field's
  (`with_token_amount`, `with_topics`, `with_encrypt`), every value it named
  kept.

And the six compiled doc examples under `src/`:
`src/wallet/cached_key_deriver.rs` (two), `src/wallet/mod.rs` (`CacheConfig`);
`src/totp/core.rs` (`TotpOptions`, `TotpValidateOptions`), `src/totp/mod.rs`.
The `ArcConfig` literals stay. `git diff -U0 1eda0808 -- <the 12 files> |
grep -cE '^[+-].*assert'` is 0. No `PeerOptions` line is touched
(`auto_persist_last_session: false` under `tests`: 0 on the base and the tip,
part a having moved the 26 to `.with_auto_persist_last_session(false)`).

## RED before green (step 5)

One scratch tree, `git archive 1eda0808` under the lane's out folder, its
target `/Volumes/Lanes/targets/fix-843d8c-red`; both removed at the end.

(a) `tests/config_setters_843d8c.rs` and the 12 migrated files overlaid on
the base, `cargo test --features "full,http" --no-run --test <name>` for each
of the 13: 80 errors, E0599 79 (no such method) and E0277 1
(`HistorianConfig<Bare, Bare>: Default`); by binary: `config_setters_843d8c`
47 and the E0277, `secret_debug` 9, `storage_tests` 5,
`live_policy_http_tests` 4, `transport_fault_trackers` 3,
`storage_advertisement_envelope_544`, `transport_fault_broadcasters`,
`storage_http_tests` and `wallet_tests` 2 each, `broadcaster_http_tests`,
`overlay_integration_tests` and `storage_lock_position_537` 1 each;
`kvstore_options_342` compiles on the base (the setters it uses existed).

(b) the tip overlaid on the scratch tree with the 18 `#[non_exhaustive]`
lines removed: `cargo test --doc --all-features` 408 passed, 18 failed, the
18 `compile fail` blocks of `ContactsManagerConfig`, `IdentityClientConfig`,
`KVStoreGetOptions`, `KVStoreRemoveOptions`, `KVStoreSetOptions`,
`KVStoreConfig`, `HistorianConfig`, `ReputationConfig`,
`RegistryClientConfig`, `StorageDownloaderConfig`, `StorageUploaderConfig`,
`TotpOptions`, `TotpValidateOptions`, `TeranodeConfig`, `WocBroadcastConfig`,
`BlockHeadersServiceConfig`, `LivePolicyConfig`, `CacheConfig` and no other;
`tests/arch_non_exhaustive_843d.rs` 3 of 7 failed, the table test naming the
same 18 (`every field is pub and it has no #[non_exhaustive]`).

Green on the tip: `config_setters_843d8c` 4 of 4, the two machines 7 and 14
(the ignored doc-log reader run by hand on the tip's doc log, green).

## The gate (step 8), on this host (macOS, no VM; the Linux witness is CI's)

| Run | Base `1eda0808` (scratch tree) | Tip |
|---|---|---|
| `cargo test --features "full,http" --lib` | 1,853 passed, 0 failed, 4 ignored | 1,853, 0, 4 |
| `cargo test --features "full,http" --doc` | 388, 0, 127 | 424, 0, 127 (+36: 18 `compile_fail` blocks and 18 twins) |
| the integration suite, two halves of `--test` names | 409 results: 4,154, 0, 35 | 410 results: 4,159, 0, 35 (+5: the new file's 4 and the machine's seventh test) |
| `cargo test --doc --all-features` | | 426, 0, 128 |

The conformance files ran against the corpus (5,116 total, 4,121 run, 4,110
passed, 958 unsupported, 37 skipped, 11 known failures: the pinned census).
`--lib` by filter on the tip: `overlay` 119, `storage` 36, `registry` 48,
`kvstore` 76, `identity` 126, `totp` 46, `transaction` 263, `wallet` 207, 0
failed. `--test 'arch_*'`: 38 results, 202 passed, 0 failed, 1 ignored. The
three `cargo fmt` lines of beta's `lint` job, `cargo clippy --all-targets
--all-features -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc
--no-deps --all-features`, `cargo build --examples --all-features`, `cargo
test --test readme_examples` (1), the combined wasm32 slice,
`mutants_entries.py` (28 entries), `rows_from_sources.py --check` (0
refusals) and `gitleaks` over the commit: clean.

The ratchet (`tools/ratchet/run --check --against 1eda0808`, its own target
dir): all 7 counters, the oversized-file limits and the mutation floors pass;
`duplicate_windows_40` 7,138 (7,119 on the base by part b's record, the bound
8,257), `pedantic_warnings` 2,659 (the bound 2,661), `missing_docs` 0. The
setters stand in field order everywhere: no counter forced another. Lines
per file:

| File | Base | Tip | Bound |
|---|---|---|---|
| `src/overlay/host_reputation_tracker.rs` | 986 | 954 | 986 |
| `src/overlay/reputation_config.rs` | (new) | 105 | 800 |
| `src/overlay/historian.rs` | 515 | 582 | 800 |
| `src/storage/downloader.rs` | 286 | 330 | 800 |
| `src/storage/uploader.rs` | 445 | 466 | 800 |
| `src/wallet/cached_key_deriver.rs` | 553 | 580 | 800 |
| `src/totp/core.rs` | 930 | 859 | 930 |
| `src/totp/options.rs` | (new) | 158 | 800 |
| `src/transaction/broadcasters/teranode.rs` | 216 | 262 | 800 |
| `src/transaction/broadcasters/whatsonchain.rs` | 364 | 416 | 800 |
| `src/transaction/chain_trackers/block_headers_service.rs` | 289 | 334 | 800 |
| `src/transaction/fee_models/live_policy.rs` | 415 | 474 | 800 |
| `src/identity/types.rs` | 779 | 860 | 886 |
| `src/kvstore/types.rs` | 787 | 685 | 842 |
| `src/kvstore/options.rs` | (new) | 179 | 800 |
| `src/registry/client.rs` | 1,079 | 1,100 | 1,130 |

## The break's evidence (step 6)

`cargo semver-checks check-release --baseline-rev 1eda0808 --all-features
--release-type patch` (0.51.0): 229 checks, 228 pass, 1 fail, 31 skip; the
one lint `struct_marked_non_exhaustive`, on the 18 structs (43 lines, one per
public path of each), no other.

The rustdoc JSON (format 60) of base and tip, each in its own target dir,
diffed by item (`jsondiff.py` under the lane's out folder: items keyed by
kind and path, methods by their impl's type and name; ids, spans and link
tables dropped):

- added, 83: 41 functions (the 40 setters and `TeranodeConfig::new`), the 12
  inherent `impl` blocks that hold them, `impl<T, C> Default for
  HistorianConfig<T, C>` with no bound, and the 6 moved structs with their 23
  fields at their new definition paths;
- removed, 30: the same 6 structs and 23 fields at their old definition
  paths, and `HistorianConfig`'s derived `Default` with its `T: Default, C:
  Default` bounds;
- changed: the other 12 structs (doc text and the `non_exhaustive`
  attribute; with the 6 moved, 18 marked), `HistorianConfig`'s `default`
  (the derive's attributes gone), and doc text alone on
  `CachedKeyDeriver::new`, `Totp::generate`, `Totp::validate` and the modules
  `totp` and `wallet` (the six doc examples);
- public paths reachable from the root: 1,740 and 1,740, none lost.

The dependents, read-only (`git -C <path> grep -n -P
"(?<![A-Za-z0-9_])(<the 19 names>)\s*\{" <ref> -- '*.rs'`): 0 lines on
`bsv-wallet-toolbox-rs` `origin/main` (`3ddf48db`) and `origin/beta`
(`184c4182`), `bsv-wallet-cli` `origin/main` (`2cc76c9`) and `origin/beta`
(`6dc14ef`), `bsv-overlay-cloudflare` `origin/main` (`2abcd748`),
`rust-message-box` `origin/main` (`44a6320`); the last two have no
`origin/beta`. No dependent was edited.

## Not verified here

- No Linux run (CI's). No `cargo mutants` run over the new setters.
- The `pedantic_warnings` figure of the base was not measured in this run
  (the tip's passes its bound).
- The reference lines the CHANGELOG cites were read at `edf6e03` by `git
  show`; nothing of the reference was run (no behaviour is compared).

## Carried onto `e15ebc39` (lane rebase-843d8c, 2026-11-17)

Everything above is the run of 2026-11-15 on `1eda0808` and stands as that
run's record. On 2026-11-17 the change was carried as one commit onto
`e15ebc39` (pull request #1005 on beta `4c5454be`, after the changelog's cut
to `## [0.9.0-beta.8] - 2026-11-16`). What moved with the base:

- Conflicts, five files: `src/kvstore/mod.rs` and `src/overlay/mod.rs` (both
  module lines kept: `options` beside `token_derivation`, `reputation_config`
  beside `rank_change_receiver`); `tests/arch_non_exhaustive_843d.rs`
  (all-public structs 220, attributed 15 to 33, `BeefLinkLimits` of #749 the
  one the base gained); `tests/arch_non_exhaustive_pins_819.rs` (`DOC_PINS`
  27 to 45, both sides' entries kept in order);
  `tests/transport_fault_trackers.rs` (the base's comment on #98's bound
  kept, the literal in the setter form).
- Two documents the pick doubled without a conflict, mended by hand: the root
  `CLAUDE.md`'s pin count (one line, 45 pinned since #843d8c, 27 since
  #843d8b) and three rows of `tests/CLAUDE.md` (the base's rows kept, part
  c's words merged into them; the all-public count restated as 220).
- Four struct expressions of the eighteen that beta gained since, in three
  files, moved to the door form with no assertion changed:
  `tests/beef_link_doors.rs` two (`KVStoreConfig`,
  `StorageDownloaderConfig`), `tests/kvstore_empty_value.rs` one and
  `tests/kvstore_key_bound_signature.rs` one (`KVStoreSetOptions`). With the
  33 above: 37 in 15 files.
- The CHANGELOG rebuilt from the base's file with this entry at the top of
  `## [Unreleased]`, its figures restated (45 pinned, 33 attributed, 37
  expressions).
- RED on this base: a scratch copy of `e15ebc39` with
  `tests/config_setters_843d8c.rs` overlaid, `cargo check --test
  config_setters_843d8c`: 48 errors (E0599 47, E0277 1). The attribute-removal
  run was not repeated here.
- The dependents, read again on 2026-11-17 (the same grep, an upper bound): 0
  literals on `bsv-wallet-toolbox-rs` `origin/main` (`c7fc2539`) and
  `origin/beta` (`b9880eb4`, two `IdentityClientConfig::default()` calls,
  which compile unchanged), `bsv-tracker` (`fdc8896`, `3cfba16`),
  `bsv-wallet-cli` (`16e7e50`, `6dc14ef`), `bsv-middleware-rs` (`5a1fd27`),
  `rust-message-box` (`44a6320`), `chaintracks-cloudflare` (`eff96cb`),
  `bsv-overlay-cloudflare` (`2c626f7c`), `bsv-storage-cloudflare`
  (`e917c94`), `bsv-dd` (`acbbfae8`). No dependent was edited.
