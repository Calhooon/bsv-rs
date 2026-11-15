# Lane fix-843dall: `ALL` is a slice on `WalletRefusalClass` and `Kind`

#843, the freeze plan's Q4; BREAKING on beta, decided 3 of 3 by independent
design reads (root rule 13): `ALL: &'static [Self]` for every public constant
whose type carries the count of an open set. Started from beta `d892e206`
(`origin/beta`'s tip at the start; #896 on it: `src/util/non_exhaustive.rs`
and `tests/arch_non_exhaustive_pins_819.rs` exist). #843 stays open.

## The sites, side by side

| side | lines | before | after |
|---|---|---|---|
| reference | `ts-stack@edf6e03` `packages/sdk/src/wallet/WalletError.ts:71-80`, `:82` | `export enum walletErrors { unknownError = 1, .. abortRefused = 8 }`; `export type WalletErrorCode = keyof typeof walletErrors`: no count in any type; the toolbox's sixteen `WERR_*` by name (`packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts:8-260`) | nothing to port |
| Go | `go-sdk@2ca481c` `wallet/error.go:8-12` | `type Error struct { Code byte; Message string; Stack string }`: no table | nothing |
| this crate | `src/error/wallet_refusal.rs:99` at `d892e206` | `pub const ALL: [Self; 20] = [` | `pub const ALL: &'static [Self] = &[` (`:100`), the same twenty in the same order |
| this crate | `src/transaction/beef_stream/reason.rs:95` at `d892e206` | `pub const ALL: [Kind; 26] = [` | `pub const ALL: &'static [Kind] = &[` (`:96`), the same twenty-six in the Lean's order |

Why it was wrong: both enums are `#[non_exhaustive]`, and each variant added
changed a public type. `Kind::ALL` is `[Kind; 18]` at v0.4.0, 19 at v0.4.1,
20 at v0.4.3, 24 from v0.5.0, 25 at v0.9.0-beta.1, 26 since beta.2. The
crate's precedent: `KnownCertificateType::all() -> &'static [Self]`
(`src/identity/types.rs`).

## The base check

The freeze lists' three scans on `d892e206`, against `6bc872d7` (the same
commands run on a `git archive` of its `src/`, the two outputs diffed):

| scan | `6bc872d7` | `d892e206` | the difference |
|---|---|---|---|
| structs named `*Config`, `*Options`, `*Params`, `*Limits` | 34, 3 attributed | 34, 6 attributed | `AuthFetchOptions`, `PeerOptions`, `WebSocketTransportOptions` attributed: #843d8a, under `## [Unreleased]` |
| `pub enum` | 70, 18 attributed | 74, 18 attributed | four more lines, none attributed: `Sample` and `Other`, twice each, the sample types inside `src/util/non_exhaustive.rs`'s macro doc tests (#819's fold, #896, under `## [Unreleased]`); a plain `grep -c non_exhaustive` over the scan's output reads 22 because those four lines carry the file's name |
| `#[deprecated` | 13 lines matching `#\[deprecated` (11 attributes; two are prose) | the same 13 | none (the lines equal after sorting) |

This lane's two scans hold exactly: `git grep -n -P '^\s*pub (const|static) \w+: \['`
is 13 lines (the two `ALL`s, nine BIP-39 wordlists `[&str; 2048]`, two
`[u8; 4]` version constants of `src/messages/mod.rs`); `git grep -n -P '::ALL\b'`
over `src`, `tests`, `benches`, `examples`, `fuzz` is 21 lines.

## The compile's table

A scratch copy of `d892e206` (`git archive` under
`/Volumes/Lanes/out/bsv-rs/fix-843dall/scratch`, target
`/Volumes/Lanes/targets/fix-843dall-scratch`) with the two type lines changed
and nothing else: `cargo check --lib --all-features`, the library mended,
`cargo check --all-targets --all-features --keep-going`, `cargo check
--manifest-path fuzz/Cargo.toml` (with the fuzz line unmended, then mended),
`cargo clippy --all-targets --all-features -- -D warnings`. Line numbers are
`d892e206`'s; where the compiler's error sits on a later line of the same
statement or loop body, that line is given. No doc comment names `ALL` in
code, so the doc tests name no site (run on the tip, 384 passed).

| # | `::ALL` line | named by | at | mend |
|---|---|---|---|---|
| 1 | `src/error/wallet_refusal.rs:203` (`from_name`) | E0308 | `:203` | `.into_iter()` to `.iter().copied()` |
| 2 | `src/error/wallet_refusal.rs:268` | stands | | `.iter().map(..)` |
| 3 | `src/error/wallet_refusal.rs:273` (#896's test) | E0308 | `:274` (`position(value)`) | `.into_iter()` to `.iter().copied()` |
| 4 | `src/transaction/beef_stream/reason.rs:352` | stands | | `.iter().map(..)` |
| 5 | `src/transaction/beef_stream/reason.rs:354` (#896's test) | E0308 | `:355` | `.into_iter()` to `.iter().copied()` |
| 6 | `fuzz/fuzz_targets/fuzz_beef_parser.rs:55` | E0308 | `:56` | `.into_iter()` to `.iter().copied()` |
| 7 | `tests/beef_stream.rs:301` | E0277 | `:301` | `.into_iter()` to `.iter().copied()` |
| 8 | `tests/beef_stream.rs:302` | stands | | `.len()` |
| 9 | `tests/beef_two_readers_agree.rs:88` | E0308 | `:89` | `.into_iter()` to `.iter().copied()` |
| 10 | `tests/merkle_path_two_readers_agree.rs:73` | E0308 | `:74` | `.into_iter()` to `.iter().copied()` |
| 11 | `tests/wallet_fault_shapes_819.rs:69` | clippy `needless_borrow` | `:69` | `&T::ALL` to `T::ALL` |
| 12 | `tests/wallet_fault_shapes_819.rs:78` | stands | | `.len()` |
| 13 | `tests/wallet_fault_shapes_819.rs:79` | E0277 | `:79` | `.into_iter()` to `.iter().copied()` |
| 14 | `tests/wallet_fault_shapes_819.rs:81` | E0308 | `:82` | `for class in` to `for &class in` |
| 15 | `tests/wallet_fault_wire_439.rs:36` | E0308 | `:39`, `:43` | `for &class in` |
| 16 | `tests/wallet_http_json_refusal_class.rs:67` | E0308 | `:79` | `for &class in` |
| 17 | `tests/wire_wallet_refusal_class.rs:157` | stands | | `.iter().map(..)` |
| 18 | `tests/wire_wallet_refusal_class.rs:169` | E0308 | `:170`, `:172`, `:175` | `for &class in` |
| 19 | `tests/wire_wallet_refusal_class.rs:227` | stands | | `.iter().map(..)` |
| 20 | `tests/wire_wallet_refusal_class.rs:271` | E0308 | `:273` | `for &class in` |
| 21 | `tests/wire_wallet_refusal_class.rs:326` | E0308 | `:327`, `:331` | `for &class in` |

Against the brief's reading: 14 lines break at compile (the brief: ten of the
13 lines of `6bc872d7`, one library, one fuzz, eight in six test files, and
four of #896's eight), clippy names `tests/wallet_fault_shapes_819.rs:69`,
six stand. The counts agree. Three rules, one per class: `.into_iter()` to
`.iter().copied()` (8), `for x in` to `for &x in` (6), `&T::ALL` to `T::ALL`
(1). No assertion line of an existing file moved
(`git diff -U0 --diff-filter=M d892e206 -- src tests fuzz | grep -c -E '^[+-].*assert'`
is 0).

## RED

Watched on a scratch copy of `d892e206` (`git archive`, never a checkout of a
dirty tree), the tip's two new files overlaid one at a time:

- `tests/all_constants_843dall.rs`: compile-RED, 4 errors, each E0308: the
  two typed bindings (`:22:46`, `:55:32`) and two Migration forms (`:97:9`,
  `for &class in` over an array; `:109:22`, `Kind::ALL` handed as `&[Kind]`).
  Green on the tip, 3 passed.
- `tests/arch_array_constants_843dall.rs`: 2 of 5 RED, naming exactly
  `src/error/wallet_refusal.rs:99: ALL is public and typed [Self ; 20]` and
  `src/transaction/beef_stream/reason.rs:95: ALL is public and typed [Kind ; 26]`
  (and the text pin of the two declarations). Green on the tip, 5 passed.

## The plants (#896's guards)

`cargo test --features "full,http" --lib all_holds_every_variant` on the tip:
2 passed. Then on a scratch copy of the tip, one at a time, each reverted:

| plant | result |
|---|---|
| `Kind::MismatchedNode` dropped from `Kind::ALL` | RED at run time (`names` against `VARIANT_NAMES`). On the base the array's count refused this at compile (`[Kind; 26]` with 25 entries), so this test is now the guard of a dropped entry |
| `InvalidHmac` and `InvalidSignature` swapped in `WalletRefusalClass::ALL` | RED at run time |
| a variant `Planted` added to `Kind` alone | E0004 at `position` (`reason.rs:323`) |
| the same with its arm `Kind::Planted => 26` and no `ALL` entry | RED at run time |

This lane opens no type: `tests/arch_non_exhaustive_pins_819.rs` passes, its
lists untouched.

## The break's evidence

- Rustdoc JSON (`cargo +nightly rustdoc --lib --all-features -- -Z unstable-options --output-format json`,
  nightly 1.101.0 of 2026-10-12, each tree its own target dir), compared item
  by item with ids resolved to names and spans left out: 17,681 items of this
  crate on each side; two differ, the two `ALL` associated constants (the
  type `array len 20 of Self` to `&'static` slice of `Self`, `array len 26 of
  Kind` to `&'static` slice of `Kind`, and the doc sentence added); no other
  item.
- `cargo semver-checks check-release --release-type patch --baseline-rev d892e206 --all-features`
  (0.51.0): `229 checks: 229 pass, 31 skip`, `no semver update required`. No
  lint fires: at this version the tool does not judge an associated constant's
  type. The JSON difference and the compile-RED witness are the evidence.
- The dependents (`git -C <path> grep -n -P '(Kind|WalletRefusalClass)(::ALL\b|; *\d+\])' <ref> -- '*.rs'`,
  the local clones' remote-tracking refs as they stood on 2026-11-15, read
  only):

| dependent | ref | sites of this crate's constants |
|---|---|---|
| `bsv-wallet-toolbox-rs` | `origin/main` `3ddf48db` | 0 |
| `bsv-wallet-toolbox-rs` | `origin/beta` `184c4182` | 1: `src/error/refusal_tests.rs:99`, `for class in WalletRefusalClass::ALL {` (a test; `class` is moved into a field and compared, so it breaks, mended by `for &class in`) |
| `bsv-wallet-cli` | `origin/main` `2cc76c9d` | 0 |
| `bsv-wallet-cli` | `origin/beta` `6dc14ef5` | 0 (`src/store/origin_grants/migrate_tests.rs:316` names its own `Kind`, `rows.rs:14`, `ALL: [Self; 4]`) |
| `bsv-overlay-cloudflare` | `origin/main` `2abcd748` (no `beta`) | 0 (`RecordKind::ALL` is its own) |
| `rust-message-box` | `origin/main` `44a63204` (no `beta`) | 0 |

  None names the array type.
- No behaviour moves: the one library use is `from_name`, the same order and
  answer.

## The gate's counts

The whole suite, `--features "full,http,websocket" --no-fail-fast`, as the
lib, the `--test` names in eight batches (each under ten minutes) and the doc
tests, every `test result:` line summed:

| | lib | integration | doc | total |
|---|---|---|---|---|
| scratch base `d892e206` | 1,876 passed, 4 ignored | 408 files: 4,153 passed, 35 ignored | 384 passed, 128 ignored | 6,413 passed, 0 failed, 167 ignored |
| tip | 1,876 passed, 4 ignored | 410 files: 4,161 passed, 35 ignored | 384 passed, 128 ignored | 6,421 passed, 0 failed, 167 ignored |

The eight more: `all_constants_843dall.rs`' three
(`wallet_refusal_class_all_is_a_static_slice_of_its_twenty_each_once_843dall`,
`kind_all_is_a_static_slice_of_its_twenty_six_each_once_843dall`,
`the_migration_forms_compile_and_agree_843dall`) and
`arch_array_constants_843dall.rs`' five
(`no_public_constant_static_or_return_is_an_array_of_an_open_set_843dall`,
`the_two_all_tables_are_slices_843dall`, `the_scan_reads_each_form_843dall`,
`the_scan_passes_what_is_no_open_array_843dall`,
`a_site_without_a_row_and_a_row_naming_nothing_are_each_refused_843dall`).

Also green on the tip: the three `cargo fmt` lines of beta's `lint` job;
`cargo clippy --all-targets --all-features -- -D warnings`;
`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`;
`cargo test --features "full,http" --lib error` (31) and `--lib beef_stream`
(5); the eight test files the `::ALL` grep names with `all_constants_843dall`
under `full,http` (124 passed); `cargo check --manifest-path fuzz/Cargo.toml`;
`cargo test --doc --all-features` (384 passed, 128 ignored); the wasm32
combined slice; `cargo test --features "full,http" --test 'arch_*'` (39
binaries, 206 passed, 1 ignored); `cargo build --examples --all-features`;
`cargo test --test readme_examples`; `tools/ratchet/run --check --against
d892e206`; `mutants_entries.py`; `rows_from_sources.py --check`; gitleaks over
the lane's commit. The conformance census on the tip, the corpus at the
default `../ts-stack/conformance` (`--test conformance_scripts --test
conformance_beef -- --nocapture`): 5,116 total, 4,121 run, 4,110 passed, 958
unsupported, 37 skipped, 11 known failures, 0 failures, 0 panics, the pinned
figures since #816; the scratch base sits at another path and skipped the
corpus, the two files' test counts the same either way.

## The forms the scan cannot see, surveyed once (the strength read)

`tests/arch_array_constants_843dall.rs` names in its header what its lexical
scan does not read: an array behind a `pub type`, a public field, a trait's
method or associated constant, an item a macro writes. The rustdoc JSON
comparison above diffs base against tip; it does not list those forms. The
strength read (`lane/review-strength-fix-843dall`, 2026-11-15, at `73afabc6`,
no cargo) surveyed them by `git grep -P` over `src/`:

| form | found | open-set array |
|---|---|---|
| `pub type` aliased to an array | `src/primitives/mod.rs:30` `Hash32 = [u8; 32]`, `src/wallet/types.rs:161` `TxId = [u8; 32]` | none (bytes) |
| a `pub` field typed as an array | `src/wallet/key_args.rs:144` `hmac: [u8; 32]` | none (bytes) |
| a `fn` without `pub` returning an array (trait items, private helpers) | `src/compat/bip39/mnemonic.rs:86` `Language::wordlist` (private, `[&str; 2048]`), `src/wallet/wire/linkage.rs:60` (private), three in test modules | none public |
| a `const` without `pub` typed as an array | seventeen, every one private or in a test module | none public |
| a macro writing a constant | `non_exhaustive_enum!`'s `VARIANT_NAMES`, `pub(crate)`, under `cfg(test)`, a slice | none |

No public open-set array hides in a form the scan cannot see at this tip. A
grep is lexical too (a field typed through a multi-line generic is not read);
a rustdoc JSON survey of every item's type for `array` with a non-`u8`
element would close that gap once and was not run (no cargo in this read).
