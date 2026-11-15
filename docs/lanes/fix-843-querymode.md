# Lane fix-843-querymode: one `QueryMode` in the wallet

#843, the line of its comment on the same-name public types ("`QueryMode` is
declared twice (`src/wallet/types.rs:925`, `src/wallet/validation.rs:856`)");
the captain's ruling of 2026-11-15, given in the lane's brief: the copy is
deleted and `validation` re-exports the `types` one. Additive. Started from
beta `d892e206` (`origin/beta`'s tip at the start and at the gate).

The other pair that comment names (`BroadcastResult`, an enum in `identity` and
an alias in `transaction`) is not this lane's and is untouched.

## The two declarations, side by side (at `d892e206`)

| | Variants | Has | Named by |
|---|---|---|---|
| `src/wallet/types.rs:925` | `Any` (default), `All` | `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Default`, serde (lower case), `as_str`, `FromStr` | `ListOutputsArgs::tag_query_mode`, `ListActionsArgs::label_query_mode`, `wallet::QueryMode` (the re-export of `wallet/mod.rs`), the wire, the kvstore's local store, the tests |
| `src/wallet/validation.rs:856` | `Any`, `All` | `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq` | `validate_query_mode`'s answer, `ValidListOutputsArgs::tag_query_mode`, `ValidListActionsArgs::label_query_mode`, the module's unit test; nothing outside the file |

The references hold one type each: `ts-stack@edf6e03` a string union
(`'any' | 'all'`, `Wallet.interfaces.ts:487,632`), which its validators return
as they read it (`validationHelpers.ts:1623-1625`, `:1686-1688`: undefined or
`'any'` is `'any'`, `'all'` is `'all'`, anything else refused); go-sdk@2ca481c
one `QueryMode` string type (`wallet/interfaces.go:286-290`).
`validate_query_mode` reads the same three cases and refuses the rest in this
crate's own words, older than this lane and unchanged by it.

## The change

`src/wallet/validation.rs`: the enum is deleted; in its place
`pub use super::types::QueryMode;`, with a doc comment saying what it is, and
`validate_query_mode`'s doc comment says its three cases. No other file under
`src/` moves; `src/wallet/wire/` is not touched (another lane's today).

## RED

A scratch copy of `d892e206` (`git archive` under the lane's out folder,
target `/Volumes/Lanes/targets/fix-843-querymode-red`, both removed) with
`tests/wallet_query_mode_one_type_843.rs` overlaid,
`cargo test --features wallet --test wallet_query_mode_one_type_843`: the file
does not compile, 16 errors.

- `validate_query_modes_answer_goes_into_a_wallet_argument_843`: E0308 twice
  (`tag_query_mode: Some(mode)`, `label_query_mode: Some(mode)`: expected
  `bsv_rs::wallet::QueryMode`, found `bsv_rs::wallet::validation::QueryMode`).
- `the_validation_path_and_the_types_path_name_one_query_mode_843`: E0308 at
  each of the two `one_type` calls, at the typed `let` and at its comparison;
  E0599 for `default` and for `as_str` at the `validation` path; E0277 for
  `Serialize` and for `Hash` there.
- `the_validated_argument_records_hold_the_wallets_query_mode_843`: E0308 at
  each of the two readers' return.
- `validate_query_mode_keeps_its_verdicts_and_words_843`: no RED, a pin of the
  unchanged validator (the module's own unit test held the three accepted
  cases before; the refused texts and the words are pinned here).

On the tip the three are ordinary tests: a regression is a test file that does
not build, which CI's test step reports as a failure of the file. No
`compile_fail` doc test is added: there is nothing that must NOT compile.

## Measured

- `cargo semver-checks` 0.51.0 on a shared clone holding the change, baseline
  `d892e206`, the command of beta's `semver` job
  (`check-release --baseline-rev <base> --all-features --release-type minor`):
  202 checks, 202 pass, 58 skip, "no semver update required"; with
  `--release-type patch`: 229 pass, 31 skip. Run under rustc 1.98.1, this
  host's default; the job's toolchain is its own.
- The dependents on this host, read at their checked-out heads by `grep` over
  their `*.rs` outside `target/`: `bsv-wallet-toolbox-rs` `a3377ef0`,
  `bsv-wallet-cli` `f4285bf`, `bsv-overlay-cloudflare` `2efad2f0`,
  `rust-message-box` `08418ec`, `bsv-middleware-rs` `3cb76f0`,
  `chaintracks-cloudflare` `ea8d9a6`, `bsv-dd` `e9d69436`. Lines naming
  `wallet::validation`: 0 in each. Lines naming `validate_query_mode`,
  `ValidListOutputsArgs` or `ValidListActionsArgs`: 0 in each. An `impl` of
  anything for a `QueryMode`: 0 in each. `bsv-middleware-cloudflare` and
  `bsv-worm` are no folder here; no other dependent was read.
- The one break in theory: a caller's own trait implemented for both paths'
  types is two impls for one type since the change (E0119). The Migration line
  of the CHANGELOG states it.

## Beside the lane: the two `validate_satoshis`

Not built, described for the captain. The issue's text and its six comments
name no `validate_satoshis` (a search of the issue as read on 2026-11-15: 0
lines); the pair is in the tree all the same:

- `wallet::types::validate_satoshis(value, name) -> Result<u64>`
  (`src/wallet/types.rs:1610`), re-exported as `wallet::validate_satoshis`:
  refuses a value above `MAX_SATOSHIS`.
- `wallet::validation::validate_satoshis(value, name, min: Option<u64>) -> Result<u64>`
  (`src/wallet/validation.rs:57`): the same refusal in the same words, then,
  with `Some(min)`, a value below it (`Invalid <name>: must be at least <min>
  satoshis`). Called by `validate_create_action_output`.

They are not the same kind of twin as the enum was. The two enums were one
shape under two identities, so a re-export merged them and nothing a caller
wrote stopped compiling. The two functions have different signatures: one name
cannot be both, so a re-export of either at the other's path breaks every call
there (an argument count). With `None` the three-argument one answers exactly
as the two-argument one, so the additive merge is the two-argument body
calling the three-argument one with `None`, both names kept; removing either
name is a break and a question for the break window.

## The gate (foreground, one cargo at a time, `CARGO_BUILD_JOBS=4`)

- Rustfmt, the lint job's three lines: clean.
- `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`: clean.
- `cargo check --all-targets --all-features`: clean.
- `cargo test --features "full,http" --lib wallet::`: 186 passed, three times
  (the third `--test-threads=1`); `--test wallet_query_mode_one_type_843
  --test wallet_tests`: 4 and 57 passed, three times (the third single
  threaded).
- `cargo test --features "full,http" --test 'arch_*'` (in two globs, 38
  files): 201 passed, 0 failed, 1 ignored. `--test fixtures_replay --test
  readme_examples`: 1 and 1 passed.
- The wasm32 slice of rule 6: builds.
- `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features`: clean;
  `cargo test --doc --all-features wallet::validation`: 12 passed.
- `tools/ratchet/run --check --against origin/beta`, `mutants_entries.py`,
  `rows_from_sources.py --check`, gitleaks over `origin/beta..HEAD`: pass.

Not run: the whole suite (the lane ran the touched module and the gate's
files), the Linux and Windows cells, a mutation run.
