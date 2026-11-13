# Lane fix-843d8a: the auth option structs take `#[non_exhaustive]`

#843, the freeze plan's row 8, part a; BREAKING, on the captain's rulings of
2026-11-12 (three design reads, not reopened). Started from beta `43ee8c85`
(`origin/beta`'s tip at the start, checked after `git fetch origin`).

## The site, side by side

| | Shape | `auto_persist_last_session` |
|---|---|---|
| `ts-sdk@9e3ede6b` `src/auth/Peer.ts:85-92` | constructor, six positional arguments | |
| `ts-stack@edf6e03` `packages/sdk/src/auth/Peer.ts:139-147` | constructor, seven positional arguments (`messageValidation: AuthMessageValidationOptions = {}` the seventh) | default true (`:100`, `:165`), read by `toPeer` (`:190-196`) and `requestCertificates` (`:436-442`) |
| `ts-stack@edf6e03` `packages/sdk/src/auth/clients/AuthFetch.ts:33-49` | a record of seven optional members (`method?`, `headers?`, `body?`, `retryCounter?`, `paymentContext?`, `paymentRetryAttempts?`, `labels?`) | |
| go-sdk@2ca481c `auth/peer.go:115`, `auth/transports/websocket_transport.go:30-33` | structs (`PeerOptions`; `WebSocketTransportOptions { BaseURL, ReadDeadline }`) | default true when nil |
| this crate at `43ee8c85` | `PeerOptions` (six `pub` fields, no derive, no constructor), `AuthFetchOptions` (six, `Clone, Default`), `WebSocketTransportOptions` (two, `Clone`): built by literals | held, never read (`peer.rs:174-175`) |
| this crate after the lane | `#[non_exhaustive]` each; `PeerOptions::new(wallet, transport)`, `AuthFetchOptions::default()`, `WebSocketTransportOptions::new(base_url)`, a `with_<field>` per other field | `new` sets true; still never read (the stated row) |

`#896` (the non-exhaustive pins of #819) was open at `d07321fb`, not on this
base: `tests/arch_non_exhaustive_pins_819.rs` does not exist here, so its
reader was neither taught nor moved; the three structs carry the same doc
blocks it asks for (`compile_fail,E0639` `rebuilt` and its `kept` twin, the
generic one's functions carrying `<W: WalletInterface, T: Transport>`), and
the two derive lines with a trailing comment (`auth_fetch.rs`,
`websocket_transport.rs`) had their comment moved to its own line, which that
reader asks for.

## The RED, each watched

Scratch copies under `/Volumes/Lanes/out/bsv-rs/fix-843d8a/scratch` (the base
by `git archive 43ee8c85`, the tip by copying the tracked and new files), one
target dir, `/Volumes/Lanes/targets/fix-843d8a-red`, removed before the report.

1. `tests/arch_non_exhaustive_843d.rs` (and `tests/arch_support/mod.rs`'s new
   `scan_tokens_with_attributes`) overlaid on the base:
   `every_all_public_struct_is_attributed_or_listed_843d8a` RED naming exactly
   `src/auth/clients/auth_fetch.rs:AuthFetchOptions`,
   `src/auth/peer.rs:PeerOptions` and
   `src/auth/transports/websocket_transport.rs:WebSocketTransportOptions`
   (and the census `the_scan_reads_every_form_by_name_843d8a`, `left: 9`,
   `right: 12`); the other four green.
2. `pub struct Planted { pub a: u8 }` appended to `src/auth/types.rs` in a
   copy of the tip: RED naming `src/auth/types.rs:Planted (line 674)`.
3. `#[non_exhaustive]` removed from each struct in turn in a copy of the tip:
   that struct's `compile_fail` doc test FAILED (it compiles), the other five
   doc blocks ok; three runs.
4. `tests/auth_options_843d8a.rs` on the base: compile-RED, 5 errors, all
   E0599 (`new` absent on `PeerOptions` twice and `WebSocketTransportOptions`
   twice, `with_method` absent on `AuthFetchOptions`).

## The counts

Before any edit (the brief's base check, every one as stated): 34 suffix
structs, 70 `pub enum`, 27 `#[non_exhaustive]`, 13 `#[deprecated`, 26
`auto_persist_last_session: false` in 13 test files. After: 26
`with_auto_persist_last_session(false)`, the count per file unchanged (13
files); 31 literals moved in 17 test files (26 `PeerOptions`, 4
`AuthFetchOptions`, 1 `WebSocketTransportOptions`), by one rule, no line with
`assert` or `fn ` in the diff of those files.

The machine's census: 219 all-public structs (218 braced, `HeadersFn` the
tuple; six generic; seven inside `key_args!`), 12 attributed, 207 rows:
Record 125, ParameterBlock 3, Deprecated 2, Pending 20 (8b: 2, 8c: 18),
Unruled 57 (the draft counted 61; the difference is judgment: the four
`Encrypt`/`Decrypt` args and results mirror the reference's
`WalletEncryptArgs`, `WalletEncryptResult`, `WalletDecryptArgs`,
`WalletDecryptResult`, `Wallet.interfaces.ts:749-764`, and are Records here).
ASSIGNED 6. A Record's reference line was found by the type's name at
`edf6e03` (`export interface|type|class <Name>`), `packages/sdk/src` preferred
where several match; four name matches were judged another type's and left Unruled
(`BlockHeader`, the stream's `Leaf`, the wallet's `Outpoint` and
`Certificate`).

## The break

semver-checks 0.51.0 against `43ee8c85`, `--all-features --release-type
patch`: 229 checks, 228 pass, 31 skip, one fail, `struct_marked_non_exhaustive`
on the three structs alone. The rustdoc JSON (nightly, `--all-features`)
differs in the three structs' attribute and docs, thirteen new methods, and
the doc text of the rewritten examples; every other difference is id or span
noise (cfg spans, tuple field ids). The dependents' literals, read by `git
grep` on the local remote-tracking refs (not fetched): `bsv-wallet-toolbox-rs`
`origin/main` 1, `origin/beta` 4 `PeerOptions`; `bsv-overlay-cloudflare`
`origin/main` 5 `PeerOptions`; `bsv-wallet-cli` (both) and
`rust-message-box` none; no literal of the other two anywhere.

## The gate

The three Rustfmt lines of `ci.yml`; clippy `--all-targets --all-features -D
warnings`; rustdoc `-D warnings`; doc tests (329 passed, 128 ignored); `--lib
auth` under `full,http` (143); `--test 'auth_*'` under `full,http` (45
binaries, 391 passed, 7 ignored); `socketio_*` and `transport_*` (11, 66);
`secret_debug` and `wallet_originator_option_329` under `full,http,websocket`
(21, 12); the wasm32 slice of rule 6; the whole suite under
`full,http,websocket` (`[a-k]*` 186 binaries, 1,718 passed, 13 ignored;
`[l-z]*` 197, 2,168, 19; `--lib` 1,838, 4 ignored); `arch_*` (28, 131);
`cargo build --examples --all-features`; `readme_examples` (1);
`tools/ratchet/run --check --against 43ee8c85` (all seven counters pass);
`mutants_entries.py`; `rows_from_sources.py --check` (0 refusals); gitleaks
over `43ee8c85..HEAD`. No failure anywhere.

## The fold (fix-843d8a-fold, 2026-11-13)

Pull request #930 went red in the land queue after its rebase onto beta
`77c96981` (`69bf1f5b`): `lint` at Clippy and the Test Suite at the
integration tests, `error[E0639]`. The fold rebased it onto beta `b36bca93`
(after #913, #896 and #815; one conflict, `CHANGELOG.md`, both sides kept).

The literals that landed ahead. `cargo check --all-targets --all-features
--keep-going` names one site, `tests/socketio_app_event_receiver_843d23.rs:69`
(#843d23's `PeerOptions` literal), now `PeerOptions::new(..)
.with_auto_persist_last_session(false).with_originator(..)`; no assertion
moved. The twelve Clippy slices build no test; a text search of `src/`,
`tests/`, `examples/`, `benches/`, `fuzz/` and the README finds no other
literal outside the crate (the crate's own `src/` may build one).

One machine for the pins, one for the table. #896's
`tests/arch_non_exhaustive_pins_819.rs` reads every `#[non_exhaustive]` type
under `src/` and refused the three at the rebase (their blocks opened with a
`use` line; `PeerOptions` is generic, which its line reader did not read).
Now: the three blocks are its form (the full path, no `use`), each followed by
`assert_no_drop!`, and `DOC_PINS` names them (21 to 24; the machine reads 30
types, 24 pinned, 6 listed, from 27, 21 and 6). A generic struct is read as
pinned at one instantiation, `PeerOptions<ProtoWallet, MockTransport>`: the
block's path carries the arguments, the update names the base path, and
`assert_no_drop!` takes them after the name (its one arm
`$name:ident $(< $($arg:ty),+ >)?`; a generic sample and a generic `Drop`
type in its doc tests, three `compile fail` lines where two;
`MACRO_FILE_DIGEST` `0x9dce_d5a1_36dd_693d`). The update names the base path
because `Path<A> { ..value }` does not parse as an expression: in an
earlier draft of the fold, with the arguments on the update line and
`PeerOptions`' attribute removed in a copy of the tip, its `compile_fail`
still read `ok`; the reader now refuses that form
(`a_generic_struct_is_pinned_at_one_instantiation_843d8a`).
`tests/arch_non_exhaustive_843d.rs` keeps the table (every all-public struct
attributed or a row, the setters, the classes) and no longer refuses another
spelling of the attribute: it reads `#[non_exhaustive]` alone as the
attribute, and #896's reader refuses every other spelling (its plants at
`cfg_attr(all(), ..)` and an attribute list).

The table re-counted on `b36bca93` plus this change: 219 all-public structs,
12 attributed, 207 rows (Record 125, ParameterBlock 3, Deprecated 2, Pending
20, Unruled 57), ASSIGNED 6: unchanged, as the landed pull requests added no
all-public struct.

RED, in a scratch copy of the tip: each of the three attributes removed,
`the_doc_pins_are_every_pinned_type_found_under_src_819` names the three
(`DOC_PINS entries that name no pinned type`), the doc suite reads the three
`compile_fail` blocks `FAILED`, the log reader names each, and the table
names each; a `pub struct Planted { pub a: u8 }` with no row appended to
`src/auth/peer.rs` is RED in the table by name.

The gate (host stable 1.98.1 and 1.100.0): the three Rustfmt lines; Clippy
`--all-targets --all-features` and the twelve slices on both toolchains;
`cargo doc --no-deps --all-features` under `-Dwarnings`; doc tests 379
passed, 128 ignored, and the log reader as CI runs it; the suite under
`full,http,websocket`: `--lib` 1,859 passed, 4 ignored; `[a-k]*` 194
binaries, 1,773 passed, 14 ignored; `[l-z]*` 203 binaries, 2,246 passed, 21
ignored (397 files, no failure); `arch_*` under `--all-features` 33
binaries, 163 passed, 1 ignored; `fixtures_replay` 1; the wasm32 combined
slice (the `http` build refused by `build.rs` alone; the cdylib 60,909,915
bytes); the ratchet against `69bf1f5b` and `b36bca93`; `mutants_entries.py`
(28 entries) and its tests; `rows_from_sources.py --check` (0 refusals) and
its tests; gitleaks 8.30.1 over `origin/beta..HEAD` (no leaks);
cargo-semver-checks 0.51.0 as beta's job runs it (`--baseline-rev b36bca93
--release-type minor`): exit 100, one lint, `struct_marked_non_exhaustive`, on
the three structs alone, which the job turns into a notice under the
`api-break` label.
