# Lane break-tx-fields: a `Transaction` owns its four serialized fields (#843, PR A)

Base: `origin/beta` at `7ab65f65da588a02202e3a535582a712aa8b1767` (the worktree's HEAD at the start, no reset needed). The specification is `docs/design/843-identity-and-framing.md` (sections 1, 2, 3 "Ensemble 3", 5, 7) and the five design reads' Part I. Logs and scratch trees: `/Volumes/Lanes/out/bsv-rs/break-tx-fields/`.

## RED on the base

A scratch copy of the base (`git archive origin/beta`, its own target dir) with a probe file written against the base API (`red_843_probes.rs`, kept in the out folder; it does not land, it cannot compile on the tip). Its output, `cargo test --features transaction --test red_843_probes -- --nocapture`:

```
TABLE after lock_time = 7, before invalidate_caches:
  id()        stale=true 99296a9c40f5e307530147cc99133f35ae866b280d362d7c487bfd30ea1d72d8
  to_binary() last4=[00, 00, 00, 00] stale=true
  to_hex()    stale=true
TABLE after invalidate_caches():
  id()        stale=false 32571cd650a936108dc37b97eb6515d3fc89dc9973a6b6b3ffaca457733c32fb
  to_binary() last4=[07, 00, 00, 00]
  to_hex()    stale=false
A: child id unchanged after parent edit + child.invalidate_caches(): true (before 73ecaca0... after 73ecaca0...); parent's own id 99296a9c... (its own stale cache)
B: after a.lock_time = 7, a == b: true
C: lock_time after JSON round trip: 0 (edited to 7)
D: clone's id is the stale one: true (99296a9c...)
E: id() 99296a9c... ; display(sha256d(fields' bytes)) 32571cd6... ; equal: false
```

`tests/arch_owned_fields_843.rs` on the same scratch copy: RED, `Transaction.version`, `Transaction.inputs`, `Transaction.outputs`, `Transaction.lock_time at src/transaction/transaction.rs:72 (pub)`, and `Transaction.version is private (#843)`.

## What was built

- `src/transaction/transaction/fields.rs` (`transaction.rs`'s child module, 214 lines): the reads `version(&self) -> u32`, `lock_time(&self) -> u32`, `inputs(&self) -> &[TransactionInput]`, `outputs(&self) -> &[TransactionOutput]`; the doors `set_version(&mut self, u32)`, `set_lock_time(&mut self, u32)`, `inputs_mut(&mut self) -> &mut Vec<TransactionInput>`, `outputs_mut(&mut self) -> &mut Vec<TransactionOutput>`, `parts_mut(&mut self) -> TransactionPartsMut<'_>`, each calling `clear_caches` before it lends or sets; `from_parts(TransactionParts) -> Self` and `into_parts(self) -> TransactionParts` (fields taken by `mem::take`, `Drop` then walks nothing; `metadata` and `merkle_path` dropped, said in the doc); `TransactionParts { pub version, pub inputs, pub outputs, pub lock_time }` (`Debug`, `Clone`) and `TransactionPartsMut<'a>` (four `pub &'a mut`, `Debug`), re-exported from `bsv_rs::transaction`; `clear_caches(&mut self)`, `pub(super)`, the one place the three cells are emptied; five `compile_fail` doc tests (`tx.version = 2` and `tx.lock_time = 7` and `tx.inputs.push(..)` E0616, `tx.invalidate_caches()` E0599, a `Transaction { .. }` literal E0451).
- `transaction.rs`: the four fields plain private; the caches `OnceLock<[u8; 32]>`, `OnceLock<Vec<u8>>`, `OnceLock<String>` (filled by `get_or_init`, set by the readers as `OnceLock::from`); `invalidate_caches` removed; `new()` through `with_params`; the file 2,875 lines against 2,924 at the base.
- `src/` migrated by the compiler's E0616 spans (a script of this lane, `tools/migrate.py` in the out folder, then every remaining error by hand); the defensive `invalidate_caches` calls of the BEEF (`beef_tx.rs` `txid`, `tx_mut`, `refresh`, `written_tx_bytes`; `beef/index.rs` `edit_tx`, three) deleted: they defended a state the doors make unbuildable.
- `Beef::bare_stub` is `clone_for_beef` plus the BEEF's BUMP: until now it took the sources out, cloned (copying the caches) and put them back, so a stub of a transaction whose input named its source by link alone held a copied cache over fields that wrote that input's txid as 32 zero bytes. Its doc line and the legacy test walk's call follow.

## The internal mutators (item 4)

Every function of `transaction.rs` and `fields.rs` that takes `&mut self` or builds a `Transaction`, and where it clears:

| Function | Writes a serialized field? | Where the caches are cleared |
|---|---|---|
| `new`, `with_params`, `from_parts` | builds one | fresh empty cells |
| `from_binary`, `from_hex` | builds one | cells set from the input, which is exactly the transaction (#840); `from_hex` lower-cases the hex cache |
| `from_reader`, `from_ef`, `from_hex_ef`, `from_beef`, `from_atomic_beef` | builds one | empty (via `with_params`, or `find_atomic_transaction`'s linking below) |
| `set_version`, `set_lock_time`, `inputs_mut`, `outputs_mut`, `parts_mut` | yes | `clear_caches` first |
| `into_parts` | moves the fields out | the value is consumed |
| `add_input`, `add_output` | yes | through `inputs_mut()` / `outputs_mut()` (until this lane `invalidate_caches` then a direct push) |
| `add_p2pkh_output`, `add_op_return_output`, `add_op_return_parts_output`, `add_hash_puzzle_output` | yes | through `add_output` |
| `add_input_from_tx`, `add_input_from`, `add_inputs_from_utxos` | yes; the minimal source built by `with_params` | through `add_input` |
| `sign` | yes (each signed input's `unlocking_script`) | through `inputs_mut()` (the template's take and the script's write); the two `invalidate_caches` it held are gone (both redundant once the writes go through the door) |
| `fee` | yes (`retain` of unfunded change outputs) | through `outputs_mut()`; its leading `invalidate_caches` gone (redundant) |
| `distribute_change` | yes (change amounts) | through `outputs_mut()` at each of its three writes |
| `update_metadata` | no (`metadata` is not serialized) | none needed |
| `clone_without_sources`, `Clone` | copies, and links each copied source back | the caches copied: the copy's bytes are the original's |
| `clone_for_beef` | writes `source_txid` of an input that named its source by link | none: the txid written is the source's id, so the bytes, and the copied cache, are unchanged |
| `Drop` | takes the sources out | the value is dying |
| `with_cached_bytes_for_test` (`cfg(any(test, fuzzing))`) | plants a byte cache on purpose | its users (`prepass_621_tests.rs`, `fuzz_beef_parser`) build the pre-#840 state the BEEF writers' scan refuses |

## The `_mut` door calls under `src/` outside `fields.rs` and test code (item 5)

`transaction.rs` 903 `add_input` (write), 923 `add_output` (write), 1492 `sign` (write: the template's take), 1500 `sign` (write), 1558 `fee` (write), 1594, 1605, 1610 `distribute_change` (write); `beef.rs` 168 `find_transaction_for_signing` (write: links sources), 285 and 292 `add_input_proof` (write: links a source, the input's txid set, so the bytes do not move; each call clears that transaction's caches and its id is computed once more after the walk). No read goes through a `_mut` door. Every other `_mut` call under `src/` is in a `#[cfg(test)]` module.

## The plants (item 3)

A scratch copy of the tip (`git archive HEAD`), `cargo test --test transaction_identity_843` with `--config profile.dev.debug-assertions=false` (so the property's own checks catch, not a debug assertion); control green (7 of 7, then 8 of 8):

| Site planted out | Caught by | Message (first) |
|---|---|---|
| `set_version`'s clear | the property | `seed 0x8431d3e71710001, sequence 3, steps ["from_hex re-read", "set_version"]: to_binary() is the fields' bytes` |
| `set_lock_time`'s clear | all seven | `to_binary() ends 07 00 00 00` |
| `inputs_mut`'s clear | the property, probe A | `the child's id moved with it` |
| `outputs_mut`'s clear | the property | `sequence 0, steps [.., "outputs_mut().push"]` |
| `parts_mut`'s clear | the property | `sequence 0, steps [.., "parts_mut"]: to_binary() is the fields' bytes` |
| `clear_caches`: `cached_hash.take()` | six of seven | `assertion left != right failed` |
| `clear_caches`: `raw_bytes_cache.take()` | all seven | `assertion left == right failed` |
| `clear_caches`: `hex_cache.take()` | the property, the table | `to_hex() moved` |
| `from_hex`'s hex cache not lower-cased | the property | `sequence 2, steps [.., "from_hex re-read"]` |
| `add_input` past its door | the property | `sequence 0, steps [..]` |
| `add_output` past its door | the property | `sequence 3, steps [..]` |
| `sign`'s two writes past the door | the property | `sequence 38, steps [.., "add_input_from", ..]` |
| `fee`'s `retain` past the door | the property, the `fee` cell | `fee 50000 Equal over 1 change outputs: to_binary() is the fields' bytes` |
| `distribute_change`'s three writes past the door | the property, the `fee` cell | `fee 100 Equal over 2 change outputs` |

The last two went uncaught on the first run: the property's `fee` step added the change output (which clears) just before `fee`, so the caches were always empty when `fee` wrote. That finding added the cell `fee_writes_the_change_through_the_doors_after_the_caches_are_full_843` and a cache read inside the property's `fee` step; both plants then failed both.

## The architecture test's allowlist (item 5 of the tests)

`tests/arch_owned_fields_843.rs`'s rule, with one refinement of the brief's wording, stated: a field whose name contains `cache` or `index` counts only when its type is a collection (`HashMap`, `BTreeMap`, `HashSet`, `BTreeSet`, `IndexMap`, `IndexSet`, `Vec`, `VecDeque`, `LruCache`); by the name alone 26 data structs were caught (`output_index: u32`, a position; `hosts_cache_ttl_ms: u64`, a figure; `SpendParams`, `SigningContext`, `SighashParams`, `ScriptOffset`, `KVStoreToken`, `OutputListItem`, `IdentityClientConfig`, `LookupResolverConfig`), none holding anything derived. The rows:

- named by the brief: `Transaction.metadata`, `Transaction.merkle_path` (not serialized); `Beef.txs`, `Beef.bumps` (#843's next PR);
- **not named by the brief, findings for the captain**: `Beef.version`, `Beef.atomic_txid` (public by Part O, a `Beef` holding `txid_index`); `AuthFetch`'s ten `pub(super)` fields (`src/auth/clients/auth_fetch.rs:47`, beside `Mutex`/`RwLock`s of sessions and peers); `PeerState.peer`, `identity`, `mutual` (`src/auth/clients/state.rs:18`, `pub(super)` struct, `RwLock`s of session facts); `HistorianConfig.debug`, `history_cache`, `interpreter_version`, `ctx_key_fn` (`src/overlay/historian.rs:33`, a caller's configuration whose `history_cache` is the caller's map); `Envelope.atomic`, `transactions` (`src/wallet/substrates/result_values/beef.rs:10`, a `pub(super)` read-only parse with `bump_indexes`). None of these is derived from the listed field, as read; each is the captain's to keep or own.
- **not seen, a finding**: `BeefTx` (`input_txids`, `is_valid` public; `txid`, `raw_tx` private caches) holds its derived values with no cell and no collection named for a store, so the scan does not see it, and its two rows the brief named cannot be listed (the list's "no longer exists" check would fail). The test's header says so; #843's next PR names them by hand.

## Measurements

Host load at the runs 1.6 to 9 (one-minute), one cargo at a time, `CARGO_BUILD_JOBS=4`, debug builds.

The linear-time pins, each alone, two runs each (`finished in` of the test binary):

| Pin | Base `7ab65f65` | Tip, debug check on | Tip, debug check off (landed) |
|---|---|---|---|
| `a_deep_diamond_chain_links_and_verifies_in_linear_time` (lib) | 0.11 s, 0.08 s (linked and verified in 30.2, 30.1 ms) | 0.08, 0.08 s (30.6, 31.8 ms) | 0.11, 0.08 s (30.4, 30.2 ms) |
| `tests/beef_deep_chain.rs` (whole file) | 7.34, 7.18 s | 8.97, 8.72 s | 7.40, 7.44 s |
| `the_whole_path_walks_a_wide_bump_in_linear_time` | 0.50, 0.46 s | 0.50, 0.50 s | 0.48, 0.50 s |

The debug check (item 6: a cache hit in `to_binary` compared with a fresh `build_serialized_bytes()` in debug builds, the test door's planted caches excepted) moved `beef_deep_chain` by about 1.4 s (+19%); the whole suite's wall time with it, 307 s (lib and the six integration groups), and without it, 315 s (the host's load differed; no growth seen). A pin moved, so by the brief's rule the check is **left out** (its flag for planted caches with it); the property test and the plants carry the law. The migration itself leaves the pins where they were.

The property test: 10,000 sequences of 12 steps (4,976 picks of the `sign` step, counted by the step's name whether or not `sign` ran: it runs only when every templated input has its source, and writes a script only where a template is held; the strength read of `98f09276`) in 14.2 s, debug.

The suite, `--features "full,http,websocket"`, the library whole and by module filter, every integration file in six groups of at most 60, doc tests: base 5,845 passed, 1 failed (`every_tests_claude_row_names_the_modules_its_source_names_706`, the scratch copy's two added probe files having no rows: not the base's), 160 ignored; tip 5,866 passed, 0 failed, 160 ignored. The tip has 20 more: the 11 new tests and 9 new doc tests (the fields doors'). Fewer by name on the tip: `a_stale_cached_entry_is_filed_under_its_bytes_hash_621` and `to_writer_writes_a_tx_mut_entry_from_its_fields_not_its_cache_621` (`beef/merge_entry_621_tests.rs`), which pinned the BEEF's repair of a stale transaction cache, restated on the law as `an_entry_edited_inside_tx_mut_is_filed_under_its_fields_hash_843` and `to_writer_writes_a_tx_mut_entry_from_its_fields_843`; six doc tests of `transaction.rs` renamed by their line numbers only.

## Other tests that changed how they reach a field, not what they assert

- The diamond-chain fixture of `beef.rs`'s `merkle_path_reattach_tests` built "shallow" copies by dropping each input's source after a clone: the clone's copied cache stood in for inputs whose fields then wrote 32 zero bytes, so the BEEF it built held ids its own fields did not hash to. Under the law the copy's id was its fields' and the fixture failed (`Transaction ... not found in BEEF`); the fixture now names each dropped source by its txid. A test relying on a stale cache: the class, in a fixture.
- `tests/beef_writer_refusals_817.rs`'s `an_entry_edited_through_tx_mut_is_written_from_its_fields_by_to_writer_621` now edits through `set_lock_time`; its doc says the stale state is unbuildable since #843.
- The example `examples/beef_spv.rs` (one token, `tx.inputs()[0]`), README's block pasted from it (`cargo test --test readme_examples` green), and the example's source guard in `tests/support/fixtures/binary.rs` re-hashed (`37f25c28...` to `8389c030...`, the guard's own instruction).
- `.cargo/mutants.toml`'s `dependency_order` entry re-pointed from `beef.rs:1138:29` to `1133:29` (`bare_stub`'s shorter body).

## Findings outside the brief

1. `Transaction::benford_number` divides by `1_f64.log10()`, zero (`transaction.rs`, unchanged from the base): `fee(.., ChangeDistribution::Random)` over two or more change outputs computes an infinite factor, `u64::MAX` after the cast, and overflows (a debug panic, seen by the property run on the tip; in release a wrapped amount). A caller's own choice reaches it, no peer's bytes. Not fixed here; the property test avoids `Random` over two or more change outputs and says why.
2. go-sdk@2ca481c is not "public fields, no cache": it holds an opt-in `cachedTxID` the caller sets with `SetTxHash` and must clear (`transaction/transaction.go:27-32,301-319`). Stated so in the parity note.
3. The architecture test's rows above, and `BeefTx` unseen by its scan.

## What this lane did not do

- `src/script/script.rs` untouched; `Transaction` is not `Sync` (its `Script`s' `RefCell`s), and nothing claims it is.
- The BEEF's fields, `BeefTx`'s read-only members, `tx_mut`'s removal and the typed id: #843's next PRs. #843 stays open.
- No downstream compiled (the design read measured them); no push.
- `cargo semver-checks` ran (expected red; its breaks are the migration paragraph's: `invalidate_caches` and the four fields, each at three paths).
- The conformance files ran against the local `~/bsv/ts-stack` checkout at `4d0ea63`, not CI's pin `edf6e03`; the totals held at 5,116 / 4,121 run / 4,110 passed / 958 unsupported / 0 failures.

## The fold of PR #869 (lane break-tx-fields-fold, 2026-11-10)

After the three reads (cold MERGE 0.88, rule FIX 0.8 on `into_parts`, strength FIX 0.75), on the captain's rulings.

**The base.** Rebased onto `origin/beta` `18ff3307` (#868's two commits, `abac313b` and `18ff3307`). One code conflict, `distribute_change`: beta's arithmetic stands (each change output but the last `floor(change / n)` or a Benford portion of what remains, the last the rest), each of its two writes through `outputs_mut()`; `tests/transaction_fee_random_change_868.rs` reads `tx.outputs()` at its three sites; the CHANGELOG's two `[Unreleased]` sections kept, #843's above #868's. The four readers' commits were picked without a conflict (`339219a1`, `f0dc5e07`, `58f7f11c`, `e94c13ba`; no sentence touched by two).

**The parts are lossless.** `TransactionParts` carries the six fields (`version`, `inputs`, `outputs`, `lock_time`, `metadata`, `merkle_path`), derives `Debug`, `Clone`, `Default`, and is not `#[non_exhaustive]`; `TransactionPartsMut<'_>` lends the same six; both re-exported at the crate root. `into_parts_then_from_parts_keeps_the_merkle_path_and_the_metadata_869` was RED on `98f09276` (the test overlaid on a scratch worktree: `left: None`, `right: Some("fd8403...")`, the merkle path lost); the property's round-trip step no longer saves `metadata` around the call.

**The fields behind `fields.rs`.** `Transaction { fields: Fields, metadata, merkle_path }`; `Fields` (`pub(super)`) holds the four serialized fields and the three caches, its fields private to `fields.rs`, so a write in `transaction.rs` does not compile: `self.fields.outputs.clear()` planted there is `error[E0616]: field 'outputs' of struct 'Fields' is private` (`transaction.rs:1525`). What `transaction.rs` reaches of `fields.rs` beside the doors: `Fields::new` (a fresh value, no cache), `read_exact` (the readers' fill: the bytes the transaction was just read from, exactly one transaction since #840), `serialized_bytes`, `serialized_hex`, `serialized_hash` (the fills behind `to_binary`, `to_hex`, `hash`, through `&self`, from the fields alone), `clone_for_beef` (`pub(in crate::transaction)`: the txid fill moves no byte, the serializer reading a missing `source_txid` through the source), `with_cached_bytes` (`pub(crate)`, a read). The serializer, `hash_sources_without_txids`, `clone_without_sources` (now private to `fields.rs`: its caches can name a source it no longer holds, so only its two callers there use it), `Clone` and `Debug` moved into `fields.rs`; `Drop` stays in `transaction.rs` and takes the ancestry through `inputs_mut()`, so it needs no exception. `transaction.rs` went from 2,875 lines to 2,614; `fields.rs` is 582, its longest production function `Clone::clone` at 41 lines. `tests/arch_field_writes_843.rs` is re-pointed: the textual rule over `transaction.rs` is vacuous under the compiler and is gone; the rule reads `fields.rs` and refuses every function whose text holds `mut` or names a cache that neither calls `clear_caches` nor is listed (sixteen entries, each with its reason), and a `pub` field of `Fields`, an `unsafe` or a `macro_rules!`. A `pub(super) fn plant_write` writing `self.fields.outputs` without a clear planted in `fields.rs`: RED, `fields.rs:307` named.

**No public shape moved by the move.** `cargo semver-checks` 0.51.0 against `98f09276`: one lint, `constructible_struct_adds_field`, naming `TransactionParts.metadata`, `.merkle_path`, `TransactionPartsMut.metadata`, `.merkle_path` (step 2's). The nightly rustdoc JSON of both (`--all-features`), normalized (ids, spans, docs dropped; `super::Transaction` read as `Transaction`): the same items, the same inherent and trait impls of `Transaction` with the same members (36 impls), and `TransactionParts` gaining its two fields and `Default`, `TransactionPartsMut` its two fields; nothing else. `Debug` prints the same nine fields in the same order (the hand impl moved, its body unchanged but for the path to each field).

**The test door.** `with_cached_bytes_for_test` is under `cfg(any(test, feature = "internal-test-doors"))`, a feature documented in `Cargo.toml` as no part of the API, not in `full`, turned on by `fuzz/Cargo.toml` alone. A scratch crate depending on `98f09276` with `RUSTFLAGS="--cfg fuzzing"` called it (built); on the tip the same crate: `error[E0599]: no method named 'with_cached_bytes_for_test' found for struct 'bsv_rs::Transaction'`. The fuzz crate's two users build (`cargo +nightly fuzz build`), and `prepass_621_tests.rs` under `cfg(test)`.

**The law as a fuzz invariant.** `fuzz/fuzz_targets/support/identity_law.rs`, in `fuzz_transaction_parser` (after `from_binary` succeeds) and `fuzz_beef_parser` (every linked subject `find_atomic_transaction` returns): up to six edits through the doors chosen by the input's bytes (the setters, pushes, element edits, `pop`, `retain`, `parts_mut`, `into_parts`/`from_parts`, `Clone`, a linked source's edit), and after each `id()` the display hex of `sha256d` of the target's own serialization of the fields, a fresh parse of `to_binary()` the same id. 60 s twice each: 583,596 and 549,126 runs, 110,061 and 114,605 runs, no crash. A scratch copy with `set_lock_time`'s clear removed crashed `fuzz_transaction_parser` inside its minute (`after ["no edit", "set_lock_time"]: id() is the hash of the fields`). The seeds are the targets' own; the corpus generator is unchanged (the invariant needs no new seed).

**The property's reach.** `Counts` with a floor of 200 each, printed with the seed when one falls short. At the seed: 1,033 `sign` calls over a templated input (the 4,976 of the first record were picks of the step), `fee` 2,436 `Equal` and 2,550 `Random` (1,377 of those over two or more change outputs, #868's cell, the avoidance gone), steps ending at depth 1, 2, 3: 45,134, 13,072, 7,452, the parent's, grandparent's and great-grandparent's edits 3,367, 841, 242, every other door at least 2,450. The generator was raised where counts were low: `parent` links a grandparent one time in two and a great-grandparent two times in three of those, the deep edit walks to a chosen depth through the deepest linked input, `fee` first drops unfunded inputs through `inputs_mut()` and adds a funded one if none is left. On the way the floor caught the generator short twice (`a linked great-grandparent's edit: 23 < 200`, then `47`, `57`, `76`, `133`).

**The attempts as cells.** `tests/transaction_identity_attempts_869.rs` (six cells, all holding) and `compile_fail` doc tests in `fields.rs` for `tx.outputs.push(..)` (E0615), `tx.outputs()[0].satoshis = Some(1)` (E0594) and a read of `inputs()` held across `inputs_mut()` (E0502); doc sentences on `outputs_mut` and `parts_mut` as `inputs_mut`'s.

**The plants on the new shape.** The lane's fourteen and the cold read's five, each on the scratch worktree at `f2be42a9`, `cargo test --all-features --config profile.dev.debug-assertions=false` over `transaction_identity_843`, `transaction_identity_attempts_869` and `arch_field_writes_843`; every one RED, the five that wrote past a door now by the compiler:

| Site planted | Caught by |
|---|---|
| set_version's clear | the property, the guard |
| set_lock_time's clear | the property, the guard, 7 cells |
| inputs_mut's clear | the property, the guard, 3 cells |
| outputs_mut's clear | the property, the guard, 3 cells |
| parts_mut's clear | the property, the guard, 2 cells |
| clear_caches: cached_hash.take() | the property, 9 cells |
| clear_caches: raw_bytes_cache.take() | the property, 10 cells |
| clear_caches: hex_cache.take() | the property, 4 cells |
| from_hex's hex cache not lower-cased | the property |
| add_input past its door | does not compile: E0616, field `inputs` of struct `Fields` is private |
| add_output past its door | does not compile: E0616, field `outputs` of struct `Fields` is private |
| sign's write past the door | does not compile: E0616, field `inputs` of struct `Fields` is private |
| fee's retain past the door | does not compile: E0616, field `outputs` of struct `Fields` is private |
| distribute_change's writes past the door | does not compile: E0616, field `outputs` of struct `Fields` is private |
| cold: clear_caches empties the hash alone | the property, 10 cells |
| cold: a door lends before it clears | does not compile: E0499, `*self` borrowed mutably twice |
| cold: from_parts carries a cache | the property, the guard, 1 cell |
| cold: Clone drops its link back | the property, 2 cells |
| cold: add_op_return_parts_output past add_output | does not compile: E0616, field `outputs` of struct `Fields` is private |

**Measurements** (a host at one-minute load 5 to 16, other lanes building): release, a 2,000-deep chain of `OP_1` spends over a proven root, median of five, two passes alternating base (`98f09276`) and tip: verify 3.448 / 3.054 ms and 2.803 / 2.830 ms, `to_beef` 3.328 / 2.955 and 2.685 / 2.720 ms, `from_beef` 3.296 / 3.010 and 2.681 / 2.728 ms. `beef_deep_chain` in release, four passes alternating: 1.05 / 0.96 s, 2.05 / 2.67 s (the load at 16 then), 0.99 / 1.02 s, 0.94 / 0.98 s; `the_whole_path_walks_a_wide_bump_in_linear_time` 0.02 to 0.03 s on both. Flat within the passes' spread.

**Two guards followed the move.** `tests/arch_owned_fields_843.rs` reads the caches in `Fields` (every field private) and `Transaction` holding it privately; `Transaction.metadata` and `Transaction.merkle_path` left its `ALLOWED` list (the list shrank by two). `tests/arch_no_unwrap.rs`: `Clone`'s two `expect`s moved with it, the ceiling entry from `transaction.rs` to `fields.rs` (2 for 2).

**The gate.** Both fmt checks, clippy `--all-targets --all-features -D warnings`, the doc build under `-D warnings`, the doc tests (316 passed, 128 ignored), the four #843/#869 files three times (one with `--test-threads=1`), the whole suite with `full,http,websocket` in pieces (the library 1,823 passed and 4 ignored; the 357 integration files in eight `--test` groups, 3,748 passed, 0 failed, 28 ignored): 5,887 passed, 0 failed, 160 ignored, the cold read's 5,868 plus beta's seven (`transaction_fee_random_change_868.rs`) and this fold's twelve (two parts tests, six attempt cells, four doc tests); the cold read's two guard tests renamed with their rule (`every_write_of_a_serialized_field_goes_through_a_door_843` and `the_write_reader_reads_the_probe_843` are `every_writer_in_fields_rs_clears_the_caches_or_is_listed_843` and `the_reader_judges_the_probe_843`). Examples, `readme_examples`, `bench --no-run`, `cargo +nightly fuzz build` (every target), the wasm32 slice, the two conformance files with the ts-stack corpus (5,116: 4,121 run, 4,110 passed, 958 unsupported, unmoved), the `sibling` job's steps at its pin (13,765 entries, 0 divergences, GREEN), the ratchet against `origin/beta`, `mutants_entries.py`, `rows_from_sources.py --check` and gitleaks over `origin/beta..HEAD` pass; `cargo semver-checks` against `origin/beta` red with two lints, `inherent_method_missing` and `struct_pub_field_missing`, the migration paragraph's.

## Fold 2

From `2f5ba421` (the rule re-read's ACCEPT with FIX 0.8, the cold re-read's FIX 0.8); the rule re-read's docs commit taken first (`bfac25cb`, picked as `9547df34`).

**The probe.** The cold re-read's (`probe_clone_for_beef_843.rs`): a parent whose input names its linked source by the text `"zz"`, under a child linked by no txid; after `Beef::merge_transaction`, the stored parent's `id()` was `73ecaca0f86d8ecd041e377ab87d5f1960076c58d359ea46a877dec74e1ea7c7` and the hash of its fields `1d0bc34cbcd9446f3e41a422f0dc437e25fa7b135754db8aee718bb453df2f4a`. The serializer wrote the source's hash for an input whose text does not parse; `clone_for_beef` repaired only a `None`, dropped the source and kept the cache. As a test, `a_beef_copy_of_a_parent_whose_txid_text_does_not_parse_keeps_the_law_869`: RED on `2f5ba421` with exactly those two ids, green on the tip.

**The one function.** The serializer's rule as found (`build_serialized_bytes`): `get_source_txid_bytes()` when it answers `Ok` (the `source_txid` text through `from_hex`, `hex::decode`, of exactly 32 bytes; with no text, the linked source's `id()` through the same path), else the linked source's `hash()`, else 32 zero bytes. As one function, `outpoint_txid` (`fields.rs`, crate-private): `Named(text)` when the `source_txid` is 64 ASCII hex digits (exactly the texts `hex::decode` reads as 32 bytes, either case; a unit test sweeps lengths 0 to 70 of seven character classes and every single change of a 64-digit text against `get_source_txid_bytes`), else `Source(&source)` when a source is linked, else `Zero`; `outpoint_txid_bytes` the bytes. No byte moved: the serializer writes `outpoint_txid_bytes`, the iterative pre-hash (`hash_sources_without_txids`) walks the `Source` arm, `clone_for_beef` names every `Source` input by its source's id, and `replace_source` keeps the caches on the `Named` arm alone. A first version decoded the hex on every arm check and cost `to_beef` and `from_beef` 5 to 15% against beta at 20,000 deep; the arm now holds the text and only the writer decodes. Side fix of the same rule: the pre-hash read only a `None`, so a chain named by unparsable texts recursed once per link in `id()` (the base overflowed a 1 MiB stack on a 20,000-deep chain; the tip hashes it).

**The property's new states** (`tests/transaction_identity_843.rs`, each with a floor of 200; the counts are printed by the run, `/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold2/tip-property.txt`): a `source_txid` not hex, of a wrong length (62 and 66 digits), empty, each linked and unlinked, and one that parses and is not the source's id; one time in two on a linked source's input (`odd txid below the top`), since a BEEF stores the top as given and only the ancestors as copies (on the top alone the BEEF property was green on the base). Four links: the txid the source's, another, none, not hex. The main run (10,000 sequences) keeps the plain law after each step, the BEEF law on every step took it past its minute (130 s at load 20); `every_copy_a_beef_stores_keeps_the_law_869` (2,000 sequences, its own seed) runs the BEEF law after each odd naming, link and last step: every transaction reachable through `merge_transaction`, `merge_beef` (into an empty BEEF and into itself), `to_beef` and `to_atomic_beef` read back, `from_beef`, `from_atomic_beef`, `find_transaction_for_signing` per entry, `find_atomic_transaction` of the last entry and `clone`, `id()` the hash of its fields and of `from_binary(to_binary())`. RED on `2f5ba421`: `merge_transaction, entry 2: id() is the hash of the fields`. The runs at load 20 to 30: 24 to 27 s and 19 to 22 s.

**The fuzz invariant.** `identity_law.rs`'s writer walks the read-through sources on an explicit stack, memoized by address (it recursed, the doc said a stack): a 20,000-deep chain (alternating `None` and `"zz"`, and all `None`) passes on a 1 MiB thread stack in a debug build; 2f5ba421's recursive writer overflowed on the all-`None` chain, which the crate itself hashes iteratively. `law_reach` judges every linked source; `beef_copies_keep_the_law` judges every entry of the parsed BEEF, each linked again and merged back through `merge_transaction`, and the BEEF merged into an empty BEEF and into itself; a thirteenth edit sets an input's text to one that does not parse. Two 60 s runs of each target before and after the merge-back door, no crash (715,241 and 584,445; 570,560 and 854,613 runs of the transaction parser; 108,578 and 123,704; 89,752 and 103,046 of the BEEF parser). Under the cold re-read's plant (`copy.fields.lock_time ^= 1` in `clone_for_beef`) `fuzz_beef_parser` crashed inside its minute: `a linked entry merged back: id() is the hash of the fields (#843)`.

**The door.** `Transaction::replace_source(index, Option<Box<Transaction>>) -> Option<Box<Transaction>>`, `pub(in crate::transaction)`, in `fields.rs`, on the guard's list with its reason. The linking sites moved to it: `beef.rs`' `add_input_proof` (the child's link back, the stub's link, the caller's own source taken) and `find_transaction_for_signing`. Its units (`link_source_869_tests.rs`): after a cache-full child is relinked to another source, the law first, then the caches kept for a txid that is the source's or another parsing one, emptied for none and for `"zz"`, `""`, 62 digits. The guard (`arch_field_writes_843.rs`) counts a clear only as the body's leading `self.clear_caches();`, so a function that clears on one path is listed, not passed by the call's presence (a probe `some_path` pins it).

**The sixteen entries, re-read against the odd states** (eighteen since the fold):

| Entry | Reason as written before | A state that breaks it | Pinned by |
|---|---|---|---|
| `clear_caches` | the clearing itself | none | plants 5 to 7, 14 |
| `new` | a fresh value, caches empty | none | plant 16 (via `from_parts`) |
| `into_parts` | consumes; no cache outlives the take | none | `the_parts_default_is_transaction_new_869`, the round trip |
| `read_exact` | caches the bytes just read, one transaction (#840) | none: bytes read always name parsing txids | `transaction_trailing_data_840.rs`, the property's re-read |
| `serialized_bytes` | fills from the fields | none | the property |
| `serialized_hex` | fills from the bytes | none | the property, plant 8 |
| `serialized_hash` | fills from the bytes | none | the property |
| `with_cached_bytes` | reads | none | `prepass_621_tests.rs` |
| `with_cached_bytes_for_test` | the test door that plants a cache | by design | n/a |
| `hash_sources_without_txids` | hashes sources read through a missing txid | a text that does not parse: not pre-hashed, `id()` recursed (stack, not the law) | the deep probe; now reads `outpoint_txid` |
| `unhashed` | as above | as above | as above |
| `build_serialized_bytes` | a `let mut` writer | none | the property |
| `clone_for_beef` | a missing txid filled from the source, the bytes unmoved | **a text that does not parse with a linked source: the copy wrote zeros under the copied id (FALSE until this fold)** | the probe test, `every_copy_a_beef_stores_keeps_the_law_869`, plants 19, 20 |
| `clone_without_sources` | callers repair | **the same state through `clone_for_beef` (FALSE until this fold)** | as above, plant 17 |
| `fmt` | prints | none | n/a |
| `clone` | the copied source linked back where the original held it | none: the same arm, the same id by induction | plant 17, the property's clone, the BEEF law's |
| `replace_source` (new) | keeps on `Named`, empties otherwise | none | the door's units, plants 21, 22 |
| `outpoint_txid_bytes` (new) | a `let mut` local | none | the arm sweep unit |

**Linking leaves a cache it cannot change: the siblings.** Every call of `inputs_mut()`, `outputs_mut()`, `parts_mut()`, `set_version`, `set_lock_time` under `src/` outside tests, by a run on the tip:

| Site | Path | A filled cache can be present | Verdict |
|---|---|---|---|
| `transaction.rs:841` `add_input` | build | yes | moves bytes: must empty |
| `transaction.rs:861` `add_output` | build | yes | moves bytes: must empty |
| `transaction.rs:1342` `sign`, the template taken | build | yes (`to_binary` just read) | a script is written next on success; on a template's error nothing moved, a build path's refusal: kept |
| `transaction.rs:1350` `sign`, the script written | build | yes | moves bytes |
| `transaction.rs:1409` `fee`, change removed | build | yes | moves bytes, or none when no change output exists: a build path, kept |
| `transaction.rs:1438`, `:1441` `distribute_change` | build | yes | moves bytes |
| `transaction.rs:1729`, `:1735` `Drop` | the value dying | yes | nothing reads after: kept |
| `beef.rs:175` `find_transaction_for_signing` | read | yes (the clone's) | moved to `replace_source` |
| `beef.rs:295`, `:310`, `:315` `add_input_proof` | read and verify (`from_beef`, `verify`'s graph) | yes | moved to `replace_source` |

**The timings against beta** (`/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold2/timings.txt`; scratch probe crates on beta `18ff3307`, `2f5ba421` and the tip, each its own target, release; a chain of `OP_1` spends over a proven root; per operation the minimum and median of seven in one process; four passes, the one-minute load about 4):

| 20,000 deep, min ms | beta | 2f5ba421 | tip |
|---|---|---|---|
| verify | 15.89, 16.57, 17.34, 15.31 | 24.02, 22.59, 26.06, 22.45 | 15.82, 16.79, 16.16, 15.16 |
| to_beef + to_atomic_beef | 46.32, 47.28, 50.43, 46.83 | 46.59, 44.47, 50.68, 43.81 | 46.35, 52.56, 47.63, 46.33 |
| from_beef | 33.20, 34.54, 36.87, 32.86 | 32.48, 30.43, 36.45, 30.05 | 34.04, 40.54, 34.55, 31.97 |
| clone | 2.67, 2.88, 2.79, 2.71 | 2.34, 2.22, 2.47, 2.23 | 2.63, 2.81, 2.71, 2.40 |

At 2,000 deep (two passes): verify 1.70, 1.64 beta; 2.45, 2.43 `2f5ba421`; 1.67, 1.63 tip; the others within 0.05 ms of beta. The tip's second pass at 20,000 is high on every column at once (load noise; its medians too); the third and fourth are beta's. Within beta's noise: no cost to state. Earlier passes at a load of 20 to 30 showed the same order with wider spread.

**The plants on the fold's shape** (`/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold2/plants/`, each alone on a scratch copy of the tip, `--config profile.dev.debug-assertions=false`, the two property files, the attempts, the two guards and the door's units): the nineteen of the earlier fold all RED again (the same seven by not compiling: E0616 five times, E0499, and `add_op_return_parts_output` E0616), and this fold's six:

| Plant | Caught by |
|---|---|
| `clone_for_beef` flips the copy's lock time (the cold re-read's) | the probe test, the BEEF-copy property, `fuzz_beef_parser` |
| `clone_for_beef` repairs a missing txid alone (the base's rule) | the probe test (`1d0bc34c..`), the BEEF-copy property |
| the linking door never empties | the door's units (`the law after the link`, `67bdb022..` against `84db51db..`) |
| the linking door empties only a missing txid | the door's units (`"zz": the law after the link`) |
| the oracle back under `cfg(any(test, fuzzing))` | `arch_test_doors_869` (`src/transaction/beef_writable.rs:301`) |
| the parts' `Default` back to version 0 | `the_parts_default_is_transaction_new_869` |

The linking door's two plants are caught by its units alone among the fold's tests, and the reason the fold gave for that (the door's unparsable case relinks the source it took, the same transaction, so no id moves) is false (the cold read of the second fold, `5bf34e29`): `add_input_proof` keys its stubs by the input's `source_txid` text, so a transaction whose two inputs hold one text that does not parse (`"zz"`, `""`, `"abc"`) over two different linked sources, merged by `merge_transaction`, comes back from `find_atomic_transaction` of its id with its second input relinked to the first input's stub: the id asked `c7448f41..`, the id answered `2d282673..`. The law holds on the tip, since the door empties the caches on that arm. On beta `18ff3307` the same state broke the law (the cached `c7448f41..` over fields hashing to `2d282673..`). Under the plants "never empties", "keeps when the text does not parse" and "empties only a missing txid" the law broke through that public door at `5bf34e29`. Neither the property nor the fuzz invariant built two inputs sharing one unparsable text over different sources (the third fold keys the stubs by what an input links and builds the state in both; since then those three plants reach no public door: "Fold 3", below). The probe is `/Volumes/Lanes/out/bsv-rs/review-break-tx-fields-fold2/probe_shared_bad_text_review.rs`.

**The test doors.** `cfg(any(test, fuzzing))` under `src/` on `2f5ba421`, by a run: `beef_writable.rs:284` (`snapshot_round_trip`, `pub(super)`) and `:296` (`merge_snapshot_oracle`, `pub`, `#[doc(hidden)]`); nothing else. Both under `cfg(any(test, feature = "internal-test-doors"))`; callers `beef/prepass_621_tests.rs` (the crate's `cfg(test)`) and `fuzz_beef_parser` (the fuzz crate's `internal-test-doors`, `fuzz/Cargo.toml`). A scratch crate depending by path, `RUSTFLAGS="--cfg fuzzing"`, no feature: on `2f5ba421` `merge_snapshot_oracle callable: Ok(0)`; on the tip `error[E0599]: no method named 'merge_snapshot_oracle' found for struct 'Beef' in the current scope`. The guard `tests/arch_test_doors_869.rs` (a new file: the field-writes guard is `fields.rs`'s, and no earlier test read the feature).

**The gate.** The three fmt lines; clippy `--all-targets --all-features -D warnings`; the doc build under `-D warnings`; the doc tests (316 passed, 128 ignored); the #843 files and `arch_test_doors_869` three times (186 passed each, one at `--test-threads=1`); the whole suite with `full,http,websocket` in pieces: the library by its fourteen module filters, 1,829 passed and 4 ignored (unique names), the 358 integration files in eight `--test` groups, 3,753 passed, 0 failed, 28 ignored; 5,898 passed, 0 failed, 160 ignored, the cold re-read's 5,887 plus eleven (the door's six units, the parts and probe tests, the BEEF-copy property, the guard's two), no test removed. Examples, `readme_examples`, `bench --no-run`, `cargo +nightly fuzz build`, the wasm32 slice, the two conformance files with the ts-stack corpus (5,116: 4,121 run, 4,110 passed, 958 unsupported, unmoved), the `sibling` job's steps at its pin (13,765 entries, 0 divergences, GREEN), `beef_deep_chain` alone in release (11 passed, 0.98 s, load 4), the ratchet against `origin/beta`, `mutants_entries.py` (the `dependency_order` entry re-pointed to `1147:29`), `rows_from_sources.py --check` and gitleaks over `origin/beta..HEAD` pass. `cargo semver-checks` against `origin/beta`: the same two lints. The rustdoc JSON against `2f5ba421` (both `--all-features`, ids, spans and docs dropped): one difference, `impl Default for TransactionParts` without `automatically_derived`.

## Fold 3

Lane `break-tx-fields-fold3b`, from `5bf34e29` (`origin/lane/break-tx-fields`), rebased onto `origin/beta` at `842562fd` (#878, #876, #881; #882 had not landed). Two conflicts, both kept on both sides: `CHANGELOG.md` (#843's entry at the top of `[Unreleased]`, #854's under it) and `docs/design/843-identity-and-framing.md` (beta's #842 row, this pull request's #843 row). The readers' two docs commits taken: `8abcbeb8` (the linking door's unparsable case, its last two sentences put in the past tense of `5bf34e29` since this fold) and `6335db1a` (the pre-hash's reference sentence).

**The linker's key (the cold re-read's FIX).** `add_input_proof` keyed its stubs by the input's `source_txid` text (`beef.rs:301,320` on `5bf34e29`). It keys them now by the id of what the input links: its own source's id when it carries one, else the text the BEEF is asked by (`find_txid`); an input naming no txid is skipped as before (a source it carries is left and not descended, older than this fold). Not `outpoint_txid` exactly: where a text parses and the input's own source has another id, the outpoint rule names the text, so the second of two such inputs would be handed the first one's source; the reference keeps a linked source (`#resolveInputSource` fills only a null one) and visits by the source's id (`ts-stack@edf6e03` `Beef.ts:649-679`), so each input keeps its own (pinned: `two_inputs_sharing_a_text_that_parses_keep_their_own_sources_869`). Where the text is 64 hex digits and names its source, the two keys are the same string.

The sites under `src/transaction/` that read `source_txid` (or `get_source_txid`, which returns it), by `grep -n "source_txid"` and `get_source_txid`, test modules excluded:

| Site | What it does with the text | Kind | This fold |
|---|---|---|---|
| `transaction.rs` readers (`from_reader`, `from_ef`) | writes the text it read (64 hex digits) | builds | n/a |
| `transaction.rs` `collect_ancestors` error, `beef.rs` legacy error | prints it | display | kept |
| `transaction.rs` `add_input` | refuses an input with neither text nor source | presence | kept |
| `transaction.rs` `to_ef`, `spending.rs` `sighash_of` | `get_source_txid_bytes`: parses it once | parse | kept: a text that does not parse is refused there (`to_ef` `Err` where `to_binary` writes the source's hash; older, stated) |
| `transaction.rs` `is_coinbase` | compares the text with zeros | compare | kept, stated: a public predicate older than #843; on the odd states (`""` over a linked source answers `true` where the bytes carry the source's hash; `"zz"` with none `false` where they carry zeros) it moves only with the typed `Txid` |
| `verify.rs` `sources` | looks the source up by the text in the gathered map | key | kept: a text that does not parse is refused (`Input N has no source transaction`); moving it turns a refusal into a judgment, a verdict outside this fold, and the reference refuses such a text earlier (`requireTXID`) |
| `tx_json.rs` `to_tx_json` | writes the text as the JSON `txid` member | display | kept: the `hex` member beside it carries the bytes and wins on read; read through the members, #845 refuses it |
| `tx_json.rs` reader | lower-cases a 64-digit text | builds | n/a |
| `beef.rs` `find_transaction_for_signing` | asks the BEEF for the text, only for an input with no source | key (BEEF lookup) | kept: an input with a source is never relinked; a text that does not parse names no entry (entries are named by their hash) |
| `beef.rs` `add_input_proof` | keyed its stubs by the text | key | **moved**: the linked source's id, else the text |
| `beef.rs` `trim_known_proven` | references by `get_source_txid` | key | **moved**: `outpoint_txid_name` |
| `beef_tx.rs` `input_txids_of` | an entry's `input_txids` by `get_source_txid` | key | **moved**: `outpoint_txid_name` |
| `beef/in_memory.rs` `spent_txids`, `content_refused` | the in-memory judge's edges and outpoints | key | **moved**: `outpoint_txid_name` (a text that does not parse over a source was the sentinel `[0xEE; 32]`, so two such inputs read as one repeated outpoint) |
| `fields.rs` `outpoint_txid`, `clone_for_beef` | the rule itself and its repair | rule | the rule |

`outpoint_txid_name` (`fields.rs`, crate-private): the text when 64 hex digits, else the linked source's id, else the text as given; with no source linked it returns the text without the scan (the read path's entries link nothing).

**RED.** `tests/beef_shared_txid_text_869.rs`, overlaid on a scratch copy of `5bf34e29` (its own target dir): 3 of 3 RED. `"zz"`: `find_atomic_transaction's id`, `left: "2d282673.."`, `right: "c7448f41.."` (the probe's ids); the text that parses: `find_atomic_transaction's sources`, the first source twice; the graph: `["zz"] input_txids`, `left: ["zz"]`. Green on the tip.

**For well-formed input nothing moved.** A scratch crate (`/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold3b/diff/`), two projects on `5bf34e29` and on the tip, one seed: 20,000 random transactions with 64-hex-digit txids, sources linked to depth four (half the inputs), parents shared between two inputs (the stub), through `to_beef`, `to_atomic_beef`, `merge_transaction` and the merged BEEF's bytes and entry txids, `find_atomic_transaction` (its id, its bytes, its `to_beef`) and `find_transaction_for_signing`: the two outputs byte-identical, one digest `13dbdd3f7cfde0ce9244cbc7d99ed30015646ae1181a5dc22ae4eab2b3493910`, run again after the scan change below.

**The state in both machines.** The identity property's step gains two arms (`shared txid: does not parse`, `""`, `"zz"` or `"abc"`; `shared txid: parses`): two or three inputs pushed with one text, each linked to a source of its own, on the top or one time in two on a linked source (`shared_below_the_top`). Each held to the floor of 200: at the seed 5,703, 1,884 and 2,603 in the edit run, 1,108, 445 and 524 in the BEEF run (the step's draw is now one of 31, so every other count moved too; every floor holds, 1.5 s and 1.7 s in release, 22 s in debug for both). After `merge_transaction` the BEEF law asserts that `find_atomic_transaction` and `find_transaction_for_signing` of the id merged hand back that id, and each input that carried a source is linked to a source of the same id at every depth both reach (`same_sources`, an explicit stack); every stored entry linked for signing under its own id, and the last linked whole under its own. `fuzz_beef_parser` (`support/identity_law.rs`): every entry's id linked for signing and whole, each linked subject merged back through `merged_hands_back_what_it_took` (the same three checks), each edited one too, and a fourteenth edit: when an input is linked, a second input linked to a copy of its source under another lock time, then one text (`"zz"`, `""`, or 64 hex digits) on every input. Without the second source the fuzzer did not reach the state in its minute under the key plant (two different parents under one subject are rare among the seeds); with it, a crash inside the minute (not reproduced: the cold re-read of this fold ran the plant three times for 60 s with no crash, and the fourth fold five times from the committed seeds with no crash; the fourth fold's seed reaches it, "Fold 4" below).

**The plants** (`/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold3b/plants/`: `plants.py` applies each alone to an rsync of the tip and runs `transaction_identity_843`, `transaction_identity_attempts_869`, `beef_shared_txid_text_869`, `arch_field_writes_843`, `arch_test_doors_869` and the door's units, `--all-features --config profile.dev.debug-assertions=false`; the tip with no plant green):

| # | Plant | Caught by (first message) |
|---|---|---|
| 1 | set_version's clear | the property, the guard (`fields.rs:215`); 5 tests failing |
| 2 | set_lock_time's clear | the property, the guard; 13 tests failing |
| 3 | inputs_mut's clear | the property, the guard; 9 tests failing |
| 4 | outputs_mut's clear | the property, the guard; 9 tests failing |
| 5 | parts_mut's clear | the property, the guard; 8 tests failing |
| 6 | clear_caches: cached_hash.take() | the property; 16 tests failing |
| 7 | clear_caches: raw_bytes_cache.take() | the property; 17 tests failing |
| 8 | clear_caches: hex_cache.take() | the property; 8 tests failing |
| 9 | from_hex's hex cache not lower-cased | both runs of the property |
| 10 | add_input past its door | does not compile: E0616 |
| 11 | add_output past its door | does not compile: E0616 |
| 12 | sign's write past the door | does not compile: E0616 |
| 13 | fee's retain past the door | does not compile: E0616 |
| 14 | distribute_change's writes past the door | does not compile: E0616 |
| 15 | cold: clear_caches empties the hash alone | the property; 17 tests failing |
| 16 | cold: a door lends before it clears | does not compile: E0499 |
| 17 | cold: from_parts carries a cache | the property, the guard (`fields.rs:312`), the parts test; 6 tests failing |
| 18 | cold: Clone drops its link back | the property, the probe test; 12 tests failing |
| 19 | cold: add_op_return_parts_output past add_output | does not compile: E0616 |
| 20 | clone_for_beef flips the copy's lock time | the probe test, the BEEF-copy property |
| 21 | clone_for_beef repairs a missing txid alone | the probe test, the BEEF-copy property |
| 22 | the linking door never empties | the door's units alone (`"zz": the law after the link`) |
| 23 | the linking door empties only a missing txid | the door's units alone |
| 24 | the oracle back under `cfg(any(test, fuzzing))` | `arch_test_doors_869` |
| 25 | the parts' `Default` back to version 0 | `the_parts_default_is_transaction_new_869` (`byte for byte`) |
| 26 | the linking door keeps when the text does not parse | the door's units alone |
| 27 | the linker's stubs keyed by the raw text (item 2 put back) | the BEEF-copy property (`seed 0x869beef0002, sequence 5, steps [.., "shared txid: does not parse"]: find_atomic_transaction of the id merged`), the three tests of `beef_shared_txid_text_869`; `fuzz_beef_parser` crashed inside its minute (`a linked source's id (#869)`; not reproduced by the cold re-read or by the fourth fold from the committed seeds, five runs of 60 s; with the fourth fold's seed five of five at once) |
| 28 | `input_txids` by `get_source_txid` | `a_beefs_graph_names_the_outpoints_its_bytes_carry_869` (`["zz"] input_txids`) |
| 29 | the in-memory judge's outpoint by the text | the same test (`["zz"] the in-memory verdict against the bytes'`) |
| 30 | guard (a): `fn plant_update(f: Fields, v: u32) -> Fields { Fields { version: v, ..f } }` | the guard: `fields.rs:586: plant_update builds Fields by a struct update, which copies the caches under a new field` |
| 31 | guard (b): `self.clear_caches(); let _ = self.fields.raw_bytes_cache.set(bytes);` | the guard: `fields.rs:523: plant_fill fills a cache outside the listed fills (["read_exact", "with_cached_bytes_for_test"])` |

The three door plants (22, 23, 26) are not RED in the property, and cannot be by any public door: the brief asked for it on the cold re-read's finding that they broke the law through `find_atomic_transaction`, which held only while the linker handed an input another transaction's source. With the key on what an input links, every link the door makes (the input's own source taken and put back after its walk, or a stub of the same id) leaves the outpoint's bytes as they were, so keeping or emptying the caches cannot move an id: they are cost plants on this shape, as "always empties" was, and the door's units are their only witness (stated). Plant 24 as first written moved only the `pub(super)` helper and stayed green (the guard reads `pub` items); written to move both, RED.

**The guard's two blind spots.** `tests/arch_field_writes_843.rs` gains `update_and_fill_errors`: a `Fields {` literal holding `..` followed by an expression (a struct update; a rest pattern's `..` is followed by `}`) in a function not on `ALLOWED`, and `<cache>.set(` or `OnceLock::from` in a function not on `FILLS` (`read_exact`, `with_cached_bytes_for_test`). The two planted functions RED (plants 30, 31); the eighteen `ALLOWED` entries pass, unchanged; the probe test `the_update_and_fill_rule_judges_the_probe_869` (three refused, a rest pattern, a listed fill, a plain literal and a range passing). `judged_fns` reads its functions through the same `fn_items`. A fill through `get_or_init` with a caller's closure is not read (stated in the file's header).

**A deep chain of texts that do not parse.** No test pinned it (`tests/beef_deep_chain.rs` and the #869 files read). `a_deep_chain_whose_txid_texts_do_not_parse_hashes_serializes_and_verifies_on_a_small_stack_869`: the 100,000-link chain with every input's text `"zz"`, `id()`, `to_binary()` and `verify` on one 1 MiB thread (0.53 s in debug), the id and bytes the parsed chain's, `verify` refusing the subject's input in its words. On `18ff3307`, a scratch copy with the test written to its public fields (`invalidate_caches` at each level), one walk per process at 20,000 links: `id`, `to_binary` and `verify` each exit 101 with `thread '<walk>' has overflowed its stack` / `fatal runtime error: stack overflow, aborting`. Nothing aborting is left in the tree.

**`from_beef` at 20,000 deep.** Release, a 20,000-link chain of `OP_1` spends over a proven root, medians of nine per pass, alternating binaries (`timing*.txt` in the out folder). At a one-minute load of about 3, `18ff3307` 34.9 to 38.2 ms against the tip 40.1 to 40.9 ms; the tip and `5bf34e29` within each other's passes, and a copy of the tip with this fold's three source changes reverted alternating with the tip (load 9) on both sides of it. Splitting `from_beef` into its read (`Beef::from_binary`) and its link (`find_atomic_transaction`): the difference sat in the link, and a copy of the tip with `names_32_bytes` (`fields.rs`) cut to its length check ran inside `18ff3307`'s spread (link 13.2 to 13.4 ms against 13.5 to 13.9, the tip 13.9 to 14.9; load 5). The scan runs in `replace_source` (once per link, the second fold's door), in `clone_for_beef` and, since this fold, in `outpoint_txid_name` on the read path; the last two now skip it where no source is linked (it decides nothing there). After that, eight passes at a load of about 4: `from_beef` 31.1 to 34.8 ms (median 31.65) against `18ff3307`'s 30.2 to 31.9 (median 30.5), +3.8%; `from_beef` then `verify` median 47.8 against 46.6, +2.6%; the read equal (15.4 to 16.1 against 15.4 to 16.2 ms), the link 14.1 to 16.1 against 13.5 to 14.3. The rest is the linking door's per-link scan, stated in the CHANGELOG's entry (above 3%).

**The gate** (`CARGO_BUILD_JOBS=4`, one cargo at a time). The three Rustfmt lines of `ci.yml`; clippy `--all-targets --all-features -D warnings`; the doc build under `-D warnings`; the doc tests (317 passed, 128 ignored); the 26 files of `grep -l '843\|869' tests/*.rs` three times, one at `--test-threads=1`, 316 passed each; the whole suite with `full,http,websocket` in pieces: the library 1,829 passed and 4 ignored, the 360 integration files in eight groups of 45, 3,774 passed, 0 failed, 29 ignored; 5,920 passed, 0 failed, 161 ignored: the second fold's 5,898 and 160, plus #876's 16 tests and 1 doc test and its ignored recorder (`shamir_backup_854.rs`; `integration_tests.rs` and `secret_debug.rs` unchanged in count, the library's count unchanged), plus this fold's five (three in `beef_shared_txid_text_869.rs`, the guard's probe, the deep chain), no test fewer. Examples, `readme_examples`, `bench --no-run`, `cargo +nightly fuzz build`; `fuzz_beef_parser` 88,233 and 89,716 runs and `fuzz_transaction_parser` 605,898 and 588,787 in two 60 s runs each on the final edit, no crash (corpora copied to the out folder, the tree's untouched). The wasm32 slice. The two conformance files with the ts-stack corpus: 5,116, 4,121 run, 4,110 passed, 958 unsupported, unmoved. The `sibling` job's steps at its pin (`1c051eae`, a local clone): the harness's unit tests OK, 13,765 entries, 0 divergences, GREEN. `beef_deep_chain` alone in release: 12 passed, 1.02 s. `cargo semver-checks` against `origin/beta`: the same two lints (`inherent_method_missing`, `struct_pub_field_missing`). The rustdoc JSON (`--all-features`; ids, spans, docs dropped, ids resolved to names, interned attribute numbers normalized): against `02b3f2f3`, this fold's parent, no difference; against `5bf34e29`, #854's items alone (`shamir`, `split_private_key_with`, `to_backup_format`, `recover_private_key_from_legacy_backup`). The ratchet against `origin/beta` passes once `beef.rs` is held to its 3,074-line ceiling (the linker's new lines tightened; it refused 3,077); `mutants_entries.py` passes with the `dependency_order` entry re-pointed to `1154:29`; `rows_from_sources.py --check` 0 refusals; gitleaks over `origin/beta..HEAD` no leaks. The linker's last reshape (`map_or(text, Transaction::id)`, the same expression) came after the suite: clippy, the ratchet and the plants' clean tip and plant 27 were run on it.

## Fold 4

Lane `break-tx-fields-fold4`, from `b603b27a` (beta `3814053b`), after the cold re-read of the third fold (FIX, 0.62). Its three standing items and its unrun measures, nothing wider. Logs, probes and the recordings' runs: `/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold4/`.

**The linker descends an input that names no txid.** `add_input_proof` (`src/transaction/beef.rs`) skipped an input whose `source_txid` is absent (`with_source_transaction`, `add_input_from_tx`), where the reference's `#addInputProof` descends every linked source (`ts-stack@edf6e03` `Beef.ts:649-679`). Its key is now the linked source's id whether or not the input names a txid, else the text; an input that links and names nothing is left as it is. The reference's answers, by a run (`tests/support/beef_input_without_txid_869.mjs`, the bundle of `packages/sdk` at `edf6e03` by bun, Node v22.18.0, two runs byte-identical, `tests/vectors/beef_input_without_txid_869.json`), each state merged by `mergeTransaction` then `findAtomicTransaction` of the child:

| State | The reference | `b603b27a` | The tip |
|---|---|---|---|
| (a) a linked source a BUMP of the BEEF proves | the source, with the path | the source, no path | the source, with the path |
| (b) a linked unproven source over a linked unproven source | both, descended, no path | the same | the same |
| (b2) as (b), the deepest proven | both, the deepest with the path | both, no path | both, the deepest with the path |
| (c) no linked source, no txid | `sourceTransaction is undefined` at `id` and at `mergeTransaction`, before any BEEF door | merged (the outpoint written as zeros), the input left | the same: stated |
| (d) a linked source the BEEF does not hold (removed after the merge) | its own source, descended, no path | the same | the same |

Every source by id is the reference's in (a), (b), (b2) and (d). Two cells are stated, not followed. The reference's `mergeTransaction` runs `materializeSourceTXIDs` over the caller's graph before it merges (`Beef.ts:883`, `Transaction.ts:254-271`), writing each linked source's id into the input's `sourceTXID`; `merge_transaction` stores the transaction as given (#764), so the input comes back naming no txid (counted per state in the test and pinned apart). State (c) cannot be conformed without a `Result` on `id()` and `merge_transaction`: kept. Neither changes what `verify`, `to_beef` or `to_atomic_beef` answer for well-formed input; no peer's bytes build either state: every transaction reader gives each input its 64-hex-digit text (`transaction.rs:293,393`), the JSON reader its member's (`tx_json.rs:225`), and a BEEF's entries are read from bytes. Nothing for a private report. Of the consequence: a caller who builds a graph through `add_input_from_tx`, merges it and links it again through `find_atomic_transaction` now has the BEEF's proof on a proven source, so a `verify` of that result checks the proof where it ran the source's ancestry before (the reference's answer).

RED: `tests/beef_input_without_txid_869.rs` on a scratch copy of `b603b27a` (its own target dir): 2 of 5, `state a: the source and its path` (`"path": Bool(false)` against `Bool(true)`) and `state b2: the deepest source with the BEEF's path`; green on the tip. The plant that puts the skip back on the tip: the same two, by the same messages.

For well-formed input nothing moved: 20,000 random transactions, sources two deep, two in five linked inputs naming no txid, three in ten sources carrying a path of their own, through `to_binary`, `id`, `to_beef`, `to_atomic_beef`, and `from_beef` and `from_atomic_beef` with every linked source's id, path and text: one digest `655605a04db01d3fb75f4ad27135bf860a3d73a28f40e50dee66b553fa030cb3` on `b603b27a` and on the tip (`rprobe/src/bin/diff.rs`). The linker is reached by `find_atomic_transaction` alone; the writers walk `collect_ancestors`.

**The fuzz claim.** Under the key plant (the raw text as the linker's key) in a scratch copy of the tip, from the committed corpus alone (66 seeds, an empty directory ahead of them for what libFuzzer adds), five runs of 60 s with `-seed=1` to `5`: none crashed (91,329, 76,581, 81,349, 87,109 and 94,116 inputs). The third fold's sentence that the target crashed inside its minute is not reproduced by any run here or by the cold re-read's three. The target reads its edits from the input's own bytes (`identity_law.rs`, `edits_keep_the_law`): the leading byte decides the count, so on a well-formed BEEF the edits are fixed by its header and the shared-text edit (`op % 14 == 13`) needs a byte inside the frame that libFuzzer must hit while the BEEF stays valid. One seed added through `fuzz/corpus-gen` (`shared_text_edit_seed`, this crate's writer, its layout asserted): `fold4-869-shared-text-edit`, a V2 BEEF of a proven parent and its child, two edits (`02`), the version and then the leading BUMP's block height's low byte, 269 written `fd 0d 01` (13). Under the plant from the committed corpus with it: five runs of five crash at once, on the seed (`a linked source's id (#869)`, `identity_law.rs:217`). On the clean tip both parser targets ran twice for 60 s, no crash (`fuzz_beef_parser` 99,765 and 115,068 inputs; `fuzz_transaction_parser` 631,434 and 620,164). A full `corpus-gen` run panics in `wallet_corpora` (`fuzz/corpus-gen/src/main.rs:432` on the tip, `:394` on `origin/beta` at `3814053b`, the cold re-read of the fourth fold's run; five `tests/vectors/wallet_wire/*.json` files carry no `wire` member, the oldest from #338): older than this lane, after the BEEF corpora are written; every other seed of `fuzz_beef_parser` was rewritten byte for byte.

**The guard sees a child module.** `tests/arch_field_writes_843.rs` reads `fields.rs` alone, so a `#[path]` child module in another file, which sees `Fields`' private fields, wrote past it unseen. `shape_errors` now refuses a `mod` item in `fields.rs` outside `#[cfg(test)]` (`arch_support`'s tokens drop a `#[cfg(test)]` item), inline or by `#[path]`, naming it; pinned on a probe (a `#[cfg(test)]` module by `#[path]` and inline passes; a `#[path]` module, an inline `pub(super)` one and one under `cfg(any(test, feature = ..))` refused). The plant: `#[path = "plant_writer.rs"] mod plant_writer;` in `fields.rs`, its file `f.outputs.clear()` on a `&mut super::Fields`: RED, `fields.rs:641: mod plant_writer in fields.rs outside #[cfg(test)]: a child module, ...`. The root `CLAUDE.md`'s sentence and `tests/CLAUDE.md`'s row say what it enforces; a `get_or_init` fill after a leading `self.clear_caches();` stays green and is stated in the guard's header.

**The plants** (each alone on an rsync of the tip, `plants/plants.py`, the four files `beef_input_without_txid_869`, `beef_shared_txid_text_869`, `arch_field_writes_843`, `transaction_identity_843`):

| # | Plant | Caught by (the message) |
|---|---|---|
| 1 | the linker's skip put back | `beef_input_without_txid_869`, 2 of 5 (`state a: the source and its path`) |
| 2 | the linker keyed by the raw text | `beef_shared_txid_text_869`, 2 of 3 (`["zz"] find_atomic_transaction's id`); `fuzz_beef_parser` on the new seed, five of five |
| 3 | a `#[path]` child module of `fields.rs` writing a field | `arch_field_writes_843` (`mod plant_writer in fields.rs outside #[cfg(test)]`) |

**Measures the cold re-read did not run.** `from_beef` on chains written by this crate (`rprobe/src/bin/gen.rs`: a proven root, each link spending the last), release, two scratch builds (`18ff3307` and the tip, their own target dirs), four alternating passes at a one-minute load of about 3, each a median of nine; the median of the four, `18ff3307`'s figure before the tip's: 2,000 links `from_beef` 2.74 ms on both, `from_beef` then `verify` 4.36 against 4.37; 20,000 links `from_beef` 29.9 against 31.3 (+4.8%; the tip's passes 30.9 to 35.3, the base's 29.6 to 30.3), with `verify` 46.1 against 47.3 (+2.6%). The CHANGELOG's cost sentence is restated to these figures. The rustdoc JSON (`--all-features`) of `b603b27a` and the tip: 17,587 items each, none differs with spans dropped; the only other difference is the external crates' rmeta paths, which name the target dirs. `cargo semver-checks check-release --baseline-rev 3814053b --all-features --release-type patch`: 229 checks, 2 fail, the same two lints (`inherent_method_missing` for `invalidate_caches`, `struct_pub_field_missing` for the four fields), no other.

**The gate** (`CARGO_BUILD_JOBS=4`, one cargo at a time, scratch target dirs under `/Volumes/Lanes/targets/break-tx-fields-fold4-*`, removed after). The three Rustfmt lines; clippy `--all-targets --all-features -D warnings` and the `transaction` slice; the doc build under `-D warnings`; the doc tests 317 passed, 128 ignored; the 27 files of `grep -l '843\|869' tests/*.rs` three times, one at `--test-threads=1`, 321 passed each; the whole suite with `full,http,websocket` in pieces: the library by its fourteen modules (each named in full, `--exact`) 1,829 passed and 4 ignored, the 361 integration files in eight groups 3,779 passed, 0 failed, 29 ignored; 5,925 passed, 0 failed, 161 ignored: the third fold's 5,920 and 161 plus this fold's five, every one of `b603b27a`'s 6,081 test names present. `beef_deep_chain` alone in release 12 passed; examples built; `cargo +nightly fuzz build`. The wasm32 slice. The two conformance files with the corpus at `edf6e03` (`git archive`): 5,116, 4,121 run, 4,110 passed, 958 unsupported, unmoved. The `sibling` job's steps at its pin (`1c051eae`, a local clone): the harness's 67 unit tests OK, 13,765 entries, 0 divergences, GREEN. The ratchet against `origin/beta` passes (`beef.rs` 3,072 lines, two under its ceiling); `mutants_entries.py` passes with the `dependency_order` entry re-pointed to `1152:29`; `rows_from_sources.py --check` 0 refusals; gitleaks in git mode, no leaks.

## Fold 5

Lane `break-tx-fields-fold5`, from `041f6f7a` (beta `3814053b`), after the cold re-read of the fourth fold (FIX, 0.7): its one gap, and its observation classed. Logs and plants under `/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold5/`. The re-read's commit `1e684338` (the #843 parity note states the linker's two cells; the corpus-gen panic's line) is picked first.

**The guard refuses the class, not one member.** The fourth fold refused a child module of `fields.rs`; the re-read wrote `self.version` past `clear_caches()` with the guard green through two siblings: `include!("x.rs")` in `fields.rs`, and a `macro_rules!` of `transaction.rs` invoked at item level there. `tests/arch_field_writes_843.rs` now holds that `fields.rs` carries no code the rule does not read as written there: `expansion_errors` refuses a macro invocation whose bare name is not on `MACROS` (`debug_assert`, `matches`, `vec`: the file's three, std's, each expanding to its arguments' code, which is the file's text), at item level or in a body, a macro named by a path, an attribute (outer or inner) not on `ATTRIBUTES` (`allow`, `cfg`, `doc`, `derive`), a derive not on `DERIVES` (`Debug`, `Clone`), a glob `use` and a `use` importing a listed name; `shadow_errors` refuses a `macro_rules!` anywhere under `src/` taking a listed name. The header lists each way Rust puts code in a file and what the rule does with it (a child module, `#[path]`, `include!` and its two siblings, a foreign macro, a `macro_rules!` defined in `fields.rs`, `#[cfg_attr]`, a proc-macro attribute or derive: each refused; an `impl` elsewhere and a dependency's macro of a listed name: the compiler's, E0616 and E0659). `arch_support::Source::tokens_with_attributes` keeps the attributes the scan drops (an item under a known-false cfg still skipped whole). Pinned on a probe (`the_expansion_rule_judges_the_probe_869`).

**The plants** (one rsync of the tip, all three at once, each compiling under `--features transaction` and writing past the caches; `plants_old_guard.log`, `plants_new_guard.log`):

| # | Plant | `041f6f7a`'s guard | This guard (the message) |
|---|---|---|---|
| 1 | `include!("plant_include.rs");` in `fields.rs`, its file writing `self.fields.version` | green | `fields.rs:715: \`include!\` in fields.rs: a macro outside the enumerated list` |
| 2 | `plant_writer!();` at item level in `fields.rs`, the macro defined in `transaction.rs` writing `self.fields.version` | green | `fields.rs:716: \`plant_writer!\` ...` |
| 3 | `plant_fill!(self)` in a `&self` function of `fields.rs` (no `mut`, no cache's name in its text), the macro defined in `transaction.rs` filling `hex_cache` | green | `fields.rs:720: \`plant_fill!\` ...` |

**The re-read's observation** (a generator whose `from_beef(None)` returned another transaction on both trees) is reproduced and classed in the lane's REPORT to the captain, not here.

## Fold 6

Lane `break-tx-fields-fold6`, from `519b0abd` (beta `46da3e71`), after the narrow read of the fifth fold (FIX, 0.9): four plants compiled, wrote `version` past `clear_caches()` and left the guard green (A: a trait method named `clear_caches` that does nothing; B: `Self { version: v, ..f }`; C: a closure in a `const`, F the same in a `static`; Q: `#[path]` on `mod fields;`, the guard reading the dead file). The third read in a row to find a spelling: a lexical guard cannot be made complete, so the invariant moved to the compiler (the captain's ruling). Logs, plant specs and the harness under `/Volumes/Lanes/out/bsv-rs/break-tx-fields-fold6/`.

**The sealed module.** `fields.rs` declares `mod sealed { .. }` inline; `Fields` lives there with every field private to `sealed`, its name `pub(in crate::transaction::transaction)` (the owner `Transaction` holds one), its functions `pub(super)` (visible to `fields.rs` alone): `new` (no cache), `read` (the four, shared), `caches` (the three, shared), `write` (the one exclusive door: the three `take()`s, then the four `&mut`), `into_four` (by value), `replace_source` (the linking door, which lends nothing: keeps the caches only where the input's `source_txid` is 64 hex digits, the outpoint rule's `Named` arm under which the serializer never reads the source, else empties them through `write`), `copy_relinked` (`Clone`'s step: the copy keeps the original's caches only where each input's new source has the cached hash the original's had, else none), `copy_named` (`clone_for_beef`: each input the serializer read through its source named by that source's id, the same bytes), the private `copy_with`, `names_32_bytes` (the outpoint rule's test, which `outpoint_txid` reads too) and the private `named`. No macro, derive or attribute inside but doc comments. It is 137 lines without comments, not 60: the two copies own their cache rules so no code outside can put copied caches under other fields, and the brief's second door (a `&mut` to a source without a clear) became `replace_source`, which performs the link itself. `transaction.rs`' `with_params` builds through `from_parts`. `Clone` builds each copy after its sources' copies (a list per frame); the `Clone` rustdoc is unchanged.

**What left the guard and what stayed.** Gone, the compiler refusing every write they read for: the leading-clear rule and its `ALLOWED` list (eighteen entries), the struct-update rule, the `ATTRIBUTES` and `DERIVES` lists, `FILLS` by `OnceLock::from`. Stayed for (c) alone, the cache fills, each now saying so: the macro rule (now `debug_assert!` alone outside `sealed`; `vec!` became `Vec::from`, `matches!` left with `replace_source`), the `use` and shadow checks of that name, `macro_rules!` in `fields.rs`, and the child-module rule (a module outside `#[cfg(test)]`). New: (a) the `sealed` pin (items by signature, `pub`, attributes, macros, `write`'s opening, the FNV-1a digest of its tokens) and (b) the declarations (`mod transaction;` twice, `mod fields;`, `mod sealed {`, each name once under `src/`). The guard reads raw tokens (`arch_support::Source::raw_tokens`), so no `#[cfg]` hides an item from the pin.

**The plants** (each alone on an archive of the tip, `plants/run.sh` with `plants/specs.json`, `cargo check --features transaction --lib`, then the guard where it compiles; `plants/plants.log`):

| Plant | Shape | On the tip |
|---|---|---|
| A | trait `Nop { fn clear_caches(&self) {} }` for `Fields`, then `self.version = v` | E0616 |
| B | `Self { version: v, ..f }` | E0451 |
| C, F | a closure writing `f.version` in a `const`, in a `static` | E0616 |
| D | `impl Fields` in a function body | E0616 |
| E1, E2 | a `From` impl; a private trait's default method | E0616 |
| G | a body `macro_rules!` reading `$s.fields.version` | E0616 |
| H, H2 | `use crate::plant_h as matches;` and its braced form | compile, write nothing (`fields.rs` invokes no `matches!`); guard green |
| I1 | `crate::plant_i!(1)` | compiles, writes nothing; guard red (`plant_i!` in fields.rs) |
| I2 | `#[macro_use] extern crate std` | E0468 |
| J1, J2 | `#[cfg(not(test))]`, `#[cfg(any(test, debug_assertions))]` modules writing `super::Fields` | E0616 |
| K1, K2 | `let f = &mut self.fields; f.version = v`; the destructuring form | E0616; E0451 |
| P1 | `include!("plant_include.rs")` writing `self.version` | E0616 (in the included file) |
| P2 | a `macro_rules!` of `transaction.rs` at item level writing `self.version` | E0616 |
| P3 | a macro of `transaction.rs` filling `hex_cache` through `&self` | E0616 |
| P3c | P3 through `caches().2.set(..)` | compiles, fills a cache; guard red (`plant_fill!` in fields.rs) |
| M4 | the fourth fold's `#[path]` child module writing `Fields::version` | E0616 |
| Q | `#[path = "transaction/fields_q.rs"] mod fields;`, the copy writing `self.fields.version` | E0616 |
| Qs | Q with the copy's `write` stripped of its takes | compiles; guard red (`mod fields` must be `mod fields;`; `mod sealed` declared 2 times) |
| T1, T2 | `transaction.rs` writing `self.fields.version`; calling `read()` | E0616; E0624 |
| U1 | a raw pointer write in `unsafe` | `unsafe_code = "forbid"` |
| R1 | the reverse plant: `write` without its three takes | compiles; guard red (`Fields::write` does not open with the three caches' `take()`; the digest); `transaction_identity_843` red (`to_binary() is the fields' bytes`, four tests) |
| R2 | a third function in `sealed` (`version_mut`) | compiles; guard red (an item not on its list; an attribute; the digest) |
| R3 | `pub(crate)` on `version`, written from `fields.rs` | compiles; guard red (an item not on its list; a `pub` wider than `pub(super)`; the digest) |

No plant compiles, writes a field past the caches and leaves every machine green.

**Measurements.** Differential (`harness/fold6_differential.rs`, release, on archives of `519b0abd` and the tip, each in its own target dir): 20,000 random transactions with sources two deep (`to_binary`, `id`, `to_beef(true)`, `to_atomic_beef(true)`, `from_beef` and its id and bytes, `clone`'s id) `886fbf8a35ae2908d5afcb367ee2835cc58a6afde8c19b1cb3e1885197a325a5` on both; 20,000 sequences of 8 edits through `set_version`, `set_lock_time`, `inputs_mut`, `outputs_mut`, `parts_mut`, `add_input`, `add_output`, a linked source's `set_lock_time` through `inputs_mut`, `into_parts`/`from_parts` and `clone`, `id()` read after each, `b2ff43f45a5f7b38da17db67f3b1da11714249110e5b118cdb7ea48b0fe67a44` on both. (A first tip run in a target dir shared with the R1 plant read a stale library and gave another edit digest; rerun in a fresh dir it agrees.) Timings, ms, passes 0 to 3, load 3 to 4:

| | `519b0abd` | tip |
|---|---|---|
| verify, 2,000 | 2.44, 2.36, 2.23, 2.17 | 2.42, 2.22, 2.15, 2.13 |
| to_beef, 2,000 | 2.10, 1.82, 1.80, 1.80 | 2.14, 1.77, 1.80, 1.82 |
| from_beef, 2,000 | 3.23, 2.88, 2.81, 2.83 | 3.37, 2.86, 2.90, 2.91 |
| clone, 2,000 | 0.18, 0.14, 0.13, 0.13 | 0.26, 0.16, 0.16, 0.16 |
| verify, 20,000 | 21.29, 21.18, 21.08, 20.93 | 20.96, 20.85, 20.75, 20.88 |
| to_beef, 20,000 | 20.48, 19.74, 20.05, 19.99 | 20.65, 19.72, 19.32, 19.66 |
| from_beef, 20,000 | 35.00, 32.64, 31.68, 31.80 | 33.12, 32.30, 30.88, 31.51 |
| clone, 20,000 | 2.74, 2.48, 2.33, 2.40 | 2.70, 2.42, 2.27, 2.27 |

`clone` at 2,000 links is outside the base's spread by about 0.03 ms (15 ns a link: the list of copied sources each frame builds); the rest inside. Surface: the rustdoc JSON of both (`--all-features`, nightly), ids, spans and interned symbol numbers normalized (`harness/rustdoc_cmp.py`): 3,962 items each, 0 differ.

**The gate** (`CARGO_BUILD_JOBS=4`, one cargo at a time, each under ten minutes). The #843 and #869 files three times (the third with `--test-threads=1`): 37 passed each, and the 6 `link_source_869` units. The whole suite with `full,http,websocket`: the library by module filter, 1,833 unique tests, 1,829 passed and 4 ignored (two names matched two filters); the 362 integration files in four `--test` groups, 3,808 passed, 29 ignored; the doc tests, 317 passed, 128 ignored: 5,954 passed, 0 failed, 161 ignored, the `--list` of the library and the integration files against `519b0abd`'s equal save the guard's own names (four replaced by five). `beef_deep_chain.rs` alone, 12 passed. Conformance with `BSV_CONFORMANCE_DIR`: 5,116 total, 4,121 run, 4,110 passed, 958 unsupported, 37 skipped, 11 known failures, 0 failures. `cargo +nightly fuzz build`; `fuzz_transaction_parser` and `fuzz_beef_parser` twice for 60 s each, no crash. Clippy `--all-targets --all-features -D warnings`, the doc build with `-Dwarnings`, the three Rustfmt lines and the ratchet's own, the wasm32 slice (its build, the `http` refusal at `build.rs`, the cdylib), the `sibling` job's steps (13,765 entries, 0 divergences), `cargo semver-checks check-release --baseline-rev 46da3e71 --all-features --release-type patch` red on `inherent_method_missing` (`invalidate_caches`) and `struct_pub_field_missing` (the four fields) alone, the ratchet against `46da3e71` (`fields.rs` at 800 lines), `mutants_entries.py`, `rows_from_sources.py --check`, gitleaks over `46da3e71..HEAD`: all green.

**A finding older than this fold.** Five `compile_fail` fences in `fields.rs` name a code the compiler no longer gives: `tx.version = 2`, `tx.lock_time = 7`, `tx.inputs.push(..)` and `tx.outputs.push(..)` say E0616 and fail with E0615 (no field of that name since #869's fold, a method of it), and the `Transaction { version: 1, .. }` literal says E0451 and fails with E0560. Stable rustdoc does not check the code, so the gate is green; nightly's rustdoc reds all five, on `519b0abd` as on the tip. Each still fails for the right reason (no field to write). The fences are public doc text, which this fold keeps as it was; correcting the five codes is a one-line change each for the next fold.
