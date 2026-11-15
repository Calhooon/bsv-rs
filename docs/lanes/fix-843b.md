# Lane fix-843b: a `Beef` owns `txs` and `bumps` and its txid doors take a `Txid` (#843, its second pull request)

Base: `471bdaf640334151b172e6b84708e55b44e1aeca` (pull request #974's head, an input's `source_txid` a `Txid`, rebased onto beta `d892e206`); this pull request is stacked on it. Logs: `/Volumes/Lanes/out/bsv-rs/fix-843b/`. Host rules: one cargo at a time, `CARGO_BUILD_JOBS=2` while the host's swap use stood above half and 4 otherwise, targets `/Volumes/Lanes/targets/fix-843b`, `-red` (the base's scratch copy), `-tip` (the tip's), `-hb` and `-ht` (the harness against each), `-fuzz`, `-semver` and `-dep`, each removed at the end.

## The rule and the decision

Part O of #843's ensemble (5 of 5 for `txs`, 4 of 5 for `bumps`; `docs/design/843-identity-and-framing.md`, section 3): a type that stores something derived from its fields (a cache, an index, a position another field points at) lends them only through `&mut` doors that repair the derived value. And the tie-break on the typed id (T1, 3 of 3): "the `Beef` doors that take a txid take a `Txid` in the same cut as the private `txs`". #974 built the input's half; this is that cut. The captain's rulings of 2026-11-15 stand as the brief worded them: the doors take a `Txid` by value; `BeefTx::txid() -> Txid` with `id() -> String` beside it; `SortResult`'s lists hold `Txid`; `atomic_txid: Option<Txid>` stays public; `Utxo::txid` stays text here (a pull request of its own follows); `MerklePath` and the stream's `Hash32` are not touched; no new recording of the reference lands; `merge_bump -> Result` and a door that lends an entry for signing are not built (the ways are in the lane's REPORT).

The shape diverges from the reference, stated: it keeps `bumps` and `txs` public (`ts-stack@edf6e03` `Beef.ts:163-166`), repairs lazily (`:342-352`, `:516-524`) and holds every txid as a string, checked at no door (`:497`, `:552-565`, `:919-929`, `BeefTx.ts:183-190`). go-sdk@2ca481c keeps both fields public too (`transaction/beef.go:20-24`) and keys them by a typed hash.

## The site, side by side

Each line re-found by its text at `471bdaf6` before anything was changed.

| | The reference (`edf6e03`, read) | go-sdk (`2ca481c`, read) | This crate at the base | This crate now |
|---|---|---|---|---|
| The rows | `bumps`, `txs` public (`Beef.ts:163-164`); four private maps keyed by the txid's string (`:167-170`) | `BUMPs []*MerklePath`, `Transactions map[chainhash.Hash]*BeefTx`, public (`beef.go:20-24`) | `pub bumps`, `pub txs`; beside them `txid_index: HashMap<String, usize>`, `indexed_len`, `holds_twins`, `needs_sort`, `wire_order` (`beef.rs:105-128`) | `Rows`, private to `beef/rows.rs`' `sealed` module: `txs`, `bumps`, the index (`OnceLock`, keyed by `Txid`), `needs_sort`, `wire_order`; read through `txs()`, `bumps()` |
| The repair | lazy: `synchronizeNestedTransactionMutations` at `findTxid` and the other doors that synchronize (`:342-352`, `:497-500`), `#rebuildTxIndexes` the last position winning (`:516-524`), `#invalidateBumpIndexes` when the BUMPs moved (`:296-309`); `clone()` shares the entries and drops the maps (`:1605-1622`) | the map is the index | eager at the doors, and for a hand edit of `txs` only where it could be noticed (`beef/index.rs:15-31`, the stated window; `sync_index`, `refresh_mutated`, `reindex`) | none needed: no code outside `sealed` changes a row but through a function that does the index's and the marks' part, or the one general door that empties the index before it lends |
| An entry lent mutably | every entry, always (`findTxid` returns the object) | the pointer | `find_txid_mut` (`beef/index.rs:231-233`), `BeefTx::tx_mut` (`beef_tx.rs:245-255`, deprecated), `pub input_txids`, `pub is_valid` (`beef_tx.rs:68,70`), `raw_tx_or_compute(&mut self)` (`:348-360`) | no door; `edit_tx`, `set_bump_index`, `edit_bump`, `retain_txs`, `retain_bumps` |
| Removal | `removeExistingTxid` (`:907-917`: a splice, the rest's order kept, the index rebuilt); `trimKnownTxids` (`:1649-1685`) | `RemoveExistingTxid` (`beef.go:852`) | a hand `txs.retain` and a hand remap (`trim_known_proven`, `beef.rs:511-608`, the one in-crate instance) | `retain_txs` (order kept), `retain_bumps` (every entry re-pointed; an index that named no BUMP kept as given) |
| A txid at a door | a `string`, checked at none (`findTxid` `:497`, `makeTxidOnly` `:552-565`, `findBump` `:570-574`, `findTransactionForSigning` `:615-629`, `findAtomicTransaction` `:639-646`, `mergeTxidOnly` `:919-929`, `toBinaryAtomic` `:1210-1212`, `sortTxs`' five lists `:1352-1358`; `BeefTx.ts:77-78`) | a typed hash at every door (`beef.go:620,640,655,681,801,852,952,1700`); the sort's lists `[]string` (`:1054-1060`) | text everywhere (`beef.rs:115`, `beef_tx.rs:66`, `:163-174`, `beef.rs:439-449`); the writer where a text that is no txid was judged (`beef_tx_writer.rs:79-92,120-127,153-155`) | a `Txid` at every door of the table below; the writer's three arms gone |

## The scan

The brief's three commands, from the worktree's root, at the base (`logs/scan-base.txt`) and at the tip (`logs/scan-tip.txt`); the rustdoc JSON of "The break, measured" is the list that counts and agrees with it.

At the base: 16 signatures, 8 fields, 13 signatures outside the BEEF's files.

At the tip: 6 signatures, 1 field, 12 signatures outside the BEEF's files (`from_beef` left that list). What is left, each for its reason: `display_hex(&Hash32)` (the stream's 32 bytes, no text door), `BeefTx::id()` (the text beside `txid()`), `Beef::from_hex`, `to_hex` and `to_log_string` (a frame's hex, a log), `verify_structure`'s roots and `BeefValidationResult::roots` (a merkle root is no txid); outside the BEEF's files the broadcasters' answers, `TransactionInput::get_source_txid`, `add_input_from` (#845's reader of a text, its words kept) and `MerklePath`'s doors, which Part O does not touch.

    src/transaction/beef_stream.rs: pub fn display_hex(hash: &Hash32) -> String 
    src/transaction/beef_tx.rs: pub fn id(&self) -> String 
    src/transaction/beef_writable.rs: pub fn to_hex(&mut self) -> Result<String> 
    src/transaction/beef.rs: pub fn verify_structure(&mut self) -> std::result::Result<HashMap<u32, String>, Kind> 
    src/transaction/beef.rs: pub fn from_hex(hex: &str) -> Result<Self> 
    src/transaction/beef.rs: pub fn to_log_string(&mut self) -> String 
    --- fields
    src/transaction/beef.rs:81:    pub roots: HashMap<u32, String>,
    --- outside the BEEF's files
    src/transaction/broadcaster.rs: pub fn success(txid: String, message: String) -> Self 
    src/transaction/broadcaster.rs: pub fn success_with_competing( txid: String, message: String, competing_txs: Vec<String>, ) -> Self 
    src/transaction/broadcaster.rs: pub fn with_txid(code: String, txid: String, description: String) -> Self 
    src/transaction/input.rs: pub fn get_source_txid(&self) -> crate::Result<String> 
    src/transaction/merkle_path_verify.rs: pub async fn verify(&self, txid: &str, tracker: &dyn ChainTracker) -> Result<bool> 
    src/transaction/merkle_path.rs: pub fn new_txid(offset: u64, hash: String) -> Self 
    src/transaction/merkle_path.rs: pub fn from_coinbase_txid(txid: &str, height: u32) -> Self 
    src/transaction/merkle_path.rs: pub fn compute_root(&self, txid: Option<&str>) -> Result<String> 
    src/transaction/merkle_path.rs: pub fn contains(&self, txid: &str) -> bool 
    src/transaction/merkle_path.rs: pub fn contains_and_mark(&mut self, txid: &str) -> bool 
    src/transaction/merkle_path.rs: pub fn txids(&self) -> Vec<String> 
    src/transaction/transaction.rs: pub fn add_input_from( &mut self, prev_txid: &str, vout: u32, prev_locking_script: &LockingScript, satoshis: u64, template: crate::scr

## The holes, run on the base

A probe written against the base's API (`probe/red_843b_probes.rs` in the out folder; it does not land), on a scratch copy of the base (`git archive 471bdaf6`, target `/Volumes/Lanes/targets/fix-843b-red`): `cargo test --features transaction --test red_843b_probes -- --nocapture --test-threads=1`, 13 probes, output `probe/base_probe.log`.

| Hole | On the base (run) | On the tip |
|---|---|---|
| 1. A hand replacement inside the indexed prefix (`beef.txs[0] = entry of C`) | `find_txid(C)` `None` for the held C; `merge_raw_tx(C)` stores it again: 3 entries, 2 holding C | does not compile (E0615 from outside the crate, where `txs` is a method; E0616 from inside it); the same replacement through the rows' general door is found at once and merged once (`a_replacement_in_place_is_found_at_once_843b`) |
| 2. `*beef.find_txid_mut(a).unwrap() = BeefTx::from_txid(b)` | the entry holds B; `find_txid(B)` `None`, `find_txid(A)` `None`; `merge_txid_only(B)` stores a second B | does not compile (E0599: no `find_txid_mut`) |
| 3. `find_txid_mut(t).set_bump_index(..)` on a BEEF read from bytes (#764's residue) | `merge_beef` of it still walks the entries as read (`[child, parent]`), where a marked BEEF is walked sorted (`[parent, child]`) | `set_bump_index(t, ..)` sets both marks: walked sorted (the reference's order for an edited BEEF) |
| 4. `BeefTx::tx_mut`'s #171 window | after the edit `find_txid(new)` `None` and `find_txid(old)` `None`; `merge_raw_tx(new)` stores it twice | does not compile (E0599); `edit_tx` re-keys at once |
| 5. A hand `bumps.remove(0)` | the entry that named BUMP 0 (height 100) names the BUMP of height 101; the next names none; `verify_structure` `TxidNotInBump` | does not compile (E0615, E0616 from inside the crate); `retain_bumps` re-points every entry |
| 6. A hand write of `input_txids` (the cached ring) | the sort answers `not_valid` for an entry made to wait on itself, `verify_structure` `InputNamesNoElement`, while `to_binary` writes the entry's own bytes | does not compile (E0616) |
| 7. A clone inside the hand-edit window | the clone carries the stale index: `find_txid(C)` `None` on a clone holding C, and its `merge_raw_tx(C)` stores C twice | a clone's index is its rows' (`Rows::copy`; the property's check 4) |
| 8. The atomic door's position map against the index, inside the window | `find_txid(parent)` `None` while `to_binary_atomic(child)`'s closure holds the parent | one index; the map is gone (`a_parent_put_in_place_of_an_entry_is_found_and_kept_in_its_childs_closure_843b`) |

**The named case**, `merge_txid_only(text)` for a text that is not 64 hex digits, on the base (every row: the entry holds the text as given and `find_txid(text)` finds it):

| Text | V2 `to_writer`, `BeefTx::to_writer`, `to_binary`, and `merge_beef` of it as a source | V1 |
|---|---|---|
| `abcd` | `Invalid txid-only entry txid: expected 64 hex digits, got 4` | `a valid serialized Transaction is expected` |
| 62 digits | `... got 62` | the same |
| 63 digits | `... got 63` | the same |
| 66 digits | `... got 66` | the same |
| `zz` x 32 | `Invalid hex string` | the same |
| the empty text | `... got 0` | `Beef::to_writer`, `to_binary`, `merge_beef`: `... got 0` (the empty txid is refused ahead of everything); `BeefTx::to_writer`: `a valid serialized Transaction is expected` |
| space-padded 62 digits | `Invalid hex string` | `a valid serialized Transaction is expected` |
| control: 64 lower-case digits | `Ok` (39 bytes; the entry 33) and merged | `a valid serialized Transaction is expected` |

On the tip none of the seven texts is a `Txid` (`Txid::from_hex` refuses each: `txid must be a 32-byte hexadecimal transaction ID.`), so no entry holds one and the writer's three arms for it are gone.

**Upper case**, on the base: `merge_txid_only(UPPER)` then `merge_raw_tx(that transaction)` holds 2 entries (the txid-only one under the upper-case text, the raw one under the lower-case), and `to_binary` writes both (101 bytes: the transaction and a txid-only entry of the same 32 bytes), which `Beef::from_binary` reads back as 2 entries; the lower-case control holds 1 entry and writes 68 bytes. On a BEEF holding the transaction, by the upper-case text: `find_txid` `None`, `find_bump` `None`, `find_transaction_for_signing` `None`, `find_atomic_transaction` `None`, `make_txid_only` `None`, `edit_tx` and `to_binary_atomic` `<UPPER> does not exist in this Beef`, `Transaction::from_beef(bytes, Some(UPPER))` `Transaction <UPPER> not found in BEEF`, and `merge_txid_only(UPPER)` adds a third entry. On the tip the upper-case text and its lower-case twin are one `Txid`: one entry, and every door finds it.

**A hand-set `atomic_txid`**, on the base: `abcd`, the empty text and `zz` answer `verify_structure` `SubjectMissing`; the subject's txid in upper case answers `Ok`. On the tip the field is `Option<Txid>`: none of the three texts can be held.

**The leaf's text** (stated, not closed): a BUMP built by hand whose level-0 hash is in upper case. On the base `find_bump(UPPER)` finds it and `find_bump(lower)` does not; a raw entry of that transaction is given no index by it (its txid is lower case), and `merge_txid_only(UPPER)` is given index 0. On the tip a `Txid`'s text is lower case, so no `Txid` finds that BUMP: `MerklePath` compares a leaf's text exactly (`merkle_path.rs`' `contains`) and is unchanged by this cut (Part O).

## The typed doors, and what stays text

Taken by value (a `Txid` is `Copy`): `find_txid`, `edit_tx`, `find_bump`, `find_transaction_for_signing`, `find_atomic_transaction`, `merge_txid_only`, `make_txid_only`, `to_binary_atomic`, `set_bump_index`, `BeefTx::from_txid`, `Transaction::from_beef(bytes, Option<Txid>)`. Given: `BeefTx::txid() -> Txid` with `id() -> String` beside it, `BeefTx::input_txids() -> &[Txid]`, `Beef::atomic_txid: Option<Txid>` (public, as `version` is: nothing is derived from either), `SortResult`'s five `Vec<Txid>`. Nothing was added to `txid.rs`.

Left as text: the merkle roots; `Beef::from_hex`, `to_hex`, `to_log_string`; `MerklePath`'s doors and a leaf's hash (the BEEF compares a `Txid`'s lower-case text with the leaf's text as held, through `find_bump`, `contains_and_mark` and the linker's index); the stream's `Hash32`; and `Utxo::txid`, which is no BEEF door (`add_inputs_from_utxos` parses it and keeps its words): it stays text until a pull request of its own, which replaces #974's sentence that it would be typed "in the BEEF's cut".

## The bytes' order at each conversion

Every place 32 bytes become a `Txid` or the reverse, the order it names, and what turned red on the scratch copy of the tip with the other order planted (the reverse plants 13 to 27 below).

| Site | Order | With the other order |
|---|---|---|
| `beef/collect.rs`, a raw entry's txid (the decoder's hash of the bytes read) | wire | `--lib transaction::beef` 23 failed; `tests/beef_rows_843b.rs` 3 |
| `beef/collect.rs`, a txid-only entry's 32 bytes | wire | `the_pre_pass_is_the_round_trip_on_every_vector_beef_621`; the property |
| `beef/collect.rs`, the atomic subject (`decoder.subject()`) | wire | `no_merge_txid_only_holds_a_text_that_is_no_txid_843b` and one more of `tests/beef_rows_843b.rs` |
| `beef_tx.rs`, `BeefTx::from_reader`, a txid-only entry | wire | `a_txid_only_entry_is_framed_in_wire_order_by_its_own_reader_and_writer_843b` (added for it: no machine saw the swap before) |
| `beef_tx.rs`, `BeefTx::txid()` of raw bytes (`sha256d`) | wire | `the_entry_txid_is_held_or_hashed_beef_tx_ts_105_116`, 4 more unit tests, 2 of `tests/beef_rows_843b.rs` |
| `beef_tx_writer.rs`, a txid-only entry's 32 bytes (`as_wire_bytes`) | wire | `the_pre_pass_is_the_round_trip_on_every_vector_beef_621`; 3 of `tests/beef_rows_843b.rs` |
| `beef_atomic.rs`, the Atomic prefix | wire | 2 unit tests; 2 of `tests/beef_rows_843b.rs` |
| `beef/merge_entry.rs`, a source entry holding no txid (`sha256d` of its bytes) | wire | `an_entry_holding_no_txid_is_merged_under_its_bytes_hash_in_wire_order_843b` (added for it; the branch is reached through the test door alone, every merge door storing the txid) |
| `beef/in_memory.rs`, the atomic table's key | wire | `tests/beef_atomic_graph.rs` 8 failed |
| `beef/in_memory.rs`, the atomic table's edges | wire | `tests/beef_atomic_graph.rs` 4 failed |
| `beef/in_memory.rs`, the content check's outpoint (`check_transaction`'s `prev`) | wire | none can: the check reads those bytes for the null outpoint (32 zero bytes) and a repeated outpoint alone, the same answers under either order (reverse plant 23, every machine green) |
| `beef.rs`, the atomic rule's subject (`atomic_unreached`) | wire | `tests/beef_atomic_graph.rs` 8 failed |
| `overlay/facilitators.rs`, a binary lookup answer's outpoint txid | display (the answer's 32 bytes are the txid as its text reads) | `tests/identity_evidence_hint_735.rs` 4 failed |
| `kvstore/local_lookup.rs`, a wallet outpoint's `TxId` | display (`Txid::from_display_bytes`) | `tests/kvstore_local_454.rs` 6 failed; `tests/kvstore_two_token_454.rs` 2 |
| `identity/contacts_actions.rs`, a wallet outpoint's `TxId` | display (`Txid::from_display_bytes`) | `tests/contacts_listed_spend.rs` 6 failed |

From text, no bytes: `overlay/wallet_retry.rs` (a wallet's evidence text names an entry only as its own 64 lower-case digits, as the text key it was compared with did; any other text the same `malformed` refusal as before) and `wallet/substrates/http_json/review_actions.rs` (`t.parse()`; a text that does not parse names no entry, as before).

Under `src/wallet/`: one site, one line (`substrates/http_json/review_actions.rs`, the competing BEEF's lookup). Under `src/auth/certificates/`: none.

## The machines

**(a) The compiler.** 45 plants, each alone, on a scratch copy of the tip (`git archive` of the tip's commit, target `-tip`; `tools/plants.py compile` in the out folder), each refused with its expected error and no other machine needed: 15 E0616, 14 E0308, 5 E0599, 3 E0451, 2 E0624, 2 E0615, 2 E0596, 1 E0277 and one error that carries no number (`cannot construct `Beef` with struct literal syntax due to private fields`).

| # | Plant | Refused with |
|---|---|---|
| 1 | a write of txs from beef.rs | E0616 |
| 2 | a write of bumps from beef.rs | E0616 |
| 3 | a write of txs from beef/index.rs | E0616 |
| 4 | a write of bumps from beef/index.rs | E0616 |
| 5 | a write of txs from beef_writable.rs | E0616 |
| 6 | a write of bumps from beef_writable.rs | E0616 |
| 7 | a write of txs from beef_atomic.rs | E0616 |
| 8 | a write of bumps from beef_atomic.rs | E0616 |
| 9 | a write of txs from rows.rs outside sealed | E0616 |
| 10 | a write of the index from rows.rs outside sealed | E0616 |
| 11 | a write of a mark from beef.rs | E0616 |
| 12 | a new child module writing txs | E0616 |
| 13 | a struct literal of Rows in beef.rs | E0451,type `rows::sealed::Index` is private |
| 14 | a struct update of Rows in beef.rs | E0451 |
| 15 | mem::swap on a lent entry in beef.rs | E0596 |
| 16 | a closure in a const writing txs | E0616 |
| 17 | a call of Rows::write from beef.rs | E0624 |
| 18 | a call of Rows::append from beef/index.rs | E0624 |
| 19 | outside: a write of the field txs | E0615 |
| 20 | outside: a write of the field bumps | E0615 |
| 21 | outside: a push through txs() | E0599 |
| 22 | outside: mem::swap on a lent entry | E0596 |
| 23 | outside: a mutable borrow of a found entry | E0308 |
| 24 | outside: find_txid_mut | E0599 |
| 25 | outside: reindex | E0599 |
| 26 | outside: tx_mut | E0599 |
| 27 | outside: a write of input_txids | E0616 |
| 28 | outside: a write of is_valid | E0616 |
| 29 | outside: the test door without the feature | E0599 |
| 30 | outside: a struct literal of Beef naming the rows | E0451,type `beef::rows::sealed::Rows` is private |
| 31 | outside: a struct literal of Beef without the rows | cannot construct `Beef` with struct literal syntax due to private fields |
| 32 | a text to find_txid | E0308 |
| 33 | a text to edit_tx | E0308 |
| 34 | a text to find_bump | E0308 |
| 35 | a text to find_transaction_for_signing | E0308 |
| 36 | a text to find_atomic_transaction | E0308 |
| 37 | a text to merge_txid_only | E0308 |
| 38 | a text to make_txid_only | E0308 |
| 39 | a text to to_binary_atomic | E0308 |
| 40 | a text to set_bump_index | E0308 |
| 41 | a text to BeefTx::from_txid | E0308 |
| 42 | a text to Transaction::from_beef | E0308 |
| 43 | a text into atomic_txid | E0308 |
| 44 | 32 bytes of no named order to find_txid | E0308 |
| 45 | a Txid from 32 bytes without a named order | E0277 |

The twelve `compile_fail` doc tests of `src/transaction/beef/rows.rs` name their numbers (E0615 for `beef.txs.clear()` and `beef.bumps.remove(0)`, E0596, E0599 for `find_txid_mut`, `reindex` and `tx_mut`, E0616 for a write of `input_txids` and of `is_valid`, E0308 for a text at `merge_txid_only`, `find_txid` and `atomic_txid`, E0451 for a struct literal), read by `cargo +nightly-2026-10-19 test --doc --all-features`.

**The reverse plants.** 27 changes of the tip, each alone, each compiling; with none planted every machine named is green on the scratch copy (`tools/plants.py control`: 11 commands). 26 turn a named machine red; one changes no answer (23, above).

| # | Plant | | Machines red |
|---|---|---|---|
| 1 | the general door without its emptying | RED | tests/arch_field_writes_843: 2 failed (the_beefs_sealed_pin_refuses_each_change_843b, ...); lib transaction::beef: 7 failed (a_replacement_in_place_is_found_at_once_843b, ...); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 2 | the general door without the sort mark | RED | tests/arch_field_writes_843: 2 failed (the_beefs_sealed_pin_refuses_each_change_843b, ...); lib transaction::beef: 1 failed (each_door_sets_the_marks_it_owes_843b); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 3 | an append that skips the index | RED | tests/arch_field_writes_843: 2 failed (the_beefs_sealed_module_is_as_pinned_843b, ...); lib transaction::beef: 28 failed (retain_bumps_re_points_every_entry_843b, ...); tests/beef_rows_843b: 2 failed (no_merge_txid_only_holds_a_text_that_is_no_txid_843b, ...) |
| 4 | a replace that re-keys nothing | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b); lib transaction::beef: 4 failed (append_and_replace_keep_the_index_the_rows_843b, ...); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 5 | a replace that keeps a filled index over a twin | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b); lib transaction::beef: 3 failed (append_and_replace_keep_the_index_the_rows_843b, ...); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 6 | retain_bumps without re-pointing | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b); lib transaction::beef: 1 failed (retain_bumps_re_points_every_entry_843b); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 7 | swap_parse without its check | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b); lib transaction::beef: 1 failed (each_door_sets_the_marks_it_owes_843b) |
| 8 | a copy that keeps a stale index | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b); lib transaction::beef: 7 failed (the_index_is_the_rows_after_the_general_door_843b, ...); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 9 | a new function in sealed that lends an entry | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b) |
| 10 | a new function in sealed that lends the BUMPs | RED | tests/arch_field_writes_843: 1 failed (the_beefs_sealed_module_is_as_pinned_843b) |
| 11 | a public door added without the property | RED | tests/beef_rows_843b: 1 failed (every_public_mut_door_of_beef_is_exercised_843b) |
| 12 | a trim that keeps no parse | RED | tests/beef_rows_843b: 1 failed (a_trim_keeps_the_parse_of_a_proven_entry_held_raw_843b) |
| 13 | order: the collector, a raw entry txid | RED | lib transaction::beef: 23 failed (edit_tx_keeps_a_twin_found_and_a_no_op_moves_no_mark_843b, ...); tests/beef_rows_843b: 3 failed (no_merge_txid_only_holds_a_text_that_is_no_txid_843b, ...) |
| 14 | order: the collector, a txid-only entry | RED | lib transaction::beef: 1 failed (the_pre_pass_is_the_round_trip_on_every_vector_beef_621); tests/beef_rows_843b: 1 failed (the_index_and_every_bump_position_are_the_rows_after_every_door_843b) |
| 15 | order: the collector, the atomic subject | RED | tests/beef_rows_843b: 2 failed (no_merge_txid_only_holds_a_text_that_is_no_txid_843b, ...) |
| 16 | order: BeefTx::from_reader, a txid-only entry | RED | tests/beef_rows_843b: 1 failed (a_txid_only_entry_is_framed_in_wire_order_by_its_own_reader_and_writer_843b) |
| 17 | order: BeefTx::txid of raw bytes | RED | lib transaction::beef_tx: 1 failed (the_entry_txid_is_held_or_hashed_beef_tx_ts_105_116); lib transaction::beef: 4 failed (the_amount_refusal_stands_ahead_of_a_subject_not_held_on_both_doors_817, ...); tests/beef_rows_843b: 2 failed (a_trim_keeps_the_parse_of_a_proven_entry_held_raw_843b, ...) |
| 18 | order: the writer, a txid-only entry | RED | lib transaction::beef: 1 failed (the_pre_pass_is_the_round_trip_on_every_vector_beef_621); tests/beef_rows_843b: 3 failed (a_txid_only_entry_is_framed_in_wire_order_by_its_own_reader_and_writer_843b, ...) |
| 19 | order: the atomic prefix | RED | lib transaction::beef: 2 failed (a_parent_put_in_place_of_an_entry_is_found_and_kept_in_its_childs_closure_843b, ...); tests/beef_rows_843b: 2 failed (no_merge_txid_only_holds_a_text_that_is_no_txid_843b, ...) |
| 20 | order: merge_beef, an entry without a held txid | RED | lib transaction::beef: 1 failed (an_entry_holding_no_txid_is_merged_under_its_bytes_hash_in_wire_order_843b) |
| 21 | order: the atomic table key | RED | tests/beef_atomic_graph: 8 failed (every_accepted_vector_round_trips_through_the_atomic_writer, ...) |
| 22 | order: the atomic table edges | RED | tests/beef_atomic_graph: 4 failed (every_accepted_vector_round_trips_through_the_atomic_writer, ...) |
| 23 | order: the content check outpoint | GREEN?! | every machine green |
| 24 | order: the atomic rule subject | RED | tests/beef_atomic_graph: 8 failed (an_unreached_child_earlier_by_the_trie_order_is_the_entry_named, ...) |
| 25 | order: the binary lookup answer outpoint | RED | tests/identity_evidence_hint_735: 4 failed (a_binary_answers_outputs_each_carry_their_own_txids_atomic_beef_735, ...) |
| 26 | order: the kvstore wallet outpoint | RED | tests/kvstore_local_454: 6 failed (local_authentication_uses_beef_when_listing_omits_the_script_454, ...); tests/kvstore_two_token_454: 2 failed (local_remove_two_token_bytes_and_signature_requests_454, ...) |
| 27 | order: the contacts wallet outpoint | RED | tests/contacts_listed_spend: 6 failed (an_update_of_a_token_at_output_1_over_a_one_output_parent_signs_it_contacts, ...) |

Two of them were green on the run made before their tests existed, and each got its test: `BeefTx::from_reader`'s txid-only entry (16) and `merge_beef`'s entry without a held txid (20). One more passed the property and led to its sixth check (2, the general door without the sort mark: the marks are now read through `to_binary` and `merge_beef` after the four new doors). The pin (`tests/arch_field_writes_843.rs`) is red on each of the ten changes inside `sealed` (1 to 10); the property on 9 of the twelve changes of the rows' module and the trim, and on 7 of the 15 byte-order swaps.

**(b) The pin.** `tests/arch_field_writes_843.rs`: `sealed`'s 24 items by signature (`ROWS_ITEMS`), its tokens' digest (`ROWS_DIGEST`), `write` opening with `self.index.take(); self.needs_sort = true; self.wire_order = false;`, no `pub` wider than `pub(super)` but `Rows`' name, no attribute or macro inside; `mod beef;`, `mod rows;` and the two `mod sealed {` each once and inline; the index filled by `index` (`get_or_init`) and `copy` (`set`) alone. The test door `Beef::with_rows_for_test` sits outside `sealed` (the module admits no attribute), in `rows.rs`, and builds through `Rows::of`; `tests/arch_test_doors_869.rs` lists it.

**(c)** `tests/arch_owned_fields_843.rs`: the four `Beef.*` rows left `ALLOWED`; `BeefTx` named by hand (no `pub` field).

**(d) The property.** `tests/beef_rows_843b.rs`, seed `0x0843_b000_5eed_0001`, 700 sequences of 28 steps, the census of the run (`--nocapture`): 19,600 steps; each of the 20 doors between 839 and 942 times (floor 500), the two public fields 843 and 959; 76,483 rows checked, each looked up by its `Txid` and by its upper-case text's; 142,840 absent lookups; 6,095 states holding a txid twice; 10,703 rows naming no BUMP by an index past them; 18,232 txid-only rows; 16,531 round trips as held and 16,531 sorted; 2,823 readings of the marks; 350 sequences on a BEEF read from bytes and 350 on one built by merges. The doors are held against the source (`every_public_mut_door_of_beef_is_exercised_843b`): `edit_bump`, `edit_tx`, `is_valid`, `make_txid_only`, `merge_beef`, `merge_bump`, `merge_raw_tx`, `merge_transaction`, `merge_txid_only`, `retain_bumps`, `retain_txs`, `set_bump_index`, `sort_txs`, `to_binary`, `to_binary_atomic`, `to_hex`, `to_log_string`, `trim_known_proven`, `verify_structure`, `verify_valid`.

**(e) The fuzz target.** `fuzz_beef_parser` runs `support/rows_law.rs` on every BEEF it parses (up to eight edits through eleven doors chosen by the input's bytes, the law after each). 61 s from its seeds on `nightly-2026-10-19`: 40,252 runs, no failure. With the general door planted not to empty the index, on the scratch copy, the target fails on its seeds at once (a stale position past the entries, `beef/index.rs:42`). The 62-digit hand state it built until now is gone with the door that held it: in its place a txid-only entry of a txid from the input's bytes, under the BEEF's version word and under the other of V1 and V2, which reaches the one writer refusal left for such an entry (a txid-only entry outside V2). Its other hand states go through `edit_bump`, `edit_tx` and the rows' test door.

**(f) The differential.** One harness (`harness/` in the out folder: a text-keyed surface over each tree's API, so the same sequences run on both), built in release against the base's scratch copy and against the tip: seeded sequences of merges (`merge_bump`, `merge_txid_only`, `merge_raw_tx` with and without an index, `merge_transaction`, `merge_beef` of built and read sources), `make_txid_only`, `edit_tx`, the trim, the sort, `verify_structure`, `verify_valid`, the writers, the atomic door, the log, the two public fields, a read back and a clone, over a pool of nine transactions and well-formed lower-case txids; after every step every entry, every BUMP, every lookup of every pool txid (`find_txid`, `find_bump`, `find_transaction_for_signing`, `find_atomic_transaction` with its `to_beef` and `to_atomic_beef`), the bytes written and `from_beef` of them go into a running SHA-256.

| Seed | Sequences × steps | Records | Bytes of answers | Digest, base and tip |
|---|---|---|---|---|
| `843b0001` | 4,000 × 40 | 4,444,874 | 1,039,810,352 | `71d6805b735cf0daffa42ce7ac6a7ca6589411ffd7757616ca867adb4a12de15`, equal |
| `843b0002` | 4,000 × 40 | 4,407,742 | 1,021,736,911 | `9f7b70d51682ac6dffc90d414fdb8469361c1a2f8e165311d9ad4eaafaf7221d`, equal |
| `843b0003` | 4,000 × 40 | 4,456,742 | 1,046,752,582 | `7b8260492c12e915f904219b4d2b7fccd9fd6c0e620963af511b0f9d2e4b22b8`, equal |

It differs when the trees differ, seen on a real difference: on the tip as built before the fix below, seed `843b0001` gave 4,414,772 records and the digest `0cdaa53d54d5e20e24c52ac9dad056e91a3d7b2a0c9928eb986f54bd36b1436b` (the other two seeds differed too), and the harness built against the scratch copy of the final tip with reverse plant 12 applied (the trim keeping no parse) gives that digest again. The difference: the base's `trim_known_proven` parses an entry held raw with no input list (a proven one) and keeps the parse (`BeefTx::parsed`), so after a trim `find_transaction_for_signing` and `find_atomic_transaction` answer its transaction; the tip read the inputs through `&self` and kept nothing, so both answered `None`. Fixed (the trim stores the parse through `Rows::swap_parse`, no mark moved) and pinned: `a_trim_keeps_the_parse_of_a_proven_entry_held_raw_843b`, RED on the scratch copy with the fix removed (reverse plant 12).

## Tests restated on the law, or removed

No shared vector is edited. A test that pinned a hand-edit window, a `tx_mut` cell or a text that is no txid, and what replaced it:

| File | Was | Now |
|---|---|---|
| `src/transaction/beef/index_817_tests.rs` | the six tests of the hand-edit window (`indexed_len`, the incremental index, the mismatched hit, `reindex`) | `the_index_is_the_rows_after_the_general_door_843b`, `a_replacement_in_place_is_found_at_once_843b`, `append_and_replace_keep_the_index_the_rows_843b`, `each_door_sets_the_marks_it_owes_843b`, `retain_bumps_re_points_every_entry_843b`, `edit_tx_keeps_a_twin_found_and_a_no_op_moves_no_mark_843b` |
| `src/transaction/beef/merge_entry_621_tests.rs` | `an_entry_edited_inside_tx_mut_is_filed_under_its_fields_hash_843`, `to_writer_writes_a_tx_mut_entry_from_its_fields_843` | `an_entry_edited_after_its_id_was_read_is_filed_under_its_fields_hash_843b`, `to_writer_writes_an_edited_entry_from_its_fields_843b` (on `edit_tx`); new, `an_entry_holding_no_txid_is_merged_under_its_bytes_hash_in_wire_order_843b` |
| `src/transaction/beef/prepass_621_tests.rs` | 17 states a BEEF, one holding a 62-digit txid-only entry; the `tx_mut` state; 27 recorded states | 16 states a BEEF over 372 BEEFs (5,952: 2,566 `Ok`, 3,386 refused, 1,789 by the reader, 252 the judge's `RootNotCarried`; the refused 372 fewer, one a BEEF, nothing else moved); the edit through `edit_tx`; 17 recorded states built (4 `Ok`, 13 refused, 2 by the reader), the ten that hold a text that is no txid counted by name |
| `src/transaction/beef/reference_603_tests.rs` | `a_ring_in_the_input_cache_is_refused_wire_beef_002_beef_004` (a hand write of `input_txids`) | `a_ring_of_two_entries_is_refused_wire_beef_002_beef_004_843b` (two entries filed under sentinel txids through the crate's `with_txid`) |
| `src/transaction/beef/atomic_batch_817_tests.rs` | `a_parent_the_index_was_never_given_stays_in_its_childs_closure_817` (the window) | `a_parent_put_in_place_of_an_entry_is_found_and_kept_in_its_childs_closure_843b`; the oracle keeps its own position map; the subjects `zz` and the empty text are no longer asked |
| `src/transaction/beef_tx.rs` (units) | the `has_txid` test; `raw_tx_or_compute` keeping what it computed; a `tx_mut` test | `the_entry_txid_is_held_or_hashed_beef_tx_ts_105_116`; `raw_tx_or_compute` keeps nothing; the `tx_mut` test removed |
| `tests/beef_edit_door_817.rs` | `a_hand_retain_then_find_txid_and_merge_raw_tx_holds_each_txid_once_817` | `a_retain_then_find_txid_and_merge_raw_tx_holds_each_txid_once_843b` (`retain_txs`) |
| | `a_hand_push_then_a_lookup_finds_the_pushed_entry_817` | `an_appended_entry_is_found_at_once_and_merged_into_its_place_843b` |
| | `a_hand_swap_then_a_lookup_of_each_finds_it_817`, `reindex_after_a_hand_reorder_finds_every_entry_817` | `a_beef_read_in_another_order_finds_each_entry_and_merges_into_its_place_843b` (a frame read in the other order) |
| | `a_hand_replace_keeping_the_count_misses_until_reindex_stated_817` | `a_replacement_in_place_is_found_at_once_and_held_once_843b` (the window closed; a clone checked too) |
| | `reindex_rekeys_an_entry_edited_through_the_deprecated_tx_mut_817` | removed (it does not compile); the law is `edit_tx_on_a_raw_entry_rekeys_it_at_once_and_keeps_it_raw_817` |
| | `a_hand_push_a_door_then_a_retain_back_to_the_count_finds_the_pushed_entry_817` | `an_append_a_lookup_then_a_retain_back_to_the_count_finds_the_appended_entry_843b` |
| | `a_hand_push_of_a_held_txid_is_answered_by_the_later_entry_after_a_door_stated_817` | `a_txid_held_twice_is_answered_by_the_later_entry_before_and_after_a_door_843b` (a twin read from bytes; the later entry in every state) |
| | `a_no_op_edit_keeps_the_entrys_is_valid_817` | `a_no_op_edit_keeps_the_sorts_word_on_the_entry_843b` |
| | `the_two_edit_tx_cells_inside_the_window_stated_817` | `the_two_edit_tx_cells_of_the_closed_window_843b` |
| | `a_hand_removal_then_two_pushes_finds_each_pushed_entry_817` | `a_retain_then_two_appends_finds_each_appended_entry_843b` |
| | `two_hand_pushed_twins_are_answered_by_the_later_817`, `an_edit_of_a_hand_pushed_twin_keeps_the_other_entry_found_817`, `an_edit_of_a_twin_after_reindex_keeps_the_other_entry_found_817` | `two_twins_read_from_bytes_are_answered_by_the_later_843b`, `an_edit_of_a_twin_read_from_bytes_keeps_the_other_entry_found_843b`, `an_edit_of_a_twin_on_a_copy_keeps_the_other_entry_found_843b` |
| `tests/beef_door_sync_817.rs` | `an_edit_through_txs_by_tx_mut_is_the_171_window_stated_817` | `an_edit_of_a_held_transaction_is_found_by_its_new_txid_and_held_once_843b` (the reference's recording, no longer stated) |
| | `an_edit_then_find_txid_mut_answers_the_edited_txid_817` | `an_edit_then_the_lookup_answers_the_edited_txid_as_find_txid_mut_did_843b` |
| | `a_hand_drop_…_stated_817`, `a_hand_push_…_stated_817`, `a_hand_swap_…_stated_817`, `a_hand_replace_keeping_the_count_is_the_window_stated_817` | `a_retain_then_the_lookups_and_merge_raw_tx_stated_843b`, `an_append_then_find_txid_and_merge_raw_tx_stated_843b`, `a_swapped_order_then_find_each_and_merge_raw_tx_stated_843b`, `a_replacement_keeping_the_count_is_found_at_once_stated_843b` |
| | `the_stated_cells_counted_are_fifteen_of_forty_three_817` | `the_stated_cells_counted_are_fourteen_of_forty_three_843b`; all 43 cells replayed |
| `tests/beef_writer_refusals_817.rs` | `each_writer_cell_is_the_reference_s_or_a_stated_refusal_817` | `each_writer_cell_is_the_reference_s_a_stated_refusal_or_counted_unbuildable_843b` |
| | `the_txid_door_takes_any_text_and_the_writer_judges_it_817` | `the_txid_door_takes_a_txid_and_a_text_that_is_none_is_refused_where_it_enters_843b` |
| | four `_817` tests of the snapshot, the order of the checks and the order after a refusal | the same names `_843b`, their hand states through the doors |
| | `an_entry_edited_through_tx_mut_is_written_from_its_fields_by_to_writer_621` | `an_entry_edited_through_edit_tx_is_written_from_its_fields_by_to_writer_843b`; new, `an_upper_case_txid_and_its_lower_case_twin_are_one_entry_843b` |
| `tests/beef_tx_mut.rs` | `a_tx_mut_edit_is_unseen_by_the_per_entry_doors_stated_171` | `an_edit_is_seen_by_the_per_entry_doors_at_once_843b` |
| `tests/beef_cycle.rs` | `a_ring_written_in_the_input_cache_stops_the_sort_and_the_judge` | removed (it does not compile); `an_entrys_input_list_is_its_transactions_after_every_door_843b`; `a_ring_closed_through_tx_mut_…` renamed `a_ring_closed_through_an_edit_renames_the_entry_and_is_a_chain` |
| `tests/beef_merge_beef_txid_621.rs` | `a_source_entry_built_from_raw_bytes_without_a_txid_merges_under_its_hash_621`, `a_source_entry_mutated_through_tx_mut_merges_under_its_new_txid_621` | `a_source_entry_merged_from_raw_bytes_merges_under_its_hash_843b`, `a_source_entry_edited_through_edit_tx_merges_under_its_new_txid_843b` |
| `tests/transaction_numbers_844.rs` | `a_hand_pushed_entry_with_such_an_output_…_844` | `an_entry_held_as_a_transaction_with_such_an_output_is_refused_by_every_writer_and_merged_as_the_round_trip_843b` (through `merge_transaction`) |
| `tests/beef_bump_index_757.rs` | `a_raw_entry_mutated_through_tx_mut_is_copied_through_the_raw_branch_798` | `a_raw_entry_edited_in_place_is_copied_through_the_raw_branch_798` (the same recorded cell, the edit `edit_tx`'s) |

**Recorded cells this crate can no longer build**, each counted by name in its test (`tests/vectors/beef_v1_txid_only_writer_817.json`, unchanged): the `writers` group's `txid_only_non_hex`, `txid_only_62_digits`, `txid_only_66_digits`, `txid_only_63_digits`, `txid_only_non_hex_short`, `txid_only_empty_after_merge_threw`, `txid_only_empty_with_non_hex_bump_hash`; the `merge_door` group's `source_txid_only_non_hex`, `source_txid_only_62_digits`, `source_version_word_and_txid_only_62_digits` (the ten are `UNBUILDABLE_843B`, `tests/support/beef_merge_states_817.rs`); `sort_on_refusal`'s `empty_txid` and `non_hex_txid` and `txid_door`'s `empty`, `non_hex`, `short_hex`, named with the recorded words. `tests/vectors/beef_door_sync_817.json`: all 43 cells replayed.

Also moved, no behaviour: `tests/support/fixtures/binary.rs`' source guard for `examples/beef_spv.rs` (the example's subject is a `Txid`; its seeded recipe is unchanged, `tests/fixtures_replay.rs` green on the same fixture bytes); `.cargo/mutants.toml`'s equivalent-mutant entry for `dependency_order` re-pointed from `beef.rs:1029:29` to `1003:29`.

## The break, measured

**The rustdoc JSON** of the base and the tip (`cargo +nightly-2026-10-19 rustdoc --lib --all-features -- -Z unstable-options --output-format json`), normalized (ids, spans and docs dropped, an id replaced by the path it names) and diffed (`tools/rustdoc_cmp.py`): 7,023 items on the base, 7,025 on the tip; 7 removed, 9 added, 21 changed.

- Removed: the fields `Beef.txs`, `Beef.bumps`, `BeefTx.input_txids`, `BeefTx.is_valid`; `Beef::find_txid_mut`, `Beef::reindex`, `BeefTx::tx_mut`.
- Added: `Beef::txs`, `Beef::bumps`, `Beef::retain_txs`, `Beef::retain_bumps`, `Beef::edit_bump`, `Beef::set_bump_index`; `BeefTx::id`, `BeefTx::input_txids`, `BeefTx::is_valid`.
- Changed: the struct `Beef`, `Beef.atomic_txid`, `Beef::find_txid`, `edit_tx`, `find_bump`, `find_transaction_for_signing`, `find_atomic_transaction`, `merge_txid_only`, `make_txid_only`, `to_binary_atomic`; `SortResult.missing_inputs`, `not_valid`, `valid`, `with_missing_inputs`, `txid_only`; the struct `BeefTx`, `BeefTx::from_txid`, `BeefTx::txid`, `BeefTx::raw_tx_or_compute` (`&mut self` to `&self`); `Transaction::from_beef`; `Beef`'s `Debug::fmt` (written by hand where it was derived: the same signature, its types spelled otherwise in the JSON).

`BeefTx::set_bump_index` stays public, on an entry a caller owns; no door hands a BEEF an entry.

**cargo-semver-checks 0.51.0** (`cargo semver-checks check-release --baseline-rev 471bdaf640334151b172e6b84708e55b44e1aeca --all-features --release-type minor`, Rust 1.95.0): exit 100; 202 checks, 199 pass, 3 fail, 58 skipped. `inherent_method_missing`: `BeefTx::tx_mut`, `Beef::reindex`, `Beef::find_txid_mut`. `struct_pub_field_missing`: `BeefTx.input_txids`, `BeefTx.is_valid`, `Beef.bumps`, `Beef.txs`. `struct_pub_field_now_doc_hidden`: `BeefTx.input_txids`, `BeefTx.is_valid` (its reading of a field made private; nothing is `#[doc(hidden)]`). It has no lint for a parameter's or a field's changed type: the eleven typed doors, `BeefTx::txid`'s return and the typed fields are in the JSON's diff alone.

**The dependents.** By a compile where the pin is this line's version: the wallet toolbox, its `beta` at `184c4182`, its library (`cargo check --lib`, a `[patch.crates-io]` to each tree on a scratch copy by `git archive`): 56 errors against the base (this line's earlier breaks), 145 against the tip; tip less base, by the compiler's code and what it names:

| | |
|---|---|
| E0615, `txs` used as a field | +42 |
| E0615, `bumps` used as a field | +13 |
| E0308, a text where a `Txid` is taken or the reverse | +35 |
| E0599, `find_txid_mut` | +2 |
| E0599, `join` on a `Vec<Txid>` | +1 |
| E0277, a comparison or a collect with a text | +1 |
| errors of the base no longer reported (behind an earlier error of the same expression) | -5 |

94 new, 89 net; one compile's count (an error can hide the next). The other three pin another version line (the CLI `=0.9.0-beta.6`, the overlay engine `=0.7.2`, the relay `=0.6.0`), where a patch to this tree's version is unused and the CLI's own code is checked only after its toolbox compiles: they are read by a grep of their `.rs` files at the named ref, lines matching, tests included (a grep reads no types: `.txs` may be another struct's):

| Lines matching | toolbox `184c4182` | CLI `6dc14ef5` | overlay `2abcd748` | relay `44a63204` |
|---|---|---|---|---|
| `.txs` as a field | 72 | 6 | 72 | 0 |
| `.bumps` as a field | 51 | 2 | 48 | 0 |
| `.find_txid(` | 85 | 13 | 43 | 0 |
| `to_binary_atomic(` | 28 | 14 | 33 | 1 |
| `atomic_txid` | 12 | 4 | 13 | 0 |
| `.find_bump(` | 11 | 0 | 7 | 0 |
| `merge_txid_only(` | 10 | 1 | 1 | 0 |
| `find_txid_mut(` | 3 | 0 | 11 | 0 |
| `.set_bump_index(` | 6 | 0 | 4 | 0 |
| `make_txid_only(` | 2 | 0 | 2 | 0 |
| `.txs.retain` | 1 | 1 | 0 | 0 |
| `Transaction::from_beef(` | 2 | 3 | 54 | 0 |
| `find_atomic_transaction(` | 1 | 2 | 4 | 0 |
| `.input_txids` as a field | 0 | 1 | 2 | 0 |
| `raw_tx_or_compute` | 0 | 0 | 9 | 0 |
| `sort_txs()` (its lists read after) | 13 | 3 | 6 | 0 |
| `tx_mut()`, `reindex()` | 0 | 0 | 0 | 0 |

**The cost.** Release, one harness built against each tree, seven alternating passes, medians (the host's load average 8 to 9 during the run): a proven root and a chain of unproven spends, each linked to its parent.

| Measure | base median (ms) | tip median (ms) | tip/base | base range | tip range |
|---|---|---|---|---|---|
| to_beef@2000 | 3.579 | 3.070 | 0.86 | 3.519 to 3.660 | 2.810 to 3.107 |
| from_beef@2000 | 7.860 | 5.995 | 0.76 | 7.748 to 8.051 | 5.858 to 6.254 |
| verify@2000 | 3.649 | 3.719 | 1.02 | 3.405 to 3.737 | 3.677 to 3.779 |
| merge_raw_tx loop@2000 | 2.740 | 2.343 | 0.86 | 2.672 to 2.768 | 2.223 to 2.377 |
| find_txid per entry, a key in hand@2000 | 0.083 | 0.056 | 0.67 | 0.075 to 0.091 | 0.048 to 0.060 |
| find_txid per entry, from text each call@2000 | 0.077 | 0.201 | 2.61 | 0.073 to 0.080 | 0.189 to 0.233 |
| edit_tx x 2000@2000 | 3.482 | 2.059 | 0.59 | 3.382 to 3.654 | 1.903 to 2.095 |
| to_binary@2000 | 0.590 | 0.367 | 0.62 | 0.557 to 0.697 | 0.312 to 0.373 |
| from_binary@2000 | 4.363 | 2.466 | 0.57 | 4.163 to 4.467 | 2.356 to 2.522 |
| merge_beef, merges of ten@20000 | 45.806 | 24.844 | 0.54 | 45.599 to 46.942 | 24.142 to 25.132 |
| to_beef@20000 | 35.033 | 30.128 | 0.86 | 33.491 to 35.538 | 29.390 to 31.668 |
| from_beef@20000 | 83.656 | 64.995 | 0.78 | 80.538 to 84.314 | 63.186 to 66.720 |
| verify@20000 | 34.644 | 35.429 | 1.02 | 34.221 to 35.442 | 34.357 to 37.291 |
| merge_raw_tx loop@20000 | 27.408 | 23.090 | 0.84 | 26.431 to 28.279 | 22.933 to 23.897 |
| find_txid per entry, a key in hand@20000 | 1.329 | 0.768 | 0.58 | 1.006 to 1.460 | 0.684 to 0.915 |
| find_txid per entry, from text each call@20000 | 1.072 | 2.385 | 2.22 | 0.833 to 1.216 | 2.005 to 2.593 |
| edit_tx x 2000@20000 | 3.400 | 2.126 | 0.63 | 3.170 to 3.530 | 1.964 to 2.147 |
| to_binary@20000 | 9.022 | 6.953 | 0.77 | 8.178 to 9.637 | 6.657 to 7.411 |
| from_binary@20000 | 41.834 | 24.545 | 0.59 | 40.825 to 44.206 | 23.940 to 24.765 |
| merge_beef, merges of ten@200000 | 5712.687 | 255.831 | 0.04 | 5431.759 to 5927.644 | 250.822 to 262.338 |

`find_txid` from a text costs more at the tip: the text is parsed at each call (about 100 ns), where the base hashed the text as a key; with the `Txid` in hand the lookup is faster than the base's. The merges into one growing BEEF are the whole-target scan `merge_beef` ran for `tx_mut` (#621's stated cost), gone with the door: 5,713 ms to 256 ms at 200,000 entries.

## The gate

On the lane's host, each command in the foreground and alone, `CARGO_BUILD_JOBS=2` (swap use above half throughout):

- `cargo fmt --all -- --check`, `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`, `cargo fmt --manifest-path fuzz/corpus-gen/Cargo.toml -- --check`: clean.
- `cargo +1.100.0 clippy --all-targets --all-features -- -D warnings`: clean (CI's stable). The host's default 1.95.0 clippy refuses one line this change does not touch, `src/util/debug_redact.rs:156` (`nonminimal_bool`), and refuses it on the base too.
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`: clean.
- `cargo test --doc --all-features`: 399 passed, 127 ignored, on 1.95.0 and on `nightly-2026-10-19`, where the error number of each of the twelve `compile_fail` blocks of `rows.rs` is read.
- `tests/beef_rows_843b.rs` three times, once under `--test-threads=1`: 7 passed each.
- `cargo test --features "full,http" --lib <module>`, each its own run: `transaction` 265, `identity` 126, `kvstore` 76, `overlay` 119, `wallet` 207, none failed.
- The whole suite, `--features "full,http,websocket"`: the library 1,878 passed, 4 ignored; the 411 integration binaries in 14 runs of 30: 4,176 passed, 0 failed, 35 ignored; the doc tests above.
- The named set (every `tests/beef_*.rs`, `tests/transaction_*.rs`, `tests/merkle*.rs`, every file naming `Beef`, `BeefTx` or `SortResult`, `fixtures_replay`, the two conformance files): on the base's scratch copy 98 binaries, 1,028 passed, 0 failed, 4 ignored; on the tip 100 binaries (`beef_rows_843b` and `arch_field_writes_843` join it), 1,045 passed, 0 failed, 4 ignored.
- `conformance_beef` and `conformance_scripts` with `BSV_CONFORMANCE_DIR` set (the host's ts-stack clone): the totals and every class equal on the base and the tip; the script corpus `total=5116 run=4121 passed=4110 unsupported=958 skipped=37 known_failures=11 failures=0 panics=0`.
- The removed writer text (`Invalid txid-only entry txid: expected 64 hex digits, got N`): asserted by no test, carried by no vector, matched by none of the four dependents (a grep of each).
- `cargo +nightly-2026-10-19 fuzz build`: every target; then 61 s each from the seeds into a scratch corpus: `fuzz_beef_parser` 53,981 runs, `fuzz_transaction_parser` 684,111, `fuzz_merkle_path` 446,011, no failure. `fuzz/corpus-gen` writes the BEEF and BUMP seeds byte for byte (no file under `fuzz/corpus/` moved, all 26 doors reached); it stops after them, in `wallet_corpora`, on a wallet-wire vector with no `wire` member, which this change does not touch.
- `cargo build --target wasm32-unknown-unknown --no-default-features --features "auth,wallet,transaction,overlay,socketio,wasm"`: builds.
- `cargo build --examples --all-features`; `cargo test --test readme_examples` (in the suite); `examples/beef_spv` runs to `verified true`.
- `tools/ratchet/run --check --against 471bdaf640334151b172e6b84708e55b44e1aeca`: all 7 counters, the oversized-file limits and the mutation floors pass (`beef.rs` 2,956 lines, at its bound; `overlay/facilitators.rs` 800, at its; `beef/rows.rs` 570).
- `python3 -B .github/scripts/mutants_entries.py`: 28 entries, each one listed mutant. `python3 -B .github/scripts/rows_from_sources.py --check`: 0 refusals.
- `gitleaks git --redact --no-banner --exit-code 1 --log-opts="471bdaf640334151b172e6b84708e55b44e1aeca..HEAD" .`: no leaks found.
- The differential, run again on the tip as committed: the three digests equal.

## Not verified

- The measures and the dependents' counts are one host's, under other lanes' load; the medians are of seven passes.
- The CLI, the overlay engine and the relay were not compiled against the tip (they pin another version line): their counts are greps. The toolbox was compiled as a library alone.
- cargo-mutants was not run over `beef/rows.rs` (the nightly's); the reverse plants are the lane's own 27.
- CI's other cells (Windows, macOS, the beta toolchain) were not run here.
- The differential's harness has no step for what only the removed doors reached. One such effect is known and stated in the CHANGELOG entry: on the base `raw_tx_or_compute(&mut self)`, called on an entry lent by `find_txid_mut` or `txs`, kept the bytes it computed on an entry held as a transaction alone, which moved that entry to the atomic writer's raw branch; the tip's `&self` reading keeps nothing.
- `Beef`'s `Debug` output moved (written by hand: the version, the subject, the entries, the BUMPs and the two marks, no index); no test or dependent was found to read it.

