# Lane fix-843-removals (#843): the removals of the 0.9.0 cut

Started from `4c5454be` (`origin/beta`'s tip on 2026-11-17). The word it rests on: the owner's ruling of 2026-11-17 (the cut fixes every break that should happen; a public item that stays through the freeze stays for the whole 0.9 line), the captain's rulings 4 and 5 of that day on #843, the three design reads of the unused public items (3 of 3 on every item here), and ruling 5 of 2026-11-15 (the mode helpers no wire call carries).

## What left, what is hidden, what stays

| Item | State | What to call instead |
|---|---|---|
| `Beef::from_binary_with_limits`, `transaction::BeefLimits` (deprecated since 0.4.0) | removed | `Beef::from_binary`; `beef_stream::verify_stream` for a stranger's BEEF |
| `overlay::create_overlay_admin_token` (deprecated since 0.3.7) | removed | `create_signed_overlay_admin_token` |
| `KVStoreInterpreter::verify_signature_legacy` (deprecated), `src/kvstore/legacy_signature.rs` | removed | `extract_fields` then `verify_signature` |
| `Error::HmacMinimalLengthKey` (never emitted since 0.9.0-beta.4, in no stable release) | removed | `Error::HmacLegacyKey` |
| `script::transaction`: `TransactionInputContext`, `TransactionOutputContext`, `TransactionContext`, `SpendValidation`, `UtxoProvider`, `SimpleUtxo` | removed | `Transaction`'s accessors, `Transaction::verify`, `transaction::verify_input` |
| `wallet::wire::status_codes`, `wallet::wire::counterparty_codes` | `pub(crate)`, read by the codec and `flags.rs` | the bytes |
| `WireWriter::write_query_mode`, `write_output_include`, `write_optional_output_include`; `WireReader::read_query_mode`, `read_output_include`, `read_optional_output_include` | removed | `write_optional_query_mode` / `read_optional_query_mode` for listActions; listOutputs' `include` is the transceiver's |
| `wallet::wire::{WireReader, WireWriter}` | `#[doc(hidden)]`, no part of the public contract | `WalletWireTransceiver`, `WalletWireProcessor` |

Every `#[deprecated]` item of the base was read (`git grep '#\[deprecated' -- src`, eleven attributes):

| Deprecated item | Note | Verdict |
|---|---|---|
| `Beef::from_binary_with_limits` | since 0.4.0, "the limits no longer refuse anything" | removed |
| `create_overlay_admin_token` | since 0.3.7, "Use `create_signed_overlay_admin_token` instead" | removed |
| `KVStoreInterpreter::verify_signature_legacy` | "A signature verdict alone, for a token in the key-bound form only" | removed (ruling 4) |
| `ChainTip::genesis_height` | since 0.9.0-beta.4, "until its removal at the next api-break" | not this lane's: another change of the cut removes it |
| `BeefTx::tx_mut` | "use Beef::edit_tx" | kept: the stable line has no `Beef::edit_tx` (`git grep 'fn edit_tx' origin/main -- src`: none), so 0.8.11's callers edit an entry through it; the note promises no removal |
| `ArcConfig`, `ArcBroadcaster`, `ArcBroadcaster::new`, `ArcBroadcaster::with_config` | since 0.9.0, "ARC is deprecated; ARCade is the standard" | kept: deprecated on this prerelease line alone, undeprecated on the stable line; no removal promised |
| `DEFAULT_POLICY_URL`, `LivePolicy::new` | since 0.9.0, the same | kept, as above |

The stable line's 0.8.10 and 0.8.11 entries were read for each removed name (`origin/main`'s `CHANGELOG.md`): 0.8.10 names `verify_signature_legacy` as "the deprecated" door among those it fixed and tells no caller to use it; it tells a caller of `create_overlay_admin_token` to write with `create_signed_overlay_admin_token`; 0.8.11's doors `from_beef_with_limits` and `BeefLinkLimits` are other items than `from_binary_with_limits` and `BeefLimits`, and stay.

Not this lane's, met and left: the four public serde helper modules of `wallet::types` (`hex_bytes`, `hex_bytes_option`, `hex_txid`, `hex_txid_vec_option`; private after #1008 retypes them), `ChainTip::genesis_height`, the eighteen configuration structs of row 8c (the `Pending` rows of `tests/arch_non_exhaustive_843d.rs`, untouched), the linkage types of row 4, the one broadcast answer type.

## What was carried from `lane/fix-843d10` and what was rebuilt

`fa0f4880` (one commit of 2026-11-12 on `43ee8c85`) was applied onto the base with `git cherry-pick -n`. Carried as it stood: the code of `src/error.rs`, `src/overlay/mod.rs`, `src/overlay/overlay_admin_token_template.rs`, `src/transaction/beef.rs`, `src/transaction/beef/collect.rs`, `fuzz/fuzz_targets/fuzz_beef_parser.rs`, and the tests `tests/beef_limits.rs`, `tests/overlay_cross_sdk_tests.rs`, `tests/overlay_integration_tests.rs`, `tests/wire_error_frames.rs`. Resolved by hand: `src/transaction/mod.rs` (the base's re-export gained `BeefLinkBudget`, `BeefLinkLimits` and `LinkedTransaction` with 0.8.11's doors, kept), `src/kvstore/interpreter.rs` (the base's door calls `legacy_signature::signed_by`, GHSA-mj2m-jxgv-r446's body, removed with it), `.cargo/mutants.toml` (the `dependency_order` exclusion's line, 857 to 821). Rebuilt on the base: every record (`CHANGELOG.md`, the `CLAUDE.md` rows, `docs/ARCHITECTURE.md`: the auto-merge had put the entry inside another entry and doubled table rows), and what the base gained since: `src/kvstore/legacy_signature.rs`, `tests/kvstore_legacy_signature_verdict.rs`, the legacy door in `tests/kvstore_key_bound_signature.rs` and in `fuzz_script_parser`, the row of `tests/arch_text_doors.rs`, the `BeefLimits` row of `tests/arch_non_exhaustive_843d.rs`. Its lane record `docs/lanes/fix-843d10.md` is not carried; this file stands for it. New here: `script::transaction`, the wire's code modules and six methods, the hidden codec, `tests/arch_removed_names_843.rs`.

## The pin

`tests/arch_removed_names_843.rs`, two tests; RED on a scratch copy of `4c5454be` with the file overlaid (`cargo test --test arch_removed_names_843`: 1 passed, 1 failed, the failure naming every removed name at its line, `src/script/mod.rs:83`, `src/script/transaction.rs`, `src/wallet/wire/mod.rs:94` unhidden, `:660` and `:670` not `pub(crate)`, the module docs without the sentence); green on the tip.

## The dependents, counted, not changed

`git grep -nE` of every removed and hidden name over `*.rs` in the fifteen repositories under `~/bsv` on this host that name `bsv-rs` in a `Cargo.toml` (each named by its path; `~/bsv/bsv-low` not read): `bsv-messagebox-cloudflare-public`, `bsv-middleware-rs`, `bsv-overlay-cloudflare`, `bsv-storage-cloudflare`, `bsv-tracker`, `bsv-wallet-cli`, `bsv-wallet-toolbox-rs`, `chaintracks-cloudflare`, `rust-message-box`, `rust-wallet-infra`, `bsv-dd`, `btg-token`, `composer-overlay`, `verifier-lab`, `bsv-zk-notes-nullifiers`, at their checked-out heads, and `origin/beta` of the toolbox, the CLI and the tracker.

| Name | Uses |
|---|---:|
| each removed name (seventeen, and the two code modules) | 0 |
| `WireReader` | 0 |
| `WireWriter` | 1 site in one test: `bsv-wallet-toolbox-rs` `origin/beta` (`b9880eb4`) `src/wallet/wallet.rs:7392,7495`; it calls none of the six removed methods and compiles unchanged |

The hits that are not uses: `bsv-overlay-cloudflare`'s own `overlay_engine::beef_limits::BeefLimits` (16 lines), `bsv-wallet-toolbox-rs`'s own `arc::status_codes` (12 lines), two test function names holding `status_codes`, and `bsv-middleware-rs` `tests/payment_limits.rs:408`, a string in a list of names its own source must not hold.

## The break, as the tool prints it

`cargo semver-checks check-release --baseline-rev origin/beta --all-features --release-type minor` (0.51.0): 202 checks, 194 pass, 8 fail, 58 skip: `enum_variant_missing`, `function_missing`, `inherent_method_missing`, `module_missing`, `pub_module_level_const_missing`, `struct_missing`, `struct_now_doc_hidden`, `trait_missing`, each naming an item of the table above and nothing else. The six codec methods are named by no lint (the tool does not read the methods of a type that is now hidden). The pull request needs the `api-break` label (`tests/arch_ci_semver_holds_beta_886.rs`).

## Files shared with the open pull requests

Measured on 2026-11-17: `gh pr diff <n> --name-only` against this change's 43 files (`git diff --name-only origin/beta`). Every one of the six also writes `CHANGELOG.md`, the root `CLAUDE.md` and `tests/CLAUDE.md`.

| Pull request | Files shared, beside those three |
|---|---|
| #915 | `.cargo/mutants.toml`, `fuzz/fuzz_targets/CLAUDE.md`, `fuzz/fuzz_targets/fuzz_script_parser.rs`, `src/script/CLAUDE.md`, `src/script/mod.rs` (its `SimpleUtxo` proofs go with whichever lands second), `src/transaction/CLAUDE.md`, `src/transaction/mod.rs` |
| #1014 | `.cargo/mutants.toml`, `src/overlay/CLAUDE.md`, `src/script/CLAUDE.md`, `src/transaction/CLAUDE.md`, `src/wallet/CLAUDE.md`, `tests/arch_non_exhaustive_843d.rs` |
| #1005 | `src/overlay/CLAUDE.md`, `tests/arch_non_exhaustive_843d.rs`, `tests/kvstore_key_bound_signature.rs`, `tests/overlay_integration_tests.rs` |
| #974 | `src/CLAUDE.md`, `src/transaction/beef.rs`, `src/transaction/CLAUDE.md`, `src/transaction/mod.rs`, `tests/beef_limits.rs`, `tests/overlay_integration_tests.rs`, `tests/script_transaction_context_603.rs` (deleted here), `tests/wire_method_roundtrip_tests.rs` |
| #1009 | `.cargo/mutants.toml`, `docs/ARCHITECTURE.md`, `fuzz/fuzz_targets/CLAUDE.md`, `fuzz/fuzz_targets/fuzz_beef_parser.rs`, `src/CLAUDE.md`, `src/transaction/beef.rs`, `src/transaction/beef/collect.rs`, `src/transaction/CLAUDE.md`, `src/transaction/mod.rs`, `tests/beef_limits.rs`, `tests/overlay_integration_tests.rs`, `tests/script_transaction_context_603.rs` (deleted here), `tests/wire_method_roundtrip_tests.rs` |
| #1008 | `src/CLAUDE.md`, `src/transaction/beef.rs`, `src/transaction/CLAUDE.md`, `src/transaction/mod.rs`, `src/wallet/CLAUDE.md`, `src/wallet/wire/CLAUDE.md`, `src/wallet/wire/encoding.rs`, `src/wallet/wire/mod.rs`, `tests/beef_limits.rs`, `tests/overlay_integration_tests.rs`, `tests/script_transaction_context_603.rs` (deleted here), `tests/wallet_tests.rs`, `tests/wire_method_roundtrip_tests.rs` |

No rebase of any of them onto this change was tried.

## The fold of the three reads (2026-11-17)

The reads of `d85d8724`: the cold read MERGE, the rule read ACCEPT, the strength read FIX. Taken: the cold read's `76291f72` (the counts of `docs/ARCHITECTURE.md`, `fuzz/fuzz_targets/CLAUDE.md` and the non-exhaustive row) and the rule read's `03ef0191` (`token_derivation.rs`'s header without `verify_signature_legacy`), both documents alone, picked clean; the strength read's `738b6d09` makes the same change to the same header lines as `03ef0191` and is not taken.

The FIX, as a class: every test that left with a removed or hidden item was read for the door it judged.

| Removed item | Tests that went | What each pinned | At a door that stays |
|---|---:|---|---|
| `verify_signature_legacy` | 13 | the shared derivation (`token_derivation.rs`) and the signature | ported now (5, as 4 tests in `tests/kvstore_key_bound_signature.rs`): the noncanonical protocol field, a token changed in one respect (and the four- and seven-field counts with it), the controller field naming another key, the recorded tokens; pinned elsewhere (5): a forged signature and no signature (`test_verify_signature_invalid`, `_missing`, `_empty` in `src/kvstore/interpreter.rs`), an empty value (`tests/kvstore_empty_value.rs`), the generated one-byte changes (`a_key_bound_token_is_read_at_every_door_and_no_division_of_it_is` and the ported one-respect test), the earlier form whatever its lock (`a_token_whose_signature_does_not_bind_its_key_authenticates_at_no_door`); nothing to pin (3): the verdict against an outside key (the door that stays reads the controller field, no argument), and the legacy answers on repeated or empty tags, which `extract_fields` refuses (`malformed_reference_tags_are_refused_by_both_reader_paths`, `an_explicit_empty_tag_field_is_kept_and_signed`) |
| `script::transaction` | 5 (4 in `script_transaction_context_603.rs`, `test_simple_utxo`) | the traits' default methods and `SimpleUtxo` | nothing to pin: no door of the crate read them |
| `from_binary_with_limits`, `BeefLimits` | 3 | the hints changing nothing read | nothing to pin: the claimed-count refusal stays on `Beef::from_binary` in the same file |
| the six 0/1 mode methods | 6 (3 in `encoding.rs`, one each in `wallet_tests.rs`, `wire_method_roundtrip_tests.rs`, `wallet_wire_flags_1002.rs`) | the methods' own bytes | nothing to pin: no wire call carried them; the methods' flag bytes are `wallet_wire_flags_1002.rs`'s |
| `create_overlay_admin_token` | 0 (rewritten) | the decode's refusal of the 4-field token | pinned elsewhere: `test_admin_token_creation_and_decoding` builds it with `PushDrop` |
| `HmacMinimalLengthKey` | 0 (one entry of `wire_error_frames.rs`) | the variant's frame | nothing to pin: never emitted |
| `status_codes`, `counterparty_codes`, the hidden codec | 0 | | the frames of `wallet_wire_flags_1002.rs` |
| the two fuzz targets | 2 invariants | the legacy door's bound, the hinted parse's agreement | nothing to pin |

The RED of each ported check, on a scratch copy of the fold (`cargo test --no-fail-fast --features "full,http" --lib` and the 20 `kvstore_*` targets): `namespace`'s canonical comparison removed, `a_namespace_token_signed_in_noncanonical_json_is_refused` alone fails; the derived-lock comparison of `derivation` made `is_ok()`, `a_signed_token_changed_in_one_respect_is_refused` and `the_recorded_kvstore_tokens_take_the_checks_verdict` alone fail. `a_signed_token_whose_controller_field_is_another_key_is_refused` is held twice there (the lock and the signature), no one-line mutation of either found failing it alone.

Not folded, for the captain: the interpreter's own refusal `KVStore protocol ID must use canonical JSON` (`src/kvstore/token_validation.rs:87-89`) named by no test (the strength read's row, older than this change); the module docs of `src/wallet/wire/mod.rs` naming the codec's readers as this repository's alone, where a dependent's test also uses `WireWriter` (the rule read's note); `.github/scripts/nightly_mutants.py:58`'s comment naming `script::transaction::tests` (the cold read's note).


## The second fold: the three rows left for the captain (2026-11-17)

Taken now, on the captain's ruling that a pull request about what the removed doors' tests pinned keeps it pinned.

**The interpreter's canonical-JSON refusal.** On a scratch copy of `30333c49` with `if false &&` put before the comparison at `src/kvstore/token_validation.rs:87`, `cargo test --no-fail-fast --features "full,http" --lib` and the 20 `kvstore_*` targets: 21 binaries, 2,153 passed, 0 failed. No test named it. With `a_token_whose_protocol_text_is_not_canonical_json_is_refused_in_the_reference_words` added (`src/kvstore/token_validation_tests.rs`: five texts, `[1, "kvstore"]`, `[ 1,"kvstore"]`, a trailing space, a trailing line feed and an escaped `o`, each tagged and not, written by this crate's `ProtoWallet`, `KeyDeriver` and `PushDrop`, signed and locked for `[1,"kvstore"]`; the error asserted as `Error::KvStoreError` in the reference's words, `kvStoreTokenValidation.ts:97-98` at `ts-stack@edf6e03`; the canonical control read), the library under the plant: 1,862 passed, 1 failed, that test alone.

**The class: every refusal on the reader's path.** `decode_and_verify` and the helpers it calls, and `writable`, the set path's check of the same bounds. Named already 10 (the table's eight rows so marked, the set path's row three), pinned now 10 (`each_refusal_ahead_of_the_lock_is_made_in_its_words`, one cell or more each, by variant and words; the reference's words where it makes the same refusal, `kvStoreTokenValidation.ts:28-74`), not pinned 4. Each pinned-now row was planted alone on the scratch copy (`cargo test --lib kvstore::`) and failed the class test (the field count past six also `_544`).

| Line | Refusal | Test |
|---|---|---|
| 47-50 | `decode_before`'s refusal, the canonical words where they apply | named: `the_reader_gives_the_reference_verdict_in_its_words_544` (`noncanonical_envelope`) |
| 52 | field count | named: `_544` (`unsigned`, four fields); seven fields pinned now |
| 57 | a field past 1 MiB | pinned now |
| 61 | the data past 1 MiB and 64 KiB | pinned now |
| 65 | the envelope | named: `_544` |
| 41 | a text field not UTF-8 (protocol, key, value, tags) | pinned now |
| 76 | protocol not JSON | named: `_544` (`raw_protocol`, the variant; serde's words) |
| 80 | protocol not two members | pinned now |
| 82 | protocol level or name type | pinned now (`[1,7]`; the level bound is held twice, see 91) |
| 85 | protocol name length | pinned now |
| 88 | canonical JSON | pinned now |
| 91 | `Protocol::from_tuple` | not pinned: line 82 admits levels 0 to 2 alone, so it refuses nothing; with line 82's range widened to 3 it refuses level 3 in the same words, so the plant on line 82 is green (an equivalent pair) |
| 117 | key length | pinned now (801 bytes) |
| 121 | value length | not pinned: no canonical token carries an empty value (the writer writes an empty field as `OP_0`, read back as `[0]`; a zero-length push fails the envelope) and a value past 1 MiB is refused at line 57 first |
| 124 | controller length | pinned now |
| 129 | controller point | named: `a_tag_05_key_is_refused_in_the_reference_words_550` |
| 133 | tags not JSON, and `validate_tags`' three rules | pinned now (not JSON, by variant; the three rules also named by `interpreter.rs`'s `malformed_reference_token_tags_use_the_reference_words_and_order`) |
| 140 | `derive_public_key`'s refusal of a protocol name the wallet's validator refuses | not pinned: the wallet validator's variant and words, pinned at its own doors; whether a name this reader admits reaches it here is not measured by this fold |
| 142 | lock not linked | named: `_544` (`wrong_lock_key`) |
| 155 | `verify_signature`'s error, mapped | named: `_544` (`bad_signature`) |
| 162 | `!verified.valid` | not pinned: unreachable, `ProtoWallet::verify_signature` answers `Err` for a bad signature |
| 97, 100, 104 | `writable`: key and value bounds, tags | named: `tests/kvstore_key_bound_signature.rs` (`set` at 801 bytes and 1 MiB + 1, a repeated and an empty tag) |

**The codec's sentence.** `src/wallet/wire/mod.rs` and the CHANGELOG entry now say the same: the codec is hidden from the documentation, no part of the public contract and may change or vanish in any release; it stays reachable so that this repository's tests, benches and `fuzz_wire_protocol` keep compiling, and at this writing one dependent's test reaches the writer there too, on no promise. (`fuzz_wire_protocol` is the one fuzz target that names it; `benches/wire_codec.rs` the one bench.)

**The stale comment.** `.github/scripts/nightly_mutants.py:57-60` names `error::` and `script::evaluation_error::` as the collision the rule guards today, and `script::transaction::tests` as the one it guarded until #843; the script's behaviour is unchanged (a comment alone), its 122 tests pass.

## The third fold: every refusal at its edge, against the reference's recorded answers (2026-11-17)

The re-read of the second fold planted three faults at the edges of refusals this record called pinned (the canonical-JSON check skipped at levels 0 and 2, the payload bound moved by up to 53 bytes, the controller's length a lower bound alone) and each passed every kvstore test: the cells held one point of each refusal, not its edge. The class is closed by two machines.

**Machine 1: the edges, recorded.** `tests/vectors/kvstore_token_edges.json`, 215 cells over the 19 checks of the table below, each a token this crate's writer builds (`src/kvstore/token_edges_tests.rs`, the cells in `token_edges_cells.rs`: `PushDrop`'s script, `KeyDeriver`'s lock, `ProtoWallet`'s signature; the bounds written as the reference's literals, never this crate's constants, so a moved bound is a verdict the replay reads), named in the vector by its script's SHA-256, judged by `decodeAndVerifyKVStoreToken` run under Node v22.18.0 at the pin `ts-stack@edf6e03` and at the head the fold read, `ts-stack@11faa7d1` (`tests/support/kvstore_token_edges.mjs`; two runs byte-identical). One test, `every_refusal_edge_is_the_reference_answer`, rebuilds every script, checks its hash and replays this crate's `decode_and_verify` against the pin's verdict and words: 44 cells accepted on both sides, the rest refused. Each check has cells on both sides of its edge (a length one under, at and one past; a text canonical and each spelling a peer can send), at every value of each parameter the table names.

| Row | Check, as the code writes it | Edge | Parameters | Reference (`kvStoreTokenValidation.ts` at `11faa7d1`; at the pin `edf6e03` every line after `:11` is one later, its `MAX_TAGS` at `:12`, so the pin's are `:N+1` and its tags' `:58-74`) | Cells (accepted) |
|---|---|---|---|---|---|
| R01 | `decode_before`: the lock key a point (`canonical_refusal`'s words) | tag 02/03/04, 05, 06/07 parity, x past p | the key's form | `PushDrop.ts:73-77`, `Point.fromDER` | 7 (0) |
| R02 | `matches!(fields.len(), 5 \| 6)` | 4, 5, 6, 7 | | `PushDropValidation.ts:59-61` | 4 (2) |
| R03 | `field.len() > MAX_VALUE_BYTES` | 1 MiB - 1, 1 MiB, 1 MiB + 1 | the field | `PushDropValidation.ts:63-66` | 4 (2) |
| R04 | `payload > MAX_PAYLOAD_BYTES`, running | 1,114,112 - 1, exact, + 1 | 5 and 6 fields | `PushDropValidation.ts:67-71`, `:89-90` | 6 (0) |
| R05 | `token.lock() != script` | each drop form, a trailing opcode, a non-minimal push, `0x81`, `0x05`, `0x00`, `0x01` | | `PushDropValidation.ts:40-52,72-74` | 12 (3) |
| R06 | `strict_utf8`: fatal UTF-8, one BOM dropped | `ff`, overlong, surrogate bytes, one BOM, two | | `toUTF8Strict`, `:94` | 5 (1) |
| R07 | `serde_json::from_str` | no JSON, cut, a trailing comma, `1e400` | | `JSON.parse`, `:95` | 4 (0) |
| R08 | an array of exactly two | `[]`, one, three, object, string, `null`, number | | `:28-30` | 7 (0) |
| R09 | the level a number equal to 0, 1 or 2, the name a string | -1, 3, 1.5, `"1"`, `true`, `null`, `0.0`, `1.0`, `2.0`, `-0`, `-0.0`, `1e0`, `1E0`, `10e-1`, `1.0000000000000001`, 2^64 + 1; the name a number, `null`, an array, an object | | `:31-35` | 20 (0) |
| R10 | `(5..=400).contains(&name.len())` | 4, 5, 400, 401 bytes; 4 bytes of two characters | level 0, 1, 2 | `:36-37` | 15 (6) |
| R11 | `serde_json::to_string(&(level, name)) != text` | canonical and twelve spellings (spaces, line ends, a tab, escapes, `L.0`, `Le0`), `-0` | level 0, 1, 2 | `:96-98` | 41 (3) |
| R12 | the key strict UTF-8, `(1..=800).contains(&key.len())` | a BOM alone, a BOM then `k`, 1, 800, 801, a BOM then 800, 800 bytes of 400 characters, 802 of 401 | | `:41-46`, `:99` | 8 (5) |
| R13 | the value strict UTF-8, 1 byte to 1 MiB | a BOM alone, a BOM then `v`, a BOM then 1 MiB - 3 | | `:48-55`, `:100` | 3 (2) |
| R14 | `data[3].len() != 33` | 32, 34 (33 in every other cell) | | `:101` | 2 (0) |
| R15 | `PublicKey::from_bytes` of the controller | the other parity, tags 00 01 04 05 06 07 08, x of no point, 0, p, p + 1, p + 2, `ff`x32 | the key's form | `:75-81`, `:102` | 14 (0) |
| R16 | the tags: JSON, an array of at most 32, each a string of 1 to 256 bytes, unique | `[]`, `null`, `{}`, a string, a number, 32, 33, 0/1/256/257 bytes, 256 and 257 bytes of four-byte characters, a number, `null`, an array, twice, case, a BOM, not UTF-8, no JSON, spaced | | `:57-73` (the pin `:58-74`, `MAX_TAGS` at `:12`), `:103` | 22 (8) |
| R17 | the derivation's rules on the name (`validate_protocol_name`) | a hyphen, two spaces, ` protocol` at the end, three characters of six bytes, short after the trim; upper case, a leading and a trailing space, the Kelvin sign | | `KeyDeriver.ts:470-511`, through `:105` | 9 (4) |
| R18 | `expected != token.locking_public_key` | another key ID, another level, `for_self` false, another controller | level 0, 1, 2; 5 and 6 fields | `:105-108` | 18 (6) |
| R19 | the signature (`verify_signature`, `!verified.valid`) | another signer, other data, high S, a trailing byte, 8 bytes, 1 byte, text | 5 and 6 fields | `:109-116` | 14 (2) |

Of the 215 cells, 199 agree with the pin in verdict and words. One class differed and is **fixed** here, RED first: a level spelled as a non-integer JSON number equal to 0, 1 or 2 (`1.0`, `-0`, `1e0`, `10e-1`, `1.0000000000000001`; 17 cells, R09 and R11) was refused `KVStore protocol ID is invalid` here, where the reference's `JSON.parse` reads the number, admits it at `:34` and refuses the text after as `KVStore protocol ID must use canonical JSON` (`:97-98`; the pin's lines, the head's `:33` and `:96-97`); `protocol` now reads the level as the number and compares it as the reference does. The RED: `every_refusal_edge_is_the_reference_answer` failed at `level_0_0` (`left: "KVStore protocol ID is invalid"`). Both sides refused every such text before and after: words alone.

Sixteen cells are **stated** (`STATED`, each with its reason; both sides refuse every one): five a key the reference reads and this crate's byte path refuses at its parse (a hybrid lock key whose prefix names y's parity, a lock key or a controller with x past p that reduces to a point), the reference refusing the token later at the envelope or the lock (#498's row: the byte path stays strict); six a text no JSON (and `1e400`, `Infinity` to `JSON.parse`), refused in `serde_json`'s words where the reference's are V8's; five a protocol name the derivation refuses, refused in the shared deriver's words (`validate_protocol_name`, the words of every door that derives, so conforming here alone would split them; a name of three two-byte characters is refused for its length there, counted in UTF-16 units, and for its characters here). One cell moved at the head (`HEAD_MOVED`, the vector's `head`): 33 tags, refused at the pin, read at `11faa7d1` (`c0453b58`, "Remove fixed GlobalKVStore tag-count caps from client and overlay"); this crate keeps the pin's cap, a move of the pin being its own change.

The bound, in plain words: the cells hold each check's edge as the reference answers it, for the tokens this crate's writer can build; they do not hold a check this path does not make, the reference's behaviour on a token no writer of this crate produces (a script that is no PushDrop at all is #544's and #618's), nor the derivation's rules beyond the names listed.

**Machine 2: the mutation sweep.** `cargo mutants` 27.1.0 (the nightly's `CARGO_MUTANTS_VERSION`), `--jobs 1`, `--features "full,http"`, in shards each under ten minutes, over the functions this pull request's diff touches under `src/` (`git diff origin/beta...HEAD --stat -- src`; the deletions leave nothing to mutate): `src/kvstore/token_validation.rs` whole (the path of machine 1; `protocol` changed by this fold), `src/wallet/wire/encoding.rs`'s `read_counterparty`, `read_action_status`, `write_counterparty`, `write_action_status` and `src/wallet/wire/flags.rs`'s `action_status` and `read_listed_action_status` (the code modules' constants, `--test wallet_wire_flags_1002 --test wallet_wire_cross_sdk_tests`), `src/transaction/beef.rs`'s `from_binary` and `from_reader` and `src/transaction/beef/collect.rs`'s `collect` (the regex took `bumps_as_read` and `collect_element` with it; `--lib transaction::beef`); the kvstore shards under `--lib kvstore::`. The hunk of `src/overlay/overlay_admin_token_template.rs` that stays is a doc comment.

| Surface | Made | Caught | Missed | Unviable | Timeout |
|---|---:|---:|---:|---:|---:|
| `token_validation.rs` | 42 | 34 | 4 | 4 | 0 |
| the wire's five functions | 12 | 7 | 1 | 4 | 0 |
| the BEEF reader's | 18 | 17 | 1 | 0 | 0 |
| total | 72 | 58 | 6 | 8 | 0 |

Each missed mutant's fate:

| Mutant | Fate |
|---|---|
| `token_validation.rs:103:5` `writable` → `Ok(())` | caught by `tests/kvstore_key_bound_signature.rs` (the set path's door, outside `--lib`; 9 of 9 `writable` mutants caught there) |
| `token_validation.rs:103:8` delete `!` in `writable` | caught there |
| `token_validation.rs:106:8` delete `!` in `writable` | caught there |
| `token_validation.rs:109:30` delete `!` in `writable` | caught there |
| `encoding.rs:163:13` delete the `ANYONE` arm of `read_counterparty` | caught by `wallet::wire::encoding::tests::test_counterparty_roundtrip` (`--lib wallet::wire`) |
| `collect.rs:194:25` `+=` → `*=` in `bumps_as_read` (`leaf.at`) | stated: outside the functions this pull request changes (the regex took it); a leaf's offset there is read only by a refusal `Bump::read_alone` has already made, so it is likely equivalent, not shown; left to the nightly's BEEF surface |

**The re-read's three plants, planted again on the folded tree** (`cargo test --features "full,http" --lib kvstore::`, each alone): the canonical comparison under `level == 1 &&`, `MAX_PAYLOAD_BYTES` raised by 32, the controller's check `< 33`: each fails `every_refusal_edge_is_the_reference_answer` alone (at `level_0_0`, `payload_plus_1_5_fields`, `controller_34_bytes`), 75 others passing. Raised or lowered by one byte, the payload bound fails it too (`payload_plus_1_5_fields`, `payload_exact_5_fields`); the builder reads the reference's literal bounds, so the failure is the verdict's and never a drifted script.

The counts above replace the second fold's: the table of that fold named 10 refusals and pinned 10 more by one cell each; every row here has cells on both sides of its edge.

## The fourth fold: the table rebuilt by its rule (2026-11-18)

The re-read of the third fold planted six faults and two passed the replay: the level compared in `f32` or within 0.1 (no cell one representable step past a level: `1.0000000000000001` reads as exactly 1.0), and every leading byte-order mark trimmed from the key (two marks were tried on the protocol field alone). The table's rule was "both sides of each check's edge"; one field stood for every field a shared helper serves, and a float compare had no neighbour cells. The rule is widened, and the table is derived from it:

- **(a) A helper serves every field it is applied to.** For every helper the path calls, each field it reads has its own cells on both sides of each of the helper's edges: zero, one and two of what it strips, one not leading; the shortest and longest it accepts and one past each.
- **(b) A numeric compare has its neighbours.** For each constant, the nearest representable value on each side in the type the reference compares in (a double: `JSON.parse`'s number and `!==`), the same in the next narrower float (`f32`), and the spellings that read as exactly the constant.
- **(c) A count or a length has its bound, one under and one over.**

The helpers, enumerated by `grep -nE 'strict_utf8\(|serde_json::from_str|\.len\(\)|contains\(|from_bytes|validate_tags|canonical_refusal|point_message|decode_before|derive_public_key|verify_signature|position\(' src/kvstore/token_validation.rs` and, for the two it calls in other files, `grep -n 'fn validate_tags' src/kvstore/interpreter.rs` and `grep -nE 'fn (decode_before|point_message|canonical_refusal)' src/script/templates/pushdrop_position.rs`:

| Helper or check (row) | Fields it serves | Cells the rule demands | Had | Added |
|---|---|---|---:|---:|
| `strict_utf8` (R06, R12, R13, R16): fatal UTF-8, one leading mark dropped | protocol, key, value, tags | each field: `ff`, an overlong `c0 80`, surrogate bytes, a cut sequence, a code point past U+10FFFF, U+10FFFF read, one mark, two marks, a mark not leading | 13 | 25 |
| the field bound (R03), 1 MiB a field | protocol, key, value, controller, tags, signature | each field at 1 MiB and at 1 MiB + 1 (the value at 1 MiB - 1 too) | 4 | 9 |
| the running payload (R04) | the fields' sum | 1,114,112 - 1, exact, + 1 at five and six fields | 6 | 0 |
| `serde_json::from_str` (R07, R11, R16) | protocol, tags | each field: no JSON, white space, an escape in its long form, a surrogate pair and a lone surrogate escape, a number past the double range, nesting 127, 128 and 129 deep | 36 (R07's 4, R11's 30 white-space and escape spellings, R16's 2) | 13 |
| the byte length (`str::len`, the reference's `utf8ByteLength`; R10, R12, R13, R16) | name, key, value, each tag | each field at its bound in two-byte and in four-byte characters, and one character past | 5 | 5 |
| the level compare (R09, R11), `== 0.0, 1.0, 2.0` | the level | for 0, 1 and 2 the nearest double on each side (6), the nearest `f32` on each side (6), the spellings that read as exactly a level (17; `1.05` beside them for a tolerance) | 9 | 21 |
| the name 5 to 400 bytes (R10) | the name, at levels 0, 1, 2 | 4, 5, 6, 399, 400, 401 | 12 | 6 |
| the key 1 to 800 bytes (R12) | the key | 0, 1, 2, 799, 800, 801 | 4 | 2 |
| the value 1 byte to 1 MiB (R13) | the value | 0, 1, 2 (1 MiB - 1, 1 MiB at R03; 1 MiB + 1 is R03's refusal) | 2 | 1 |
| the controller 33 bytes (R14) | the controller | 32, 33 (every cell), 34 | 2 | 0 |
| `validate_tags`' count, at most 32 (R16) | the tags | 31, 32, 33 | 2 | 1 |
| `validate_tags`' tag 1 to 256 bytes (R16) | each tag | 0, 1, 2, 255, 256, 257 | 4 | 2 |
| the field count 5 or 6 (R02) | the fields | 4, 5, 6, 7 | 4 | 0 |
| `PublicKey::from_bytes`, `decode_before`, `point_message` (R01, R15) | the lock key, the controller | the key's forms, as in the third fold | 21 | 0 |
| the derivation (R17, R18) | the name, the key ID | as in the third fold (the key ID's bound in UTF-16 units is never under the byte bound) | 27 | 0 |
| the signature (R19) | the signature | as in the third fold (1 MiB at R03) | 14 | 0 |

The protocol field's U+10FFFF and a mark not leading are not built: a code point outside `[a-z0-9 ]` is the derivation's refusal (R17's stated class) and a mark not leading is no JSON (R07's). 85 cells added; the vector holds 300, 71 accepted on both sides.

**The recording.** `record_the_edge_tokens` wrote the 300 tokens, and `tests/support/kvstore_token_edges.mjs` judged them at the pin `ts-stack@edf6e03` and at the head `11faa7d1` under Node v22.18.0, each SDK bundled with bun from an archive of its sha; two runs byte-identical, the third fold's 215 cells unchanged byte for byte. The recorder writes a tag no `serde_json` text can hold (a lone surrogate) as its UTF-16 code units, `{"utf16": [55296]}`; no other cell's bytes moved. No added cell answers otherwise at the head than at the pin: `tags_33` stays the one moved cell.

**What the cells answered.** 77 of the 85 are the pin's verdict and words, with no change of code: the reader of the third fold already compared the level as a double, read each field through one fatal decoder that drops one mark, and bounded each field and each length where the reference does. Eight are stated, none fixed:

- seven both sides refuse in other words, the JSON reader's: `lone_surrogate_escape` (a protocol name with `\ud800`: the reference parses it, stringifies it to the same text and refuses the name at its derivation, `Protocol names can only contain letters, numbers and spaces`; `serde_json` refuses the escape), `tags_bom_twice` and `tag_number_1e400` (`JSON_WORDS`), and `protocol_depth_128`, `protocol_depth_129`, `tags_depth_128`, `tags_depth_129` (`JSON_DEPTH`: `serde_json`'s recursion bound of 128, kept so that no text can exhaust the stack, root rule 5; `JSON.parse` reads the text and the reference refuses the value after, `KVStore protocol ID must contain exactly two fields` and `KVStore tag has an invalid length`); depth 127 agrees on both;
- one the reference reads and this crate refuses (`STATED_READ_THERE`): `tag_lone_surrogate_escape`, a tag `["\ud800"]`, a string `JSON.parse` holds and no Rust `String` can (the #566 residue), refused here in `serde_json`'s words. Read as a representation residue, not a defect of the other side: the signature is over the bytes on both sides and no identity or verdict turns on the held text.

The replay asserts that a stated cell's words differ, so a stated row that comes to agree is seen.

**The plants**, each planted alone in a scratch copy of the tip and run under `cargo test --features "full,http" --lib kvstore::` (82 others passing each time): the level compared as `f32` fails at `level_f64_after_0`; compared within 0.1 at `level_f64_after_0`; within `f64::EPSILON` (an added plant) at `level_f64_after_0`; every leading mark trimmed from the key at `key_bom_twice_then_k` (`protocol_id_text`: the lock no longer the controller's for the key read); the same for the value at `value_bom_twice_then_v` (`value_sha256`).

**The sweep.** `cargo mutants` 27.1.0 with `--in-place` (one job; `--jobs` cannot be given with it), `--features "full,http"`, in shards of two to five mutants, each under six minutes, the shard logs under the lane's out folder:

| Surface | Tests | Made | Caught | Missed | Unviable | Timeout |
|---|---|---:|---:|---:|---:|---:|
| `src/kvstore/token_validation.rs` whole | `--lib kvstore::` | 42 | 34 | 4 | 4 | 0 |
| `validate_tags`, `decode_before`, `point_message`, `canonical_refusal` (the filter took `KVStoreInterpreter::verify_signature`'s ten with them) | `--lib kvstore::` | 44 | 18 | 25 | 1 | 0 |

Each missed mutant's fate:

- the four of `writable` (`token_validation.rs:103:5`, `103:8`, `106:8`, `109:30`): caught by `tests/kvstore_key_bound_signature.rs` (9 of 9 `writable` mutants there, run again);
- the eighteen of `pushdrop_position.rs` (`decode_before`'s length check, `point_message`'s parity guard, `canonical_refusal`'s count, bounds and payload): each caught by the helpers' own tests (`--lib --test script_pushdrop_canonical_bounds_616 --test primitives_sec1_tag_05_550 --test kvstore_local_parser_words_489`: 22 of 22 of the three functions caught). No kvstore cell reaches them: the writer's tokens are canonical, and `canonical_refusal` speaks only for a script `decode_before` refuses;
- `KVStoreInterpreter::verify_signature`'s seven, outside the rule's helpers, run against `tests/kvstore_key_bound_signature.rs` and `tests/kvstore_interpreter_envelope_544.rs`: four caught; three equivalent, each in eight words: `hash_to_directly_verify` deleted (`None` is the field's default value already), `for_self` deleted (`None` is read as false, the value given), the empty-signature guard made `true` (an empty signature never verifies, the guard only shortens).

**The bound, once, in plain words.** The cells hold every field each helper of this path serves at each of the helper's edges, both neighbours of the level in a double and in a float, and every bound with its two neighbours, as the reference answers them, for the tokens this crate's writer can build. They do not hold: a helper's edge the rule does not name (a JSON reader's every grammar case, every invalid UTF-8 sequence, every malformed DER), a field's value combined with another field's at its edge (the cells move one thing at a time, save R04's sum), the reference's answer to a script that is no PushDrop token (#544's and #618's), or a comparison written in a type narrower than `f32`; the grammar's cases and the narrower type are why the sweep stands beside the cells.

**The citations** (rule 4 of the brief: every citation of the reference's lines in the lines this pull request adds, 42 lines, read at the sha each names, or the pin where none is named; the five false ones corrected):

| File and line | Sha claimed | True at it | Corrected |
|---|---|---|---|
| `src/kvstore/token_validation.rs:82` (`:33`, the level compare) | the pin (the file's header) | no: the pin's `:34`, the head's `:33` | `:34` at the pin, the head's `:33` |
| `tests/support/kvstore_token_edges.mjs:3` (`:84-118`) | the pin | no: the head's lines; the pin's `:85-119` | both named, each with its sha |
| `docs/lanes/fix-843-removals.md` R16 (the pin `:57-74`) | the pin | no: `:58-74` | `:58-74`, `MAX_TAGS` at `:12` |
| `CHANGELOG.md:18` (`kvStoreTokenValidation.ts:33`) | the pin | no: `:34` | `:34`, `:96-98` at the pin |
| `CHANGELOG.md:40` (refuses at `:33`) | the pin | no: `:34` | `:34` |
| `docs/lanes/fix-843-removals.md`, the third fold's paragraph after its table (`:33`, `:96-98`) | the head (the table's convention) | yes at the head, read as the pin's elsewhere | the pin's `:34` and `:97-98`, the head's named |
| the third fold's table rows R03 to R19 (`:94` to `:116`, `PushDropValidation.ts`, `KeyDeriver.ts:470-511`) | the head; the derivation and `PushDropValidation.ts` the pin (unchanged at the head) | yes | none |
| `src/kvstore/token_validation.rs:2,19,73,83,115`, `src/kvstore/token_edges_tests.rs:19-20`, `src/kvstore/token_validation_tests.rs:95-99,143`, `tests/kvstore_key_bound_signature.rs:459`, `tests/CLAUDE.md:273`, `src/kvstore/CLAUDE.md:29`, `docs/lanes/fix-843-removals.md:99,101` | the pin | yes | none |
| `CHANGELOG.md:40` (`PushDropValidation.ts:72-74`, `kvStoreTokenValidation.ts:106-108`, `KeyDeriver.ts:470-511`) | the pin | yes (`:72-74` holds the envelope's compare at `:73-74`) | none |
| `CHANGELOG.md:38`, `CLAUDE.md:237,244`, `tests/CLAUDE.md:88`, `src/wallet/wire/CLAUDE.md:12` (the wallet wire, `OverlayAdminTokenTemplate.ts:164-165`, `Beef.ts:1286`, `ProtoWallet.ts:315`, `ContactsManager.ts:813-834,981-1001`, `completeBoundAction.ts:1044-1151,1111-1120`), carried lines this pull request edited for other words | the pin | yes, each read | none |
