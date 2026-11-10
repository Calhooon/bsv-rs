# Kill lane: `src/wallet/substrates/result_values/raw_tree.rs` (#603)

Base: `origin/beta` at `b91c487d11c6c7cafd76945d178ec7fbe654c854` (the worktree opened there; the file
unchanged since `2ff81a44`, the complete run's commit). The reference is `ts-stack@edf6e03`'s
`HTTPWalletJSON` (`packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:318-335`: `assertSafeWalletJSONValue`,
`normalizeBRC100WalletByteFields`, `assertSafeWalletValue`, `validateWalletResult`), its snapshot budgets
(`WalletResultValidation.ts:215-219,664-743,765-831`) and byte forms (`BRC100ByteEncoding.ts:32-34`,
`WalletResultValidation.ts:524-621`). go-sdk@2ca481c's JSON substrate only unmarshals; BRC-100 was not needed.

## Why the survivors stood

`Snapshot::read` (`raw_tree.rs:159-208`) indexes the answer; `check` and `visit` (`:231-292`) apply the
budgets. The #432 budget cases (`row_3_getHeight_graph_edge`/`_over`, 499,997 and 500,001 `{}`) stop at the
1,000,000-node visit bound and never reach the 1,000,002-property one; no case carried a dense byte array past
the node bound, an index-keyed object outside the byte names, or an unsafe key under a byte name.
`normalized` (`:297-436`) runs only when the typed and the `Value` readings both fail
(`src/wallet/substrates/http_json/answer.rs:92-101`), and its one test, `tests/wallet_http_json_linear_432.rs`,
is in `COST_CHECKS`, so the night never reached `write_raw`, `enqueue`, `reference_edit` or `integer_token`.

## Sources

(a) The reference recorded by Node 22 (`tests/support/http_json_raw_tree_603.mjs`, the method of
`tests/support/http_json_result_values_408.mjs`: the bundle built from `git archive edf6e03 packages/sdk` with
`bun build`, the fetch injected, no listener) into `tests/vectors/http_json_raw_tree_603.json`: eleven cases,
each verdict as the case predicted. The large bodies are expansion recipes, `array` and `index_object`
(`{"0":item,..,"N-1":item}`), expanded alike by the recorder and the test.
(c) Two crate-contract pins, counted apart, in `src/wallet/substrates/result_values/raw_tree_tests.rs`
(declared by two lines appended at the end of `raw_tree.rs`; no survivor's line moved).

## Kills

Each RED on its mutant's own diff (`cargo mutants --list --diff`) applied to a scratch copy under
`$TMPDIR/kill-raw-tree/scratch` with its own target dir, then GREEN on the tree; the failing lines are in
`/Volumes/Lanes/out/bsv-rs/kill-raw-tree/red-<line>-<col>-<op>.log`.

| Case (test) | Source | Mutants killed |
| --- | --- | --- |
| C1 `a_dense_byte_array_past_the_node_limit_is_bytes_not_nodes` | a | 135:5 `false`, 136:34 `!=`, 211:9 `None`, 211:12 `!`, 215:13 arm, 275:75 `>` |
| C2 `an_integral_value_above_255_is_not_a_byte` | a | 136:41 `\|\|` |
| C3 `a_non_byte_array_one_property_past_the_budget_is_refused` | a | 245:42 `*`, 245:42 `-`, 246:55 `*` |
| C4 `an_index_keyed_object_outside_the_byte_names_counts_its_keys` | a | 220:37 `true`, 220:48 `\|\|`, 253:55 `*`, 447:5 `true` |
| C5 `an_escaped_quote_does_not_end_a_string` | a | 146:17 arm, 146:30 `*=` |
| C6 `a_historical_byte_object_is_written_as_an_array_on_the_raw_path` | a | 220:37 `false`, 220:51 `!`, 224:25 `!=`, 328:37 `false`, 447:5 `false` |
| C7 `a_byte_field_name_does_not_shield_an_unsafe_key` | a | 224:43 `\|\|` |
| C8 `nested_arrays_keep_their_brackets_on_the_raw_path` | a | 176:52 `*`, 328:37 `true`, 397:24 `-=` |
| C10 `a_trailing_bits_signable_reference_is_reencoded_on_the_raw_path` | a | 404:9 `()`, 431:43 `+` `/`, 433:26 `*` `-`, 376:44 `+` `/`, 379:44 `!=`, 379:68 `!=` |
| C11 `a_negative_zero_byte_is_written_as_zero_on_the_raw_path` | a | 471:14 `==` (serde reads `-0` as `-0.0`, no `u8`: `invalid type: floating point -0.0, expected u8`) |
| U1 `the_copied_byte_budget_is_judged_on_the_sum_crate_contract_pin_603` | c | 276:25 `*=`, 277:28 `==`, 277:28 `>=` |
| U2 `only_the_reference_token_is_replaced_crate_contract_pin_603` | c | 379:53 `\|\|` |

39 killed: 35 on (a), 4 on (c). U1 quotes `src/wallet/substrates/CLAUDE.md` R03 ("total copied bytes 256 MiB")
and `WalletResultValidation.ts:689-692`; HTTP cannot reach it (the 256 MiB body cap, `HTTPWalletJSON.ts:59`,
at two characters a byte). U2 quotes `raw_tree.rs:294-295`. Variants beside the brief's names were also RED
(135:5 `true` on C2, 176:52 `-`, 246:55 `-`, 276:25 `-=`); they were caught at the base already.

**The answer bound.** Under `397:24 -=` C8 panics (`attempt to subtract with overflow`), but C10 and C11 spin in
`write_raw`, allocating, and libtest waited on them, so tip shard 12 read the mutant as a timeout. Each
case now runs on a thread of its own with a current-thread runtime, the test waiting 20 s for the answer
(`ANSWER_BOUND`); the process exit ends a spinning thread. Under `397:24 -=` C11 fails at 20 s with 325 MB
resident; every honest case answers in milliseconds (the file runs in 1.7 s).

## Candidate

`328:48` (`&&` to `||` in `enqueue`): it writes a non-historical index-keyed byte object as an array. Every
member of `src/wallet/types.rs`, `types/linkage.rs`, `key_args.rs` and the substrate's own response structs
(`http_json.rs`, `http_json/key_requests.rs`) was listed: the maps are `IndexMap<String, String>` (an all-number
index object fails them as a sequence does, and R73, R77, R80 and R85 refuse it before `normalized`);
`Outpoint`'s visitor has `visit_str` and `visit_map`, no `visit_seq`, and every outpoint a result carries is
checked as a canonical string ahead of the typed read (R29, R55, R64, R72); no nested result struct reads a positional
sequence of numbers (each leads with a string, txid, key, bool or `Vec` field, or requires one after a number);
the flattened structs have no catch-all map; every raw byte member carries one of the seventeen names
(`tx`, `BEEF`, `beef`, `inputBEEF`, `competingBeef`, `signature`, `ciphertext`, `plaintext`, `hmac`,
`encryptedLinkage`, `encryptedLinkageProof`), so it is historical anyway; a root of index keys is refused by
its call's validator before `normalized`. None found: a candidate, not declared (three reads are the rule).

## Hangs

Re-run alone through `cargo mutants` with the oracle's selection, `--baseline=skip --timeout 60`
(`/Volumes/Lanes/out/bsv-rs/kill-raw-tree/hangs*/`), each the second timeout after the complete run's:

| Mutant | Spins on | Why |
| --- | --- | --- |
| 140:5 `token_end` to 1 | `{"height":1}` | every scalar sets the offset back to 1 |
| 143:17 `*=` | any string token | `end *= 1` never leaves the token's second byte |
| 146:30 `-=` | `{"version":"ab\"c"}` (C5) | the escape steps back onto the backslash |
| 152:17 `*=` | a scalar of two or more bytes (`10`, `true`) | `end *= 1` never advances |
| 181:28 `-=` | `[1,2]` | at a comma the offset steps back to the token before it, which steps forward to the comma |
| 181:28 `*=` | `{"height":1}` | the offset stays on the colon |

The inputs are read from the code, not each run alone. The brief named five; both `181:28` variants time
out here, where the complete run caught one. `140:5` with 0 is caught (30 s). No production bound:
`token_end` returns past `start` on every input and each loop advances.

Not run here: `397:24 *=` (`write_raw` pushes `,` forever once C8, C10 or C11 runs; excluded by
`--exclude-re 'raw_tree\.rs:397:24: replace \+= with \*='`), and `168:28 *=` on the base: on the tip it timed
out once in its shard (419 s; `offset *= 1` at a bracket pushes a frame per turn, an allocation without
bound), where the complete run caught it. Both are named for CI's #781 re-run.

## Re-measure

`$TMPDIR/kill-raw-tree/measure.sh` builds the nightly's arguments with
`nightly_mutants.mutation_args("substrates", ..., ["src/wallet/substrates/result_values/raw_tree.rs"])`
(`--lib` and the targets naming `wallet` less `COST_CHECKS` and `APART`, 151 at the base and 152 at the tip, the `test_skips("substrates")` skips),
drops `--locked` (no lockfile is committed) and adds `--jobs 1 --baseline=skip --timeout 390` (three times
the 129 s baseline test time of shard 0/12, the nightly's multiplier). The six hangs and `397:24 *=` are
excluded; the other 103 split into 24 round-robin shards (`list103.txt`), each run by exact name in one or two
pieces under ten minutes (`piece.sh`), base (a `git archive b91c487d` copy) and tip in the same partition.

| Tree | Caught | Missed | Timeout | Unviable | Not run |
| --- | ---: | ---: | ---: | ---: | --- |
| Base `b91c487d` | 59 | 40 | 0 | 3 | `168:28 *=` |
| Tip | 98 | 1 (`328:48`) | 1 (`168:28 *=`) | 3 | |
| Hangs, alone (tip) | | | 6 | | `397:24 *=` |

The base agrees with the record (61, 41, 5): the record's two more caught are `168:28 *=` and one `181:28`
variant, its 41st miss `397:24 *=`. Every base miss but `328:48` is caught on the tip (39). Score on the tip,
110 mutants, 107 viable: under #781 98 of 99, 99.0%, once `168:28 *=` times out again alone; 98 of 100, 98.0%,
counting it now; the record's way, every timeout in and `397:24 *=` counted as one, 98 of 107, 91.6%. The
base: 59 of 99, 59.6%, under #781. Tip shards 0 to 11 ran before the answer bound was added and 12 to 23 after it
(shard 12 re-run, 4 of 4 caught); the bound only adds a failure path, so a mutant caught before stays caught.
`docs/ratchets.json` stays the complete run's.
