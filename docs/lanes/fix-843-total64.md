# Lane fix-843-total64: a listOutputs total is 64-bit (#843, pull request #1039)

The lane's own record was not written on its branch (the rule read's residual risk); the change, its pins and its parity note are in the `CHANGELOG.md` entry of #843, the listOutputs total. This file holds the fold of the three reads.

## The fold of the three reads (lane fix-843-total64-fold)

Head judged: `0060bdf6`. Verdicts: the cold read MERGE, the rule read ACCEPT, the strength read FIX (the two balance sweeps of `tests/wallet_list_outputs_total64_843.rs` lacked a total of 0; the code needs no change).

Readers' commits taken (documents alone): `758c4d0c` (`src/wallet/wire/CLAUDE.md`, three stale sentences) and `5a147384` (`src/wallet/substrates/CLAUDE.md:28`, the `normalize_numbers` guard's equivalence).

The cells added, each RED on a scratch copy of the tip with one line of `src/wallet/substrates/result_values/lists.rs` changed, then green (the file stays at 11 tests):

| Cell | Plant | RED |
|---|---|---|
| a balance of 0 through the binary wire, both baskets | `n >= 0.0` to `n > 0.0` | `a_balance_past_two_to_the_32_crosses_the_binary_wire_whole_843` |
| a balance of 0 in JSON, both baskets | the same plant | `a_balance_past_two_to_the_32_is_read_from_json_843` |
| a JSON balance written `-0`, read as 0 | `n >= 0.0` to `n.is_sign_positive()` | `a_balance_past_two_to_the_32_is_read_from_json_843` |
| a balance answer with `"BEEF": null`, refused (the reference's `!== undefined`) | the BEEF test to a member other than `null` | `a_balance_answer_with_outputs_or_a_beef_is_refused_in_json_843` |

Not pinned, with the reason:

- A JSON balance written `1e2`: the planted `integer_token` without `'e'` (`raw_tree.rs:471`) stays green, `boundary::normalize_numbers` reading the float on the fallback; no one-line change fails the cell, so it is not added. `-0` is covered the same way; both are named together, with the mechanism, in the second fold's section below.
- `LocalKVStore::count`'s `usize::try_from` (`src/kvstore/local.rs:361`): `as usize` is caught on a 32-bit target alone; no CI step runs that test on wasm32.
- `src/wallet/wire/mod.rs:517`, `map_or(true)` to `map_or(false)`: equivalent, no target has a page length a `u64` cannot hold.
- A balance query through `WalletClient`: it forwards unvalidated (`src/wallet/client.rs:380`); a pin would hold the forwarding, not the rule.
- The truncated balance varints assert a refusal, not its variant; the reader's refusal is every varint's, pinned where the reader is.

## The second fold (lane fix-843-total64-fold2): every spelling against the reference's answers, and a mutation sweep

Head judged: `5a34e171`. The re-read (FIX 0.7) planted six changes on lines of this pull request, of which five passed the suite (a zero balance refused only under a `limit`; `0.0` refused; `-0.0` refused; a `"BEEF": {}` and a `"BEEF": ""` accepted), and the sixth (the `raw_tree.rs` `-0` guard removed) passed too. The class is closed by two machines, not by more single cells.

**The recording.** `tests/vectors/list_outputs_balance_843.json`, written by `tests/support/list_outputs_balance_843.mjs`: the reference's own `HTTPWalletJSON.listOutputs` at `ts-stack@11faa7d16` (`git archive` of `packages/sdk`, `bun build`), under Node v22.18.0 with an injected fetch, two runs byte-identical. 248 cells: the two balance baskets (`balance default`, `p color balance aa`), each with no `limit` and with `limit: 10`, times 62 bodies: 42 spellings of `totalOutputs` (every zero, `-0`, `0.0`, `-0.0`, `0e5`, `-0E-3`; `1e2`, `1E2`, `1e+2`, `1.5e1`, `100e-2`, `100.0`, `100.000`; negatives, fractions, `1e-7`; 2^32 - 1, 2^32, 2^32 written `.0`, 2^53 - 1 to 2^53 + 2, 2^64 - 2048, 2^64 - 1, 2^64, 2^64 in exponent form, 2^65, `1e30`, `1e400`; a string of digits, the empty string, `null`, `true`, `false`, `[]`, `[5]`, `{}`, absent), 9 of `outputs` (empty, one output, absent, `null`, `{}`, `""`, `0`, `true`, `[null]`) and 11 of `BEEF` (absent, `null`, `[1]`, `[]`, `{}`, `{"0":1}`, `""`, `"AQ=="`, `0`, `true`, `false`). Each cell holds the reference's answer: accepted with the total it holds (its exact double, in decimal), or refused with its words.

**The replay.** `every_spelling_of_a_balance_answer_is_judged_as_the_reference_judges_it_843` (`tests/wallet_list_outputs_total64_843.rs`) serves each body from one `wiremock` host and reads it through `HttpWalletJson::list_outputs`: 224 cells answered as the reference answers them (each refusal in its words, each acceptance the same total), 24 stated, none fixed in the reader (no cell disagreed unstated). The 24 are six bodies at the four basket and request shapes, the CHANGELOG's stated cell: `9007199254740993` and `18446744073709551615` held exactly here, the reference's Number rounded (the test asks that both are one double); `18446744073709551616`, `1.8446744073709552e19`, `36893488147419103232` and `1e30` refused at the typed read in serde's words (`invalid type`) where the reference's Number carries them.

**The bound.** The cells hold every member the balance reader judges (`totalOutputs`, `outputs`, `BEEF`) in the spellings above, on the HTTP JSON substrate, for the two balance baskets with and without a `limit`. They do not hold: another request member (only `basket` decides a balance query, `limit` stands for the rest), a balance query told by another basket (the basket rule is the unit `a_balance_basket_is_told_by_the_reference_pattern_843`), the binary wire (its varint is the frame's one spelling, pinned by the file's wire tests), members the balance reader does not read (an extra member is ignored on both sides, unrecorded), or a spelling outside the table (a number with leading zeros or a leading `+` is no JSON, refused by both readers' grammar).

**Two spellings covered by another normalizer.** `1e2` and `-0`: serde_json reads either as a float, the typed `u64` read refuses it and the answer is read again from the raw tree, where `raw_tree::integer_token` rewrites an integral token to its integer and `boundary::normalize_numbers` rewrites every integral float to its integer, so either alone makes it 100 or 0. So removing the `-0` guard of `integer_token` (`raw_tree.rs:471`) or its `'e'` changes no answer and no one-line plant fails: stated. Both removed together (the guard and `normalize_numbers`' float arm) the replay goes RED, with `a_balance_past_two_to_the_32_is_read_from_json_843` (the `-0` cell), on a scratch copy of the tip.

**The six plants of the re-read, planted again by hand on a scratch copy of this fold** (each alone, the file `tests/wallet_list_outputs_total64_843.rs` run):

| Plant | Caught by |
|---|---|
| Z1: a zero balance refused only when the request carries a `limit` | the replay (the `limit: 10` cells of `totalOutputs_zero`) |
| Z2: `0.0` refused | the replay |
| M2: `-0.0` refused | the replay |
| B1: `"BEEF": {}` accepted | the replay |
| B2: a string `BEEF` accepted | the replay |
| M1: the `-0` guard of `integer_token` removed | stated: covered by `normalize_numbers`, above |

**The mutation sweep.** `cargo mutants` 27.1.0 (the nightly's `CARGO_MUTANTS_VERSION`), `--jobs 1`, `--in-diff` of `git diff origin/beta...HEAD -- src` (the lines this pull request changes) under `--features full,http`, nine shards each under ten minutes, the tests `--lib` and the 17 integration files that read the changed functions (`wallet_list_outputs_total64_843`, `kvstore_local_total64_843`, `kvstore_local_empty_page_479`, `kvstore_local_error_470`, `kvstore_local_rounds_483`, `kvstore_integration_tests`, `wallet_http_json_pending_432`, `wallet_wire_flags_1002`, `wire_u32_field_bounds_tests`, `wallet_wire_bounds_473`, `wallet_http_json_result_values_408`, `wallet_wire_result_validation_487`, `contacts_wallet_failures`, `registry_token_fields_543`, `wire_method_roundtrip_tests`, `wallet_wire_discovery_validation_495`, `wallet_wire_result_kill_603`). The functions: `is_balance_query`, `assert_page_count`, `LocalKVStore::count`, `read_actions_page`, `read_outputs_page`, `parse_discovery_result`, `WalletWireTransceiver::list_outputs` and `list_certificates`, `set_internal`, `remove_internal`, `LookupValueResult::found`, `count_of`, `get_outputs`, `lookup_current`, `request_fields`, `balance`, `outputs`, `<ListOutputsResult as WireResult>::check`. 51 mutants: 39 caught, 8 unviable, 1 timeout, 3 missed.

| Mutant | Fate |
|---|---|
| `local_lookup.rs:101:37` `>` to `>=` (a total of exactly 10,000 refused) | caught since this fold by `a_listing_at_the_stores_ten_thousand_passes_the_list_check_843` (`tests/kvstore_local_total64_843.rs`) |
| `local_lookup.rs:102:25` `>` to `==` (a page of exactly 10,000 refused) | caught since this fold, the same test |
| `local_lookup.rs:102:25` `>` to `>=` | caught since this fold, the same test |
| `local_actions.rs:146:47` `==` to `!=` in `remove_internal` (timeout) | stated: the removal loop breaks only on a page short of its total, so a complete page loops for ever; the tool's timeout is its detection |

The three missed re-run against the new test: caught (with `101:37` `==`, caught before). The test asks the reference's own edge (`LocalKVStore.ts:193-198` at `edf6e03`: `> MAX_LOCAL_OUTPUTS` for the total and the page): a total of 10,000 passes the list check and reaches #479's refusal, 10,001 is refused at it; a page of 10,000 outputs passes and reaches the BEEF's refusal, 10,001 is refused at it. The third clause (`returned > 10,000`) is implied by the first two (a total at least the page's length and at most 10,000); its deletion is not a mutant the tool makes.
