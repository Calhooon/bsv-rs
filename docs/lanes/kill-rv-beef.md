# Kill lane: `src/wallet/substrates/result_values/beef.rs` (#603)

Base: `origin/beta` at `b681f1fa2ed040404e0cf834bf554f2237740b2d` (the worktree's start, equal
to `origin/beta`'s tip on the fetch). `beef.rs` is unchanged since the record's `2ff81a44`, so the
record's lines hold. The reference decides every kill: `ts-stack@edf6e03`
`packages/sdk/src/wallet/WalletResultBEEF.ts` (bundled alone with `bun build`, not in the package
index at the pin), recorded under Node v22.18.0 by `tests/support/wallet_result_beef_603.mjs`
into `tests/vectors/wallet_result_beef_603.json` (two runs byte-identical). BRC-100, the node,
go-sdk and the sibling Lean define none of these guards; no crate-contract pin.

## Before and after

| Run | Caught | Missed | Timeout | Unviable | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| Complete run of 2026-11-04 (`docs/census/mutants-2026-11-04.json`) | 51 | 17 | 0 | 13 | 75.00% |
| This lane, 41 shards | 63 | 5 | 0 | 13 | 92.65% |

The re-measure: `cargo mutants --jobs 1 --baseline=skip --timeout 240 --build-timeout 240` with
the arguments `mutation_args("substrates", "k/41", files=[beef.rs])` prints
(`.github/scripts/nightly_mutants.py:161-180`: `--lib` and the surface's 151 test targets),
`--shard k/41` for k from 0 to 40, one after another, each under ten minutes (33 s to 205 s). The
baseline was run once at `--shard 0/16` (22 s build, 137 s test, green) and that shard stopped
past ten minutes; it is not counted. The shards' outputs and logs are under
`/Volumes/Lanes/out/bsv-rs/kill-rv-beef/shard-*-41*`.

## Kills (`src/wallet/substrates/result_values/beef_603_tests.rs`)

Each test reads its case's hex from the vector, calls `parse` (and `subject`), and asserts the
reference's verdict, the transactions read and the subject's txid, never a message: every caller
of `parse` drops the error's content (`beef.rs:303`, `:315`, `action_binding.rs:53`,
`validation/client.rs:17-21`). Each mutant RED in a scratch copy with its own target, by a hand
patch of the one operator (`red-<line>-<col>-<op>.log` in the out folder).

| Mutant | Case (reference verdict) | Test |
| --- | --- | --- |
| `53:10` `>` to `==`, `>` to `>=` in `count` | `height_2_53` (`varInt is too large`, `:84`), `height_2_53_minus_1` (ok) | `a_bump_height_past_the_safe_integer_is_refused_and_at_it_read_603` |
| `88:36` `/` to `%` in `raw_transaction` | `outputs_remaining_multiple_of_9` (ok: 18 bytes after the output count) | `a_transaction_whose_output_bytes_are_a_multiple_of_nine_is_read_603` |
| `119:19` `>` to `==`, `>` to `>=` in `bump` | `level_count_half_remaining` (ok: one duplicate leaf, three bytes left, self-paired at `:224-225`) | `a_level_count_equal_to_half_the_bytes_left_is_read_603` |
| `126:23` `>` to `==`, `>` to `>=` in `bump` | `offset_at_level_max` (ok: level 1 at `0x7fffffff`, `:257`) | `a_leaf_at_its_levels_maximum_offset_is_read_603` |
| `126:46` `>>` to `<<`, `126:56` `\|\|` to `&&` in `bump` | `offset_past_level_max` (`Invalid Merkle Path offset`, `:259`) | `a_leaf_past_its_levels_maximum_offset_is_refused_603` |
| `247:9` body to `None`, `252:16` `!` deleted, `271:21` `==` to `!=` in `Envelope::partial_atomic_subject` | `atomic_closed_expected_parent` (strict and partial atomic both X, `:389-428`) | `a_closed_atomic_subject_wins_over_the_expected_parent_603` (`subject(Some(P))` is X; `subject(None)` X, the control) |

All twelve caught in the re-measure too.

## Equivalent candidates (named, not declared)

Five survivors, each an early refusal of a count the bytes cannot hold; no capacity is reserved
from the count, so the loop's next read fails on the same input and only which `Err` `parse`
returns changes, which no caller reads. Not written to `.cargo/mutants.toml`; three reads judge
them.

- `74:36` `/` to `*` in `raw_transaction`: an input is at least 41 bytes (32 + 4 + 1 + 4).
- `88:36` `/` to `*` in `raw_transaction`: an output is at least 9 bytes (8 + 1).
- `119:40` `/` to `*` in `bump`: a leaf is at least 2 bytes (offset and flags).
- `165:15` `>` to `==` and `>` to `>=` in `parse`: a BUMP is at least 37 bytes; a count equal to
  the bytes left (at least 1) cannot be met, and a count of 0 with nothing left fails at the
  transaction count's read (`:172`).

On wasm32 `remaining * 41` could wrap past about 104 MiB; mutants run native.

## Records

`docs/ratchets.json` `mutation_floors` untouched; the next complete run records the score.
Nothing under `src/script/` or `src/transaction/` changes, so the conformance and sibling-harness
steps do not apply.
