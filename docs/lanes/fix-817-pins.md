# Lane fix-817-pins: four test pins of the transaction bucket (#817)

Started from `cb950611` (`origin/beta`). One commit on `lane/fix-817-pins`, not pushed. No file under `src/` is changed; `src/transaction/beef_stream*` and its tests are not touched.

## The four lines

| Line | What had no witness | The pin | RED (a scratch copy of the tip, the one fault planted) |
|---|---|---|---|
| the held-entry rule | `merge_beef` leaving an entry the target holds raw or parsed as it is (`beef/merge_entry.rs`, `holds_a_transaction` then return), on the sweep of every BEEF | `tests/beef_merge_beef_txid_621.rs`: `a_held_raw_entry_keeps_the_index_of_its_own_bump_on_every_beef_817`, `a_held_parsed_entry_keeps_its_source_link_on_every_beef_817` | the return removed: 2 of 2 (`left: Some(1)`, `right: Some(0)`; the link gone) |
| the raw door's mark | `store_raw_entry`'s `mark_mutated` after a read from bytes | `tests/beef_merge_beef_held_621.rs`: `a_source_read_then_given_a_raw_transaction_is_merged_in_its_sorted_order_817` | the mark removed: X, T, Y for Y, T, X; the same with the `needs_sort` half kept |
| a duplicate above level 0 | an odd-length text paired with itself in a computed node | `tests/merkle_path_hash_pair_817.rs`: `an_odd_length_child_duplicated_into_a_computed_node_is_paired_as_the_reference_817`, the vector's fourteenth cell | that site padding each side alone: `8de60ca0...` for `b1633cc4...` |
| the unchecked index | `merge_raw_tx(raw, Some(n))` storing `n` as given, as the reference does | `tests/beef_merge_raw_tx_index_817.rs` (5 tests, six recorded cells) | the BUMPs scanned over a given index: 2 of 5; an index at or past the count refused: 2 of 5 |

## What the premise said and what the tip showed

The lines were written from a read that ran no cargo. Checked on `cb950611`:

- The held-entry return sits at `merge_entry.rs:52-54` (cited as `:50-52`); `store_raw_entry` at `:100-105`, the mark at `:103` as cited.
- "The differential stayed green with the return removed" is no longer true of the tree: with the return removed `merge_beef_writes_the_bytes_the_per_entry_merge_writes_621` fails at `tests/vectors/beef_door_sync_817.json#16` (a BEEF two of whose BUMPs hold one txid, added by #817's door-sync vectors, so its held raw entry is rescanned to the later BUMP). One seed of 379 by accident of a vector; the two new tests tell it by construction on 225 and 133 BEEFs.
- "`mark_mutated` in the per-entry merge has no witness" holds for the 33 `tests/beef_*.rs` (the mark removed, every one green but the new test) and half holds for the unit tests: `transaction::beef::reference_603_tests::a_merge_after_a_serialization_sorts_again_wire_beef_023` fails with the mark removed (its `needs_sort` half). With `needs_sort` set by hand and `wire_order` left, `--lib transaction` is green (257 passed) and the new test RED: the `wire_order` half was the unpinned one.
- The thirteen `hash_pair` cells and the parity of the index door are as the lines say.

## The recordings

The bundle: `git -C ~/bsv/ts-stack archive edf6e03 packages/sdk`, `bun build mod.ts --target node --format esm`, run under Node v22.18.0. Before any change both older recorders were run against it and reproduced their vectors byte for byte (`transaction_fold_817.json`, `beef_merge_beef_held_621.json`).

- `tests/vectors/transaction_fold_817.json`: one cell appended by `tests/support/transaction_fold_817.mjs`; `diff` of the old and the new file is 43 added lines after the thirteenth cell and nothing else; two runs byte-identical (`cmp`). The cell holds no BEEF.
- `tests/vectors/beef_pins_817.json`, new, by `tests/support/beef_pins_817.mjs`; two runs byte-identical. It carries no BEEF: the reference's bytes are recorded as SHA-256 digests and each BEEF is rebuilt by this crate's writer from the steps, so the seed sweep (`tests/support/beef_seeds_817.rs`) reads nothing new and the censuses of `docs/lanes/fix-817.md` do not move (372 on this tip, `prepass_621_tests` and `beef_v1_txid_only_writer_817.rs`' `SWEPT`, both green in the gate). The alternative, a case added to `beef_merge_beef_held_621.json`, would have added three BEEF texts to the sweep and moved the pinned totals, one of them in a test module under `src/`.

## The reference's answers on the index door

| Cell | Held after `mergeRawTx` | `toBinary` | `fromString`, `fromBinaryStrict` | `verifyValid(true)` | This crate |
|---|---|---|---|---|---|
| one BUMP, index 5 | index 5 | written | read, index 5 | not valid | the same, bytes equal |
| one BUMP, index 1 | index 1 | written | read, index 1 | not valid | the same |
| no BUMP, index 0 | index 0 | written | read, index 0 | not valid | the same |
| a BUMP holding T, the transaction U, index 0 | index 0 | written | read, index 0 | not valid | the same |
| BUMPs of X and T, the transaction T, index 0 | index 0 (not rescanned to 1) | written | read, index 0 | not valid | the same |
| the same, index 1 | index 1 | written | read, index 1 | valid | the same |

No cell differs. go-sdk@2ca481c's `MergeRawTx` refuses an index outside its BUMPs (`transaction/beef.go:836-839`), read, not run.

## For the captain

- A check on the index is not built. If one is wanted it is a divergence from the reference to state (rules 1 and 13), and `tests/beef_merge_raw_tx_index_817.rs` is then the record of what changes.
