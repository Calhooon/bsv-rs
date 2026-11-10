# Lane fix-93-l1: the cached root walk moves to `merkle_path_walk.rs` (#93 P0)

Started from `4e57b23f53dcf271ed19a34a22c1aeab66fd6789`, which was `origin/beta`'s tip
when the lane opened (2026-11-09). This is a refactor: no fixture, verdict, error text or
public item changes.

## The move

- Before: `src/transaction/merkle_path.rs:523-755` (`SCAN_MAX`, `Node`, `RootWalker` and
  its `impl`, `hash_pair`), 1,462 lines in the file.
- After: `src/transaction/merkle_path_walk.rs:12-244`, the same 233 lines, behind a module
  doc and its `use` lines (`:1-10`). The file is 244 lines; `merkle_path.rs` is 1,230.
- Lines that are not part of the moved block: the module doc and the four `use` lines in the
  new file; five `pub(super)` tokens (`RootWalker`, `new`, `shared`, `root_from`,
  `hash_pair`); in `merkle_path.rs` `use super::merkle_path_walk::RootWalker;`, `sha256d`
  dropped from the primitives import (clippy: unused), and
  `use super::super::merkle_path_walk::hash_pair;` inside `linear_root_equivalence_tests`;
  `mod merkle_path_walk;` in `src/transaction/mod.rs`. A line-by-line comparison of the
  removed block against the new file's body finds those five token edits and nothing else.

## Proof it stayed identical

| What | Base (scratch copy of `4e57b23f`, its own target) | Tip |
|---|---|---|
| `cargo test --features "full,http" --lib transaction::merkle_path` | 20 passed | 20 passed |
| `--test merkle_path_lone_leaf --test merkle_path_two_readers_agree --test merkle_path_even_offset_duplicate --test merkle_path_641 --test merkle_path_649 --test merkle_path_cost --test fixtures_replay` | 1+6+10+5+2+6+5 = 35 passed | 35 passed |
| `--test transaction_coinbase_depth_734` | 8 passed | 8 passed |
| `cargo mutants --list` (base: `merkle_path.rs`; tip: both files; `--no-config`) | 96 | 96 (28 in `merkle_path_walk.rs`), the same texts with `file:line:col` removed; the walker's mutants' line is the base's minus 511, the rest plus 1 (the added `use` line), columns unchanged |
| `nightly_mutants.mutation_args('merkle','0/1')` | | only `--file src/transaction/merkle_path_walk.rs` added |

Conformance at the tip (`BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance`):
`conformance_scripts` `total=5116 run=4120 passed=4109 unsupported=959 skipped=37
known_failures=11 failures=0 panics=0`; `conformance_beef` 4 passed, 0 failures in every class.

The sibling's harness (`~/bsv/bsv-script-lean` at `5dc337e1`, archived to scratch, never
edited): `harness/Cargo.toml:32` replaced with a `path =` to the base copy and then to this
tree, `cargo update -p bsv-rs` in each (the two lockfiles identical), `harness/run --impl
bsv-rs --corpus seed --spec recorded`: GREEN on both. `diff -r` of the `bsv-rs/` reports
differs only in `manifest.json`'s `corpus` member (the two scratch copies' paths), and
`summary.txt` only in the timestamp and the `--out` path.

## The mutation surface

`SURFACES["merkle"]` names both files; `is_gate_path` names `merkle_path_walk.rs` exactly
(not a glob, so `merkle_path_extra.rs` stays outside). RED before the change, under `-k
merkle_walk`: `AssertionError: 'src/transaction/merkle_path_walk.rs' not found in
['src/transaction/merkle_path.rs']`; green after. The three `.cargo/mutants.toml` entries and
their comment are re-keyed to `merkle_path_walk.rs:141:27`, `:141:33` and `73:13`;
`mutants_entries.py` passes (28 entries, 1,235 mutants listed).

## Departures from the brief

- `mutants_record.py`'s two floor sentences are unchanged: the writer rewrites the records
  before it byte for byte, and `test_a_record_before_791_is_rewritten_byte_for_byte_791`
  fails with the new file named there (the census `mutants-2026-11-04.md`). Naming the file
  in future records only would need a dated branch in the writer; left to the captain.
- No ratchet record (as the brief says): `tools/ratchet/run --check --against 4e57b23f`
  passes with `merkle_path.rs` measured at 1,230 against the recorded 1,463, and
  `merkle_path_walk.rs` at 244, under 800. The `--record` is the captain's, in its own commit.
