# One merged integration binary against its parts (#693, speed loop three)

A measurement row of loop three (`docs/lanes/ci-speed-3.md`), opening from
#691's evidence read: about 0.49 s of fixed cost per integration binary on
this host (a least-squares fit over the 283 in one contended build) and
0.19 s to 0.26 s of it per binary on CI's 61 s to 83 s window. Nothing is
restructured here: the merged binary lived in a scratch copy and is gone.

Base: `origin/beta` at `c46a3b29`. Host: the Studio (macOS, Darwin 25.6.0,
Apple's linker), rustc 1.95.0, `CARGO_BUILD_JOBS=2` (swap above half), the
Test Suite's environment as #691 measured it (`RUSTFLAGS=-Dwarnings`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`), features `full,http`, a `git archive` of the
base under `$TMPDIR` with its own target dir under `~/bsv/targets`. The
one-minute load is quoted before each sample; it read 4.70 to 6.81 over the
lane. Logs, the timings HTML and the scratch scripts are under
`/Volumes/Lanes/out/bsv-rs/ci-merged-binary/`. At this base the tree holds
286 `tests/*.rs` binaries (the 283 of #691 and three since).

## The family

The ten `tests/script_*witness*.rs` files: `script_flags_witnesses`,
`script_int64_fold_witness`, `script_int64_operand_witness`,
`script_low_s_order_witness`, `script_num_length_witness`,
`script_residual_witnesses`, `script_shift_count_witness`,
`script_sighash_dispatch_witness`, `script_stack_memory_witness`,
`script_undefined_hashtype_witness` (2,936 lines, 100 tests). Why: every
one has the feature gate `default` and the Modules cell `` `primitives`,
`script` `` in #706's table (`origin/lane/fix-706:tests/CLAUDE.md`), so the
reach rule gives each the same answer for a library change; none declares
a module, reads a file or carries a `#![cfg]`; and the family holds both
the smallest binary of the set (`script_low_s_order_witness`, 83 lines, 3
tests) and the heaviest run (`script_stack_memory_witness`, 28 tests,
about 2.9 s), so the reach rule's loss is measured at both ends. The
`wallet_wire_*` family has eight files over mixed cells.

The merged binary, `tests/script_witness_merged.rs` in the scratch copy: a
`//!` line and ten `#[path = "<part>.rs"] mod <part>;` declarations. No part
needed an edit: each part's `//!` and `#![allow(...)]` are a module's inner
attributes, and the helpers every part defines (`run`, `check`, `spend`,
`heavy`) stay in their own modules. It builds under `-Dwarnings` with no
warning and runs the same 100 tests (the parts' sum: 9, 15, 8, 3, 4, 11, 9,
6, 28, 7).

## The figures

Warm-up before (a): `cargo build --features full,http --lib` (46.3 s) and
`cargo test --features full,http --no-run --test chain_encoding` (34.5 s),
which build the library and every dev-dependency, so (a) is the binaries'
own compile and link. (The brief's warm-up, `--tests`, would have built the
parts themselves.) A second cold sample is a `touch` of the files: with
`CARGO_INCREMENTAL=0` that recompiles and relinks each whole.

| Measure | Command | Parts (ten binaries) | Merged (one) | Load |
| --- | --- | ---: | ---: | --- |
| (a) cold build, wall | `cargo test --features full,http --no-run --timings $PARTS` / `--test script_witness_merged` | 1.87, 1.77 s | 0.64, 0.61 s | 5.77, 4.96 / 4.96, 4.96 |
| (a) unit time (`--timings`) | the units table | 3.00, 3.10 s (0.26 to 0.41 each) | 0.51, 0.48 s | |
| (b) one-line change in `script_low_s_order_witness.rs`, wall | the same, after `echo "// one-line change" >>` | 0.39, 0.36 s (that unit 0.26, 0.24) | 0.63, 0.62 s (0.50, 0.49) | 5.86 |
| (c) run, wall | `cargo test --features full,http $PARTS` / `--test script_witness_merged` | 5.68, 3.23, 3.19 s | 3.28, 3.10 s | 6.81, 6.38, 5.69 / 6.38, 6.19 |
| (c) tests; libtest seconds | `test result:` lines | 100; 3.01, 3.03, 2.98 (`script_stack_memory_witness` 2.91, 2.93, 2.88 of them) | 100; 2.91, 2.94 | |
| (c) one part alone, wall | `--test script_low_s_order_witness`; `--test script_stack_memory_witness` | 0.16, 0.15 s (3 tests); 3.11, 3.11 s (28) | | 4.70 |
| (d) rustc time, sequential | `RUSTC_BOOTSTRAP=1 cargo rustc --features full,http --profile test --test <t> -- -Z time-passes`, each after a `touch` | 2.770 s summed (0.249 to 0.358 each) | 0.537 s | 5.62 / 5.68 |
| (d) of it `link` | the same, the `link` pass | 1.510 s summed (0.141 to 0.163 each) | 0.170 s | |

`--timings` gives no link column for a test unit (its `sections` are
empty), so (d)'s link is rustc's own `-Z time-passes` (`run_linker` 0.113 to
0.130 s of each `link`). The parts' run sample of 5.68 s is a third larger
than the other two, so a third sample was taken (3.19 s); the excess sits
outside libtest's own seconds (3.01 against 3.03), on the opening run of ten
new executables. That macOS checks a new executable on its opening launch is
the likely cause, not verified; a Linux runner does not pay it.

Per binary removed, from this family (nine removed):

| Reading | Parts less merged | Per binary removed |
| --- | ---: | ---: |
| unit time, `--timings`, mean of two | 3.05 less 0.495 = 2.56 s | 0.28 s |
| rustc time, `-Z time-passes` | 2.770 less 0.537 = 2.23 s | 0.25 s |
| of it the link | 1.510 less 0.170 = 1.34 s | 0.15 s |
| wall at two jobs | 1.82 less 0.625 = 1.20 s | 0.13 s |

The two readings agree: each part costs about 0.25 s fixed (60 percent of it
the link) and the ten parts' code about 0.29 s together, which is the merged
binary's 0.54 s. This is lower than #691's 0.49 s fit, which was read from
one build of all 283 binaries at two jobs on `full,http,websocket`, each
unit stretched by the others beside it; the merged binary saves the fixed
part only, whichever figure is used.

## The reach rule's loss

`affected_tests.py`'s `reach()` on two scratch layouts of the base: the
base itself, and a copy with the ten parts moved to `tests/script_witness/`
(no longer binaries), the merged binary declaring them by
`#[path = "script_witness/<part>.rs"]`, and their ten `tests/CLAUDE.md`
rows replaced by one row naming `script_witness_merged.rs`
(`reach_driver.py`, `reach.txt`). The plan's `module_sources` follows the
`#[path]` declarations, so a part's change reaches the merged binary.

| Changed file | Base: reached (the family's parts) | Merged layout: reached (the merged binary) |
| --- | --- | --- |
| `src/script/spend/mod.rs` | 229 (10 of 10) | 220 (yes) |
| `src/primitives/hash.rs` | 275 (10 of 10) | 266 (yes) |
| `src/transaction/beef.rs` | 220 (0 of 10) | 220 (no) |
| `tests/script_low_s_order_witness.rs` | 2 (1: itself) | 2 (yes, whole) |
| `tests/script_stack_memory_witness.rs` | 2 (1: itself) | 2 (yes, whole) |
| `tests/CLAUDE.md`, the low-S row edited | 2 (1) | 2 (yes, whole) |

- **A library change:** no loss. A one-module pull request (`src/script/`,
  229 binaries reached here, #684's plan read 228) already reaches all ten
  parts, so the merged binary runs the same 100 tests: none of the 229
  becomes a whole-binary run it was not already. This holds by the rule's
  construction for any group whose `uses` sets (the `bsv_rs::` paths, the
  re-exports and the row's module names) are equal; #706's equal cells are
  close to that but not the same thing (`row_modules` still reads a
  description's `src/<m>/` paths, which the cell ignores), so each group's
  equality is the plan's to show, as it showed here.
- **A test-only change to one part** (its file, its row, a file only it
  names): the merged binary runs whole. Run: 3.10 to 3.28 s against the
  low-S part's 0.15 s, about 3.0 s lost; against the stack memory part's
  3.11 s, nothing lost. Build: 0.62 s against the part's 0.37 s, 0.25 s
  lost. The CI figure is nextest's (a process per test, four threads) and is
  not measured here (no nextest on this host): the merged binary's test
  seconds over four, bounded by its slowest test.
- **The saving against it:** every build that compiles the family (every
  library pull request reaching `script` or `primitives`, every push run)
  saves the nine binaries' fixed cost: 1.2 s of wall here at two jobs; by
  #691's CI figures 9 times 0.19 to 0.26 s, 1.7 to 2.3 s of a build.

## The extrapolation (labelled: projections from one family, not results)

Groups from #706's table (`families.py`, `families.txt`): the 286 binaries
by their (feature gate, Modules cell) pair fall into 83 groups, 35 of them
with more than one binary (238 binaries; the largest `default` /
`primitives`, `script` with 31, then `auth` / `auth`, `primitives`,
`wallet` with 28, `transaction` / `primitives`, `script`, `transaction`
with 19); within those, the stem's leading word and the cell together give
45 families of more than one (219 binaries, four of them of eight to twelve
files).

| Scope | Binaries removed | This host (0.25 to 0.28 s of unit time each) | #691's local fit (0.49 s) | CI, the fixed part (#691's 0.19 to 0.26 s of wall each; the low bound the fixed 0.19 s, not this host's 0.13 s) | The reach rule's loss |
| --- | ---: | ---: | ---: | ---: | --- |
| this family | 9 | 2.2 to 2.5 s (1.2 s of wall measured) | 4.4 s | 1.7 to 2.3 s | none on a library change; a test-only change to one part runs the ten (about 3 s here) |
| the 45 prefix-and-cell families | 174 | 44 to 49 s | 85 s | 33 to 45 s | none on a library change where the plan shows equal reach; a test-only change runs its family |
| the 35 equal-cell groups | 203 | 51 to 57 s | 99 s | 39 to 53 s | as above, the group the size of the run (up to 31 binaries) |
| one binary for the suite | 285 | 71 to 80 s | 140 s | 54 to 74 s | every pull request that reaches a binary runs the whole suite: a `src/script/` change 286 binaries' tests where it ran 229, a test-only change the whole run (72 s on #691's hit) where it ran one |

The costs beside the seconds:

- **The per-file isolation the rows record.** A compile error in one part
  fails the merged binary; a file's own `#![cfg]` gate becomes a module
  attribute (none in this family); under `cargo test` the parts share one
  process (`script_stack_memory_witness`'s `heavy()` mutex serializes its
  large rows among themselves, no longer apart from the other 72 tests;
  under nextest a test keeps its own process, so CI is unchanged).
- **The rows.** Ten rows become one shared row with a part per file
  (#706's shared-row form), and the moved files' references move with them:
  `docs/ARCHITECTURE.md` and the comments of
  `tests/script_shift_count_int_max_383.rs` and
  `tests/script_splice_position_reader_382.rs` name these files by path;
  `tests/arch_tests_claude_rows_name_modules_706.rs` and the #146 guard
  read the `tests/*.rs` set.
- **The mutation oracle's selection.** It names binaries (`direct`, #685):
  for an equal-cell group every part is selected already for a mutant of its
  modules, so a survivor runs the same tests; for a merge across unequal
  cells, every mutant reaching one part runs the whole merged binary.

## Decision (for the keeper)

Merge only where the gate and the Modules cell are equal and the plan shows
every part reached alike (as it did for this family): there a library pull
request loses nothing and every build saves about 0.25 s of rustc per binary
removed (0.15 s of it the link), 39 to 53 s of a CI build over the 35
groups by #691's figures; a test-only pull request pays its group's run.
Merge nothing across unequal cells, and never the whole suite (every pull
request would run all 286 binaries' tests). The row opens on those figures
if the keeper wants the 39 to 53 s; the move is one group a landing, each
with its plan diff and its run time measured.
