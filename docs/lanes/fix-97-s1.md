# Lane fix-97-s1 (with fix-97-s1b): the node's oracle on every pull request into beta (#97, S1)

Started at `7df16cf6` (`origin/beta`, 2026-11-10). The earlier lane `fix-97-s1` built the
command (`bed36ce3`, cherry-picked here) and stopped BLOCKED on `crypto-00079`; the captain's
ruling on Q97.5 (under the owner's decision of 2026-11-10) split the check in two: the node's
verdicts with no waiver, this crate's words against a column this repository records.

## Sites

- `.github/scripts/sibling_harness.py`: `run` (stage, rewrite, stage `bsvrs_words`, drop the
  public edition's withheld entries, settle, harness, words, compare), `compare` (`verdicts_of`
  from the logs and the manifest, `reasons_of` from the words, `--record`), `summary`.
- `.github/scripts/sibling_words.rs`: the reader built in the scratch copy on the harness's own
  adapter (`engine::run_tx`, `run_tx_words`, `words_of`; `spec_words` transcribed from `run_diff`).
- `.github/scripts/test_sibling_harness.py`: 67 tests (34 before the fold, 56 before the second).
- `tests/sibling/column.json` (13,765 entries, nine corpora, `bsv-script-lean@1c051eae`) and
  `tests/sibling/CLAUDE.md`.
- `.github/workflows/ci.yml`: job `sibling`, no reach filter since the fold;
  `tests/arch_ci_pr_runs_the_required_set.rs`: `sibling` in `REQUIRED_ON_BETA`, and since the
  fold `the_sibling_job_judges_on_every_event_it_runs_on_with_no_reach_filter_97`, since the
  second fold `the_sibling_step_is_pinned_and_no_failure_of_it_is_absorbed_97`, since the third
  `the_sibling_job_and_what_it_inherits_are_pinned_whole_97` (`SIBLING_JOB`, `SIBLING_INHERITS`).

## The sibling

`Calgooon/bsv-script-lean` (the pin `5dc337e1`) is PRIVATE and archived (2026-10-27);
`Calhooon/bsv-script-lean` is PUBLIC, the sibling's home since then, its tip `1c051eae` the
export of `da684279` (a descendant of `5dc337e1`). At the two commits the nine corpora's files
are byte-identical but `gen/gen.jsonl` (150 entries withheld: `"tx": "WITHHELD: ..."`, which
the harness's own `run_diff` refuses, `a corpus entry must be well-formed`) and the corpus
manifests; the harness differs by a host-variable module, two withheld rule references and a
comment. The job checks out the public edition, no token; the withheld entries are dropped from
the staged copy and counted. Nothing is vendored: each withheld entry names its group in its
`tx` field, `d7-node-team-split` (58, the group `corpus/INDEX.md` names) or
`d8-node-team-discretion` (92).

## The runs (logs under `/Volumes/Lanes/out/bsv-rs/fix-97-s1b/runs/`)

- At the tip, public pin, `--corpus all`: harness `8 GREEN, 1 RED` (crypto: `0 unexplained
  divergences, 0 messages outside the table, 1 recorded bsv-rs verdicts disagreeing`); the
  command `VERDICTS: 13765 entries, 0 divergences`, `REASONS: 13765 equal, 0 differ`, GREEN.
- The 150 withheld entries are not judged by the job (the public edition carries their ids
  alone).
- Live RED 1 (`src/script/script.rs:193` `pos < length` to `pos <= length`, a scratch tree):
  exit 1, `VERDICTS: 13765 entries, 2 divergences`, `seed: UNEXPLAINED spec seed-000397
  (mutation/lock, rule mutation, version 2): spec invalid SCRIPT_ERR_BAD_OPCODE vs bsv-rs
  undecided Some("panic: index out of bounds: the len is 7 but the index is 7")` (and its
  `spec-mempool` twin), five counts moved, `REASONS: 13764 equal, 1 differ` naming seed-000397.
- Live RED 2 (PR #846's opening head `4b3fe10d`, its `src/primitives/` and `src/wallet/wire/mod.rs`
  applied to a scratch tree): exit 1, `VERDICTS: 13765 entries, 0 divergences`, `REASONS:
  13763 equal, 2 differ`: `crypto-00035 [rec/spec/mempool]: column invalid "The top stack
  element must be truthy after script evaluation."; run invalid "The signature format is
  invalid."` and `crypto-00077 [rec/spec/mempool]: column invalid "OP_CHECKSIG requires failing
  signatures to be empty."; run invalid "The signature format is invalid."`. The flipped
  verdict (`<zero-S sig> <key> OP_CHECKSIG OP_NOT`, version 2, post-Chronicle word) is in none
  of the nine corpora: no entry's verdict moved.

## The walls (Apple M5 Max, 18 cores, 36 GiB; cargo 1.95.0; `CARGO_BUILD_JOBS=4`)

The job's command (copy mode from a checkout at `1c051eae`, `--corpus all`, the committed
column), interleaved, load 5.9 to 6.2: cold (empty target) 18.54, 18.58, 18.65 s; warm 2.99,
3.46, 3.18 s; the crate rebuilt over cached dependencies (`touch src/script/mod.rs`) 10.92,
11.05, 11.16 s. A hosted runner (4 vCPU) is not measured here: its wall is the job's earliest
dispatch.

## RED before green, the unit tests

All 34 green on the tip; on `bed36ce3`'s script 31 error (the module lacks the parts). Each
new behaviour planted back in a scratch copy: the 0.7.0 words judged 3 RED, the unexplained
entry unnamed 1, the words not compared 4, the withheld entries kept 8, a log without a verdict
line 1 (logs `red-*.log`).

## The gate

`python3 -B -m unittest discover -s .github/scripts -p 'test_*.py'` 216 OK; `cargo fmt --check`
clean; `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo test --features
"full,http" --test 'arch_*'` 19 binaries, 95 passed (97 by the cold read's count, which is right:
the record miscounted); `rows_from_sources.py --check` 0 refusals;
`mutants_entries.py` PASS; `tools/ratchet/run --check --against 7df16cf6` pass; gitleaks over
the commit. No file under `src/` moved.

## The fold (#853's three reads of `4d81e9da`, 2026-11-10)

The reads: cold FIX 0.8, rule FIX 0.85, strength FIX 0.8; each found a way for the job to pass
without judging. The ruling it implements is zero divergences from the node, no waiver, so each
way is closed as a class.

- The readers' commits, cherry-picked in the order cold `5d6b3ea6`, rule `63111ae2`, strength
  `4d4bb25f`. The cold and rule reads both moved `main-in-beta`'s comment back above its job:
  the rule read's identical hunk applied as already present, one copy kept. In
  `tests/sibling/CLAUDE.md` the cold and strength reads worded the "a reason the code table does
  not carry" sentence differently: the strength read's (the later; it also names the adapter
  build stop) is kept, with the cold read's witness (`flow.rs:168`, 26 entries) folded into it,
  and the cold read's default-mode paragraph kept.
- No reach filter (cold: `src/lib.rs`, `build.rs`, no `Cargo.lock`; strength: a rename out of a
  listed path). The plan step, its `steps.plan.outputs.reached` conditions on six steps and the
  `SKIP sibling (not reached)` step are gone; the checkout no longer fetches the whole history
  (the plan alone read it). `the_sibling_job_judges_on_every_event_it_runs_on_with_no_reach_filter_97`
  refuses a step condition, a `needs:`, a job condition reading more than `github.event_name`,
  `github.base_ref` and `github.ref`, a `paths`/`paths-ignore` on the triggers and a `sibling`
  step without `sibling_harness.py run`, each shown on a mutated text. RED on `4d81e9da`'s
  `ci.yml` (`red-arch-base.log`): `a step of `sibling` carries a condition: `if:
  steps.plan.outputs.reached == 'true'`` five times and `!= 'true'` once. The job's step is
  measured at 46 s cold on GitHub (the cold read), the job 1m7s.
- The record path (rule): `--record` refuses a run with any rules row or abort witness, and at
  the column's own pin a run whose counts, corpus sha256, corpora or withheld counts differ from
  the column it replaces; a column carrying a rules row or an abort witness is exit 2 at load;
  compare is RED on every rules row of the run (the `want_rows - got_rows` arm, the strength
  read's `:515-516`, is removed: a column cannot carry a row, so a row the run lost cannot
  exist). The four wordings (the script's docstring, the manual's VERDICTS item, the CHANGELOG,
  the `ci.yml` comment) say an explained row is refused.
- Compare cannot pass uncompared (strength): a corpus of the run absent from the column's
  `corpora` or `words` is exit 2; an entry of the column absent from the run is RED by name (it
  was; now pinned).
- The note lookup strips the trailing colon (`entry: in the column, absent from the run` now
  prints its note); an uncaught exception is exit 2 with `sibling_harness: SETUP STOP: an error
  of the script itself: ...`, a line the step summary's grep carries.

RED (`/Volumes/Lanes/out/bsv-rs/fix-97-s1b-fold/`): the 56 tests over `4d81e9da`'s script, 12
tests RED, one ERROR (`red-python-base.log`); every surviving mutation the strength read
listed, planted in a scratch copy of the tip, RED (`red-mutations-tip.log`):

| Mutation | RED test |
|---|---|
| `:398` `>` to `>=` | `test_unexplained_divergences_each_named_print_no_more_line` |
| `:402-403` deleted | `test_messages_outside_the_table_the_manifest_does_not_name_are_counted` |
| `:490` `rules_pin` dropped | `test_another_rules_pin_is_2` |
| `COMPARED` less `agree_mempool`, `agree_block`, `undecided`, `aborts_as_witnesses` (each) | `test_each_compared_count_moved_is_1_naming_it` (the key's subtest), and the record pin or abort test |
| `:328` `not in (0, 1)` to `> 1` | `test_a_harness_killed_by_a_signal_is_2` |
| `:195` `cases-manifest.json` dropped | `test_a_cases_manifests_sha256_is_rewritten_for_the_staged_file` |
| `:184-187` non-JSON line raising | `test_a_corpus_line_that_is_not_json_is_kept` |
| `:289` deleted | `test_a_non_empty_out_is_2` |
| `:457-459` silent | `test_an_entry_in_the_column_absent_from_the_run_is_1_naming_it` |
| `:515-516` deleted | removed (above): unreachable once a column carries no row |
| `:528` colon kept | `test_a_note_is_printed_beside_an_entry_absent_from_the_run` |
| the top-level catch removed | `test_an_error_of_the_script_itself_is_2_with_a_setup_line` |

and the fold's own lines, each removed in turn: the record's explained refusal (2 RED), its pin
hold (4 subtests), the column's load check (2), the run's rules row in compare (1), the two
uncompared-corpus stops (1 each).

The runs: the job's command on the fold's tip against `Calhooon/bsv-script-lean@1c051eae`
(a fresh shallow fetch), `--corpus all`: GREEN, `VERDICTS: 13765 entries, 0 divergences`,
`REASONS: 13765 equal, 0 differ`, 18.7 s cold (`job-tip.log`); `--record` from that run at the
pin re-records the column byte for byte (the hold passes); the same command on `origin/beta`'s
tip `a42e8aac` (beta moved past `01946931`) with the fold's script and column: GREEN, 13,765 and
13,765 (`job-beta-a42e8aac.log`).

The gate after the fold: `python3 -B -m unittest discover -s .github/scripts -p 'test_*.py'`
238 OK (56 the sibling's); `cargo test --features "full,http" --test 'arch_*'` 19 binaries, 98
passed; actionlint clean on `ci.yml`.

## The second fold (#853's scoped re-reads of `fba88838`, 2026-11-10)

The reads: cold FIX 0.85, rule FIX 0.85. The judging and the record path held under every real
crate fault the cold read planted (five, each RED in compare and exit 2 under `--record`); what
was left was the same class: ways to end green without judging every entry. Rebased onto
`origin/beta` `842e5cc4` first (the CHANGELOG conflict keep-both, this entry at the top of
`[Unreleased]`).

- The readers' commits, cold `e669fa0c` then rule `2c793b18`. Both corrected the column's
  "every verdict the node's" for the 73 undecided pre-Genesis entries: in the CHANGELOG the rule
  read's sentence (the later, and true of the code) is kept with the cold read's "held at the
  pin" clause folded into it; in `tests/sibling/CLAUDE.md` the two paragraphs on the 73 are one,
  and the cold read's sentence on the arch guard's six unread commands is replaced by what the
  guard reads now.
- The arch guard reads the command (cold item 9, rule FIX-2 and FIX-3): the judging step equals
  `SIBLING_STEP` byte for byte, `continue-on-error` anywhere in the job and a `defaults:` on the
  job or the workflow refused; `shell: bash` is the runner's `bash --noprofile --norc -eo
  pipefail {0}`. The seven plants and a changed shell, each refused on the tip; against
  `sibling_refusals` of `fba88838` (`red-arch.log`): `refused=false` for each of the seven step
  plants and the changed shell, `errors=[]` for `continue-on-error` and `defaults:` on the job.
- A re-record at an unchanged pin is judged entry by entry (rule FIX-1): `held_at_the_pin` adds
  `verdicts_moved`, every entry's verdict under `rec`, `spec` and `mempool` against the column it
  replaces, at most 20 named then a count. Live on the tip's run: the column with `eras-00001`
  (undecided) and `eras-00002` (valid) swapped is refused, exit 2, both named, the column
  untouched (`job-record-flipped.log`).
- A run covers the column (rule FIX-2, FIX-4): a corpus the column carries that the run does
  not, and a corpus of the run's record its manifest lacks (or the other way), exit 2.
- The headline (cold): `VERDICTS:` counts an explained row among its divergences.
- Stated, not fixed (cold 8(c)): a refusal re-worded with no verdict moved is written by
  `--record`; the manual says a re-recorded column is a reviewed change of words, held beside a
  crate change by the next stage's file-class rule.

RED (`/Volumes/Lanes/out/bsv-rs/fix-97-s1b-fold2/`): the 67 tests over `fba88838`'s script, 10
FAIL (`red-fba88838.log`: the two decided/undecided and swapped flips, the two recorded-word
flips, the 20-then-count, the entry gone, the three coverage stops, the headline); each new
line removed in a scratch copy of the tip (`red-plants-python.log`): the per-entry check (6
RED), the check run at every pin (1: the other pin's record), the column coverage stop (1), the
record-in-manifest stop (1), the manifest-in-record stop (1), the headline's count (2).

The runs: the job's command on the tip against `bsv-script-lean@1c051eae` (`--rev`, the public
edition's commit, 150 `gen` entries withheld): GREEN, `VERDICTS: 13765 entries, 0 divergences`,
`REASONS: 13765 equal, 0 differ`, 18.1 s cold (`job-run.log`); `--record` from it re-records
the column byte for byte (`job-record.log`).

## The third fold (#853's scoped re-read of the second fold, `89d6e0df`, 2026-11-10)

The re-read confirmed the second fold by plants and live runs and said FIX 0.85 on one thing:
the guard pinned one step, so a step inserted before it, a job or workflow `env:` key, a job
`container:` or another action for the sibling's checkout turned the job green without
judging and passed every arch test. The reader's docs commit picked first (`3e7db787`), its
As-built sentence then rewritten to what the guard holds.

- The pin is the job: `SIBLING_JOB` is `ci.yml:874-948` byte for byte (the key line to the
  last line, a key behind a comment at the job's indent read inside it, the next job's
  preamble comments outside), `SIBLING_INHERITS` the workflow's `permissions:`,
  `concurrency:` and `env:` blocks byte for byte, `WORKFLOW_KEYS` the workflow-level keys (no
  `defaults:` anywhere in the file, none twice), and the context `sibling` the job's alone (a
  twin in ci.yml or a job named `sibling` in another workflow). The named rules of the earlier
  folds are kept beside the pin; `SIBLING_STEP` is gone, inside `SIBLING_JOB`. A failure is one
  line: `ci.yml line N`, then `expected:` and `found:`, each quoted.
- The plants (`/Volumes/Lanes/out/bsv-rs/fix-97-s1b-fold3/plants.py`, `plants.txt`): each alone
  in a scratch copy of the tip's workflows, the guard built by `rustc --test` with the scratch
  as its manifest directory, the tip's and `89d6e0df`'s; 30 of 30 refused on the tip by
  `the_sibling_job_judges_on_every_event_it_runs_on_with_no_reach_filter_97`, 13 of them passing
  `89d6e0df`'s sibling test (the three inserted steps, the four job `env:` keys, the workflow `BASH_ENV`,
  another checkout action, the checkout's `ref:`, a workflow `env:` key behind a column-0
  comment, a `defaults:` at the file's end, a job named `sibling` in another workflow), and a
  fourteenth, a twin `sibling` job in ci.yml, refused there by the exact-set tests alone.
- Not held, said in the manual: the pin travels in the pull request's tree beside the job; the
  next stage reads the judge from beta.
