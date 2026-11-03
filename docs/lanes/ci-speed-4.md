# CI speed, loop one, cut 4 (#667): a pull request's Test Suite runs the test targets its changed files reach; the whole suite once per landing by a label read live

Branch `lane/ci-speed-4` from `origin/beta` at `e3fef6dc` (the worktree opened there; no
reset was needed). Loop one of the speed line (the keeper's word of 2026-11-03 02:1xZ):
the seven cuts of #665, #664, #666 and #667; this is cut 4, ordered before round two's
shard by step (#671): a shard spends more of the account's twenty slots to go faster, this
cut spends fewer.

## The measurement before

Read from `gh api repos/Calhooon/bsv-rs/actions/runs/<id>/jobs`, `steps[].started_at` to
`completed_at`, on 2026-11-03 (the raw lines are
`/Volumes/Lanes/out/bsv-rs/ci-speed-4/before-pr-steps.txt` and `before-steps.txt`). Every
run below ran the whole suite: before this cut a pull request's own run and the
sequencer's landing run on its rebased head each run all five test steps, so a landing
costs two whole Suites, and the push to `beta` after the merge a third.

The pull requests' runs (the figures the issue quotes):

| Run | PR | Run wall | Test Suite | Unit | Integration | Memory | Tracing | Doc |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 41571159770 | #664 (`lane/ci-speed-2`) | 12m09s | 12m05s | 1m15s | 5m10s | 4m35s | 20s | 30s |
| 41573018866 | #666 (`lane/ci-speed-7`) | 16m48s | 15m15s | 1m31s | 6m34s | 6m01s | 25s | 33s |
| 41574976294 | #669 (docs only) | 10m05s | 9m47s | 1m08s | 4m07s | 3m35s | 17s | 27s |

The landings' push runs on `beta`, the same five steps again:

| Run | Commit | Run wall | Test Suite | Unit | Integration | Memory | Tracing | Doc |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 41572799982 | `5ef80340` (#664) | 16m37s | 15m27s | 1m38s | 6m36s | 5m59s | 27s | 34s |
| 41574906815 | `74705007` (#666) | 12m06s | 12m02s | 1m21s | 5m07s | 4m31s | 21s | 29s |
| 41576128679 | `fdbaa858` (#669) | 15m23s | 15m21s | 1m38s | 6m32s | 5m58s | 25s | 33s |

The setup steps (checkout, toolchain, lockfile, cache restore, nextest's install) sum to
10 to 15 s in every run: the Suite is test-bound, integration and memory 80 to 85 percent
of it. The docs-only PR (#669) ran all of it.

## The plan: `.github/scripts/affected_tests.py`

A sibling script, not a mode of `nightly_mutants.py plan`: the night's question is which
measured sources a change can create mutants in, this one's is which test targets can
fail; the answers run in opposite directions over the same readings, so the script
imports `nightly_mutants` for `test_rows` (the `tests/CLAUDE.md` table), `is_doc`,
`is_test_only` and `callers` (the one-level `crate::<m>` graph), and the night's script
stays as it is (a change to it would make the next night complete).

`plan --range HEAD^1..HEAD` (on a pull request's merge ref `HEAD^1` is the base it
is tested on, so the diff is what the merged tree changes; `fetch-depth: 2`) reads
`git diff --name-only --no-renames` and writes a JSON plan: the reached binaries with the
reason per binary, `everything`, `lib`, `doc`, `memory`, `tracing`. Per changed path:

- **Everything**: `Cargo.toml`, `Cargo.lock`, `build.rs`, `src/lib.rs`, `src/error.rs` and
  `src/error/`, `.cargo/config*`, `.config/` (nextest's), the toolchain files,
  `.github/workflows/ci.yml` and the plan's own script.
- **A library source** (`src/<m>/`, not documentation): the unit and doc tests, and every
  integration binary that uses module `m` or, one level out, a module whose non-test
  sources name `crate::m` (the night's callee rule). A binary uses a module when its
  sources (the file and every module it declares, `mod support;` and `#[path]`
  transitively) name `bsv_rs::<m>`, or a crate-root re-export of `m` (`bsv_rs::{Script}`,
  read from `src/lib.rs`'s `pub use` lines), or its `tests/CLAUDE.md` row names `src/<m>/`
  or `<m>::`. A test-only module (`*_tests.rs`, `#![cfg(test)]`) reaches the unit tests
  alone.
- **A test binary** (`tests/<name>.rs`): itself; a removed one, nothing.
- **`tests/CLAUDE.md`**: the binaries whose row text differs between the base and the
  head. A finding against the brief, which listed the file under everything: 30 of the
  last 50 landings on `beta` change it (every fix lands with its row), so everything there
  would leave most landings on the whole suite; the rows decide only which binaries a
  library change reaches, and the head's rows are what the plan reads.
  `nightly_mutants.py` is likewise not under everything here (5 of the last 50 landings
  changed it, counted per landing by each landing's `git diff --name-only`; `git log
  --oneline -50 -- .github/scripts/nightly_mutants.py` gives 7, the file's whole history,
  two of them before the fifty): its readings are pinned by `test_affected_tests.py`, which
  the plan step runs before it plans.
- **Any other path** (a support module, a vector, a fixture, a doc a test reads, a workflow
  an arch test reads): the binaries whose sources declare it, or name it in a string
  literal (its whole path; its file name when it lies under `tests/` or the name is
  distinctive; its directory when two deep under `tests/`, the #666 F3 clause), or whose
  `format!` template's directory holds it, or that walk a directory holding it (a literal
  naming a directory, in a source that calls `read_dir`: `src` for the arch rules, `tests`
  for #146's guard, `examples` for the README's). Names are read in string literals only
  (a small lexer past comments, char literals and raw strings): prose mentions of
  `CHANGELOG.md` or `CLAUDE.md` reach nothing. A library source naming the path (an
  `include_str!` of a vector) adds the unit and doc tests.

The run-apart binaries (`memory_profiling`, `wire_tracing_sink`) leave the integration
list for their own steps' flags; `tracing` is set when any of the tracing step's three
files is reached.

`check --plan P --metadata M` asserts the reached names are integration targets of
`cargo metadata --no-deps` (282, the same set `cargo nextest list --tests` reports on the
tip: 282 test binaries, 4,856 tests), that a library change reaches at least one, and that
an everything plan lists the whole. `cargo metadata` in place of `cargo nextest list`
because the list builds every binary, the cost the reached run saves.

The tests, `.github/scripts/test_affected_tests.py` (19 since the #680 fold, a fixture tree): a docs-only
change reaches nothing; a file named only in prose is not read; a `src/script/` change
reaches its users by path, row and re-export and one level of callers, not two; a row
naming a module reaches its binary; a test-only module runs the unit tests alone; a
`tests/support/` change and a vector reach their declarers and namers, a built path
through its template's directory; a vector a library source includes runs the unit tests;
a test-file change reaches itself; a changed row reaches its binary alone; `src/lib.rs`,
`Cargo.toml`, `src/error.rs`, `ci.yml`, the script and `.cargo/config.toml` reach
everything; the check refuses a name outside the whole, an empty set on a library change,
and an everything plan short of the whole; the lexer; a walked literal longer than a file
name is no directory, and a `README.md` change reaches the binaries that read it (both the
fold's, below). RED witnesses: the callee rule
switched off fails the script case; a ci.yml whole-suite step under `github.event_name ==
'push'` fails #146's guard on the real file.

## The workflow (`ci.yml`, the `test` job)

1. `actions/checkout` with `fetch-depth: 2`.
2. **Plan the targets the change reaches** (`shell: bash`): on any event but
   `pull_request` it writes `whole=true lib=true doc=true memory=true tracing=true` and
   stops (no Python: the dispatch's Windows cells run it). On a pull request it runs the
   plan's tests, then reads the labels live, `gh api repos/$REPOSITORY/pulls/$PR` with the
   job's `GITHUB_TOKEN` under `pull-requests: read` (a failed read fails the job; it never
   falls to the narrower run), and plans `--whole` when `full-suite` is present, else
   `--range HEAD^1..HEAD`. No `on.pull_request.types` of `labeled`: a label would start a
   second run, the toolbox's twin runs.
3. The cache step saves on a pull request only when the plan is the whole suite (`whole`,
   since the #680 fold; `lib` before it): a docs or test-only change, or a library change
   whose subset leaves the memory, tracing or integration build unrun, would on a key miss
   save an empty or partial target under the shared key, every later run's exact hit. The
   landing run carries `full-suite`, so a complete cache is still saved once per landing.
4. **Check the reached set within the whole** (pull requests): `cargo metadata`, then
   `affected_tests.py check`, printing the reached names beside the whole's count.
5. The unit step under `lib`; **Run every integration test** (`--tests`, unchanged) under
   `whole`; **Run the integration tests the change reaches** under `whole != 'true'` and a
   nonempty set: `cargo nextest run --features "full,http,websocket" $REACHED_TESTS
   --no-fail-fast --cargo-verbose`, the plan's binaries as `--test <name>` words. The
   `--test` form and not `-E 'binary(..)'`: cargo builds the named binaries alone, where an
   expression after `--tests` builds every binary and runs some; nextest keeps
   `--no-fail-fast` and each test's timing either way. The memory step under `memory`, the
   tracing step under `tracing`, the doc step under `doc`.

`permissions: contents: read, pull-requests: read` on the job, and the same on
`release.yml`'s call of `ci.yml`: a called job asking more than its caller grants never
starts, so the tag's run would fail at startup without it.

## The guard (#146, `tests/arch_ci_runs_every_test.rs`)

Each step now carries its `if:`, and a step whose words hold a `$VARIABLE` is the reached
step, never a whole-suite one. `reached_refusals`, on the Test Suite job alone: every test
step runs always or under a plan flag (`steps.plan.outputs.<flag> == 'true'`); the
whole-suite step under `whole` exactly; the reached step under `whole != 'true'`; a
reached step without a whole-suite step refused; the plan's non-PR line sets every flag a
step reads to `true`; the event test, the live label read, the `full-suite` match, the
check and the plan's tests are present; no `labeled` trigger. Two new cases pin the shape
and each refusal; the coverage rule is unchanged (the whole-suite step still runs every
binary its features compile).

## The plan on real diffs

Each planned on its own commit's tree (`git archive` into a scratch copy), the diff the
landing's parent to the landing; the whole is that tree's binaries less the two run apart.

| Landing | Changed | Plan | Integration | Unit, doc | Memory | Tracing |
|---|---|---|---:|---|---|---|
| `fdbaa858` (#669, docs only: `CHANGELOG.md`, `docs/lanes/ci-speed-1.md`) | 2 | `arch_ci_lines` (reads `CHANGELOG.md`) | 1 of 280 | skipped | skipped | skipped |
| `541b672d` (#657, one module: `src/script/spend/crypto.rs`, three tests, two support files, a vector, the rows) | 12 | `src/script/` and its seven callers' users, the changed tests, the arch rules walking `src` | 226 of 277 | run | run | run |
| `c90299ee` (0.9.0-beta.6: `Cargo.toml`) | 3 | everything (`Cargo.toml`) | 254 of 254 | run | run | run |

No landing in the last fifty changed `src/lib.rs`; `c90299ee` is the manifest's.

Across the last fifty landings (`git log -50 e3fef6dc`, linear; each planned on its own
tree under the committed rule, `tests/CLAUDE.md` by its changed rows and
`nightly_mutants.py` not everything, re-read in the #680 fold on Python 3.12 with the
fold's script; the committed script on Python 3.14 gives the same plan on all fifty;
`/Volumes/Lanes/out/bsv-rs/ci-speed-4-fold/survey-fold-summary.txt`): 4 plan everything
(three `ci.yml`, one `Cargo.toml`); 21 run the unit and doc tests: 20 change a library
source and reach 103 to 275 binaries (17 of them 204 to 226 of 255 to 278: `primitives`,
`script` and `transaction` are called by nearly every module, so the one-level rule reaches
most of the suite), all but one (`938917de`, `auth`) with the memory step, and one
(`51fa67ac`) changes a vector a library source includes and reaches 5; 25 reach 0 to 12
binaries with no unit, doc or memory step (docs-only, test-only, `.cargo/mutants.toml`,
nightly workflow and three `nightly_mutants.py` landings). The lane's survey read the five
`nightly_mutants.py` landings under the brief's rule (everything): under the committed one
three of them reach 3 binaries, one (`10b88ea3`) is a library landing and one (`51fa67ac`)
the vector one, so its 9, 19 and 22 are 4, 21 and 25. The cut's saving is on those 25:
their unit, integration, memory and doc steps, about 8 to 12 minutes each by the before
table; the 20 library landings save the integration step's unreached fifth and the build
of its binaries.

The one-level rule's residual: a full transitive walk of the `crate::<m>` graph reaches
34 more binaries for a `script` change (257 against 223), 43 for `transaction` (257
against 214) and 99 for `block` (257 against 158), measured on the tip tree in the fold.
The cold read found no concrete binary one of those changes can fail that the one-level
set leaves out; the landing run's whole suite is the backstop for any it misses.

## The sequencer's two lines

The label must exist once: `gh label create full-suite --repo Calhooon/bsv-rs --color
0e8a16 --description "The landing run: the whole Test Suite"` (not created by this lane).
In `sequencer8`, before the push of a PR's rebased head for its landing run, and after the
merge:

```sh
gh pr edit "$N" --repo Calhooon/bsv-rs --add-label full-suite      # before git push of the rebased head
gh pr edit "$N" --repo Calhooon/bsv-rs --remove-label full-suite   # after the merge
```

The label is read when the job starts, so it must be on the PR before the push that starts
the landing run; a label added after the run started applies to the next run (a rerun
included: the read is live, not the event's payload).

## The five figures

| Figure | Before | After |
|---|---|---|
| A PR's CI wall clock | 12m09s (#664, run 41571159770), 16m48s (#666, run 41573018866), 10m05s (#669 docs, run 41574976294) | 11m09s whole (this PR's landing run 41590906372, planned whole by the `full-suite` label: the Test Suite 9m11s); 7m43s on a one-module PR (#684's run 41598630196: 6 changed files, 228 of 280 binaries reached, the Test Suite 7m40s) |
| Queue wait | 0m03s, 1m32s and 0m17s to the Test Suite on those three runs (the hour's load, not the workflow) | 1m57s (run 41590906372) and 0m02s (run 41598630196), the hour's load |
| The nightly | 10h43m (run 41347058507, the last complete one; run 41579707627, the earliest incremental, in progress at 05:39Z) | unchanged by this cut (run 41579707627 ended at 2h28m06s, loop one's record in `docs/lanes/ci-speed-2.md`) |
| A cold read | 16m49s (the #660 cold read) | unchanged by this cut |
| The landing latency, lane DONE to landed | five landings: 113, 124, 181, 186 and 219 minutes (loop one's record, `docs/lanes/ci-speed-loop2-slowest.md` "The five figures", on `beta` since `3b29b3eb`, #670); the landing run now costs one whole Suite where a PR and its landing cost two | 64 minutes for this PR (#680), 46 for #684 (the captain's count, 2026-11-03 morning) |

The after source is this PR's CI run. Its run 41585824405 (on `f39d4a95`) failed at the plan
step after ten seconds (the fold, below), so the after figures are the fold's run's. The
after figures for a docs-only PR and a manifest PR come from the next PRs of each kind.

The after figures, read from `gh run view <id> --json jobs` on 2026-11-03 (the step lines
are `/Volumes/Lanes/out/bsv-rs/ci-speed-loop1-close/steps.txt`):

| Run | PR | Plan | Run wall | Test Suite | Plan step | Unit | Integration | Memory | Tracing | Doc |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 41590906372 | #680 (this PR) | everything (the `full-suite` label: the landing run) | 11m09s | 9m11s | 1s | 1m15s | 5m38s whole | 1m06s | 26s | 34s |
| 41598630196 | #684 (`src/script/spend/`, its tests) | 6 files, 228 of 280 | 7m43s | 7m40s | 3s | 1m15s | 4m04s reached | 1m06s | 25s | 34s |

The setup steps still sum to about 10 s. The sequencer's label: since `sequencer9` it is set
before the sequencer's first poll; #684's landing run, under `sequencer8`, ran the subset
(the label came after the run started), and the whole suite ran on `beta`'s push run
41599782319 after the merge (its Test Suite 6m29s).

## The #680 fold

The three reads' items, one commit on `f39d4a95`:

- **The plan crashed on the runner's Python.** `Tree` tested every walked literal with
  `Path.is_dir()`; on Python 3.11, 3.12 and 3.13 a literal longer than a file name raises
  `OSError` (ENAMETOOLONG: `[Errno 36]` on Linux, `[Errno 63]` on macOS), where 3.14, the
  lane's local Python, answers False. Run 41585824405 failed there on a multi-line `ci.yml`
  literal of an architecture test (`OSError: [Errno 36] File name too long`), and the
  committed script on Python 3.12 fails the same way on the tip tree here. Now
  `os.path.isdir`, which answers False on any `OSError`. The case: a walked 300-character
  literal, RED on 3.11, 3.12 and 3.13, green on all four.
- **The lexer's end anchor.** `names_path` tested the two characters before a match with
  `[\w./-]$`; `$` also matches before a trailing newline, and the joined text holds one
  literal per line, so the previous literal's last character read a path as the tail of a
  longer one: a `README.md` change reached nothing, though `readme_examples` reads it
  (`CLAUDE.md` rule 8). Now `\Z`. The `before == '"/'` branch was dead (the joined text
  holds no quotes); it is now live as the comment meant it, a slash opening a literal
  (`concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")`), `before in ("/", "\n/")`. The case:
  a `README.md` change reaches a binary naming it after another literal and one naming it
  by a leading slash; RED on all four Pythons, and the slash binary alone RED with the
  branch removed. On the tip tree a `README.md`-only change now reaches `readme_examples`.
  Neither change moves a plan on the fifty landings.
- **The cache's PR arm** saves on `whole`, not `lib` (the workflow step 3 above).
- **The live label read worked** on run 41585824405: `labels: ci`, under the job's token
  with `PullRequests: read`, before the plan crashed.
- **The architecture binaries** are twelve `tests/arch_*.rs` files plus `fixtures_replay`,
  where the PR's body said thirteen architecture binaries.

## The order

This cut before round two's shard (#671): the shard is cut on what remains above the
eight-minute line after a pull request runs its reached set. Loop two (#668, the docs-only
exit; the ten slowest tests) opens from this record's after figures.
