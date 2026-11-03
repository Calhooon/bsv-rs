# ci-speed-7: the nightly incremental (speed round 1, cut 7)

The keeper's speed line, cut 7, on the owner's word of 2026-11-02 23:3xZ:
"even the nightly... is all that necessary? or maybe a fraction". Base
`84a01d2a` (beta's tip; the worktree opened at `efe12e63`, main's, and was
reset to `origin/beta`). The rule, the record's shape and the dispatch lines
are in `docs/NIGHTLY.md`, "Incremental nights and the complete run (cut 7)".

## The measurement

Run 41347058507, read from the API on 2026-11-02 (`gh api
repos/Calhooon/bsv-rs/actions/runs/41347058507/jobs`, the steps' `started_at`
and `completed_at`; the counts from the shards' `mutants-*` artifacts,
unexpired). Dispatched 2026-11-01 20:28:54Z at `9640eaa7`, measured `42a74f1b`
(#629's finding). Created to last job 07:11:59Z: 10h43m. Queued until
23:52:16Z (3h23m, the concurrency group), running 7h19m: the mutation shards
23:52Z to 03:04Z (3h12m at six at a time), the score job 03:04Z, the fuzz
targets 03:04Z to 07:11Z (4h07m, four waves of six).

Every shard's baseline succeeded (exit codes 2 and 3, misses and timeouts);
the score job failed on eleven gate-path files below 80
(`locking_script.rs`, `not_judged.rs`, `script.rs`, `p2pk.rs`, `pushdrop.rs`,
`transaction.rs`, `unlocking_script.rs`, `beef.rs`, `beef_stream.rs`,
`beef_tx.rs`, `merkle_path.rs`), #603's list. The brief's "failed at the
baseline" is not what the API shows for this run.

| Surface | Files | Mutants generated | Caught | Missed | Timeout | Unviable | Shard minutes (the scoped step, four shards) | Job minutes (max) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| script | 48 | 2,059 | 1,656 | 302 | 7 | 94 | 133.1, 124.8, 129.6, 129.3 (516.8) | 136.2 |
| BEEF | 3 | 748 | 512 | 172 | 3 | 61 | 36.2, 40.1, 33.3, 38.6 (148.2) | 43.3 |
| Merkle | 1 | 101 | 64 | 25 | 0 | 12 | 3.2, 2.5, 3.0, 3.1 (11.8) | 6.2 |
| wire | 16 | 793 | 470 | 168 | 0 | 155 | 20.9, 20.9, 18.6, 17.5 (77.9) | 23.9 |
| substrates | 25 | 1,142 | 167 | 863 | 4 | 108 | 37.8, 32.6, 35.3, 40.8 (146.5) | 43.8 |
| all | 93 | 4,843 | | | | | 901.2 | |

The fuzz targets: nineteen, 60.1 to 63.2 minutes in the fuzz step, 60.9 to
66.8 minutes a job (the build about four).

## The rule

A file's mutation score moves only when the file or the tests that reach it
change: a night mutates the files the reach rule names since the last
complete run and carries every other figure from the record with its run's
id and sha. The table is in `docs/NIGHTLY.md`. Where it departs from the
brief's literal words, and why:

- `tests/support/` and `tests/vectors/`: the brief re-measured everything on
  any change there. Eight of beta's last ten commits touch one (each #603 and
  #6xx landing adds a recorder `.mjs` or `.lean` and a vector), so the literal
  rule makes nearly every night complete. The plan follows such a file to the
  compiled sources that name it (a test file, a support module by its `mod`
  name, a unit-test source under `src/`) and re-measures what they reach; a
  file nothing compiled names reaches nothing.
- `.cargo/mutants.toml`: the brief re-measured everything. An `exclude_re`
  entry is anchored on its file (`^src/...\.rs:line:col: ...`), so an added or
  removed entry re-measures that file; any other setting, or an entry that
  names no file, still re-measures everything.
- A test no surface's selection runs re-measures nothing: it never meets a
  mutant.
- `src/lib.rs`, `src/error.rs`, `build.rs` and `.cargo/*` re-measure
  everything (the brief named the manifest, the lock and the nightly's files;
  these are the crate root, the unit-test skips' source, and the build).
- The library commits no `Cargo.lock`: a night builds the complete run's own
  lockfile, kept in the record (its sha256 checked), so an upstream release
  cannot move a carried figure's oracle unseen; a `Cargo.toml` change makes
  the night complete with a fresh resolution.

## The plan on the real tree

`plan --commit 84a01d2a...` against a record built from run 41347058507's
artifacts with its complete-run commit set to the named base (the hand run's
stand-in: no `mutation-record` exists before this lands; the record's 93
files are `42a74f1b`'s, two measured files are newer and would be in a real
night's diff).

`ffff16d0..84a01d2a` (one commit, the #603 S4 landing):

```text
mode incremental; 4 files measured tonight, 91 carried
beef: src/transaction/beef.rs, src/transaction/beef_stream.rs, src/transaction/beef_tx.rs
merkle: src/transaction/merkle_path.rs
matrix: beef 0/3, 1/3, 2/3; merkle 0/1 (4 shards, six at a time)
.cargo/mutants.toml -> beef_stream.rs (the exclusions added or removed name these files)
src/transaction/beef_stream.rs -> itself (a measured file)
src/transaction/beef_stream/reason.rs -> the four transaction files (a source of src/transaction/)
tests/beef_stream_603_s4.rs -> beef_stream.rs (its tests/CLAUDE.md row, within the beef selection)
tests/support/beef_reference_603.mjs -> the four (named by tests/beef_stream_603_s2.rs, tests/beef_stream_603_s4.rs, src/transaction/beef/reference_603_tests.rs)
tests/vectors/beef_reference_603.json -> the four (the same three)
CHANGELOG.md, docs/NIGHTLY.md, src/transaction/CLAUDE.md, tests/CLAUDE.md -> nothing (documentation)
```

`9eba10a8..84a01d2a` (the last ten): `mode complete`, why
`.github/scripts/nightly_mutants.py changed: the selection, the skips and the
score`; twenty shards, twenty at a time.

## The expected night

Beta's last ten commits (2026-11-02 06:51 to 18:22 local, one day's
landings), each planned alone against its parent:

| Commit | Plans |
| --- | --- |
| `84a01d2a` beef-stream S4 | 4 files (BEEF and Merkle) |
| `ffff16d0` the pin (#629) | everything (the nightly's script) |
| `e49cf55d` merkle-path #649 | 4 files |
| `a7555589` script A | 50 files (the script surface: `tests/script_script_603_a.rs`'s row names no file) |
| `3fd977be` HANDOFF | nothing |
| `b9f78224` merkle-path #641 | 4 files |
| `7b44110e` filings | nothing |
| `2ec03225` beef-stream S3 | 3 files |
| `51fa67ac` beef-stream S2 | everything (the nightly's script) |
| `1147ea71` script C | 3 files |

Under the literal rule eight of the ten re-measure everything; under this one
two (both the nightly's own script). The day's union without those two is 54
files: the script surface's 50 and the four transaction files, 15 shards (11
script, 3 BEEF, 1 Merkle) at six at a time, about 2h30m of shards, then the
fuzz at ten minutes a target (four waves of about 14 minutes, about 56
minutes): about 3h30m running. A day of BEEF and Merkle landings alone: four
shards, about 55 minutes, then the fuzz: about 1h55m. A day of documentation:
no shard, the fuzz alone, about an hour. A row in `tests/CLAUDE.md` that names
its file (`script_script_603_a.rs`'s names none) is what keeps a script test's
night to its file.

## PR #666's fold: the five holes

The three reads (cold, reach, workflow) found five ways a change that should
re-measure files planned too little; the fold closes each with a
`test_fold_*` case in `test_nightly_mutants.py` (61 tests; on `cc50c557`'s
script the five fail, and the fixture's `beef_only.json` case, which now
reaches `beef.rs` alone through the test-only source that reads it). The rules
are `docs/NIGHTLY.md`'s table. The plans below ran `plan` from the fold's
script on a clone at `84a01d2a`, against a record built from run
41347058507's `mutation-summary` with its complete-run commit set to the base
named (the stand-in, as above); the measured files are now 82 (script 40,
BEEF 3, Merkle 1, wire 15, substrates 23), the thirteen test-only modules out.

`ffff16d0..84a01d2a`: 9 files, 5 shards, 73 carried (`beef.rs`,
`beef_stream.rs`, `beef_tx.rs`, `merkle_path.rs`, and the five substrates
files that call `crate::transaction`: `http_json.rs`, `http_json/answer.rs`,
`http_json/review_actions.rs`, `http_wire.rs`, `result_values/beef.rs`,
reached by `src/transaction/beef_stream/reason.rs`). The vector
`beef_reference_603.json` and its recorder now reach `beef.rs` and
`beef_stream.rs` (the S2 and S4 rows, and the test-only
`beef/reference_603_tests.rs`'s parent), not the four.

The cold read's three probes, each one commit on `84a01d2a`:

| Probe | cut 7 | the fold | the second fold (`callee_added`) |
| --- | --- | --- | --- |
| `git rm tests/script_script_603_a.rs` | nothing | 40 files, 11 shards (the base's script selection; its base row names no file) | 40/11 (0) |
| `tests/fixtures/wire/createAction.json` | nothing | 15 files, 2 shards (`wallet_wire_cross_sdk_tests` names `fixtures/wire/`) | 15/2 (0) |
| `src/primitives/hash.rs` | nothing | 39 files, 16 shards (script 25, wire 6, substrates 4, BEEF 3, Merkle 1) | 39/16 (39) |
| `src/transaction/beef.rs` (measured) | 1/1 | 1/1 | 7/2 (6: `beef_tx.rs` and the five substrates callers) |
| `src/script/spend/flow.rs` (measured) | 1/1 | 1/1 | 29/10 (28: 25 script, 3 BEEF) |

What the reads' other cases reach now: `tests/support/fixtures/*` (each of
seven) the wire's 15, through the fourteen tests whose `#[path]` includes
`support/fixtures/mod.rs` (one, `wallet_wire_cross_sdk_tests`, in a
selection); `tests/vectors/sighash.json` 55 (the script's 40 through
`sighash_tests`, the wire's 15 through `support/fixtures/binary.rs`);
`script_script_603_c.rs` the 15 measured files of `src/script/` (its row
names `script_length_603_tests.rs`), `script_arithmetic_result_bound_374.rs`
the 16 of `src/script/spend/`, `script_pushdrop_key_bytes_545.rs` the 9 of
`src/script/templates/`.

Beta's last ten, each against its parent (files/shards):

| Commit | cut 7 | the fold | the second fold (`callee_added`) |
| --- | --- | --- | --- |
| `84a01d2a` beef-stream S4 | 4/4 | 9/5 | 9/5 (5) |
| `ffff16d0` the pin (#629) | all | all | all (0) |
| `e49cf55d` merkle-path #649 | 4/4 | 9/5 | 9/5 (5) |
| `a7555589` script A | 50/11 | 40/11 | 43/14 (3) |
| `3fd977be` HANDOFF | 0/0 | 0/0 | 0/0 (0) |
| `b9f78224` merkle-path #641 | 4/4 | 9/5 | 9/5 (5) |
| `7b44110e` filings | 0/0 | 0/0 | 0/0 (0) |
| `2ec03225` beef-stream S3 | 3/3 | 3/3 | 3/3 (0) |
| `51fa67ac` beef-stream S2 | all | all | all (0) |
| `1147ea71` script C | 3/3 | 15/5 | 40/14 (25) |

29 shards over the eight incremental nights before, 34 after the fold, 46
after the second fold. The callee
rule's frequency on `origin/beta` (2026-10-03 to 2026-11-02): 25 of 1,033
commits changed `src/primitives/` (12 of the 25 days with a commit; 2 of the
last 50 commits); 36 changed `primitives` or `block`; 9 changed nothing
compiled but those. A night with a `primitives` change is 16 of the complete
run's 20 shards.

## PR #666's second fold: the count per night, the rule's letter

The re-read's FIX: the keeper's word ("the record names per night how many
files the cure added") was met only inside each path's reason text. Now the
plan's JSON carries `callee_rule` and `callee_added` (the sorted names of the
files the callee rule reached that no other rule did: `reach` run again with
`callee=False`, the difference; a complete run's is empty), the record's
`runs[]` entry `callee_added` (the count) beside its `run_id` and `commit`,
and the scoreboard's header `callee_line`: "The callee rule added N files
tonight (<mode>): <names>", "(complete: every file measured)" on a complete
run, "The callee rule is off (`CALLEE_RULE`)" when it is.

The rule's letter ("a changed module re-measures every measured file that
names it"): the fold applied `callers` to a changed unmeasured source only;
it now applies to every changed source under `src/<m>/`, measured or not, a
test-only source excepted (it compiles into no caller), still behind
`CALLEE_RULE` and counted in `callee_added`. Same-module callers count: a
measured `src/script/` file reaches the 22 other script files that name
`crate::script` and the three BEEF files that do. What moved (the tables
above, replayed with the same stand-in record from run 41347058507's
`mutation-summary` on a clone at `84a01d2a`, the fold's script and this one
side by side): `script-a` 40/11 to 43/14 and `script-c` 15/5 to 40/14 (both
change measured script files), the two measured probes 1/1 to 7/2 and
29/10; the BEEF and Merkle landings are unchanged (they also change the
unmeasured `beef_stream/reason.rs`, which already reached the five
substrates callers), and so are the three probes.

Tests (`test_fold2_*`, three): a changed measured file reaches the measured
files naming its module, a test-only one does not, the switch off restores
cut 7's; the plan counts the rule's files on a night where it adds one, on
one where another path reaches the same file (0), on one where it adds none,
and on a complete run; the record's run entry and the scoreboard's line.
RED on the fold's script (two `KeyError`s on the count, one missing caller),
GREEN with this one: 64 of 64.

## The four figures of the standing rule

| Figure | Before | After |
| --- | --- | --- |
| PR wall clock | 29m11s | unchanged by this cut (ci.yml is `ci-speed-1` and `ci-speed-2`'s) |
| Queue wait | 3m10s | unchanged by this cut |
| The nightly | 10h43m (run 41347058507, 7h19m running) | (from the first incremental run) |
| A cold read | 16m49s | unchanged by this cut |

The dispatch that follows the landing is complete by the rule (the
nightly's workflow and script changed, and no record exists): `gh workflow run
nightly.yml --ref beta -f mode=complete`. The incremental nights begin with
the one after it.

## The fleet's runner cap

The keeper's line, 10:0xZ 2026-11-03, on the opening API read of the pool:
every heavy run on the runners carries `max-parallel: 6` (14 from the line
of 06:2xZ until then), for the pull request and queue runs of the four
repositories (bsv-rs, the CLI, the toolbox, the stack), which share the
account's twenty hosted runners as one pool; and this crate's complete
dispatch takes the 07:00Z slot (00:00Z until then). The day's dispatch rule
(the keeper's correction at this file's next touch, 2026-11-03): one hand
dispatch a day at 07:00Z, incremental by default, complete at a pin and
after a measured cap change; the 00:00Z slot retired.

The read (the toolbox's loop-four tool, 12,251 jobs over three days, the
keeper's figures): the twenty runners peak at exactly twenty in 22 of 24
hours, so there is no quiet hour; the lightest are 07Z (5.5 slots on the
mean) and 16Z to 18Z (7.0 to 7.6), the hottest 20Z to 01Z (18.9 on the mean
at 00Z, a median pull request wait of 7:25); a job queued beside a heavy run
waits a median of 0:38 and at worst 88:53, against 0:02 and 3:16 beside
none; LOW's overlay repository carries nearly all the runner-minutes. The
non-heavy p95 is 14 slots, so a heavy run of 14 left the fleet nothing at
its p95: the cap is 6 (the plan's 6 for a complete run and 6 for a night,
`ci.yml`'s two matrices 6), until the next occupancy read shows the p95
under 10. The read repeats every 48 hours fleet-wide. The cost (a longer
complete run, below) and the gain (the pull request waits beside it) go in
this record from the complete run at 07:00Z 2026-11-04.

The fact, 2026-11-03. This crate's complete nightly, run 41579707627
(dispatched 04:42:51Z on beta, `mode: complete`, at `e3fef6dc`), asked for
its twenty shards in one wave; they started between 04:44:45Z and 05:32:12Z
as runners came free, and the run held the pool until 06:23:10Z. PR #679's
run, 41581840579, created 05:05:32Z, started its Test Suite at 05:36:33Z
(31 minutes queued for a 15m21s job) and its `checks` at 05:54:05Z, and
finished at 05:57:44Z, 52 minutes after it was created (`gh run view
41581840579 --json jobs`). The same night the CLI's fifty-shard run made
every CLI pull request run wait 40 to 50 minutes on a five-minute job until
05:48Z (the keeper's reading). A night on one repository costs the others'
pull requests the same minutes.

The line. The nightly's `mutants` matrix reads its `max-parallel` from the
pin job's `max_parallel` output, and the plan hands out
`HEAVY_MAX_PARALLEL = 6` for a complete run (14 under the line of 06:2xZ;
`NIGHT_PARALLEL = 6` for a night, unchanged), so both modes of #666 sit under the cap. GitHub reads no
`env` in `strategy` (`${{ fromJSON(env.HEAVY_MAX_PARALLEL) }}` is refused
there), so the number lives in one place, the plan's constant in
`.github/scripts/nightly_mutants.py`, read through the job output the matrix
already used; its owner is loop four's #675, which will read the account's
occupancy from the API and move it. The `fuzz` matrix keeps its literal 6.
`tests/arch_nightly_cap.rs` refuses a heavy matrix in any workflow without
`max-parallel`, a literal above 6, a reading other than the plan's output,
and a plan constant above 6 (14 under the line of 06:2xZ).

The `ci-full` edge (the fold of #682). Each matrix under 14 alone is not the
line: `ci-full` started two whole `ci.yml` runs at the dispatch, beside the
shards (before the cap, 17 of its jobs at 04:48Z and 19 at 05:15Z). It now
runs after the shards and the fuzz targets, whatever their result, under
`if: ${{ !cancelled() }}`.

The two runs one after the other (#682's second fold, the keeper's word (a)
of 07:1xZ 2026-11-03). The fold's check read the two runs' `needs:` graphs:
the "about 12" measured in run 41579707627 was held down by the shards
filling the pool, not the runs' width. Beta's dispatched run (beta's
`ci.yml`) starts six test cells, `lint`, `checks` and the dependents' plan
at once, 9; the dependents are skipped on beta. Main's dispatched run reads
main's own `ci.yml` (`origin/main`, still the nine separate gates): six
cells, nine gates and the plan at once, 16, then the seven dependents after
the plan, up to 22. Together they asked for up to 31, the whole pool. The
word: a dispatched whole `ci.yml` run is a heavy run; the nightly runs
beta's, then main's, and the matrices carry `max-parallel` 14 under a
dispatch.

The mechanism: `ci-full` split into `ci-full-beta` (`needs: [mutants,
fuzz]`; it dispatches beta's run, finds it by identity, waits with `gh
run watch` and reads its conclusion; the rule below, #682's third fold) and `ci-full-main` (`needs: [ci-full-beta]`, both under
`!cancelled()`, so main's follows a failed, timed-out or red beta). The
cost: the waiting job's one runner for beta's run (22m42s in run
41579716973), beside beta's 9 and then 6. The other mechanism, a
`concurrency` group shared by the two dispatch runs (one running, one
pending, which costs no runner while it waits), does not work here: a
dispatch on main runs main's `ci.yml`, whose group is
`ci-${{ github.event_name }}-${{ github.ref }}`, so a group added on beta
would not hold main's run until main carried the file; GitHub's rule that a
group holds one running and one pending run, the older pending one
cancelled when a third arrives ("Using concurrency", GitHub Actions docs),
would also let a hand dispatch on either line cancel main's pending run, and
the group needs `cancel-in-progress: false` where `ci.yml`'s is true off
tags. One runner for 23 minutes buys an order that holds tonight.

The matrices: `ci.yml`'s Test Suite (six cells on a dispatch) and
dependents (seven) carry the literal `max-parallel: 6` (14 under the line
of 06:2xZ, which moved nothing). The Test Suite's six cells sit at it. The
dependents run six, then one, wherever their matrix runs: a dispatch, a
tag's call, a push to main and a pull request into main (`dependents-plan`
runs when `github.base_ref == 'main'` or on any event but a pull request
and a push to beta). The seventh in the lock's order,
bsv-middleware-cloudflare (1m37s in main's run 41579745459), starts when
the earliest of the six, bsv-tracker (1m13s), ends, and ends at 2m50s,
inside the toolbox's 7m08s: the matrix's span is unchanged in the replay,
the cost one runner start-up for the seventh if the pool is full. GitHub reads the `github`
context in `strategy`, so the expression form
`${{ github.event_name == 'workflow_dispatch' && 6 || N }}` is legal too,
and the guard accepts it (its dispatch value at most 6); the literal is plainer. The cap reaches main's
dispatched run only when main's `ci.yml` carries it (the direction rule).

The widths by phase, by the `needs:` graphs, with the replay of the
measured job durations of beta's run 41579716973 and main's 41579745459
(every job without `needs` at the run's start, the dependents 5 seconds
later, the plan's length; runner start-up ignored):

| Phase | Before the second fold | After it | At the cap of 6 (10:0xZ) |
| --- | --- | --- | --- |
| the pin job (`source`) | 1 | 1 | 1 |
| the shards (`mutants`) | 14 | 14 | 6 (four waves: 6, 6, 6, 2) |
| the fuzz targets and the score job | 6 + 1 | 6 + 1 | 6 + 1 |
| beta's `ci.yml` run | 9 (beside main's), then 6 | 9 + the waiting job, 10 for 2m30s; then 7 to 22m42s | unchanged (six cells at the cap; no dependents on beta) |
| main's `ci.yml` run (main's file) | 16, then 22 (beside beta's: up to 31) | 16, then up to 22 (21 in the replay), above 14 for about 89 seconds; 13 by 2m08s; ends at 16m32s | unchanged until main carries the file (main's `ci.yml` at `8729f8a5` has no `max-parallel`) |
| main's run once main carries beta's file | | 9, then 15, above 14 for about 73 seconds | 9, then 14 (six cells, six dependents, `lint`, `checks`), the seventh dependent after the earliest |

The residual: a `max-parallel` caps one matrix, not the sum of a run's
singleton jobs. Main's run on main's file holds up to 22 for a minute
and a half at its start (the nine gates, the longest `deny` 2m08s and Clippy
2m07s, beside the six cells and the seven dependents), 15 on beta's file
(14 at the cap of 6: six cells, six dependents, `lint`, `checks`, more
than 6 and at the non-heavy p95 for the dependents' opening minutes); the
word leaves it, and the next complete run measures it.

The run watched (#682's third fold, the second fold's scoped check): the
lookup was the newest beta dispatch of `ci.yml` created in the minute
before ours, whoever made it, so a hand dispatch in that minute (ours not
yet listed at the poll) or just after ours (`--limit 1` taking the newer)
was the run watched; ours then cancels the hand run (`ci.yml`'s group,
`cancel-in-progress: true`), the watch ends at once and main's run starts
beside beta's. The rule now: the job lists the bot's `workflow_dispatch`
runs of `ci.yml` on beta before the dispatch (`--user
'github-actions[bot]'`, the identity of the job's token, read on the
night's runs: every dispatch since 2026-11-01 has it as actor and
triggering actor; `gh run list` has no `actor` field, so the filter is the
flag, the API's `actor` query; that query matches wider than the run's
`actor` field, read on 2026-11-03: `--user Calgooon` also returns the five
bot dispatches made by the nightlies Calgooon dispatched, while `--user
'github-actions[bot]'` returns 14 of the 17 `ci.yml` dispatches and leaves
out the three hand ones of 2026-10-27, so the bot filter excludes a hand
dispatch as the rule needs); it polls ten seconds apart for a new id not in that list, five
minutes then the job fails; more than one new run is a warning naming every
id, the one created nearest after the dispatch watched; the id and url are
printed; the step runs under `set -euo pipefail`, so a failing `list | jq`
in the poll fails the job at once instead of reading as an empty count and
a misleading "no new run" five minutes later. The watch gives up at 55
minutes of the job (`timeout`, its budget clamped to at least a second),
inside its 60: exit 124, the give-up alone, is a warning and the conclusion
read still runs, which prints `in progress` while the run is unfinished (its
`conclusion` is `""` then, read on 2026-11-03 with gh 2.82.1 on an
in-progress run), so the job ends with the warning and no verdict and main's
dispatch follows; any other non-zero exit of the watch (the API, the
network) is an error with its code and fails the job, so a failed watch
never leaves the night green without beta's verdict (#682's fourth fold;
until it every non-zero exit was a warning and `exit 0`). Then the run's conclusion
is read (`gh run view --json conclusion`) and printed: `failure`,
`timed_out` or `startup_failure` fails the job, so the night shows beta's
CI verdict (`ci-full-main` still runs under `!cancelled()`); `cancelled`
or another conclusion is a warning, no verdict. What remains: a dispatch of
`ci.yml` on beta by the same bot identity in the same minute (another
workflow of this repository dispatching it, or a second nightly) is a
second new run, named in the warning, and the older is watched, which may
be the other's; the other run, being a dispatch on beta, still cancels or
is cancelled by ours through `ci.yml`'s group.

The cost replayed on 14 slots (the line of 06:2xZ; the replay on 6 is
below). The shards' second wave, about 35 minutes (below). The CI phase in sequence: beta's run, 22m42s by its longest cell,
then main's, 16m32s by its longest cell when it runs alone and up to the
hour measured beside the shards (04:43Z to 05:43Z in run 41579707627):
about 39 minutes replayed, an hour and 23 minutes at the measured bound.
The next complete run in its slot (07:00Z since the line of 10:0xZ) is the
measurement.

The guard: `tests/arch_nightly_cap.rs` reads the nightly's `needs:` graph
and refuses two heavy jobs (a heavy matrix or a dispatch of `ci.yml`) with
no `needs:` path between them and any of the five edges that keep the
sequence (fuzz needs mutants, the score job needs mutants, `ci-full-beta`
needs mutants and fuzz, `ci-full-main` needs `ci-full-beta`) removed,
naming the pair and the edge; it refuses a dispatch of `ci.yml` in a
matrix, a dispatch job naming another line than its own, `ci-full-beta`
without its `gh run watch`, without the before-list or the bot's filter
in its lookup, or without its conclusion read and a `failure` failing it
(the third fold, RED with the filter removed and with the read removed), and a `ci.yml` matrix without `max-parallel` or
above 6 (14 under the line of 06:2xZ; the literal or the dispatch value of
the expression). Under the line of 10:0xZ, RED on a scratch copy two more
ways: the plan's `HEAVY_MAX_PARALLEL` restored to 14 (two tests, the plan's
constant named above the cap of 6) and the dependents' literal restored to
14 (`ci.yml dependent-check: max-parallel 14 on a dispatch, above the
fleet's cap of 6`). RED on a scratch copy five ways under the second fold: the wait removed, `ci-full-main`'s edge removed,
`ci-full-beta`'s edge removed, the Test Suite's cap removed, the
dependents' cap removed. Not seen: the weekly `bench` job's dispatch of
`bench.yml`, which still starts at the dispatch beside the pin job and so
beside the shards on a Sunday night.

The sites judged:

| Workflow | Matrix | Heavy | Verdict |
| --- | --- | --- | --- |
| `nightly.yml` | `mutants` (both modes) | yes | capped at 6 through the plan (14 under the line of 06:2xZ; was 20 complete, 6 night) |
| `nightly.yml` | `fuzz` (19 targets) | yes | left at 6 (at the cap, the balance rule's) |
| `nightly.yml` | `ci-full-beta`, `ci-full-main` (was the `ci-full` matrix) | yes, by the word (a) | after the heavy work (the fold), then beta's run and main's one after the other (the second fold): each a job starting a whole `ci.yml` run (run 41579707627's: beta's 41579716973, 10 jobs, 04:43Z to 05:05Z, up to 9 at once by its graph; main's 41579745459, 24 jobs with seven dependents, 04:43Z to 05:43Z, up to 22 at once by its graph, 6 measured beside the shards) |
| `ci.yml` | Test Suite (OS × toolchain), dependents | on a dispatch | `max-parallel: 6`, a literal (14 under the line of 06:2xZ, which moved nothing): the six cells at it, the seven consumers six then one on a dispatch, a tag, a push to main and a pull request into main; main's run takes it when main's `ci.yml` does |
| `features.yml` | `wasm32-slices` (5) | no | left: build checks on dispatch and before a tag, five cells |
| `bench.yml`, `msrv.yml`, `machete.yml`, `docs.yml`, `release.yml`, `sync-main-into-beta.yml` | none | no | no matrix |

The cost under the line of 06:2xZ. A complete run's twenty shards run
as 14, then 6 as the earliest finish: the night's wall clock grows by about one shard's length.
Run 41579707627's twenty shards (`gh run view 41579707627 --json jobs`,
each job's `completedAt` less its `startedAt`): the longest 65m02s (script
1/11), the median 50m45s, the shortest 10m22s (merkle 0/1). Replayed in
the plan's matrix order on 14 slots (script 11 and BEEF 3 in the first
wave, the other six as the earliest finish, at 41m), the shards' span is
about 100 minutes against 65 on twenty free slots: about 35 minutes more,
on a night whose shards took 1h40m from the dispatch to the last shard's
end because the pool never gave the one wave its twenty (at most 17 of the
run's jobs at once).

The cost on 6 slots (the line of 10:0xZ). The same twenty shard times,
replayed in the plan's matrix order (script 0 to 10, BEEF 0 to 2, Merkle,
wire 0 and 1, substrates 0 to 2), each shard taking the slot that comes
free earliest: script shards 0 to 5 from 0; script 6 to 10 and
BEEF 0 at 41.3, 46.7, 47.4, 50.5, 58.8 and 65.0 minutes; BEEF 1 and 2,
Merkle, wire 0 and 1 and substrates 0 at 95.6, 97.8, 111.0, 111.4, 112.1
and 112.2; substrates 1 and 2 at 121.4 and 139.4, the last ending at 187.4
minutes. The shards' span is about 3h07m against 1h40m on 14 slots and
65 minutes on twenty: about 88 minutes more than 14, two hours more than
the one wave. The floor is the sum over six, 974.85 shard minutes / 6 =
162.5 minutes, which no order on six slots beats. The fuzz targets (6,
46.7 minutes replayed from the same run's nineteen jobs in the matrix's
order), the score job and the CI phase (about 39 minutes replayed) follow
unchanged, so the night's wall clock grows by those 88 minutes: a complete
run dispatched at 07:00Z ends its shards near 10:07Z, its fuzz targets
near 10:54Z and its CI phase near 11:33Z, by the replay, before the
CLI's 17:00Z slot. The computation reads `gh run view 41579707627
--json jobs` (each job's `completedAt` less its `startedAt`); runner
start-up and queue waits are ignored.

The gain. Fourteen runners free for the fleet's pull request and queue
runs throughout a complete run (the non-heavy p95), where 14 left six and
the one wave of twenty none.

Both are measured at the next complete run: its wall clock against
41579707627's, and the queue wait of the pull request runs created while it
holds the pool.

The stagger slots (the line of 10:0xZ, on the read's lightest hours). A
complete run takes its slot alone: this crate's at 07:00Z (00:00Z until
the line, the hour the read measured hottest), the CLI's at 17:00Z, the
toolbox's at 18:00Z (the keeper's correction of 2026-11-03; this record had
the toolbox at 16:00Z and the CLI at 17:30Z). A complete run never
overlaps another repository's complete run or a sibling's dispatch, and a
dispatch outside the slot is not run.
