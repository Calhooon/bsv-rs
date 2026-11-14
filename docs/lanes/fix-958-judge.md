# Lane fix-958-judge: the bucket #958, the lines about the judge's script (2026-11-14)

Started from `origin/beta` at `2b419d90b567dc3a67031741d165875340378afe`. Nothing pushed, nothing
written to GitHub; reads by `gh` alone. The pull request changes the judge's script, its tests and
words: `class_of` (the judge's own rule, run on the diff's paths) answers J for
`.github/scripts/sibling_judge.py` and `.github/scripts/test_sibling_judge.py` and N for
`CHANGELOG.md`, `tests/CLAUDE.md`, `tests/sibling/CLAUDE.md` and this file; no P, W or C path, so
`classify` reads the head as class J and its green is titled `JUDGE CHANGE`. No file under `src/`,
no workflow, no vector. The trampoline `sibling-judge.yml` is untouched.

The scope: the lines of #958 about `sibling_judge.py` and its tests. The lines about the sync
workflow, the arch tests and `RELEASING.md` are the lane `fix-958-sync`'s.

## The table

| # | The line (#958) | Fate | The evidence |
|---|---|---|---|
| 1 | The trampoline mints the App's token before the run's identity is read, and mints through the deprecated `app-id` | Script half BUILT (`owed`); the trampoline's step and the owner's variable NEED A DECISION (D1) | `command_owed`; `Owed`, 5 tests, 5 RED before it (the command absent). The trampoline's exact change is under D1 |
| 2 | The environment `sibling-judge` reads `can_admins_bypass: true` and no step reads it back | The read-back BUILT (the sweep's last line; the manual re-dated); the setting NEEDS A DECISION (D2, the owner's) | `environment_line`; `SweepEnvironment`, 3 tests, 3 RED before it. Read on 2026-11-14: `{"can_admins_bypass":true,"deployment_branch_policy":{"custom_branch_policies":true,"protected_branches":false}}`, branch policies `[{"name":"main","type":"branch"}]`; the live sweep's last line `environment sibling-judge: can_admins_bypass true; deployment branches: main (main alone)` |
| 3 | Every `gh api` call runs with no timeout | BUILT | `GitHub._gh` (30 s a read, 120 s the download), `Git.run` (120 s), `resolve`'s clock; `Timeouts`, 7 tests, 7 RED on the base (`subprocess.TimeoutExpired` escaping, `resolve() got an unexpected keyword argument 'clock'`) |
| 4 | The sync's wait for stage R can end without its re-judge line | `fix-958-sync`'s | not read here |
| 5 | The sync holds its concurrency group through the stage R wait | `fix-958-sync`'s | not read here |
| 6 | `report` is not told which run `judge` judged; two `NOT JUDGED` texts name the run called | Script half BUILT (`judge` writes `run` and `attempt`; `report` reads `JUDGED_RUN` and `JUDGED_ATTEMPT` when handed them; both texts); the trampoline's four lines NEED A DECISION (D3) | `judged_of`, `write_outputs`, `command_report`; `ReportBound`, 10 tests, 10 RED before it (5 by assertion, 5 by the absent attribute; with the binding alone removed in a scratch copy, plant `m5`, 5 RED by assertion) |
| 7 | The sweep prints `check stands` for a head whose only check is a `NOT JUDGED` failure; `unless-standing` is silent over it | BUILT | `newest_check`, `not_judged_title`, `standing`; `StandingNotJudged`, 8 tests, 6 RED before it, the two verdict tables green on both |
| 8 | The trampoline's comment says the judgements of a head run one at a time | NEEDS A DECISION (D4): a change of the trampoline, the words given | `.github/workflows/sibling-judge.yml:27-34` read; nothing built |
| 9 | Four changes of meaning in `resolve` and `report` pass every test; three inputs are served by none | BUILT (the tests); the cancelled newest run's verdict NEEDS A DECISION (D5), stated by a test as it stands | `ResolveInputs`, 5 tests; `ReportBound.test_reports_own_not_judged_names_the_run_it_resolved_958` for the re-judge line; each of the four planted in a scratch copy and RED (`m1`, `m2a`, `m2b`, `m3`, `m4`); "two re-judges of one head at once" is row 5's test already (`Interleavings.test_row5_...`) |
| 10 | The copy of the sync workflow that runs is main's, and no test on main pins it | `fix-958-sync`'s | not read here |
| 11 | `run_lines` in `tests/arch_ci_lines.rs` has no test of its own | `fix-958-sync`'s | not read here |
| 12 | `RELEASING.md` step 25 lacks the default branch, the visibility and what main takes | `fix-958-sync`'s (`RELEASING.md` is class C by the judge's rule: it cannot ride this pull request) | read on 2026-11-14: `{"default_branch":"main","visibility":"public"}` |

Counts: 3 lines built whole (3, 7, 9, the last with one question left), 3 built in their script half
with a decision left for the half outside this lane's reach (1, 2, 6), 1 a decision alone (8),
5 left to `fix-958-sync` (4, 5, 10, 11, 12). None was already true at beta's tip, none is no defect.

## Why no built line can earn a head a green

The one line that sets `success` is `Check.passed`, called after the last rule of `_judge`
(`Conclusions`' two tests, unchanged and green). Each change, against that:

- **3 (timeouts).** A call that passes its figure raises `GitHubError` or `sh.Stop`, the two
  errors every arm already turns into `NOT JUDGED`, silence or exit 1. The clock only ends a wait
  sooner; a wait that ends is `Silent` (no check). The new fallback re-judge line is text.
- **7 (standing).** `standing()` is read in two places. The sweep prints and never writes. In
  `report`, a `NOT JUDGED` check no longer silences an `unless-standing` post, and what is then
  posted is forced to `failure` (`test_unless_standing_never_posts_a_success_958`, RED before).
- **6 (the run judged).** The two names can only turn a verdict into `NOT JUDGED`: a mismatch, a
  name that does not read, a success naming no run. Absent names are read as before, no wider.
  `write_outputs` adds two lines after the four; the trampoline's `outputs:` map names four, so
  the two are unread until its sitting.
- **9 (tests).** Tests alone.
- **1 (`owed`).** It posts nothing and holds no key. It answers `no` only on `Silent`, raised by
  the same two functions `report` calls; every other path, a failed read included, answers `yes`
  and leaves the question to `report`.
- **2 (the sweep's line).** A printed line after the sweep's loop; the exit status does not move.

## The rows added to fix-97c's table of interleavings

A and B are stage R runs of one head, A's id below B's, as in `docs/lanes/fix-97c.md` (rows 1 to 9
there). Tests are in `.github/scripts/test_sibling_judge.py`.

| Row | What happens | Which invocation posts | Whose verdict | Test |
|---|---|---|---|---|
| 10 | the judge job judged A; B completes before `report` reads (the trampoline handing on the run judged) | `report`, `NOT JUDGED` with the re-judge of B | none, then B's (its own judgement, or the re-judge) | `ReportBound.test_a_newer_run_completed_between_the_two_jobs_does_not_get_the_older_runs_verdict_958` |
| 10' | the same with a newer attempt of one run | `report`, `NOT JUDGED` with the re-judge | none, then the newer attempt's | `ReportBound.test_a_newer_attempt_completed_between_the_two_jobs_does_not_get_the_older_attempts_verdict_958` |
| 10'' | the same, the trampoline handing on no name (today's file) | `report`, the outputs' verdict | A's, on the head both built | `ReportBound.test_a_trampoline_that_hands_on_neither_name_is_read_as_before_958` |
| 11 | the head's newest check is a `NOT JUDGED` failure; a re-judge whose artifact is gone (`unless-standing`) | `report`, over it | none (`NOT JUDGED` again, the re-run named) | `StandingNotJudged.test_unless_standing_posts_over_a_standing_not_judged_958`; the sweep: `test_the_sweep_names_a_not_judged_check_with_the_rejudge_of_the_newest_run_958` |
| 11' | the same over a standing verdict | none | the standing one | `StandingNotJudged.test_unless_standing_is_silent_over_each_standing_verdict_958` |
| 12 | a `gh` or git call of the judgement hangs | the judge's `report`, `NOT JUDGED` naming the call and the re-judge; a hung read of `report` itself: none, exit 1 naming it | none | `Timeouts.test_a_judgement_whose_read_hangs_is_not_judged_with_the_rejudge_of_the_run_called_958`, `test_a_report_whose_read_hangs_exits_one_naming_the_read_and_posts_nothing_958` |
| 13 | B is `queued`, `waiting`, `requested` or `pending` when A's judgement reads | A's judgement, after waiting for B; none if B has not ended after the wait | B's | `ResolveInputs.test_a_newest_run_not_yet_started_is_waited_for_and_judged_once_it_completes_958` |
| 14 | the listing does not hold the run that called | the calling judgement | the calling run's unless a listed run is newer | `ResolveInputs.test_a_calling_run_the_listing_does_not_hold_is_judged_as_the_newest_958` |
| 14' | the run that called is a fork's, a `push` run or names no head sha, on a head this repository's own stage R run built | none; no listing is read | none | `ResolveInputs.test_a_calling_run_that_is_no_stage_r_run_of_this_repository_reads_no_listing_958` |
| 15 | B was cancelled (a dispatch someone cancelled) after A's `GREEN` | B's judgement or any re-judge, `NOT JUDGED: stage R ended cancelled`, over the `GREEN` | none (stated as it stands; D5) | `ResolveInputs.test_a_cancelled_newest_run_is_not_judged_over_an_older_runs_verdict_stated_958` |
| 16 | the newest run's `run_attempt` is no integer | none (waited for, then a line) | none | `ResolveInputs.test_a_run_attempt_that_is_no_integer_is_never_judged_958` |
| 17 | `owed` asked before the mint | none (it posts nothing): `no` where `report` is silent, `yes` otherwise and on a failed read | none | `Owed`, 5 tests |

## RED before green

Logs under `/Volumes/Lanes/out/bsv-rs/fix-958-judge/`. Each group of tests was written and run
against the script as it stood before its commit (`red-*.log`), then the script changed.

- `red-timeouts.log`: 7 of 7 (9 sub-cases) RED on the base script.
- `red-standing.log`: 6 of 8 RED, the two tables of standing verdicts green on both.
- `red-bound.log`: 10 of 10 RED.
- `red-owed-env.log`: 8 of 8 RED (`Owed` 5, `SweepEnvironment` 3).
- `ResolveInputs` pins the script as it stands, so its RED is by plant. `mutants.py` (in the same
  folder) copies `.github/scripts` to a scratch folder there, plants one change, runs the whole
  file and removes the copy. Fifteen plants, each RED on the test named for it (`mutants-a.log`,
  `mutants-b.log`); every run also shows the two tests that read the tree around the script
  (`Classes.test_every_tracked_path...`, `StageRScript...`), RED in any copy outside the tree, as
  fix-97c's record says of its own scratch run.

| Plant | The change | The test it turns RED |
|---|---|---|
| `m1` | `== "completed"` as `!= "in_progress"` | `test_a_newest_run_not_yet_started_...` |
| `m2a`, `m2b` | the calling run's head-repository check, its event check, dropped from `resolve` | `test_a_calling_run_that_is_no_stage_r_run_of_this_repository_reads_no_listing_958` |
| `m3` | `report`'s re-judge line naming the run called | `test_reports_own_not_judged_names_the_run_it_resolved_958` and two more |
| `m4` | `runs.setdefault(run_id, run)` dropped | `test_a_calling_run_the_listing_does_not_hold_is_judged_as_the_newest_958` |
| `m5` | `report` reading no name of the run judged | five of `ReportBound` |
| `m6` | `isinstance(attempt, int)` dropped | `test_a_run_attempt_that_is_no_integer_is_never_judged_958` |
| `m7` | a `NOT JUDGED` check standing as before | six of `StandingNotJudged` |
| `m8` | `unless-standing` posting the outputs' conclusion | `test_unless_standing_never_posts_a_success_958` |
| `m9` | the wait bounded by its count alone | `test_the_wait_for_a_newer_run_is_bounded_by_the_clock_958` |
| `m10` | the newest check taken by the listing's order | `test_of_two_checks_the_newest_decides_958` |
| `m11`, `m12` | the timeout dropped from the `gh` call, from the git call | `test_a_gh_call_that_hangs_...`, `test_a_git_call_that_hangs_...` |
| `m13` | a success naming no run posted | `test_a_success_that_names_no_run_is_not_judged_...` |
| `m14` | the attempt left out of the comparison | `test_a_newer_attempt_completed_between_the_two_jobs_...` |

## The questions that need a decision

**D1 (line 1). Should the trampoline ask `owed` before it mints, and mint through `client-id`?**
The exact change, `report`'s steps in `.github/workflows/sibling-judge.yml` (one sitting: beta's
pull request, main's pick, `SIBLING_JUDGE` and `stage_j_holds_its_named_rules_97` moved with it;
the owner adds, before it, the environment variable `SIBLING_JUDGE_CLIENT_ID`, the App's client id):

```yaml
      - name: Is a check owed
        id: owed
        env:
          GH_TOKEN: ${{ github.token }}
          RUN_ID: ${{ github.event.workflow_run.id || inputs.run_id }}
          REPOSITORY_ID: ${{ github.repository_id }}
        run: |
          set -euo pipefail
          [[ "$RUN_ID" =~ ^[1-9][0-9]{0,19}$ ]]
          python3 -I -B judge/.github/scripts/sibling_judge.py owed --run-id "$RUN_ID" \
            --repository "$GITHUB_REPOSITORY" --repository-id "$REPOSITORY_ID"

      - name: Mint the App's token
        id: token
        if: steps.owed.outputs.owed != 'no'
        # ... with `client-id: ${{ vars.SIBLING_JUDGE_CLIENT_ID }}` in place of `app-id:`

      - name: Report
        if: steps.owed.outputs.owed != 'no'
```

The ways: (a) as above; (b) leave the order and change the input alone; (c) leave both. What each
costs: (a) one more step and four reads a judgement, and one window: a newest run still running
when `owed` reads and completed when `report` would have read is now silence where `report` posted
`NOT JUDGED: the judge posted nothing where a check is owed`; the sweep names such a head (`check
absent` with its re-judge), and the run's own judgement posts unless a token started it. (b) keeps
a token minted and revoked for every fork's run. (c) keeps the deprecation warning until the action
drops the input. Recommendation: (a), in the sitting that carries D3 and D4, after this pull
request lands (the reader, then the caller, as the manual's "A change that needs both
sides at once" has it). Not verified: that the report job's `github.token` reads the three
endpoints `owed` asks (its `permissions:` are the judge job's, which reads them today).

**D2 (line 2). Should `can_admins_bypass` be false on the environment `sibling-judge`?** The
owner's setting: Settings, Environments, `sibling-judge`, "Allow administrators to bypass
configured protection rules" unticked. The read-back:
`gh api repos/Calhooon/bsv-rs/environments/sibling-judge --jq '{can_admins_bypass, deployment_branch_policy}'`
and the sweep's last line, which must read `can_admins_bypass false; deployment branches: main
(main alone)`. What it costs: nothing a caller sees; the one admin can still rewrite the
environment. Recommendation: set it false, then re-date the manual's sentence in the next judge
pull request. `RELEASING.md` step 25's read-back gaining the environment's line is a class C
change (it cannot ride a J pull request): `fix-958-sync`'s or the sitting's. Not verified: whether
bypass reaches the deployment branch policy at all (no read has shown it), and the API form of the
change (a `PUT` of the environment replaces settings it is not handed; the settings page is the
sure way).

**D3 (line 6). Should the trampoline hand `report` the run `judge` judged?** The exact change,
four lines: in `judge`'s `outputs:`, `run: ${{ steps.judge.outputs.run }}` and
`attempt: ${{ steps.judge.outputs.attempt }}`; in the Report step's `env:`,
`JUDGED_RUN: ${{ needs.judge.outputs.run }}` and `JUDGED_ATTEMPT: ${{ needs.judge.outputs.attempt }}`;
and the header comment's "four outputs" becomes six. The ways: (a) hand them on; (b) leave it. What
each costs: (a) in the window (a newer run or attempt of the head completing between the two jobs)
the head reads `NOT JUDGED` with a re-judge where it read the older run's verdict of the same
tree; the newer run's own judgement, queued behind in the head's group, then posts, unless a token
started that run, and then the re-judge is by hand or the sweep's. (b) keeps the older run's
verdict on a run it did not judge, a difference only on a flake. Recommendation: (a), with D1 and
D4 in one sitting. Until then the script reads today's trampoline as before
(`test_a_trampoline_that_hands_on_neither_name_is_read_as_before_958`).

**D4 (line 8). What should the trampoline's concurrency comment say?** The words, for lines 27-28:
"one group per judged head for an event's judgement, and one per run id for a dispatch (a hand
re-judge, the sequencer's, the sync's): an event's judgements of a head run one at a time; a
dispatch may run beside them, which is safe because every judgement judges the newest stage R run
of its head (one verdict per head), and beta's strict protection bounds a slower one posting
last." The other way, a group keyed by head for a dispatch too, needs the dispatch to pass the
head (a new input every dispatcher must fill): a design line, not recommended. What it costs: a
comment's sitting; no caller sees it. Recommendation: the words, folded into the sitting of D1 and
D3; `stage_j_holds_its_named_rules_97`'s plant "one concurrency group per head" re-read against
them.

**D5 (line 9). Should a cancelled newest stage R run displace an older run's standing verdict of
the same head?** Today it does: the cancelled run is the newest completed one, its judgement is
`NOT JUDGED: stage R ended cancelled`, posted with `post` `yes` over the `GREEN` (row 15, pinned
as it stands). The ways: (a) as today; (b) a cancelled newest run posts `unless-standing`, as a
dispatch whose artifact is gone does (one line in `_artifact_files`); (c) `resolve` passes over
cancelled runs. What each costs a caller: (a) a hand dispatch someone cancels turns a green pull
request red until a re-run completes; (b) nothing where a verdict stands, and a head with no
verdict still reads `NOT JUDGED`; a standing `RED` also stays, as it should; (c) makes a cancelled
run invisible and gives a head whose only run was cancelled an older run's verdict or none, a
wider change. Under (b) no head earns a green it did not: the standing verdict is of the same head
sha. Recommendation: (b), by the captain's word, with row 15's test turned to it.

## Left, and why

- A `report` whose answer is no object (a run record that is a JSON array) ends in a traceback and
  exit 1, posting nothing; `judge` turns the same into `NOT JUDGED: the judge failed`. It fails
  closed and was not on the bucket; `owed` reads it as `yes`.
- The reads of one judgement that each answer just under their timeout can still pass the judge
  job's ten minutes after the longest wait (360 s of the 600, then the judging's own reads and git
  commands); the job's timeout then cancels it and `report` posts `NOT JUDGED: the judge job ended
  cancelled`, as before. A whole-judgement deadline would close it; not built.
- The live witnesses (a fork's stage R run whose mint step is skipped; a hung call on a runner) are
  after the sitting, CI's.
