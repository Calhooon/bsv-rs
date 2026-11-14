# Lane fix-958-sync: the bucket #958, the lines about the sync workflow and the tests that pin workflows (2026-11-14)

Started from `origin/beta` at `2b419d90b567dc3a67031741d165875340378afe` (`origin/main` at
`f569499a64a24354644848f7b99b2958f17e21e9`, its `sync-main-into-beta.yml` and `sibling-judge.yml`
byte for byte beta's by `git diff origin/main origin/beta`). Nothing pushed, nothing written to
GitHub; reads by `gh` alone. The bucket's other seven lines (the judge's script, the trampoline,
the environment) are the lane `fix-958-judge`'s and are not read here. This pull request touches
no file of the judge: every changed path is class C or N by `sibling_judge.py`'s `class_of`.

## The table

| # | The line (the bucket's words, cut) | Fate | Evidence |
|---|---|---|---|
| 4 | The sync's wait for stage R can end without its re-judge line: a failed poll under `set -e`, 160 polls past the step's 45 minutes, no guard on the figures | BUILT | `.github/workflows/sync-main-into-beta.yml`, the step `Start the PR's stage R and its judge`; `sync_stage_r_wait` and `the_sync_stage_r_wait_is_bounded_by_the_clock_and_ends_with_its_rejudge_line_958` in `tests/arch_ci_lines.rs`; RED 4 of 20 over beta's workflow (`red-wait-base-workflow.log`); the step under bash with a fake `gh`, seven modes (`harness/base.log`, `harness/tip.log`) |
| 5 | The sync holds its concurrency group through the wait; a third push to main replaces the queued second run, which shows as cancelled | BUILT (the stated way of the line's two) | the workflow's header and `RELEASING.md` step 19; `SYNC_GROUP_STATED` and the group's two lines as needles of `sync()`, two plants in the same test, each seen by the digest. The other way is below, not built |
| 10 | The copy of the sync workflow that runs is main's, and no test on main pins it | NEEDS A DECISION | the question below; nothing built |
| 11 | `run_lines` has no test of its own | BUILT | `run_lines_reads_a_one_line_run_and_every_line_of_a_block_958`, `a_variable_read_only_inside_the_stage_r_block_is_read_958`; RED 2 of 19 on a scratch copy with the block arm removed (`red-runlines.log`) |
| 12 | `RELEASING.md` step 25 lacks the default branch, the visibility, and what main takes of the sync step | BUILT, with one question on its third sentence | `RELEASING.md` steps 19 and 25 and the direction rule, the root `CLAUDE.md` rule 10; `releasing_names_the_settings_that_silence_the_judge_and_the_syncs_cancelled_run_958`; RED 1 of 21 over beta's `RELEASING.md` (`red-releasing.log`); `gh api repos/Calhooon/bsv-rs --jq '{default_branch, visibility}'` answered `main`, `public` on 2026-11-14 |

Counts: built 4, already true 0, needs a decision 1, not a defect 0 (of this lane's five lines).
The logs named are under `/Volumes/Lanes/out/bsv-rs/fix-958-sync/`.

## Line 4: what the step does now

```
status=""
budget=2400
while [ "$SECONDS" -lt "$budget" ]; do
  if ! status="$(timeout 60 gh api ".../actions/runs/${run}" --jq '.status')"; then
    status="unread (its last poll failed)"
  fi
  if [ "$status" = completed ]; then break; fi
  sleep 15
done
```

- A poll that fails is the condition of an `if !`: `set -e` does not end the step, and the next
  turn reads again. A poll that hangs spends its own 60 s and is the same failed poll.
- The bound is the clock. The last turn can start at 2399 s, spend 60 s on its poll and 15 s on
  its interval: 2475 s, 225 s under the step's 2700. The rule in the test holds budget + poll +
  interval at or under the step's minutes less 120 s, and refuses a figure it cannot read.
- The error line names the status and the minutes spent, with the hand command and the run's id.
  The same command is printed before the judge's dispatch, so a refused dispatch (the one failure
  after `completed`) leaves it one line above the failure.
- `SECONDS` is bash's own; `SYNC_STAGE_R_READS` lists it as `Definition::Shell`, defined nowhere in
  the file (an assignment would restart the clock and is refused by the scan of definitions).

The seven modes of the harness (a fake `gh`, a one-second `sleep`, a three-second stand-in for
`timeout`, since this host has no coreutils `timeout`; the clock modes started at `SECONDS=2396`):

| Mode | beta's step | this step |
|---|---|---|
| the run completes at the third poll | exit 0, judge dispatched | exit 0, judge dispatched |
| the second poll fails once | exit 1, no hand command | exit 0, judge dispatched |
| every poll fails | exit 1 at poll 1, no hand command | exit 1, hand command printed |
| the run never completes | exit 1 after 160 polls, hand command printed | exit 1 at the budget, hand command printed |
| poll 1 hangs (20 s) | waits the 20 s (no bound of its own) | the poll cut at its timeout, read again, judge dispatched |
| the judge's dispatch is refused | exit 1, no hand command | exit 1, hand command printed one line above |
| the dispatch answers no run id | exit 1, its own line (no id to name) | the same |

Not witnessed: the step on a GitHub runner (a live sync that pushes picks runs it; the next one
after main's pick is the witness), and coreutils' own `timeout` (the runner's image carries it;
`actionlint` 1.7.12 with shellcheck passes the step).

## Line 5: the way not built

The line gives two ways. Built: the sentence, in the workflow's header and in step 19. Not built:
the wait moved out of the grouped job (the picks and the dispatches in the grouped job, the wait
and the judge's dispatch in a second job in a group keyed by the stage R run). It would end the
cancelled runs and the lag, at the price of a second job with `actions: write`, an output
carrying the run's id between jobs, `SYNC_STAGE_R` no longer "to the job's end", and a file `main`
runs that no live run has exercised before its pick. Nothing is lost today (the newest sync finds
every commit beta lacks), so the sentence is the sure change; the second job stays open as a design
line if the lag is ever felt.

## Line 10: the question (nothing built)

**Question.** Should a required check on `beta` go red while `beta`'s copy of
`sync-main-into-beta.yml` or `sibling-judge.yml` differs from `main`'s?

**The ways, and what each costs.**

1. A step of `ci.yml`'s `main-in-beta` on every pull request into `beta` and every push to it:
   `git diff --exit-code origin/main HEAD -- <the two files>`, a pull request that itself changes
   one of them let through (`git diff --quiet HEAD^1 HEAD -- <files>` on the merge commit), with a
   rule in `tests/arch_ci_lines.rs` that the step exists. Cost: from the landing of such a change
   on `beta` to its pick on `main`, every other pull request into `beta` is red on a required
   check, so the queue is held for that sitting (what step 25 already asks for a trampoline
   change, and would now enforce for the sync too).
2. The same step on a push to `beta` alone. Cost: nothing is refused; `beta`'s tip reads red
   from the landing until the next push after the pick, and a drift is seen only by whoever
   reads the tip's checks.
3. The judge's sweep prints the two blobs' equality (the bucket's own second way). Cost: seen
   only when someone sweeps; it is a change to `sibling_judge.py`, the lane `fix-958-judge`'s
   file, class J.

**Recommendation.** Way 1, for the two files alone: ways 2 and 3 report what the reads already
find by hand and refuse nothing, and the window way 1 holds the queue for is the sitting the
ritual already prescribes. It is not built here because it changes when a required check of the
line goes red for every open pull request, which is the captain's to say, and because this pull
request's own landing would open such a window itself.

## Line 12: the question on its third sentence

The direction rule now names the whole step and says that the wait and the judge's dispatch are a
reading of the owner's word of 2026-11-12 (fix-97c's rule read), not that word. **Question:** does
the owner's word cover the step as `main` carries it since `560e7271`? Yes: the clause "a reading
recorded as such ... not yet written here" is replaced by the date of the confirming word. No: the
wait and the dispatch on `main` stand outside the word and need the owner's own, or leave `main`.
Recommendation: confirm; the step holds no key and judges nothing, and without it a sync pull
request never earns `sibling-judge`.

## The pick to main

`main` takes the workflow file by `git cherry-pick -x` of the commit that changes it (subject
`ci: the sync's stage R wait is bounded by the clock ...`). Rehearsed on `origin/main` `f569499a`
in a scratch worktree: the workflow's hunk applies; `tests/arch_ci_lines.rs` conflicts, as
fix-97c's pick did, because `main`'s copy of the test carries neither `SYNC_STAGE_R` nor
`SYNC_FILE_DIGEST`; resolved to `main`'s test file, the pick is the workflow alone (one file, 16
insertions, 5 deletions, byte for byte beta's after it), and `main`'s arch tests pass on it
(`arch_ci_lines` 7, `arch_ci_pr_runs_the_required_set` 15, `arch_secrets_scan_scope` 1;
`main-rehearsal-arch.log`), `actionlint` clean.

## Left, and why

- A behavioural test of the step in the suite (bash spawned from a Rust test): no test of this
  crate spawns a shell, the Windows cells would skip it, and the host's `timeout` differs from the
  runner's; the harness is a run of the lane, its script and logs kept beside the other logs.
- The cap guard's give-up rule still reads `gh run watch` waits alone
  (`tests/support/nightly_cap_rules.rs`); the sync's wait is held by its own rule instead.
- `tests/sibling/CLAUDE.md` (the judge's manual) is not edited: its sentences on the two settings
  are true, and the file is the other lane's ground.
