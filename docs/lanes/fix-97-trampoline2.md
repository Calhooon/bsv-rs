# Lane fix-97-trampoline2: the trampoline asks before it mints, and hands `report` the run judged (2026-11-14)

Started from `origin/beta` at `80532565d6b855900f0b7c66e56b4877fa4b2dd4`, which carries the judge's
script with `owed` and the run binding (`22ee5df2`, fix-958-judge) and the sync's bounded wait
(`42f5c7a4`). `origin/main` read `5758287ded86b18bbfe88bde3fc0700a6d3bb7fb` at the rehearsal, its
trampoline byte for byte beta's. Nothing pushed, nothing written to GitHub; two reads by `gh api`
(the pinned token action's `action.yml`, beta's `required_status_checks`).

The three decisions `docs/lanes/fix-958-judge.md` left for the trampoline's own sitting are built
in one commit, `ci: the trampoline asks before it mints, and hands report the run judged (#958)`,
which touches `.github/workflows/sibling-judge.yml` (38 lines added, 10 removed) and its pin,
`tests/arch_ci_sibling_judge_97.rs`, and nothing else. No other workflow moved. By the judge's own
rule (`class_of`) both paths are class J and this record, `CHANGELOG.md`, `tests/CLAUDE.md` and
`tests/sibling/CLAUDE.md` are class N, so the pull request reads `JUDGE CHANGE`. `RELEASING.md` is
class C and cannot ride a class J pull request (`classify` refuses J with C): its one sentence is a
patch for a pull request of its own, `releasing-step-25.patch` in the lane's folder
(`/Volumes/Lanes/out/bsv-rs/fix-97-trampoline2/`), tested with `arch_ci_lines` applied (21 passed)
and left off this branch.

## What changed, by decision

- **D1, the half that needs no setting.** `report` gains a step before the mint, `Is a check owed`
  (id `owed`): beta's `sibling_judge.py owed` under the job's own token. The mint and the post
  carry one condition, `steps.owed.outcome != 'success' || steps.owed.outputs.owed != 'no'`. They
  are skipped only when the asking succeeded and answered a plain `no`. The asking is
  `continue-on-error: true` with `timeout-minutes: 3` (its four reads are bounded at 30 s each by
  the script, 120 s): a step that fails, hangs, or writes no answer leaves the condition true, so
  `report` runs and decides as it did. Fix-958-judge's proposal read the answer alone
  (`steps.owed.outputs.owed != 'no'`) with no `continue-on-error`: a failed asking would then have
  ended the job with no check, since a step with no status function runs only after success. The
  outcome clause and `continue-on-error` close that.
- **D3.** `judge`'s `outputs:` gain `run` and `attempt` (six now), and the Report step's `env:`
  gains `JUDGED_RUN` and `JUDGED_ATTEMPT` from `needs.judge.outputs`. The script read them already
  (`judged_of`, `command_report`).
- **D4.** The concurrency comment's opening sentence is fix-958-judge's words; the sentence on the
  one pending run per group stays. The header says six outputs and names the asking.

## The three lenses, line by line

Line numbers are the new file's. "Line" in the last column is a line of the trampoline unless a
file is named; `sj` is `.github/scripts/sibling_judge.py` on beta.

| # | The line | The lens | The finding | Holds by |
|---|---|---|---|---|
| 1 | 8-13, 29-36 (comments) | the key | holds: no expression in either comment, nothing evaluated | the text; `expressions_in_run` reads no `${{` in them |
| 2 | 8-13, 29-36 | GitHub | holds: the comment's claims are GitHub's documented rules (one pending run per group; a group keyed by `head_sha` for `workflow_run`, by `inputs.run_id` for a dispatch, line 38) | line 38; the page "Control the concurrency of workflows and jobs" |
| 3 | 29-33 ("beta's strict protection bounds a slower one") | failing closed | holds by a setting: `strict: true` on beta, read 2026-11-14 | `gh api repos/Calhooon/bsv-rs/branches/beta/protection/required_status_checks --jq .strict` |
| 4 | 56-57 (`run`, `attempt` outputs) | the key | holds: `judge` holds no key; the values are `write_outputs`' `int()` or empty, never text of the artifact | `sj:1012`; lines 42-82 name no secret (`judge_refusals`) |
| 5 | 56-57 | GitHub | holds: a job output is a string, empty when the step wrote none or the job did not run; `steps.judge.outputs.*` on both events | "Passing information between jobs"; line 68 (`id: judge`) |
| 6 | 56-57 | failing closed | holds: all six are written in one write; a missing pair with a success is `NOT JUDGED` | `sj:1109-1114`; `ReportBound.test_a_success_that_names_no_run_is_not_judged_and_a_failure_that_names_none_is_posted_958` |
| 7 | 108-109 (the step, its id) | the key | holds: the step is before the mint and names no secret and no `steps.token`; the code is beta's script, the code that already runs with the token in `Report` | lines 122-129 come after; `owed_and_bound_refusals` ("before the mint names the key or the token") |
| 8 | 108-109 | GitHub | holds: steps run in order; `steps.owed` is read only by later steps of the same job | lines 124, 132 |
| 9 | 108-109 | failing closed | holds: the step posts nothing and writes one line, `owed=yes` or `owed=no` | `sj:1161-1185`; `Owed` (5 tests, no write to GitHub) |
| 10 | 110 (`continue-on-error: true`) | the key | holds: no key in reach of the step; a failure of it cannot stop the later steps' post-run revocation, which belongs to the mint | line 125 (the action's post step) |
| 11 | 110 | GitHub | holds: a failed step under `continue-on-error` leaves `outcome` `failure`, `conclusion` `success`, and `success()` true for later steps | "Contexts", `steps.<id>.outcome`; line 124 reads `outcome`, never `conclusion` |
| 12 | 110 | failing closed | holds: without it a failed asking ends the job with no check; with it the mint and the post run | line 124; the plant "a failed asking ends the job" |
| 13 | 111 (`timeout-minutes: 3`) | the key | holds: no key | none needed |
| 14 | 111 | GitHub | holds: a step that passes its timeout fails; whether its `outcome` reads `failure` or `cancelled` is not verified, and both are `!= 'success'` | line 124 |
| 15 | 111 | failing closed | holds: a hung asking becomes owed inside 3 of the job's 10 minutes; the script's own bound is 4 reads of 30 s | `sj:143` (`GH_SECONDS`); line 89 (`timeout-minutes: 10`) |
| 16 | 113 (`GH_TOKEN: ${{ github.token }}`) | the key | holds: the job's own token, read-only by the job's `permissions:`; not the App's | lines 91-94 |
| 17 | 113 | GitHub | holds: `github.token` is set on both events; its three reads (`actions/runs`, the workflow's runs, `commits/<sha>/pulls`) are the ones `judge` makes with the same permissions | lines 47-50 and 91-94, the same three reads |
| 18 | 113 | failing closed | holds: a token that cannot read gives `GitHubError`, read as `yes` | `sj:1175-1177`; `Owed.test_a_read_that_fails_answers_yes_958` |
| 19 | 114 (`RUN_ID`) | the key | holds: through `env:`, never a shell line; checked by the regex at line 118, then `type=int` | lines 116-120; `expressions_in_run` |
| 20 | 114 | GitHub | holds: `github.event.workflow_run.id` on `workflow_run`; empty on a dispatch, where `inputs.run_id` is taken (a writer's input, a string) | line 114, as lines 71 and 135 |
| 21 | 114 | failing closed | holds: a malformed id fails the asking, read as owed; `Report`'s own regex (line 149) then fails the job with no check, as before this change | line 149 |
| 22 | 115 (`REPOSITORY_ID`) | the key, GitHub, failing closed | holds on the three: GitHub's constant on both events, through `env:`, `type=int` | `github.repository_id`; `sj:1335` |
| 23 | 116-120 (the `run:` block) | the key | holds: no expression in the block; `python3 -I -B` on beta's checkout (`persist-credentials: false`), the one script path the other two commands run; its inputs are the run's record and the pulls, as GitHub answers them, compared and never executed or written to an output | lines 96-102; `sj:716-739,763-799`; the output line is the constant `owed=yes` or `owed=no` (`sj:1180`) |
| 24 | 116-120 | GitHub | holds: `GITHUB_OUTPUT` and `GITHUB_REPOSITORY` are the runner's on both events; `set -euo pipefail` under the default bash | line 117 |
| 25 | 116-120 | failing closed | holds: `no` only on `Silent`, raised by the two functions `report` calls; every other path `yes`; an output that cannot be written exits 1, read as owed | `sj:1168-1185`; `Owed.test_each_silence_of_report_answers_no_with_its_line_958` (the two agree on six silences) |
| 26 | 124 (the mint's `if:`) | the key | holds: the condition can only keep the key from being read; the step's code and inputs are unchanged | lines 125-129 |
| 27 | 124 | GitHub | holds: an `if:` with no status function is `success() && (...)`; `outcome` is the result before `continue-on-error`; an unset output is the empty string; `!=` on strings ignores case, and the script writes lower-case `no` alone | "Expressions"; `sj:1173` |
| 28 | 124 | failing closed | holds: skipped only on `success` with `no` (the truth table of eight pairs in the arch test); a skipped mint has minted nothing, so nothing is left unrevoked | `the_trampoline_asks_before_it_mints_and_hands_report_the_run_judged_958` |
| 29 | 132 (the post's `if:`) | the key | holds: the token is read by this step alone (line 134), as before | line 134 |
| 30 | 132 | GitHub | holds: the same expression as line 124, so the two steps are skipped together; a failed mint still skips the post (implicit `success()`), as before | lines 124, 132 |
| 31 | 132 | failing closed | holds: a skip here is `report`'s own silence (`Silent`, exit 0, no check) taken one step earlier; one window is new, below | `sj:1090-1092` |
| 32 | 144-145 (`JUDGED_RUN`, `JUDGED_ATTEMPT`) | the key | holds: through `env:`; digits or empty from a job that holds no key; read by `NUMBER.fullmatch`, never a shell line | `sj:1064-1079`; `expressions_in_run` |
| 33 | 144-145 | GitHub | holds: `needs.judge.outputs.*` is the empty string when `judge` failed, was cancelled or skipped (`report` runs under `always()`, line 87); an `env:` entry with an empty value is set, empty | line 87; "Contexts", `needs` |
| 34 | 144-145 | failing closed | holds: a mismatch, a name that does not read, one name of two, or a success naming no run is `NOT JUDGED`; neither name set is read as before this change; no path gains a `success` | `sj:1108-1123`; `ReportBound` (10 tests) |
| 35 | 124, 132 with beta's script | failing closed | holds by a setting: `no` is whatever beta's script answers, and who merges into beta is beta's protection (a pull request, admins held), as for every line of the script | `gh api repos/Calhooon/bsv-rs/branches/beta/protection` |
| 36 | 108-132 inside `report` | the key | holds by a setting: the job, the asking included, starts only once the environment `sibling-judge` admits it (`main` alone) | the environment's deployment branch policy; the sweep's last line reads it back |

Counts: 36 rows; 33 hold by a line of the file or the script, 3 hold by a setting outside every
file (rows 3, 35, 36), 0 do not hold.

What the rows do not make disappear, stated:

- **The new window (D1's cost, fix-958-judge's words).** A newest stage R run still running when
  `owed` reads and completed when `report` would have read is now silence, where `report` posted
  `NOT JUDGED: the judge posted nothing where a check is owed`. It ends with no check, never a
  green. That run's own judgement posts unless a token started it; the sweep names the head
  (`check absent`, with its re-judge).
- **A mint with no post remains** in two places: an `unless-standing` verdict over a standing
  check (the token reads the check runs), and an asking that failed for a run owed nothing.
- **Between beta's landing and main's pick** main runs the older trampoline against beta's script:
  every judgement reads `NOT JUDGED: the trampoline on main differs from beta's` (the script's
  comparison), and the older file hands on neither name, read as before.
- **The ways `report` ends**, after this change: no check (the asking's plain `no`; `Silent` in
  `Report`; a failed mint; a read `Report` cannot make; a malformed run id), `NOT JUDGED` (every
  failure of `judge` or of its outputs, a mismatch of the run judged), a verdict of `judge`
  (`RED`, `REFUSED`, `GREEN`, `JUDGE CHANGE`). A `success` is posted on one path alone, unchanged:
  `judge` succeeded, its outputs read, the title is `GREEN` or opens `JUDGE CHANGE: `, and since
  this change the run and attempt named are the ones `report` resolves.

## RED before green

`tests/arch_ci_sibling_judge_97.rs` over beta's trampoline, in a scratch worktree of `80532565`
with the file overlaid and a target dir of its own (`red-arch-97.log`): 3 of 10 RED.

- `the_two_workflows_of_the_judge_are_pinned_whole_97`: `line 8`, expected `... writes six
  outputs, ...`, found `... writes four outputs; ...`.
- `stage_j_holds_its_named_rules_97`: `` `judge`'s outputs are not the six ``, `` `report` lacks
  one of its three steps after the checkout ``, `the three commands are not beta's ...`.
- `the_trampoline_asks_before_it_mints_and_hands_report_the_run_judged_958`: the same two of
  `owed_and_bound_refusals`.

On the tip 10 of 10 (`green-arch-97.log`). The rules and their plants, each refused by name on the
file's own text: the mint without its condition; the post without it; the condition as
`== 'yes'` (an unreadable answer would skip); the condition without its outcome half (a failed
asking's `no` trusted); `continue-on-error` dropped from the asking; `continue-on-error` put on
the post; the asking under the App's token; the asking without a timeout; the asking running
another command; the asking renamed; a step condition in `judge`; either output dropped;
`JUDGED_RUN` dropped; `JUDGED_ATTEMPT` reading the event's attempt; and the asking moved below the
mint. `expressions_in_run` now takes a `run:` key at a step's column alone, since `judge` has an
output named `run`; its two older plants (an expression in a `run:` block) still refuse.

The script's side is fix-958-judge's and unchanged: `python3 -B -m unittest discover -s
.github/scripts -p 'test_sibling_*.py'` runs 215 tests before and after (142 of the judge, 73 of
the harness).

## Main's pick, rehearsed

On a scratch worktree of `origin/main` (`5758287d`), removed after (`main-rehearsal-pick.log`,
`main-rehearsal-arch.log`): `git cherry-pick -x 47a953bb` stops on
`tests/arch_ci_sibling_judge_97.rs` (deleted in HEAD: main carries no copy of the pin), `git rm`
of it and `--continue` leave one file changed, 38 added and 10 removed; the file then equals this
branch's (sha256 `ecc760af...484a29`); `actionlint -no-color` exits 0; main's three arch binaries
pass (`arch_ci_lines` 7, `arch_ci_pr_runs_the_required_set` 15, `arch_secrets_scan_scope` 1);
main's one Rustfmt line passes. The commands, with `<sha>` the commit's sha on beta after its
landing (a rebase merge gives it a new one):

```sh
git fetch origin && git switch -c pick/958-trampoline2 origin/main && git cherry-pick -x <sha>
git rm -q tests/arch_ci_sibling_judge_97.rs && git -c core.editor=true cherry-pick --continue
git diff --exit-code origin/beta HEAD -- .github/workflows/sibling-judge.yml && actionlint -no-color && cargo test --test 'arch_*'
```

## The sitting's order

1. Hold the queue. Beta's pull request from this branch: its own check reads `JUDGE CHANGE`
   (class J; main's trampoline still equals beta's base, so it is judged). Land it by a rebase
   merge, so the `ci:` commit stays one commit.
2. Within minutes, main's pick by the three commands above, its pull request and landing. While
   the two files differ every head reads `NOT JUDGED: the trampoline on main differs from beta's`.
3. The sweep from beta's checkout: `python3 -I -B .github/scripts/sibling_judge.py sweep
   --repository Calhooon/bsv-rs --app-id 5700082`.
4. One re-judge for each open pull request, the command the sweep prints for it
   (`gh workflow run sibling-judge.yml --repo Calhooon/bsv-rs --ref main -f run_id=<run>`).
5. The witnesses, `witnesses/INDEX.md` in the lane's folder with its patch (a words-only head,
   never merged): (1) a stage R run owed nothing, whose `report` job reads `Mint the App's token:
   skipped` and `Report: skipped` with `sibling_judge: owed no` in the asking's log; (2) a run
   owed a check, minted and posted, the Report step's `env:` reading `JUDGED_RUN` and
   `JUDGED_ATTEMPT: 1`; (3) a re-run of stage R, `JUDGED_ATTEMPT: 2` and `GREEN`; (4) a newer run
   completed between the jobs, made certain by re-running the `report` job alone of an older
   judgement after a newer stage R run completed: `NOT JUDGED: a newer stage R run of the head
   completed after the judge read it`, then the re-judge it names; (5) the sweep.
6. `RELEASING.md` step 25's sentence, `releasing-step-25.patch`, in a pull request of its own
   (class C).

## Left for the owner: `client-id`

The pinned action (`64ab729a`, v3.3.0) takes `client-id` and marks `app-id` deprecated (its
`action.yml`, read at the pin). The change, once the owner has added the variable
`SIBLING_JUDGE_CLIENT_ID` (the App's client id) to the environment `sibling-judge`, beside
`SIBLING_JUDGE_APP_ID`, which stays (the Report step's `APP_ID` and the sweep read the numeric id):

```diff
-          app-id: ${{ vars.SIBLING_JUDGE_APP_ID }}
+          client-id: ${{ vars.SIBLING_JUDGE_CLIENT_ID }}
```

in `.github/workflows/sibling-judge.yml` (the mint's `with:`) and the same line in
`tests/arch_ci_sibling_judge_97.rs`, twice: the pin `SIBLING_JUDGE` and `judge_refusals`' list of
the token step's inputs. One sitting again: beta, main's pick, the sweep. Not built here.

## Not verified

- Any of it live: no run of the new file exists until main carries it. The witnesses are CI's.
- That a step ended by `timeout-minutes` reads `outcome` `failure` (row 14); `cancelled` is closed
  the same way.
- That GitHub hands a re-run `report` job the outputs of the `judge` job it did not re-run
  (witness 4); the index names the other reading.
- That an `env:` entry with an empty value reaches the script as set and empty (row 33). If it
  were unset, `judged_of` reads the pair as absent and `report` reads the outputs as before this
  change, which is today's behaviour.
- That GitHub never withholds the outputs `run` or `attempt` as a possible secret (digits; the
  judge job holds none). Withheld, the pair is one name of two or none with a success: `NOT
  JUDGED`.
