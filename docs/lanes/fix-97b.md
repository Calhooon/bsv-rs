# Lane fix-97b: the node oracle's judge wired (#97, lane 2 of 2)

Started from `origin/beta` at `4dc92be39b6feb3df9660a667526d7dace380a59` (the judge lane, PR #925,
landed there: `tests/sibling/PIN`, `sibling_judge.py`, `sibling_harness.py raw` and `checks`'
`judge-tests` gate present); rebased during the lane onto `ad43c2694385c29ea7eadf7281a4795da073cf64`
(#886, PR #898, which landed meanwhile: two conflicts, the CHANGELOG's entries and `tests/CLAUDE.md`'s
rows side by side, both kept). Nothing is made required: `REQUIRED_ON_BETA`, RELEASING's step 2 and
root rule 7's set do not move; no protection, environment, ruleset or App was touched, nothing was
dispatched or pushed.

## The commits

1. The opening items from lane 1's three reads (`.github/scripts/`, the manual, the import
   allowlist of `tests/arch_ci_sibling_judge_97.rs`), ahead of the wiring so the trampoline's
   commit stays one file.
2. T, `.github/workflows/sibling-judge.yml` alone: the commit `main` takes by
   `git cherry-pick -x`.
3. W, `.github/workflows/sibling-run.yml`, the pins (`tests/arch_ci_sibling_judge_97.rs`,
   `tests/arch_ci_lines.rs`' shape test) and the records (CHANGELOG, RELEASING step 25 and the
   direction rule's sentence, the manual, the root `CLAUDE.md`, `docs/ARCHITECTURE.md`,
   `tests/CLAUDE.md`, this file).
4. S, the sync's dispatch step, its `STATED` row and its pin (`SYNC_STAGE_R`, whole since the fold): the commit `main` takes by a pick
   of its own carrying the workflow's step alone: `tests/support/nightly_cap_rules.rs` and
   `tests/arch_ci_lines.rs`' pin are dropped there (the first absent on main, the second a test,
   which the direction rule's sentence keeps off main: "no test"; the rule read of PR #931).

## The opening items (the captain's, 2026-11-13, from the three reads of PR #925)

- The strength read's FIX lines: `StampAndRecord` pins each of the nine comparisons of the stamp
  and the run's record alone and the dispatch's stamp naming no pull request; each comparison
  removed in a scratch copy turns a test RED (nine of nine). Every split of corpus, words, log and
  manifest text is on a line feed alone (`sibling_harness.lines_of`; `str.splitlines` also splits
  on U+0085, U+2028 and U+2029, which JSON holds raw in a string; the class: `read_words_text`,
  the log reader, `drop_withheld`, `rewrite_dependency`, `command_summary` and the judge's
  `Facts`), RED on the unchanged scripts; no corpus file at the pin holds such a character (every
  `corpus/**/*.jsonl` counted), so no column moves. The branch name is `shlex.quote`d in the
  re-push act and the sweep's act (RED: a branch `lane/x;touch $(id) 'y'` read back whole).
- The strength read's row: stage R uploads with `overwrite: true`, and the judge counts only an
  artifact created at or after the judged attempt's `run_started_at`; `Rerun` shows a re-run
  judged GREEN whether the earlier artifact was replaced or is still listed (RED before: `NOT
  JUDGED: 2 unexpired sibling-raw artifacts, not one`), and an earlier attempt's artifact alone
  `NOT JUDGED`.
- The rule read's R2: stage R runs beta's `sibling_harness.py` (from `judge/`, on the head's
  tree), said so by the script's docstring and the manual (`StageRScript`) and held in the
  workflow by `run_refusals` (a script outside `judge/` refused). Beta's, because a J diff must
  not change the script that writes its own artifact.
- The rule read's R3: `standing()` counts a check only when its app id is the configured one
  (`Standing`: no app, a null app, an app without an id and another App's each not standing, RED
  before on the first).

## Rows left

- R1 of the rule read (stays a row): the class-N guard of `tests/arch_ci_sibling_judge_97.rs`
  reads the `include!` family alone (`include_str!`, `include_bytes!`, `include!`); a `build.rs`
  or a proc macro that reads `CHANGELOG.md`, a `docs/` file or a `CLAUDE.md` by `std::fs` is not
  seen, so class N's "cannot move a verdict" rests on the reads of such a change.
- `report` runs `gh api` with the App's token for its reads too (the run, `commits/<sha>/pulls`,
  the superseding runs, the standing check), where the token holds `permission-checks: write`
  alone (the brief's token inputs). On a public repository an installation token is expected to
  read these; if it does not, `report` exits 1 and posts nothing, which the captain's E1 shows.
  The script holds one GitHub client and reads its token from `GH_TOKEN`; giving `report` the
  job's `GITHUB_TOKEN` for reads would be a change of the judge's script (a J diff).
- Stage R checks beta out when it runs and the judge when it judges: if beta moves between them,
  stage R ran an older beta script than the one that judges. The judge's head-holds-beta rule
  refuses the head then (the head lacks beta's new tip), so no verdict is posted on a mismatch,
  but a refusal of that kind reads `REFUSED: behind beta`.
- `actions/create-github-app-token` v3.3.0 marks `app-id` deprecated for `client-id`: the step
  runs with an annotation. `client-id` is the App's client id, another value than 5700082 and
  another variable; moving to it is the owner's (the environment's variables).

## The pin read

`gh api repos/actions/create-github-app-token/releases/latest` read `v3.3.0` (published
2026-10-12T23:42:23Z, not a prerelease); `gh api repos/actions/create-github-app-token/git/ref/tags/v3.3.0`
read a commit, `64ab729a6294000f5aa4a4bc0b73d1f32bc45510`; its `action.yml` at that commit takes
`app-id`, `private-key` and `permission-checks`, runs on node24. Read 2026-11-12.
`actions/upload-artifact` is the repository's own pin (`ea165f8d...`, v4.6.2, which carries
`overwrite`).

## What this lane could not show, and who shows it

Each the captain's, after a landing (the brief's acts B to H), but the last:

- `workflow_run` firing from main for a workflow main lacks (`sibling-run.yml` lives on beta alone).
- A dispatch of a workflow the default branch lacks (the sync's step; stage R by hand).
- The environment `sibling-judge` admitting the `workflow_run` job on main, and refusing a branch
  off main.
- The App's installation and its token (minted with `permission-checks: write`).
- Which of two check runs of one name the protection reads.
- A re-run's artifact list as GitHub answers it (`overwrite: true` replacing, or both listed).
- A `GITHUB_TOKEN` dispatch raising `workflow_run` for the trampoline.
- A token step that fails: the owner's hand alone, not asked.
