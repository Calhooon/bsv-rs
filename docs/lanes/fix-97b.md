# Lane fix-97b: the node oracle's judge wired (#97, lane 2 of 2)

Started from `origin/beta` at `4dc92be39b6feb3df9660a667526d7dace380a59` (the judge lane, PR #925,
landed there: `tests/sibling/PIN`, `sibling_judge.py`, `sibling_harness.py raw` and `checks`'
`judge-tests` gate present); rebased during the lane onto `ad43c2694385c29ea7eadf7281a4795da073cf64`
(#886, PR #898, which landed meanwhile: two conflicts, the CHANGELOG's entries and `tests/CLAUDE.md`'s
rows side by side, both kept). Nothing is made required: `REQUIRED_ON_BETA`, RELEASING's step 2 and
root rule 7's set do not move; no protection, environment, ruleset or App was touched, nothing was
dispatched or pushed.

## The commits

Twelve, in this order, each green by itself; `main` takes two of them by `git cherry-pick -x` (the
direction rule's sentence of 2026-11-12) and nothing else:

1. O, `fix(ci): the judge's opening items from lane 1's three reads (#97)`: `.github/scripts/`,
   the manual, the import allowlist of `tests/arch_ci_sibling_judge_97.rs`, ahead of the wiring
   so the trampoline's commit stays one file. Beta alone.
2. T, `ci: the node oracle's trampoline, sibling-judge.yml (#97)`: `.github/workflows/sibling-judge.yml`
   alone. **`main` picks it whole.**
3. W, `feat(ci): stage R of the node oracle's judge, its pins and its records (#97)`:
   `.github/workflows/sibling-run.yml`, the pins (`tests/arch_ci_sibling_judge_97.rs`,
   `tests/arch_ci_lines.rs`' shape test) and the records (CHANGELOG, RELEASING step 25 and the
   direction rule's sentence, the manual, the root `CLAUDE.md`, `docs/ARCHITECTURE.md`,
   `tests/CLAUDE.md`, this file). Beta alone.
4. S, `ci: the sync workflow starts stage R on its branch (#97)`: the sync's dispatch step, its
   `STATED` row and its pin (`SYNC_STAGE_R`, whole since the fold). **`main` picks it carrying
   the workflow's step alone**: `tests/support/nightly_cap_rules.rs` and `tests/arch_ci_lines.rs`'
   pin are dropped there (the first absent on main, the second a test, which the direction rule's
   sentence keeps off main: "no test"; the rule read of PR #931).
5. `fix(ci): the judge's boundary at an attempt's start pinned, its re-push act printed on two lines (#97)`
   (the fold's items 2 and 3). Beta alone.
6. `docs(#97): the fold's records: the sync's step pinned whole, the judge's suite at 88`. Beta alone.
7. `docs: the rule read of PR #931: root rule 10 names the judge's two picks, ...` (the rule
   read's documents, `cherry-pick -x aff611c3`). Beta alone.
8. `fix(ci): the judge's two time comparisons pinned at the second: ...` (the second fold's
   item 1). Beta alone.
9. `docs(#97): the second fold's records: ...` (this list and the two fold sections). Beta alone.
10. `test(ci): every variable the sync's stage R dispatch reads defined once, where the pin says (#97)`
    (the second fold's item 2), placed last because it is S's pin. **`main` does not pick it**:
    it touches `tests/arch_ci_lines.rs` alone, the file S's pick already drops, and the direction
    rule keeps every test off `main`. Main's copy of the step is held by the pick of S's bytes
    and, on beta, by this test over the file both lines carry (the sync workflow fires from
    `main`; `main-in-beta` keeps beta's copy equal). If the owner ever lets S's pin reach `main`,
    this commit travels with it, picked right after S.
11. `fix(ci): the judge compares its two times as times, a time that does not parse not judged (#97)`
    (the third fold's item 1: `sibling_judge.py`, its tests, `datetime` on the import allowlist
    of `tests/arch_ci_sibling_judge_97.rs`, the records of item 1). Beta alone.
12. `test(ci): the sync workflow pinned whole by its digest (#97)` (the third fold's item 2:
    `tests/arch_ci_lines.rs`, `fnv` moved into `tests/arch_support/mod.rs` and shared by
    `arch_field_writes_843.rs` and `arch_non_exhaustive_pins_819.rs`, their digests unchanged;
    the records of item 2 and this list). Beta alone, for the reason of 10: tests alone.
    `main` needs nothing of either. Main's `tests/arch_ci_lines.rs` (484 lines at `origin/main`)
    checks the sync workflow by needles (fires on main, `-x`, no merge, rebase or squash, the
    branch and its label) and holds neither `SYNC_STAGE_R`, the definition scan nor the digest,
    and main has no `tests/arch_support/`; main's copy of the workflow is S's step picked onto
    main's file, held on beta by the digest through `main-in-beta` (the sync fires from main,
    and beta carries main's commits).

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

## The fold (2026-11-13, after the three reads of PR #931, all accept)

- The sync's step pinned whole (the strength read's FIX): `SYNC_STAGE_R` holds ci.yml's dispatch
  step and the stage R step byte for byte to the job's end and `sibling-run.yml` named once, in S
  (an amend: the pin lives in S's own file). RED: the read's three plants (`--ref beta`, the
  `if:` dropped, the step moved ahead of ci.yml's) pass the old needle and are each refused by
  the pin's message; kept as `a_sync_stage_r_dispatch_retargeted_unconditioned_or_moved_is_refused_97`.
- The boundary at an attempt's start (`sibling_judge.py`, `>=` to `>` survived): an artifact
  created at the instant the attempt started is judged, RED under `>`.
- The re-push act: `clean()` turned its line break into `?`, so a pasted act was one comment
  line; each line is cleaned apart and the branch before it is quoted, RED before (`1 != 2`).
- The rule read's documents commit picked last (`aff611c3`, a conflict in this file kept both
  sides).

## The second fold (2026-11-13, after the re-read of the fold: FIX, two plants slipped)

Rebased onto `origin/beta` at `f549192a` (the 0.8.9 sync, with the security release's commit
under it): one conflict, the CHANGELOG's `[Unreleased]` entries, both kept, the security entry
above this one. Beta moved during the fold (#843d23 and the `source_txid` refusal), and the
branch was rebased again onto `8719c7aa`: one conflict, the root `CLAUDE.md`'s rules 10 and 11
side by side, this branch's rule 10 (the judge's two picks) and beta's rule 11 (the foreign-type
clause) both kept. T names one file, its bytes those of `5192c478`; S carries its step and its pin
together, as before.

- Item 1, the start cut to the minute (`a["created_at"] >= started[:16]` passed all 88 tests:
  `Rerun`'s start sat on a minute). The start moves to `10:00:30Z`;
  `test_the_attempts_start_is_judged_to_the_second_inside_its_minute` leaves out an earlier
  attempt's artifact made earlier in the same minute (`10:00:10Z`) beside one a second after,
  reads one a second after alone, and leaves out one a second before alone. The sweep of every
  time comparison in `sibling_judge.py`:

  | Comparison | Equal | One second before | One second after | Same minute |
  |---|---|---|---|---|
  | artifact `created_at` against the attempt's `run_started_at` (`:829`) | held (the instant test) | held (new) | held (new) | held (new) |
  | the trampoline's last commit time on `main` against beta's (`:456`, which line is behind) | held (new) | held (new) | held (new) | held (new: a minute earlier; the left side cut to the minute RED) |

  Two comparisons, eight boundaries: one held before this fold, seven by its two tests. The
  other comparisons of the script are counts, sizes, ids and attempts, no time. RED (the scratch
  copy, `/Volumes/Lanes/out/bsv-rs/fix-97b-fold2/item1-red.log`): the minute cut on the start
  alone and on both sides fail four subtests each; `>=` to `>` fails the instant test; a later
  minute or equality fails two; `<=` to `<` fails the same second, `<=` to `>=` three, the left
  side cut to the minute the second after. Stated, not changed: the script compares the two
  ISO texts as strings, which is the timestamps' order while GitHub writes both without
  fractional seconds, as it does.
- Item 2, a job-level `SYNC_BRANCH: beta` redirected the dispatch with every pinned byte
  standing. `SYNC_STAGE_R_READS` names every variable the pinned steps read (the `run:` lines'
  `$NAME` and the steps' `env:` keys, held equal to the pin's by the test) with where it is
  defined: `SYNC_BRANCH` once, in the workflow's top-level `env:`, as `sync/main-into-beta`;
  `GH_TOKEN` in a step's own `env:` alone, as `${{ github.token }}`; `GITHUB_REPOSITORY` nowhere
  (the runner's); and since `gh` reads its `GH_*` settings without the step naming them (a
  job-level `GH_HOST` would send the dispatch and its token elsewhere), no `GH_*` name but
  `GH_TOKEN` is defined anywhere in the file. A definition is the name as a word followed by a quote at most and then `:` (a
  key, quoted or in a flow mapping) or a lone `=` (an assignment, an `export`, a `$GITHUB_ENV`
  write). `every_variable_the_stage_r_dispatch_reads_has_its_one_definition_97` plants twelve:
  the re-read's job-level `SYNC_BRANCH`, a job-level flow mapping, a quoted job key, the
  workflow's value changed, the definition moved to the job, a `$GITHUB_ENV` write, an `export`,
  a job-level `GH_TOKEN`, a step's `GH_TOKEN` of another value, a defined `GITHUB_REPOSITORY`, a job-level `GH_HOST`, a `GH_REPO` written to `$GITHUB_ENV`.
  RED in the real workflow (`item2-red.log`): the job-level `SYNC_BRANCH`, the `$GITHUB_ENV`
  write, the job-level `GH_TOKEN` and the job-level `GH_HOST` each pass S's test (14 of 14) and are each refused by the
  new rule naming the variable and its lines. The scan reads the spellings it names and no
  others (the second re-read passed a flow mapping with no space after its brace, a multiline
  `$GITHUB_ENV` write and a YAML escape in a key through it); since the third fold every
  spelling is held by the digest of the whole workflow, the scan a readable second check.

## The third fold (2026-11-13, after the second re-read: FIX, three plants slipped)

Rebased onto `origin/beta` at `b36bca93` without a conflict, the ten commits as cut (T names one
file, `sibling-judge.yml`, unchanged; S its step and its pin); this fold's commits come after
them. Logs: `/Volumes/Lanes/out/bsv-rs/fix-97b-fold3/`.

- Item 1, the times compared as times. The script compares two timestamps, no more (every other
  comparison is a count, a size, an id or an attempt number):

  | Comparison | Before | Now |
  |---|---|---|
  | artifact `created_at` against the attempt's `run_started_at` (`_artifact_files`) | the two ISO texts as strings; an absent start skipped the filter | each parsed by `instant` to an aware UTC time and compared as times; a start or a creation time that does not parse `NOT JUDGED`, naming it |
  | the trampoline's last commit time on `main` against beta's (`Judgment.lines`, which line is behind) | `int(out or 0)`, an empty answer read as 0 | `Git.last_change` reads the `%ct` text as a decimal integer of seconds or answers `None`, and a `None` on either line is `NOT JUDGED`, naming the line |

  `Rerun`'s start moves to `10:07:37Z`, on no coarser mark (not on a minute, ten seconds or five
  seconds; 37 is prime, so on no mark of any whole number of seconds from 2 to 36 inside its
  minute). The one-second cell: an artifact made at `10:07:36Z` is the earlier attempt's, beside
  this attempt's at `10:07:37Z` and at `10:07:38Z` in either order; any cut of the start coarser
  than a second lands at or before `10:07:36Z` and admits it (two artifacts, `NOT JUDGED`), and any
  cut of the creation time moves `10:07:37Z` or `10:07:38Z` below the start (none). An offset and
  a fraction read as the instants they name (`11:07:36+02:00`, whose text sorts after the start's,
  is an hour before it). RED on a scratch copy (`item1-red.log`): the re-read's plant (the start
  cut to ten seconds) 6 failures, the first re-read's (to the minute) 6, both texts cut to ten
  seconds 6, the parsed start floored to ten seconds, to two and to the minute 6 each, `>` for
  `>=` 5, the plain string comparison 1 (the offset cell), an unparsed creation time dropped
  silently 3 errors, `int(out or 0)` back 3. 92 tests (90 before).
- Item 2, the sync workflow pinned whole. `SYNC_FILE_DIGEST` (`0x828b_6214_aa7a_399a`, FNV-1a
  of the whole text, line endings normalized, the form #819 pins its macro file by, through the
  one `arch_support::fnv`) beside `the_sync_workflow_is_pinned_whole_by_its_digest_97`, the
  constant's comment telling whoever changes the workflow deliberately to read the change and
  move the constant in the same diff. RED in the real workflow (`item2-red.log`, each plant
  written into `sync-main-into-beta.yml` and the file restored): the second re-read's flow
  mapping with no space (`env: {SYNC_BRANCH: beta}` at job level), its multiline `$GITHUB_ENV`
  write (`SYNC_BRANCH<<EOF`) and its escape row (`"SYNC_BRAN\x43H": beta`) each pass the scan
  (`every_variable_..._97` green) and fail the digest test alone by its message (`its text
  moved (digest ..., pinned 0x828b6214aa7a399a)`). The test plants those three, a job-level
  `HTTPS_PROXY` (the re-read's other row) and a comment. The scan stays as a readable second
  check, and the records say it reads the spellings it names; the digest holds every spelling.
- The bound, one sentence (the test file's header and the CHANGELOG entry say the same): what
  holds the sync's dispatch is the pinned step's text and the digest of the whole workflow; what
  neither sees is a change that edits the workflow and its digest in the same pull request (a
  reviewer's matter, visible in the diff), and a value GitHub keeps outside the file (an
  organization or repository variable, which reaches a job only through a `${{ vars.NAME }}` the
  file would carry, and of which the repository and its organization held none on 2026-11-13:
  `gh api repos/Calhooon/bsv-rs/actions/variables` and `.../actions/organization-variables`
  answered a count of 0; the environment `sibling-judge` holds one, `SIBLING_JUDGE_APP_ID`,
  which no job of the sync names).

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
