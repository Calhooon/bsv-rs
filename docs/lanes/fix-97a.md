# Lane fix-97a: the node oracle's judge on beta, with nothing fired (#97)

Started from `origin/beta` at `5a87392e217ee7e8752bd9e13bbcbfde1496cb53` (the brief was written
against `6bc872d7`; `git diff --stat 6bc872d7 5a87392e -- .github tests/sibling
tests/arch_ci_pr_runs_the_required_set.rs tests/arch_ci_lines.rs tests/arch_ci_docs_only_exit.rs
RELEASING.md` is empty: nothing the brief cites moved). Open pull requests into beta read on
2026-11-12 about 17:28Z: none touches `tests/sibling/` or the `sibling` job's pin (#898 edits
`ci.yml`'s `semver` job alone).

## What neither the issue nor the tree carries

- **2026-11-10, the two-stage decision.** Four of five design reads, then a tie-break, chose
  the judge's shape: a stage R that runs the head's build with no secret and uploads raw output;
  a judge on the default branch that reads it with beta's files and reports as its own App
  (`bsv-rs-sibling-judge`, ID 5700082) from the environment `sibling-judge` (branch policy
  `main` alone; its variable `SIBLING_JUDGE_APP_ID`, its secret `SIBLING_JUDGE_KEY`, which this
  lane never reads and names in no workflow); `pull_request_target` refused; no Actions job may
  report `sibling-judge`; `ci.yml`'s `sibling` stays the oracle of a push to beta and of a tag.
  The same day: zero divergences from the node, no explained row (the owner's ruling), and the
  column's rules (outside a pin change words alone; in a pin change no corpus and no judged
  entry dropped, `withheld` not grown, an unchanged entry's words kept).
- **2026-11-12, three design reads**, folded into the brief's tagged sentences a01 to a35: the
  class table total and ordered, computed from git objects (a04, a13); the head never checked
  out, its PIN and column read as blobs (a09); beta's facts at one sha and the trampoline's file
  compared on both lines (a10, a29); the head holding beta (a23); the pin's place on the
  sibling's `main` by `behind_by` (a15); the stage J staging of the sibling's corpora itself, as
  data (a18); the artifact read in memory by an allowlist, through `gh api` (a07); one artifact
  of the run (a08); the run's state and supersession (a03); `success` or `failure` alone, from
  one line (a02); the three words (a22); the bounded text (a16); the act as a command (a24); the
  two commands and the four outputs (a06); the check created once, completed (a17); the exits
  (a27); the sweep (a21); the dry run (a28); the gate (a20); the reads' limits stated (a01, a25).
- **2026-11-12 about 18:07Z, the owner's word** on the six decisions of `owner-decisions-97.md`
  ("for 97... I like all of your recommendations"): main takes by pick the trampoline and the
  sync step that starts `sibling-run.yml` (and `sibling-run.yml` only if GitHub refuses that
  start without it), written into RELEASING's direction rule by the wiring lane; a scratch
  branch `witness-97` for the forgery witnesses; the Deployments box unticked by the owner;
  `sibling-judge` joins beta's protection after the witnesses and the soak, never before; the
  lift for one repairing merge the owner's alone; no rehearsal rotation of the key.

## What was built

`tests/sibling/PIN`; `ci.yml`'s `sibling` reading it (`pin` step) and `SIBLING_JOB` re-pinned;
`sibling_harness.py raw` and `stage_and_run`; `judge_run` (files as bytes, facts as an
argument); `.github/scripts/sibling_judge.py` (`judge`, `report`, `sweep`, `members`, `pack`,
`judge --dry-run`); `.github/scripts/test_sibling_judge.py` and its fixtures; the `judge-tests`
gate of `checks`; `tests/arch_ci_sibling_judge_97.rs`. The manual: `tests/sibling/CLAUDE.md`,
"The judge" and "What the judge does not hold".

`.github/scripts/test_front_pages.py`'s `Producers` pinned the headline's producer as `print(f"VERDICTS: ...")`; the line is built by `judge_run` now and printed by `compare`, so the test's literal follows it (`lines.append(...)`), the headline's text unchanged.

Two choices of the lane, stated: the class is read from `git diff --raw -z --no-renames
--no-abbrev` (the brief's `--name-only -z --no-renames` plus each side's mode, one command);
the stamp's pin is compared at the stamp check (`NOT JUDGED`, "compared and never used"), the
head's PIN blob against beta's and the sibling's `main` at the pin rule (`REFUSED`).

## RED before green

Rust, on a scratch copy of `5a87392e` (`git archive`, the scratch target
`/Volumes/Lanes/targets/fix-97a-scratch`) with the tip's three test files overlaid:
`arch_ci_sibling_judge_97.rs` 2 of 5 RED (`tests/sibling/PIN: No such file or directory`,
`.github/scripts/sibling_judge.py: No such file or directory`); `arch_ci_pr_runs_the_required_set.rs`
3 of 20 RED (`the sibling job is not SIBLING_JOB byte for byte ... ci.yml line 905`, and the
two plant tables at their edit sites); `arch_ci_lines.rs` 2 of 12 RED (`checks: no step
judge-tests for the gate judge-tests`, `the last step does not judge judge-tests`).

Python, on a scratch copy of the tip's `.github/scripts` per rule, its line removed or made
`if False:`, the test naming it run there: 34 of 34 RED (the rule, the test, the failure:
`/Volumes/Lanes/out/bsv-rs/fix-97a/red-python.txt`): the run's path, head repository, event,
open pull request, base `beta`, head moved, superseded, the trampoline, behind beta, one of
J/P/C, W beside J, the modes, the pin's text, `behind_by`, the column at the pin, words alone,
a pin move keeping words, the run's conclusion, one artifact, `unless-standing`, a symlink
member, the allowlist, the declared size, `..`, the stamp's head, the verdict, the text's
backticks, the text's bound, `report`'s judge result, identity, supersession, standing check,
422 retry and success guard.

## Witnesses on this host

1. The REDs above, then green on the tip.
2. `python3 -B -m unittest discover -s .github/scripts -p 'test_sibling_*.py'`: 147 tests
   (74 of the judge, 73 of the harness).
3. `raw` at the tip (`f47761e1`, the lane's commit before its records; the crate's files are the
   tip's) into a tree, 20 s with a fresh target: exit 0 (the harness's own exit 1, the sibling's
   recorded 0.7.0 words). The tree's allowlisted files zipped by `pack`: 89,835 bytes, 31
   members, 2,447,757 bytes declared, the largest `bsvrs-words/seed.jsonl` at 1,786,434 bytes
   (the bounds: 64 MiB and 16 MiB; the unlisted `spec/` files, up to 1,991,763 bytes, are not
   uploaded). The tree and its scratch deleted, `judge --dry-run` on the zip with head and beta
   the tip: `GREEN` (VERDICTS 13,765 entries, 0 divergences; REASONS 13,765 equal).
4. `src/script/script.rs:193`'s `<` planted as `<=` (a commit object made by `git commit-tree`
   from a scratch index, no checkout): `raw` exit 0; the dry run against the tip as beta `RED`,
   naming `seed-000397` (`spec` and `spec-mempool` `SCRIPT_ERR_BAD_OPCODE` against a panic,
   `index out of bounds: the len is 7 but the index is 7`; REASONS 13,764 equal, 1 differ); the
   headline counts 4 divergences, the two others explained rows of the sibling's rules table.
5. The `sibling` job's steps by hand: the `pin` step's lines read the file, the sibling's
   checkout at the pin, the harness `run` GREEN.
6. `actionlint` 1.7.12 with `shellcheck` on `PATH` over `.github/workflows/*.yml`; `docs.yml`'s
   `uses:` grep.

A real fork's run is not used: the identity table's foreign `head_repository.id` case is its
witness (a30).
