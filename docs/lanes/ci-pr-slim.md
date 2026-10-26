# Lane: ci-pr-slim. On a pull request CI runs what decides the merge; the full matrix runs on a push to beta or main and in the nightly (the owner's word of 2026-10-26, through the keeper)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in the worktree cca gives you on a branch from `origin/beta`. Read `CLAUDE.md` (rules 6, 7; the "Where the numbers come from" paragraph names CI's matrix), `RELEASING.md` (the direction rule; the four classes of main patch; the required checks on each line), `docs/lanes/README.md` (the lane rules; everything foreground, under ten minutes; never `~/bsv/bsv-low/` or `~/vault/`), `.github/workflows/ci.yml`, `nightly.yml`, `sync-main-into-beta.yml`, `release.yml`, and every test that reads the workflows (`grep -rln "workflows/ci.yml\|ci\.yml" tests src tools`; `arch_ci_runs_every_test` is one). You never push, tag or open a PR; you commit on your branch and end with the REPORT. `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/ci-pr-slim` (`mkdir -p` it before the run).

## The word and the numbers

The owner: CI "should be passing" and must not put needless load on GitHub; "there has gotta be a balance". The measurement (the keeper's, 2026-10-26): 215 workflow runs on the account in 24 hours, 99 of them bsv-rs's CI at 32 jobs each, 79 cancelled by concurrency. The keeper's recommendation, the owner's word behind it: on a pull request run only what decides the merge; the full matrix on a push to `beta` and `main` and in the nightly; keep cancel-in-progress. The merge queue is already one PR at a time (one CI run per PR), so the per-run job count is what remains.

## The shape

One `ci.yml` for both lines (the direction rule: born on beta, cherry-picked to main by the captain; so every condition is on the event and the ref, never on the branch name alone where main and beta differ). Each job gets a condition by class:

- **On every pull request (the deciding set, every required context of both lines kept):** `fmt` (Rustfmt), `clippy` (Clippy), the `test` matrix cell `ubuntu-latest` × `stable` only (its context name `Test Suite (ubuntu-latest, stable)` unchanged: the matrix must still produce exactly that name; read how the matrix names its cells and keep the push-time cells' names unchanged too), `fixtures`, `vectors`, `ratchet`, `secrets`, `semver`, `deny`, `main-in-beta` (PRs into beta, as today), `beta-born` (PRs into main, as today), `dependents` and its plan and matrix (PRs into `main` only, where it is required: `github.base_ref == 'main'`; on PRs into beta it moves to push), `actionlint` and `machete` (seconds each, keep), `docs` (one build, keep), and ONE wasm32 cell, the `combined` consumer, as the pull request's guard of rule 6 (the other four consumers on push and nightly). Say in the REPORT the job count on a PR before and after (32 before by the keeper's count).
- **On a push to `beta` or `main` and in the nightly:** everything above plus the other five `test` cells (macOS and Windows on stable and beta; ubuntu on beta), the other four wasm32 consumers, `msrv`, `features`, `benchmarks` (today "pull_request or push to beta": push to beta and the nightly only), `benchmarks-build`, and `dependents` on beta.
- **The nightly** (`nightly.yml`): read what it runs; add a `workflow_call` of `ci.yml` with an input that selects the full set (or a `schedule` on `ci.yml` itself: choose the one that keeps one source of truth and say why), so the full matrix runs once a day on `beta` and on `main` whether or not anything was pushed.
- **`scoreboard`** (`if: always()`): it must not go red for a job that was skipped by its condition; read it and fix its reading of skipped jobs if it would.
- **Concurrency:** `cancel-in-progress` stays as it is (tags excepted).

The required-context lists on both lines (`gh api repos/Calhooon/bsv-rs/branches/beta/protection` and `.../main/protection`, read-only) do not change: every required context still runs on every pull request into its line. A required context that stops running on a PR would block every merge; the test below pins that it cannot happen.

## Rule 2

A test in `tests/` beside `arch_ci_runs_every_test` that reads `ci.yml` and the two required-context lists (as constants in the test, with the date and the command they were read by) and asserts that each required context's job has no condition that excludes `pull_request` on its line (parse the `if:` text; a job with no `if:` passes; one with `github.event_name == 'push'` fails). Red on the tip when you gate a required job off PRs on a scratch copy, then green. `arch_ci_runs_every_test` and every other workflow-reading test stays green (if one asserts the whole matrix runs on PRs, it is updated to the new word with its doc comment saying why). `actionlint` on the result (`actionlint .github/workflows/*.yml`, install it if absent). A dry read of each event: list, in the REPORT, the jobs that run on (a) a PR into beta, (b) a PR into main, (c) a push to beta, (d) a push to main, (e) the nightly.

## Docs

`CLAUDE.md` rule 7's sentence "CI runs the matrix (Linux, macOS, Windows × stable, beta)" becomes the new word (the deciding set on a PR; the matrix on a push and nightly); `RELEASING.md`'s required-checks paragraphs unchanged in substance, a sentence on the event split; `.github/workflows/CLAUDE.md` or `benches/CLAUDE.md` rows that describe the jobs; the changelog under `## [Unreleased]` as a `### Changed` entry (what moved, why, the numbers, the test that pins the required set). `tests/CLAUDE.md` row for the new test.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `for f in $(ls tests | grep -E '^arch' | sed 's/\.rs$//'); do cargo test --features "full,http" --test $f || exit 1; done` and the new test; `actionlint`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` (never re-record a baseline).

## Rules

No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name the change (`ci:`); bodies say what and why with the numbers; end with the Co-Authored-By line the session gives you. One concern per commit: the workflow, the test, the docs.

## REPORT (the last thing you print)

`REPORT` then: the base sha, the tip sha and each commit; the five event lists of jobs; the PR job count before and after; the RED run then green; `actionlint`'s line; every gate command with its result line; the sentence for the captain on the cherry-pick to main (which class of RELEASING.md it is, and what conflicts to expect); anything you could not do and why.
