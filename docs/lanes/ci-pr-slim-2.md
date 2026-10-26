# Relaunch note (read before the brief below)

A lane on an earlier draft of this brief was stopped by the captain five minutes after it started, when the keeper added the exact-set rule below. `git log --oneline origin/beta..HEAD` and `git status` show anything it left; keep a commit that fits this brief and say so, reset the rest to `origin/beta`.

# Lane: ci-pr-slim. On a pull request CI runs what decides the merge; the full matrix runs on a push to beta or main and in the nightly (the owner's word of 2026-10-26, through the keeper)

You are a code lane of bsv-rs (`~/bsv/bsv-rs`), in the worktree cca gives you on a branch from `origin/beta`. Read `CLAUDE.md` (rules 6, 7; the "Where the numbers come from" paragraph names CI's matrix), `RELEASING.md` (the direction rule; the four classes of main patch; the required checks on each line), `docs/lanes/README.md` (the lane rules; everything foreground, under ten minutes; never `~/bsv/bsv-low/` or `~/vault/`), `.github/workflows/ci.yml`, `nightly.yml`, `sync-main-into-beta.yml`, `release.yml`, and every test that reads the workflows (`grep -rln "workflows/ci.yml\|ci\.yml" tests src tools`; `arch_ci_runs_every_test` is one). You never push, tag or open a PR; you commit on your branch and end with the REPORT. `CARGO_TARGET_DIR=$HOME/bsv/targets/bsv-rs-lanes/ci-pr-slim` (`mkdir -p` it before the run).

## The word and the numbers

The owner: CI "should be passing" and must not put needless load on GitHub; "there has gotta be a balance". The measurement (the keeper's, 2026-10-26): 215 workflow runs on the account in 24 hours, 99 of them bsv-rs's CI at 32 jobs each, 79 cancelled by concurrency. The keeper's recommendation, the owner's word behind it: on a pull request run only what decides the merge; the full matrix on a push to `beta` and `main` and in the nightly; keep cancel-in-progress. The merge queue is already one PR at a time (one CI run per PR), so the per-run job count is what remains.

## The shape: a pull request runs exactly the required set

The keeper's rule for every public repository of the stack, the owner's word behind it (2026-10-26): the set of jobs a pull request runs is exactly the required set on that line's branch protection. A job that runs on a PR but cannot refuse it is noise; a job that could refuse but is not required is a hole. The captain set the required sets at 15:5xZ, each context green on its line's tip:

- **beta** (eleven): `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `vectors`, `deny`, `ratchet`, `fixtures`, `secrets`, `semver`, `main-in-beta`, `wasm32 (combined)`.
- **main** (twelve): `Test Suite (ubuntu-latest, stable)`, `Clippy`, `Rustfmt`, `vectors`, `deny`, `dependents`, `semver`, `beta-born`, `ratchet`, `fixtures`, `secrets`, `wasm32 (combined)`.

Read both with `gh api repos/Calhooon/bsv-rs/branches/<line>/protection/required_status_checks` (read-only) and pin them in the test below. One `ci.yml` for both lines (the direction rule: born on beta, cherry-picked to main by the captain), every condition on the event and the ref:

- **On a pull request:** a job runs if and only if its context is required on the PR's base line (`github.base_ref`): the `test` matrix produces only the `ubuntu-latest` × `stable` cell (its context name unchanged; the push-time cells' names unchanged too); the wasm32 matrix only the `combined` consumer; `dependents` with its plan and matrix only on PRs into `main`; `main-in-beta` only into `beta`, `beta-born` only into `main`, as today; `semver` as today. Nothing else runs on a PR: `docs`, `actionlint`, `machete`, `msrv`, `features`, the other five test cells, the other four wasm32 consumers, `benchmarks`, `benchmarks-build` and `scoreboard` move to push and nightly (if `dependent (${{ matrix.id }})` and `Plan pinned dependents` must run for `dependents` to decide, they are part of it; say so). Say in the REPORT the job count on a PR into beta and into main, before (32) and after.
- **On a push to `beta` or `main` and in the nightly:** every job.
- **The nightly** (`nightly.yml`): read what it runs; add a `workflow_call` of `ci.yml` with an input that selects the full set (or a `schedule` on `ci.yml`: choose what keeps one source of truth and say why), so the full matrix runs once a day on `beta` and on `main` whether or not anything was pushed.
- **`scoreboard`** (`if: always()`): on push and nightly only; it must not go red for a job skipped by its condition.
- **Concurrency:** `cancel-in-progress` stays as it is (tags excepted).

## Rule 2

A test in `tests/` beside `arch_ci_runs_every_test` that reads `ci.yml` and carries the two required-context lists as constants (with the date and the command they were read by) and asserts the exact-set rule both ways per line: (a) every required context's job runs on a pull request into that line (its condition does not exclude `pull_request` with that base; the matrix produces that context name on a PR), and (b) no job whose context is not required runs on a pull request into that line. Parse the `if:` text and the matrix `include`/conditions as the file writes them; keep the parser small and say its limits. Red on a scratch copy when a required job is gated off PRs, and red when an unrequired job is left on; green on the tip. `arch_ci_runs_every_test` and every other workflow-reading test stays green (one asserting the whole matrix on PRs is updated to the new word with its doc comment saying why). `actionlint` on the result (`actionlint .github/workflows/*.yml`, install it if absent). List in the REPORT the jobs that run on (a) a PR into beta, (b) a PR into main, (c) a push to beta, (d) a push to main, (e) the nightly.

## Docs

`CLAUDE.md` rule 7's sentence "CI runs the matrix (Linux, macOS, Windows × stable, beta)" becomes the new word (the deciding set on a PR; the matrix on a push and nightly); `RELEASING.md`'s required-checks paragraphs unchanged in substance, a sentence on the event split; `.github/workflows/CLAUDE.md` or `benches/CLAUDE.md` rows that describe the jobs; the changelog under `## [Unreleased]` as a `### Changed` entry (what moved, why, the numbers, the test that pins the exact set). `tests/CLAUDE.md` row for the new test.

## The gate (foreground, each under ten minutes)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `for f in $(ls tests | grep -E '^arch' | sed 's/\.rs$//'); do cargo test --features "full,http" --test $f || exit 1; done` and the new test; `actionlint`; `mkdir -p "$CARGO_TARGET_DIR" && tools/ratchet/run --check --against origin/beta` (never re-record a baseline).

## Rules

No em dash; never "first" as an ordinal; never "conformant" without a run. Commit subjects name the change (`ci:`); bodies say what and why with the numbers; end with the Co-Authored-By line the session gives you. One concern per commit: the workflow, the test, the docs.

## REPORT (the last thing you print)

`REPORT` then: the base sha, the tip sha and each commit; the five event lists of jobs; the PR job count before and after; the RED run then green; `actionlint`'s line; every gate command with its result line; the sentence for the captain on the cherry-pick to main (which class of RELEASING.md it is, and what conflicts to expect); anything you could not do and why.
