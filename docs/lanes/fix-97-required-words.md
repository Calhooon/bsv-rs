# Lane fix-97-required-words: the required-set guard says what is live on beta's protection (2026-11-14)

Started from `origin/beta` at `6232488b4644bb350374817e7dbd7b9527d5a20e`. Nothing pushed, nothing
written to GitHub; two reads by `gh` (issue #97 with its comments, beta's
`required_status_checks`). Words alone: one test file's comments, two manuals, the changelog.

## The issue's comments

Three comments on Calhooon/bsv-rs#97. The decision of 2026-11-12 (two stages; nothing required
until the witnesses and the soak; `ci.yml`'s `sibling` job stays as it is) asks nothing of this
lane and forbids nothing it does. The comment of 2026-11-13 leaves one decision to the owner (a
head that edits `sibling-run.yml`), untouched here. The comment of 2026-11-14, fact 1, names this
lane's work and offers two answers: the PATCH, or the comment and the row saying "listed ahead of
the PATCH" with the date. This lane is the second. No comment waits on something this lane needs.

## The premise, checked on this tip

| Cited | On `6232488b` |
|---|---|
| `REQUIRED_ON_BETA` lists `sibling` under "the captain PATCHes beta's protection after the job runs green on its tip" (`tests/arch_ci_pr_runs_the_required_set.rs:43-60`) | holds (the constant at `:51-60`, the sentence at `:57-58`) |
| the guard reads no network (`:21`) | holds |
| `tests/CLAUDE.md:109` says the list is read by `gh api .../protection/required_status_checks` and counts 6 | holds |
| the live protection holds five contexts and no `sibling` | holds: `strict: true`; `Test Suite (ubuntu-latest, stable)`, `main-in-beta`, `semver`, `lint`, `checks`, each `app_id` 15368 |
| the App's entry `{sibling-judge, app 5700082}` | NOT in the live protection: it is the entry `RELEASING.md` step 25 writes for the owner's PATCH. The words say so and do not call it live |
| the trampoline's guard refuses a job reporting that context (`tests/arch_ci_sibling_judge_97.rs:309`) | holds (`no_workflow_names_pull_request_target_or_a_sibling_judge_job_97`, at `:308-309`) |

## The list against the live protection

The list differs from the live protection by `sibling` alone, which is the issue's fact 1 and
nothing further. The list is not changed: the exact-set rule (`exact_refusals`) reads it as the
jobs a pull request may run, so with `sibling` taken out the `sibling` job is refused as a job
left on, and the assertions would move. `REQUIRED_ON_MAIN` was not read against main's protection
(out of this lane's brief).

One thing the reading found, stated and not built: `tests/arch_ci_sibling_judge_97.rs`
(`mains_required_set_never_names_the_judges_check_97`) carries the comment "beta's set may name
it", and its own rule passes with `sibling-judge` planted in `REQUIRED_ON_BETA`; this guard would
refuse that list, since it proves every entry by a job of `ci.yml` and no job reports the App's
context. The new words say the name never joins this list. That file is the judge's and was not
touched.

## What changed

- `tests/arch_ci_pr_runs_the_required_set.rs`: the doc comment of `REQUIRED_ON_BETA` and the
  comment over its `sibling` entry. No code line, no constant, no assertion.
- `tests/CLAUDE.md`: the file's row.
- `tests/sibling/CLAUDE.md`: one paragraph after "What the pin cannot hold".
- `CHANGELOG.md`: the entry under `[Unreleased]`.

Not changed, stated: `docs/ARCH-RULES.md:295` says `REQUIRED_ON_BETA` (five), the count at the
bundling it describes; `RELEASING.md` is another pull request's class. No file under `src/`.

## RED

None. Words alone: no assertion reads them, and a test that read the live protection would break
the hermetic rule. The guard's tests pass unchanged before and after.

## The gate

On macOS, one cargo at a time, `CARGO_BUILD_JOBS=4`, a target dir of the lane's own (removed
after); logs under `/Volumes/Lanes/out/bsv-rs/fix-97-required-words/`.

| Command | Result |
|---|---|
| the lint job's three `cargo fmt ... -- --check` lines | clean |
| `cargo +1.100.0 clippy --all-features --test arch_ci_pr_runs_the_required_set -- -D warnings` | clean |
| `cargo test --features "full,http" --test 'arch_*'` | 35 binaries, 185 passed, 0 failed, 1 ignored |
| the guard and `arch_ci_sibling_judge_97`, three runs, one with `--test-threads=1` | 20 and 10 passed each run |
| `--test fixtures_replay --test readme_examples` | 1 and 1 passed |
| `tools/ratchet/run --check --against origin/beta` | all 7 counters, oversized-file limits and mutation floors pass |
| `python3 .github/scripts/mutants_entries.py` | PASS, 28 entries |
| `python3 -B .github/scripts/rows_from_sources.py --check` | 0 refusals |
| `gitleaks git` over `origin/beta..HEAD` | no leaks |

Not run: `cargo doc` (no rustdoc text moved: the edited comments sit in an integration test),
the wasm32 build (no file under `src/`), `actionlint` (no workflow or script touched).
