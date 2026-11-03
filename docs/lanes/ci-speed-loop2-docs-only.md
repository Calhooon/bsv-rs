# CI speed, loop two: a docs-only pull request's fast exit (#668)

Branch `lane/ci-speed-loop1-close` from `origin/beta` at `4b2e1d35`. Loop two of the speed
line (the keeper's word of 2026-11-03 02:1xZ), opening from loop one's recorded figures
(`docs/lanes/ci-speed-2.md`, "Loop one closed").

## What a docs-only pull request cost

#669 (`CHANGELOG.md` and `docs/lanes/ci-speed-1.md`) ran 10m05s, run 41574976294, before
cut 4: the whole Test Suite. Under cut 4 its plan reaches one binary (`arch_ci_lines`, whose
needle names `CHANGELOG.md`; `docs/lanes/ci-speed-4.md`, "The plan on real diffs"), so its
Test Suite builds the crate for that binary, and `lint` (2m01s to 2m33s) and `checks` (2m24s
to 3m04s on runs 41590906372, 41598630196, 41587646252) build everything they build for a
code change.

## The exit

- **The Test Suite.** `affected_tests.py plan` writes `build`: true when the plan reaches
  everything, the unit or doc tests, or any integration binary (the two run apart included).
  A push, a dispatch and a tag's call write `build=true` with the other flags. Every step
  after the plan carries `steps.plan.outputs.build == 'true'` (the toolchain, the lockfile,
  the cache restore, the nextest install, the reached-set check) or a plan flag that implies
  it (the five test steps, unchanged); a last step under `build != 'true'` prints
  `docs-only: nothing to build` and the required context `Test Suite (ubuntu-latest,
  stable)` reports green.
- **`lint` and `checks`.** A plan step after the checkout runs the same plan on a pull
  request and writes `docs_only`: every changed path a `*.md` other than `README.md` (the
  ratchet measures it, `tools/ratchet/src/tree.rs`) and outside `tools/ratchet/` (the
  ratchet's code), the ratchet record rule below, no unit or doc test,
  and none of the binaries `ci.yml` runs by `--test` reached (the names read from `ci.yml`
  itself, so a new `--test` in `vectors` or `fixtures` is in the list without an edit). A
  push writes `docs_only=false`. The toolchain installs, the cache restore, `cargo-deny`'s
  install, the corpus checkout and the lockfile step (`ready`) carry `docs_only != 'true'`;
  every gate already waits on `ready`, so Rustfmt, Clippy, deny, ratchet, mutants-entries,
  vectors, fixtures, Documentation and wasm32 skip. `secrets` runs on `ready` or a docs-only
  change (gitleaks needs Go, not the crate). The verdict step reads a skipped gate as `SKIP`
  when `DOCS_ONLY` is true and the gate is not `secrets`; any other skip stays a FAIL.
- **Not exited.** `semver` (49 to 51 s on a cache hit, 6m03s on a miss: runs 41590906372,
  41598630196, 41587646252) and `main-in-beta` (7 to 10 s) run as before; #668 names both,
  and either is the next cut if a docs-only run's wall clock sits on it.
- **The `CHANGELOG.md` residue.** `arch_ci_lines` holds `Cargo.toml | CHANGELOG.md)` as a
  needle of `ci.yml`'s text, and the plan's lexer reads it as a read of the file, so a
  pull request touching `CHANGELOG.md` reaches that binary: its Test Suite builds and runs
  it, while `lint` and `checks` exit (the binary is not one `ci.yml` runs by name). Planned
  locally: #669's diff (`fdbaa858^..fdbaa858`) gives `build=true`, `docs_only=true`; this
  branch's docs commit gives `build=false`, `docs_only=true`; #681's code landing
  (`b680d59f`) `build=true`, `docs_only=false`.

## The ratchet record rule (the #688 fold)

The cold read's FIX: under the reading above as the lane wrote it (`docs/` or a `*.md`), a
pull request loosening `docs/ratchets.json` planned docs-only, `lint` exited before the
ratchet and reported green, and the line's push run would fail after the landing. #668's
words name `docs/` as documentation; a file under `docs/` that is not Markdown is data a
tool reads (`docs/ratchets.json` the ratchet's record, `docs/dependents.lock` the dependents
job's list, `docs/a8/` and `docs/census/` the oracle's JSON), so the fold reads
documentation as Markdown alone (`affected_tests.is_documentation`): a `*.md` other than
`README.md` and outside `tools/ratchet/`. The ratchet's code (`tools/ratchet/run`, its
sources and lockfiles) was never documentation; its Markdown now is not either. A scratch
commit loosening `docs/ratchets.json` (`unwrap_expect` 40 to 41) plans, on the tip's script,
`build: False; docs only: True`, and on the fold's `whole=false build=false docs_only=false
lib=false doc=false memory=false tracing=false reached=0`: the Test Suite builds nothing (no
test reads the record) and `lint` runs the ratchet. Pinned by
`test_a_data_file_under_docs_or_the_ratchet_code_is_no_docs_only_change` (eight paths, five
of them docs only on the tip's reading).

## The guard

`tests/arch_ci_docs_only_exit.rs`: each step after the plan in the three jobs carries its
condition (or, in `lint` and `checks`, waits on `ready`), the last Test Suite step is the
report under `build != 'true'`, the push path writes `build=true`, `secrets` runs on a
docs-only change and the verdict steps accept a skip only there. Each refusal is shown on a
mutated `ci.yml` in the file's third test; RED on a scratch copy of the tip with the
nextest install's condition removed. The #688 fold closes three holes the cold read named:
each condition is read whole against the exact forms the guard lists (a substring read let
`build == 'true' || always()` pass; RED on a scratch copy with `|| always()` appended to the
nextest install's condition, the tip's guard green there); only a checkout runs before a
plan step (RED on a scratch copy with the Test Suite's cache restore moved above its plan,
the tip's guard green there; a `cargo` run before `lint`'s plan refused too); and the plan's
output keys are tied to the workflow (`WorkflowKeyTests` in `test_affected_tests.py`: every
`steps.plan.outputs.<key>` the `test`, `lint` and `checks` jobs read is one the script's
`outputs` or the step's own shell writes on a pull request, and every one but `reached`,
`tests` and `file` one the push branch writes; RED with `build` renamed `builds` in the
script). The plan's two flags have unit tests in
`.github/scripts/test_affected_tests.py` (docs alone builds nothing; `CHANGELOG.md` with a
binary named by `--runs`; code, the manifest, `README.md`, a workflow file and an empty
change are never docs only).

## The five figures

| Figure | Before | After |
|---|---|---|
| A docs-only PR's CI wall clock | 10m05s (#669, run 41574976294) | measured by the loop's close, the pull request carrying `docs/lanes/ci-speed-2.md`'s "Loop two closed" (the earliest docs-only one under the exit), its run's seconds written by the captain at its landing in the next docs pass |
| The queue wait | 0m02s to 1m57s (loop one closed) | (from the next docs-only PR's run) |
| The nightly | 2h28m06s (run 41579707627) | unchanged by this cut |
| A cold read | about 16 minutes; reads without cargo 3 to 7 minutes | unchanged by this cut |
| The landing latency | 39, 46 and 64 minutes (#676, #684, #680) | (from the next docs-only PR's landing) |

This lane measured nothing on GitHub: its own run changes `ci.yml` and plans everything.
