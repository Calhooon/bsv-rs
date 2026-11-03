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
- **Not exited by #668.** `semver` (49 to 51 s on a cache hit, 6m03s on a miss: runs
  41590906372, 41598630196, 41587646252) and `main-in-beta` (7 to 10 s) ran as before; #668
  named both, and either was the next cut if a docs-only run's wall clock sat on it. The
  next docs-only run's wall clock sat on `semver` (below, "The opening measurement"), and
  #689 exits it; `main-in-beta` (5 s there) stays.
- **The `CHANGELOG.md` residue.** `arch_ci_lines` holds `Cargo.toml | CHANGELOG.md)` as a
  needle of `ci.yml`'s text, and the plan's lexer reads it as a read of the file, so a
  pull request touching `CHANGELOG.md` reaches that binary: its Test Suite builds and runs
  it, while `lint` and `checks` exit (the binary is not one `ci.yml` runs by name). Planned
  locally: #669's diff (`fdbaa858^..fdbaa858`) gives `build=true`, `docs_only=true`; this
  branch's docs commit gives `build=false`, `docs_only=true`; #681's code landing
  (`b680d59f`) `build=true`, `docs_only=false`.

## The opening measurement (#690)

#690, the earliest docs-only pull request under the exit (run 41617426467 on `849ff87e`,
beta `7a9030d4`): the Test Suite 8 s, `lint` 9 s, `checks` 30 s, `main-in-beta` 5 s,
`semver` 4m39s; the run's wall clock 4m43s against #669's 10m05s. The three exited jobs
end inside half a minute; `semver`, untouched by #668, bounds the run.

## The semver exit (#689)

`semver` runs lint's plan step itself, after its own checkout (the script is pure Python
over `git diff`, a second or so), and every step after it carries
`steps.plan.outputs.docs_only != 'true'`: the scratch-directory step (moved below the
plan, since only a checkout may run before one), the 1.95.0 toolchain, the tool's cache
restore, the tool's install (`docs_only != 'true' && cache-hit != 'true'`: on a docs-only
run the skipped cache step leaves `cache-hit` empty, which alone would install) and the
check. A last step under `docs_only == 'true'` prints `docs-only: no API to check`, so the
required context reports green. On every other pull request the steps, the baseline (`git
describe` of the PR base's last tag), the `--baseline-rev` form and the release type read
from the version change are the ones before; nothing is read from the registry.

Not `needs: test` with the Test Suite's plan output: `semver` would start only when the
Test Suite ends, adding its minutes to every code change's wall clock where today the two
run side by side; the Test Suite's plan writes `build` (a target reached), not `docs_only`,
and a `CHANGELOG.md` change reaches `arch_ci_lines` there, so `semver` would never exit on
a changelog edit. Planned locally on #690's commit
(`849ff87e^..849ff87e`): `build=false docs_only=true`; on #681's code landing
(`b680d59f`): `build=true docs_only=false`.

The guard: `tests/arch_ci_docs_only_exit.rs`'s `semver_refusals` holds each step after the
plan to `docs_only != 'true'` (the install to the combined form alone), the check's
`check-release --baseline-rev "$baseline" --all-features` after the plan, and the last step
to the report under `docs_only == 'true'`; three mutations in the file's third test (the
check's condition removed, the install's `docs_only` arm removed, the report's condition
removed) and the scratch step above the checkout in its fourth; `WorkflowKeyTests` in
`test_affected_tests.py` reads `semver`'s plan keys with the other three jobs'. RED on a
scratch copy of the tip with the check's condition removed (the check named, running under
an empty condition), and on the base's `ci.yml` (`semver: no plan step`).

## The two remaining rows (#689)

Branch `lane/fix-689` from `origin/beta` at `ba59e71d`. Planned on the tip tree, one
changed path each, with the plan step's reading (`reach` and `finish` on the tree, the
tree's `tests/CLAUDE.md` as the base rows):

| Changed path | Before (`ba59e71d`'s script) | After |
|---|---|---|
| `CHANGELOG.md` | `integration binaries reached: 1 of 288`, `build: True; docs only: True`; `named by 1 binaries' sources` (`arch_ci_lines`) | `integration binaries reached: 0 of 288`, `build: False; docs only: True`; `documentation no test reads` |
| `src/script/CLAUDE.md` | `integration binaries reached: 7 of 288`, `build: True; docs only: True`; `under a directory 7 binaries walk` (`arch_arc_deprecated`, `arch_network_sites`, `arch_no_env`, `arch_no_string_errors`, `arch_no_system_time`, `arch_no_unwrap`, `arch_tests_claude_rows_name_modules_706`) | `integration binaries reached: 0 of 288`, `build: False; docs only: True`; `documentation no test reads` |
| `src/script/spend/mod.rs` | `unit: True; doc: True; memory: True; tracing: True`, `integration binaries reached: 227 of 288`, `build: True; docs only: False` | the same lines, the same 229 binaries |

- **The changelog row: fixed at the planner, not by splitting the string.** The reach rule's
  record (`docs/lanes/ci-speed-4.md`, "Any other path") reads names in string literals so
  that prose reaches nothing; an assertion's needle and its message are prose that happens
  to sit in a literal. Splitting `arch_ci_lines`'s needle would leave the next needle or
  message naming a file to trip the same reading. A literal holding whitespace now names no
  file (`literal_text`); no tracked path holds a space. Across the 3,934 tracked paths the
  rule drops 98 (binary, path) pairs over 20 paths' reach (with the walker
  rule below, 297 pairs over 48 paths), every one a word in a message or a needle (no
  binary of the 98 pairs opens or runs the file it drops); it adds none. No `tests/arch_*.rs` reads
  `CHANGELOG.md`: `arch_ci_lines` names it in a needle of `ci.yml`, and four other test
  files in comments, so a changelog change keeps no binary.
- **The module `CLAUDE.md` row: open on the tip, now closed.** The docs-only reading
  (`is_documentation`) already counted `src/**/CLAUDE.md` as Markdown no gate reads, so
  `lint`, `checks` and `semver` exited on it; the Test Suite did not, since the fixture
  clause's walk reached the seven walkers of `src/`. Every one reads `.rs` files alone
  (`tests/arch_support/mod.rs`) or lists the module directories; a Markdown file under
  `src/` (28 on the tip) reaches no walker now.

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
| A docs-only PR's CI wall clock | 10m05s (#669, run 41574976294) | 4m43s (#690, run 41617426467 on `849ff87e`: the Test Suite 8 s, lint 9 s, checks 30 s, main-in-beta 5 s, semver 4m39s) |
| A docs-only PR's `semver` job (#689) | 4m39s (#690, run 41617426467) | measured by the pull request of `lane/docs-loop3-after` (the earliest docs-only one after #689 landed at `ec14da1c`, 13:00Z 2026-11-03), read in at its landing |
| The queue wait | 0m02s to 1m57s (loop one closed) | (from the next docs-only PR's run) |
| The nightly | 2h28m06s (run 41579707627) | unchanged by this cut |
| A cold read | about 16 minutes; reads without cargo 3 to 7 minutes | unchanged by this cut |
| The landing latency | 39, 46 and 64 minutes (#676, #684, #680) | (from the next docs-only PR's landing) |

This lane measured nothing on GitHub: its own run changes `ci.yml` and plans everything.
