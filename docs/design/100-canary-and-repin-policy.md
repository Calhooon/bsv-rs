# Design for #100: the canary and re-pin policy, written down

Read at `origin/beta` `e228c61a` on 2026-11-09. A design only; no cargo run. `[X]` = read at the line or run (python only); `[D]` = told or proposed.

## 1. The exit test and the scoreboard row

The issue [X]: "**Exit test.** RELEASING.md carries it; `docs/DEPENDENTS.md` shows every pin at the current minor or with a dated plan." Its body adds: the minor publishes from main, and the three dependents behind (0.4.5, 0.6.0, 0.7.2) get a plan with captains named.

The row it moves [X] `docs/NORTH-STAR.md:30`: Dependents, "Consumer builds, semver guard and current pins or dated plans", today "not yet measured". Epic #101's row [X]: "the pin spread (0.4.5 to 0.8.1 today) closed or dated with a captain per row".

"At target with recorded evidence" as proposed here [D]:

- Command: `python3 -B .github/scripts/dependents.py ledger --sdk "$PWD" --check` exits 0 (new mode, step 2).
- Record: `dependents.json` written by that mode, uploaded as an artifact named `dependents-ledger` in the `bench.yml` run and collected by the `scoreboard` job, reading `behind_without_plan: 0`, `overdue: 0`, `canary_current: true`, with the commit and run id the collector stamps (`bench.yml:247-253` [X]).

## 2. Today on beta

| Fact | Where | Mark |
|---|---|---|
| The canary paragraph, ending "#100 owns the full release policy" | `RELEASING.md:3-11` | [X] |
| A prerelease tag is the owner's word; announced to the two canary captains with the fixtures' diff | `RELEASING.md:32-33` (points 14, 15) | [X] |
| The main-merge gate names "the CLI's gate run and the production reads green"; neither has a command or record path here | `RELEASING.md:34` | [X] |
| The ledger: 11 Rust rows, 4 app rows, snapshot 2026-10-23, production cells `[D] Unknown` or a 2026-10-12/13 report | `docs/DEPENDENTS.md:3,27-39,60-65` | [X] |
| The train: eight rows dated 2026-10-24 to 2026-10-27, all past; no acceptance or execution recorded | `docs/DEPENDENTS.md:75-90` | [X] |
| Nine of eleven captain cells read "Stack keeper until named" | `docs/DEPENDENTS.md:31-39` | [X] |
| The lock: schema 1, 14 rows over 11 repositories, all `branch = "main"`; no captain or date field; private apps kept out | `docs/dependents.lock:1-7` | [X] |
| `admits`: a prerelease is admitted only by an exact requirement equal to it | `.github/scripts/dependents.py:34-39` | [X] |
| `plan`; `run` (locked rev, declared requirement, path patch, resolution witness, check, tests) | `dependents.py:71-86,128-168` | [X] |
| Jobs `dependents-plan`, `dependent-check`, `dependents`; skipped on a PR into and a push to `beta` | `.github/workflows/ci.yml:53-157` | [X] |
| The tag's call runs them with the read token | `.github/workflows/release.yml:58-63` | [X] |
| `semver` runs on pull requests alone; none before a tag's publish (#99's) | `ci.yml:159-233`, `release.yml:114-139` | [X] |
| The crate is `0.9.0-beta.7`; tags `v0.9.0-beta.1` to `.7` exist | `Cargo.toml:3`, `git tag` | [X] |
| **At this version the plan admits zero consumers**: `python3 -B .github/scripts/dependents.py plan --sdk "$PWD"` prints 14 `SKIP` lines and `{"include":[]}`, so `dependents` passes on zero checks on every dispatch and beta tag's call | run here; `ci.yml:157` | [X] |
| The scoreboard collector has four inputs (benchmarks, ratchets, wasm_sizes, mutation); none for dependents | `.github/workflows/bench.yml:204-209` | [X] |
| beta.7 on crates.io since 2026-11-04; "the CLI and the toolbox pin it through the keeper's chain"; the chain's scripts are outside the tree | `docs/CHECKPOINT-2026-11-04.md:9,45,74` | [D] |
| Eight selector and resolution unit tests | `.github/scripts/test_dependents.py:10-56` | [X] |
| Blockers: #83 CLOSED 2026-10-24; #75 OPEN (umbrella, landed as `6934860a`); #96 and #99 OPEN, no commit names either | `gh issue view`, `git log --grep` | [X] |

Not on record (never estimated): any consumer's manifest pin after 2026-10-23, the canaries' beta-line pins included; any row's production bsv-rs; a captain's acceptance of a train date; "the CLI's gate" as a command; a soak's length or closing word; LOW's and the witness wallet's rows (`docs/NORTH-STAR.md:130-131` names them, the ledger does not); whether `DEPENDENTS_READ_TOKEN` exists; job times beyond the two in `ci.yml:86-89` (toolbox 7m08s, middleware-cloudflare 1m37s).

## 3. The gap

1. `RELEASING.md` carries a paragraph, not the policy: no rule for a red canary, the soak, the minor or a pin behind.
2. The ledger is 17 days old and hand-written; its dates have passed; "current minor" is undefined on a prerelease line.
3. The dependents job checks nothing at any `0.9.0-beta.N`: the canary runs only after publication, in the consumers' pin PRs.
4. No producer writes the Dependents row; the collector has no input for it.
5. A prerelease's canary run leaves no record here (beta.7's is one clause of a checkpoint).

## 4. The design

No step touches `src/`, a vector, a fixture, an error text or the public API: the sibling harness run and a bench delta apply to none. The code is Python under `.github/scripts/` with unit tests RED before it, beside docs and YAML; each step is one lane and one PR.

| Rank | Step | Change | Why it closes the gap | Stays identical | Proof | Risk |
|---|---|---|---|---|---|---|
| 1 | The policy section | `RELEASING.md`: `:3-11` becomes the section drafted below; points 15 and 16 point at it | Half the exit test; the cheapest | Points 1 to 22 and their numbers | The text read against the answers to Q100.1 to Q100.6; `rows_from_sources.py --check` 0 refusals | 0.10 |
| 2 | The ledger as data and its check | `docs/dependents.lock` schema 2: per row `line` (`canary`, `stable`), `captain`, `plan_date`, `plan_target`; `dependents.py`: `records` accepts 1 and 2, new `ledger(sdk, output, check)` giving each row `current`, `planned`, `overdue` or `unplanned`; `docs/DEPENDENTS.md`'s train table written from it | "Every pin current or dated" becomes an exit code; today it reads `overdue` | `plan` and `run` outputs for every schema-1 row (a pinned test) | RED in `test_dependents.py`: a row behind with no date fails, a past date fails, a row at the minor passes, schema 1 plans byte-identically; then `ledger --check`'s output | 0.25 |
| 3 | The scoreboard input | `bench.yml`: a python-only job `dependents-ledger` uploading `dependents.json`; a fifth entry at `:204-209`; `scoreboard.needs`; the cell at `docs/NORTH-STAR.md:30` | The row is written by a producer, not a hand | The four existing inputs' JSON; bench comparison | A `bench.yml` dispatch: the summary carries `inputs.dependents.status: available` | 0.20 |
| 4 | Canary rows and the rehearsal | Lock: two `line = "canary"` rows (`branch = "beta"`, exact prerelease) for the toolbox and the CLI; `plan` admits a canary row whose requirement is an earlier prerelease of the same `X.Y.Z`; `run` rewrites that one requirement in the checkout to the tree's version (what the pin PR will do), then the existing witness, check and tests; `breaks_at` with `migration` skips one named version loudly | The job stops passing on zero rows: on the tag's call the canary builds before the prerelease publishes | Stable rows' admission; no `continue-on-error` (`docs/DEPENDENTS.md:51`); job names and required contexts | RED: same-base earlier beta admitted, other base refused, the rewrite touches one line, an unused patch still fails, `breaks_at` skips only its version; then a `ci.yml` dispatch with `count` 2 | 0.45 |
| 5 | The canary record | `docs/canary/<version>.toml` per prerelease: tag sha, announcement, rehearsal run, the two pin PRs, the CLI gate run, soak rows with captain and date, production reads; `ledger --check` requires one for the latest beta tag after a grace; beta.7's backfilled as `[D]` | Point 16's gate reads a file, not a memory | Nothing executable | RED: a tag without a record past the grace fails; a record lacking `cli_gate` fails for a minor | 0.30 |
| 6 | The drift read | `dependents.py drift`: `git ls-remote` per row, reporting a `rev` behind; dispatch-only, never required, never a test (rule 4) | The lock stops ageing silently | Hermetic CI | A dispatch log listing each row's drift | 0.15 |

The measurement step 4's lane takes: the two canary rows' job times on a dispatch.

### The drafted `RELEASING.md` section (a proposal; the owner's answers edit it) [D]

> **The canary and the re-pin policy (#100).** (a) *Order.* A prerelease `vX.Y.Z-beta.N` is rehearsed against the toolbox's and the CLI's beta lines by `dependents` before it publishes; after it publishes the toolbox's beta pins it exactly, then the CLI's; then the CLI's gate runs. (b) *Red.* A red rehearsal holds the tag unless the lock names the break and its migration for that one version by a reviewed PR under the owner's word. (c) *Soak.* After the CLI's gate, the workers' and LOW's captains re-pin on their own trains, each writing its line in `docs/canary/<version>.toml`; the apps follow their layer. (d) *The minor.* `vX.Y.0` is tagged on `main` only from a tree a recorded prerelease covers, its record showing the CLI's gate and the production reads green (point 16). (e) *Behind.* A stable row is current when its requirement names the latest minor on `main`; a row behind carries a captain and a date in `docs/dependents.lock`; a passed date fails `ledger --check`. (f) *Authority.* This section moves no pin, cuts no tag and deploys nothing; each is its captain's PR and the owner's word.

### The dated re-pin table (a proposal; each date is its captain's to accept or replace) [D]

| Row | Today (2026-10-23 read) | Target | Proposed date | Captain |
|---|---|---|---|---|
| toolbox beta, CLI beta | exact beta pin `[D]` beta.7 | each `0.9.0-beta.N` | the hour chain after each tag | toolbox, CLI |
| bsv-overlay-cloudflare (3 rows) | `=0.7.2` | Q100.2 | 2026-11-12 | keeper until named |
| bsv-agent-template | `0.6.0` | Q100.2 | 2026-11-13 | keeper until named |
| bsv-storage-cloudflare (2 rows) | `=0.4.5` | Q100.2 | 2026-11-16 | keeper until named |
| agents `manage`, Zanaadu, Teragun | `0.5.0`, `=0.4.5`, `0.7` and `=0.4.5` | after their layer | 2026-11-18 | their captains via the keeper |
| the eight rows at 0.8 | `0.8` to `=0.8.1` | `0.9` | at `v0.9.0` on `main` (point 16) | as recorded |

## 5. The slicing

| Lane | Steps | Waits on | Gate |
|---|---|---|---|
| A `docs-100-policy` | 1 | Q100.1, Q100.4, Q100.5 | python rows check; no cargo |
| B `oracle-100-ledger` | 2 | Q100.1, Q100.2, Q100.3 | `unittest` on `test_dependents.py`; `ledger --check` output |
| C `oracle-100-scoreboard` | 3 | B | a `bench.yml` dispatch; actionlint |
| D `oracle-100-rehearsal` | 4 | B (the schema), Q100.4 | `unittest`; a `ci.yml` dispatch; `cargo test --test arch_ci_pr_runs_the_required_set --test arch_nightly_cap` (one builder) |
| E `docs-100-canary-record` | 5, 6 | B, D | `unittest`; the backfilled record read by the keeper |

A and B run in parallel; C and D in parallel after B; E last. Shared files: `dependents.py` and `test_dependents.py` (B, D, E, in that order), `docs/dependents.lock` and `docs/DEPENDENTS.md` (B, D), `RELEASING.md` (A, then E's one pointer).

Collision surfaces with other open work:

- The beta.8 cut and its pin chain (`docs/CHECKPOINT-2026-11-04.md:45`): lane B lands before or after a cut, never across one. #735 (`OutputListItem.txid`, the toolbox's four literal sites) is the live case for step 4's `breaks_at`.
- The blocking set (#734, #735, #751, #756, #775, #782, #785, #786, #796) and the mutants campaign #603 live under `src/` and `tests/`: no shared file but `CHANGELOG.md`; #603's scripts are other files of `.github/scripts/`.
- #96's design: `docs/DEPENDENTS.md:20-25` (the workers' slices), the `wasm_sizes` entry at `bench.yml:207`, `scoreboard.needs`.
- #99's design: `RELEASING.md` (steps 3 to 10) and `release.yml`; paragraph (d) leans on its semver before publish.
- #97 and #98: new `ci.yml` jobs, so `tests/arch_ci_pr_runs_the_required_set.rs` and `tests/arch_nightly_cap.rs` move beside lane D's edits.
- #90 to #95: `bench.yml` producers and `docs/NORTH-STAR.md`'s cells, each its own row.
- `docs/ARCHITECTURE.md:123` (the dependents invariant) is edited by lane D alone.

## 6. The owner's questions

No ts-stack, node or BRC line governs a pin policy; each default below is the stack's page at `13e1fa5d` or this repository's standing rule.

- **Q100.1 What "current minor" means while the line is a prerelease.** (a) the latest minor tagged on `main` (0.8 today) for stable rows and the latest beta for canary rows; (b) 0.9 for every row. Default: Cargo's rule, a stable caret never admits a prerelease (`RELEASING.md:9-10`). Recommendation: (a). Cost: (a) leaves eight consumers current; (b) puts every stable consumer behind until god tier.
- **Q100.2 Where the three behind go.** (a) to `0.8` now on the proposed dates; (b) one move to `0.9.0` when it publishes, undated. Default: the stack's line names one exact pin per member (`docs/RELEASE.md`). Recommendation: (a), because only a dated plan passes the exit test and 0.9.0's date is not on record. Cost: storage, the template and overlay migrate twice under (a); under (b) the row stays below target until the minor.
- **Q100.3 Lock schema 2 and the private apps.** (a) schema 2 with `line`, `captain`, `plan_date`, `plan_target`; apps as name-only `[[app]]` entries, no repository path or rev; (b) apps as full private rows behind `DEPENDENTS_READ_TOKEN`; (c) apps stay prose. Default: the lock's own word, private paths stay out "until the owner says otherwise" (`docs/dependents.lock:4-7`). Recommendation: (a). Cost: (b) needs a credential and puts four private paths in a public file; (c) leaves four rows unchecked.
- **Q100.4 Whether a red rehearsal holds a prerelease.** (a) holds; (b) holds unless the lock names the break and migration for that version by a reviewed PR; (c) advisory. Default: no best-effort path (`docs/DEPENDENTS.md:49-51`). Recommendation: (b). Cost: (a) deadlocks an intended break between betas (a consumer cannot migrate to an unpublished version); (c) ships breaks to the toolbox and the CLI unannounced.
- **Q100.5 What closes the soak and what "the CLI's gate" is.** (a) each captain's dated line in the record, no timer; (b) a fixed number of nights. Default: the stack cuts a line on the owner's word after its check, with no timer (`docs/RELEASE.md`). Recommendation: (a), and the CLI's captain names the gate's command and run for the record. Cost: (b) puts a clock on LOW and the workers that no record supports.
- **Q100.6 The pins and the names.** The dated table of section 4 moves nothing until each captain accepts its row and the owner authorizes it; nine rows need a captain named in place of "Stack keeper until named". Recommendation: the keeper carries the table to the captains and records each answer on #100.

## 7. Stack alignment

The issue's line: "The stack's line and the keeper's versions page". Pointers at `bsv-stack-lean@13e1fa5d748b`: `docs/RELEASE.md` (the line tag, `stack.toml`'s exact member pins), `docs/p0/versions-2026-10-10.md` (the version table), `docs/UPDATE-LOOP.md` (a release arriving as a PR with checks). No charter, Lean rule or matrix row is touched: no wire, verdict or protocol changes. A beta tag is never admitted to the stack's line (`RELEASING.md:32`).

- T1: the cost grows with the consumer rows, never with the chain.
- T2: not applicable.
- T3: the rehearsal finds a break one hop before the consumer's pin PR.
- T4: the policy is an exit code (`ledger --check`), not discretion.
- T5: the ledger's cells come from a locked rev and a producer.
- T6: the record is JSON and TOML a command replays; no Lean statement is claimed.

## 8. Not in this design

- Any pin move, tag, publish, deployment or consumer-repository read: the captains' and the owner's.
- Semver, an SBOM and signing before publish: #99. wasm32 slice budgets: #96.
- A fresh production inventory: each captain's (`docs/DEPENDENTS.md:72-73`).
- LOW's and the witness wallet's ledger rows: added when their captains supply them through the keeper.
- Two stale sentences (`docs/DEPENDENTS.md:139-140`'s baseline `v0.8.2`, `ci.yml:86`'s "seven consumers"): lane B re-reads them.
