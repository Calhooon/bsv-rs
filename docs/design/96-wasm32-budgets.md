# Design for #96: the wasm32 slices and their size budgets

Read at `origin/beta` `e228c61a` on 2026-11-09. `[X]` read at the line; `[D]` told or proposed. This lane ran no cargo: a size is a record or is named as not on record.

## 1. The exit test and the scoreboard row

The issue [X]: "**Exit test.** wasm32 builds in CI within budget for every named slice." Its body asks "a size budget per slice; `docs/DEPENDENTS.md` names each worker's slice". Label `after-cut`.

The row it moves [X] `docs/NORTH-STAR.md:28`: wasm32, "Every consumer's feature slice builds and stays within its approved size budget", producer "`wasm-sizes.json` and budgets pending #96", "not yet measured". Epic #101's row says the same [X]; the phase line is `docs/NORTH-STAR.md:98`.

"At target with recorded evidence":

| What | Command | Record |
|---|---|---|
| Every named slice measured | `python3 -B .github/scripts/wasm_sizes.py measure` [D] | artifact `wasm-sizes` holding `wasm-sizes.json` (the collector's convention, `docs/NORTH-STAR.md:40-41`, `.github/workflows/bench.yml:207` [X]) |
| Every measurement at or under its approved ceiling | `wasm_sizes.py check` [D]; exit 1 names slice, metric, bytes, ceiling | `docs/wasm-budgets.json` [D]: per slice the features, consumers, ceilings, approval reference and the recorded measurement with commit, run and `rustc -V` |
| The scoreboard shows it | `gh workflow run bench.yml --ref beta` | `scoreboard.json`, `inputs.wasm_sizes.status == "available"` with a record whose `source` names the run |

## 2. Today on beta

| Fact | Where [X] |
|---|---|
| Six slices build on wasm32: combined, watchtower, monitor, chaintracks, overlay, relay | `docs/ARCH-RULES.md:336-347` |
| Combined (`auth,wallet,transaction,overlay,socketio,wasm`) is a step of `checks` on every event; it also proves `http` stops at `build.rs` | `.github/workflows/ci.yml:803-822`, `build.rs:14-19` |
| The other five run on dispatch and on a tag's call only | `.github/workflows/features.yml:7-9,53-96`; `release.yml:91-94`; `publish` waits on `features`, not on `bench` (`release.yml:105-116`) |
| The slice table is hand-written three times (a shell `case`, the clippy loop, the deny line) | `features.yml:69-76`, `ci.yml:575-576`, `ci.yml:590` |
| Each slice prints one size to its log: a debug `cdylib` with `-C link-dead-code=yes`. "Unoptimized diagnostic library sizes, not deployable Worker sizes"; #96 is to define the artifact | `ci.yml:800-801,820-822`, `features.yml:93-96`, `docs/ARCH-RULES.md:349-354` |
| The collector has a `wasm_sizes` input and reads its own run's artifacts only; two repository baselines beside them, none for wasm | `bench.yml:183-187,207,254` |
| Most dependencies are unconditional: the `block` slice links the curves, AES, the big integers | `Cargo.toml:22-56,110,120`; optional ones at `:67,82-107,113,117,125` (`futures` `:110` and `urlencoding` `:120` unconditional) |
| The consumer map: 14 lock rows, 9 with a wasm32 target | `docs/dependents.lock:40-207`, `docs/DEPENDENTS.md:27-39` |
| The arch tests pin `wasm32 (combined)` as a step of `checks` and the five as `features.yml`'s | `tests/arch_ci_lines.rs:512,636`, `tests/arch_ci_pr_runs_the_required_set.rs:124-125` |

The lock's wasm32 rows against CI's slices [X]:

| Lock row (`docs/dependents.lock`) | Resolved feature set on wasm32 | CI slice today |
|---|---|---|
| `bsv-wallet-infra-cloudflare` (:57), `bsv-messagebox-cloudflare` (:87), `bsv-middleware-cloudflare` (:117), `bsv-agent-template` (:147), `bsv-storage-cloudflare` (:162) | `auth,wallet,transaction,wasm` (default and `script` add nothing, `Cargo.toml:161-170`) | watchtower |
| `bsv-tracker` wasm (:40) | `transaction,wasm`, no defaults | monitor |
| `chaintracks-cloudflare` (:72) | `block`, no defaults | chaintracks |
| `bsv-overlay-worker` (:192) | `overlay,wasm` | overlay |
| `bsv-overlay-app-layer` (:207) | `overlay` without `wasm` | **none** |
| no row | `auth,socketio,wasm` | relay (`docs/DEPENDENTS.md:22-24`: "also checks") |

Not on record in the tree (searched its `*.md`, `*.yml`, `*.json`, `*.toml`): any slice's byte count (the diagnostic numbers live in run logs alone); any release or compressed size; any budget or approval; the time a release measurement adds to `checks`; whether `--release` with `-C link-dead-code=yes` keeps the library in a wasm `cdylib`. The local checkouts of messagebox, storage and chaintracks (older than the lock's revisions) declare no `[profile.release]` and build with `worker-build --release` (`wrangler.toml` :62-63, :43-44, :51-56) [X at those HEADs]. Cloudflare's compressed size limits per plan are [D], in no record here.

## 3. The gap

1. No machine-readable size: the number is a log line, so the scoreboard cell cannot leave "not yet measured".
2. The measured artifact is not one a budget can mean anything about (debug, dead code kept).
3. No budget file, no approved number, no check that fails.
4. One consumer shape (`overlay` without `wasm`) has no slice; relay has no consumer row; the issue's "five of the eleven" is not the lock's nine rows.
5. A pull request builds the combined slice alone; the exit test's "CI" is undefined between pull request, dispatch and tag.
6. The collector cannot see an artifact from `features.yml`'s run.

## 4. The design

The budget judges one artifact per slice, built from this crate alone, at two metrics: raw bytes and `gzip -9` bytes of a release `cdylib` (`cargo rustc --release --lib --crate-type cdylib --target wasm32-unknown-unknown --no-default-features --features <slice> -- -C link-dead-code=yes -C opt-level=s`) [D]. It is a ceiling on what a worker can link from the slice, not a deployed size; it rises when a dependency, a table or a module enters the slice.

| Rank | Step | Change | Why it closes the gap | Proof | Risk | Size |
|---|---|---|---|---|---|---|
| 1 | The record | `docs/wasm-budgets.json` (the slice table as data, no ceilings yet); `.github/scripts/wasm_sizes.py` with `test_wasm_sizes.py`; `features.yml`'s `wasm32-slices` reads its features from the file, measures, uploads `wasm-sizes-<slice>`; `ci.yml`'s combined step prints through the same script | Gaps 1, 2: a number with its commit, run and `rustc -V` | RED: the script's unit test on a planted `.wasm` of known length; a branch dispatch of `features.yml` returns the artifacts and what section 2 lists as not on record | 0.25 | one lane, one PR |
| 2 | The consumer map as a test | `tests/arch_wasm_slices.rs`: every wasm32 row of `docs/dependents.lock` resolves to exactly one slice of `docs/wasm-budgets.json`; the clippy loop, the deny line and `ARCH-RULES.md`'s table name the same sets; add the `overlay` slice without `wasm` (Q96.4) | Gap 4: "every named slice" is a set a test enumerates | RED: the test fails today on `bsv-overlay-app-layer`; a planted lock row with an unknown set fails | 0.15 | one lane, one PR |
| 3 | The collector | `bench.yml`: `wasm_sizes` gains the repository record (`docs/wasm-budgets.json`, as `:254` reads the two others); `release.yml`: `bench` gains `needs: features` so a tag's scoreboard reads the run's own artifacts | Gaps 1, 6: the cell moves on a dispatch (repository record) and on a tag (current run) | A dispatch of `bench.yml` shows `available`; the same-run artifact read on a tag is [D] until the next beta tag proves it; fallback: a `wasm-sizes` job in `bench.yml` calling the same script | 0.3 | one lane, one PR |
| 4 | The budgets and the gate | Ceilings written into `docs/wasm-budgets.json` from step 1's hosted run by the owner's rule (Q96.1, Q96.2); `wasm_sizes.py check` as a step after the measurement; a re-record is its own commit naming its approval | Gap 3: an overrun fails a run | RED: a ceiling one byte under the recorded figure exits 1 naming slice and metric; green at the approved ceilings | 0.2 | one lane, one PR, after the owner's numbers |
| 5 | Where the gate runs | By Q96.3: the five (six with `overlay`) stay in `features.yml` and hold the publish; the combined slice's check joins the `wasm32 (combined)` step if step 1's measured time allows; the nightly dispatches `features.yml` [D]; the `arch_ci_*` tests, `ARCH-RULES.md`, `CLAUDE.md` rule 7 and `NORTH-STAR.md:28` follow | Gap 5 | The arch tests RED before the workflow edit, green after; a hosted run per event | 0.3 | one lane, one PR |
| 6 | The reachable size (report only) | `tools/wasm-probe/`, a crate of its own outside the package (as `tools/ratchet`), a `cdylib` per slice exporting a named list of public entry points; release, no dead code; a per-crate attribution list as an artifact | Closer to what a worker pays, and the attribution a reduction needs. The gated artifact only if step 1 finds the release dead-code build collapses | The probe's sizes beside step 1's in `wasm-sizes.json`; no gate | 0.4 | one lane, one PR |
| 7 | Reductions, only for a slice over its approved ceiling | Candidates named by step 6's attribution: dependencies made optional per module (the `block` slice's unconditional set, `Cargo.toml:22-56`), the wallet's `regex` Unicode tables and `url` (`Cargo.toml:84,87`), the curves' `precomputed-tables` on wasm (`Cargo.toml:32-33`) | Moves the number itself | The size delta by step 1's command; the full gate; under `src/script/` or `src/transaction/` the sibling's `harness/run --impl bsv-rs --corpus seed` identical before and after; `benches/` p99 held where a table is dropped | 0.6 | one lane per candidate; needs Q96.5 |

Identical through steps 1 to 6: every file under `src/`, every fixture, vector, conformance verdict and error text, the public shape, `Cargo.toml`, the required contexts' names. Step 7 alone can touch the manifest.

## 5. The slicing

| Order | Lane | Waits on | Gate | Parallel with |
|---|---|---|---|---|
| A | step 1, the record | the `0.9.0` cut (`after-cut`) | the script's tests, `actionlint`, a branch dispatch of `features.yml` | B |
| B | step 2, the map test | nothing (lands after A, whose file it reads) | `cargo test --test arch_wasm_slices` RED then green | A |
| C | step 3, the collector | A | a dispatch of `bench.yml` | D's question round |
| D | step 4, the budgets | A's hosted numbers, Q96.1, Q96.2 | the planted-ceiling RED | C |
| E | step 5, the gate's place | D, Q96.3 | the arch tests, a hosted run | none (it edits `ci.yml`) |
| F | step 6, the probe | A | its artifacts | C, D |
| G | step 7 | F, a failing budget, Q96.5 | per candidate | per candidate |

Shared between these lanes: `docs/wasm-budgets.json` (A, B, D), `.github/workflows/features.yml` (A, D, E), `.github/scripts/wasm_sizes.py` (A, D, F), `docs/ARCH-RULES.md` (B, E).

Collision surfaces with other open work:

- The blocking set (#734, #735, #751, #756, #775, #782, #785, #786, #796): source under `src/`; no file shared with A to F but `CHANGELOG.md` and `CLAUDE.md`. They move the sizes, so the recorded run is taken after the beta.8 cut.
- #603 (mutants): `tests/CLAUDE.md`'s table gains B's row; `mutants-entries` sits beside the step E edits.
- #90 to #93: `bench.yml` (their jobs, `scoreboard.needs` and the collector C edits), `docs/NORTH-STAR.md`'s scoreboard table; #92 and G both reach the crypto dependencies in `Cargo.toml`.
- #94, #95: `http` is outside every slice; a dependency they add to `wallet` or `transaction` meets D's gate.
- #97, #98: `ci.yml` and the `tests/arch_ci_*.rs` pins E also edits: one lands at a time.
- #99: `release.yml` (C's one-line `needs`; Q96.6 leans on its pinned toolchain).
- #100: `docs/DEPENDENTS.md`, `docs/dependents.lock`: a re-pin that changes a row's features passes B's test in the same PR.

## 6. The owner's questions

No reference decides these: the TypeScript SDK at `edf6e03` ships no wasm artifact and its root and `packages/sdk` manifests name no size budget [X: `git grep` for `size-limit`, `bundlesize`, `bundlewatch`, empty]; the node and the BRCs say nothing of it. The defaults are this crate's own practice.

- **Q96.1 The artifact a budget judges.** (a) the release dead-code `cdylib` of this crate per slice, raw and gzip (section 4); (b) the probe's reachable size (step 6); (c) each worker's own release `.wasm` built at its lock revision against the PR tree. Default: (a), the release form of what `ci.yml:820` builds. Recommendation: (a) gated, (b) reported, (c) each worker's captain's. Cost to downstreams: (a), (b) none; (c) puts every worker's own code in this crate's gate, and four of the nine rows are excluded by pin today (`docs/DEPENDENTS.md:37-39`).
- **Q96.2 The numbers and who may raise one.** (a) ceiling = the recorded figure plus 5 percent, the tolerance `tools/bench-compare` uses for p99; (b) plus 10 percent; (c) an absolute figure per slice, a share of the Workers plan limit. A raise: (i) the owner's word each time, (ii) the captain's with a cold read and the reason in the commit. Recommendation: (a), with (ii) under one percent and (i) above it. Cost: none to downstreams; a tight ceiling holds a landing that adds a dependency until the word.
- **Q96.3 Which event "CI" is.** (a) dispatch, nightly and every tag (`features.yml`, holding the publish), the pull request as today; (b) as (a) plus the combined slice's budget inside `checks` on every pull request; (c) all slices on every pull request. The owner's word of 2026-10-27 holds a pull request to the required set (`features.yml:4-5`). Recommendation: (b) if step 1 measures the added release build under two minutes of `checks`, else (a). Cost: (c) adds six release builds to every pull request; (a) finds an overrun after the landing.
- **Q96.4 The named set.** (a) the six of today; (b) the six plus `overlay` without `wasm` (the lock's `bsv-overlay-app-layer` row); (c) as (b), renamed from the workers' names (watchtower, monitor, relay) to the feature sets. Recommendation: (b), the names as logs and contexts carry them. Cost: none; a rename touches `ARCH-RULES.md` and the arch tests.
- **Q96.5 Reductions that change the feature shape** (step 7). (a) never inside 0.9; (b) additive only, every existing feature set resolving to the same code; (c) allowed with a changelog migration. `CLAUDE.md` rule 9 reads as (b). Recommendation: (b), each candidate its own word. Cost: (c) can break a worker that reaches a type through a feature it never named; (b) costs none.
- **Q96.6 The toolchain of the size job.** (a) floating `stable` as every slice job uses today (`features.yml:82-86`), the record carrying `rustc -V`; (b) a pinned toolchain, as `semver` pins 1.95.0 (`docs/DEPENDENTS.md:132-133`). Recommendation: (a) with Q96.2's headroom, moving to (b) when #99 lands a pinned release toolchain. Cost: none to downstreams; under (a) a compiler release can turn a ceiling red until a re-record.

## 7. Stack alignment

No charter, Lean rule or matrix row at `13e1fa5d748b` states a wasm size bound [X: `git grep -i 'wasm\|worker'` over `docs/MATRIX.md`, `docs/charters/`, `docs/BSV-NORTH-STAR.md`]. Nearest: the matrix's rows at `docs/MATRIX.md:29,45` (a Worker's memory, #91's subject) and the tracker charter's "One Rust crate, with a wasm32 build for the browser" (`docs/charters/tracker.md:131`), which the monitor slice serves. No machine rule and no wire changes.

- T1 scale: a slice grows with the features a worker asks for, never with the chain; the budget makes that growth a reviewed number.
- T2 verify, T4 law: not touched.
- T3 fast and cheap: a Worker pays cold start and plan limit in compiled bytes; the gate keeps them from growing unseen.
- T5 trust: "it fits a Worker" stops being a word and becomes `wasm-sizes.json` with its commit and run.
- T6 executable: one script, one data file, a RED test per step; no Lean statement.

## 8. Not in this design

- A worker's deployed size, its `worker-build` and `wasm-opt` settings, its release profile: each worker's captain (Q96.1 (c)), LOW's included.
- The re-pin train and the canary policy: #100. A slice executed under a Workers runtime: no issue yet.
- A Worker's memory at run time: #91. `http` on wasm32: #152 stays refused.
- The budgets' numbers: the owner's, from step 1's hosted run.
