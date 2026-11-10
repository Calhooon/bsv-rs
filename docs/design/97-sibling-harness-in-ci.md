# Design for #97: the sibling's harness on every PR

Read at `e228c61a` (`origin/beta`, 2026-11-09). Sibling: `bsv-script-lean@5dc337e1`. Stack: `bsv-stack-lean@13e1fa5d748b`.
`[X]` read at the line or run; `[D]` told or proposed. No cargo was run.

## 1. The exit test and the scoreboard row

Issue #97, quoted: "**Exit test.** A refusal that diverges from the node machine fails the PR with the witness transaction." Its body allows the harness "or its exported corpus through the evaluator", on every PR touching `script/` or `transaction/`, "GREEN required" `[X]`.

The row it moves: `docs/NORTH-STAR.md:23`, Script interpreter, "identical conformance verdicts", whose producer cell reads "conformance job and artifact pending #97" `[X]`; the phase line is `:102`; epic #101 carries the same row `[D]`.

"At target with recorded evidence" as a command and a record:

- Command: `.github/scripts/sibling_harness.py run --tree . --sibling <checkout at the pin> --corpus seed` (proposed, step S1), which wraps `harness/run --impl bsv-rs --corpus seed --spec recorded`; exit 0 only when every corpus is GREEN and the column equals the committed one.
- Record: `tests/sibling/column.json` (proposed), the per-corpus column at the pin, plus the run's `conformance.json` artifact naming the commit, the run id and the sibling pin. At target: a required context `sibling` ran on the merge commit and the collector holds that record.

## 2. Today on beta

| What | Where | Note |
|---|---|---|
| ts-stack corpus on every PR | `.github/workflows/ci.yml:652-656` (`checks`, `BSV_CONFORMANCE_DIR`), `:695-703` (sparse checkout at `edf6e03d`), `:745-751` (`vectors` step) `[X]` | the SDK's vectors, not the node machine's |
| the two files | `tests/conformance_scripts.rs:64-65` (env read, skip), `:501-507` (5,116 pinned), `:446` (known failures); `tests/conformance_beef.rs:38,215,442,654,883` `[X]` | 5,116 total, 4,120 run, 4,109 passed, 11 known failures: `CLAUDE.md`, "Where the numbers come from" `[D]` |
| ts-stack corpus in the nightly | `.github/workflows/nightly.yml:414,421-431,572,579-589` `[X]`; #31 closed by `b8d0a008`, `6fe627df`; #602 open (`b8d0a008`, `9640eaa7` under it) `[X]` | |
| the sibling's seed in CI | `.github/workflows/bench.yml:81,92-105`: `seed.jsonl` by the contents API at `8840488c` with `secrets.BSV_SCRIPT_CORPUS_TOKEN`; without the token `script_spend` is skipped `[X]` | judges time, never a verdict (`benches/script_spend.rs:62`) |
| an in-tree transcription of the adapter | `benches/script_spend.rs:75-168` (`engine::run_input`, `word_for`, block path), stamp `:164` `[X]` | |
| the local rule | `docs/NORTH-STAR.md:124-128`, `docs/NIGHTLY.md:406-407`: a change under `src/script/` or `src/transaction/` carries identical before and after seed runs `[X]` | by hand: a scratch copy, the `=0.7.0` pin replaced by `path` (`docs/lanes/fix-603-pushdrop.md:17`) `[X]` |
| recorded runs | `CHANGELOG.md:20557-20560` (runs `20261024-215622`, `20261024-222200`, nine corpora GREEN at `8840488`); `:20491-20493` (seed, 10,000 of 10,000, 0 witnesses); `:685`, `:1461`, `:1632` (nine corpora GREEN at `5dc337e1`, #603's lanes) `[D]` | no record file in this tree |
| the required set | `tests/arch_ci_pr_runs_the_required_set.rs:51-57` (beta: five contexts), `:61-68` (main: six) `[X]` | a PR runs exactly these |
| the scoreboard collector | `.github/workflows/bench.yml:205-208`: four inputs, none for conformance `[X]` | |

The sibling at `5dc337e1` `[X]`: `harness/run` builds `run_diff` and `spec_recorded` (`cargo build --release --locked`, Rust 1.95.0 by `harness/rust-toolchain.toml`); `--impl bsv-rs` needs cargo, git and python3 alone (`harness/README.md:25`); `--spec recorded` needs no Lean. `harness/Cargo.toml` pins `bsv-rs = "=0.7.0"` with `transaction`. Exit 0 GREEN, 1 RED (an unexplained divergence, a message outside the code table, a recorded verdict that moved), 2 setup. The report: `summary.txt`, `<corpus>.log`, `bsv-rs/manifest.json`, `bsv-rs/<corpus>.jsonl` (one witness per corpus, column and rule, the entry with its `tx`, `prevouts` and both verdicts), `spec/<corpus>.jsonl`. `harness/rules/bsv-rs.json`: 25 rows. Corpora: seed 10,000 entries (29.1 MB, one blob at `8840488c` and `5dc337e1`), flow 1,094, gen 1,157, eras 74, tx 40; the nine of `--corpus all` about 68 MB; `corpus/wire` 24.4 MB. Cost on record: the whole bsv-rs column at 0.7.0, wall 50 s on host `box`, builds apart (`docs/records/20261017-015602-column-bsv-rs-0.7.0-s3.md`). The repository is private; `Calhooon/bsv-rs` is public `[X]` (`gh repo view`).

The queue's blockers (`docs/NORTH-STAR.md:219`): #75 OPEN (its CI part landed, `6934860a`), #76 CLOSED `[X]`; "accessible corpus/evaluator at the approved pin" is open: Q97.1, Q97.2.

Not on record: a harness run at `e228c61a`; the column's per-corpus counts at the tip; the wall of the harness build and run on a hosted runner; `BSV_SCRIPT_CORPUS_TOKEN`'s scope beyond the one file `bench.yml` reads; whether the sibling's public edition is readable by a runner.

## 3. The gap

1. No CI job runs the sibling's harness; the proof is a hand procedure whose report is never stored.
2. The harness links a published crate by pin; judging a PR's tree needs the path rewrite, which nothing in this tree automates.
3. A RED today names no witness on the PR: the report is on a lane's host.
4. The sibling is private and this repository public: a token on PRs and the publication of a witness need words.
5. The harness's build breaks on a public shape change (`SpendParams` is built as a literal at `harness/src/engine.rs:324-339`; the crate's struct is `src/script/spend/mod.rs:146-182`), and its code table reads this crate's error texts: a red that is no verdict needs its own name.
6. The scoreboard has no conformance input.

## 4. The design

One command for a lane and for CI; the sibling's harness stays the judge (its classifier and code table are never copied here).

| Step | Change | Why | Stays identical | Proof | Risk | Size |
|---|---|---|---|---|---|---|
| S1 the command and the column | `.github/scripts/sibling_harness.py` (`run`, `compare`, `summary`) with `test_sibling_harness.py`; `tests/sibling/column.json`; `tests/sibling/CLAUDE.md`. `run` copies the sibling's `harness/` to scratch, rewrites the one `bsv-rs` line to `path`, settles the lock with `cargo metadata`, runs `harness/run --impl bsv-rs --corpus <c> --spec recorded --out <dir>` with `RUSTFLAGS` empty; `compare` reads `bsv-rs/manifest.json` against the column (pin, corpus sha256, entries, agreements, class rows) | gaps 1, 2; the loop's step 3 as one command with a record | no file under `src/`; the sibling's clone never edited | RED: a python unit test on a planted manifest with one unexplained row; a live RED from a scratch mutant of #603's shard B (18 of its 28 moved verdicts, `tests/script_script_603_b.rs:39-43`); GREEN at the tip; the measured wall of build and run | 0.2 | one lane, one PR |
| S2 the job | `ci.yml`: job `sibling` (checkout of the PR; sparse checkout of `Calgooon/bsv-script-lean` at the pin: `harness`, `corpus/seed`, `docs/PROVENANCE.md`; Rust 1.95.0; a cache of its own; S1's command). It always reports: when the plan (`affected_tests.py`) reaches none of `src/script/`, `src/transaction/`, `src/primitives/`, `Cargo.toml`, the workflow, the command or `tests/sibling/`, it prints `SKIP sibling (not reached)` and passes without building. `tests/arch_ci_pr_runs_the_required_set.rs`: `sibling` in `REQUIRED_ON_BETA` and `REQUIRED_ON_MAIN`; `tests/arch_sibling_pin.rs`: one pin across `ci.yml`, `bench.yml` and the column | the exit test's "fails the PR" | the five and six existing contexts; `checks`' steps; the `Test Suite` plan's outputs | RED: the arch test fails before the job exists; a dispatch on a branch carrying the planted mutant shows the context red; the protection read back after the captain's PATCH | 0.35 | one lane, one PR, after Q97.1 to Q97.3 |
| S3 the witness on the PR | `summary` writes to `$GITHUB_STEP_SUMMARY` and as `::error::` lines, for each unexplained divergence: id, rule, column, the flag word, both verdicts, `tx` hex and prevouts; three red classes kept apart: `VERDICT` (exit 1, a divergence), `TABLE` (a message outside the sibling's code table or a moved recorded verdict), `SETUP` (exit 2, the harness did not build: a shape change). Artifact `sibling-report`: `summary.txt`, logs, `bsv-rs/manifest.json`, the witnesses, `conformance.json`; never `spec/*.jsonl` | the exit test's "with the witness transaction"; gap 5 | the harness's own report files | the planted mutant's run shows the witness's `tx` in the summary; a planted extra `SpendParams` field in a scratch copy shows `SETUP`, never `VERDICT` | 0.25 | one lane, one PR, after Q97.4 |
| S4 the scoreboard | `bench.yml:205-208`: a fifth input `conformance` (artifact stems `sibling`, file `conformance.json`; repository baseline `tests/sibling/column.json`); a `sibling` job in `bench.yml` calling S1's command, so the collector's run holds a current record; `docs/NORTH-STAR.md:23` cell updated | gap 6; the row leaves "pending #97" | the four existing inputs' JSON | the collector's JSON on a dispatch names the input `available` with the commit | 0.15 | one lane, one PR |
| S5 the width | the measured wall decides: `--corpus all` on a PR if the job stays under the `Test Suite`'s wall, else seed on a PR and all nine on a dispatch and a tag's call; `run_wire` on `corpus/wire` (150 rows, the BEEF, BUMP and EF codecs) against the spec's column for `src/transaction/`; one pin: `bench.yml:103` moves from `8840488c` to the design's pin (one seed blob, so `benches/baseline.json` keeps its sha256; the stamp at `benches/script_spend.rs:164` re-read) | "transaction checks" of the title | every bench number | the column gains rows; the bench's `BSV_BENCH_CORPUS` sha256 equal before and after | 0.3 | one lane, one PR |
| S6 the waiver (only on Q97.5) | `tests/sibling/waivers.json`: entry id, column, issue, ruling, the sibling pin it expires at; a waiver naming an entry that agrees fails as stale | a ruled behaviour change landing before the sibling's table moves | GREEN stays the default; a waiver never hides an unnamed entry | unit tests: a stale waiver and an unnamed divergence refused | 0.3 | one lane, one PR |

The fallback, not ranked: an in-tree evaluator (`tests/conformance_sibling.rs` over the exported corpus, the adapter of `benches/script_spend.rs:75-168` plus each entry's `spec@<commit>` keys). It removes the build coupling but copies the sibling's classifier (25 rule rows, the code table) into this tree, where it drifts. Taken only if Q97.1 refuses the harness checkout.

## 5. The slicing

| Order | Lane | Waits on | Gate |
|---|---|---|---|
| 1 | S1 (measures the wall; writes the column) | nothing; needs one builder slot | python unit tests; GREEN at the tip; the planted RED |
| 2 | S2 and S3, in parallel | S1 landed; Q97.1, Q97.2, Q97.3 (S2); Q97.4 (S3) | the arch tests; a dispatch showing the three red classes |
| 3 | S4 | S3's `conformance.json` | the collector's JSON |
| 4 | S5 | S1's measured wall; S2 | the column's new rows; bench sha256 equal |
| 5 | S6 | Q97.5 | unit tests |

Files two lanes touch: `.github/scripts/sibling_harness.py` (S1, S3, S6); `ci.yml` (S2, S5); `tests/sibling/column.json` (S1, S5); `bench.yml` (S4, S5). S2 keeps to the workflow and S3 to the script.

Collision surfaces:

- The blocking set of `0.9.0`: no shared file. #734 (`src/transaction/merkle_path.rs`) and #782 (`src/script/templates/`) are reached by the new context only if S2 lands before them; land S2 after the cut (the issue is labelled `after-cut`). #735, #751, #756, #775, #785, #786, #796 touch identity and overlay, never reached.
- #603: its lanes run the procedure by hand (`docs/lanes/fix-603-*.md:17`); after S1 they call the command. `nightly.yml` is untouched.
- The sibling designs: #90 shares `benches/script_spend.rs`, `bench.yml:92-105` (the seed's pin and token) and the scoreboard row `NORTH-STAR.md:23`, and S2's context is its "conformance run identical" proof; #91 to #93 share the collector block `bench.yml:205-208` and reach `src/transaction/` or `src/primitives/` (they run under the gate); #96 and #98 each add a PR job, so they share `ci.yml` and `tests/arch_ci_pr_runs_the_required_set.rs:51-68` (land one at a time); #98 may share `affected_tests.py`; #99 shares the tag's call (`release.yml` passes the token to `bench.yml` at `:110`, and must pass it to `ci.yml`); #100 shares nothing.
- Any lane adding a public field to `SpendParams` (#90, #91) turns the harness's build red (`SETUP`) until the sibling moves: the keeper's sequencing, named in S3.

## 6. The owner's questions

- **Q97.1 The sibling in a public repository's CI.** Options: (a) a read-only token to the private sibling as a repository secret, read by the one job `sibling` on PRs from this repository's branches; (b) wait for the sibling's public edition and check it out without credentials, as ts-stack is at `ci.yml:695-703`; (c) the in-tree evaluator over an exported corpus. Reference-shaped default: `bench.yml:92-105` already does (a) for one file. Recommend (a) now and (b) when the edition exists. Downstreams: none (CI only).
- **Q97.2 A PR without the secret (a fork).** Options: (a) the context fails closed, a maintainer pushes the branch; (b) it skips loudly and passes, as `script_spend` does (`bench.yml:96-99`). Recommend (a): a required context passing unread is a hole. Downstreams: none.
- **Q97.3 A sixth required context, or a step of `checks`.** Options: (a) a job `sibling` of its own, added to both lines' protection by the captain; (b) a step in `checks` (`ci.yml:652`), no protection change, the secret then visible to every step of that job. Recommend (a): the secret stays in one job. Downstreams: none.
- **Q97.4 The witness in public.** The exit test wants the witness transaction on the PR; the corpus is private and its export lists withhold named entries (58 `gen` spends, 2 `road`, `corpus/INDEX.md:7` at the pin). Options: (a) print id, verdicts, `tx` and prevouts for seed witnesses, and the id alone for an entry of a corpus with withheld rows; (b) print ids only, the transaction read from the sibling by whoever holds access; (c) print everything. Recommend (a). Downstreams: none.
- **Q97.5 A ruled divergence before the sibling's table moves.** The harness at a pin reads RED when this crate changes a verdict or an error text under `src/script/` by ruling (#657 changed CHECKMULTISIG's words). Options: (a) no waiver: the sibling's rules move and the pin moves in one PR here; (b) S6's waiver file, each row naming an issue and a ruling, expiring at the next pin. Reference-shaped default: `EVALUATION_KNOWN_FAILURES` (`tests/conformance_scripts.rs:446`) is (b) for the ts-stack corpus. Recommend (a) while the sibling's captain answers within a day, (b) if a landing ever waits on it. Downstreams: none new; an error text they match on stays #76's fixture question.
- **Q97.6 The pin.** `5dc337e1` (NORTH-STAR's pointer, 2026-10-19) for the job, the column and `bench.yml`; a move is a commit of its own with the column re-recorded. Recommend yes; the harness's `=0.7.0` pin is the sibling's and stays.

## 7. Stack alignment

The node machine is the sibling's Lean definition judged by its harness: `harness/README.md` and `docs/PROVENANCE.md` at `bsv-script-lean@5dc337e1` (`NORTH-STAR.md:179`); the matrix's nearest row is a broadcaster's policy rejection (fee, size, script, standardness), `docs/MATRIX.md:22` at `13e1fa5d748b` `[X]`. No charter word, wire shape or Lean rule moves.

- T2 verify: this crate's script verdicts checked against the specification entry by entry.
- T4 law: the rule stays in script; the job decides nothing.
- T5 trust: "a lane ran it" becomes a required context with a record.
- T6 executable: every RED is a replayable witness (id, word, tx, prevouts).
- T1, T3: not touched.

## 8. Not in this design

- The other implementations' columns and `--spec live` (Lean): the sibling's own gate.
- The sibling under every mutant in the nightly: #602 and #603.
- Throughput on the corpus: #90. The ts-stack corpus: unchanged (#31).
- The signer column (`run_signer`): it needs a regtest node; #92's design.
- The harness's `bsv-rs` pin and rules: the sibling's lanes, through the keeper.
- A release, a consumer's pin, the protection PATCH: the captain's and the owner's.

## As built (S1 and S2 in one PR, #853, 2026-11-10)

Departures from the plan above, each stated where it was made (`docs/lanes/fix-97-s1.md`, the CHANGELOG entry, `ci.yml`'s `sibling` comment):

- The pin is `Calhooon/bsv-script-lean@1c051eae`, the public edition (an export of `da684279`, a descendant of `5dc337e1`), not `5dc337e1`: the private repository is archived and unread by the job. No token; nothing vendored. The public edition withholds 150 `gen` entries; the command drops them from its staged copy and the column counts them.
- `--corpus all` on every pull request (S5's width decided by the measured wall), not seed alone.
- Q97.5 was ruled as a split, not (a) or (b): the node's verdicts with no waiver; this crate's words against `tests/sibling/column.json`, re-recorded in the commit that changes them. S6 is not built.
- `sibling` is in `REQUIRED_ON_BETA` alone (fixes are born on beta), not in `REQUIRED_ON_MAIN`.
- No reach filter (#853's fold, the captain's ruling of 2026-11-10): the job builds and judges on every pull request into beta, push to beta, dispatch and tag call, about 1m7s on GitHub. The plan step's `grep -E` the PR opened with missed `src/lib.rs`, `build.rs` and a rename out of a listed path, and no path list sees a dependency's release (no `Cargo.lock` is tracked); `tests/arch_ci_pr_runs_the_required_set.rs` refuses a condition on the job's steps.
- Explained rows are refused (#853's fold): `--record` records no run carrying a rules row or an abort witness and at a fixed pin moves words only; compare is RED on any rules row of the run; a column carrying one is exit 2.
- The judging step cannot absorb its own failure (#853's second fold): it is pinned byte for byte in `tests/arch_ci_pr_runs_the_required_set.rs` (`SIBLING_STEP`, no `continue-on-error`, no `defaults:`), a run must carry every corpus the column does, and `--record` at a fixed pin refuses any entry whose verdict moved (two offsetting flips keep every total). Since #853's third fold the pin is the whole job (`SIBLING_JOB`, its key line to its last) and what it inherits (`SIBLING_INHERITS`: the workflow's `permissions:`, `concurrency:` and `env:`; `WORKFLOW_KEYS`, no `defaults:`), and the context `sibling` is the job's alone: a step inserted before the judging one, a job- or workflow-level `env:` key (`BASH_ENV`, `PATH`, `PYTHONPATH`, `RUNNER_TEMP`), a job `container:`, another checkout action or `ref:`, which the second fold's pin of one step passed (its scoped cold re-read), are each refused. The pin travels in the pull request's own tree beside the job it holds; holding it against a pull request is the next stage (the judge read from beta, reported by its own App).
- `tests/arch_sibling_pin.rs` (one pin across `ci.yml`, `bench.yml` and the column) is not built: `bench.yml` still reads the seed at `8840488c`; the column's pin is checked against the checkout at run time only (`sibling_harness.py` `compare`, exit 2).
- S3's witness transaction on the pull request and S4's scoreboard input are not built: a divergence is named by id from `run_diff`'s log.
