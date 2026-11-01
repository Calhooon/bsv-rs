# Nightly oracles

`.github/workflows/nightly.yml` carries the on-demand mutation check for
[bsv-rs #81](https://github.com/Calhooon/bsv-rs/issues/81) and the fuzz matrix
for [bsv-rs #82](https://github.com/Calhooon/bsv-rs/issues/82), part of
[the north-star programme](https://github.com/Calhooon/bsv-rs/issues/101).
Never on a push or a PR: the gate is `ci.yml`. It runs on demand only,
`workflow_dispatch` on the line to measure (`gh workflow run nightly.yml --ref
beta`), never on a schedule: the owner's word of 2026-10-27 (the nightly runs
were a waste of resources) took the 03:00 UTC cron off both lines. One
dispatched measurement before each minor tag (0.9.0 to `main` gets one), none
for a prerelease (`RELEASING.md` step 3 names the dispatch: this workflow is
not callable, so `release.yml` cannot run it before a tag). A push to a
protected branch runs `ci.yml`'s required set, nothing more (the owner's word
of 2026-10-27). Its `ci-full` job dispatches `ci.yml` on `beta` and on `main`,
so each line's whole test matrix and `dependents` run at its tip (a pull
request and a push run only the line's required set). The other measurements
are workflows of their own, dispatched on the line and called by `release.yml`
before every tag: `bench.yml` (build and scoreboard; comparisons only on branch
dispatches), `msrv.yml`, `features.yml`, `machete.yml`, `docs.yml` (actionlint).
`Documentation` is a required job in `ci.yml` on both lines after #515's
protection update: it also runs on pull requests and pushes, with
`cargo doc --no-deps --all-features` under `RUSTDOCFLAGS: -Dwarnings`.
The captain adds that context to `beta`'s protection at the landing and to
`main`'s once `main`'s `ci.yml` carries the job, reading each back, then
updates the sequencer's required-check list. The constants
in `tests/arch_ci_pr_runs_the_required_set.rs` name that intended set.
A dispatched run resolves the selected ref once, then every mutation
shard, the score job and every fuzz job check out that same commit.

GitHub requires the workflow on the default branch (`main`) to enable manual
dispatch, so the file lives on both lines, ported by `git cherry-pick -x`.
See [manual dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

Permissions are scoped per job: every job has `contents: read`; only the fuzz
job, which files its crashes as issues, adds `issues: write`.

## What runs

`cargo-mutants` 27.1.0 is built from crates.io source with `cargo install
--version 27.1.0 --locked`. Every action is pinned to a commit with its version
beside it, following `ci.yml`. The mutation jobs' token has only `contents: read`.

There are four disjoint shards per surface, at most twenty concurrent jobs.
Each shard uses one mutation worker, its own `CARGO_TARGET_DIR`, a 120-second
test timeout (300 seconds for BEEF) and a 300-second build timeout per mutant. A job is limited to
six hours. A failed baseline, interrupted job or missing shard fails the score
check. These limits bound work; they never turn an unfinished run into a score.

The runner uses copied source trees, with `--in-place` absent. Both copies and
build products are under the runner's temporary directory, outside the checkout.
One worker per shard prevents independent copies from sharing mutable build
products through a single `CARGO_TARGET_DIR`.
The mutation runner enables `CARGO_INCREMENTAL=1`, including when the host
environment disables it, so each mutation can reuse the baseline's compilation.

The test command is `cargo test --features "full,http" --locked --lib`, followed
by one `--test NAME` for every suite in the row below. The same target selection
applies to `cargo test --no-run`. The library commits no `Cargo.lock`, so each
mutation job runs `cargo generate-lockfile` in its checkout before cargo-mutants
copies it: `--locked` then holds the baseline and every mutant to one graph
(#574). Cargo runs every test binary through
`.github/scripts/test-runner-memory-ceiling.sh`
(`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER`), which sets `ulimit -v` to
4,000,000 KB (`MUTANTS_TEST_VMEM_KB`), well under half the 16 GB hosted runner,
since a doubling Vec touches up to the ceiling before its next reserve fails: a
mutant whose loop allocates without bound aborts on the refused allocation and
is caught, where it once exhausted the runner before its test timeout; the
baselines peak at 805 MB of address space, and a step before the mutants runs
the library's test list through cargo and fails unless the runner's marker
(`MUTANTS_CEILING_MARKER`) records that limit (#577). The library target is essential: it includes
the codec and interpreter's inline tests. Unit tests are scoped with libtest
`--skip` arguments to keep the relevant source namespace: `script`, `transaction`
for BEEF, `transaction::merkle_path`, `wallet::wire`, or `wallet::substrates`.
Integration suites run in full except the BEEF cost check named below. All
skips are recorded in the exact command in each run artifact.

BEEF omits the independent `transaction::merkle_path` unit namespace. Merkle
omits its three randomized `linear_root_equivalence_tests`, whose exhaustive
rescans take minutes in a debug build, and retains its focused unit tests and
the three integration suites below. The full CI library gate and the lane's
full-suite check retain those randomized tests; a mutation score never claims
they ran for each mutant. The mutation loop also omits `merkle_path_cost`,
`beef_deep_chain`, `beef_stream_deep`, `beef_stream_pause` and
`beef_stream_linear_spend`: these include
large stress cases and wall-clock bounds, which remain in the lane's full-suite
gate. Within `beef_stream`, `the_whole_path_walks_a_wide_bump_in_linear_time`
also stays in that gate, so its wall-clock bound cannot count as a caught mutant.
HTTP tests use `wiremock`; the job has no wallet
credentials and makes no live wallet call.

| Surface | Files mutated | Integration test targets |
| --- | --- | --- |
| script | `src/script/**/*.rs` | Every `tests/script_*.rs`, `template_tests`, `sighash_tests`, `resource_limits`, `conformance_scripts`, `identity_spend_witness` |
| BEEF | `src/transaction/beef*.rs` | `transaction_tests`, `beef_stream`, `beef_limits`, `beef_atomic_graph`, `conformance_beef` |
| merkle path | `src/transaction/merkle_path.rs` | `transaction_tests`, `merkle_path_lone_leaf`, `conformance_beef` |
| wallet wire | `src/wallet/wire/**/*.rs` | `wallet_tests`, `wire_method_roundtrip_tests`, `wallet_wire_cross_sdk_tests` |
| wallet substrates | `src/wallet/substrates/**/*.rs` | `wallet_tests`, `wallet_http_json_busy_tests` |

The globs include files directly in each directory and its descendants.
`tests/CLAUDE.md` documents these suites. The conformance targets read the
ts-stack corpus and skip, passing vacuously, when `BSV_CONFORMANCE_DIR` names
no `META.json`. Since #602 each mutation job checks the corpus out as `ci.yml`'s
`vectors` job does (`bsv-blockchain/ts-stack` at
`edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9`, the commit the pinned totals were
audited against, sparse `conformance`, no credentials, `path: ts-stack`), sets
`BSV_CONFORMANCE_DIR` to `$GITHUB_WORKSPACE/ts-stack/conformance` in the job's
environment and asserts `META.json` before the baseline, so `conformance_scripts`
(script surface) and `conformance_beef` (BEEF and Merkle surfaces) run the
corpus's script evaluation (5,116 vectors) and BEEF vectors against every
mutant. The runner passes its environment to cargo-mutants, which passes it to
each test run in its copy of the tree; the variable names the checkout's corpus,
not the copy's (cargo-mutants also copies the `ts-stack/` directory, about
10 MB, since it is not ignored: harmless). Unset, the suites' default
`../ts-stack/conformance` resolves against that copy under `TMPDIR`, never the
checkout, so a mutation run without the variable reads the narrow figure even
with ts-stack checked out beside bsv-rs.
The sibling script harness remains the other oracle; production edits under
`src/script/` or `src/transaction/` still require its before/after seed run.

### The narrow figure and the widened one (#602)

The first complete scoreboard, run 41294262955 at `ab155018` (2026-11-01,
artifact 13083854460), was measured without the corpus: the conformance suites
skipped in every baseline and every mutant, so its scores (the sixteen gate-path
files below 80 and their 517 survivors, #603; the floors table on #602) are the
**narrow** figure. The **widened** figure is the first dispatch after #602's
landing, the same selection with the corpus read. Floors are set from the
widened figure, never the narrow one, and the census record carries both
side by side, so a moved score says it moved because the corpus caught what the
narrow suites did not. The widened figure is run 41327640129 at `b8d0a008`
(2026-11-01 16:41Z): ten gate-path files moved (`spend/bitwise.rs` 36.36% to
85.71%, `merkle_path.rs` 53.93% to 71.91%, `spend/splice.rs` 77.67% to 82.04%
among them), none elsewhere; the floors and the record are below
("The floors (#602)").

The local witness on one file (`src/script/not_judged.rs`, three viable
mutants, the script surface's selection, cargo-mutants 27.1.0, macOS, 2026-11-01).
libtest captures a passing test's output, so neither the suite's `SKIP` line nor
its summary line reaches `mutants.out/log/`; the logs show the corpus by the
`conformance_scripts` binary's time, and a corpus that cannot be read shows it
by failing the baseline:

| Reading | `conformance_scripts` in the baseline's log | Caught | Missed | Score |
| --- | --- | ---: | ---: | ---: |
| narrow (corpus unset) | 3 passed in 0.00 s (the suites return at the missing `META.json`) | 2 | 1 | 66.67% |
| widened (corpus at `edf6e03`) | 3 passed in 1.44 s (the corpus's 5,116 vectors run) | 2 | 1 | 66.67% |
| broken (the copy at `edf6e03` without `vectors/sdk/scripts/evaluation.json`) | `conformance_scripts_evaluation ... FAILED`: the unmutated baseline fails, no mutant runs | | | |

On this file the corpus changes no outcome: the two `flags_message` mutants are
caught by earlier suites, and the surviving `Display::fmt` replacement is not
observed by the corpus either (`conformance_scripts` judges verdicts and never
names `NotJudgedCause`). The witness shows that the variable reaches the mutants'
test runs (the binary's time in the baseline's and the surviving mutant's log,
and the broken corpus's red baseline) and what the oracle now runs; the score
movement on the other files is the widened dispatch's to measure. Run directly
with `--nocapture`, the suite prints its summary, `total=5116 run=4120
passed=4109 unsupported=959 skipped=37 known_failures=11 failures=0
panics=0`.

## Score and evidence

The **Mutation score floor** job writes the per-file table to the job summary.
The `mutation-summary` artifact holds the same table as Markdown and
`mutation-summary.json`. The `mutants-SURFACE-SHARD` artifacts hold the generated
candidate list, source commit, exact command, outcomes and diffs. Retention is
30 days. They omit `lock.json`, debug logs and arbitrary test output, which can
carry host metadata or test values. Download evidence before retention expires;
on a lane host, keep it under `/Volumes/Lanes/out/bsv-rs/oracle-nightly/`.

For each file:

```text
viable = caught + missed + timeout
score = 100 * caught / viable
pass = 100 * caught >= floor * viable
```

Unviable mutants are reported but excluded from the denominator. A timeout is
not a caught mutant. A file with generated mutants but no viable result fails.
Files generating no mutants are listed as `NO MUTANTS`, without a numeric score.
The check requires every candidate to have exactly one recognized outcome,
successful baselines, matching tool versions, matching source commits and all
20 shards. Duplicate, missing, corrupt or unfinished evidence fails closed.
The integer comparison avoids accepting a displayed percentage rounded upward.

A file whose generated mutants are all unviable (each replacement refused by
the compiler, so nothing a test can catch) is listed as `NO VIABLE MUTANTS`,
without a score, when its surface has viable mutants elsewhere; if a surface
has no viable mutant at all, the build is read as broken and every such file
fails (#81's fail-closed intent, kept). `src/wallet/substrates/http_json/answer.rs`
is the one such file in both 2026-11-01 runs: its two mutants replace
`refusal -> Error` and `success -> Result<R, Error>` with `Default::default()`,
and `Error` has no `Default`. A floor cannot be set on such a file.

### The floors (#602)

On the owner's word of 2026-11-01 14:1xZ through the keeper: 80% caught on
the gate paths (`src/script/**`, `src/transaction/beef*.rs`,
`src/transaction/merkle_path.rs`), and elsewhere (`src/wallet/wire/**`,
`src/wallet/substrates/**`) the measured value is the floor, never lowered,
raised by a landing that raises the score. The floors live in the ratchet's
record, `docs/ratchets.json`'s `mutation_floors` member (`{"percent": N,
"issue": URL}` per file), which the score job reads from the measured commit
(`nightly_mutants.py report --floors docs/ratchets.json`, the default; the
workflow's former `MUTATION_FLOORS` string is gone) and which
`tools/ratchet/run --check --against <base>` refuses to lower or remove
([RATCHETS.md](RATCHETS.md)). A gate-path file carries no entry (the report
refuses one); a file elsewhere at or above 80 carries none until a raise needs
one. A floor under 80 names its improvement issue. Partial samples cannot
establish or lower a floor; an unexpected failure is investigated, never
ratcheted downward.

The 29 entries are the widened run's scores rounded down (run 41327640129,
written by `.github/scripts/mutants_record.py floors --write`); every file
elsewhere scored the same in both runs, so they equal #602's narrow table.
The record of both runs, every measured file side by side, the gate paths'
survivors by `file:line:column` and the survivors the corpus killed, is
`docs/census/mutants-2026-11-01.md` (and `.json`), written by
`mutants_record.py write` from the artifacts (the commands are in the record).

| Figure | Run | Scoreboard as it ran (80 everywhere) | Under the record's floors |
| --- | --- | --- | --- |
| narrow, no corpus | 41294262955 at `ab155018` | 31 PASS, 46 FAIL, 15 NO MUTANTS | |
| widened, corpus at `edf6e03` | 41327640129 at `b8d0a008` | 33 PASS, 44 FAIL, 15 NO MUTANTS | 62 PASS, 14 FAIL, 15 NO MUTANTS, 1 NO VIABLE MUTANTS |

The fourteen failures are the gate-path files below 80 (548 gate-path
survivors under the widened oracle, 396 of them on those fourteen; 97 of the
narrow run's 643 killed by the corpus, all in the script and BEEF/Merkle
surfaces; two timeouts new to the widened run, both caught in the narrow
one). They stay red until #603's lanes land: that is the gate.

## Local replay

Use the pinned tool, set `CARGO_TARGET_DIR` to a dedicated directory under
`/Volumes/Lanes/targets/` or `~/bsv/targets/`, and put `TMPDIR` on the lane volume.
Use a different target directory for each concurrent run. These commands run
all generated mutants for the named file, with the workflow's test selection:

```sh
RUN_ROOT="/Volumes/Lanes/out/bsv-rs/oracle-nightly/$(date -u +%Y%m%dT%H%M%SZ)"
# The widened figure (#602): the corpus at the pinned commit, an absolute path.
export BSV_CONFORMANCE_DIR=/absolute/path/to/ts-stack/conformance
python3 .github/scripts/nightly_mutants.py run --surface merkle \
  --output "$RUN_ROOT/merkle"
python3 .github/scripts/nightly_mutants.py run --surface wire \
  --file src/wallet/wire/encoding.rs \
  --output "$RUN_ROOT/encoding"
python3 .github/scripts/nightly_mutants.py report \
  --input "$RUN_ROOT" --output "$RUN_ROOT/scores.json"  # floors: docs/ratchets.json
python3 -B -m unittest discover -s .github/scripts -p 'test_nightly_mutants.py' -v
```

Use a fresh output parent for each experiment: the runner refuses an existing
directory so an interrupted retry cannot inherit old evidence. A local subset's
report omits `--expected-shards`; it
does not establish that the whole schedule passed. A bounded sample can use
`--shard 0/N`, with round-robin selection, but its fraction and untested candidates
belong in the report. Missing shards produce `PARTIAL` rows and fail the score
check even when a sample catches every selected mutant.

## Mutation findings

A surviving mutant becomes a test-gap finding. For `src/script/` and
`src/transaction/beef*.rs`, file an issue with the source commit, tool version,
exact command, mutant name and attached diff. Check for an existing issue before
filing. Reduce it to a deterministic regression test that fails with the mutant
and passes on the intended behavior. Judge a suspected behavior error against
the pinned references and the script oracle; a surviving equivalent mutation
still needs an explicit explanation. Keep behavior fixes in their own lane.
An issue for a lower floor links its complete per-file counts and the artifact.
The mutation jobs publish evidence for review; they do not create issues or PRs.
The fuzz job files its own crashes (below).

## Fuzz (#82)

**What runs.** One job per target of `fuzz/Cargo.toml` (19 today, pinned to the matrix by `tests/arch_fuzz_targets_dispatched.rs`; the table is in `fuzz/fuzz_targets/CLAUDE.md`), each built with `cargo fuzz build -O` on the pinned nightly (AddressSanitizer, but `-s none` for `fuzz_script_spend_default`, whose 128 MiB budget ASan's resident set takes past the 2,048 MB RSS limit, #398) (`FUZZ_TOOLCHAIN`, `cargo-fuzz` by version) and run for one hour from its checked-in corpus `fuzz/corpus/<target>/` (`-fork=2 -ignore_crashes=1 -max_total_time=3600`): a crash is recorded and the run goes on.

**Where the results land.**

| What | Where |
|---|---|
| New corpus entries | the artifact `corpus-<target>` (14 days). The repository does not let a workflow open a pull request ("Allow GitHub Actions to create and approve pull requests" is off), so no PR is opened: the captain merges an artifact by hand (below). |
| Crash, OOM and timeout inputs | the artifact `crashes-<target>` (90 days) |
| The count of new entries, and whether a crash was found | the job summary |

**What a crash becomes.** An issue, one per target and panic site, titled `fuzz: <target>: <repo-relative path>:<line>:<col>` (or `fuzz: <target>: oom` / `timeout`), with the source commit, the toolchain and the cargo-fuzz version on one line, the panic's tail and the input as base64 (up to 4,096 bytes; larger ones are in the artifact). A site that already has an open issue gets a comment with the night's run instead. The job then fails, so the night is red until the issue is closed by a fix and its regression test (CLAUDE.md rule 2), never by editing the target. A target may skip one known case while a ruling is pending, with the issue's number at the skip (`fuzz_ecies`: #109; `fuzz_auth_messages`: #110). A panic inside the crate is never skipped (#108).

**Merging an artifact.** Download `corpus-<target>` into a scratch directory, then minimize it into the checked-in corpus and commit the result in its own commit:

```bash
cargo +nightly fuzz cmin <target> fuzz/corpus/<target> <scratch>   # keeps the entries that add coverage
du -sh fuzz/corpus                                                  # the checked-in corpora stay under 2 MB in all
```

**Locally.** `cargo +nightly fuzz run <target> fuzz/corpus/<target> -- -max_total_time=600`. On a macOS host whose default SDK's `.tbd` files the linker cannot read (`ld: tapi error: malformed file`), set `SDKROOT` to an older SDK (`/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`). The seeds are written by `fuzz/corpus-gen` (`cargo run --release --manifest-path fuzz/corpus-gen/Cargo.toml -- --rest <dir>`); rerunning it rewrites its own seeds by name and leaves the merged entries.

A crash's input is preserved in the run artifact; its minimized form joins the
regression corpus through review, with the deterministic regression test of
the fix. Inputs and logs carry no production keys, account identifiers or
deployment hostnames. Corpus additions are artifacts for review, not automatic
commits.

## Stack alignment

T1: fixed surfaces, shards and time budgets bound the tooling's work. T2: this
lane changes no proof or verification code. T3: scoped tests and parallel shards
bound turnaround. T4: the floor is explicit integer arithmetic. T5: versioned
source tools, pinned actions and read-only credentials reduce trust. T6: the
workflow, replay command, JSON evidence and score-checker tests are executable.
