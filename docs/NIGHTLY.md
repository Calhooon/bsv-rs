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
for a prerelease; the push matrix on the protected branches is `ci.yml`'s own.
Its `ci-full` job dispatches `ci.yml` on `beta` and on `main`, so each line's
whole matrix runs at its tip (a pull request runs only its line's required
set). A dispatched run resolves the selected ref once, then every mutation
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
applies to `cargo test --no-run`. The library target is essential: it includes
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
`tests/CLAUDE.md` documents these suites. The conformance targets also exercise
the committed vectors; their external ts-stack corpus portions skip unless
`BSV_CONFORMANCE_DIR` is supplied. The dispatched job does not claim those skipped
portions as evidence. CI's separate vector job supplies its pinned corpus.
The sibling script harness remains the other oracle; production edits under
`src/script/` or `src/transaction/` still require its before/after seed run.

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

The default floor is 80% per file. `MUTATION_FLOORS` in the workflow contains
only explicit exceptions, with that file's complete measured score rounded
down and a link to its improvement issue. Partial samples cannot establish or
lower a floor. Raising a floor follows a complete run with the same test command;
an unexpected failure is investigated, never automatically ratcheted downward.

## Local replay

Use the pinned tool, set `CARGO_TARGET_DIR` to a dedicated directory under
`/Volumes/Lanes/targets/` or `~/bsv/targets/`, and put `TMPDIR` on the lane volume.
Use a different target directory for each concurrent run. These commands run
all generated mutants for the named file, with the workflow's test selection:

```sh
RUN_ROOT="/Volumes/Lanes/out/bsv-rs/oracle-nightly/$(date -u +%Y%m%dT%H%M%SZ)"
python3 .github/scripts/nightly_mutants.py run --surface merkle \
  --output "$RUN_ROOT/merkle"
python3 .github/scripts/nightly_mutants.py run --surface wire \
  --file src/wallet/wire/encoding.rs \
  --output "$RUN_ROOT/encoding"
python3 .github/scripts/nightly_mutants.py report \
  --input "$RUN_ROOT" --output "$RUN_ROOT/scores.json"
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

**What runs.** One job per target of `fuzz/Cargo.toml` (18 today; the table is in `fuzz/fuzz_targets/CLAUDE.md`), each built with `cargo fuzz build -O` on the pinned nightly (`FUZZ_TOOLCHAIN`, `cargo-fuzz` by version) and run for one hour from its checked-in corpus `fuzz/corpus/<target>/` (`-fork=2 -ignore_crashes=1 -max_total_time=3600`): a crash is recorded and the run goes on.

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
