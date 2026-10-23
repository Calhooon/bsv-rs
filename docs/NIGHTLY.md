# Nightly oracles

`.github/workflows/nightly.yml` is the scheduled mutation check for
[bsv-rs #81](https://github.com/Calhooon/bsv-rs/issues/81), part of
[the north-star programme](https://github.com/Calhooon/bsv-rs/issues/101).
Its cron requests 03:00 UTC daily; `workflow_dispatch` supports a manual run.
The scheduled run resolves `beta` once, then every shard and the score job
checks out that same commit. A manual run tests the selected ref.

GitHub only schedules workflows present on the repository's default branch
(`main` at this lane's baseline). Landing this file on `beta` does not activate
its cron. The captain must arrange the default-branch scheduler before calling
the schedule live. The schedule deliberately checks out `beta`; this lane does
not change the default branch or write to `main`.
See [GitHub's schedule rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).
GitHub also requires the workflow on the default branch to enable manual
dispatch, so a new file on `beta` alone cannot be dispatched yet.
See [manual dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

## What runs

`cargo-mutants` 27.1.0 is built from crates.io source with `cargo install
--version 27.1.0 --locked`. Every action is pinned to a commit with its version
beside it, following `ci.yml`. The workflow token has only `contents: read`.

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
`BSV_CONFORMANCE_DIR` is supplied. The scheduled job does not claim those skipped
portions as evidence. CI's separate vector job supplies its pinned corpus.
The sibling script harness remains the other oracle; production edits under
`src/script/` or `src/transaction/` still require its before/after seed run.

## Score and evidence

The **Mutation score floor** job writes the per-file table to the job summary.
The `mutation-scores` artifact holds the same table as Markdown and
`mutation-scores.json`. The `mutants-SURFACE-SHARD` artifacts hold the generated
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

## Findings and the fuzz lane

A surviving mutant becomes a test-gap finding. For `src/script/` and
`src/transaction/beef*.rs`, file an issue with the source commit, tool version,
exact command, mutant name and attached diff. Check for an existing issue before
filing. Reduce it to a deterministic regression test that fails with the mutant
and passes on the intended behavior. Judge a suspected behavior error against
the pinned references and the script oracle; a surviving equivalent mutation
still needs an explicit explanation. Keep behavior fixes in their own lane.
An issue for a lower floor links its complete per-file counts and the artifact.
The workflow publishes evidence for review; it does not create issues or PRs.

The fuzz jobs and their seed corpora belong to `oracle-fuzz`
([#82](https://github.com/Calhooon/bsv-rs/issues/82)); the workflow leaves their
insertion point marked. A crash input becomes an issue with the minimized input
attached, its hash, target, source commit, toolchain/sanitizer options and exact
offline replay command. Preserve the original input in the run artifact, add
the minimized input to the regression corpus through review, and require a
deterministic regression test with the fix. Inputs and logs carry no production
keys, account identifiers or deployment hostnames. Corpus additions are artifacts
for review, not automatic commits.

## Stack alignment

T1: fixed surfaces, shards and time budgets bound the tooling's work. T2: this
lane changes no proof or verification code. T3: scoped tests and parallel shards
bound turnaround. T4: the floor is explicit integer arithmetic. T5: versioned
source tools, pinned actions and read-only credentials reduce trust. T6: the
workflow, replay command, JSON evidence and score-checker tests are executable.
