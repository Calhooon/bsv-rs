Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# #515: the docs job into the PR's required set; the benchmark job off tag events (the beta.4 Release runs' two findings)

Branch `lane/fix-515-ci-required-docs` from `origin/beta`'s tip (name the base sha in your REPORT). CI hygiene on the keeper's word of 2026-10-30 13:2xZ; the docs job's command stays as it is.

The two findings (issue #515): the Release workflow calls `ci.yml` (`workflow_call`) and its `docs` job (`name: Documentation`, `cargo doc --no-deps --all-features` under `RUSTDOCFLAGS: -Dwarnings`, `ci.yml:178-203`) is not in the pull request's required set, so one unresolved intra-doc link landed through two reviewed PRs and the first beta.4 Release run (41058300024) failed on it; and the `benchmarks` job (`name: Benchmark Regression Check`, `if: github.event_name == 'pull_request'`, `ci.yml:315-362`) ran on the tag event through the Release workflow's call with empty `github.base_ref` and `github.head_ref`, compared two baselines of the same tree, and failed 9 of 9 nanosecond-scale benches on noise against its +5% p99 threshold, so the third Release run (41076363406) reads failure while its publish succeeded.

The required set in this repository is beta's branch protection (`gh api repos/Calhooon/bsv-rs/branches/beta/protection/required_status_checks --jq '.contexts'`), pinned by `tests/arch_ci_pr_runs_the_required_set.rs` (`REQUIRED_ON_BETA`, `REQUIRED_ON_MAIN`) against the jobs a pull request runs; the captain updates the protection itself and the sequencer's list when this lands (you do not touch repository settings).

## What to do

1. `tests/arch_ci_pr_runs_the_required_set.rs`: `Documentation` added to `REQUIRED_ON_BETA` and `REQUIRED_ON_MAIN` (the docs job runs on pull requests and pushes today: confirm from `ci.yml`'s triggers and the job's `if`, if any); the test's reading of the workflow proves the job runs for a pull request; the docs comment at the constants says the captain reads the protection after the landing (the dates kept honest: the constants are the protection as it will be, say so).
2. The benchmark job on tag events: read why `if: github.event_name == 'pull_request'` did not skip it under the Release workflow's `workflow_call` (the caller's event, the `Bench` name in the run's job list: find where that job is defined on beta, `ci.yml` or another workflow file) and make it not run on a tag event (an input from the caller, or the guard reading the right context), with actionlint clean; a pull request still runs it; `tests/arch_ci_*.rs` green (they pin the workflows' shape: read them first).
3. The entry under `[Unreleased]`: the two findings, the fix, the captain's two follow-ups (the protection, the sequencer's list) named; `docs/NIGHTLY.md` or the CI docs row if one describes the required set.
4. The gate, every command in the foreground: `cargo fmt --check`; `cargo test --features "full,http"` with one `--test` per file matching `arch_*` and `fixtures_replay*`; `actionlint` on every workflow file you touch (installed locally; else say so); `cargo test --doc --all-features`; `tools/ratchet/run` on the built target; `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/beta..HEAD" .` from the repo root. One commit, no push.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.

## Report

The base sha and the tip; the constants as changed; the benchmark guard's cause and fix by file:line; the gate table; anything unverified; nothing else.
