Every gate and every test runs in the foreground, in your turn: no background job, no subagent; the REPORT is the last thing you write, and a turn that ends with a command still running is a stopped lane.

# main: the cherry-pick of #515 (the `Documentation` job into main's CI, the benchmark comparison off tag events), CI-only, in beta's order (the keeper's word, 2026-10-31 03:1xZ, the rulings page)

Branch `lane/main-515-ci-cherry-pick` from `origin/main` (`5ec5bf98`, version 0.8.3). One commit, made by `git cherry-pick -x a67ea4119e354b129953987475c5466cb18b7342` (the #524 squash on beta; keep the `(cherry picked from commit …)` line: main's `beta-born` check reads it). Never push.

## The reading (the keeper's)

The owner's "no merge to main until god tier" is about 0.9.0's line crossing to main. This cherry-pick carries a workflow job and no code of 0.9.0: CI's hygiene on the stable line. So: CI-only. Nothing of 0.9.0's code, API or documentation of 0.9.0 features enters main through this PR.

## What to carry, and how to resolve

1. The four workflows: `.github/workflows/ci.yml` gains the `docs` job named `Documentation` as beta's has it (`cargo doc --no-deps --all-features` under `RUSTDOCFLAGS: -Dwarnings`, no `if:`, so it runs on pull requests, pushes, dispatches and the Release workflow's call); `docs.yml` keeps actionlint and loses the doc build if main's `docs.yml` carries it (read main's `docs.yml` first: on main the measurements and docs run on dispatch, `5ec5bf98`'s shape); `bench.yml`'s comparison refuses a caller on a `refs/tags/` ref (`if: ${{ !startsWith(github.ref, 'refs/tags/') }}` on the comparison job, as beta's `bench.yml:70`); `release.yml` as beta's change has it where main's file has the corresponding lines. Resolve every conflict by reading both lines' files; say in the REPORT how each hunk was resolved. `actionlint` on every changed workflow.
2. `tests/arch_ci_pr_runs_the_required_set.rs` on main: `Documentation` into `REQUIRED_ON_MAIN` (13) and, if the file names beta's set, `REQUIRED_ON_BETA` (12), with the comment saying the protection follows the landing (the captain PATCHes main's contexts after the job has reported green on main, never before); every `arch_*` test on main green on the tip (`cargo test --features "full,http" --test arch_ci_lines --test arch_ci_pr_runs_the_required_set --test arch_secrets_scan_scope`, or main's feature set if `full,http` is not main's; read main's `Cargo.toml` features).
3. `CHANGELOG.md` on main: one `### Changed:` entry under `## [Unreleased]`, in main's own words and shape (read main's existing entries), the two CI facts and the cherry-pick source (`beta a67ea411`, PR #524, issue #515); none of beta's 0.9.0 entry text that names 0.9.0 features.
4. Documentation files: `CLAUDE.md`, `README.md`, `RELEASING.md`, `docs/NIGHTLY.md` take the same edit only where main's file has the corresponding paragraph (the CI badge/required-set text, the release ritual's required list); a hunk that describes 0.9.0 is dropped. `benches/README.md` and `docs/ARCHITECTURE.md` do not exist on main: drop those hunks, do not create the files.
5. The docs build on main's tree, after the cherry-pick: `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features` (main's features). If it is red, the fix rides this PR as docs only (an intra-doc link, a doc comment), named line by line in the REPORT. If making the docs build would need a code change, STOP: commit nothing of it, write the REPORT with the failing lines and the words "code change needed", and end.

## Gate (foreground; main's commands, read from main's `ci.yml`, including its toolchain pin)

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; the three `arch_*` binaries above; `cargo test --doc --all-features`; the docs build above; `actionlint` on the changed workflows; `tools/ratchet/run --check --against 5ec5bf98` with `CARGO_TARGET_DIR` outside the checkout (main's ratchet bounds are tighter than beta's); `cargo semver-checks check-release --baseline-rev 5ec5bf98 --release-type patch` (no public change expected: say what it reports); `gitleaks git --redact --no-banner --exit-code 1 --log-opts="origin/main..HEAD" .` from the repo root.

## REPORT

Tip sha and message (with the cherry-pick line); every file changed with the hunks' resolutions (carried, adapted, dropped and why); the docs build's result on main's tree and any docs-only fix; the gate's results in a table; anything unverified; nothing else.

Rules: never end your turn with a command running in the background; commit on the branch, never push; no test or probe on a default URL or port (a MetaNet Client listens on 3301, 3321 and 2121 on this machine; another session's process on 3390); do not read `~/bsv/bsv-low/` or `~/vault/`, and do not grep across `~/bsv/` as a whole (the reference and the downstreams are read by their named paths); vectors are written by recorders, never by hand; scratch copies under `$TMPDIR` with their own `CARGO_TARGET_DIR`, removed at the end; never `rustup default` or `rustup override` (use `cargo +1.99.0`); a new dependency needs the captain's word first.
