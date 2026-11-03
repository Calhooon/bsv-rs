# CI speed, round 1, cut 1: the Test Suite job

The fleet's speed line (the owner's word: free cuts, no own hardware, no paid
runners). This cut touches the `test` job of `.github/workflows/ci.yml` alone;
the sibling lane `ci-speed-2` takes every other job and the triggers. Base:
`origin/beta` at `84a01d2a`.

## Before: run 41537280176, `Test Suite (ubuntu-latest, stable)`

The last green run on beta's queue (a pull request from `lane/fix-654` at
`5062db4f`), 22:29:37Z to 22:55:38Z, 26 minutes 1 second. Read from the job's
log (`steps[].started_at/completed_at` from the API; inside each step the
`Finished` line against the `Running` and `test result` lines).

| Step | Wall | Compile | Test |
| --- | ---: | ---: | ---: |
| Set up, checkout, toolchain | 0:04 | | |
| `actions/cache` restore | 2:45 | | |
| Unit tests (`--lib --all-features`) | 1:45 | 0:36 | 1:08 (1,714 passed, 4 ignored) |
| Every integration test (`--tests`, `full,http,websocket`) | 12:15 | 2:48 | 9:26 (275 binaries, one after another) |
| Memory profiling (`--all-features`, one thread) | 7:24 | 0:22 | 7:02 (13 tests; one alone 5:36) |
| Tracing sink (three named binaries) | 0:33 | 0:29 | 0:04 |
| Doc tests | 1:09 | (rustdoc compiles each, inside) | 1:09 |
| Post cache, cleanup | 0:02 | | |
| **Total** | **26:01** | **4:15** | **18:49** |

The cache: a hit on its primary key
`Linux-cargo-stable-54620ff1…` (the lockfile alone), 7,350 MB
(7,707,096,633 bytes): 54 seconds of download and 1 minute 51 seconds of
`tar`. An exact hit is never saved, so the archive was whatever `target` held
when the lockfile last changed, every stale test binary and its debuginfo
included. The four compiles are the workspace crate and its 275 test binaries
(the dependencies were warm).

What the split says: the test minutes, not the compile, are the job. The
integration step ran 275 binaries one after another (each binary's tests in
threads, never two binaries at once); its slowest binaries were the lib's own
unit tests again (72.5 s: `--tests` includes the lib target, so they run
twice, under two feature sets; unchanged here, a note for the next round),
`beef_deep_chain` (58.9 s), `beef_two_readers_agree` (52.0 s),
`merkle_path_two_readers_agree` (51.0 s), `merkle_path_cost` (34.9 s). The
memory step ran its 13 tests on one thread; one of them,
`test_http_json_success_tx_in_the_array_form_costs_the_typed_reading`, took
5 minutes 36 seconds alone.

## The four figures of the standing rule

| Figure | Before | After |
| --- | --- | --- |
| A PR's CI wall clock | 29:11 (run 41537280176, created 22:26:27Z, last job done 22:55:38Z) | (from the PR's CI run) |
| Queue wait | 3:10 (created 22:26:27Z; the earliest job that ran, the Test Suite, started 22:29:37Z; four skipped jobs are stamped at creation) | (from the PR's CI run) |
| The nightly | 10:43:05 (run 41347058507 on beta, 2026-11-01 20:28:54Z to 2026-11-02 07:11:59Z, complete, conclusion failure; no later run is complete) | (from the PR's CI run) |
| A cold read | 16:49 (the #660 cold read on the Studio, by its run record; the span of `review-fix-654`'s file stamps, about 14 minutes, is a lower bound only, that folder holding no REPORT) | (from the PR's CI run) |

## What changed in the job

**The cache.** `Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0`
(v2.9.3, the release's commit read from the tag on 2026-11-02; the sibling
lane pins the same) in place of the `actions/cache` block. Its key, read from
the action's `src/config.ts` at that tag:
`v1-rust-test-suite-<os.type()>-<os.arch()>-<env hash>-<lock hash>`, where
`prefix-key: v1-rust` and `shared-key: test-suite` (one cache for the job's
three feature sets and every cell's steps; the OS and the architecture keep
the cells apart), the env hash is SHA-1 over `rustc -vV` of every installed
toolchain (release, host, commit hash: a toolchain change misses) and every
environment variable whose name starts with `CARGO`, `CC`, `CFLAGS`, `CXX`,
`CMAKE` or `RUST` (so `RUSTFLAGS=-Dwarnings`, `CARGO_INCREMENTAL` and the two
profile variables below are in the key: a change to any misses), and the lock
hash is over `Cargo.lock` and the parsed dependency tables of `Cargo.toml`.
The restore key is the same less the lock hash, so a lockfile change restores
the same toolchain's previous cache and builds only the changed dependencies.
What is cached: `~/.cargo` registry and git, and `target` cleaned of the
workspace crate, incremental state and anything older than a week (the
dependencies' build alone; `cache-bin: false`, so nextest's binary is
installed every run, not cached). `cache-on-failure: true`. `save-if`: a pull
request, or a push to `beta` or `main`; a dispatch and a tag's call restore
and never save (the six cells would otherwise share the repository's 10 GB
with the required one, and a tag's ref scope serves nobody).

A pull request's view: GitHub serves a PR its own ref's caches and then its
base branch's. A PR whose lockfile equals beta's hits beta's cache on the
exact key and saves nothing (the action skips a save on an exact hit); a PR
that changes the lockfile restores beta's by the restore key, builds the new
dependencies and saves under its own ref, which its later pushes hit.

**The profile.** In the job's `env`: `CARGO_INCREMENTAL: "0"`,
`CARGO_PROFILE_DEV_DEBUG: "0"`, `CARGO_PROFILE_TEST_DEBUG: "0"`. Env, not a
`[profile.ci]` in `Cargo.toml`: it reaches CI alone, so a developer's and a
downstream's `cargo test` keep debuginfo, and no `--profile` flag moves the
artifacts to `target/ci`. `debug = 0`, not `line-tables-only`: a failing
assertion still prints its `file:line` (`std::panic::Location` is compiled in
as data, not debuginfo), and symbol names stay (nothing is stripped); what a
failure loses is the file and line of each backtrace frame under
`RUST_BACKTRACE`, which CI does not set. `tests/script_budget_before_allocation_348.rs`
reads dhat's backtraces by symbol name (`arithmetic_room::reserve`, kept out
of line, bsv-rs#401) and passes under this profile locally (below).
`dtolnay/rust-toolchain` already exported `CARGO_INCREMENTAL=0` (the run's
log), and rust-cache sets it too; the job states it.

**The linker.** No step. `rustc` 1.99.1, the run's stable (its log), links
`x86_64-unknown-linux-gnu` with its own `rust-lld`, the default on that
target since Rust 1.90; the Linux cells are on lld already. `mold` would mean
`-C link-arg=-fuse-ld=mold` in `RUSTFLAGS` against the self-contained lld
rustc selects, a key change, and a gain not measurable on this host (a
macOS link is not the runner's); left for a round that can measure it on a
dispatch. The macOS and Windows cells keep their default linkers.

**nextest.** `cargo-nextest` 0.9.150 by
`taiki-e/install-action@682ce6c3c696a4cd5168a05f98e51aa02b877941` (v2.89.1),
`tool: nextest@0.9.150`. The lib, integration, memory and tracing steps are
`cargo nextest run` with the same features and target selectors, each with
`--no-fail-fast` (nextest cancels at a failure by default; `cargo test` ran
every test of a binary) and `--cargo-verbose` (the old `--verbose`: cargo's
rustc lines). nextest runs every test in a process of its own and binaries
side by side. The memory step keeps its own step: each test now has dhat's
global allocator and its one profiler to itself in its own process, the
isolation `--test-threads=1` gave, without running the 13 one at a time.
The step also sets `RUST_TEST_THREADS: "1"` (the cold read's fold): nextest
starts each test as `<binary> --exact <name> --nocapture` with no thread
count, so libtest inside the process takes the core count and runs the one
test on its concurrent path, whose 60-second warning allocates in the
profile (#372; `test_beef_stream_memory_is_flat_per_element` printed it at
67 s on the Studio); libtest reads the variable and runs the test on its
synchronous path, while nextest's own count is untouched by it (nextest
0.9.150 measured: `NEXTEST_TEST_THREADS` stays the core count). Locally the
twelve tests other than the array-form one took 74 s under nextest's default
count and 105 s under `--test-threads=1`, with the variable set and no
warning; each test's resident peak is under 1 GB (the 64 MiB wire test
955 MB, the array-form test 572 MB when stopped at 560 s), so four at once
sit far below the runner's 16 GB.
Doc tests stay `cargo test --doc --all-features` (nextest runs none). The
#146 guard is unchanged in what it demands (`--tests`, no enumeration); it
now reads a `cargo nextest run` line as a step, as it read `cargo test`
(`tests/arch_ci_runs_every_test.rs`, a seventh test,
`a_nextest_run_is_a_step_as_cargo_test_is`). The base guard against the new
ci.yml refuses all 272 files (the RED); the new guard passes.

## Sharding: the decision rule and the figure

The rule: shard the job only when the PR's measured warm build still exceeds
8 minutes; this workflow runs one job, as before. The figure says it will:
the memory step's one test (5:36 on the runner) and the doc tests (1:09) are
a floor of about 7 minutes before any compile or integration minute, so the
job cannot reach 8 minutes as one job. That is the next round's cut, on the
PR's measured figure: the memory step and the doc tests in a job of their
own beside the rest (a shard by step, not by `--partition`), and the lib's
unit tests run once instead of twice. Nothing of that is done here.

## Local verification (macOS, aarch64; not the runner)

Scratch copy of the tree under `$TMPDIR`, its own target dirs, nextest's
binary in the copy's own `cargo-home/bin`, `CARGO_BUILD_JOBS=4`; logs under
`/Volumes/Lanes/out/bsv-rs/ci-speed-1/`.

- Count: `tests/script_budget_before_allocation_348.rs` under `full,http`
  and the CI profile: `cargo test` 4 passed, `cargo nextest run` "4 tests
  run: 4 passed, 0 skipped".
- The profile's effect on one build (`--no-run` of that file): target dir
  905,884 KB with debuginfo, 529,328 KB without (42 percent less; on Linux the
  debuginfo sits in the binaries, on macOS partly in object files, so the
  runner's ratio differs).
- `memory_profiling` under nextest and `--all-features`: 12 of 13 passed,
  each in its own process (wire 64 MiB 9.2 s, the reversed chain 18.7 s, the
  flat stream 67.8 s); the array-form test passed 540 s on a host at a load of
  13 without finishing and was stopped under the ten-minute rule. Its pass is
  the PR's run's to show.
- `actionlint` 1.7.12 on `ci.yml`: clean. `cargo fmt --check`: clean. The 12
  architecture tests and `fixtures_replay` under `full,http`: green.

Not verified here: the runner's link time, the cache's size and hit rate, the
after figures.
