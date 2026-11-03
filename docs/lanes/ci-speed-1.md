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

## After: three runs, `Test Suite (ubuntu-latest, stable)`

Read from the API (`steps[].started_at/completed_at`) and the job logs
(rust-cache's `Cache hit for`, `Restored from cache key`, `No cache found`,
`Sent N of N`, `Cache up-to-date` lines; inside each step cargo's `Finished`
line and nextest's `Summary` line). Every run's cache key is
`v1-rust-test-suite-Linux-x64-1748970a-cbf959cb` (rustc 1.99.1, `58cf8f9c`).

- Run 41558273855, this PR's own (`refs/pull/665/merge`, head `374cb088`):
  `No cache found.` at 01:17:18Z (a miss: no entry under the new key yet),
  saved at the end, `Sent 219006304 of 219006304`, 209 MB. The Suite
  01:17:10Z to 01:33:16Z, 16:06.
- Run 41560881228, #652's (`refs/pull/652/merge`, head `73a749ac`):
  `No cache found.` at 01:46:07Z, a miss, not a warm hit. A pull request
  sees its own ref's entries and its base's; the entry above is scoped to
  `refs/pull/665/merge`, and beta's push run at `9c399dff` (41560683177, also
  `No cache found.` at 01:38:23Z) saved beta's entry at 01:54:19Z, eight
  minutes after this restore. It saved its own, `Sent 218980655 of
  218980655`. The Suite 01:46:02Z to 01:58:47Z, 12:45: faster than the cold
  run on every step, compiles and tests alike, with the same cache state; the
  runner's speed, not the cache.
- Run 41563214016, beta's push at `3be816e6`: `Cache hit for:
  v1-rust-test-suite-Linux-x64-1748970a-cbf959cb`, `Received 219028233 of
  219028233`, `Restored from cache key ... full match: true.` (the entry
  beta's push at `9c399dff` saved); the post step `Cache up-to-date.`, no
  save on an exact hit. The Suite 01:59:04Z to 02:14:30Z, 15:26. This is the
  measured warm figure.

The cache's hit rate so far: one hit in four restores (two pull requests
before any line entry existed, beta's push that saved it, beta's next push
that hit it). The archive is 209 MB against the 7,350 MB `actions/cache`
archive before (the dependencies' build alone, no stale test binaries, no
debuginfo); its restore took 5 s against 2:45.

| Step | Cold miss, 41558273855 | Miss, 41560881228 | Hit, 41563214016 |
| --- | ---: | ---: | ---: |
| Lockfile, cache restore, nextest install | 0:01, 0:00, 0:01 | 0:01, 0:01, 0:00 | 0:01, 0:05, 0:01 |
| Unit tests: wall (compile / test) | 2:19 (1:07 / 1:10) | 1:55 (0:58 / 0:55) | 1:29 (0:24 / 1:04) |
| Every integration test | 6:24 (1:38 / 4:44) | 5:08 (1:22 / 3:44) | 6:30 (1:38 / 4:50) |
| Memory profiling | 6:03 (0:19 / 5:43) | 4:39 (0:16 / 4:23) | 6:07 (0:21 / 5:46) |
| Tracing sink | 0:29 (0:25 / 0:03) | 0:23 (0:20 / 0:03) | 0:28 (0:24 / 0:04) |
| Doc tests | 0:34 | 0:28 | 0:36 |
| Post cache | 0:06 (save) | 0:06 (save) | 0:00 (up to date) |
| **Suite** | **16:06** | **12:45** | **15:26** |

The split after, on the hit: 2:47 of compile (the workspace crate and its
test binaries; before 4:15), 12:20 of tests and doc tests (before 18:49). The
hit saves the dependencies' build on the unit step (0:24 against 1:07 cold);
the integration step's compile is the workspace's 275 binaries and takes
1:22 to 1:38 with or without the cache (2:48 before, debuginfo on). nextest took the
integration tests from 9:26 to 4:50 and the memory step from 7:02 to 5:46,
which is now its one slow test alone. The job is test-bound, and one
runner's speed moves it by about three minutes (12:45 against 15:26).

## The four figures of the standing rule

| Figure | Before | After |
| --- | --- | --- |
| A PR's CI wall clock | 29:11 (run 41537280176, created 22:26:27Z, last job done 22:55:38Z) | 20:05 cold (run 41558273855, 01:13:12Z to 01:33:17Z, a cache miss); 21:49 on #652's run 41560881228 (01:36:59Z to 01:58:48Z, a miss too, its Test Suite queued 9:03); 15:29 on beta's push run 41563214016 (01:59:01Z to 02:14:30Z, the exact hit; a push runs no `semver`) |
| Queue wait | 3:10 (created 22:26:27Z; the earliest job that ran, the Test Suite, started 22:29:37Z; four skipped jobs are stamped at creation) | 1:38 to the earliest job (Clippy, 01:14:50Z) and 3:58 to the Test Suite (01:17:10Z) on run 41558273855; 1:48 and 9:03 on run 41560881228; 0:03 for both on run 41563214016. The queue is the runners', not the workflow's: it moves with the hour's load |
| The nightly | 10:43:05 (run 41347058507 on beta, 2026-11-01 20:28:54Z to 2026-11-02 07:11:59Z, complete, conclusion failure; no later run is complete) | Unchanged: this cut does not touch `nightly.yml`; the nightly's figure moves when #666 lands, measured on the next complete run |
| A cold read | 16:49 (the #660 cold read on the Studio, by its run record; the span of `review-fix-654`'s file stamps, about 14 minutes, is a lower bound only, that folder holding no REPORT) | Unchanged: a cold read runs on a host of the fleet, not on a runner; no cold read was measured after this landing |

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
hash is over the parsed dependency tables of `Cargo.toml` and a `Cargo.lock`
when one exists. This library tracks no `Cargo.lock`, so the job generates one
(`test -f Cargo.lock || cargo generate-lockfile`, the step before the cache,
the form the `fixtures` job and the `secrets` gate already use): the key is
rustc and the env, `Cargo.toml` and the lockfile generated in the job, never a
tracked lockfile. Without that step (the cache read's FIX) the key would hold
`Cargo.toml` alone, and a dependency's compatible release published after the
entry was saved would be rebuilt on every exact hit, which saves nothing,
until `Cargo.toml` changed or the entry aged out. With it a compatible release
moves the key: one miss, a restore by the restore key, a rebuild of the
changed dependencies and a save under the new key, which later runs hit.
The restore key is the same less the lock hash, so a resolve that changes
restores the same toolchain's previous cache and builds only the changed
dependencies.
What is cached: `~/.cargo` registry and git, and `target` cleaned of the
workspace crate, incremental state and anything older than a week (the
dependencies' build alone; `cache-bin: false`, so nextest's binary is
installed every run, not cached). `cache-on-failure: true`. `save-if`: a pull
request, or a push to `beta` or `main`; a dispatch and a tag's call restore
and never save (the six cells would otherwise share the repository's 10 GB
with the required one, and a tag's ref scope serves nobody).

A pull request's view: GitHub serves a PR its own ref's caches and then its
base branch's. A PR whose resolved lockfile equals the one beta's last push
generated hits beta's cache on the exact key and saves nothing (the action
skips a save on an exact hit); a PR whose resolve differs (a `Cargo.toml`
change, or a compatible release since beta's save) restores beta's by the
restore key, builds the changed dependencies and saves under its own ref,
which its later pushes hit.

The save policy differs from the sibling's on purpose. #664's bundled jobs
(the cold read's observation) save their cache only on a push to a line; this
job saves on a pull request too. Each is right for its job: a PR's test build
is the job's minutes and is worth keeping for that PR's next push, which
restores its own ref's entry ahead of beta's; a lint build's dependencies
change little between a PR and its line, so beta's entry serves it and a
PR's entry would only spend the repository's 10 GB.

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

The figure, measured: 15:26 on the exact hit (run 41563214016), 16:06 cold
(run 41558273855), 12:45 on a fast runner's miss (run 41560881228); every
one above the 8-minute line, so round 2 shards by step as above.

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

Not verified here: the runner's link time. The cache's size and hit rate and
the after figures are the three runs' (above).
