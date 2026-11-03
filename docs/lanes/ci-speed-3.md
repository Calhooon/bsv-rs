# CI speed, loop three: the compile time by evidence (#672)

The speed line's loop three (measure, cut, measure, record), opening from
loop two's recorded figures (`docs/lanes/ci-speed-loop2-slowest.md`; the
Suite's compile 4m15s cold and 2m47s on a cache hit at loop one's close,
`docs/lanes/ci-speed-1.md`). Base: `origin/beta` at `83068752`.

| Row | What | State |
| --- | --- | --- |
| #672 | the compile time by evidence: the Test Suite's build steps, the lint job's Clippy and ratchet | this record |
| #673 | the reads share the lane's build | open; nothing here |

## The measurement before: CI

Three push runs of `ci.yml` on `beta`, read from the API
(`gh run view <id> --json jobs`, the Test Suite's log through
`gh api repos/Calhooon/bsv-rs/actions/jobs/<job>/logs`). Every run restored
the cache by an exact hit (`v1-rust-test-suite-Linux-x64-1748970a-cbf959cb`),
so every dependency was `Fresh` and each step's build is the workspace crate
and its test targets alone. Seconds; a step's build is its `Compiling bsv-rs`
line to its `Finished` line, its run nextest's `Summary`.

| Step | 41606020511 | 41602618009 | 41599782319 | What dominates |
| --- | ---: | ---: | ---: | --- |
| Run wall clock (created to updated) | 450 | 552 | 391 | the Test Suite |
| Queue wait (created to the earliest job's start, the skipped jobs counted) | 1 | 1 | 1 | to the earliest job that ran (`checks`, the Test Suite): 2, 3 and 2 |
| Test Suite job | 448 | 548 | 389 | |
| Cache restore | 4 | 3 | 3 | exact hit |
| Unit tests: step | 64 | 69 | 55 | |
| Unit tests: build (`--lib --all-features`) | 29 | | | the lib's test target |
| Unit tests: run (1,725 tests) | 34 | | | |
| Every integration test: step | 265 | 340 | 231 | |
| Integration: build (`full,http,websocket --tests`) | 82 | 104 | 76 | the 283 binaries, 66 s, 83 s and 61 s after the lib's 16, 21 and 15 |
| Integration: run | 181 | 235 | 154 | 4,844 tests; the lib's 1,725 among them, 16, 16 and 15 percent of the test-seconds (29 s, 37 s and 24 s of the run) |
| Memory profiling: step | 52 | 67 | 45 | build 16 (the lib on `--all-features`, not a test target), run 35 |
| Tracing sink: step | 21 | 27 | 20 | build 18 (the lib on `full,http,tracing`, its own), run 3 |
| Doc tests: step | 29 | 34 | 25 | rustdoc's compiles; the lib reused from the memory step |
| lint job | 136 | 160 | 134 | beside the Suite, never its path |
| lint: Clippy | 71 | 87 | 68 | twelve slices after `--all-targets --all-features` |
| lint: ratchet | 31 | 38 | 34 | its own 1.95 pedantic Clippy of the lib |
| checks job | 229 | 230 | 217 | beside the Suite |

Two duplicates the logs show: `--tests` in the integration step names the
lib's unit target as well, so the 1,725 unit tests run twice on a whole
suite (the unit step's on `--all-features`, again here on
`full,http,websocket`; loop two's record named it a cut for this loop); and
the tracing step builds the library on a feature set no other step uses,
where the memory and doc steps share `--all-features`'s.

## The measurement before: one host

A `git archive` of `83068752` under `$TMPDIR`, its own target dir under
`~/bsv/targets`, the job's environment (`RUSTFLAGS=-Dwarnings`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`), `CARGO_BUILD_JOBS=2` (the keeper's memory
line; the runner has 4), the Studio (macOS, Apple's linker, so a binary's
link costs other seconds than rust-lld's on the runner: the local figures
compare one thing with another on one host, never with CI's). nextest
0.9.150 runs with `--test-threads 4`, the runner's count. The brief's
`src/script/spend/script.rs` does not exist; the one-line change is a
comment appended to `src/script/spend/mod.rs`, the interpreter's root.

| Measurement | Seconds | What dominates |
| --- | ---: | --- |
| `cargo build --timings --features "full,http,websocket" --tests`, cold | 137.4 | dependencies 41, the lib 16, then the 283 binaries 81 |
| the same, warm, after the one-line change | 97.1, 97.2 | the 283 binaries (156 s of unit time); the lib's test target 20 beside them |
| `cargo clippy --all-targets --all-features -- -D warnings`, cold | 72.2 | |
| the same, warm, after the change | 37.4 | |
| `cargo clippy --all-targets --features "full,http,websocket"`, after the `--all-features` run and a change | 37.3, 36.9 | the dependencies' check metadata shared: no rebuild |
| `tools/ratchet/run --check --against 83068752`, cold, warm | 57.9, 18.7 | its own clippy of the lib on 1.95 in its own target |
| `cargo-machete --with-metadata` (0.9.2) | | no unused dependency |

The timings' critical path, cold: the dependencies to 40.5 s (the longest
units `syn` 3.0.9 2.6 s, `object` 2.5, `tokio` 2.4, `criterion` 2.1,
`zerocopy` 2.0, `syn` 2.0 1.8, `regex-automata` 1.6, `h2` 1.6, `reqwest`
1.5, `futures-util` 1.4: no dependency above 3 s, 81 s of unit time in all),
the lib's 16.1 s (11.6 frontend, 4.5 codegen), then the integration
binaries from 56.6 s to 137.4 s, bound by throughput, not by a chain. Per
binary a least-squares fit over the 283 gives 0.49 s fixed and 0.00017 s per
line (110,711 lines): the fixed part is 139 s of the binaries' 156 s. On
CI the same window is 61 s to 83 s on 4 cores.

## The changes, each measured on the same host and the same change

1. **The integration step names `--test '*'`, not `--tests`.** cargo's glob
   over every `tests/*.rs` builds and runs the integration binaries alone; the
   unit step's `--lib --all-features` keeps the lib's tests (every whole
   plan sets `lib`, so a whole suite always runs it). Build after the change:
   97.1 and 97.2 s before, 93.4 and 92.1 after. Run: 98.4 and 97.6 s (4,844
   tests, 284 binaries) before, 80.3 (3,119, 283) after. The lib's tests run
   on `--all-features` only; the one source line `--all-features` compiles
   out (`src/wallet/wire/processor.rs:244`, `let _ = call;` without
   `tracing`) stays compiled by the integration build and the slices.
2. **The tracing step on `--all-features`.** It carries `tracing`, and the
   memory step before it has built the library on it: the step's build
   after the memory step's, on the same change, 18.8 and 16.1 s on
   `full,http,tracing`, 3.3 and 3.2 on `--all-features`. The three binaries'
   18 tests pass on it (`wasm` gates only `wasm32` code, `dhat-profiling`
   only `tests/memory_profiling.rs`).
3. **The dependencies at opt-level 1 in the test profile, the crate at 0.**
   cargo reads a package's profile from a configuration file and from no
   environment variable (`CARGO_PROFILE_TEST_PACKAGE_SUBTLE_OPT_LEVEL=1`
   leaves `subtle` at 0, measured), so a step before the cache writes
   `[profile.test.package."*"]` into the cargo home's `config.toml` from the
   job's `CARGO_DEPENDENCIES_TEST_OPT_LEVEL`, whose `CARGO` prefix rust-cache
   hashes into its key: another level misses, never an exact hit on
   dependencies built at the old one. On the test profile, after the same
   change:

   | | opt-level 0 | dependencies at 1 | everything at 1 |
   | --- | ---: | ---: | ---: |
   | cold build (`--test '*'`, cache miss) | 137 (dev, `--tests`) | 207.9 | 384.1 |
   | warm build after the change | 93.7 | 90.1 | 308.3 |
   | integration run, 3,120 tests | 81.0 | 50.3 | 33.8 |
   | unit run, 1,725 tests (`--all-features`) | 20.2 | 14.4 | |
   | memory run, 13 tests | 61.7 | 47.0 | |
   | doc tests | 55.6 | 55.0 | |

   Every step's tests pass with it (the memory step's thirteen bounds
   included). The crate at 1 as well costs 214 s of build for 47 of run, a
   loss on every run: not taken.

   The dhat figures are not independent of the level (the cold read, on
   `ebc12e0d`, `--all-features --test memory_profiling` at both levels on
   one host): LLVM removes some allocations at opt-level 1, so the printed
   allocation counts fall (key derivation 1,228 to 1,216; Shamir 4,336 to
   4,204, 13,000 to 12,866 and 6,400 to 6,300) and the HTTP JSON peaks move
   by tens of bytes (the array form 1,342,489 to 1,342,553 B against its
   bound of 1,874,768). Those counts are printed, not asserted; every
   asserted figure (the stream's peaks and bytes per element, the
   arithmetic steps' ratios, the pushes, the #487 answer) is the same byte
   for byte at both levels.

Together on this host: about 4 s of build and 18 s of run (1), 14 s of
build (2), 51 s of run (3), against a cache miss's 71 s more once per key.
Read onto the CI steps above (the lib's share of the run, the tracing
build, the run fractions 0.62, 0.71, 0.76 on the integration run without the
lib's tests, the unit run and the memory run), roughly 30 s, 15 s and 75 s
of a whole-suite run's Test Suite: projections, not results. The after figures
are the PR's run's.

The projection summed per run, on a cache hit (the review's arithmetic, from
the steps' `Finished` and `Summary` lines; the tracing build after the cut
taken as 3 s, the host's 3.2): 41606020511, 29 + (18.0 - 3) + (152 x 0.38 +
34.1 x 0.29 + 34.6 x 0.24 = 76) = about 120 s, the Test Suite 448 to about
328 s (5m28s); 41602618009, 37 + (22.7 - 3) + (198 x 0.38 + 41.9 x 0.29 +
46.4 x 0.24 = 98) = about 155 s, 548 to about 393 s (6m33s); 41599782319,
24 + (16.8 - 3) + (130 x 0.38 + 25.5 x 0.29 + 29.1 x 0.24 = 63) = about
101 s, 389 to about 288 s (4m48s). The warm build's 4 s of the level and
the lib's test target leaving the integration build are not counted. A miss
on CI adds the dependencies' build at level 1, unmeasured on the runner (71 s
more on this host at 2 jobs).

| Step | Before (41606020511) | After |
| --- | ---: | --- |
| Test Suite job | 448 | (from the PR's CI run) |
| Integration: build, run | 82, 181 | (from the PR's CI run) |
| Unit: run | 34 | (from the PR's CI run) |
| Memory: run | 35 | (from the PR's CI run) |
| Tracing: build | 18 | (from the PR's CI run) |
| Integration binaries | 284 (283 and the lib's) | 283 |

The PR's own run misses the cache (the key moves with the new variable) and
builds the dependencies at the new level: its Test Suite carries the miss.
The run after the landing on `beta` misses too (the workflow read): a pull
request's cache is scoped to its ref, `refs/pull/<n>/merge`, which a `beta`
push cannot restore, so that run builds the dependencies again and saves the
`beta` entry; the hit's witness is the second `beta` run after the landing,
not the landing's own push run. The miss is whole:
rust-cache 2.9.3's restore key carries the environment hash too
(`v1-rust-test-suite-Linux-x64-1748970a`, run 41606020511's log, beside the
`CARGO_*` names it considered), so no entry built at level 0 is restored by
prefix; the old entries leave the budget by age. The cache risk (0.2 in the
lane's REPORT) is therefore not a prefix restore of the level 0 entries,
which never happens, but two key families sharing the repository's 10 GB
budget until the level 0 family ages out (seven days unread): the old
entries and the new ones beside each other, evicting the oldest of either
when the budget fills.

## What the evidence does not support

- **One feature set for Clippy and the tests.** The lint job runs beside the
  Suite on its own runner and its own cache (`shared-key: lint`), never on a
  run's path; Clippy's build is check metadata, which a test build's
  artifacts cannot serve; and on this host Clippy on `full,http,websocket`
  after `--all-features` rebuilt nothing more (37.3 s against 37.4).
- **The ratchet reading the test build.** It runs `cargo +1.95.0 clippy --lib
  --all-features` with `clippy::pedantic` forced and `RUSTFLAGS` empty in a
  target of its own: another toolchain and other flags, nothing shareable,
  and off the path.
- **`CARGO_INCREMENTAL=1`.** rust-cache saves no workspace crate and no
  incremental state, so every run builds the crate without one: the warm
  build with incremental on and no state took 123.2 s against 92.5 with it
  off. `0` stays.
- **Caching the integration binaries.** Any change under `src/` rebuilds
  all 283 (each links the lib), and rust-cache drops the workspace's
  artifacts by design; a test-only pull request runs its reached binaries
  alone since cut 4.
- **Unused dependencies.** `cargo-machete --with-metadata` finds none; the
  slowest dependency is under 3 s, so no single one is worth a feature
  split. One unification to know: `--all-features` turns on `wasm`, so
  `getrandom/js` and the crates above it are built twice between the
  `--all-features` steps and the integration step; both sit in the cache,
  so the cost is the cache's size, not a run's time.
- **Merging integration binaries.** The fixed 0.49 s per binary is the
  integration build's largest term, but merging the files that test one
  module saves that cost only for each binary removed: dozens of merges for
  seconds on 4 cores, against cut 4's reach rule, which selects by binary,
  and the #146 guard and `tests/CLAUDE.md`'s rows that move with each. The
  whole suite as one binary would save most of the window (61 s to 83 s on
  CI) and make every reached run build it all: a decision for the keeper,
  with these figures. Per binary on CI, the window over the 283 is 0.22 s
  to 0.29 s of wall clock, the fixed part (139 of 156 unit-seconds on this
  host, 89 percent) about 0.19 s to 0.26 s of it: each binary a merge
  removes saves about that, ten binaries removed 2 s to 3 s. nextest runs each test
  in a process of its own whatever the binary, so a merge loses the files'
  separate compilation (a file's `#![cfg]` gate, a compile error confined to
  its own binary) and the reach rule's selection by file, not the tests'
  process isolation; the single binary's own compile time is not measured.
- **`codegen-units` and `lto`.** The dev profile already leaves `lto` off;
  the crate's own build is 16 s of a whole run's compile, its codegen 4.5 s
  of them: nothing to buy there.

## The guard

`tests/arch_ci_runs_every_test.rs`: `--test '*'` reads as a whole-suite
step (`the_lib_runs_once_and_the_named_steps_share_one_build`);
`shared_build_refusals` refuses a second step that runs the lib's unit
tests, a job with none (`--test '*'` does not run them; the #691 fold, RED
on a scratch copy with the unit step removed) and a named or doc step on
another feature set than the others;
`dependency_profile_refusals` refuses a Test Suite without
`CARGO_DEPENDENCIES_TEST_OPT_LEVEL: "1"`, without the step that writes it,
or with the cache or a build before that step
(`the_dependencies_level_is_written_before_the_cache_and_every_build`). Each
RED on a scratch copy of `ci.yml`: `--tests` restored, the tracing step back
on `full,http,tracing`, the env line removed, the step moved after the
cache. The step writing the level runs under
`steps.plan.outputs.build == 'true'`, as every step after the plan does
(#688's docs-only exit, `tests/arch_ci_docs_only_exit.rs`; the cold read's
finding on the rebase onto `7896671d`).

## The loop's five figures

| Figure | Before | After |
| --- | --- | --- |
| A PR's CI wall clock | push runs 450, 552, 391 s (41606020511, 41602618009, 41599782319) | (from the PR's CI run) |
| The queue wait | 1 s each | (from the PR's CI run) |
| The nightly's length | 2h28m (41579707627, complete, 04:42:51Z to 07:10:57Z) | unchanged by this loop (no `nightly.yml` line) |
| A cold read's length | not measured by this lane | |
| The landing latency | not measured by this lane (loop four, #675) | |
