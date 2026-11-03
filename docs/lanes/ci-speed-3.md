# CI speed, loop three: the compile time by evidence (#672)

The speed line's loop three (measure, cut, measure, record), opening from
loop two's recorded figures (`docs/lanes/ci-speed-loop2-slowest.md`; the
Suite's compile 4m15s cold and 2m47s on a cache hit at loop one's close,
`docs/lanes/ci-speed-1.md`). Base: `origin/beta` at `83068752`.

| Row | What | State |
| --- | --- | --- |
| #672 | the compile time by evidence: the Test Suite's build steps, the lint job's Clippy and ratchet | landed as PR #691 (`55424846`, 13:10Z 2026-11-03); its after columns below, from the cache-hit witness |
| #673 | the reads share the lane's build | open; nothing here |
| #696 | the semver tool's cache seeded from a push to a line | landed as PR #700 (`e9dc9a4a`, 13:40Z); the section below, the seed's miss and save measured |
| #699 | the `checks` job's cache keyed by the cargo-mutants version it installs | committed on `lane/ci-mutants-cache` over `ec36c02e`, not yet landed; the section below, the before measured, the after from the landing's push |
| #693 | one merged integration binary measured against its parts (the ten `tests/script_*witness*.rs`, one equal Modules cell) | measured on `lane/ci-merged-binary` over `c46a3b29`, nothing restructured: 0.25 s of rustc per binary removed (0.15 s the link), no reach loss on a library change, a test-only change runs the group; the record `docs/lanes/ci-merged-binary.md` |

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

| Step | Before (41606020511) | After, the hit (41646365090) | After, beta's miss (41641964966) |
| --- | ---: | ---: | ---: |
| Test Suite job | 448 | 237 | 477 |
| Cache restore | 4 | 3 | none found |
| Unit tests: step | 64 | 37 | 181 |
| Unit tests: build | 29 | 16.8 | 153 (the dependencies rebuilt at level 1) |
| Unit: run | 34 | 18.9 | 25.5 |
| Integration: step | 265 | 137 | 197 |
| Integration: build, run | 82, 181 | 64, 72.3 | 87, 107.8 |
| Memory: run | 35 | 13.3 | 18.8 |
| Tracing: build | 18 | 2.1 | 3.0 |
| Doc tests: step | 29 | 21 | 29 |
| Integration binaries | 284 (283 and the lib's) | 283 (3,128 tests) | 283 (3,125 tests) |

The after columns, read from the API on 2026-11-03 (`gh run view <id>
--json jobs`, each step's `completedAt` less its `startedAt`; a build is the
step's `Finished` line and a run its nextest `Summary`, from
`gh api repos/Calhooon/bsv-rs/actions/jobs/<job>/logs`). The hit is beta's
second push run after the landing, as defined below: 41646365090 on
`e9dc9a4a`, its log `Restored from cache key
"v1-rust-test-suite-Linux-x64-26c38808-cbf959cb" full match: true.`; its
run 5m06s, the Test Suite 3m57s (the restore 3 s, the unit tests 37 s, the
integration step 2m17s, the memory step 27 s, the tracing step 5 s, the doc
tests 21 s). Beta's landing push run 41641964966 on `55424846` misses
(`No cache found.`, 254 `Compiling` lines): the run 8m00s, the Test Suite
7m57s (the unit tests 3m01s with the dependencies rebuilt, the integration
step 3m17s, the memory step 38 s, the doc tests 29 s).

The projection held: 448, 548 and 389 s before (the Test Suite on the three
beta runs above), about 328, 393 and 288 s projected, 237 s measured on the
hit. The hit's run is under every projection; the steps beat the
projection's fractions (the integration run 72 s against 181, the unit run
19 s against 34), more than the level alone accounts for on this host, so
part of it is the runner's: one hit, not a mean.

The PR's own runs. Its opening run 41624795016 (`dd1630d5`) is the PR-side
miss (`No cache found.`, 254 `Compiling` lines; the unit build 1m33s): the
run 5m55s, the Test Suite 5m13s. Its last run 41640765441 (`0aff5a26`) is
not a miss: its log reads `Restored from cache key
"v1-rust-test-suite-Linux-x64-26c38808-cbf959cb" full match: true.`, the
entry an earlier run of the same pull request saved under its own ref (the
key unchanged between the two heads), so it is a second hit on the new
key: the run 6m26s, the Test Suite 5m54s (the unit tests 1m03s, their build
36 s, the integration step 3m23s, the memory step 38 s, the doc tests
28 s). Its unit build's 36 s against the beta hit's 17 s is the lib built
on another runner at another hour, not a rebuild (four `Compiling` lines in
each). The lane's local figures stand as measured.

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
| A PR's CI wall clock | push runs 450, 552, 391 s (41606020511, 41602618009, 41599782319) | 306 s (5m06s) on the hit (41646365090, beta's push); 386 s (6m26s) on the PR's last run, a hit on its own ref's entry (41640765441); 480 s (8m00s) on beta's miss (41641964966); 355 s (5m55s) on the PR's opening miss (41624795016) |
| The queue wait | 1 s each | 2, 1 and 29 s (41646365090, 41641964966, 41640765441; to the earliest job that ran 4, 2 and 31 s) |
| The nightly's length | 2h28m (41579707627, complete, 04:42:51Z to 07:10:57Z) | unchanged by this loop (no `nightly.yml` line); the next figure the complete run at 07:00Z 2026-11-04 at the cap of six (`docs/lanes/ci-speed-7.md`) |
| A cold read's length | not measured by this lane | 10 to 16 minutes (the captain's count over this loop's reads) |
| The landing latency | not measured by this lane (loop four, #675) | lane DONE to the merge on beta, the captain's count: 15 min (#700), 28 min (#698), 100 min (#694), 156 min (#691; the last two with the flake's hour inside). The API's opening to merge: #700 13:28:39Z to 13:39:57Z (11m18s), #698 12:20:00Z to 12:47:39Z (27m39s), #694 11:21:05Z to 13:00:14Z (99m09s), #691 10:35:14Z to 13:10:18Z (155m04s) |

## #696: the semver tool's cache seeded from a push to a line

Base `origin/beta` at `55424846`. GitHub's cache rule: a run restores a
cache created on its own ref, its pull request's base branch or the default
branch (`main`); a pull request's cache is scoped to `refs/pull/<n>/merge`
and read by that pull request's re-runs alone. `semver` runs on pull
requests only, so nothing on `beta` or `main` ever saved its tool: `gh cache
list` on 2026-11-03 holds twenty `semver-checks-0.51.0-rust-1.95.0-Linux-X64`
entries (7.7 MB each), every one on a `refs/pull/<n>/merge`, none on a
branch. Every pull request's opening run built cargo-semver-checks.

### The measurement before

The `semver` job of six pull-request runs (`gh run view <id> --json jobs`;
the restore step reports success either way, the install's skip is the hit):

| Run | Branch | Restore | Install (s) | Check (s) | Job (s) |
| --- | --- | --- | ---: | ---: | ---: |
| 41621814166 | `lane/ci-cap-6` | miss (the PR's opening run) | 294 | 48 | 358 |
| 41624795016 | `lane/ci-speed-loop3-compile` | miss (the PR's opening run) | 285 | 47 | 351 |
| 41634821365 | `lane/fix-697` | miss (the PR's opening run) | 241 | 41 | 299 |
| 41637251653 | `lane/fix-697` | hit (the same PR's later run) | skipped | 47 | 65 |
| 41638823920 | `lane/ci-semver-exit` | hit (the same PR's later run) | skipped | 48 | 66 |
| 41640765441 | `lane/ci-speed-loop3-compile` | hit (the same PR's later run) | skipped | 49 | 66 |

PR #694's own read was 5m08s for the install. An opening run's job is 299 s to
358 s, a hit's 65 s to 66 s: the install is 241 s to 294 s of it.

### The cut

A job of its own, `semver-tool-seed` (`name: semver tool cache`), on a push
to a branch (`github.event_name == 'push' && startsWith(github.ref,
'refs/heads/')`: both lines, since `main`'s protection carries `semver` as
`beta`'s does; a tag's push and a dispatch seed nothing a pull request
reads). Its cache step is `semver`'s (the same `actions/cache` sha, v4.3.0,
the same `path: ${{ runner.temp }}/tools`, the same key) with
`lookup-only: true`: on a hit it downloads nothing and saves nothing (one
lookup, no checkout, no toolchain); on a miss it installs Rust 1.95.0 and
`cargo install cargo-semver-checks --version 0.51.0 --locked` as `semver`
does, and the action's post step saves the entry in the line's scope. A
pull request into `beta` then restores `beta`'s entry (or `main`'s, the
default branch's), one into `main` `main`'s.

The shape that costs less: the separate job. `semver` itself on a push with
its check skipped would need its full-history checkout (`fetch-depth: 0`)
and its plan on every push, report a `semver` check run on the push's
commit, and break the guard's rule that a push runs no context which reads a
pull request (`PULL_REQUEST_ONLY`); the seed job's hit is one cache lookup.
The seed reports `semver tool cache`, no required context: the protection's
required contexts stay five on `beta` and six on `main`, and the pull
request's context is still `semver`.

### The guards

- `tests/arch_ci_semver_tool_seed.rs` pins the seed's cache step to
  `semver`'s (`uses:`, `path:`, `key:` equal), the toolchain step's
  `uses:` and `toolchain:`, the install's `RUSTFLAGS:` and `run:` lines
  equal, the seed alone `lookup-only: true`, the key naming 0.51.0 on Rust
  1.95.0 and the install pinned to `--version 0.51.0 --locked`. RED on a
  scratch copy with the seed's key changed to `rust-1.96.0` (`the cache
  step's key: differs`); each drift (the key, the path, the version, the
  toolchain, the lookup) refused on a mutated text in the file's second
  test.
- `tests/arch_ci_pr_runs_the_required_set.rs` carries `PUSH_SEEDS`: a job a
  push to either line runs beside its required set, proven to run there (an
  entry whose job does not is refused as stale), off pull requests by the
  exact-set rule, off the full set by its `NOT_ON_THE_FULL_SET` entry
  (`a_push_seed_off_the_push_or_on_a_pull_request_is_refused`). Base's
  `ci.yml` under the tip's guard: 10 of 17 RED (`push seed
  semver-tool-seed is not proven to run on a push to beta`, the full-set
  entry naming no job).

### The other tools

- **cargo-deny** (`lint`): `taiki-e/install-action` downloads the release
  binary; no cache involved, 1 s on PR run 41637251653 and 0 s on beta's
  push 41641964966. Nothing to seed.
- **The ratchet's build** (`lint`): `Swatinem/rust-cache` with
  `shared-key: lint` and the ratchet's target in `cache-directories`, saved
  on a push to a branch; the entry `v0-rust-lint-Linux-x64-7f9a22ea-227349d2`
  sits on `refs/heads/beta` (and a ratchet entry on `main`), restored by a
  full match on PR run 41637251653 (`Restored from cache key ... full match:
  true`); the ratchet step 40 s there, 31 s on the push. Seeded.
- **cargo-mutants** (`checks`, the mutants-entries gate, #663): not seeded,
  a finding left to a follow-up. The `checks` entry
  `v0-rust-checks-Linux-x64-c2e3c2da-227349d2` on `refs/heads/beta` was
  saved at 03:39Z, before #663 landed (`d778651d`, 05:58Z), so it carries no
  cargo-mutants binary; rust-cache saves only on a miss, and every run since
  restores that entry by a full match and builds cargo-mutants 27.1.0 again
  (`Finished release profile ... in 1m 08s` on PR run 41637251653, the step
  78 s; 78 s on beta's push 41641964966, its post-cache step saving
  nothing). It recurs until the key next moves (the step's own comment says
  so). The cut for it is the same shape or the release binary through
  `taiki-e/install-action`, not this row's.

### After

| Figure | Before | After |
| --- | --- | --- |
| `semver`'s install on a pull request's opening run | 241 s, 285 s, 294 s (41634821365, 41624795016, 41621814166; #694's 5m08s) | (from the earliest code pull request into `beta` opened after 13:45:06Z, read in at its landing) |
| `semver`'s job on a pull request's opening run | 299 s, 351 s, 358 s | (the same run) |
| The seed job on a push, hit / miss | none | miss 301 s (5m01s) on beta's push 41646365090 (`e9dc9a4a`, the landing's): `Cache not found for input keys: semver-checks-0.51.0-rust-1.95.0-Linux-X64`, the toolchain 8 s, the install 289 s (4m49s, once), then `Cache saved with key: semver-checks-0.51.0-rust-1.95.0-Linux-X64`; hit (from beta's next push run) |

This pull request's own run is a pull request: its `semver` misses as today.
The landing's push to `beta` ran the seed, which missed and saved (above);
the witness is the earliest pull request into `beta` opened after that push
whose change is not docs only. A docs-only pull request's `semver` exits
after its plan (#689) and never reaches the cache step (`if:
steps.plan.outputs.docs_only != 'true'` on the restore and the install), so
the record's own pull request (`lane/docs-loop3-after`, docs only) measures #689's exit, not this row: its
figure goes to `docs/lanes/ci-speed-loop2-docs-only.md`. No pull request
was opened between the push and 13:48Z (`gh pr list`, `gh run list
--event pull_request`).

## #699: the `checks` job's cache keyed by the tool it installs

Base `origin/beta` at `ec36c02e`. The #696 section's last finding: the
mutants-entries gate of `checks` (#663, landed `d778651d` at 05:58Z) runs
`cargo install cargo-mutants --version "$CARGO_MUTANTS_VERSION" --locked`
after the job's `Swatinem/rust-cache` step (`shared-key: checks`), and the
action saves only on a miss (`src/save.ts`: `Cache up-to-date.` and return
after an exact hit), so the entry `v0-rust-checks-Linux-x64-c2e3c2da-227349d2`,
saved on `refs/heads/beta` at 03:39:25Z before the gate existed, is restored
by a full match on every run and never saved again: no run carries the tool.

### The measurement before

The `checks` job of three runs (`gh run view <id> --json jobs`, the job log
through `gh api repos/Calhooon/bsv-rs/actions/jobs/<job>/logs`); each
restored `v0-rust-checks-Linux-x64-c2e3c2da-227349d2` with `full match:
true`, and the install's own line is cargo's `Finished release profile`:

| Run | Event | Restore | Install (s) | mutants-entries step (s) | Job (s) | Post-cache |
| --- | --- | --- | ---: | ---: | ---: | --- |
| 41672716963 | pull request (`lane/kill-script-code`) | full match | 64 (1m 04s) | 74 | 218 | no save (a pull request) |
| 41648342758 | push to `beta` | full match | 68 (1m 08s) | 78 | 234 | `Cache up-to-date.` |
| 41646365090 | push to `beta` | full match | 71 (1m 11s) | 80 | 228 | `Cache up-to-date.` |

The tool is 64 s to 71 s of a 74 s to 80 s step and about 30 percent of the
job, on every run, a push to the line included.

### The cut

`CARGO_MUTANTS_VERSION: '27.1.0'` moves from the mutants-entries step's
`env:` to the `checks` job's `env:`; the install reads the same variable, so
one bump moves the install and the key. rust-cache v2.9.3 (the pinned
`d1527c8f`) hashes every set variable whose name starts with `CARGO`, `CC`,
`CFLAGS`, `CXX`, `CMAKE` or `RUST` into the key's environment part
(`src/config.ts:110-126`, `add-rust-environment-hash-key` on by default),
and the step's own environment is the job's. The `key:` input the brief
offered first does not work here: the action reads `key` only when no
`shared-key` is set (`src/config.ts:75-82`), and `checks` sets
`shared-key: checks`; putting the version in `shared-key` would need the
same job-level variable to interpolate. The nightly already sets the
variable at its workflow level (`nightly.yml:45`), and cargo-mutants runs
under it there.

The bin directory: `cache-bin` defaults to true, the paths include
`~/.cargo/bin`, `.crates.toml` and `.crates2.json` (`src/config.ts:264-272`),
and before saving the action removes only the binaries present when it
started (`cleanBin`, the rustup proxies; `src/cleanup.ts:83-98`), so the
cargo-mutants installed after it is saved. On a restore the install finds
`.crates2.json` naming 27.1.0 and builds nothing.

The cost of the move: the environment hash is in the restore key too, so
the landing's push misses outright (no partial restore of the old entry)
and builds the whole `checks` target once (vectors, fixtures, the
documentation and the wasm32 slice), then saves. A version bump does the
same once.

### The guard

`tests/arch_ci_tool_cache_key.rs`: in every job of `ci.yml` with a
rust-cache step, each `cargo install` after it names a `--version` the key
carries: a variable set at the job or workflow level under a hashed prefix
(or listed in `env-vars:`) and not shadowed at the step, or the version (or
`${{ env.NAME }}` of a set variable) in `prefix-key:`/`shared-key:`; a
`key:` beside `shared-key:` refused as ignored; `cache-bin: "false"` and
`add-rust-environment-hash-key: "false"` refused under an install; the
`checks` install must be found (no vacuous pass). RED on a scratch copy of
`ec36c02e` with the file added, own target dir (`` `checks`'s install of
cargo-mutants sets CARGO_MUTANTS_VERSION at step level, outside the cache
key ``); each refusal shown on a mutated text in the file's second test.

The other tools installed after a cache step: in `test`, cargo-nextest
through `taiki-e/install-action` (a release binary; the cache step has
`cache-bin: "false"`, nothing to key); in `lint`, cargo-deny the same
(before the cache step), and the ratchet's build is seeded by `lint`'s push
saves (#700's evidence: `v0-rust-lint-Linux-x64-7f9a22ea-227349d2` on
`refs/heads/beta`, a full match on PR run 41637251653). In `checks`,
gitleaks is a Go build of the pinned tarball (the step 28 s on the pull
request runs, 43 s on the pushes above); rust-cache never held Go's build
cache, so a key does not help it: a row of its own if wanted (a prebuilt
release checked by sha256), not this one.

### The budget

`gh api repos/Calhooon/bsv-rs/actions/cache/usage` at 16:31:43Z:
10,690,699,350 bytes over 38 entries (10,934,221,375 at 13:27Z): under the
10 GiB budget (10,737,418,240 bytes) by 46,718,890 bytes and over 10^10 bytes
(the evidence read's correction of "above the budget"); when the budget
fills, GitHub evicts the least recently used. The new key adds one
`checks` entry per line that pushes (`beta` at the landing, `main` at its
next push; about 584 MB plus the cargo-mutants binary each). The old `beta`
entry is read by no `beta` run after the landing (its restore-key prefix
carries the old environment hash); 35 of the 39 entries were last read before
it, so it is not the eviction's next candidate, and an open pull request on
the old workflow keeps its hash alive until that branch rebases (the evidence
read's correction of "the least recently used"); it leaves at the latest
seven days after its last read: a transient 584 MB on `beta`. The pull-request-scoped semver entries stopped growing with #700:
18 at 7.7 MB (139 MB), the newest `refs/pull/700/merge` at 13:34:31Z, none
since (PR run 41672716963 at 16:17Z saved none); they age out over seven
days. `cache-on-failure` is unset in `checks` (false), so a failed gate on a
push saves nothing; setting it would add saves, never trim one. One
workspace, and its `target/` holds what the next run reads (the vectors and
fixtures test builds, the documentation, the wasm32 slice); a smaller
`workspaces` or `cache-targets: false` trims the entry by rebuilding those
on every run. Nothing lands for the budget.

### After

| Figure | Before | After |
| --- | --- | --- |
| The install in mutants-entries | 64 s, 68 s, 71 s (41672716963, 41648342758, 41646365090) | (from beta's push run after the landing: the miss, the install's seconds and `Cache saved with key: v0-rust-checks-Linux-x64-<new hash>-...`; then the first run after it: `full match: true` and the install's seconds) |
| The mutants-entries step | 74 s, 78 s, 80 s | (the same runs) |
| The `checks` job | 218 s, 234 s, 228 s | (the same runs; the landing's push a cold build of the whole target) |
| The account's cache usage | 10,690,699,350 bytes, 38 entries (16:31:43Z) | (read after the landing's save) |

