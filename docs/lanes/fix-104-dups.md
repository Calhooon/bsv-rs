# Lane fix-104-dups: the supply-chain gate refuses a new duplicate dependency version (#104)

Started from `origin/beta` at `80532565d6b855900f0b7c66e56b4877fa4b2dd4` (0.9.0-beta.7) on
2026-11-14. Nothing pushed, nothing written to GitHub; reads by `gh` alone. No file under `src/`
is touched and no dependency is added, removed or bumped. Beta moved during the lane (two commits of #958, no manifest or `ci.yml` line among them); the commit was rebased onto `b701c06f2fc4bd1ba8071e8e7dd30cf3b13eaaf2` and the gate run again there. The logs named are under
`/Volumes/Lanes/out/bsv-rs/fix-104-dups/`.

## The issue's comments

Two, both records and neither a wait on this lane: the census of 2026-11-09 (`docs/lanes/fix-104.md`,
landed as PR #824, `12a8b4e4`), and its landing note, which leaves the issue open "for the slices
and for the getrandom question, which is the owner's". This lane builds neither slice and does not
answer the question: it makes the count a gate.

## What was wrong

`cargo deny` warns on a crate held in two versions and passes (`deny.toml`,
`multiple-versions = "warn"`, no `skip`), the crate commits no lockfile, and the eleven duplicates
were a table no machine read. A manifest change, or a release under the crate, could add a twelfth
with `lint` green.

## What the gate is

| Piece | What it does |
|---|---|
| `docs/duplicate-versions.txt` | One row a crate: `graphs \| crate \| lines \| reason`. The graphs that hold the pair, the semver-compatible lines held, the older side's parents and what would end it |
| `.github/scripts/duplicate_versions.py` | Reads four graphs with `cargo tree --locked -e normal,build,dev --prefix none --format {p}` (nothing built) and refuses `NEW` (a duplicate with no row), `MOVED` (other lines than the row's, a third line included) and `STALE` (a row naming a graph that holds no such pair), and a malformed list |
| `ci.yml`, the `deny` step of `lint` | Runs the script's unit tests (21; 28 since the fold; 34 since the second) and the script after the three `cargo-deny` checks, each under `\|\| result=1`; no new gate, no new step, no tool installed |
| `tests/arch_duplicate_versions_104.rs` | Pins the list's form and totals (`ROWS` 11; `TOTALS` 11, 11, 3, 5; `LINES` 22 since the fold), the step's two lines, `deny.toml`'s warn level with no `skip`, the script's graphs |

The graphs: `all` (`--all-features --target all`), `wasm32` (`--no-default-features --features
"auth,wallet,transaction,overlay,socketio,wasm" --target wasm32-unknown-unknown`) and `default`
(`--target all`) are the three `cargo-deny` checks; `native` (`--features full,http,websocket
--target all`) is the widest documented slice, without the three internal features
`--all-features` adds. `--target all` makes the answer of `all`, `native` and `default` the same on any runner; `wasm32` names its target, so cargo evaluates its build and proc-macro edges for the runner's host (macOS here, Linux in CI), where cargo-deny's `--target` filter applies the wasm32 target to every edge: the two agree today (3 and 3 on macOS), and a host-only pair under a build edge would part them.

Why a script beside cargo-deny and not `multiple-versions = "deny"` with a `skip` list: one
`deny.toml` serves three graphs, so a skip for `sha1` (held twice in `all` alone) would let a
second `sha1` into the wasm32 slice unseen; a `skip` hides the crate from cargo-deny's own report;
and a count cannot be pinned there. The row holds lines, not versions, because no lockfile is
committed: `syn 2.0.119` to `2.0.120` must not turn the gate red, a `syn 1` beside `2` and `3`
must.

## Today's duplicates (2026-11-14, a fresh lockfile, SHA-256 `a2e3cf13...722dc`, cargo 1.98.1)

The script: `all 11, native 11, wasm32 3, default 5; 11 rows`. cargo-deny 0.20.2 on the same
lockfile: 11, 3 and 5 `warning[duplicate]` lines, all three graphs `advisories ok, bans ok,
licenses ok, sources ok`. Every version is the census's of 2026-11-09; the parents were read again
by `cargo tree -i` (`inversions-all.txt`, `inversions-wasm.txt`) and the newest releases from
crates.io (`newest.txt`).

| crate | versions | all | native | wasm32 | default |
|---|---|---|---|---|---|
| base64 | 0.22.1, 0.23.1 | x | x | | |
| block-buffer | 0.10.4, 0.12.1 | x | x | | |
| core-foundation | 0.9.4, 0.10.1 | x | x | | |
| cpufeatures | 0.2.17, 0.3.1 | x | x | | x |
| crypto-common | 0.1.7, 0.2.2 | x | x | x | x |
| digest | 0.10.7, 0.11.3 | x | x | | |
| getrandom | 0.2.17, 0.4.3 | x | x | | |
| rand_core | 0.6.4, 0.10.1 | x | x | x | x |
| sha1 | 0.10.7, 0.11.0 | x | x | | |
| syn | 2.0.119, 3.0.10 | x | x | x | x |
| windows-sys | 0.52.0, 0.61.2 | x | x | | x |

## The moves that would end a row (none made; resolution only, run through the script)

Each is a manifest edit in a scratch copy, the lockfile resolved again and the script run
(`probe-*.log`); nothing was built.

| Move | Exact edit | Rows it ends | What it adds or costs |
|---|---|---|---|
| A | `tokio-tungstenite = "0.30"` (from `"0.24"`) | `block-buffer`, `digest`, `sha1` in `all` and `native` (the three rows whole) | three new pairs in `all` and `native`: `rand` 0.8/0.10, `thiserror` 1/2, `thiserror-impl` 1/2; tungstenite 0.26 onward changed the `Message` payload types, so `src/auth/transports/websocket_transport.rs` moves |
| B | `aes-gcm = { version = "0.11", default-features = false, features = ["aes", "alloc"] }`, `aes = "0.9"`, `cbc = "0.2"` | `crypto-common` in `wasm32` and `default`, `cpufeatures` in `default` (wasm32 3 to 2, default 5 to 3) | the cipher 0.5 API in `src/primitives/symmetric.rs` and `src/compat/ecies.rs`; aes 0.9.3 and later declare rust-version 1.89 above the crate's 1.88 |
| A and B | both | also `crypto-common` and `cpufeatures` in `all` and `native` (11 to 9 there, with A's three new pairs counted) | both of the above |
| W | `wiremock = "=0.6.5"` (from `"=0.6.2"`) | none: 0.6.5 still asks base64 0.22 | nothing |
| none here | `base64`, `core-foundation`, `syn`, `windows-sys` | wait on wiremock, hyper-util, zerocopy-derive and openssl-macros, memory-stats (each the newest release, read 2026-11-14) | |
| the owner's | `getrandom`, `rand_core` | rand 0.8 to 0.10 and the `wasm` feature on getrandom 0.4's `wasm_js` | every wasm32 dependent rebuilds; the question of #104 |

## The RED runs

| Run | Tree | Result |
|---|---|---|
| `red-base.log` | a scratch copy of `80532565` with the test file overlaid | 5 of 6 fail (no list, no script, the `deny` step without the two lines); the `deny.toml` pin passes on both, a pin of standing policy |
| `red-row-added.log` | a copy of the tip, one row appended to the list | 2 of 6 fail: `12 rows, pinned 11` and each graph's total |
| `red-ci-base.log` | a copy of the tip with the base's `ci.yml` | 1 of 6 fails, naming the two lines |
| `red-script-itoa.log` | a copy of the tip, `itoa = "0.4"` added under `[dev-dependencies]`, `cargo generate-lockfile` | the script exits 1: `all 12, native 12, wasm32 4, default 6` and `NEW duplicate` in each graph |
| `arch-104-green.log` | the tip | 6 of 6 pass; the script exits 0 |

An earlier pair of planted runs reused a test binary built from an earlier scratch tree in the same
target dir and failed for that tree's missing files; they were discarded and run again in a fresh
target dir. The scratch trees and the scratch target dir are removed.

## Questions

1. **A stale row is a refusal.** A release under the crate that ends a pair (a wiremock on base64
   0.23) turns `lint` red on the next resolution, on any pull request, until the row goes. The
   other choice is a warning for `STALE` alone. Built as a refusal: the repository's rule for
   counted exceptions, and the message names the edit.
2. **`native` is a fourth graph** beside cargo-deny's three, at the brief's word. It holds the same
   eleven as `all` today and costs one `cargo tree`; dropping it is three lines.
3. **The getrandom question** stays the owner's (the issue's comment); moves A and B stay slices
   of their own.

## What is not verified

The step on a Linux runner (the script was run on macOS arm64 alone; `--target all` and the
lockfile make the graphs platform-free by cargo's own reading, and the job's Python is the one its
other scripts use; the script imports `argparse`, `pathlib`, `subprocess` and `sys` alone).

## The fold (lane fix-104-dups-fold, 2026-11-14)

The strength read's two items, and two agreements the three reads left in one place each.

| What | Before | Now | RED |
|---|---|---|---|
| `main()`'s exit code | no test: `return 0` on the last line, or `errors += judge(rows, found)` removed, passed all 21 | `Main` in `test_duplicate_versions.py`, seven tests with `cargo_tree` mocked over a temporary root: 0 with the counts line alone; 1 with its line for a new duplicate, a stale row, a moved pair, a list out of form (alone and beside a graph fault); 1 with cargo's words when `cargo tree` fails | `judge` line removed: 4 of 28 fail; `return 0`: 5 of 28 fail |
| A row widened by a line | `syn \| 2, 3` to `1, 2, 3` in the list alone moved no pinned total: 6 of 6 | `LINES` (22) in the arch test, the lines summed over the rows | the list alone widened: 2 of 6 fail, `23 lines over the rows, pinned 22` |
| The order of a row's lines | the script refused lines not distinct, not in order or not a line (`2.0.119`); the arch test asked two or more alone | the script's rule is the rule; the arch test reads it too (`line_key`, `is_line`), six planted forms | in the test's own plants |
| The wasm32 graph and the runner | the script's comment said the answer is the same on any runner | the comment says it of `all`, `native` and `default`; `wasm32` names its target, and cargo evaluates build and proc-macro edges for the runner's host | a comment |

Not built, a row for the captain: pinning the runner for the `wasm32` graph. The `lint` job's
`runs-on` already fixes the host the required check reads that graph on, so in CI the graph is one
host's; the difference is between CI and a maintainer's machine (macOS here), where a host-only
pair under a build edge would show in one and not the other. Two ways to close it, neither taken:
the arch test pinning `lint`'s `runs-on`, or the script reading the wasm32 graph without host
edges as cargo-deny's `--target` filter does.

Logs: `/Volumes/Lanes/out/bsv-rs/fix-104-dups-fold/` (`red-main-A.log`, `red-main-B.log`,
`red-lines-before.log`, `red-lines-tip.log`). The scratch tree and its target dir are removed.

## The second fold (lane fix-104-dups-fold2, 2026-11-14)

The re-read of the fold planted two faults that passed. Both are mended, each with its RED.

| What | Before | Now | RED |
|---|---|---|---|
| The exit code CI reads | every test called `dv.main()`; the script's last line changed from `sys.exit(main())` to `main()` passed all 28, and the process then exits 0 on a new duplicate and on a failing `cargo tree` | `Process` in `test_duplicate_versions.py`, three tests: a copy of the script under a temporary root, run by the step's own command line (read from `ci.yml`, `python3 -B .github/scripts/duplicate_versions.py`, no argument), a stub `cargo` (a shell script answering `cargo tree` from one file a graph) the only one on `PATH`; 0 for the graphs the list describes, 1 for a new duplicate, 1 for a `cargo tree` that fails | the plant: 2 of 34 fail (`0 != 1`, twice); the fold's 28 tests on the plant: 28 of 28 |
| A line as the two readers read it | `base64 \| 0.22, 0.23-rc` and `0.22, 0.23+x` passed the arch test 6 of 6 where the script's `parse_rows` refuses them: `is_line` did not refuse `-` or `+` as `line_of(v) != v` does | `is_line` refuses both; the arch test's header writes the script's rule out with every spelling it refuses; `REFUSED_LINES` (21 texts) plants each and `READ_LINES` (7) the spellings read; the script's tests read both tables from the arch test's file and hold `parse_rows` to them; a crate name holding a space is refused by both | `is_line` without the refusal: 5 of 6, the form test failing with no refusal for `0.10, 0.11-rc`; the two rows in a copy of the list: 3 of 6 fail on the tip |

The agreement, as far as it is held: on the two tables by a run on each side; beyond them by
reading, on a list of ASCII text whose line parts are numbers as cargo writes them. Outside that
the two can part and nothing holds them (the arch test's header lists the cells: two spellings of
one number such as `01, 1`, a number past `u64`, a digit outside ASCII, white space and line ends
Python takes and Rust does not).

Said, not built: `base64 | 0.22, 0.24` in the list alone passes the arch test 6 of 6 (the line
total does not move) and the script's `parse_rows`; the script's `judge` refuses it against the
graphs as `MOVED`, in CI. The arch test's header says so: whether the graphs hold what the list
says is the script's run, never that file's.

Logs: `/Volumes/Lanes/out/bsv-rs/fix-104-dups-fold2/` (`red1-exit-plant.log`, `red2a-is-line.log`,
`red2c-name.log`, `plant-row-*.log`). The scratch tree and its target dir are removed.
