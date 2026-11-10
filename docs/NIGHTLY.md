# Nightly oracles

`.github/workflows/nightly.yml` carries the on-demand mutation check for
[bsv-rs #81](https://github.com/Calhooon/bsv-rs/issues/81) and the fuzz matrix
for [bsv-rs #82](https://github.com/Calhooon/bsv-rs/issues/82), part of
[the north-star programme](https://github.com/Calhooon/bsv-rs/issues/101).
Never on a push or a PR: the gate is `ci.yml`. It runs on demand only,
`workflow_dispatch` on the line to measure (`gh workflow run nightly.yml --ref
beta`), never on a schedule: the owner's word of 2026-10-27 (the nightly runs
were a waste of resources) took the 03:00 UTC cron off both lines. Since cut 7
(the owner's word of 2026-11-02, "even the nightly... is all that necessary?
or maybe a fraction"), a night is incremental: it mutates the files the reach
rule names since the last complete run and carries every other file's figure
with that run's id and sha; the complete run (`-f mode=complete`) is
dispatched at each prerelease pin and before each minor tag (`RELEASING.md`
step 3 names the dispatch: this workflow is not callable, so `release.yml`
cannot run it before a tag). The rule, the record and the dispatch lines are
in "Incremental nights and the complete run (cut 7)" below. A push to a
protected branch runs `ci.yml`'s required set, nothing more (the owner's word
of 2026-10-27). Its `ci-full-beta` and `ci-full-main` jobs dispatch `ci.yml`
on `beta` and on `main`, so each line's whole test matrix and `dependents` run
at its tip (a pull request and a push run only the line's required set). They
run after the shards and the fuzz targets, whatever their result, and one
after the other: `ci-full-beta` waits for beta's run, the one it dispatched
(listed before the dispatch, the bot's alone; `gh run watch`, one runner for
its 23 minutes, given up at 55 minutes with a warning and no verdict, any
other failed watch an error; a `failure` conclusion fails the job, #682's
third and fourth folds) before `ci-full-main` dispatches main's, since
beta's run holds up to 9 jobs at once and main's up to 22 (31 together; the
fleet's runner cap, #682's two folds, the keeper's word (a)). On a Sunday
night (`-f weekly=true`) the `bench` job sits between them (#683): it
dispatches `bench.yml` after the shards, the fuzz targets and beta's run,
waits for that run under `ci-full-beta`'s rule (two jobs, then the
scoreboard, and its own one runner), and `ci-full-main` needs it too, so
the order is the shards, the fuzz targets, beta's run, the bench's run,
main's; until #683 it dispatched beside the opening wave of shards, with no
`needs`. `tests/arch_nightly_cap.rs` reads a job that dispatches any
workflow as heavy, so a new one without its edge is refused by name.
`tests/arch_nightly_cap_rules_709.rs` (#709) reads four rules more from the
YAML: every workflow is read for a dispatch (`gh workflow run`, a
`gh api .../dispatches`) or a reusable call (`uses: ./.github/workflows/...`),
a call in the nightly a heavy job as a dispatch is, one outside it refused
unless its workflow starts by a hand act alone (`workflow_dispatch`, a push
of tags: `release.yml`'s calls on a version tag) or the record names it
(today the sync's dispatch of `ci.yml` on a push to main, not sequenced with
the nightly, a stated residual); every heavy job after the shards keeps
`!cancelled()` in its `if:`; every wait gives up at or under its job's
`timeout-minutes` minus five (the 55-minute budget and the 30 × 10 s poll
under 60); and every wait's `--workflow` names the file its job dispatched,
both directions since #713's fold (two dispatches with one listed refused,
`-w` read, a `WF=bench.yml` variable read through its one assignment).
`tests/arch_nightly_cap_watch_713.rs` adds the watch rule: every dispatch job
of the nightly with a job after it carries a `gh run watch` per dispatch
(today `ci-full-beta` and `bench`), each under `timeout "$budget"`, the
`budget` the one `$((N * 60 - SECONDS))` the give-up rule reads, so a watch
dropped, unbounded or bounded by a doubled budget is refused.
`ci.yml`'s two
matrices carry `max-parallel: 6` (the keeper's line of 10:0xZ 2026-11-03;
14 before it), so the seven dependents run six, then one, wherever they run; main's run, on main's file, still holds
up to 22 for a minute and a half at its start, the residual the next complete run
measures (`docs/lanes/ci-speed-7.md`, "The fleet's runner cap"). The other measurements
are workflows of their own, dispatched on the line and called by `release.yml`
before every tag: `bench.yml` (build and scoreboard; comparisons only on branch
dispatches), `msrv.yml`, `features.yml`, `machete.yml`, `docs.yml` (actionlint).
Documentation is a step of `ci.yml`'s required `checks` job on both lines
since the small gates were bundled (`docs/lanes/ci-speed-2.md`): it runs on
pull requests and pushes, with `cargo doc --no-deps --all-features` under
`RUSTDOCFLAGS: -Dwarnings`. The constants
in `tests/arch_ci_pr_runs_the_required_set.rs` name that intended set.
**The pin (#629).** A run measures the commit it was dispatched on, never
the line's tip when its pin job dequeues. The `source` job pins
`inputs.commit` when the dispatch names one, else `github.sha`, the
dispatched ref's commit, which GitHub fixes when it creates the run;
`nightly_mutants.py pin` takes that sha as an argument, refuses one that is
not a full 40-hex sha or not on the dispatched line (`::error::the dispatch
names <sha>, which is not on beta: refused (#629)`), and never reads the pin
from a ref. Every mutation shard, the score job and every fuzz job check out
that commit; each shard refuses a checkout at another one (`run --commit`),
and the score job refuses evidence of another commit and names the pin in
the scoreboard (`report --commit`, `Source commit: <sha>`). A run queued
behind another therefore measures the tree it was dispatched on, whatever
lands meanwhile: the 2026-11-01 run 41347058507, dispatched at `9640eaa7`,
dequeued after #613 landed and measured `42a74f1b` while its `head_sha` named
`9640eaa7`. To measure a given commit of the line:
`gh workflow run nightly.yml --ref beta -f commit=<full sha>`. The workflow
has no schedule; were one restored, its `github.sha` is the default branch's
commit at the run's creation, so it would pin `main`, never `beta`.

**The entries (#663).** An `exclude_re` entry of `.cargo/mutants.toml` names
one mutant by file, line, column and text; a line shift leaves it naming
nothing, so it excludes nothing, the equivalent mutant runs and survives,
and the file reads below its true figure (fifteen `script.rs` entries after
#639, three `merkle_path.rs` entries, #677, one `beef.rs` entry, #678). The
`source` job runs `.github/scripts/mutants_entries.py` before its plan: it
lists the mutants of every file the entries name (`cargo mutants --list
--file <file> --no-config`, nothing built, about six seconds for the seven
files) and refuses the run, before any shard, when an entry matches no listed
mutant or more than one, printing the entry and its re-point (`STALE entry
(no listed mutant): <entry>` then `re-point to <line>:<col>: <listed
mutant>`, or every candidate when none is unique). CI's `checks` job runs the
same check on every pull request and push, so a change that shifts a line
under an entry re-points it in the same commit; `mutants_entries.py --fix`
rewrites each uniquely re-pointed entry and the `<line>:<col>` its comment
names, by hand, never in a workflow. The job builds cargo-mutants for it, so
its timeout is 20 minutes. A pull request that inherits a stale entry from
beta (the line moved under a landing the PR did not make) stays blocked at
`checks` until the entry is re-pointed on beta (`mutants_entries.py --fix` by
the captain, as #677 and #678 were) and the PR rebased; a red
`mutants-entries` on beta's own push run means a bypass landed a stale entry,
and the captain reads that run.

GitHub requires the workflow on the default branch (`main`) to enable manual
dispatch, so the file lives on both lines, ported by `git cherry-pick -x`.
See [manual dispatch](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

Permissions are scoped per job: every job has `contents: read`; only the fuzz
job, which files its crashes as issues, adds `issues: write`.

## What runs

`cargo-mutants` 27.1.0 is built from crates.io source with `cargo install
--version 27.1.0 --locked`. Every action is pinned to a commit with its version
beside it, following `ci.yml`. The mutation jobs' token has only `contents: read`.

The shards are the plan's (cut 7, below): a complete run is twenty-three, eight
script, three BEEF, one Merkle, three wire and eight substrates since #703's
second fold (twenty before it: eleven, three, one, two and three until #685), at
the plan's figure by window (below; at six, the fleet's cap of the keeper's line
of 10:0xZ 2026-11-03 until #791, four waves, 6, 6, 6 and 5; the twenty of the
fixed lists replayed at about 3h07m from run 41579707627's shard times,
`docs/lanes/ci-speed-7.md`; at fourteen, two waves, 14 and 9, the second the
tail at six when it is projected past 09:00Z, below); a night is as many as its
files' estimated minutes need, at the same figure.

**The heavy-run cap by window (#791).** The owner's word of 2026-11-04
17:1xZ, through the keeper, amending the balance rule of 2026-10-26 and the
fleet's cap of six: a heavy hosted run (a complete mutation run, a nightly)
takes up to fourteen of the account's twenty slots inside its own window
when no other heavy run of the account is scheduled in that window, six
otherwise. The plan (`nightly_mutants.py plan`, `heavy_max_parallel`) reads
the plan step's UTC clock (minutes after the dispatch) against the keeper's
windows table, kept as data in
the script (`HEAVY_WINDOWS`, one row per window with its owner and source, so
a later word edits a row):

| Window (UTC) | Owner | Figure here |
| --- | --- | ---: |
| 01:00Z to 09:00Z | bsv-rs: the complete run's 01:00Z slot, the incremental night's 07:00Z and the pin-chain dispatches | 14 |
| 17:00Z to 20:00Z (the keeper's table of 2026-11-04 18:0xZ, superseding the one-hour entries of 2026-11-03) | bsv-wallet-cli's night | 6 |
| 20:00Z to 01:00Z (the same table; a window past midnight wraps) | the toolbox's night | 6 |
| 09:00Z to 17:00Z (the same table: outside every window) | the day, every repository's PR CI | 6 |
| any other hour | none | 6 |

None runs at fourteen while another heavy run's window holds the hour. The
dispatch input `heavy_max_parallel` (an integer from 1 to 20; empty by
default) overrides the window for one run. The plan writes the figure as
`max_parallel` and why as `max_parallel_reason` (the window matched, "outside
every window", or the dispatch input) into `plan.json` and the step's
outputs.

**The tail (#791's fold).** The keeper's word of 2026-11-04 18:0xZ: "a run
overrunning its window drops to six for the waves after the window's end: the
plan's shard estimates project each wave's end at dispatch, the waves projected
inside 01:00Z to 09:00Z run at fourteen and those past it at six, so a complete
run dispatched by about 04:00Z runs whole at fourteen and a late one tails at six
into the day's PR CI; never fourteen into the CLI's window." Inside this crate's
window the plan (`split_tail`) cuts the matrix, in the order it runs, into waves
of the window's figure, each starting when the previous one's longest shard
ends, and projects each wave's end from the plan's clock. A complete run's shard
minutes are the last complete record's in the tree (`shards[].job_minutes` of the
newest `docs/census/mutants-*.json` with shards; a shard's minutes do not move
with the figure, only the waves do; a shard the record does not name reads as
its surface's longest there); an incremental night's are the plan's own
estimates (its shards are not the complete run's). The shards whose wave ends at
or before 09:00Z are the `mutants` job's matrix at the window's figure; the rest
are the tail, the `mutants-tail` job (the same steps and artifact names, pinned
byte for byte; `needs: [source, mutants]`, `!cancelled()`, skipped on an empty
tail) at `max_parallel_tail`, six. A run whose opening wave already ends past
09:00Z runs whole at six with no tail; outside the window there is no tail. The
dispatch input sets the window's waves only; the tail stays six (outside the
window it is the whole run's figure, as before the fold). `plan.json` keeps
`matrix` (every shard, the score's planned set) and adds `matrix_window`,
`matrix_tail`, `shards_tail`, `max_parallel_tail` and `max_parallel_fuzz`; the
step's `matrix` output is the window's waves and `matrix_tail` the tail;
`max_parallel_reason` names the waves' projected ends and the split. On the
2026-11-04 record (the two waves' longest shards 212.8 and 244.8 minutes, script
0/8 and wire 2/3) a complete run runs whole at fourteen when dispatched by
01:22Z; at 03:00Z its waves end at 06:32Z and 10:37Z, so 14 shards run at
fourteen and the 9 after them (wire 2/3 and the eight substrates shards) are the
tail; at 07:00Z the opening wave ends at 10:32Z and the whole run is at six. The
word's "by about 04:00Z" reads a shorter run than the record measures. The waves
are a bound: GitHub starts a queued shard as soon as any slot frees, so the
window's job ends no later than its projection. The mutant shards read
`max_parallel` and `max_parallel_tail`, the fuzz targets `max_parallel_fuzz` (the
window's figure, six after a tail, which ends past the window; a literal 6 until
#791); the fuzz stage and the score job need both shard jobs. The
night's record names both in its run entry and a complete run's record in its
producing-run section ("23 shards at 14 at a time, at 07:00Z, inside this
crate's window"). The figure's owner is loop four's #675.
`tests/arch_nightly_cap.rs` refuses a literal or another matrix's reading on
any of the three matrices, the line removed, the window's figure above 14, the
shared one above 6, the input's bound above 20, the tail's figure other than the
shared six, the split gone, and the tail's steps other than the window's job's.
GitHub's own waits are named as GitHub's in the record, never
absorbed as this crate's (`mutants_record.py write --github-wait <text>`, a
line each): an image change, an incident, a hosted-runner queue; on
2026-11-04 the move of `macos-latest` to the macos-26-arm64 image (run
41861794622; the step that assumed the cargo home was this crate's, fixed by
#789) and the hosted macOS arm64 queue of 16:49Z to 17:2xZ ("The job was not
acquired by Runner of type hosted even after multiple attempts"; GitHub's
notice: "Due to capacity constraints, jobs targeting macOS arm64 runners may
experience longer queue times") were GitHub's.
Each shard uses one mutation worker, its own `CARGO_TARGET_DIR`, a test timeout
of three times its baseline's test time, never under 120 seconds (300 for BEEF;
`MINIMUM_TEST_TIMEOUT`'s floors, the fixed timeouts until #685), and a 300-second
build timeout per mutant. A mutant that times out in the shard's pass is re-run
once, alone, inside the same `run` (#781, the keeper's word of 2026-11-04
15:2xZ): the shard's command without its sharding, the mutant's exact name as an
anchored `--re` (escaped as Rust's `regex::escape` escapes) and a one-line
`--in-diff` of its start line, the text unchanged (cargo-mutants 27.1.0 lists
every `StructField` mutant of the files whatever `--re` and `--exclude-re` say,
nine at `8264a95d`; the line leaves them out and the name leaves out the line's
other mutants), the baseline run again so its timeout is derived from the shard
as it is then (the base re-timed), the same limits, `--jobs 1`, and its own
`--output`, `rerun/<n>/`. The re-run's outcome is the mutant's: caught or missed
replaces the pass's timeout; a second timeout stays one. `run.json` carries the
mark (`timeout_rerun: 1`) and each re-run (the mutant, both passes' outcomes,
seconds and logs, the test each log names, the command, the method). A job is limited to
six hours. A failed baseline, interrupted job or missing shard fails the score
check. These limits bound work; they never turn an unfinished run into a score.

The runner uses copied source trees, with `--in-place` absent. Both copies and
build products are under the runner's temporary directory, outside the checkout.
One worker per shard prevents independent copies from sharing mutable build
products through a single `CARGO_TARGET_DIR`.
The mutation runner enables `CARGO_INCREMENTAL=1`, including when the host
environment disables it, so each mutation can reuse the baseline's compilation.

The test command is `cargo test --features "full,http" --locked --lib`, followed
by one `--test NAME` for every target of the shard's selection (below, "The
selection", #685). The wire surface's word is `full,http,tracing`
(`SURFACE_FEATURES`, #603): `src/wallet/wire/diagnostics.rs` is compiled only
under `tracing`, which is outside `full`, so under `full,http` its two mutants
rewrote unbuilt text and read `missed` in the complete run of 2026-11-04; the
wire surface also runs `wire_tracing_sink` beside its selection
(`SURFACE_TESTS`), where its kills live. The other four surfaces keep
`full,http`. The same target selection
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
`beef_deep_chain`, `beef_stream_deep`, `beef_stream_pause`,
`beef_stream_linear_spend` and (since #685 brought it into the wallet surfaces'
reach) `wallet_http_json_linear_432` (`COST_CHECKS`): these include
large stress cases, wall-clock bounds and time ratios, which remain in the lane's full-suite
gate. Within `beef_stream`, `the_whole_path_walks_a_wide_bump_in_linear_time`
also stays in that gate on every surface, so its wall-clock bound cannot count as a caught mutant.
HTTP tests use `wiremock`; the job has no wallet
credentials and makes no live wallet call.

| Surface | Files mutated | Integration test targets since #706's rows (#685, the direct reading) |
| --- | --- | --- |
| script | `src/script/**/*.rs` | 138: the binaries naming `script` (a `bsv_rs::script` path, a crate-root re-export of it, or a row's Modules cell naming it) |
| BEEF | `src/transaction/beef*.rs` | 107: those naming `transaction` |
| merkle path | `src/transaction/merkle_path.rs` | the BEEF surface's 107 (one module) |
| wallet wire | `src/wallet/wire/**/*.rs` | 131: those naming `wallet` |
| wallet substrates | `src/wallet/substrates/**/*.rs` | the wire surface's 131 (one module) |

**The selection** (#685, the keeper's row of 2026-11-03 and word of
16:1xZ; `selection` in `nightly_mutants.py`). A measured file's test targets are
every integration binary that names its module, with `--lib`: the direct
reading (`Tree.direct` in `affected_tests.py`, the run's alone), the binaries
whose sources name the module by a `bsv_rs::<m>` path or a crate-root
re-export, or whose `tests/CLAUDE.md` row names it in its Modules cell (since
#706; a row named it or a file of it anywhere in its text before). A pull
request's plan (`reach`, #680) reads `Tree.users` instead: those binaries and,
one level, the binaries of the modules whose library code names `crate::<m>`;
the run does not take the callers' level, where a build and not a run per
mutant is the cost. The branch's reading before the fold took it and put 216
of the 283 binaries in a script file's set, about 5,237 to 8,090 estimated
shard-minutes against the 903 of run 41347058507 (the fixed lists; the complete run 41753882105
under the direct reading measured 4,438, below). Three of that reading's targets are
left out: a binary reached only by reading the source's text (the six `arch_*`
walks of `src/`, a literal naming the file), since a mutant rewrites the text it
reads and its verdict on the text tests no behaviour; the binaries the Test Suite
runs apart (`memory_profiling`, `wire_tracing_sink`; the wire surface runs the
sink beside its selection since #603, not through it); and the cost checks
above. Every source of a module reaches the same binaries, so the 85 measured
files' sets are three: 138 for the 43 script files, 107 for the four BEEF and
Merkle files, 131 for the 38 wire and substrates files (median 138; 136, 104 and
134 at `2d3f5fd1`, before #706's rows; with the callers' level 214, 204 and 164,
216, 206 and 166 before). A file the
rule names no binary for runs `--lib` alone and the plan names it (`lib_only`;
none at `2d3f5fd1`). Both findings' tests are in the direct sets by their
`bsv_rs::script` paths: `tests/pubkey_encoding_660.rs`,
`tests/pubkey_point_shapes_660_adv.rs` and `tests/p2pk_hybrid_625.rs` name
`bsv_rs::script` items, and their `tests/CLAUDE.md` rows named no module then
(the rule read of `59eeedcc`; the fold's text had said the rows name `script` and
the templates); since #706 the three rows name `primitives` and `script`. cargo-mutants runs one test command per shard, so a shard
runs the union of its files' sets (`surface_tests` in the plan, the night's
files' union; a complete run's is the surface's). Until #685 each surface ran
the fixed list its row named (the script surface `tests/script_*.rs` and five
targets, 45 at `55424846`): the #660 tests (`tests/pubkey_encoding_660.rs`,
`tests/pubkey_point_shapes_660_adv.rs`) never met `src/script/spend/key_point.rs`'s
mutants nor `tests/p2pk_hybrid_625.rs` `src/script/templates/multisig.rs`'s, so the
measured scores left out kills the suite had (#681's opening lane, PR #684). Every
target of the five fixed lists is in its surface's set.

**Two readings, two rules.** The callee rule (2026-11-03 00:1xZ, #666) is the
PLAN's: which measured files a night re-measures, a changed file's own and those
of the modules naming its module (`callee_added` in the plan). The direct rule
(#685, the keeper's word of 2026-11-03 16:1xZ) is the RUN's: which targets a
mutant's tests are, the binaries naming the file's own module, no caller's. No
reader takes the one for the other: a caller's files are re-measured when its
callee changes, and its binaries are not run against the callee's mutants. One side effect stays: the
unit-test `--skip` prefixes apply to every binary of the command, and on the
script surface they skip six integration tests (of 2,503 listed on one host),
all in `wallet_originator_option_329` (its `auth::`, `identity::`, `kvstore::` and
`registry::` modules); the fixed lists' targets were under the same prefixes.

**What the direct reading leaves uncounted: the reading's stated limit.** The
score is the measured file's under the targets that name its module, not the
whole crate's; no reader takes it for the whole. A binary that reaches a module
only through a caller (it names `bsv_rs::transaction` and the transaction code
calls `crate::script`) is not in that module's set, by construction: its kills
of the module's mutants are not counted. Since #706 a row names modules by a
convention a guard pins (`tests/CLAUDE.md`, "A row's modules"). Its Modules cell
names at least the modules its binary's source names by a `bsv_rs::<m>` path or a
crate-root re-export (a type or, since the #708 fold, one of the fourteen
functions such as `bsv_rs::sha256`), over the binary and the module files it
declares; a row shared by several files names each file's apart (`` `a.rs`:
`m`; `b.rs`: none ``), its union no file's, so the #537 and #544 rows no longer put
their twelve binaries in the `identity`, `kvstore`, `registry` and `storage` sets
(five #544 files in `primitives`) their sources never name.
`tests/arch_tests_claude_rows_name_modules_706.rs` refuses a binary without a row,
a row naming fewer, a shared row without a part per file and a stem named in
two rows (#712: every reader keys by the stem and keeps the last copy);
`.github/scripts/rows_from_sources.py` writes the cells, and its `--check`, the
guard's refusals in Python, runs in the Test Suite's plan step beside the plan's
own tests. That clause moves no selection: `Tree.uses` reads the source already.
What moves one is the caller clause, a module the binary reaches only through a
caller named where the row's description says the binary exercises it. It is a
judgment, applied once by the writer's word list (`CALLER_WORDS`; a shared row
takes none, its description being every file's), and its six pairs are frozen in
`tests/caller_modules_706.txt`, which the guard and `--check` both read:
`beef_order_held`, `beef_stream_603_s4` and `registry_integration_tests` in
`script`, `auth_fetch_423_payment`, `wallet_http_json_pending_432` and
`wallet_http_json_success_bytes_365` in `transaction`. `affected_tests.py` reads
the cell alone (`row_modules`; a row of four cells, the table before #706, by the
old patterns), so a description pointing at another file's witnesses
(`src/identity/...` in an auth binary's row) puts no binary in that module, and
reads a re-exported name only through the crate's path (`used_modules`; the word
reading took `WalletFaultFamily::Transport` for `auth` and a comment's "Address"
for `script`). The class (`Tree.users(m)` less `Tree.direct(m)`, less the
`arch_*` walkers, the two apart and `COST_CHECKS`) is 76 script, 97 transaction
and 33 wallet binaries since #706. Before #706 it was 80, 102 and 32: the rule
read of `59eeedcc` (2026-11-03), which the docs fold recomputed from
`affected_tests.py`'s `Tree` on `59eeedcc` (a read-only script; 81, 103 and 33
before the exclusions, one cost check each); #706's lane before its fold gave 76,
97 and 27, the six binaries the shared rows' union put in `wallet` since back in
the class. Every one of the 287 integration binaries has a row, and 19 rows name
no module (the 17 `arch_*` files, `readme_examples`, `wallet_fault_439`, whose
names are `error`'s); before #706, 233 of the 256 rows of a binary named none by
`row_modules` (a `src/<m>/` path or a `` `<m>::`` path in the row; the rule read
gave 223 of 256, which the docs fold did not reproduce by that reading or a looser
one). The rows decide little: three script and three transaction binaries are in
a set by their row alone, the six frozen pairs, and no wallet binary (before #706
none, none and one, `primitives_public_key_forms_498` by its description's
pointer). On #703's night a changed row re-measures the files of the modules its
reading gains or loses: the night after #706 lands re-measures the script, BEEF,
Merkle, wire and substrates files once (the record: `docs/lanes/fix-706.md`).

The globs include files directly in each directory and its descendants.
`tests/CLAUDE.md` documents these suites. The conformance targets read the
ts-stack corpus and skip, passing vacuously, when `BSV_CONFORMANCE_DIR` names
no `META.json`. Since #602 each mutation job checks the corpus out as `ci.yml`'s
`checks` job does for its vectors step (`bsv-blockchain/ts-stack` at
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
carry host metadata or test values; since #781 they keep each lone re-run's
`rerun/<n>/outcomes.json` and `line.diff` and no log of any mutant: what a
second timeout's log names (the last test binary's file name, the tests libtest
saw running past a minute) is read into `run.json`'s `named` when the re-run
ends, and the timeout table reads it there (the strength read of #784: the
kept log carried host paths, the full rustc line and the whole libtest output).
Download evidence before retention expires;
on a lane host, keep it under `/Volumes/Lanes/out/bsv-rs/oracle-nightly/`.

For each file:

```text
viable = caught + missed
score = 100 * caught / viable
pass = 100 * caught >= floor * viable
```

Unviable mutants are reported but excluded from the denominator. A mutant that
timed out in its shard's pass is judged by its lone re-run (above, "What
runs"): caught or missed as it reads there; one that times out again is excluded
from the denominator and listed in the report's timeout table (the file, the
mutant, the shard, both passes' seconds, the method, the test the log names),
each its own row, an environment artefact or a hang read from that test: never
a survivor and never a kill, as cargo-mutants keeps `Timeout` a class apart
(#781, the keeper's word of 2026-11-04 15:2xZ: no margin on a floor; the judge,
not the floor, carries a timeout). A file with generated mutants whose every
judged mutant timed out twice (`viable = 0`, at least one timeout row) reads
`UNJUDGED`, never `NO VIABLE MUTANTS` (the compiler's label, below), its
mutants in the timeout table and the file listed by name in the record's census,
so nothing drops in silence (#781, the keeper's word of 2026-11-04 16:1xZ). The
rule in one line (the keeper's word of 16:2xZ): wherever the night enforces a
number for a file (an explicit `mutation_floors` entry, the 80 of a gate path,
or the 80 a file elsewhere without an entry is held to), a timeout-only file
fails closed, with the one error `floor has no measured file: <file>` and the
Result `FAIL`; `UNJUDGED` and green only where the night claims nothing for the
file and measures it for the record alone. Every file a night judges has such a
number, so a timeout-only file it judges fails; `UNJUDGED` and green is a carried
row's (the night reds no carried figure; a carried row with an explicit entry
still fails on that floor). `TimeoutReRun781` pins the floored, the default and
the gate cases.
Files generating no mutants are listed as `NO MUTANTS`, without a numeric score.
The report's Result column, whole: `PASS`, `FAIL`, `NO MUTANTS`, `NO VIABLE
MUTANTS` (every mutant unviable), `UNJUDGED` (every judged mutant timed out
twice, on a carried row; #781) and `PARTIAL` (a surface of the file incomplete).
The check requires every candidate to have exactly one recognized outcome,
every timeout its lone re-run (the re-run finished, its re-timed baseline
green, the one mutant alone in it, its outcome the one `run.json` records),
one timeout rule across the shards, successful baselines, matching tool versions, matching source commits and
every shard of the plan (`report --plan`; a local replay's `--expected-shards`). Duplicate, missing, corrupt or unfinished evidence fails closed.
The integer comparison avoids accepting a displayed percentage rounded upward.

Evidence from before #781 (the 2026-11-01 and 2026-11-04 runs' artifacts, whose
`run.json` carries no `timeout_rerun` mark and no `rerun/`) is judged under its
own rule, `viable = caught + missed + timeout`, the timeout counted as not
caught: `mutants_record.py write` re-derives `docs/census/mutants-2026-11-04.md`
and `.json` byte for byte from run 41753882105's artifacts, and a carried
record row keeps the denominator it was measured with (`judge` reads the row's
`viable`).

A complete run's record compares a run with the record before it, and the two
may be under different rules. Under the re-run the record says which: the
previous record's survivors are read under its own rule (`previous_survivors`:
a record without `timeout_rule` counted its timeouts as survivors, a marked one
did not; `totals.previous_timeout_rule` names it), and the survivor term's
share of minutes has the timed-out passes and the re-runs' baselines in its
denominator, which a record before #781 has not, so the two shares are not one
measure (the record's legend says so). A record under the old rule is written
as it was.

A file whose generated mutants are all unviable (each replacement refused by
the compiler, so nothing a test can catch; no timeout row) is listed as
`NO VIABLE MUTANTS`,
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

The complete run 41753882105 at `2ff81a44` (dispatched 2026-11-04 01:24:50Z,
the corpus at `edf6e03`; its record `docs/census/mutants-2026-11-04.md` and
`.json`, written by `mutants_record.py write --widened <run> --previous
docs/census/mutants-2026-11-01.json`, the one-run form) measured every gate-path
file at or above 80: 80 PASS, 0 FAIL and 5 NO MUTANTS under the floors at
`2ff81a44`, 80 PASS, 0 FAIL, 4 NO MUTANTS and 1 NO VIABLE MUTANTS under its own
(72 PASS and 8 FAIL at 80 everywhere, the eight the floored files below 80), 332
survivors where the widened run left 1,583 (152 on the gate paths, 548 then).
`mutants_record.py floors --write` raised 27 of the 29 entries to its scores
rounded down (`http_json.rs` 50 to 92, `bounds.rs` 68 to 97, `transceiver.rs` 40
to 100 among them) and held two at their figure (`wire/diagnostics.rs` 0,
`wire/processor.rs` 60); no entry was added, and none of the 29 files' source
changed between `2ff81a44` and `4ed58d05`, where the ratchet holds them.

## Incremental nights and the complete run (cut 7)

**The rule** (the keeper's word, 2026-11-02): a file's mutation score moves
only when the file or the tests that reach it change. A night therefore
mutates only the files changed since the last complete run, judges them
against their floors, and carries every other file's figure forward from the
record with the run's id and sha named per file. The complete run over every
measured file is once per prerelease (at the pin, when the figure is cut into
the record) and by hand, never nightly. The fuzz targets keep a fixed small
budget each; the bench is weekly.

**The reach rule** (`nightly_mutants.py plan`, `reach`). The changed paths are
`git diff --name-only --no-renames <complete run's sha>..<pin>`; each maps to
the measured files it re-measures, and the plan prints why:

A **measured file** is one a surface's glob names that is not test-only. A
**test-only** file (`is_test_only`) opens with `#![cfg(test)]` before its first
item, or is named `tests.rs` or `*_tests.rs`: cargo-mutants generates no mutant
in a `#[cfg(test)]` module, so such a file has no shard, no carried figure and no scoreboard row
(thirteen under the globs at `84a01d2a`, `spend/tests.rs`, `flag_tests.rs` and
the `*_603_tests.rs` among them; 82 measured files, not 95). The files a
test-only file **tests** (`tested_by`) are its directory's measured files and
the module that declares it (its `mod` line, or a `#[path]` naming it, in a
sibling, the directory's `mod.rs` or the parent's `<dir>.rs`).

| Changed path | Re-measures | Why |
| --- | --- | --- |
| a measured file under `src/<m>/` | itself, and (the callee rule) every measured file whose text names `<m>` by a `crate::<m>` path or inside a `use crate::{...}` group, one level, its own module's included | its own mutants, and the code that calls its module |
| `tests/<name>.rs` in a file's selection, at the head or at the complete run's sha | the measured files its `tests/CLAUDE.md` row names (`## Files` table), within the files whose selection runs it, a test-only file it names counting as the files that file tests; a row naming a module (`src/<m>/`, `` `<m>::` ``), every measured file of the module; no row, or a row naming neither, every file whose selection runs it (#685: the selection read with the binary's text and row at both commits) | a test reaches the files it tests |
| `tests/<name>.rs` deleted | the same, judged by the base: the files whose selection held it at the complete run's sha (its text's `bsv_rs::` paths and its row in that sha's `tests/CLAUDE.md`) | the mutants it killed are measured again without it |
| `tests/<name>.rs` in no selection (a cost check, a binary run apart, one naming no module) | nothing | it never runs against a mutant, so no score can move |
| `tests/CLAUDE.md` | for each binary whose row changed, the files whose selection the change moves: those its row's modules at the head select and those at the base do not, or the reverse (#685) | a row's modules decide a binary's selection; a row whose words change and whose modules do not moves nothing |
| a `.rs` file elsewhere under `tests/` (`support/`, `chain_vectors/`, ...) | what the sources that compile it in reach, followed through: a `#[path]` or `include!` string resolving to it, or the `mod` line of its parent module (`mod binary;` in `support/fixtures/mod.rs`); compiled in by none, nothing | a support module reaches a mutant only through the test that includes it; a bare word (`fixtures`, `binary`) in a source is not an inclusion |
| any other file under `tests/` (`vectors/`, `fixtures/`, `support/*.mjs`, ...) | what the compiled sources naming it reach, followed through: its name whole in a source's text (`vectors/sighash.json`, not `tx-sequence-zero-sighash.json`), or its directory's path when that is two or more deep under `tests/` (`fixtures/wire/`, read through `format!("{}/tests/fixtures/wire/{call}.json")`); named by none, nothing | a vector reaches a mutant only through the test that reads it; a recorder (`.mjs`, `.lean`) is never compiled; a one-deep directory (`vectors/`) is every vector's, so it names none |
| a test-only source under `src/` | the files it tests (never their callers) | its tests run against those files' mutants; it compiles into no caller |
| a source under `src/<m>/` that is neither measured nor test-only | every measured file of `src/<m>/`, and (the callee rule, `CALLEE_RULE`, `callers`) every measured file whose text names `<m>` by a `crate::<m>` path or inside a `use crate::{...}` group, one level | the module's code, and the code that calls it |
| `src/lib.rs`, `src/error.rs` | everything | the crate root (the unit-test skips are read from it) and the one `Error` every module returns |
| `Cargo.toml`, `Cargo.lock`, `build.rs`, `.cargo/*` but `mutants.toml` | everything | a dependency, feature, profile or build change reaches every file that uses it |
| `.cargo/mutants.toml` | the files its added or removed `exclude_re` entries name (`^src/...\.rs:`); any other setting, or an entry naming no file, everything | an exclusion moves its file's candidates alone |
| `.github/workflows/nightly.yml`, `.github/scripts/nightly_mutants.py`, `.github/scripts/affected_tests.py`, `.github/scripts/test-runner-memory-ceiling.sh` | everything | the jobs, toolchain, corpus pin, selection (since #685 read through `affected_tests.py`), skips, score and the ceiling that decides a runaway mutant |
| `docs/`, any other `.md` | nothing | never compiled |
| anything else (`fuzz/`, `benches/`, `examples/`, `tools/`, other workflows, the scripts' own tests) | nothing | no selection compiles it |

A path that reaches everything makes the night a complete run (`why_complete`
names it). The two risks the keeper scored: a dependency bump re-measures
everything (`Cargo.toml`; the library commits no `Cargo.lock`, so a night
builds the complete run's own lockfile, kept in the record, and a crate
released since cannot move a carried figure's oracle unseen), and a test
change re-measures the files it reaches (the rows above). The literal rule
(any change under `tests/support/` or `tests/vectors/` re-measures
everything) would have made eight of the last ten beta commits a complete
run, because each #603 and #6xx landing adds a recorder and a vector; the
table follows those files to what reads them instead. At `84a01d2a` a change
to any of `tests/support/fixtures/*` reaches the wire surface's 15 files
(through `wallet_wire_cross_sdk_tests`), `tests/vectors/sighash.json` 55 (the
script surface's 40 through `sighash_tests`, the wire's 15 through
`support/fixtures/binary.rs`), a wire fixture the wire's 15; under cut 7's
word match the two first were complete runs and the third nothing.

**The callee rule's cost** (PR #666's fold; one function, `callers`, behind
`CALLEE_RULE`, so a fold can switch it off or narrow it). The keeper's letter
(2026-11-03 00:1xZ): a changed module re-measures every measured file that
names it, so since PR #666's second fold the rule reaches from every changed
source under `src/<m>/`, measured or not, where the fold applied it to an
unmeasured source alone. At `84a01d2a` the
measured files calling `crate::primitives` are 39 of 82, `crate::transaction`
7, `crate::block` 4. A `primitives` change re-measures the 39 in 16 shards of
the complete run's 20. On `origin/beta` from 2026-10-03 to 2026-11-02, 25 of
1,033 commits changed `src/primitives/` (12 of the 25 days with a commit; 2 of
the last 50 commits), 36 changed `primitives` or `block`, and 9 changed
nothing compiled but those two. Beta's last ten commits each planned alone:
29 shards over the eight incremental ones under cut 7, 34 under the fold (each
BEEF or Merkle landing adds the 5 substrates files that call
`crate::transaction`; `script-c` grows from 3 files to 15, its row naming a
test-only file), 46 under the second fold (`script-a` 40 files in 11 shards to
43 in 14, the three BEEF files naming `crate::script`; `script-c` 15 in 5 to
40 in 14, the measured `src/script/` files it changes reaching the 22 script
files and the three BEEF files that name `crate::script`). An edit to the
measured `src/transaction/beef.rs` alone re-measures 7 files in 2 shards (it,
`beef_tx.rs` and the five substrates callers), one to
`src/script/spend/flow.rs` 29 in 10.

**The count per night** (`callee_added`, the keeper's word: "the record names
per night how many files the cure added"). The plan's JSON carries
`callee_rule` (the switch's value) and `callee_added`, the sorted names of the
files the rule reached that no other row of the table reached (the reach run
again with the rule off, the difference); a complete run carries an empty list.
The record's `runs[]` entry carries the count under the run's `run_id` and
`commit`; the scoreboard's header prints it beside the mode ("The callee rule
added 5 files tonight (incremental): ..." with the names; "added 0 files
tonight (complete: every file measured)"; "The callee rule is off" when
`CALLEE_RULE` is). On the sample: `ffff16d0..84a01d2a` adds 5 (the substrates
callers of `crate::transaction`), `script-a` 3, `script-c` 25, the
`primitives/hash.rs` probe 39 (every file it plans), a documentation night 0.

**What is still carried that could move.** A callee two levels down: a change
in `primitives` read only through `transaction` by a measured file reaches the
files that name `crate::primitives`, not the ones that reach it through
`transaction`. (A callee that is itself measured was in this list until the
second fold: the rule now reaches from a changed measured file too.) A caller that names its callee by no `crate::` path in its own text: a
`super::super::<m>` path, `bsv_rs::<m>`, or a macro defined in another
module expanding `$crate::<m>` (none at `84a01d2a` in the measured files; an
alias, `use crate::primitives as p;`, and a `$crate::<m>` in the file's own
macro are read). A test-only file's tests reaching past its directory (the
interpreter's `spend/tests.rs` drives `crate::script` from `spend/`). A file a
source reads through a path built from one-deep pieces (`vectors/` and a name
computed at run time). A test outside a file's selection that kills its mutant
(the oracle is `--lib` plus the selection; such a kill is never counted): since
#685 the selection is the direct reading, so this is a binary reaching the file
only through another module (a caller's binary driving it through `transaction`
or `wallet`, the direct rule leaves out by the keeper's word on the cost) or
through no module path (a source-text reader). The toolchain: the nightly runs the unpinned `stable`, so a
compiler release between the complete run and a night can move a figure no
path in the diff reaches. Each lasts until the next complete run.

**The record.** A run artifact, `mutation-record` (`record.json` and the
`Cargo.lock` every shard built), never a commit: a committed file needs the
workflow's write permission on `beta` and would race the sequencer; an
artifact needs neither. The source job finds the newest unexpired
`mutation-record` of the line whose run measured an ancestor of the pin
(`nightly_mutants.py latest-record`, through `gh api
repos/Calhooon/bsv-rs/actions/artifacts?name=mutation-record`); none, and the
night runs complete. Each run uploads the whole merged record for 90 days, the
longest GitHub keeps one, so the chain lives while a run lands inside each 90
days. Its shape:

```json
{
  "schema_version": 1,
  "commit": "<this run's pin>",
  "complete_run": {"run_id": "...", "commit": "<sha>", "lockfile_sha256": "..."},
  "runs": [{"run_id": "...", "commit": "<sha>", "mode": "complete", "files": 82,
            "callee_added": 0}, "..."],
  "lockfile_sha256": "...",
  "files": {
    "src/transaction/beef.rs": {
      "surface": "beef", "generated": 0, "caught": 0, "missed": 0, "timeout": 0,
      "unviable": 0, "viable": 0, "score_percent": 0.0, "no_viable": false,
      "provenance": "night", "run_id": "...", "commit": "<sha>"
    }
  }
}
```

`provenance` is `night` for a file this run measured and `carried` for one it
took from the record, whose `run_id` and `commit` name the run that measured
it. A run whose evidence is incomplete (a missing shard, a failed baseline)
writes no record; a run whose floors fail writes one (the figures are
measured). `docs/ratchets.json` keeps its shape: the floors stay there.

**The scoreboard.** `report --plan` judges the night's files against their
floors as before and lists every carried figure with its provenance
(`carried: run <id> at <sha>`) and the complete run it carries from, and its
header names how many files the callee rule added tonight, and which. A carried
figure below its floor is a finding with its run named, listed under the
table, never a new failure of the night.

**The modes and the dispatch lines.**

```sh
# The night (by hand in the fleet's one daily slot, 07:00Z; 00:00Z retired 2026-11-03): the reach rule's files, the rest carried.
gh workflow run nightly.yml --ref beta
# The complete run (the day's one dispatch in the 01:00Z slot from the chain of 2026-11-05 on, the window's start, so the whole run fits at fourteen by the record's minutes; the keeper's word of 2026-11-04 18:2xZ; 07:00Z until the beta.7 cut; the incremental night keeps 07:00Z): at each prerelease pin (RELEASING.md step 3), after a measured cap change, before a minor tag, by hand.
gh workflow run nightly.yml --ref beta -f mode=complete
# The captain's Sunday night: the night, then the bench after beta's run, then main's (#683).
gh workflow run nightly.yml --ref beta -f weekly=true
```

A complete run was twenty shards (the keeper's cut 5; twenty-three since
#703's second fold, below), at most six at a
time since the fleet's runner cap of 10:0xZ 2026-11-03 (fourteen from
06:2xZ, one wave of twenty before; `docs/lanes/ci-speed-7.md`, "The fleet's
runner cap"), dispatched in the 01:00Z slot from 2026-11-05 on (07:00Z until the beta.7 cut), alone (the CLI's 17:00Z,
the toolbox's 18:00Z): the
measured minutes of run 41347058507 (script 130 per 515 mutants, BEEF 37 per
187, Merkle 3 per 25, wire 19.5 per 198, substrates 36.5 per 286; 901
shard-minutes) shared out by the largest remainder, about 47, 50, 11, 39 and
49 minutes per shard, so each wave ends within the hour (four waves on six
slots, about 3h07m replayed, where the surfaces-by-four matrix at six took
3h12m).

**The cost of #685's selection** (`docs/lanes/fix-685.md`). A mutant rebuilds and
links every target of its shard, and a survivor runs them all: run 41347058507's
rates against their selections (script 0.25 minutes a mutant at 32 targets, wire
0.10 at 3) give about 0.005 minutes a target (`MINUTES_PER_TARGET`), which one
host's rebuild after a one-line change in `multisig.rs` matches (13 s for the
script surface's former 45 targets, 63 s for 221, two jobs). The run's reading
is the direct one (the keeper's word of 2026-11-03 16:1xZ: 136, 104 and 134
targets at `f7ea87ae`, `ESTIMATE_TARGETS`; 138, 107 and 131 since #706's rows,
the estimate not recomputed): by those rates about 0.77, 0.70, 0.63, 0.76 and 0.79 minutes a mutant
for the five surfaces, 1,585, 520, 63, 599 and 902 shard-minutes, 3,669 in all
where the rates gave 903 (4.1 times). The slope is a line through two points
(script and wire) that the other three surfaces miss (BEEF 0.20 minutes a mutant
at 5 targets, Merkle 0.12 at 3, substrates 0.13 at 2), not a validated rate; the
box's `multisig.rs` run measured 0.845 minutes a mutant where it gives 0.77. The
slope averages the record's survivors, and a survivor runs every target: read in
two parts instead (0.28 s a target to rebuild, 0.64 s a target to run a
survivor's whole set, both on one host; each surface's survivor share from run
41347058507, the substrates' 84 percent the largest), about 5,717 shard-minutes
(script 1,880, BEEF 693, Merkle 90, wire 852, substrates 2,203).

The split (#703's second fold, `complete_split`): the record's own method, the
twenty shared out by the slope's estimate (floors, one shard at least, then the
largest remainders), run over the direct reading's sets on the fold's tip
(`ESTIMATE_TARGETS`, 2026-11-03 at `f7ea87ae`), gives eight, three, one, three and
five; then a ceiling, no shard's two-part estimate past 300 minutes (the job's 360,
GitHub's six-hour cap on a hosted job, with a margin;
`SHARD_CEILING_MINUTES`): each surface takes the method's count or its two-part
minutes over 300 rounded up, whichever is more (seven, three, one, three and
eight), so eight, three, one, three and eight, twenty-three shards. A shard is
about 198, 173, 63, 200 and 113 minutes by the slope (the longest wire's 200) and
235, 231, 90, 284 and 275 in two parts (the longest wire's 284); replayed in the
matrix's order at six slots, about 11h24m by the slope and 17h05m in two parts
(10h12m and 15h53m if perfectly packed), past the 187-minute replay of the fixed
lists (run 41579707627's shard times at six, 3h07m; 3h02m by the same model): the
complete run does not fit the 07:00Z slot alone. `tests` pins the split (the
method recomputed from the constants), the ceiling (every surface's two-part
minutes over its shards under 300) and every complete shard under `JOB_MINUTES`
by the slope. The fold before kept the callers' level's nine, three, one, three
and four, which the method does not give over 3,669: its substrates shards were
226 minutes by the slope and 551 in two parts, past 360, its replay 12h55m and
20h52m. A night scales the same way (its shards at 45 minutes each, at most the
complete count). The estimate leaves out each shard's setup (about 3 minutes).

The 07:00Z complete run at six slots under this split is expected to take about
11h24m by the slope or about 17h05m in two parts (the two-part reading likely an
upper bound, its 0.64 s a target the Studio's); neither is measured on a runner,
that run measures them, and the cost falls as the kill lanes (#681) close
survivors. The 07:00Z complete run of 2026-11-04 is checkpointed at 12:00Z (the keeper's
word of 2026-11-03 17:1xZ): the shards' measured rate projects the whole run; a
projection past twelve hours of six slots cancels the run (`gh run cancel`), the
record keeping the measured per-mutant rate per surface as the figure that
settles the slope, and the retry goes to the weekend slot (2026-11-08 07:00Z)
after the survivor-term row #705 lands; a projection under twelve hours lets it
run to the end, and the record carries the figure.

**The measured complete run** (41753882105 at `2ff81a44`, the record
`docs/census/mutants-2026-11-04.md`, its shard table and survivor term). It
ran to the end: dispatched 01:24:50Z, the last shard ended 14:59:33Z and the
score job 14:59:46Z, 13h35m for the mutation part at six slots, past the twelve
hours the checkpoint named and inside the two-part 17h05m. The checkpoint ran
under the keeper's bound rule of 2026-11-04 in place of the twelve-hour cancel:
at 12:00Z the shards' mean rate projected the end before 15:00Z, the bound was
set at the longest measured end plus thirty minutes, and the run was not
cancelled; the shards ended 14:59:33Z, inside it (the record's producing run,
`mutants_record.py write --checkpoint`). Its 23 shards took 4,438 job-minutes
over 4,902 mutants (1.21 times the slope's 3,669, 0.78 of the two-part 5,717):
script 1,538 at 0.71 minutes a mutant (the slope's 0.77), BEEF 421 at 0.56
(0.70), Merkle 36 at 0.37 (0.63), wire 632 at 0.79 (0.76), substrates 1,811 at
1.57 (0.79); the longest shard wire 2/3 at 245 minutes, every shard under the
300-minute ceiling. The survivor term (#705): measured by each mutant's phases,
the 332 survivors took 779 minutes and the 4,136 kills 3,496 (17.8 percent of
4,369 minutes; 2.35 minutes a survivor against 0.85 a kill), the survivors'
share 16.7 percent of the script surface's minutes, 4.8 BEEF, 4.1 Merkle, 9.7
wire and 24.9 substrates: the kills, most of the viable mutants, carry the run,
where #705's row read the survivors as its cost.

The branch's reading before the fold, with one level of callers (216, 206 and
166 targets), is superseded; its figures stay as the reason for the fold. It
estimated about 1.17, 1.21, 1.14, 0.92 and 0.95 minutes a mutant, 5,237
shard-minutes (5.8 times 903); shared out as before, its wire and substrates
shards would have passed the job's 360 minutes (362 each), so it re-split the
twenty nine, three, one, three and four, about 268, 300, 115, 242 and 271
minutes a shard, the longest the BEEF shards at 300, and its replay at six slots
was about 17h30m: it no longer fitted the 07:00Z slot alone and held six of the
fleet's twenty runners through the toolbox's and the CLI's slots. Read in two
parts it was about 8,090 shard-minutes, the BEEF shards about 420 minutes and the
substrates' about 674, and about 24 hours at six. The direct reading is 0.70 of
its 5,237.

One host's measure on `multisig.rs` under the direct reading (47 mutants, 137
binaries): a baseline of 65.5 s; 39 of 47 mutants in 1,977 s (about 0.85
minutes a mutant), 37 caught, one unviable, the one survivor (`108:19`) 34 s
to build and 168 s to test. That baseline ran without the conformance corpus
(the host lacks it; `conformance_scripts` and `conformance_beef` skipped),
which the record's 65 s for the fixed list's 45 targets included; the corpus is
about 1 percent of a baseline (on Linux runner job 125937464890, at `55424846`
with 4,120 vectors run, `conformance_scripts` finished in 0.60 s and
`conformance_beef` in 0.01 s), so it does not explain the two baselines lining
up: the Studio's per-target test cost runs high (macOS's scan of a freshly
linked binary on its opening run, and the load), and the measure is noisy (the
survivor's full run 168 s against the same 137 binaries' 65.5 s baseline).
The cold read of `59eeedcc` on the Studio, with the corpus (4,120 vectors
run, load 5 to 10), measured the direct reading's 137 binaries at 94.5 and
95.2 s on fresh links and 43.6 and 50.2 s warm, the fixed list's 46 at 33.7 s
fresh and 23.6 s warm, the corpus about 0.5 s of either; a survivor costs
0.69 s a target on fresh links (the fold's 0.64) and 0.34 s warm, so the
two-part estimate is about 5,900 shard-minutes fresh or about 4,600 warm,
within a third of the fold's figure; `108:19` Missed at 27 s to build and
99 s to test, two caught mutants at about 27 s plus 3 s each.

Each shard is one job on its own
runner, one mutation worker, under the same `ulimit -v` of 4,000,000 KB through
the runner hook (above): the ceiling is per test binary, so a narrower shard
changes nothing about it. A night's shards are sized by its files' mutants in
the record at those rates (since #685 at the minutes of the night's sets,
`surface_minutes`; each matrix entry carries its `estimated_minutes`), 45 minutes a shard, at most the complete run's
count per surface, at the plan's figure by window (#791; six, the balance rule of 2026-10-26, until then). An empty
plan runs no shard; the score job carries every figure. The bench is the
`weekly` input: the workflow has no schedule, so "weekly" is the dispatcher's
word, and the job dispatches `bench.yml` at the line's tip, after beta's
`ci.yml` run and before main's dispatch, waiting for its own run (#683).

The hermetic pass over survivors: the nightly has no job of that name at
`84a01d2a`; the survivors' evidence is each shard's diffs, so a night's
evidence holds the night's files' survivors alone.

To plan a night by hand (no cargo; the record from a run's artifact):

```sh
python3 .github/scripts/nightly_mutants.py latest-record --line beta \
  --commit "$(git rev-parse origin/beta)" --dest "$RUN_ROOT/base"
python3 .github/scripts/nightly_mutants.py plan --commit "$(git rev-parse origin/beta)" \
  --base-record "$RUN_ROOT/base" --output "$RUN_ROOT/plan.json"
```

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

**What runs.** One job per target of `fuzz/Cargo.toml` (20 today, pinned to the matrix by `tests/arch_fuzz_targets_dispatched.rs`; the table is in `fuzz/fuzz_targets/CLAUDE.md`), each built with `cargo fuzz build -O` on the pinned nightly (AddressSanitizer, but `-s none` for `fuzz_script_spend_default`, whose 128 MiB budget ASan's resident set takes past the 2,048 MB RSS limit, #398) (`FUZZ_TOOLCHAIN`, `cargo-fuzz` by version) and run for a fixed budget from its checked-in corpus `fuzz/corpus/<target>/` (`-fork=2 -ignore_crashes=1 -max_total_time=$((FUZZ_MINUTES * 60))`): a crash is recorded and the run goes on. The budget is `FUZZ_MINUTES`, 10 minutes per target by default, set by the repository variable `NIGHTLY_FUZZ_MINUTES` (at most 30, under the job's 45-minute timeout); until cut 7 it was an hour (run 41347058507: 19 targets of 60 to 63 minutes each, six at a time, 4h07m of the night). The targets run at the plan's `max_parallel_fuzz`: the shards' figure by window (#791: 14 inside 01:00Z to 09:00Z, 6 outside, the dispatch input over both; a literal 6 until then), six after a tail (#791's fold). Every target runs every night within the budget.

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
