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
of 2026-10-27). Its `ci-full` job dispatches `ci.yml` on `beta` and on `main`,
so each line's whole test matrix and `dependents` run at its tip (a pull
request and a push run only the line's required set). The other measurements
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

The shards are the plan's (cut 7, below): a complete run is twenty, eleven
script, three BEEF, one Merkle, two wire and three substrates, in one wave; a
night is as many as its files' estimated minutes need, at six at a time.
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
| BEEF | `src/transaction/beef*.rs` | `transaction_tests`, `beef_stream`, `beef_limits`, `beef_atomic_graph`, `conformance_beef`, every `tests/beef_stream_603_*.rs` |
| merkle path | `src/transaction/merkle_path.rs` | `transaction_tests`, `merkle_path_lone_leaf`, `conformance_beef` |
| wallet wire | `src/wallet/wire/**/*.rs` | `wallet_tests`, `wire_method_roundtrip_tests`, `wallet_wire_cross_sdk_tests` |
| wallet substrates | `src/wallet/substrates/**/*.rs` | `wallet_tests`, `wallet_http_json_busy_tests` |

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
successful baselines, matching tool versions, matching source commits and
every shard of the plan (`report --plan`; a local replay's `--expected-shards`). Duplicate, missing, corrupt or unfinished evidence fails closed.
The integer comparison avoids accepting a displayed percentage rounded upward.

A file whose generated mutants are all unviable (each replacement refused by
the compiler, so nothing a test can catch) is listed as `NO VIABLE MUTANTS`,
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
| `tests/<name>.rs` in a surface's selection | the measured files its `tests/CLAUDE.md` row names (`## Files` table), within that selection, a test-only file it names counting as the files that file tests; a row naming a module (`src/<m>/`, `` `<m>::` ``), every measured file of the module; no row, or a row naming neither, every file of the surfaces whose selection runs it | a test reaches the files it tests |
| `tests/<name>.rs` deleted | the same, judged by the base: the surfaces whose selection held it at the complete run's sha (the named targets, the `script_*.rs` and `beef_stream_603_*.rs` globs) and its row in that sha's `tests/CLAUDE.md` | the mutants it killed are measured again without it |
| `tests/<name>.rs` in no selection | nothing | it never runs against a mutant, so no score can move |
| a `.rs` file elsewhere under `tests/` (`support/`, `chain_vectors/`, ...) | what the sources that compile it in reach, followed through: a `#[path]` or `include!` string resolving to it, or the `mod` line of its parent module (`mod binary;` in `support/fixtures/mod.rs`); compiled in by none, nothing | a support module reaches a mutant only through the test that includes it; a bare word (`fixtures`, `binary`) in a source is not an inclusion |
| any other file under `tests/` (`vectors/`, `fixtures/`, `support/*.mjs`, ...) | what the compiled sources naming it reach, followed through: its name whole in a source's text (`vectors/sighash.json`, not `tx-sequence-zero-sighash.json`), or its directory's path when that is two or more deep under `tests/` (`fixtures/wire/`, read through `format!("{}/tests/fixtures/wire/{call}.json")`); named by none, nothing | a vector reaches a mutant only through the test that reads it; a recorder (`.mjs`, `.lean`) is never compiled; a one-deep directory (`vectors/`) is every vector's, so it names none |
| a test-only source under `src/` | the files it tests (never their callers) | its tests run against those files' mutants; it compiles into no caller |
| a source under `src/<m>/` that is neither measured nor test-only | every measured file of `src/<m>/`, and (the callee rule, `CALLEE_RULE`, `callers`) every measured file whose text names `<m>` by a `crate::<m>` path or inside a `use crate::{...}` group, one level | the module's code, and the code that calls it |
| `src/lib.rs`, `src/error.rs` | everything | the crate root (the unit-test skips are read from it) and the one `Error` every module returns |
| `Cargo.toml`, `Cargo.lock`, `build.rs`, `.cargo/*` but `mutants.toml` | everything | a dependency, feature, profile or build change reaches every file that uses it |
| `.cargo/mutants.toml` | the files its added or removed `exclude_re` entries name (`^src/...\.rs:`); any other setting, or an entry naming no file, everything | an exclusion moves its file's candidates alone |
| `.github/workflows/nightly.yml`, `.github/scripts/nightly_mutants.py`, `.github/scripts/test-runner-memory-ceiling.sh` | everything | the jobs, toolchain, corpus pin, selection, skips, score and the ceiling that decides a runaway mutant |
| `docs/`, any `.md` | nothing | never compiled |
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
computed at run time). A test of one surface that kills another's mutant
outside its selection (the oracle is `--lib` plus the selection; such a kill is
never counted). The toolchain: the nightly runs the unpinned `stable`, so a
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
# The night (the fleet's slot, 00:00Z): the reach rule's files, the rest carried.
gh workflow run nightly.yml --ref beta
# The complete run: at each prerelease pin (RELEASING.md step 3), before a minor tag, by hand.
gh workflow run nightly.yml --ref beta -f mode=complete
# The captain's Sunday night: the night and the bench.
gh workflow run nightly.yml --ref beta -f weekly=true
```

A complete run is twenty shards in one wave (the keeper's cut 5): the
measured minutes of run 41347058507 (script 130 per 515 mutants, BEEF 37 per
187, Merkle 3 per 25, wire 19.5 per 198, substrates 36.5 per 286; 901
shard-minutes) shared out by the largest remainder, about 47, 50, 11, 39 and
49 minutes per shard, so the wave ends within the hour where the
surfaces-by-four matrix at six took 3h12m. Each shard is one job on its own
runner, one mutation worker, under the same `ulimit -v` of 4,000,000 KB through
the runner hook (above): the ceiling is per test binary, so a narrower shard
changes nothing about it. A night's shards are sized by its files' mutants in
the record at those rates, 45 minutes a shard, at most the complete run's
count per surface, six at a time (the balance rule of 2026-10-26). An empty
plan runs no shard; the score job carries every figure. The bench is the
`weekly` input: the workflow has no schedule, so "weekly" is the dispatcher's
word, and the job dispatches `bench.yml` at the line's tip.

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

**What runs.** One job per target of `fuzz/Cargo.toml` (19 today, pinned to the matrix by `tests/arch_fuzz_targets_dispatched.rs`; the table is in `fuzz/fuzz_targets/CLAUDE.md`), each built with `cargo fuzz build -O` on the pinned nightly (AddressSanitizer, but `-s none` for `fuzz_script_spend_default`, whose 128 MiB budget ASan's resident set takes past the 2,048 MB RSS limit, #398) (`FUZZ_TOOLCHAIN`, `cargo-fuzz` by version) and run for a fixed budget from its checked-in corpus `fuzz/corpus/<target>/` (`-fork=2 -ignore_crashes=1 -max_total_time=$((FUZZ_MINUTES * 60))`): a crash is recorded and the run goes on. The budget is `FUZZ_MINUTES`, 10 minutes per target by default, set by the repository variable `NIGHTLY_FUZZ_MINUTES` (at most 30, under the job's 45-minute timeout); until cut 7 it was an hour (run 41347058507: 19 targets of 60 to 63 minutes each, six at a time, 4h07m of the night). Every target runs every night within the budget.

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
