# ci-speed-7: the nightly incremental (speed round 1, cut 7)

The keeper's speed line, cut 7, on the owner's word of 2026-11-02 23:3xZ:
"even the nightly... is all that necessary? or maybe a fraction". Base
`84a01d2a` (beta's tip; the worktree opened at `efe12e63`, main's, and was
reset to `origin/beta`). The rule, the record's shape and the dispatch lines
are in `docs/NIGHTLY.md`, "Incremental nights and the complete run (cut 7)".

## The measurement

Run 41347058507, read from the API on 2026-11-02 (`gh api
repos/Calhooon/bsv-rs/actions/runs/41347058507/jobs`, the steps' `started_at`
and `completed_at`; the counts from the shards' `mutants-*` artifacts,
unexpired). Dispatched 2026-11-01 20:28:54Z at `9640eaa7`, measured `42a74f1b`
(#629's finding). Created to last job 07:11:59Z: 10h43m. Queued until
23:52:16Z (3h23m, the concurrency group), running 7h19m: the mutation shards
23:52Z to 03:04Z (3h12m at six at a time), the score job 03:04Z, the fuzz
targets 03:04Z to 07:11Z (4h07m, four waves of six).

Every shard's baseline succeeded (exit codes 2 and 3, misses and timeouts);
the score job failed on eleven gate-path files below 80
(`locking_script.rs`, `not_judged.rs`, `script.rs`, `p2pk.rs`, `pushdrop.rs`,
`transaction.rs`, `unlocking_script.rs`, `beef.rs`, `beef_stream.rs`,
`beef_tx.rs`, `merkle_path.rs`), #603's list. The brief's "failed at the
baseline" is not what the API shows for this run.

| Surface | Files | Mutants generated | Caught | Missed | Timeout | Unviable | Shard minutes (the scoped step, four shards) | Job minutes (max) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| script | 48 | 2,059 | 1,656 | 302 | 7 | 94 | 133.1, 124.8, 129.6, 129.3 (516.8) | 136.2 |
| BEEF | 3 | 748 | 512 | 172 | 3 | 61 | 36.2, 40.1, 33.3, 38.6 (148.2) | 43.3 |
| Merkle | 1 | 101 | 64 | 25 | 0 | 12 | 3.2, 2.5, 3.0, 3.1 (11.8) | 6.2 |
| wire | 16 | 793 | 470 | 168 | 0 | 155 | 20.9, 20.9, 18.6, 17.5 (77.9) | 23.9 |
| substrates | 25 | 1,142 | 167 | 863 | 4 | 108 | 37.8, 32.6, 35.3, 40.8 (146.5) | 43.8 |
| all | 93 | 4,843 | | | | | 901.2 | |

The fuzz targets: nineteen, 60.1 to 63.2 minutes in the fuzz step, 60.9 to
66.8 minutes a job (the build about four).

## The rule

A file's mutation score moves only when the file or the tests that reach it
change: a night mutates the files the reach rule names since the last
complete run and carries every other figure from the record with its run's
id and sha. The table is in `docs/NIGHTLY.md`. Where it departs from the
brief's literal words, and why:

- `tests/support/` and `tests/vectors/`: the brief re-measured everything on
  any change there. Eight of beta's last ten commits touch one (each #603 and
  #6xx landing adds a recorder `.mjs` or `.lean` and a vector), so the literal
  rule makes nearly every night complete. The plan follows such a file to the
  compiled sources that name it (a test file, a support module by its `mod`
  name, a unit-test source under `src/`) and re-measures what they reach; a
  file nothing compiled names reaches nothing.
- `.cargo/mutants.toml`: the brief re-measured everything. An `exclude_re`
  entry is anchored on its file (`^src/...\.rs:line:col: ...`), so an added or
  removed entry re-measures that file; any other setting, or an entry that
  names no file, still re-measures everything.
- A test no surface's selection runs re-measures nothing: it never meets a
  mutant.
- `src/lib.rs`, `src/error.rs`, `build.rs` and `.cargo/*` re-measure
  everything (the brief named the manifest, the lock and the nightly's files;
  these are the crate root, the unit-test skips' source, and the build).
- The library commits no `Cargo.lock`: a night builds the complete run's own
  lockfile, kept in the record (its sha256 checked), so an upstream release
  cannot move a carried figure's oracle unseen; a `Cargo.toml` change makes
  the night complete with a fresh resolution.

## The plan on the real tree

`plan --commit 84a01d2a...` against a record built from run 41347058507's
artifacts with its complete-run commit set to the named base (the hand run's
stand-in: no `mutation-record` exists before this lands; the record's 93
files are `42a74f1b`'s, two measured files are newer and would be in a real
night's diff).

`ffff16d0..84a01d2a` (one commit, the #603 S4 landing):

```text
mode incremental; 4 files measured tonight, 91 carried
beef: src/transaction/beef.rs, src/transaction/beef_stream.rs, src/transaction/beef_tx.rs
merkle: src/transaction/merkle_path.rs
matrix: beef 0/3, 1/3, 2/3; merkle 0/1 (4 shards, six at a time)
.cargo/mutants.toml -> beef_stream.rs (the exclusions added or removed name these files)
src/transaction/beef_stream.rs -> itself (a measured file)
src/transaction/beef_stream/reason.rs -> the four transaction files (a source of src/transaction/)
tests/beef_stream_603_s4.rs -> beef_stream.rs (its tests/CLAUDE.md row, within the beef selection)
tests/support/beef_reference_603.mjs -> the four (named by tests/beef_stream_603_s2.rs, tests/beef_stream_603_s4.rs, src/transaction/beef/reference_603_tests.rs)
tests/vectors/beef_reference_603.json -> the four (the same three)
CHANGELOG.md, docs/NIGHTLY.md, src/transaction/CLAUDE.md, tests/CLAUDE.md -> nothing (documentation)
```

`9eba10a8..84a01d2a` (the last ten): `mode complete`, why
`.github/scripts/nightly_mutants.py changed: the selection, the skips and the
score`; twenty shards, twenty at a time.

## The expected night

Beta's last ten commits (2026-11-02 06:51 to 18:22 local, one day's
landings), each planned alone against its parent:

| Commit | Plans |
| --- | --- |
| `84a01d2a` beef-stream S4 | 4 files (BEEF and Merkle) |
| `ffff16d0` the pin (#629) | everything (the nightly's script) |
| `e49cf55d` merkle-path #649 | 4 files |
| `a7555589` script A | 50 files (the script surface: `tests/script_script_603_a.rs`'s row names no file) |
| `3fd977be` HANDOFF | nothing |
| `b9f78224` merkle-path #641 | 4 files |
| `7b44110e` filings | nothing |
| `2ec03225` beef-stream S3 | 3 files |
| `51fa67ac` beef-stream S2 | everything (the nightly's script) |
| `1147ea71` script C | 3 files |

Under the literal rule eight of the ten re-measure everything; under this one
two (both the nightly's own script). The day's union without those two is 54
files: the script surface's 50 and the four transaction files, 15 shards (11
script, 3 BEEF, 1 Merkle) at six at a time, about 2h30m of shards, then the
fuzz at ten minutes a target (four waves of about 14 minutes, about 56
minutes): about 3h30m running. A day of BEEF and Merkle landings alone: four
shards, about 55 minutes, then the fuzz: about 1h55m. A day of documentation:
no shard, the fuzz alone, about an hour. A row in `tests/CLAUDE.md` that names
its file (`script_script_603_a.rs`'s names none) is what keeps a script test's
night to its file.

## PR #666's fold: the five holes

The three reads (cold, reach, workflow) found five ways a change that should
re-measure files planned too little; the fold closes each with a
`test_fold_*` case in `test_nightly_mutants.py` (61 tests; on `cc50c557`'s
script the five fail, and the fixture's `beef_only.json` case, which now
reaches `beef.rs` alone through the test-only source that reads it). The rules
are `docs/NIGHTLY.md`'s table. The plans below ran `plan` from the fold's
script on a clone at `84a01d2a`, against a record built from run
41347058507's `mutation-summary` with its complete-run commit set to the base
named (the stand-in, as above); the measured files are now 82 (script 40,
BEEF 3, Merkle 1, wire 15, substrates 23), the thirteen test-only modules out.

`ffff16d0..84a01d2a`: 9 files, 5 shards, 73 carried (`beef.rs`,
`beef_stream.rs`, `beef_tx.rs`, `merkle_path.rs`, and the five substrates
files that call `crate::transaction`: `http_json.rs`, `http_json/answer.rs`,
`http_json/review_actions.rs`, `http_wire.rs`, `result_values/beef.rs`,
reached by `src/transaction/beef_stream/reason.rs`). The vector
`beef_reference_603.json` and its recorder now reach `beef.rs` and
`beef_stream.rs` (the S2 and S4 rows, and the test-only
`beef/reference_603_tests.rs`'s parent), not the four.

The cold read's three probes, each one commit on `84a01d2a`:

| Probe | cut 7 | the fold | the second fold (`callee_added`) |
| --- | --- | --- | --- |
| `git rm tests/script_script_603_a.rs` | nothing | 40 files, 11 shards (the base's script selection; its base row names no file) | 40/11 (0) |
| `tests/fixtures/wire/createAction.json` | nothing | 15 files, 2 shards (`wallet_wire_cross_sdk_tests` names `fixtures/wire/`) | 15/2 (0) |
| `src/primitives/hash.rs` | nothing | 39 files, 16 shards (script 25, wire 6, substrates 4, BEEF 3, Merkle 1) | 39/16 (39) |
| `src/transaction/beef.rs` (measured) | 1/1 | 1/1 | 7/2 (6: `beef_tx.rs` and the five substrates callers) |
| `src/script/spend/flow.rs` (measured) | 1/1 | 1/1 | 29/10 (28: 25 script, 3 BEEF) |

What the reads' other cases reach now: `tests/support/fixtures/*` (each of
seven) the wire's 15, through the fourteen tests whose `#[path]` includes
`support/fixtures/mod.rs` (one, `wallet_wire_cross_sdk_tests`, in a
selection); `tests/vectors/sighash.json` 55 (the script's 40 through
`sighash_tests`, the wire's 15 through `support/fixtures/binary.rs`);
`script_script_603_c.rs` the 15 measured files of `src/script/` (its row
names `script_length_603_tests.rs`), `script_arithmetic_result_bound_374.rs`
the 16 of `src/script/spend/`, `script_pushdrop_key_bytes_545.rs` the 9 of
`src/script/templates/`.

Beta's last ten, each against its parent (files/shards):

| Commit | cut 7 | the fold | the second fold (`callee_added`) |
| --- | --- | --- | --- |
| `84a01d2a` beef-stream S4 | 4/4 | 9/5 | 9/5 (5) |
| `ffff16d0` the pin (#629) | all | all | all (0) |
| `e49cf55d` merkle-path #649 | 4/4 | 9/5 | 9/5 (5) |
| `a7555589` script A | 50/11 | 40/11 | 43/14 (3) |
| `3fd977be` HANDOFF | 0/0 | 0/0 | 0/0 (0) |
| `b9f78224` merkle-path #641 | 4/4 | 9/5 | 9/5 (5) |
| `7b44110e` filings | 0/0 | 0/0 | 0/0 (0) |
| `2ec03225` beef-stream S3 | 3/3 | 3/3 | 3/3 (0) |
| `51fa67ac` beef-stream S2 | all | all | all (0) |
| `1147ea71` script C | 3/3 | 15/5 | 40/14 (25) |

29 shards over the eight incremental nights before, 34 after the fold, 46
after the second fold. The callee
rule's frequency on `origin/beta` (2026-10-03 to 2026-11-02): 25 of 1,033
commits changed `src/primitives/` (12 of the 25 days with a commit; 2 of the
last 50 commits); 36 changed `primitives` or `block`; 9 changed nothing
compiled but those. A night with a `primitives` change is 16 of the complete
run's 20 shards.

## PR #666's second fold: the count per night, the rule's letter

The re-read's FIX: the keeper's word ("the record names per night how many
files the cure added") was met only inside each path's reason text. Now the
plan's JSON carries `callee_rule` and `callee_added` (the sorted names of the
files the callee rule reached that no other rule did: `reach` run again with
`callee=False`, the difference; a complete run's is empty), the record's
`runs[]` entry `callee_added` (the count) beside its `run_id` and `commit`,
and the scoreboard's header `callee_line`: "The callee rule added N files
tonight (<mode>): <names>", "(complete: every file measured)" on a complete
run, "The callee rule is off (`CALLEE_RULE`)" when it is.

The rule's letter ("a changed module re-measures every measured file that
names it"): the fold applied `callers` to a changed unmeasured source only;
it now applies to every changed source under `src/<m>/`, measured or not, a
test-only source excepted (it compiles into no caller), still behind
`CALLEE_RULE` and counted in `callee_added`. Same-module callers count: a
measured `src/script/` file reaches the 22 other script files that name
`crate::script` and the three BEEF files that do. What moved (the tables
above, replayed with the same stand-in record from run 41347058507's
`mutation-summary` on a clone at `84a01d2a`, the fold's script and this one
side by side): `script-a` 40/11 to 43/14 and `script-c` 15/5 to 40/14 (both
change measured script files), the two measured probes 1/1 to 7/2 and
29/10; the BEEF and Merkle landings are unchanged (they also change the
unmeasured `beef_stream/reason.rs`, which already reached the five
substrates callers), and so are the three probes.

Tests (`test_fold2_*`, three): a changed measured file reaches the measured
files naming its module, a test-only one does not, the switch off restores
cut 7's; the plan counts the rule's files on a night where it adds one, on
one where another path reaches the same file (0), on one where it adds none,
and on a complete run; the record's run entry and the scoreboard's line.
RED on the fold's script (two `KeyError`s on the count, one missing caller),
GREEN with this one: 64 of 64.

## The four figures of the standing rule

| Figure | Before | After |
| --- | --- | --- |
| PR wall clock | 29m11s | unchanged by this cut (ci.yml is `ci-speed-1` and `ci-speed-2`'s) |
| Queue wait | 3m10s | unchanged by this cut |
| The nightly | 10h43m (run 41347058507, 7h19m running) | (from the first incremental run) |
| A cold read | 16m49s | unchanged by this cut |

The dispatch that follows the landing is complete by the rule (the
nightly's workflow and script changed, and no record exists): `gh workflow run
nightly.yml --ref beta -f mode=complete`. The incremental nights begin with
the one after it.
