# The complete run's record of 2026-11-04 (#602, #705)

Branch `lane/record-complete-1104` from `origin/beta` at `4ed58d05`. The keeper's
word of 2026-11-03 17:1xZ and the owner's bound rule of 2026-11-04: the record's
docs pass for the complete run 41753882105 (`-f mode=complete`, pinned
`2ff81a44`): `docs/census/mutants-2026-11-04`, the floors raised where the run
allows, the survivors per file, #705's figures. No crate code moves; no
`cargo mutants` (the run already ran them).

## The artifacts

`python3 .github/scripts/mutants_record.py fetch --run 41753882105 --dest
/Volumes/Lanes/out/bsv-rs/record-complete-1104/complete`: 26 artifacts, the 23
`mutants-<surface>-<k>-<n>`, `mutation-summary`, `mutation-record` (the merged
record and its `Cargo.lock`) and `mutation-plan` (the plan and its lockfile),
all unexpired; `fetch` saves the jobs' listing beside them (`jobs.json`). The run
was created 2026-11-04T01:24:50Z (the API's `created_at` and `run_started_at`);
the pin job ran 01:24:54Z to 01:27:04Z; the last shard (substrates 7/8) ended
14:59:33Z and the score job 14:59:46Z, 13h35m for the mutation part. The run's
status when read was `queued`: the fuzz jobs and the full-matrix dispatches run
after the score job and are not this record's. Every shard's outcome read through
`nightly_mutants.collect` against the plan's 23 shards: complete, one commit,
every baseline green.

## The record

`write --widened <dir>/complete --previous docs/census/mutants-2026-11-01.json
--out docs/census/mutants-2026-11-04`. The script's `write` took a narrow and a
widened run; a complete run is one run, so `--previous` (the prior record's
`.json`) is the alternative to `--narrow` and selects `write_complete`: the
delta column against the previous record's widened figure, the survivors of every
measured file (the gate paths in #603's order, then the files elsewhere by score
ascending: 332, as the prior record listed its 548), the shard table and the
survivor term. `measure` reads the shards from the plan when the run has one (a
run before cut 7 keeps its four a surface) and leaves out a test-only file the
plan does not list, as the score job's `merge` does. The two-run path is
unchanged. A test pins the survivor term's sums, measured and by the rate.

The counts: 85 files; 80 PASS, 0 FAIL, 5 NO MUTANTS under the floors at
`2ff81a44`; 80 PASS, 0 FAIL, 4 NO MUTANTS, 1 NO VIABLE MUTANTS under the raised
floors; 72 PASS, 8 FAIL at 80 everywhere. Survivors 332 (152 on the gate paths),
where the 11-01 widened run left 1,583 (548). Four files are new since that
record (`script_asm.rs`, `spend/key_point.rs` among them); its eleven test-only
NO MUTANTS rows are not listed since cut 7.

## The floors

`floors --run <dir>/complete --write` raises only, to the score rounded down (the
script's rule; no margin): 27 of 29 entries raised, `wire/diagnostics.rs` (0) and
`wire/processor.rs` (60) held at their figure, none added. Held on the tip: no
floored file's source changed in `2ff81a44..4ed58d05` (the wallet change there
is `substrates/byte_fields.rs`, unfloored, a visibility word); the night's plan
at `4ed58d05` against the run's record re-measures all 85 files, and each
surface's targets at the tip hold every target the run's shards ran (script 155
over 144, BEEF and Merkle 123 over 110, wire and substrates 145 over 134), so no
kill the floors count is lost by the selection. `tools/ratchet/run --check
--against 4ed58d05`: all seven counters, the oversized-file limits and the
mutation floors pass.

## The survivor term (#705)

Measured by each mutant's phases (`phase_results` durations in
`outcomes.json`), the 332 survivors took 778.9 minutes and the 4,136 kills
3,495.7 of 4,369.0 (17.8 percent survivors; 2.35 minutes a survivor, 0.85 a
kill). By surface, survivors' share of the minutes: script 16.7 percent, BEEF
4.8, Merkle 4.1, wire 9.7, substrates 24.9. By the rate (count times the shard's
minutes a mutant) the survivors are 370.3 minutes: a survivor costs 2.8 times a
kill, so the rate halves their share. #705's premise (the survivors dominate)
reads otherwise at this run: the kills carry it, and stage one of the row saves
only what it shortens of a kill.

## Docs

`docs/NIGHTLY.md`: the 903 line names its run and the complete run's 4,438; "The
floors (#602)" carries the complete run's scoreboard and the floors moved; "The
measured complete run" after the checkpoint paragraph carries the wall clock, the
rates per surface against the slope and the two-part estimates, and the survivor
term. `CHANGELOG.md` `[Unreleased]`: `### Added:` the record.

## The checkpoint (the rule read's fold)

The checkpoint ran under the keeper's bound rule of 2026-11-04, carried on the
captain's pending list in place of the twelve-hour cancel: at 12:00Z the
shards' mean rate projected the end before 15:00Z, the bound was set at the
longest measured end plus thirty minutes, and the run was not cancelled; the
shards ended 14:59:33Z, inside it. No artifact carries it, so `write` takes it
as `--checkpoint` and the record's producing run states it. The same fold
corrects the producing run's "Shards ended" cell (it printed the score job's
14:59:46Z; now the last shard's 14:59:33Z) and writes the survivor term's rows
in the plan's surface order, so the `.md` is rewritten from the `.json` alone.

## Unverified

The checkpoint's projected figure (the rule is stated above; the projection's
number is not in the artifacts). The brief's
dispatch time 01:24:56Z differs from the API's 01:24:50Z; the record carries the
API's.
