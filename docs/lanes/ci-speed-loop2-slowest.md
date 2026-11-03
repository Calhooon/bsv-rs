# CI speed, loop two: the ten slowest tests (#670)

The speed line's loop two (measure, cut, measure, record), opening from loop
one's recorded figures (`docs/lanes/ci-speed-1.md`: the Suite 15m26s on a
cache hit, test-bound; the memory step 4m39s to 6m03s with one test at 5m36s,
the integration step 5m08s to 6m24s). This row: the ten slowest tests by
name. Base: `origin/beta` at `541b672d`. Tests and their docs only: no
source behaviour, no workflow line.

## The measurement

nextest's `PASS [ <seconds>s ]` lines in the Test Suite job's log of runs
41558273855 (job 125662398909), 41560881228 (125671367991) and 41563214016
(125678456154), read with `gh run view <run> --job <job> --log`; the ten
slowest by the median of the three.

| # | Binary | Test | Run 1 | Run 2 | Run 3 | Median |
| ---: | --- | --- | ---: | ---: | ---: | ---: |
| 1 | `memory_profiling` | `test_http_json_success_tx_in_the_array_form_costs_the_typed_reading` | 338.80 | 259.96 | 341.44 | 338.80 |
| 2 | `beef_two_readers_agree` | `the_whole_path_and_the_stream_agree_on_every_beef_the_tree_holds` | 70.42 | 54.39 | 74.15 | 70.42 |
| 3 | `merkle_path_two_readers_agree` | `the_standalone_reader_and_the_beef_reader_agree_on_every_bump_the_tree_holds` | 69.04 | 53.58 | 68.22 | 68.22 |
| 4 | lib | `transaction::merkle_path::linear_root_equivalence_tests::the_parse_matches_the_rescan_except_the_ruled_lone_leaf` | 60.63 | 48.44 | 59.06 | 59.06 |
| 5 | lib | `...::the_root_check_matches_the_rescan_except_the_ruled_lone_leaf` | 61.31 | 44.85 | 56.02 | 56.02 |
| 6 | `memory_profiling` | `test_beef_stream_memory_is_flat_per_element` | 53.91 | 39.61 | 54.23 | 53.91 |
| 7 | lib | `...::compute_root_matches_the_rescan_except_the_ruled_lone_leaf` | 49.26 | 40.84 | 50.09 | 49.26 |
| 8 | `merkle_path_cost` | `a_compound_bump_from_a_block_parses_in_under_the_bound` | 46.98 | 36.93 | 45.55 | 45.55 |
| 9 | `beef_deep_chain` | `a_deep_chain_round_trips_through_to_beef_on_a_small_stack` | 33.12 | 26.74 | 35.69 | 33.12 |
| 10 | `transport_fault_auth` | `a_timeout_after_the_request_was_written_may_have_been_received` | 30.08 | 30.06 | 30.09 | 30.08 |
| | | **The ten** | **813.5** | **635.4** | **814.5** | **804.4** |

Against the job: the test-seconds of every `PASS` line summed (unit,
integration, memory, tracing) were 1,779, 1,396 and 1,793; the five test
steps' walls 15m49s, 12m33s and 15m10s. The ten are 45% of the test-seconds in each run.
Two readings the table does not show: the memory step runs its 13 tests side
by side, so test 1 is that step's wall (363 s, 279 s, 367 s); and the three
lib tests (4, 5, 7) run twice, once in the unit step and again in the
integration step, whose `--tests` includes the lib target (loop one's note;
unchanged here, a cut for loop three). The 11th, at 30.05 s,
`auth_peer_nonces_362_364::general_message_validation_timeout_uses_reference_words_364`,
is a Peer's own 30-second timeout and is not in this row.

## The cuts

None took (b): no one of the ten is in the nightly's mutation selection
(`docs/NIGHTLY.md`: the Merkle surface omits the three `linear_root`
tests, the loop omits `merkle_path_cost` and `beef_deep_chain`, and the two
readers' files and `memory_profiling` are no surface's), so an `#[ignore]`
would have been a test no job runs. None took (c): the time is in reading
the inputs, not in making them (the deep chain's set-up is the exception,
and a 25,000-link fixture would be megabytes in the tree). All ten took (a).

| # | Cut | Why the strength holds | RED (a scratch copy, its own target) |
| ---: | --- | --- | --- |
| 1 | The answer's `tx` 128 KiB (`TX_PUSH`), not 1 MiB | The bound is a ratio, the peak under 4 times the text: 2.25 at 1 MiB, 2.86 at 128 KiB | The typed reading skipped (`answer.rs`): 13,169,752 B against the bound 1,874,768 B (28 times the text) |
| 2 | The sweep skips bytes 2 to 30 of each 32-byte hash of a well-formed BEEF (`tests/support/hash_interiors.rs`): 149,285 inputs, 203,707 before | A hash is read whole by both readers (hashed, compared, ordered by its leading bytes); bytes 0, 1 and 31 and every other byte still swept | `verify_structure`'s `index >= self.bumps.len()` to `>`: 1,173 disagreements (`whole TxidNotInBump`, `stream BumpIndexNamesNoBump`) |
| 3 | The same mask on a well-formed BUMP: 23,838 inputs, 59,811 before | As 2: a BUMP is mostly hashes | The standalone reader's truncation offset moved by one: `left: ... at byte 6`, `right: ... at byte 5` |
| 4, 5, 7 | Compound blocks of at most 32 leaves in two of `random_path`'s three block arms, not 80 and 64; the third keeps 80 (the #676 fold, the strength read's), so partial blocks of 33 to 80 leaves are still drawn; rounds unchanged | Blocks of 33 to 80 leaves took two thirds of the seconds; heights above a block's own still reach 64 through the other shapes; "both sides exercised" thresholds still met (accepted 1,753, refused 1,247; answered 9,550, erred 3,389; parsed 583) | cargo-mutants below: the same 18 caught before and after |
| 6 | 1,000, 4,000 and 16,000 links (the #676 fold; 1,000, 3,000 and 10,000 in #670), not 1,000, 10,000 and 100,000 | The index's table doubles, so the peak is a step of the depth; at 1,000 times a power of two each depth sits at the same point of the step, 351 B per element at all three (3,000 and 10,000 read 234 and 281, 100,000 read 225: the step's slack, not a fixed overhead). The bounds are per element (under 400 B) and flat (within 1.25 over sixteen times the depth), and the marginal cost per element from 4,000 to 16,000 is within 1.25 of that from 1,000 to 4,000 (the strength read's check; on 1,000, 3,000 and 10,000 it fails on the tip, 175.6 then 301.1 B, the step again). A quadratic term c times n squared (counted at the read's end) passes the 400 B bound at 16,000 up to c of about 0.0031 and the marginal check up to about 0.0064, against 0.0119 and 0.0158 at 10,000 in #670 and 0.00175 and 0.0021 at 100,000 before it. The scripts' extra under 16 KiB in all reaches a leak of 1 B per element (0.16 B at 100,000) | `spend_output` keeping a spent output: `N=1000: the scripts kept 22874 B more than the structure`; a per-link allocation of 0.016 B per index entry planted in `BeefIndex`: `N=16000: 469.95325 B per element`, where #670's depths passed it (334.9 B at 10,000); at 0.04 B with the per-element bounds disabled, `structure: the marginal bytes per element grew with the depth: 447.5 from 1,000 to 4,000, then 688.3 to 16,000` |
| 8 | The compound BUMP's root asked of nine txids spread over the block, the last included, not of every 97th (85) | The parse, the bound under test, is unchanged (0.09 s of the test); each `compute_root` on 8,192 leaves is 0.13 s in a debug build | `compute_root` walking from `index & !1`: the root differs at the sampled odd index |
| 9 | 25,000 links on a 256 KiB stack, not 100,000 on 1 MiB | The same links per byte of stack: a walk that recurses per link needs any frame over 10 bytes to overflow either | A one-frame-per-link recursion planted in `to_beef`: `thread 'to_beef' has overflowed its stack`, SIGABRT |
| 10 | A client of a 1 s timeout through `with_client`, the answer delayed 5 s, not the transport's own 30 s client delayed 40 s | The class is `delivery`'s reading of the error, not the clock's | `delivery` reading a timeout as `NeverSent`: `left: NeverSent, right: MayHaveBeenReceived` |

GREEN: every one of the ten passes on the tip (the gate below). The 30 s of
`SimplifiedFetchTransport::new`'s client, which the old test pinned only as
under 40 s and #670 left to no test, is pinned by the #676 fold without the
wait: `REQUEST_TIMEOUT` in `src/auth/transports/http/client.rs`, which
`default_client` builds with through the `default_client_with(timeout)` seam,
and the file's unit tests (the constant; the default's `Debug` that of the
seam at the constant and not `Client::new()`'s, reqwest having no getter and
naming the field by `type_name`; the seam's 1 s timeout ending a request
answered after 5 s).

### The kills kept

The three `linear_root` tests guard the linear root walk against its 0.3.34
form. Against `src/transaction/merkle_path.rs`, the tests alone
(`-- --lib -- linear_root_equivalence_tests`), on `541b672d` and on the tip:

```
cargo mutants --jobs 1 --baseline skip --timeout 300 --all-features --file src/transaction/merkle_path.rs --re 'find_or_compute_once' -- --lib -- linear_root_equivalence_tests
  base: 8 mutants tested in 3m: 1 missed, 6 caught, 1 unviable
  tip:  8 mutants tested in 3m: 1 missed, 6 caught, 1 unviable
cargo mutants ... --re 'root_from' ...
  base: 16 mutants tested in 9m: 4 missed, 12 caught
  tip:  16 mutants tested in 8m: 4 missed, 12 caught
  fold (#676, the 80-leaf arm back): 8 in 4m, 1 missed, 6 caught, 1 unviable;
        root_from by --shard 0/2 and 1/2, 1 missed 7 caught, 3 missed 5 caught
```

The same mutants missed on both: `584:13` (the `shared` field, listed by both
regexes), `652:27` (twice) and `652:33`, the four declared equivalent on
three reads in #628, missed before this row as after it (`.cargo/mutants.toml`
excludes them by regexes eight lines stale on `541b672d`, `660:` and
`592:13`: a separate fix, the pins read's finding beyond this row). The memory tests pin peaks, not mutants:
their bounds stay asserted, scaled where a size is in them (row 6's 16 KiB).

## The seconds after

This host (the Studio, `CARGO_INCREMENTAL=0`, debuginfo 0 as in the job,
`export CARGO_BUILD_JOBS=4`), each test alone, before on `541b672d`'s tests
and after on the tip. The runner's figure after is the host's after times the
test's own ratio before (runner median over host before): the integration
step's tests run under contention on the runner (ratio about 4 to 6), the
memory step's side by side under dhat (0.75 and 1.15), the timeout idle (1.0).

| # | Host before | Host after | Runner/host | Runner before | Runner after (estimated) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 451.46 | 55.14 | 0.75 | 338.80 | 41 |
| 2 | 12.09 | 8.44 | 5.82 | 70.42 | 49 |
| 3 | 14.47 | 2.50 | 4.71 | 68.22 | 12 |
| 4 | 13.88 | 5.03 | 4.25 | 59.06 | 21 |
| 5 | 14.05 | 5.02 | 3.99 | 56.02 | 20 |
| 6 | 46.94 | 6.26 | 1.15 | 53.91 | 7 |
| 7 | 12.04 | 4.67 | 4.09 | 49.26 | 19 |
| 8 | 10.25 | 1.67 | 4.44 | 45.55 | 7 |
| 9 | 6.84 | 2.06 | 4.84 | 33.12 | 10 |
| 10 | 30.02 | 1.02 | 1.00 | 30.08 | 1 |
| | **612.04** | **91.81** | | **804.44** | **about 188** |

The #676 fold gives some of it back, on this host each test alone: rows 4, 5
and 7 at 9.35, 9.73 and 8.90 s with the 80-leaf arm (5.03, 5.02 and 4.67
without it), row 6 at 9.26 s at 16,000 links (6.26 at 10,000): about 108 s
for the ten, the runner's estimate about 246 s by the same ratios.

## The five figures

| Figure | Before | After |
| --- | --- | --- |
| A PR's CI wall clock | 20m05s (cold) | 9m36s, the landing run 41587646252 (whole): the Test Suite 9m10s (unit 1m09s, integration 5m40s, memory 1m06s, tracing 25s, doc 35s), against 15m26s on a cache hit before |
| The queue wait | four to nine minutes | 25s to the Test Suite (run 41587646252) |
| The nightly | 10h43m (until #666 lands) | unchanged by this cut (#666's figure: 2h28m06s, run 41579707627, `docs/lanes/ci-speed-2.md`) |
| A cold read | 16m49s | unchanged by this cut (about 16 minutes; reads without cargo 3 to 7 minutes) |
| The landing latency, lane DONE to landed | five landings: 113, 124, 181, 186 and 219 minutes (#665 the 113, #659 the 219) | 39 minutes for this PR (#676; the captain's count, 2026-11-03 morning, from the fold: the pull request opened 03:39:28Z and merged 06:15:19Z, 155m51s, `docs/lanes/ci-speed-2.md`) |

The Suite after this cut is 9m10s on the whole suite and 7m40s on a one-module
subset (#684's run 41598630196, `docs/lanes/ci-speed-4.md`): the whole suite still
sits above the eight-minute line, the subset below it; the shard by step is loop
two's to decide on those figures.

## Logs

`/Volumes/Lanes/out/bsv-rs/ci-speed-loop2-slowest/`: the three runs' logs, the
`PASS` tables, the host timings before and after, the RED outputs and the
cargo-mutants output directories.
