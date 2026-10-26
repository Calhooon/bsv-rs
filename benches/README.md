# Benchmark measurements and gate

The five added benches use Criterion, as do the four existing ones. None judges
an interpreter verdict. A refusal is timed and black-boxed; conformance belongs
to the sibling evaluator and this crate's witness tests.

| bench | one timed operation |
|---|---|
| `beef_stream` | Read an entire 1,000,000-byte or 10,000,000-byte BEEF from a file, with script checks or with `verify_stream_structure` |
| `merkle_path` | Compute and check 10,000 distinct depth-20 paths against one synthetic block root |
| `transaction_sign_verify` | `Transaction::sign` or `Transaction::verify` for all 100 P2PKH inputs |
| `wire_codec` | Encode or decode the recorded request or successful result frame of one wallet call (#76's `full` case), including the envelope |
| `script_spend` | Visit every seed row's inputs in corpus order through `Spend::validate` under the block word |

Build output and measurements must be outside this checkout:

```sh
export CARGO_TARGET_DIR=/Volumes/Lanes/targets/bsv-rs-oracle-benches
export BSV_BENCH_ARTIFACT_DIR=/Volumes/Lanes/out/bsv-rs/oracle-benches/runs
export BSV_SCRIPT_CORPUS=/path/to/bsv-script-lean/corpus/seed
cargo generate-lockfile   # this library does not commit Cargo.lock
cargo run --locked --manifest-path tools/bench-compare/Cargo.toml
```

The tool runs `cargo bench --locked`, so the root lockfile must exist; CI
resolves it in the job, as the `deny` job does. The tool's own lockfile is
committed (`tools/bench-compare/Cargo.lock`).

On a host without `/Volumes/Lanes`, select an external target and artifact
directory under that host's `$TMPDIR`. `--output DIR` names a fresh directory;
reusing one is refused. `--from-run DIR/run.json` compares saved evidence
without measuring or recording. It uses the saved platform and hardware.

## Percentiles

The tool uses 100 Criterion samples, a 1-second warm-up and a 3-second requested
measurement interval per benchmark, with `--features wallet`. Slow workloads
can exceed that requested interval to obtain all samples. For each sample it
divides `times` (nanoseconds) by `iters`, sorts those normalized times and takes
the linearly interpolated 50th and 99th percentiles. These are **percentiles of
Criterion sample averages**, not a distribution of individual request latencies.
For the script, proof and signing batches the unit is the entire batch. Original
`sample.json` files remain in the run's `criterion` directory for inspection.

An increase strictly greater than 5% in any sample p99 exits 1. Setup errors,
missing/invalid samples, absent corpus, changed benchmark inventory, a changed
corpus digest, or a different CPU model/core count exit 2. A platform, CPU
model and core count with no baseline entry exits 3 and prints
`NO BASELINE ENTRY: <key>`. A run must include
all four codec operations for all 28 calls and all added workloads. No result
can pass merely because a benchmark stopped being registered. The machine
line contains only the CPU model and available logical core count. The run
also records its platform, Rust version, source commit and sampling settings.

`run.json` contains every p50/p99 in nanoseconds and the RSS observations;
`baseline.json` is the same run alone in the baseline's shape (the scoreboard
job reads it from the artifact; it is never written over `benches/baseline.json`);
`bench.log` contains the benchmark output. CI retains them even when a p99
regression fails the job. The console prints the complete comparison table.

## Workload scope

The BEEF writer builds a chain of approximately 1 KB transactions with one
proof, a push-only padding unlock and an `OP_DROP OP_TRUE` lock. The final
transaction is adjusted to the exact byte count. Each file is serialized by
`Beef::to_binary`, then read through a 64 KiB buffer. File open, reads, decoding,
indexing and verification are timed; fixture generation is excluded. The file
is read repeatedly and is normally in the operating system's page cache.

RSS uses `memory_stats::memory_stats().physical_mem`, the same API as
`memory_bench`. Each size/mode is measured in a fresh child process without
the writer's allocations or a resident BEEF byte vector. A sampler observes
RSS every 100 microseconds and at completion while the index is still alive.
The JSON records starting RSS, sampled high water, their difference, byte
count, wall time and index entry count. Sampling can miss shorter transient
allocations; it is not an allocator-level peak. The memory slope is
`(peak_10_MB - peak_1_MB) / 9_000_000` bytes of RSS per byte of BEEF, separately
for each mode. The ancestry index grows with transaction count; this workload
measures that growth rather than assuming constant memory.

The proof fixture has 2^20 distinct synthetic leaves. All 10,000 paths belong
to that single block. Building the tree and paths is excluded. The signing
fixture has a proven funding transaction with 100 outputs. Its key exists
only in memory. Transaction cloning and installation of all 100 signing
callbacks are outside the signing interval. Cloning drops callbacks, so each
iteration's setup reinstalls them. All
signature creation, source resolution, sighash work and template execution
remain inside the measured operation. Verification includes checking the
funding proof against a local `MockChainTracker`.
The proof and signing benches print their prepared workload observations
outside timing; they do not assert an acceptance verdict.

The wire bench's bytes are #76's recordings, not a schema of its own (#138):
for each of the 28 calls it reads the `full` case of
`tests/fixtures/wire/<method>.json`, the request frame the transceiver wrote
(`request_hex`) and the result frame the wallet side wrote (`response_hex`:
the processor's, or `WireWriter`'s type writers for the 13 calls the processor
does not answer), outside timing. A per-call layout (`wire_codec/support.rs`)
names the public `WireReader`/`WireWriter` call of each field and carries no
value: the decode op reads the recorded frame through it, the encode op writes
the values read back to the same bytes, and the bench asserts that before it
times. It measures field serialization and decoding, including walker
overhead; it does not measure asynchronous dispatch or a wallet operation.
`tests/wire_codec_bench_bytes.rs` pins every layout to both recorded cases
(the frame consumed exactly, re-encoded byte for byte), and `fixtures_replay`
pins the recordings to the crate's writers, so a wire change that re-records
the fixtures turns the test red until the layout follows. The layouts follow
the recorded bytes where the transceiver reads them otherwise: the
certificate results carry `write_wallet_certificate`'s order (type, serial,
subject, certifier, outpoint, fields, the signature unprefixed), which the
transceiver's parser does not read (the recordings pin its underflow), and
getHeaderForHeight's result carries the processor's length prefix, which the
transceiver keeps as the header's leading byte. The recordings' keys are fixed
public curve points.

`BSV_SCRIPT_CORPUS` accepts `corpus/seed` or its `seed.jsonl`. Absence prints
`SKIP script_spend` when that bench is run alone; the comparison tool requires
it and fails closed unless given `--skip script_spend`. `--skip <bench>`
(repeatable; one of `beef_stream`, `merkle_path`, `transaction_sign_verify`,
`wire_codec`, `script_spend`, whose ids carry the bench's name) does not run
that bench, records it as `skipped` in `run.json`, leaves its rows out of the
table and names it in the summary as `SKIPPED`: not measured, never a pass
and never a regression. `--record` refuses `--skip`. Bad paths and malformed/empty input fail. The adapter
follows `harness/src/engine.rs` at sibling commit
`8840488cc7922fa908ebcaa6333e885a49c6ca7c`: each input's spend height chooses
the block word, and the UTXO height chooses its Chronicle marker. The
transaction's own version is retained. Parsing/preparing the corpus is outside
timing; constructing `Spend` and executing every input is inside. The run
records the source bytes' SHA256, row count, input count and block words.

## Recording and CI

An explicit baseline update is:

```sh
cargo run --locked --manifest-path tools/bench-compare/Cargo.toml -- --record
```

This replaces only the measured machine's entry in `benches/baseline.json`,
keyed by platform, CPU model and core count.
Use it only in a run that requests a baseline update (the dispatch input below). The table
and retained run show exactly what changed. Ordinary comparisons never write
the baseline. A run on a CPU model or core count with no entry exits 3 and names
the recorded entries; hosted runners draw from several CPUs, so each one the
job lands on needs its own reviewed entry.

The CI `benchmarks` job runs on a push to `beta` and on the nightly's dispatch
on `beta`; no pull request runs it (it is not a required check, 2026-10-26).
`benchmarks-build` compiles every bench with all features on every event but
a pull request.
The seed repository `Calgooon/bsv-script-lean` is private. The captain must
provision `BSV_SCRIPT_CORPUS_TOKEN` with read access; CI downloads only
`corpus/seed/seed.jsonl` at the named commit. No wallet or network request is
made by a benchmark. Where the token is absent (a fork, a PR from outside, a
repository without the secret) the job warns
`script_spend skipped: BSV_SCRIPT_CORPUS_TOKEN not set (the script corpus is private)`
and compares the other eight benches with `--skip script_spend`. Where the
runner's platform/CPU/cores key has no entry (exit 3) the job warns
`no baseline entry for <key>: record one with gh workflow run ci.yml -f bench_baseline_record=true` and
does not fail.

The lane can record the local machine only. To record Linux, the captain
dispatches CI on the baseline PR's branch with the record input:
`gh workflow run ci.yml --ref <branch> -f bench_baseline_record=true` (until
2026-10-26 a `[bench-baseline-record]` marker in the PR's description did this;
no pull request runs the job now). That run proposes `linux-baseline.json` as an artifact; it does not commit or
publish it. Review the machine line and measurements, commit the Linux entry,
and dispatch the run again to exercise the comparison path. Record that
run's URL in the landing report. If three Linux repeats demonstrate noise
above 5%, report their numbers before proposing a wider threshold. The tool
has no option to silently widen it.

## Stack alignment

T1 (scale with use): file-backed BEEF with explicit byte and entry counts.
T2 (headers and proof): the proof and funding fixtures check known local roots.
T3 (fast and cheap): time, throughput, RSS and the p99 gate are executable.
T4 (script or math): the block-word adapter and proof hashing call this crate.
T5 (fewer trusted claims): committed sampling settings, source digests and raw
samples explain each number; external setup failures never pass as measurements.
T6 (executable): the benches and standalone comparison tool are the commands.
The corpus/gate choices address T3/T4/T5/T6, BEEF T1/T3/T6, proof workloads
T2/T3/T4/T6, and signing/wire T3/T4/T5/T6.
