# Lane bench-245-m1max: the Apple M1 Max entry of `benches/baseline.json` recorded again (#245)

Base: `origin/beta` at `b701c06f`, the tip when the worktree opened (`cb950611` at the lane's end: the section "Beta moved while the lane measured"). Host: the Studio (Apple M1 Max, 10 cores, 32 GiB, macOS 26.7.1), 2026-11-14, 20:34Z to 21:44Z. The change is one entry of `benches/baseline.json` and its records: no file under `src/`, `tests/`, `benches/*.rs`, `tools/` or `.github/` is touched, and no wire form, verdict, derivation or error text moves, so no reference is in play.

## The issue's comments, each line

| Comment | What it records | Here |
|---|---|---|
| 2026-10-27 04:23Z | the Linux record needs the corpus token and a window with no landing | done on 2026-10-27 (the rows below) |
| 2026-10-27, the rehearsal | the M1 Max record at `953d9c0` ran while seven other lanes arrived (1-minute load 5.28 to 81.69) and was not opened as a baseline: "the record itself repeats in a quiet window" | this lane is that repeat |
| 2026-10-27 12:4xZ, the token | the Linux record dispatched (run 40506085202) | done |
| 2026-10-27 12:4xZ, the owner's words | the Studio entry in a quiet window; the Linux entry through CI; a box or mini record is its own entry, recorded only if lanes compare there | followed: this machine's entry alone |
| 2026-10-27, recorded | PR #357 proposes the Linux entry | done |
| 2026-10-27, landed | the Linux entry on `beta` at `e78ed2f2` | done |
| 2026-11-12, the builder of #880 | both entries answer `benchmark inventory changed` once the five Shamir rows land, until each is recorded again | the M1 Max entry: done here. The Linux entry: owed, a dispatch (the section below) |

No comment records a wait that has not happened: the M1 Max record waited on a quiet Studio, and this lane found one.

## What was wrong

1. **The entry was recorded on a loaded host.** Its commit (`e8ad97d4`) says the 1-minute load ran between 12.6 and 34.5, and the entry shows it: across its 207 rows the p99 over the p50 has a median of 2.97, and 127 rows hold a p99 more than twice their p50 (`Verification/P256PublicKey::verify` p50 249 µs, p99 1,825 µs; `merkle_path/verify_depth20_10000` p50 334 ms, p99 1,185 ms). The gate fails a p99 more than 5 percent over the entry's, so a floor that is the load's passes a regression of that size (the finding of #126's review).
2. **Its 112 `wire_codec` rows measured another workload.** The entry is of `67559f9d`, recorded on 2026-10-24 at 02:41Z. `a81f089a` (#138, 2026-10-25) moved the bench onto #76's recorded frames, and later commits through `3cf87636` (2026-10-28) moved its layouts with the re-recorded frames, the ids unchanged: 78 of the 112 rows have a p50 more than 5 percent over the old entry's today (`wire_codec/getPublicKey/request_decode` 111 ns then, 5,286 ns now; the Linux entry of 2026-10-27 holds 8,097 ns, the same workload).
3. **It did not hold the five Shamir rows of #880** (`054aa396`, 2026-11-12), so a comparison on this machine answered `bench-compare: benchmark inventory changed; baseline update needs a PR that says so`, exit 2, before any row was judged. Run here on the tip, by the tool itself (`logs/toolrun.err`) and on the saved run (`checks/run1-vs-committed.out`).

## The record

`tools/bench-compare`'s `--record` is one `cargo bench` of all nine binaries and refuses `--skip` (`src/main.rs:248-250`): 212 rows at a 1 s warm-up and a 3 s interval each, about 17 minutes here (the nine binaries' own time 995 s). A lane's command is bounded at ten minutes, and an unsplit run is not to be backgrounded, so the record was measured in nine pieces, one bench binary each, and the entry built from their Criterion samples:

- **The measurement is the tool's.** Each piece is the cargo line `fresh_run` builds (`src/main.rs:491-517`) with one `--bench`: `cargo bench --locked --features wallet --bench <name> -- --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3`, `CRITERION_HOME=<run>/criterion`, `BSV_BENCH_ARTIFACT_DIR=<run>`, `BSV_SCRIPT_CORPUS` on `~/bsv/bsv-script-lean/corpus/seed`, `CARGO_BUILD_JOBS` unset, the binaries built beforehand, the nine in the tool's order, one after another in the foreground (`scripts/piece.sh`).
- **The entry is built by a script that repeats the tool's reading** (`scripts/assemble.py`, sha256 `7263b613...3323`): `measure` (per sample `times[i] / iters[i]`, sorted, the linearly interpolated 50th and 99th percentiles), `measurements` (every `new/` directory, keyed by `benchmark.json`'s `full_id`), the `BSV_BENCH_CORPUS` and `BSV_BENCH_MEMORY` lines of the benches' stdout, the machine, `rustc --version`, `git rev-parse HEAD`, the settings; `recorded_unix_seconds` is the last binary's end. `scripts/place.py` puts the run in the file in place of the machine's entry.
- **Checked against the tool three ways.** (a) The tool measured the four benches `--skip` cannot name itself, in one invocation under the bound (`--skip` of the other five, 429 s, exit 2 as above): from that run's own Criterion samples the script's 92 rows equal the tool's `run.json` in every p50, p99 and sample count, f64 for f64, and the tool's `run.json` printed again by the script's writer is byte-identical (`checks/assembler-vs-tool.out`). (b) The tool validates and gates the recorded run: `bench-compare --from-run run1/run.json` against the new file is `PASS (9 of 9 benches measured)`, exit 0, 212 rows at +0.00% (`validate_run`: every required id, the 112 wire rows, the corpus record, the four RSS rows). (c) The file before the change printed by the same writer is byte-identical to itself, so the Linux entry's bytes are untouched: `git diff` holds no hunk outside the M1 Max entry (lines 11 to 1129).

What the entry holds: `macos-aarch64 / Apple M1 Max / 10 cores`, 212 workloads, `rustc 1.95.0 (59807616e 2026-04-14)` (what `cargo` resolves to on this host, as the tool reads it and as the old entry was recorded), `source_commit` `b701c06f2fc4bd1ba8071e8e7dd30cf3b13eaaf2`, the corpus sha256 `bc0651d0...54b0` (10,000 rows, the blob of the workflow's pinned `8840488c`, equal to both older entries'), the lockfile resolved on the day (`cargo generate-lockfile`, sha256 `a2e3cf13...22dc`, kept as `Cargo.lock.recorded`: criterion 0.5.1, k256 0.14.0, p256 0.14.0, crypto-bigint 0.7.11).

## The load

The host was checked before the record: `machdep.cpu.brand_string` `Apple M1 Max`, `hw.ncpu` 10, the 1-minute load 1.38 to 1.93 before the lane's own build and 2.67 and falling when run 1 began (the build's tail), no `cargo`, `rustc`, `rustdoc` or `clippy-driver` of any other process at any sample. The load before and after each binary (`run1/load.log`, `run2/load.log`, with the six busiest processes at each sample):

| run | bench binary | started (UTC) | seconds | load before (1, 5, 15 min) | load after (1, 5, 15 min) | cargo or rustc of another process |
|---|---|---|---:|---|---|---|
| 1 | hash_bench | 20:34:31 | 21 | 2.67 2.38 2.04 | 2.42 2.34 2.03 | none |
| 1 | primitives_bench | 20:35:02 | 264 | 2.21 2.29 2.02 | 2.02 2.27 2.08 | none |
| 1 | script_bench | 20:39:34 | 81 | 2.30 2.33 2.10 | 2.31 2.38 2.15 | none |
| 1 | memory_bench | 20:40:56 | 61 | 2.31 2.38 2.15 | 1.92 2.28 2.13 | none |
| 1 | beef_stream | 20:42:01 | 21 | 1.92 2.28 2.13 | 1.66 2.20 2.10 | none |
| 1 | merkle_path | 20:42:22 | 21 | 1.76 2.21 2.10 | 1.77 2.18 2.10 | none |
| 1 | transaction_sign_verify | 20:42:43 | 10 | 1.77 2.18 2.10 | 1.65 2.14 2.08 | none |
| 1 | wire_codec | 20:42:57 | 508 | 1.76 2.15 2.09 | 1.82 1.69 1.84 | none |
| 1 | script_spend | 20:51:30 | 8 | 1.83 1.70 1.84 | 1.77 1.69 1.84 | none |
| 2 | hash_bench | 20:51:54 | 22 | 1.73 1.68 1.83 | 2.49 1.85 1.89 | none |
| 2 | primitives_bench | 20:52:16 | 264 | 2.49 1.85 1.89 | 1.53 1.80 1.87 | none |
| 2 | script_bench | 20:56:43 | 82 | 1.73 1.84 1.88 | 1.87 1.83 1.87 | none |
| 2 | memory_bench | 20:58:05 | 62 | 1.87 1.83 1.87 | 1.99 1.86 1.88 | none |
| 2 | beef_stream | 20:59:08 | 20 | 1.99 1.86 1.88 | 1.98 1.87 1.88 | none |
| 2 | merkle_path | 20:59:29 | 20 | 1.98 1.87 1.88 | 1.84 1.85 1.87 | none |
| 2 | transaction_sign_verify | 20:59:49 | 9 | 1.84 1.85 1.87 | 1.79 1.83 1.87 | none |
| 2 | wire_codec | 21:00:02 | 509 | 1.81 1.84 1.87 | 1.71 1.90 1.92 | none |
| 2 | script_spend | 21:08:38 | 8 | 1.58 1.87 1.90 | 1.96 1.94 1.93 | none |

The 1-minute load across the 18 samples of each run: 1.65 to 2.67 (run 1), 1.53 to 2.49 (run 2); the bench's own thread is about 1 of it. Other captains' sessions were alive on the host and idle but for short commands (a `gh`, a shell); none built.

## The two runs

Recorded twice, back to back: run 1 from 20:34:31Z to 20:51:38Z, run 2 from 20:51:54Z to 21:08:47Z, 212 rows each (`scripts/spread.py`, `checks/spread-summary.out`; the tool's own comparison of each run against the other in `checks/run2-vs-run1.out` and `checks/run1-vs-run2.out`).

| run 2 against run 1 | p50 | p99 |
|---|---:|---:|
| geometric mean of the ratio | 0.9982 | 0.9869 |
| median of the ratio | 0.9990 | 0.9925 |
| least and greatest ratio | 0.9435, 1.0881 | 0.2288, 2.0208 |
| rows apart by more than 1% | 53 | 163 |
| rows apart by more than 2% | 35 | 112 |
| rows apart by more than 5% (the gate's tolerance) | 3 | 30 |
| rows apart by more than 10% | 0 | 10 |
| rows apart by more than 25% | 0 | 6 |

The p50s repeat: three rows past 5 percent (`Shamir Secret Sharing/recover_private_key (2 of 3)` +8.8%, `wire_codec/createAction/request_decode` +5.8%, `sha256d` -5.7%), none past 10. The p99s do not: 30 of 212 rows sit more than 5 percent over the other run's, 12 with run 2 the higher and 18 with run 1 the higher, so each run answers `FAIL` against the other (exit 1). A p99 of 100 sample averages is set by its one or two slowest samples; in each run three rows hold a p99 more than 1.25 times their own p50 (run 1: `wire_codec/decrypt/request_decode` 4.39, `Symmetric Encryption/encrypt/256 bytes` 2.25, `Signing/P256PrivateKey::sign_hash` 1.80; run 2: `wire_codec/discoverByIdentityKey/result_decode` 2.05, `Sighash/sighash x50 inputs, from_raw per input (parse + no reuse)` 1.99, `wire_codec/createHmac/result_decode` 1.35), and they are not the same rows. The tool's own run of the 92 rows (a third sample of them, 21:08:57Z to 21:16:06Z, load 2.05 before and 1.88 after) agrees: against the recorded entry 11 of its 92 rows are `REGRESSION` (`checks/toolrun-vs-recorded.out`).

**The entry recorded is run 1.** `benches/README.md` and `docs/RATCHETS.md` do not say which of two records stands, so the slower does: run 1 has the higher p99 on 130 rows of 212 and the higher p50 on 138, the geometric mean of run 2's p99 over run 1's is 0.9869, and the sum of the p99s is 314.3 ms against 309.5 ms. The entry is one run whole, as the tool records one; no row is taken from run 2.

The 30 rows past the tolerance (run 2 against run 1; the last column is the tool's own run where it measured the row):

| row | run 1 p50 ns | run 1 p99 ns | run 2 p50 ns | run 2 p99 ns | p50 2/1 | p99 2/1 | third p99 ns |
|---|---:|---:|---:|---:|---:|---:|---:|
| wire_codec/decrypt/request_decode | 5493.01 | 24105.32 | 5329.27 | 5515.45 | -2.98% | -77.12% | |
| Symmetric Encryption/encrypt/256 bytes | 4154.19 | 9357.56 | 4065.66 | 4208.08 | -2.13% | -55.03% | 4237.35 |
| wire_codec/discoverByIdentityKey/result_decode | 1265.19 | 1288.05 | 1268.93 | 2602.92 | +0.30% | +102.08% | |
| Sighash/sighash x50 inputs, from_raw per input (parse + no reuse) | 136404.77 | 145983.02 | 135639.79 | 269341.41 | -0.56% | +84.50% | 147972.54 |
| Signing/P256PrivateKey::sign_hash | 61587.14 | 111006.12 | 60920.86 | 64580.07 | -1.08% | -41.82% | 64804.48 |
| wire_codec/createHmac/result_decode | 74.81 | 79.04 | 74.85 | 100.89 | +0.05% | +27.64% | |
| Hashing/sha1 (1KB) | 486.65 | 556.22 | 472.60 | 485.58 | -2.89% | -12.70% | 491.59 |
| Key Derivation/PublicKey::mul_scalar | 40429.99 | 41692.60 | 42018.35 | 46779.49 | +3.93% | +12.20% | 40748.20 |
| wire_codec/acquireCertificate/request_decode | 792.29 | 906.87 | 763.13 | 813.97 | -3.68% | -10.24% | |
| Key Derivation/PrivateKey::derive_shared_secret | 40401.18 | 47654.19 | 40748.48 | 42787.63 | +0.86% | -10.21% | 41681.87 |
| wire_codec/relinquishOutput/request_encode | 136.51 | 154.57 | 136.52 | 141.58 | +0.00% | -8.40% | |
| wire_codec/waitForAuthentication/request_encode | 61.01 | 65.08 | 59.07 | 59.98 | -3.17% | -7.84% | |
| Encoding/to_hex (1KB) | 3917.96 | 4232.64 | 3870.86 | 3932.58 | -1.20% | -7.09% | 3998.22 |
| Shamir Secret Sharing/from_backup_format | 25488.79 | 25860.96 | 26139.08 | 27691.76 | +2.55% | +7.08% | 27155.66 |
| wire_codec/verifyHmac/request_encode | 269.76 | 280.09 | 279.47 | 299.42 | +3.60% | +6.90% | |
| Script Parsing/Script::from_asm (P2PKH) | 402.98 | 409.84 | 409.70 | 436.66 | +1.67% | +6.54% | 435.00 |
| Template Sign/P2PK::sign_with_sighash | 45767.20 | 49092.40 | 45674.20 | 46100.33 | -0.20% | -6.09% | 49783.96 |
| wire_codec/createAction/request_decode | 1673.06 | 1701.61 | 1769.34 | 1809.98 | +5.75% | +6.37% | |
| wire_codec/proveCertificate/request_encode | 300.95 | 327.32 | 301.24 | 309.32 | +0.10% | -5.50% | |
| wire_codec/getHeaderForHeight/result_decode | 76.70 | 81.87 | 76.26 | 77.41 | -0.57% | -5.45% | |
| wire_codec/listActions/result_encode | 265.60 | 268.36 | 267.77 | 283.54 | +0.82% | +5.66% | |
| wire_codec/relinquishOutput/result_encode | 21.33 | 22.17 | 20.71 | 21.00 | -2.88% | -5.25% | |
| Template Lock/P2PKH::lock | 42.44 | 44.59 | 40.92 | 42.33 | -3.59% | -5.08% | 49.79 |
| Shamir Secret Sharing/recover_private_key_from_legacy_backup (255 of 255) | 10616375.17 | 11326762.67 | 10607090.33 | 10754044.86 | -0.09% | -5.06% | 11279634.17 |
| Memory/KeyDerivation/ecdh_shared_secret | 40294.78 | 44220.91 | 40278.55 | 41987.61 | -0.04% | -5.05% | 42690.46 |
| wire_codec/relinquishCertificate/result_encode | 20.71 | 20.97 | 21.21 | 22.09 | +2.40% | +5.30% | |
| Verification/P256PublicKey::verify | 215244.36 | 223785.20 | 208134.48 | 212589.60 | -3.30% | -5.00% | 218480.44 |
| wire_codec/createHmac/request_encode | 261.44 | 281.09 | 261.47 | 267.19 | +0.01% | -4.95% | |
| Shamir Secret Sharing/recover_private_key (2 of 3) | 51713.06 | 55424.44 | 56270.99 | 58232.44 | +8.81% | +5.07% | 54937.51 |
| Memory/Encryption/aes_gcm_decrypt/1024 bytes | 8461.59 | 8566.75 | 8500.10 | 8996.02 | +0.46% | +5.01% | 8815.00 |

(A row at -5.00% or -4.95% is past the tolerance from the other side: run 1's p99 is more than 5 percent over run 2's.)

## Before and after

The whole tables, per row, are the pull request's body (`pr-body.md` in the lane's folder, from `tables/before.md` and `tables/after.md`). The entry before is not a measure of the code before: the three faults above are in it. What the rows say, by class:

- Of the 87 rows outside `wire_codec` and Shamir, 85 fell in p50 and 85 in p99. The two whose p50 rose: `Template Lock/Multisig::lock_from_keys (2-of-3)` (175.5 ns to 251.0 ns; the lock checks its keys' tags since `f783d80d`, #625, the cause read from the history and not profiled here) and `Template Lock/PushDrop::lock (3 fields)` (296.7 ns to 325.9 ns; both runs agree, 321.9 ns in run 2). The two whose p99 rose: the `PushDrop::lock` row and `Symmetric Encryption/encrypt/256 bytes`, which is run 1's one slow sample (9,358 ns; 4,208 ns in run 2).
- The 112 `wire_codec` rows: 78 with a p50 more than 5 percent over the old entry's, 28 more than 5 percent under: another workload (#138), not a comparison.
- The 8 Shamir rows the old entry held: each p50 3.4 to 8.4 times the old entry's (`split_private_key (3 of 5)` 6.7 µs to 34.8 µs, `recover_private_key (3 of 5)` 7.1 µs to 56.9 µs, `to_backup_format` 8.6 µs to 53.7 µs, `from_backup_format` 5.6 µs to 25.5 µs). The rows measure #854's BRC-140 shares since `4f6e82f2` (2026-11-11); the Linux entry of 2026-10-27 holds the older figures (6.2, 7.8, 7.8 and 4.3 µs), so its next record moves the same way.
- Across the 207 rows both hold, the geometric mean of the p99's ratio is 0.40 and 105 rows' p99 at least halved; the p99 over the p50 has a median of 1.04 in the new entry (2.97 in the old), 2 rows past twice (127).

| row | before p50 ns | before p99 ns | after p50 ns | after p99 ns | run 2 p50 ns | run 2 p99 ns |
|---|---:|---:|---:|---:|---:|---:|
| `Verification/P256PublicKey::verify` | 249221.82 | 1825091.44 | 215244.36 | 223785.20 | 208134.48 | 212589.60 |
| `Verification/PublicKey::verify (secp256k1)` | 74467.13 | 737673.99 | 51062.12 | 52782.34 | 51584.88 | 53837.41 |
| `merkle_path/verify_depth20_10000` | 334475208.50 | 1184597998.51 | 183905854.50 | 192484908.24 | 183738895.50 | 189173069.49 |
| `script_spend/seed_block` | 30515208.50 | 33070502.08 | 29611156.25 | 30904569.79 | 29495802.00 | 30580885.96 |
| `transaction_sign_verify/sign_100_p2pkh` | 14928854.25 | 107552403.87 | 7011484.25 | 7288675.99 | 7005411.38 | 7141225.02 |
| `transaction_sign_verify/verify_100_p2pkh` | 9260552.25 | 38878311.38 | 5945312.50 | 6284359.58 | 5955746.58 | 6344298.11 |
| `beef_stream/structure/1000000` | 4593541.67 | 45887754.17 | 1326646.74 | 1393464.91 | 1327535.33 | 1385265.45 |
| `beef_stream/scripts/1000000` | 8838090.33 | 52020530.17 | 2223125.00 | 2317028.81 | 2211851.18 | 2306992.62 |
| `beef_stream/structure/10000000` | 45508437.00 | 206644550.00 | 13339139.00 | 14202826.14 | 13305041.67 | 13956331.00 |
| `beef_stream/scripts/10000000` | 54263312.50 | 128263331.67 | 22129697.75 | 23884393.84 | 22238239.50 | 22799972.50 |

The five rows the entry gains (#880):

| row | recorded p50 ns | recorded p99 ns | run 2 p50 ns | run 2 p99 ns |
|---|---:|---:|---:|---:|
| `Shamir Secret Sharing/recover_private_key (2 of 3)` | 51713.06 | 55424.44 | 56270.99 | 58232.44 |
| `Shamir Secret Sharing/recover_private_key (10 of 20)` | 95400.36 | 100706.72 | 94983.37 | 99142.68 |
| `Shamir Secret Sharing/recover_private_key (255 of 255)` | 18304573.00 | 18562134.08 | 18326697.75 | 19422147.38 |
| `Shamir Secret Sharing/recover_private_key_from_legacy_backup (3 of 5)` | 14302.19 | 15102.38 | 13965.64 | 14645.72 |
| `Shamir Secret Sharing/recover_private_key_from_legacy_backup (255 of 255)` | 10616375.17 | 11326762.67 | 10607090.33 | 10754044.86 |

The four `beef_stream` RSS rows (peak, bytes): structure 1 MB 3,096,576 (3,031,040 before), scripts 1 MB 3,391,488 (3,293,184), structure 10 MB 6,324,224 (6,373,376), scripts 10 MB 6,750,208 (6,602,752); the sampled slope 0.359 and 0.373 bytes of RSS per byte of BEEF.

## Beta moved while the lane measured

`origin/beta` was `b701c06f` when the worktree opened and `cb950611` when the lane ended: four commits landed in between. `83ade821` and `70e8c3b2` (#867) are CI and documents, `6232488b` (#908) is tests, and `cb950611` (#912, landed at 21:00Z, during run 2) changes `src/primitives/ec/` and one line of `src/primitives/bsv/schnorr.rs`: the ECDH doors and the Schnorr proof read the private scalar without a byte copy, and `PublicKey`'s `==` has no early exit. The entry is of `b701c06f`, as its `source_commit` says, and the branch stays on that base; `Cargo.toml`, `benches/` and `tools/bench-compare` are the same at both commits.

Whether the entry still describes the later tip was measured, not assumed: on a scratch copy of `cb950611` (`git archive`, the recorded lockfile, a target directory of its own) `primitives_bench` was measured twice and `memory_bench` once by the same cargo line, 21:33Z to 21:44Z, the 1-minute load 2.35 to 2.94 (the tail of the gate's own builds, no other build). The geometric mean of the p50s over the entry's is 1.005 on the earlier sample's 69 rows and 1.006 on the later sample's 56 (run 2 over run 1 on the same rows: 0.998); no row's p50 sits more than 5 percent outside the three samples of the recorded commit in both tip samples; the rows the change reaches (`Key Derivation/*`, `Schnorr Proofs/*`, `Memory/KeyDerivation/*`) are within 5 percent of the entry in p50 (`checks/tipcheck.out`, `checks/tipcheck2.out`). One sample put `recover_private_key_from_legacy_backup (255 of 255)` at 11.22 ms (10.62 ms in the entry) and the next at 10.62 ms: a sample's noise. The other seven binaries were not measured again at the later tip.

## The Linux entry: not built here, a dispatch

`bench.yml` has three runs on record (`gh run list --workflow bench.yml`): 43314249256 on `main` (`b109045a`), 43324383992 on `release/v0.8.8`, 43350679244 on `rehearsal/v0.8.9`, all on the stable line, which does not carry #880's rows; none on `beta`, and none since `054aa396` landed there. No artifact or log holds a Linux measurement of the 212 rows, so the entry cannot be built from a run that already ran. The record is the captain's dispatch, as `benches/README.md` writes it, on a ref that holds the five rows:

```sh
gh workflow run bench.yml -R Calhooon/bsv-rs --ref beta -f bench_baseline_record=true
```

(or `--ref <the baseline pull request's branch>`). The run proposes `linux-baseline.json` in the artifact `benchmark-evidence-Linux`; the Linux entry is committed from it and a plain dispatch then exercises the comparison. Two things to read in that artifact: the runner's CPU (a hosted runner that is not `AMD EPYC 7763 64-Core Processor / 4 cores` records another key and leaves the old entry standing), and the Shamir rows, which will read several times the entry of 2026-10-27 for the reason above.

## What the gate ran

`cargo +1.100.0 fmt --all -- --check`, `cargo +1.100.0 fmt --manifest-path fuzz/Cargo.toml -- --check`, `cargo +1.100.0 fmt --manifest-path fuzz/corpus-gen/Cargo.toml -- --check` (the three lines of `ci.yml`'s Rustfmt step); `bench.yml`'s step `Test the comparison gate` (the tool's fmt, `cargo +1.100.0 clippy --locked --all-targets -- -D warnings`, its 10 tests, two of which read `benches/baseline.json`); `cargo test --locked --features "full,http" --test 'arch_*'`, `--test fixtures_replay`, `--test readme_examples`; `RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --all-features`; `tools/ratchet/run --check --against origin/beta`; `python3 .github/scripts/mutants_entries.py`; `python3 -B .github/scripts/rows_from_sources.py --check`; gitleaks in git mode over `origin/beta..HEAD`. No clippy of the crate, `cargo check` or unit test: no Rust file is touched. No test is added: the witness of a record is the tool's own answer, exit 2 with `benchmark inventory changed` before and `PASS`, exit 0, on the recorded run after.

## What is left, and what the record found

- **The Linux entry**, the dispatch above.
- **The gate's noise on this machine.** Three quiet samples differ by more than the 5 percent tolerance in p99 on 5 to 12 percent of their rows while their p50s repeat, so a plain comparison here answers `FAIL` on noise alone, whichever run is the entry. `benches/README.md` asks that repeats showing noise above 5 percent be reported with their numbers before a wider threshold is proposed: these are the numbers (`checks/`). A change of what the gate judges (the p50, a lower percentile, more samples, a wider margin) is a change of `tools/bench-compare`, its own lane.
- **A record in one invocation does not fit a lane.** The entry here is the tool's measurement and the tool's arithmetic, put together outside `--record`. If the entry must be `--record`'s own bytes, the command is `BSV_SCRIPT_CORPUS=~/bsv/bsv-script-lean/corpus/seed CARGO_TARGET_DIR=<outside the checkout> cargo run --locked --manifest-path tools/bench-compare/Cargo.toml -- --record --output <a fresh directory>` in a quiet window of 20 minutes, by hand. A door for a record in pieces (`--record` from saved runs of one commit and one machine that together hold every bench) is a change of the tool, not built here.
- **The toolchain.** This host's `stable` is rustc 1.95.0; the Linux entry was recorded on 1.99.1. A comparison does not read `rustc`, so the entry gates runs made with whatever `cargo` resolves to here; when the host's `stable` moves, the entry is recorded again.
- Four design records cite the old entry's figures by line and commit (`docs/design/90-interpreter-speed.md:38`, `91-beef-streaming-memory.md:38`, `92-sign-verify-throughput.md:21`, `93-merkle-verify-and-header-window.md:56`, each "at `67559f9d`"): dated records, left as written.

## The evidence

`/Volumes/Lanes/out/bsv-rs/bench-245-m1max/`: `run1/` and `run2/` (each `run.json`, `baseline.json`, `load.log`, `pieces.tsv`, `logs/<bench>.stdout.log` and `.stderr.log`, Criterion's `sample.json` of every row under `criterion/`), `toolrun/` (the tool's own `run.json`, `bench.log` and samples of the four benches), `tipcheck/` and `tipcheck2/` (the later tip's samples), `checks/` (the tool's comparisons and the script's check against the tool), `tables/`, `scripts/`, `baseline-before.json`, `Cargo.lock.recorded`, `pr-body.md`. sha256: `run1/run.json` `a71e2155...8b80`, `run2/run.json` `eb0b78b7...44d9`, `benches/baseline.json` after `06755f54...8720`.
