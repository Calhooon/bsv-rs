# Lane bench-245-linux-entry: the Linux entry of `benches/baseline.json` recorded again at beta's tip (#245), and what the tests hold of the entries (#911)

Base: `origin/lane/bench-245-linux` at `d892e206` (beta's tip when the record was dispatched). The change is one entry of `benches/baseline.json`, sentences of `benches/README.md` and `CHANGELOG.md`, and this record: no file under `src/`, `tests/`, `benches/*.rs`, `tools/` or `.github/` is touched, and no wire form, verdict, derivation or error text moves, so no reference is in play. The lane measured nothing: the record is the captain's dispatch, and the lane reviewed its artifact and committed the entry, as `benches/README.md` ("Recording and CI") writes the procedure.

## The run

| | |
|---|---|
| Run | https://github.com/Calhooon/bsv-rs/actions/runs/43678287110 (`bench.yml`, `workflow_dispatch` with `bench_baseline_record=true`, the captain's), success |
| Ref | `lane/bench-245-linux` at `d892e206ac5cb4120c78c070775d8a4f8514fa8d` |
| When | 2026-11-15, created 04:47:30Z; the job `Benchmark Regression Check` from 04:47:34Z to 05:06:45Z; the entry's `recorded_unix_seconds` 1794719197 (05:06:37Z) |
| Runner | `ubuntu-24.04`, image 20261111.370.1; the tool's line `Machine: AMD EPYC 7763 64-Core Processor, 4 cores (linux-x86_64)` |
| Toolchain | `rustc 1.100.0 (0ef1bc386 2026-11-09)` (the job's `stable`, updated in the run from 1.99.1) |
| Lockfile | `cargo generate-lockfile` in the job, 298 packages: criterion 0.5.1, k256 0.14.0, p256 0.14.0, crypto-bigint 0.7.11, sha2 0.11.1, aes-gcm 0.10.3, indexmap 2.14.2; the target cache was cold (`Cache not found`) |
| Corpus | the seed at the workflow's pin, 10,000 rows and inputs, sha256 `bc0651d0f7f8193aebbd233b258148d81ca553a8f43a01fc2594b51610f554b0` (the old entry's and the M1 Max entry's digest); `script_spend` measured, nothing skipped |
| Settings | the tool's: 100 samples, 1 s warm-up, 3 s interval, `--features wallet` |
| Artifact | `benchmark-evidence-Linux`: `linux-baseline.json` (74,670 bytes, sha256 `f6220bee...b938`), `bench-results/run.json` (32,767 bytes, `f4b7994d...e91e`), `bench-results/baseline.json` (37,395 bytes, `25afcec5...13e2`), `bench-results/bench.log` (55,462 bytes, `14b273c0...dc8d`); downloaded as data, never executed |

The run's retained table is the job log's 212 record lines (`| <row> | p50 <ns> | p99 <ns> |`): each equals `run.json`'s row at two decimals (`checks/log-vs-entry.out`). The entry of `linux-baseline.json`, the one entry of `bench-results/baseline.json` and `run.json` are one value (compared parsed), and the entry's text in `linux-baseline.json` is `run.json`'s text indented by four spaces, line for line (the placing script refuses otherwise).

The entry it replaces: the record of 2026-10-27 (run 40506085202, then a dispatch of `ci.yml`), `source_commit` `4b1c46881acf4491de7285765b286075b7b98f4f`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, image 20261012.334.1, 296 packages locked, `recorded_unix_seconds` 1793106101 (13:01:41Z), landed by `e78ed2f2` (pull request #357; `git log --format=%h -- benches/baseline.json` reads `1acd0854`, `e78ed2f2`, `e8ad97d4`, `a5e93680`, and `1acd0854` is #993). That run's log holds 207 record lines, each equal to the old entry at two decimals.

## The machine line: the same key, the entry replaced whole

The artifact proposes `linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores`: the platform, CPU model and core count of the entry the file holds. So this is the case of a replacement: the old entry's 1,105 lines go and the new entry's 1,130 lines take their place; no entry is added and none stays beside it. The M1 Max entry and the order of the two are untouched (the byte comparison below).

The same key is one draw of the pool, not a property of it: the section "A second CPU in the pool" below.

## The measurements

`scripts/table.py` and `scripts/movers.py` (the lane's folder) read the old entry from the file as committed and the new one from `run.json`. The whole table, 212 rows, closes this record.

| | p50 | p99 |
|---|---:|---:|
| rows both records hold | 207 | 207 |
| rows the new record gains (#880's five) | 5 | 5 |
| geometric mean of new over old | 1.1012 | 1.1136 |
| median of new over old | 1.0158 | 1.0402 |
| least and greatest ratio | 0.7339, 9.6922 | 0.6682, 8.8496 |
| rows apart by more than 1% | 150 | 185 |
| rows apart by more than 2% | 122 | 172 |
| rows apart by more than 5% (the gate's tolerance) | 94 | 127 |
| rows apart by more than 10% | 45 | 75 |
| rows apart by more than 25% | 12 | 19 |
| rows apart by more than 100% | 8 | 8 |

139 rows moved by more than 5 percent in p50 or in p99: 82 in both, 12 in p50 alone, 45 in p99 alone. Within each entry the p99 over the p50 has a median of 1.029 (old, 7 rows past 1.25) and 1.048 (new, 6 rows past 1.25), no row past 2 in either: neither record was made under load.

The landings since the old record: `git log --oneline 4b1c4688..d892e206 -- src benches tools/bench-compare` holds 327 commits (323 of them under `src/`; 318 since the landing `e78ed2f2`; the list is `checks/landings-since-old-record.txt`).

### How a reason was given

A moved row is named with a landing only where the landing's diff changes the code or the input the row times, in the direction the row moved, and the change can be read from the diff. Every such reason is read from the history: no landing was measured apart (a hosted runner cannot be bisected from a lane, and the lane ran no bench). Every other moved row carries the word `unexplained`, which here means: no landing was found that accounts for the move. Three things moved between the two records beside the crate and are in no `git log` of it: the compiler (1.99.1 to 1.100.0), the dependency graph (resolved on each day; 296 packages then, 298 now; the old run's log names only its 13 held-back packages, each at the version the new run resolved, so the two graphs cannot be compared crate by crate) and the runner's image (20261012.334.1 to 20261111.370.1). The same CPU model is not the same machine.

| reason | rows | p50, new over old | p99, new over old |
|---|---:|---|---|
| `4f6e82f2` (#854), with `054aa396` (#880) on the three recover rows | 8 | 4.694 to 9.692 | 4.993 to 8.850 |
| `5de0f46a`, `c386c117` (#458) | 45 | 1.051 to 1.170 | 0.834 to 1.278 |
| `3cf87636` (#385) | 6 | 0.734 to 0.917 | 0.709 to 1.039 |
| `e448d0af` (#545) | 1 | 1.277 | 1.342 |
| `8311d642` (#817) | 1 | 1.122 | 1.125 |
| `unexplained`, the p50 moved | 33 | 0.851 to 1.346 | 0.742 to 1.470 |
| `unexplained`, the p99 alone | 45 | 0.980 to 1.048 | 0.668 to 1.369 |

61 rows named, 78 `unexplained`.

### The named landings, each with what was read

- **The eight Shamir rows** (`Shamir Secret Sharing/split_private_key (3 of 5)` 6.2 µs to 47.7 µs, `(5 of 10)` 14.6 µs to 68.7 µs, `recover_private_key (3 of 5)` 7.8 µs to 75.3 µs, `to_backup_format` 7.8 µs to 50.5 µs, `from_backup_format` 4.3 µs to 24.0 µs, and the three `Memory/Shamir` rows the same way): `4f6e82f2` (#854, 2026-11-11) made the shares BRC-140's. `split` now writes the tag from the key's public key (`integrity_of`: HASH160 of the compressed key, a public key derivation, 30.6 µs on this runner by `Key Generation/PrivateKey::public_key`) and draws each share's coordinate (an HMAC-SHA-512 output modulo p, a field element of full width) where it was 1 to n; `to_backup_format` reads each point's text back to hold it canonical; `recover_private_key` interpolates over those coordinates and derives the recovered key's public key for the tag. `054aa396` (#880, 2026-11-12) gave the recover rows one modular inverse for the set. The M1 Max record of #993 read the same rows at 3.4 to 8.4 times its old entry and said this entry's next record would move the same way.
- **45 of the 56 `wire_codec` decode rows** (`request_decode` 19 of 28, `result_decode` 26 of 28; +5.1 to +17.0 percent in p50): `5de0f46a` (#458, 2026-10-29) moved the reader's primitives into `src/wallet/wire/reader.rs` and put `.map_err(reference_error)` on each (`read_u8`, `read_i8`, `read_u16_le`, `read_u32_le`, `read_u64_le`, `read_bytes`, `read_var_int`), where each was a plain call of the inner reader; `c386c117` (#458) reads every count through a precision check (`read_optional_count`, `wire_number`). The rows moved as a class, which one row's draw does not do: none of the 56 fell by as much as 1 percent; the eight not past 5 percent whose time is a key's point (the 8 µs `request_decode` rows of `createHmac`, `createSignature`, `decrypt`, `encrypt`, `getPublicKey`, `revealSpecificKeyLinkage`, `verifyHmac`, `verifySignature`) held within 1 percent, and the three others moved by +3.4, +4.4 and -0.7 percent; and the rise follows the count of primitive reads: a result frame of one read (`abortAction`, `waitForAuthentication`) +3.2 ns, of two reads (`getNetwork`) +7.3 ns, a request frame of three reads (`getHeight`, `getNetwork`, `isAuthenticated`) +9.6 to +9.7 ns. Whether the compiler's move shares in it is not separated.
- **Six `wire_codec` encode rows of the frames that carry a string map** (`acquireCertificate/request_encode` -8.3 percent, `acquireCertificate/result_encode` -20.9, `proveCertificate/request_encode` -20.2, `listCertificates/result_encode` -20.1, `discoverByIdentityKey/result_encode` -25.1, `discoverByAttributes/result_encode` -26.6): `3cf87636` (#385, 2026-10-27, after the old record's commit) made the certificate field maps `IndexMap`s, and `write_string_map` writes the map in its order where it collected the keys of a `HashMap`, sorted them and looked each value up.
- **`Template Lock/PushDrop::lock (3 fields)`** (359.0 ns to 458.5 ns): `e448d0af` (#545, 2026-10-31) made `lock` a call of `lock_with_key_bytes`, which builds the lock's two chunks and the fields' chunks as two vectors and extends one with the other (four allocations of chunk storage for three fields, where the one vector `lock` pushed into took two); `PushDrop::new`, the minimal-push and the drop helpers are the old ones. The row rose on the M1 Max too (296.7 ns to 325.9 ns, both of its runs).
- **`merkle_path/verify_depth20_10000`** (224.9 ms to 252.4 ms a batch of 10,000 paths and 200,000 pairs: 1.12 µs to 1.26 µs of batch time a pair): `8311d642` (#817, 2026-11-12) rewrote `hash_pair`, the step `compute_root` runs twenty times a path (`root_from` around it reads as the old one but for that step's `Result`): it checks both texts for hex digits, builds one text of the two, decodes it once and reverses it, where it decoded and reversed each side apart.

### The 78 rows left `unexplained`

**33 moved in p50** (17 up, 16 down; 13 by more than 10 percent, one by more than 25). For each, what the history holds for the code it times:

| row | old p50 ns | new p50 ns | p50 | p99 | what the history holds for its timed code |
|---|---:|---:|---:|---:|---|
| `wire_codec/listActions/result_encode` | 308.6 | 262.7 | -14.9% | -15.6% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/listCertificates/request_encode` | 221.3 | 190.5 | -13.9% | -8.8% | unchanged: the frame and the writer calls byte for byte |
| `Memory/Encryption/aes_gcm_decrypt/64 bytes` | 407.5 | 357.2 | -12.3% | -9.0% | unchanged: no commit to `src/primitives/symmetric.rs` |
| `Symmetric Encryption/decrypt/64 bytes` | 389.1 | 347.0 | -10.8% | -11.4% | unchanged: no commit to `src/primitives/symmetric.rs` |
| `wire_codec/internalizeAction/request_encode` | 305.6 | 277.1 | -9.3% | -7.0% | the frame unchanged; `write_string_array` writes each entry plain (`ad6e350a`, #458), no work added |
| `Script Type Detection/is_multisig (2-of-3)` | 85.5 | 77.7 | -9.1% | -6.8% | unchanged: its functions are outside the diff of `src/script/script.rs` |
| `wire_codec/relinquishCertificate/request_encode` | 168.8 | 153.8 | -8.9% | +0.4% | unchanged: the frame and the writer calls byte for byte |
| `Symmetric Encryption/decrypt/256 bytes` | 550.4 | 504.7 | -8.3% | -1.2% | unchanged: no commit to `src/primitives/symmetric.rs` |
| `wire_codec/createAction/result_encode` | 225.7 | 207.8 | -7.9% | -5.2% | the frame moved by one status byte (`141b5268`, #590); the writer calls unchanged |
| `wire_codec/discoverByIdentityKey/request_encode` | 162.3 | 150.8 | -7.1% | -5.4% | unchanged: the frame and the writer calls byte for byte |
| `Script Type Detection/is_p2pkh` | 46.6 | 43.4 | -6.9% | -3.7% | unchanged: its functions are outside the diff of `src/script/script.rs` |
| `wire_codec/createAction/request_encode` | 425.0 | 396.6 | -6.7% | -6.1% | the frame unchanged; `write_string_array` writes each entry plain (`ad6e350a`, #458), no work added |
| `wire_codec/signAction/result_encode` | 182.4 | 170.5 | -6.6% | -25.8% | the frame moved by one status byte (`141b5268`, #590); the writer calls unchanged |
| `transaction_sign_verify/verify_100_p2pkh` | 10141744.8 | 9495101.8 | -6.4% | -5.8% | changed: `fba61029` (#331), `f8f72db6` (#734), `f5a12929` (#855), `1a3e4c5a` (#843), none shown to be the cause |
| `Script Serialization/to_hex (PushDrop 10 fields)` | 20.8 | 19.6 | -5.7% | -4.9% | unchanged: its functions are outside the diff of `src/script/script.rs` |
| `wire_codec/revealCounterpartyKeyLinkage/request_encode` | 177.6 | 168.6 | -5.0% | -6.4% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/proveCertificate/result_encode` | 98.4 | 103.6 | +5.3% | -8.3% | unchanged: the frame and the writer calls byte for byte |
| `Key Generation/SymmetricKey::random` | 489.9 | 517.5 | +5.6% | +5.4% | unchanged: no commit to `src/primitives/symmetric.rs` |
| `Encoding/from_hex (1KB)` | 3873.3 | 4092.6 | +5.7% | +0.5% | unchanged: no commit to `src/primitives/encoding.rs` |
| `Encoding/to_hex (1KB)` | 4562.1 | 4844.8 | +6.2% | +11.7% | unchanged: no commit to `src/primitives/encoding.rs` |
| `wire_codec/verifySignature/request_encode` | 344.4 | 367.9 | +6.8% | +13.4% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/decrypt/request_encode` | 326.3 | 349.8 | +7.2% | +3.7% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/createHmac/request_encode` | 328.6 | 353.4 | +7.6% | +8.4% | unchanged: the frame and the writer calls byte for byte |
| `script_spend/seed_block` | 60031011.5 | 64629585.5 | +7.7% | +7.6% | changed: 35 commits under `src/script/spend`, none shown to be the cause |
| `wire_codec/revealSpecificKeyLinkage/request_encode` | 322.5 | 361.9 | +12.2% | +17.0% | unchanged: the frame and the writer calls byte for byte |
| `Template Lock/Multisig::lock_from_keys (2-of-3)` | 470.4 | 539.0 | +14.6% | +13.4% | unchanged: `lock_from_keys`, `PublicKey::to_compressed`, `Script::from_chunks` byte for byte (`f783d80d`, #625, changed `Multisig::lock`, which the row does not call) |
| `wire_codec/getHeaderForHeight/result_encode` | 57.4 | 65.9 | +14.8% | +14.6% | unchanged: the frame and the writer calls byte for byte |
| `Script Parsing/Script::from_hex (P2PKH)` | 206.4 | 246.7 | +19.5% | +47.0% | unchanged: its functions are outside the diff of `src/script/script.rs` |
| `wire_codec/listOutputs/result_encode` | 153.6 | 183.7 | +19.6% | +32.2% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/listActions/request_encode` | 154.6 | 188.7 | +22.1% | +17.8% | the frame unchanged; `write_string_array` writes each entry plain (`ad6e350a`, #458), no work added |
| `wire_codec/signAction/request_encode` | 159.4 | 196.8 | +23.4% | +16.3% | unchanged: the frame and the writer calls byte for byte |
| `wire_codec/listOutputs/request_encode` | 157.4 | 196.7 | +25.0% | +30.2% | the frame unchanged; `write_string_array` writes each entry plain (`ad6e350a`, #458), no work added |
| `wire_codec/relinquishOutput/request_encode` | 112.3 | 151.2 | +34.6% | +44.5% | unchanged: the frame and the writer calls byte for byte |

Read with it: `git log 4b1c4688..d892e206` holds no commit to `src/primitives/symmetric.rs`, `src/primitives/encoding.rs` or `src/primitives/hash.rs`. The diff of `src/script/script.rs` changes `parse_chunks` (#634), moves `from_asm` and `to_asm` out (#634, #723) and changes `set_chunk_opcode`; `from_hex`, `from_binary`, `to_hex`, `to_binary`, `is_p2pkh`, `is_p2pk` and `is_multisig` are outside it. The wire writer's diff changes `write_string_array` (`ad6e350a`), `write_string_map` and the keyring writer (`3cf87636`), `write_send_with_result_status` (`141b5268`) and `checked_field_names`, nothing else; and of the 56 recorded frames the bench reads, 54 are the old bytes (`checks/wire-fixtures-full-case.txt`: the result frames of `createAction` and `signAction` moved by one status byte each, at the same length). So `wire_codec/relinquishOutput/request_encode` rose 34.6 percent on a frame and writer calls that are byte for byte the old ones: a move of that size needs no change of the crate on rows of 100 to 400 ns. `script_spend/seed_block` (+7.7 percent, 6.00 µs to 6.46 µs an input) and `transaction_sign_verify/verify_100_p2pkh` (-6.4 percent) are the two rows whose code did change, in many commits, with no one of them read to be the cause.

One of the 33 corrects a reading this lane inherited. `Template Lock/Multisig::lock_from_keys (2-of-3)` rose 14.6 percent (470.4 ns to 539.0 ns), and the M1 Max record of #993 (`docs/lanes/bench-245-m1max.md`, "Before and after", and its pull request's body) named `f783d80d` (#625) for the row's rise there: "the lock checks its keys' tags". That commit changed `Multisig::lock`, the door that takes the keys' bytes. The bench calls `lock_from_keys`, which is byte for byte the old one, as are `PublicKey::to_compressed`, `Script::from_chunks` and `src/script/locking_script.rs` under it (each compared at `4b1c4688` and `d892e206`), so no landing explains the row here. Over the M1 Max record's own range (`67559f9d` to `b701c06f`) `lock_from_keys` is the same too, and the one change under it is `to_compressed`'s call into k256 (0.13's `to_encoded_point`, 0.14's `to_sec1_point`: #125, which lies ahead of the old Linux record). That record's sentence is left as written; it is not true of the code.

**45 moved in p99 alone**, the p50 within 5 percent: 13 down and 32 up. A p99 of 100 sample averages is set by its one or two slowest samples. In the 13 that fell, the slow tail was the old record's (its p99 over its p50 from 1.07 to 1.56, the new one's from 1.02 to 1.11: `Verification/PublicKey::verify (secp256k1)` p99 125,858 ns to 84,103 ns at a p50 of 80,489 ns and 80,205 ns); in the 32 that rose it is the new record's (1.04 to 1.39). No landing is named for a tail.

| row | p50 | p99 | old p99 over p50 | new p99 over p50 |
|---|---:|---:|---:|---:|
| `Verification/PublicKey::verify (secp256k1)` | -0.4% | -33.2% | 1.56 | 1.05 |
| `Template Sign/P2PKH::sign_with_sighash` | +1.2% | -21.2% | 1.31 | 1.02 |
| `Script Parsing/Script::from_asm (P2PKH)` | +2.6% | -21.1% | 1.37 | 1.05 |
| `Symmetric Encryption/encrypt/1024 bytes` | -1.0% | -16.4% | 1.22 | 1.03 |
| `wire_codec/getVersion/request_encode` | +3.0% | -14.5% | 1.33 | 1.11 |
| `Schnorr Proofs/Schnorr::verify_proof` | +1.6% | -11.5% | 1.18 | 1.03 |
| `Hashing/sha512 (1KB)` | -0.3% | -8.9% | 1.15 | 1.05 |
| `wire_codec/getNetwork/request_encode` | +2.9% | -8.9% | 1.15 | 1.02 |
| `WIF and Address/PrivateKey::to_wif` | +0.4% | -7.1% | 1.10 | 1.02 |
| `wire_codec/relinquishOutput/result_encode` | -0.0% | -6.7% | 1.09 | 1.02 |
| `wire_codec/relinquishCertificate/result_encode` | +0.0% | -5.5% | 1.18 | 1.11 |
| `Symmetric Encryption/decrypt/1024 bytes` | -1.9% | -5.4% | 1.07 | 1.03 |
| `Script Serialization/to_binary (PushDrop 10 fields)` | +0.0% | -5.1% | 1.10 | 1.04 |
| `transaction_sign_verify/sign_100_p2pkh` | +1.4% | +5.0% | 1.01 | 1.04 |
| `Template Lock/P2PKH::lock` | +2.7% | +5.1% | 1.04 | 1.07 |
| `wire_codec/revealSpecificKeyLinkage/request_decode` | -0.1% | +5.5% | 1.02 | 1.08 |
| `wire_codec/waitForAuthentication/result_encode` | +0.1% | +5.7% | 1.13 | 1.20 |
| `Script Type Detection/is_p2pk` | +4.8% | +5.9% | 1.06 | 1.07 |
| `Script Serialization/to_asm (P2PKH)` | +2.6% | +5.9% | 1.03 | 1.06 |
| `Signing/P256PrivateKey::sign` | +0.8% | +6.0% | 1.01 | 1.06 |
| `wire_codec/verifyHmac/result_encode` | +0.1% | +6.0% | 1.02 | 1.08 |
| `wire_codec/revealSpecificKeyLinkage/result_encode` | +1.8% | +6.0% | 1.06 | 1.11 |
| `wire_codec/getVersion/result_encode` | +1.8% | +6.1% | 1.02 | 1.07 |
| `wire_codec/createHmac/request_decode` | -0.3% | +6.1% | 1.01 | 1.07 |
| `WIF and Address/PublicKey::to_address` | +0.7% | +7.1% | 1.01 | 1.08 |
| `wire_codec/encrypt/request_encode` | +4.3% | +7.2% | 1.01 | 1.04 |
| `beef_stream/structure/1000000` | -1.6% | +7.2% | 1.04 | 1.13 |
| `wire_codec/internalizeAction/result_encode` | -0.0% | +7.6% | 1.01 | 1.09 |
| `Sighash/compute_sighash (5 inputs, 5 outputs)` | -2.0% | +7.7% | 1.02 | 1.12 |
| `wire_codec/abortAction/result_encode` | +0.1% | +8.8% | 1.02 | 1.10 |
| `wire_codec/abortAction/request_encode` | +0.5% | +8.9% | 1.04 | 1.13 |
| `wire_codec/listCertificates/request_decode` | +4.4% | +9.5% | 1.02 | 1.07 |
| `wire_codec/waitForAuthentication/request_encode` | +2.9% | +9.7% | 1.01 | 1.08 |
| `wire_codec/isAuthenticated/request_encode` | +3.7% | +10.8% | 1.03 | 1.10 |
| `Sighash/sighash x50 inputs, free fn (no midstate reuse)` | +2.7% | +10.9% | 1.01 | 1.10 |
| `beef_stream/scripts/1000000` | +0.9% | +11.0% | 1.02 | 1.12 |
| `wire_codec/revealSpecificKeyLinkage/result_decode` | -0.7% | +12.0% | 1.06 | 1.19 |
| `Memory/Signing/ecdsa_sign` | +1.4% | +12.3% | 1.01 | 1.12 |
| `wire_codec/createSignature/request_decode` | +0.0% | +14.0% | 1.05 | 1.20 |
| `sha512` | -0.5% | +14.3% | 1.01 | 1.16 |
| `wire_codec/getNetwork/result_encode` | -0.0% | +15.8% | 1.02 | 1.18 |
| `wire_codec/encrypt/request_decode` | +0.7% | +18.9% | 1.18 | 1.39 |
| `wire_codec/createHmac/result_encode` | +0.1% | +20.1% | 1.05 | 1.26 |
| `wire_codec/discoverByAttributes/result_decode` | +3.4% | +22.8% | 1.01 | 1.20 |
| `wire_codec/getHeight/result_encode` | +2.5% | +36.9% | 1.02 | 1.36 |

### The run's own witness: one operation in two bench binaries

Thirteen operations are timed twice in one run, by `primitives_bench` and by `memory_bench`, on keys and payloads of their own. Their moves against the old entry:

| operation, in `primitives_bench` and in `memory_bench` | p50 new/old | p50 new/old (twin) | p99 new/old | p99 new/old (twin) |
|---|---:|---:|---:|---:|
| `Symmetric Encryption/encrypt/64 bytes`, `Memory/Encryption/aes_gcm_encrypt/64 bytes` | 0.979 | 0.988 | 1.009 | 0.999 |
| `Symmetric Encryption/encrypt/1024 bytes`, `Memory/Encryption/aes_gcm_encrypt/1024 bytes` | 0.990 | 0.985 | 0.836 | 0.995 |
| `Symmetric Encryption/encrypt/16384 bytes`, `Memory/Encryption/aes_gcm_encrypt/16384 bytes` | 1.000 | 1.002 | 1.005 | 1.030 |
| `Symmetric Encryption/decrypt/64 bytes`, `Memory/Encryption/aes_gcm_decrypt/64 bytes` | 0.892 | 0.877 | 0.886 | 0.910 |
| `Symmetric Encryption/decrypt/1024 bytes`, `Memory/Encryption/aes_gcm_decrypt/1024 bytes` | 0.981 | 0.955 | 0.946 | 0.959 |
| `Symmetric Encryption/decrypt/16384 bytes`, `Memory/Encryption/aes_gcm_decrypt/16384 bytes` | 0.998 | 1.000 | 0.989 | 1.029 |
| `Key Derivation/PrivateKey::derive_child`, `Memory/KeyDerivation/brc42_derive_child` | 1.013 | 1.018 | 0.979 | 1.044 |
| `Key Derivation/PrivateKey::derive_shared_secret`, `Memory/KeyDerivation/ecdh_shared_secret` | 1.016 | 1.016 | 0.978 | 1.045 |
| `Shamir Secret Sharing/split_private_key (3 of 5)`, `Memory/Shamir/split_3_of_5` | 7.674 | 7.752 | 7.491 | 8.120 |
| `Shamir Secret Sharing/split_private_key (5 of 10)`, `Memory/Shamir/split_5_of_10` | 4.694 | 4.836 | 5.024 | 4.993 |
| `Shamir Secret Sharing/recover_private_key (3 of 5)`, `Memory/Shamir/recover_3_of_5` | 9.692 | 8.938 | 8.260 | 8.850 |
| `Signing/PrivateKey::sign (secp256k1)`, `Memory/Signing/ecdsa_sign` | 1.020 | 1.014 | 1.004 | 1.123 |
| `Verification/PublicKey::verify (secp256k1)`, `Memory/Signing/ecdsa_verify` | 0.996 | 0.979 | 0.668 | 0.991 |

Outside Shamir (ten pairs) the two p50 ratios of a pair are within 2.7 percent of each other, and the two p99 ratios are apart by more than 5 percent in five pairs (48 percent on `PublicKey::verify`, where one binary's old tail was slow and the other's was not). So within this one record a p50 move is the run's (the code, the compiler, the graph or the machine: `decrypt` of 64 bytes fell 10.8 and 12.3 percent in the two binaries with no commit to its file), and a p99 move beside a steady p50 is a tail.

### The RSS rows

`beef_stream`, peak bytes, old then new: structure 1 MB 4,743,168 then 4,907,008; scripts 1 MB 4,751,360 then 4,825,088; structure 10 MB 6,443,008 then 6,258,688; scripts 10 MB 6,684,672 then 6,418,432; the entries 1,002 and 10,002 in both; the sampled slope 0.189 then 0.150 (structure) and 0.215 then 0.177 (scripts) bytes of RSS a byte of BEEF. The gate judges no RSS figure.

## The question for the captain: is the entry a fair floor, and do the three repeats apply

One record is one draw of a hosted runner, and 78 of its rows moved past the tolerance with no landing to name.

- `benches/README.md`'s rule ("If three Linux repeats demonstrate noise above 5%, report their numbers before proposing a wider threshold") is a condition on a proposal to widen the threshold. It is not a condition on a record, and this change proposes no threshold. As written it does not apply to this pull request.
- It will apply to what follows. The plain dispatch the README asks for after the landing is a second draw; it prints every row's p99 against this entry. The witness above (five of ten twin pairs with p99 moves apart by more than 5 percent inside one run) and the M1 Max record's two back-to-back runs (30 of 212 rows more than 5 percent over the other run's p99, #993) both say a plain comparison is likely to print `REGRESSION` rows on tails alone, on rows whose p50 holds. If it does on this CPU, that run and two more are the three repeats, and their numbers go to #911's row on the gate's noise before anything is proposed.
- What the repeats would settle for this entry: the 45 p99-alone rows (a tail that is high in this record is a floor that passes a regression of that size on that row; a tail that is low fails a later run on noise) and the 33 p50 movers (a p50 that returns to the old figure in a later draw was the draw; one that stays is the compiler's, the graph's or the code's, and the entry is right for it). Nothing in one record tells which.
- The lane's reading, for a decision that is the captain's: the entry stands as recorded, one run whole. Taking the lower or the higher of two records row by row would be a record by hand, which the README now rules out.

## The commit's bytes

The tool has no door that takes a proposed entry: `--record` measures, and refuses `--from-run` (`tools/bench-compare/src/main.rs:245-247`). The artifact's file is not copied whole either, for two reasons the comparison shows: `--record` writes the entries in key order (the Linux entry ahead of the M1 Max one, the other way round from the committed file), and it reads the M1 Max entry and prints it again through a reader that is not the round-trip one (`serde_json` without `float_roundtrip`), so 38 of that entry's 636 numbers come back one unit in the last place off (`Hashing/sha512_hmac (1KB)` p99 `1097.1395107105475` committed, `1097.1395107105477` in the artifact; the worst relative difference 2.1e-16; `scripts/m1diff.py`). So the entry's lines are placed as text, by this script (`scripts/place.py`, run with `python3 -I`):

```python
"""Put one machine's entry of a proposed baseline into benches/baseline.json as text.

usage: place.py KEY COMMITTED PROPOSED RUN OUT

The entry's lines are copied from PROPOSED (the artifact's linux-baseline.json, written by
`bench-compare --record`) byte for byte; no number is parsed and printed again. Every other
byte of COMMITTED is kept: the other entries, their order, the indentation, the missing
final newline. RUN is the same run's run.json: the entry must be its text, indented.
"""
import json
import sys


def span(lines, key):
    """The [start, end] line indexes of `key`'s entry under "platforms" (indent 4)."""
    opening = '    ' + json.dumps(key) + ': {'
    starts = [i for i, line in enumerate(lines) if line == opening]
    if len(starts) != 1:
        raise SystemExit('%s: found %d times' % (key, len(starts)))
    end = next(i for i in range(starts[0] + 1, len(lines)) if lines[i] in ('    }', '    },'))
    return starts[0], end


key, committed, proposed, run, out = sys.argv[1:6]
old = open(committed, encoding='utf-8', newline='').read()
new = open(proposed, encoding='utf-8', newline='').read()
old_lines, new_lines = old.split('\n'), new.split('\n')
a, b = span(old_lines, key)
c, d = span(new_lines, key)
entry = new_lines[c:d] + ['    }']

# the proposed entry is the run's own text, four spaces in
run_lines = open(run, encoding='utf-8', newline='').read().split('\n')
expected = ['    ' + json.dumps(key) + ': ' + run_lines[0]] + ['    ' + line for line in run_lines[1:]]
if entry != expected:
    raise SystemExit('the proposed entry is not run.json, indented')

closing = old_lines[b]  # '    }' or '    },': the committed file's comma stays
placed = old_lines[:a] + entry[:-1] + [closing] + old_lines[b + 1:]
text = '\n'.join(placed)
if json.loads(text)['platforms'][key] != json.loads(new)['platforms'][key]:
    raise SystemExit('the placed entry does not parse to the proposed one')
if list(json.loads(text)['platforms']) != list(json.loads(old)['platforms']):
    raise SystemExit('the entries or their order moved')
open(out, 'w', encoding='utf-8', newline='').write(text)
print('placed %s: lines %d to %d of the committed file (%d lines) by %d lines of the proposed one'
      % (key, a + 1, b + 1, b - a + 1, len(entry)))
```

```sh
python3 -I place.py 'linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores' \
  benches/baseline.json artifact/linux-baseline.json artifact/bench-results/run.json baseline-after.json
# placed linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores: lines 1134 to 2238 of the committed file (1105 lines) by 1130 lines of the proposed one
```

No number is parsed and printed again and nothing is typed. The comparison (`scripts/bytes.py`: the two entries extracted from the file before and after, and from the artifact):

```text
before    73789 bytes  sha256 06755f5435a585382b1dd0b348282e59d50ee32acf03fa4b755d1a9e75ed8720  ends with a newline: False  keys in order: ['macos-aarch64 / Apple M1 Max / 10 cores', 'linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores']
after     74691 bytes  sha256 16c1b4d90da7953df84c48d530fbf3a0636b34ff1917a738aebb41b318a77ff7  ends with a newline: False  keys in order: ['macos-aarch64 / Apple M1 Max / 10 cores', 'linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores']
proposed  74670 bytes  sha256 f6220bee57a6848ac3d94f4bdc6a5c371fdd6201d36b87e2dd8e9ec761b2b938  ends with a newline: False  keys in order: ['linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores', 'macos-aarch64 / Apple M1 Max / 10 cores']
M1 Max entry before:   bytes 42..37336  37294 bytes  sha256 3783cf6649cfb95c6f17944843111a536b218c1cb776a226cc242262001cc863
M1 Max entry after:    bytes 42..37336  37294 bytes  sha256 3783cf6649cfb95c6f17944843111a536b218c1cb776a226cc242262001cc863
M1 Max entry before == after, byte for byte: True
M1 Max entry in the proposed file == committed: False (37273 bytes there)
Linux entry before:    bytes 37338..73783  36445 bytes  sha256 fb9cf4e61fe2583393ed4d856c56c474b194349300a8da046a3d3d44381e61e5
Linux entry after:     bytes 37338..74685  37347 bytes  sha256 50f359b1f5f843634dd48c01be0b757710d45ec2cab43d0a42bcf0d74841edc7
Linux entry proposed:  bytes 42..37389  37347 bytes  sha256 50f359b1f5f843634dd48c01be0b757710d45ec2cab43d0a42bcf0d74841edc7
Linux entry after == the proposed entry, byte for byte: True
bytes ahead of the Linux entry before == after: True (37338 bytes)
bytes behind the Linux entry before == after: True (b'\n  }\n}')
ONLY THE LINUX ENTRY MOVED
```

`git diff -U0 -- benches/baseline.json` holds 220 hunks, the least old line touched 1140 and the greatest 2234, inside the Linux entry's lines 1134 to 2238; 458 insertions, 433 deletions. The file has no final newline, as before.

The tool reads the result (the read-only mode, `--from-run`, which measures nothing): the record's `run.json` against the file as committed before is `bench-compare: benchmark inventory changed; baseline update needs a PR that says so`, exit 2 (`checks/run-vs-old-entry.out`); against the new file it is `PASS (9 of 9 benches measured): p99 threshold is +5%`, exit 0, 212 rows at +0.00% (`checks/run-vs-new-file.out`).

## What the tests hold of the entries (#911)

The row from the reads of #993: its CHANGELOG paragraph said, under "Pinned by", that `tools/bench-compare`'s 10 tests pass, "two of which read the file". The code: the eight tests of `src/tests.rs` judge a `fixture()` built in the test and never open the file. The two of `tests/from_run.rs` call `recorded()`, which parses the file as a `serde_json::Value` and takes `platforms.values().next()`: the tool's `serde_json` has no `preserve_order` (its lockfile holds no `indexmap`), so an object is a sorted map and that entry is the one whose key sorts ahead of the others, `linux-x86_64 ...`. Each test then writes its own scratch baseline (empty, or that one entry) and runs the binary with `--from-run`. Neither reads a member of the M1 Max entry.

The run: a scratch copy of `tools/bench-compare` (`git archive` of the tip) beside a `benches/baseline.json` edited by hand (`scripts/variants.py`, one text edit each), `cargo +1.100.0 test --locked --no-fail-fast`, and the scratch binary's read-only gate for the Linux record's run against the same file (`checks/which-tests-fail.out`):

| the hand edit | tests passed of 10 | tests failed | the gate for the Linux run |
|---|---:|---|---|
| none | 10 | none | exit 0, `PASS` |
| M1 Max: the p99 of `Hashing/sha256 (1KB)` multiplied by ten | 10 | none | exit 0, `PASS` |
| M1 Max: the required row `sha256` deleted | 10 | none | exit 0, `PASS` |
| M1 Max: that p99 put under its p50 | 10 | none | exit 0, `PASS` |
| M1 Max: an unknown member added | 10 | none | exit 2, `unknown field` (the whole file refused) |
| M1 Max: the entry deleted whole | 10 | none | exit 0, `PASS` |
| M1 Max: a comma removed (the file no longer JSON) | 8 | both tests of `tests/from_run.rs` | exit 2 |
| Linux: the p99 of `Hashing/sha256 (1KB)` doubled | 10 | none | exit 0, `PASS` |
| Linux: the required row `sha256` deleted | 8 | both tests of `tests/from_run.rs` | exit 2, `missing benchmark: sha256` |

On the file as #993 left it (the old Linux entry) the M1 Max p99 multiplied by ten and the M1 Max entry deleted whole pass all ten as well. So: no test in the tree reads the M1 Max entry; a hand edit to it fails a test only where it breaks the file's JSON; and no test holds a number of either entry. The corrected sentence is in `CHANGELOG.md` (the M1 Max paragraph, "Pinned by") and the rows are `benches/README.md`'s new section "What the tests hold of the entries". No other test in the tree opens the file (`git grep -l 'baseline.json' tests tools .github` names `tools/bench-compare/tests/from_run.rs`, the tool's `src/main.rs` and `bench.yml`).

The other sentence owed (#911, the captain's answer on the record staying whole) is in `benches/README.md` where the section says who records what: a machine's entry is recorded whole, in one run of `--record`, and the record is the captain's act, never row by row, one bench at a time or by hand, the form #993 used for the M1 Max entry.

## A second CPU in the pool

Read from the job log of run 43645481398 (2026-11-14, 21:57Z, a dispatch with the record input on `lane/bench-245-m1max-now` at `41ed1c66`, seven hours before this record): `Machine: INTEL(R) XEON(R) PLATINUM 8573C, 4 cores (linux-x86_64)`, 212 record lines, success. Its artifact was not downloaded. `benches/baseline.json` holds no entry for that key, and this change adds none: the entry here is the run named in the lane's brief, of one commit and one CPU.

What it means for the next step: a plain dispatch after the landing that lands on that CPU prints `NO BASELINE ENTRY: linux-x86_64 / INTEL(R) XEON(R) PLATINUM 8573C / 4 cores`, exits 3, and the job warns and succeeds, having compared nothing. A green run is not a comparison: the log's `Machine:` line says which it was. The two record dispatches of 2026-11-14 and 2026-11-15 drew two CPUs.

## What the gate ran

Each in the foreground, one cargo at a time, `CARGO_BUILD_JOBS=2`, the target directory outside the checkout.

- **The lint job's Rustfmt step**, its three lines on this base: `cargo fmt --all -- --check`, `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`, `cargo fmt --manifest-path fuzz/corpus-gen/Cargo.toml -- --check`, each with `+1.100.0` (the job's `stable`; the host's is 1.95.0): exit 0. And `bench.yml`'s step for the tool: its fmt and `cargo clippy --locked --all-targets -- -D warnings`: exit 0.
- **The tests that read `benches/baseline.json`**: `git grep -l 'baseline.json' tests tools .github` names `tools/bench-compare/tests/from_run.rs` (its two tests) beside the tool's `src/main.rs` and `bench.yml`, which are no tests; no file under `tests/` opens it. `cargo test --locked --manifest-path tools/bench-compare/Cargo.toml`: 10 passed (8 unit, the 2 of `from_run`), 0 failed, on the file as committed here.
- **The comparison, read-only** (`--from-run`, which measures nothing and writes nothing): `cargo run --locked --manifest-path tools/bench-compare/Cargo.toml -- --from-run <artifact>/bench-results/run.json` printed `Machine: AMD EPYC 7763 64-Core Processor, 4 cores (linux-x86_64)`, the four RSS rows, the two slopes (0.150187 and 0.177038), 212 rows each `PASS` at `+0.00%`, and `PASS (9 of 9 benches measured): p99 threshold is +5%`; exit 0. The same run against the file before: exit 2, `benchmark inventory changed`. This is the tool judging the committed entry against the run it came from; a comparison of a new measurement is the captain's dispatch.
- **The front pages** (the CHANGELOG moved): `cargo test --test front_page`: 10 passed; `python3 -B .github/scripts/test_front_pages.py`: 97 tests, OK.
- `python3 -B .github/scripts/rows_from_sources.py --check`: 0 refusals (its 10 unit tests OK).
- `tools/ratchet/run --check --against d892e206`: all 7 counters, oversized-file limits and mutation floors pass.
- gitleaks 8.30.1 in git mode from the root over `d892e206..HEAD`: no leaks.

Beyond the gate, for the row of #911: the nine hand edits above, `cargo +1.100.0 test --locked --no-fail-fast` on a scratch copy of the tool with a target directory of its own. No clippy of the crate and no test of it beyond `front_page`: no Rust file is touched. Nothing was run on Linux: that witness is CI's. Both target directories were removed at the lane's end.

## What is left

- **The comparison dispatch**, the captain's, after the push: `gh workflow run bench.yml -R Calhooon/bsv-rs --ref <the pull request's branch>` (no record input). Read its `Machine:` line: on the EPYC it prints the table against this entry and `PASS` or `FAIL`; on another CPU it exits 3 and compares nothing (dispatch again, or record that CPU's entry by a record dispatch at the tip).
- **The 78 `unexplained` rows**: the section "The question for the captain". Told only by repeats on this CPU.
- **A sentence of #993's record that is not true of the code**: `docs/lanes/bench-245-m1max.md` names `f783d80d` (#625) for the rise of `Template Lock/Multisig::lock_from_keys (2-of-3)`; the bench does not call the door that commit changed (the section on the unexplained rows). Left as written, for the captain.
- **`--record` moves the other entries' numbers** by one unit in the last place where its reader does not round-trip (38 of 636 here). A change of `tools/bench-compare` (the `float_roundtrip` feature of its `serde_json`), its own lane; until then an entry is placed as text.
- **The tests hold no number of an entry and nothing of an entry that does not sort ahead of the others.** Stated in `benches/README.md`. A test that reads every entry through the tool's own reader and `validate_run` would hold the shape of each; nothing can hold the numbers but the review of a record.
- Three design records cite the old Linux entry's figures by commit and by the file's line (`docs/design/90-interpreter-speed.md:39`, `92-sign-verify-throughput.md:21`, `93-merkle-verify-and-header-window.md:57`, each "at `4b1c4688`"): dated records, left as written; the lines they name hold other rows now.

## The evidence

`/Volumes/Lanes/out/bsv-rs/bench-245-linux-entry/`: `artifact/` (the download), `baseline-before.json` and `baseline-after.json`, `scripts/` (`place.py`, `bytes.py`, `table.py`, `movers.py`, `variants.py`, `m1diff.py`), `variants/` and `variants-before/` (the hand edits), `checks/` (the byte comparison, the tool's read-only answers, the tests' results on each hand edit, the fixture comparison, the landings since the old record), `tables/`, `logs/` (the three job logs read by `gh run view --log`, the scratch runs, the gate). sha256 of `benches/baseline.json`: `06755f54...8720` before, `16c1b4d9...7ff7` after.

## The table

Every row, the old entry (2026-10-27, `4b1c4688`) against the new (2026-11-15, `d892e206`), nanoseconds; "past 5%" says which of the two figures moved by more than 5 percent; the five rows without an old figure are #880's.

| row | old p50 ns | new p50 ns | p50 new/old | old p99 ns | new p99 ns | p99 new/old | past 5% | reason |
|---|---:|---:|---:|---:|---:|---:|---|---|
| `Encoding/from_base58 (1KB)` | 452303.47 | 453896.79 | 1.004 | 456012.61 | 463964.26 | 1.017 |  |  |
| `Encoding/from_hex (1KB)` | 3873.31 | 4092.59 | 1.057 | 4379.71 | 4399.72 | 1.005 | p50 | unexplained |
| `Encoding/to_base58 (1KB)` | 1446739.79 | 1446921.52 | 1.000 | 1452231.38 | 1456051.76 | 1.003 |  |  |
| `Encoding/to_hex (1KB)` | 4562.07 | 4844.76 | 1.062 | 4797.51 | 5357.36 | 1.117 | both | unexplained |
| `Hashing/hash160 (1KB)` | 933.76 | 935.20 | 1.002 | 937.90 | 972.77 | 1.037 |  |  |
| `Hashing/ripemd160 (1KB)` | 3784.61 | 3788.11 | 1.001 | 4065.98 | 3923.60 | 0.965 |  |  |
| `Hashing/sha1 (1KB)` | 641.45 | 641.07 | 0.999 | 649.89 | 654.20 | 1.007 |  |  |
| `Hashing/sha256 (1KB)` | 694.16 | 694.29 | 1.000 | 698.14 | 698.35 | 1.000 |  |  |
| `Hashing/sha256_hmac (1KB)` | 834.26 | 837.55 | 1.004 | 851.62 | 851.46 | 1.000 |  |  |
| `Hashing/sha256d (1KB)` | 746.17 | 746.29 | 1.000 | 749.59 | 755.41 | 1.008 |  |  |
| `Hashing/sha512 (1KB)` | 2220.65 | 2213.01 | 0.997 | 2559.33 | 2331.21 | 0.911 | p99 | unexplained (p99 alone) |
| `Hashing/sha512_hmac (1KB)` | 2996.27 | 2987.44 | 0.997 | 3042.84 | 3180.80 | 1.045 |  |  |
| `Key Derivation/PrivateKey::derive_child` | 61682.31 | 62513.36 | 1.013 | 65705.28 | 64295.72 | 0.979 |  |  |
| `Key Derivation/PrivateKey::derive_shared_secret` | 60919.39 | 61880.57 | 1.016 | 69493.40 | 67971.37 | 0.978 |  |  |
| `Key Derivation/PublicKey::derive_child` | 122573.60 | 124170.61 | 1.013 | 126933.45 | 130370.40 | 1.027 |  |  |
| `Key Derivation/PublicKey::mul_scalar` | 60690.39 | 61798.50 | 1.018 | 65868.95 | 63832.36 | 0.969 |  |  |
| `Key Generation/P256PrivateKey::public_key` | 3.39 | 3.41 | 1.007 | 3.46 | 3.53 | 1.021 |  |  |
| `Key Generation/P256PrivateKey::random` | 93125.48 | 93761.01 | 1.007 | 93871.72 | 95816.73 | 1.021 |  |  |
| `Key Generation/PrivateKey::public_key` | 29935.29 | 30550.29 | 1.021 | 30168.78 | 31271.31 | 1.037 |  |  |
| `Key Generation/PrivateKey::random` | 549.22 | 575.10 | 1.047 | 560.80 | 581.20 | 1.036 |  |  |
| `Key Generation/SymmetricKey::random` | 489.90 | 517.55 | 1.056 | 503.90 | 530.98 | 1.054 | both | unexplained |
| `Memory/Encryption/aes_gcm_decrypt/1024 bytes` | 1247.51 | 1191.16 | 0.955 | 1279.90 | 1227.35 | 0.959 |  |  |
| `Memory/Encryption/aes_gcm_decrypt/16384 bytes` | 14125.01 | 14132.00 | 1.000 | 14225.52 | 14639.22 | 1.029 |  |  |
| `Memory/Encryption/aes_gcm_decrypt/64 bytes` | 407.50 | 357.21 | 0.877 | 417.47 | 380.08 | 0.910 | both | unexplained |
| `Memory/Encryption/aes_gcm_encrypt/1024 bytes` | 1822.16 | 1795.71 | 0.985 | 1852.55 | 1843.89 | 0.995 |  |  |
| `Memory/Encryption/aes_gcm_encrypt/16384 bytes` | 14956.25 | 14978.69 | 1.002 | 15161.38 | 15623.35 | 1.030 |  |  |
| `Memory/Encryption/aes_gcm_encrypt/64 bytes` | 906.77 | 895.73 | 0.988 | 918.38 | 917.21 | 0.999 |  |  |
| `Memory/KeyDerivation/brc42_derive_child` | 61731.08 | 62869.37 | 1.018 | 62446.51 | 65225.16 | 1.044 |  |  |
| `Memory/KeyDerivation/ecdh_shared_secret` | 60798.98 | 61777.37 | 1.016 | 63709.54 | 66572.03 | 1.045 |  |  |
| `Memory/Shamir/recover_3_of_5` | 8046.15 | 71917.78 | 8.938 | 8382.35 | 74180.06 | 8.850 | both | `4f6e82f2` (#854), `054aa396` (#880) |
| `Memory/Shamir/split_3_of_5` | 6127.25 | 47498.37 | 7.752 | 6231.11 | 50598.45 | 8.120 | both | `4f6e82f2` (#854) |
| `Memory/Shamir/split_5_of_10` | 14133.85 | 68348.77 | 4.836 | 15135.08 | 75574.58 | 4.993 | both | `4f6e82f2` (#854) |
| `Memory/Signing/ecdsa_sign` | 69726.26 | 70731.94 | 1.014 | 70731.62 | 79461.64 | 1.123 | p99 | unexplained (p99 alone) |
| `Memory/Signing/ecdsa_verify` | 81328.49 | 79609.98 | 0.979 | 84886.35 | 84151.28 | 0.991 |  |  |
| `Schnorr Proofs/Schnorr::generate_proof` | 153363.83 | 155632.04 | 1.015 | 162834.74 | 158678.92 | 0.974 |  |  |
| `Schnorr Proofs/Schnorr::verify_proof` | 319808.52 | 324841.82 | 1.016 | 376344.94 | 333013.72 | 0.885 | p99 | unexplained (p99 alone) |
| `Script Parsing/Script::from_asm (P2PKH)` | 562.52 | 577.32 | 1.026 | 769.80 | 607.12 | 0.789 | p99 | unexplained (p99 alone) |
| `Script Parsing/Script::from_binary (P2PKH)` | 23.71 | 23.70 | 0.999 | 24.13 | 24.65 | 1.022 |  |  |
| `Script Parsing/Script::from_hex (P2PKH)` | 206.37 | 246.70 | 1.195 | 209.00 | 307.21 | 1.470 | both | unexplained |
| `Script Serialization/to_asm (P2PKH)` | 314.62 | 322.90 | 1.026 | 323.26 | 342.41 | 1.059 | p99 | unexplained (p99 alone) |
| `Script Serialization/to_binary (P2PKH)` | 18.38 | 18.39 | 1.000 | 19.77 | 19.31 | 0.976 |  |  |
| `Script Serialization/to_binary (PushDrop 10 fields)` | 18.38 | 18.39 | 1.000 | 20.25 | 19.21 | 0.949 | p99 | unexplained (p99 alone) |
| `Script Serialization/to_hex (P2PKH)` | 19.62 | 19.01 | 0.969 | 20.77 | 19.76 | 0.951 |  |  |
| `Script Serialization/to_hex (PushDrop 10 fields)` | 20.83 | 19.64 | 0.943 | 21.46 | 20.41 | 0.951 | p50 | unexplained |
| `Script Type Detection/is_multisig (2-of-3)` | 85.48 | 77.73 | 0.909 | 88.15 | 82.17 | 0.932 | both | unexplained |
| `Script Type Detection/is_p2pk` | 55.10 | 57.74 | 1.048 | 58.32 | 61.73 | 1.059 | p99 | unexplained (p99 alone) |
| `Script Type Detection/is_p2pkh` | 46.59 | 43.38 | 0.931 | 48.65 | 46.87 | 0.963 | p50 | unexplained |
| `Shamir Secret Sharing/from_backup_format` | 4327.57 | 23954.77 | 5.535 | 4423.90 | 27713.98 | 6.265 | both | `4f6e82f2` (#854) |
| `Shamir Secret Sharing/recover_private_key (10 of 20)` | | 117298.55 | | | 144407.03 | | | new row (#880) |
| `Shamir Secret Sharing/recover_private_key (2 of 3)` | | 75518.40 | | | 83106.94 | | | new row (#880) |
| `Shamir Secret Sharing/recover_private_key (255 of 255)` | | 20528063.25 | | | 21659327.01 | | | new row (#880) |
| `Shamir Secret Sharing/recover_private_key (3 of 5)` | 7771.71 | 75324.65 | 9.692 | 9923.55 | 81967.49 | 8.260 | both | `4f6e82f2` (#854), `054aa396` (#880) |
| `Shamir Secret Sharing/recover_private_key_from_legacy_backup (255 of 255)` | | 12786333.17 | | | 13083463.55 | | | new row (#880) |
| `Shamir Secret Sharing/recover_private_key_from_legacy_backup (3 of 5)` | | 15290.83 | | | 16806.04 | | | new row (#880) |
| `Shamir Secret Sharing/split_private_key (3 of 5)` | 6215.95 | 47702.87 | 7.674 | 6498.15 | 48676.65 | 7.491 | both | `4f6e82f2` (#854) |
| `Shamir Secret Sharing/split_private_key (5 of 10)` | 14645.50 | 68742.08 | 4.694 | 14813.91 | 74428.39 | 5.024 | both | `4f6e82f2` (#854) |
| `Shamir Secret Sharing/to_backup_format` | 7840.76 | 50467.99 | 6.437 | 8373.02 | 51817.25 | 6.189 | both | `4f6e82f2` (#854) |
| `Sighash/compute_sighash (5 inputs, 5 outputs)` | 1263.21 | 1238.06 | 0.980 | 1284.87 | 1384.22 | 1.077 | p99 | unexplained (p99 alone) |
| `Sighash/sighash x50 inputs, SighashCache (midstates once)` | 15007.59 | 15017.20 | 1.001 | 15113.25 | 15373.20 | 1.017 |  |  |
| `Sighash/sighash x50 inputs, free fn (no midstate reuse)` | 135430.46 | 139067.27 | 1.027 | 137395.13 | 152339.43 | 1.109 | p99 | unexplained (p99 alone) |
| `Sighash/sighash x50 inputs, from_raw per input (parse + no reuse)` | 178981.48 | 181905.74 | 1.016 | 194830.71 | 199026.11 | 1.022 |  |  |
| `Signing/P256PrivateKey::sign` | 101998.34 | 102831.46 | 1.008 | 102990.65 | 109119.60 | 1.060 | p99 | unexplained (p99 alone) |
| `Signing/P256PrivateKey::sign_hash` | 101896.39 | 102594.34 | 1.007 | 104513.76 | 105964.35 | 1.014 |  |  |
| `Signing/PrivateKey::sign (secp256k1)` | 69441.39 | 70813.23 | 1.020 | 72694.63 | 73021.16 | 1.004 |  |  |
| `Symmetric Encryption/decrypt/1024 bytes` | 1205.07 | 1181.73 | 0.981 | 1288.41 | 1218.23 | 0.946 | p99 | unexplained (p99 alone) |
| `Symmetric Encryption/decrypt/16384 bytes` | 14159.23 | 14125.84 | 0.998 | 14429.35 | 14268.43 | 0.989 |  |  |
| `Symmetric Encryption/decrypt/256 bytes` | 550.40 | 504.68 | 0.917 | 565.00 | 558.39 | 0.988 | p50 | unexplained |
| `Symmetric Encryption/decrypt/4096 bytes` | 3794.14 | 3760.88 | 0.991 | 3814.83 | 3903.84 | 1.023 |  |  |
| `Symmetric Encryption/decrypt/64 bytes` | 389.14 | 347.02 | 0.892 | 404.00 | 357.84 | 0.886 | both | unexplained |
| `Symmetric Encryption/encrypt/1024 bytes` | 1805.27 | 1786.85 | 0.990 | 2194.53 | 1835.38 | 0.836 | p99 | unexplained (p99 alone) |
| `Symmetric Encryption/encrypt/16384 bytes` | 20107.79 | 20115.98 | 1.000 | 20984.67 | 21092.08 | 1.005 |  |  |
| `Symmetric Encryption/encrypt/256 bytes` | 1078.61 | 1057.06 | 0.980 | 1108.70 | 1098.87 | 0.991 |  |  |
| `Symmetric Encryption/encrypt/4096 bytes` | 5762.48 | 5725.55 | 0.994 | 5892.83 | 5817.03 | 0.987 |  |  |
| `Symmetric Encryption/encrypt/64 bytes` | 913.82 | 894.50 | 0.979 | 925.02 | 933.66 | 1.009 |  |  |
| `Template Lock/Multisig::lock_from_keys (2-of-3)` | 470.36 | 538.97 | 1.146 | 493.25 | 559.56 | 1.134 | both | unexplained |
| `Template Lock/P2PK::lock` | 35.10 | 35.04 | 0.998 | 37.11 | 37.42 | 1.008 |  |  |
| `Template Lock/P2PKH::lock` | 34.97 | 35.90 | 1.027 | 36.54 | 38.41 | 1.051 | p99 | unexplained (p99 alone) |
| `Template Lock/PushDrop::lock (3 fields)` | 359.00 | 458.48 | 1.277 | 366.91 | 492.23 | 1.342 | both | `e448d0af` (#545) |
| `Template Sign/Multisig::sign_with_sighash (2 sigs)` | 140307.39 | 142193.62 | 1.013 | 143606.86 | 145207.02 | 1.011 |  |  |
| `Template Sign/P2PK::sign_with_sighash` | 70221.65 | 71150.24 | 1.013 | 71947.87 | 75511.27 | 1.050 |  |  |
| `Template Sign/P2PKH::sign_with_sighash` | 100622.05 | 101872.59 | 1.012 | 131377.08 | 103488.44 | 0.788 | p99 | unexplained (p99 alone) |
| `Verification/P256PublicKey::verify` | 331586.20 | 330301.72 | 0.996 | 356989.93 | 358014.84 | 1.003 |  |  |
| `Verification/PublicKey::verify (secp256k1)` | 80488.64 | 80205.27 | 0.996 | 125858.44 | 84103.16 | 0.668 | p99 | unexplained (p99 alone) |
| `WIF and Address/PrivateKey::from_wif` | 907.13 | 942.93 | 1.039 | 934.34 | 966.82 | 1.035 |  |  |
| `WIF and Address/PrivateKey::to_wif` | 1880.02 | 1887.32 | 1.004 | 2070.52 | 1924.32 | 0.929 | p99 | unexplained (p99 alone) |
| `WIF and Address/PublicKey::hash160` | 430.74 | 448.39 | 1.041 | 443.89 | 453.26 | 1.021 |  |  |
| `WIF and Address/PublicKey::to_address` | 1289.28 | 1298.00 | 1.007 | 1304.49 | 1396.84 | 1.071 | p99 | unexplained (p99 alone) |
| `beef_stream/scripts/1000000` | 2708706.62 | 2733847.05 | 1.009 | 2764703.32 | 3069972.41 | 1.110 | p99 | unexplained (p99 alone) |
| `beef_stream/scripts/10000000` | 26865829.75 | 27881464.75 | 1.038 | 29546550.90 | 29235764.40 | 0.989 |  |  |
| `beef_stream/structure/1000000` | 1758587.15 | 1731240.06 | 0.984 | 1828018.67 | 1960198.14 | 1.072 | p99 | unexplained (p99 alone) |
| `beef_stream/structure/10000000` | 18245576.00 | 18090224.75 | 0.991 | 19201875.31 | 18874513.64 | 0.983 |  |  |
| `hash160` | 296.66 | 297.44 | 1.003 | 299.70 | 301.61 | 1.006 |  |  |
| `merkle_path/verify_depth20_10000` | 224905764.00 | 252385547.50 | 1.122 | 233875631.45 | 263109249.37 | 1.125 | both | `8311d642` (#817) |
| `script_spend/seed_block` | 60031011.50 | 64629585.50 | 1.077 | 60916832.70 | 65559363.13 | 1.076 | both | unexplained (its path changed: 35 commits under `src/script/spend`) |
| `sha256` | 71.23 | 70.06 | 0.984 | 72.84 | 71.22 | 0.978 |  |  |
| `sha256_hmac` | 215.05 | 213.40 | 0.992 | 219.92 | 217.77 | 0.990 |  |  |
| `sha256d` | 121.97 | 121.72 | 0.998 | 124.27 | 128.28 | 1.032 |  |  |
| `sha512` | 278.38 | 276.93 | 0.995 | 281.26 | 321.34 | 1.143 | p99 | unexplained (p99 alone) |
| `transaction_sign_verify/sign_100_p2pkh` | 10685295.00 | 10833238.50 | 1.014 | 10756635.88 | 11295018.05 | 1.050 | p99 | unexplained (p99 alone) |
| `transaction_sign_verify/verify_100_p2pkh` | 10141744.83 | 9495101.75 | 0.936 | 10227395.78 | 9638544.50 | 0.942 | both | unexplained (its path changed: `fba61029` (#331), `f8f72db6` (#734), `f5a12929` (#855), `1a3e4c5a` (#843)) |
| `wire_codec/abortAction/request_decode` | 129.33 | 146.69 | 1.134 | 132.76 | 150.69 | 1.135 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/abortAction/request_encode` | 74.60 | 74.99 | 1.005 | 77.61 | 84.55 | 1.089 | p99 | unexplained (p99 alone) |
| `wire_codec/abortAction/result_decode` | 62.79 | 66.01 | 1.051 | 63.49 | 66.83 | 1.053 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/abortAction/result_encode` | 20.54 | 20.55 | 1.001 | 20.87 | 22.70 | 1.088 | p99 | unexplained (p99 alone) |
| `wire_codec/acquireCertificate/request_decode` | 875.63 | 961.02 | 1.098 | 1186.46 | 989.56 | 0.834 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/acquireCertificate/request_encode` | 319.52 | 292.86 | 0.917 | 336.64 | 349.69 | 1.039 | p50 | `3cf87636` (#385) |
| `wire_codec/acquireCertificate/result_decode` | 427.06 | 499.61 | 1.170 | 434.31 | 531.73 | 1.224 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/acquireCertificate/result_encode` | 267.60 | 211.74 | 0.791 | 307.84 | 218.39 | 0.709 | both | `3cf87636` (#385) |
| `wire_codec/createAction/request_decode` | 1967.56 | 2115.41 | 1.075 | 2007.06 | 2216.48 | 1.104 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/createAction/request_encode` | 424.95 | 396.61 | 0.933 | 436.70 | 409.90 | 0.939 | both | unexplained |
| `wire_codec/createAction/result_decode` | 608.61 | 657.33 | 1.080 | 615.47 | 679.47 | 1.104 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/createAction/result_encode` | 225.68 | 207.84 | 0.921 | 235.30 | 223.03 | 0.948 | both | unexplained |
| `wire_codec/createHmac/request_decode` | 8189.32 | 8165.13 | 0.997 | 8247.16 | 8751.18 | 1.061 | p99 | unexplained (p99 alone) |
| `wire_codec/createHmac/request_encode` | 328.60 | 353.43 | 1.076 | 345.56 | 374.53 | 1.084 | both | unexplained |
| `wire_codec/createHmac/result_decode` | 89.42 | 97.87 | 1.095 | 91.56 | 101.20 | 1.105 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/createHmac/result_encode` | 56.36 | 56.43 | 1.001 | 59.21 | 71.14 | 1.201 | p99 | unexplained (p99 alone) |
| `wire_codec/createSignature/request_decode` | 8244.29 | 8245.62 | 1.000 | 8688.34 | 9904.09 | 1.140 | p99 | unexplained (p99 alone) |
| `wire_codec/createSignature/request_encode` | 338.33 | 351.75 | 1.040 | 358.80 | 373.24 | 1.040 |  |  |
| `wire_codec/createSignature/result_decode` | 89.22 | 97.52 | 1.093 | 93.87 | 101.19 | 1.078 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/createSignature/result_encode` | 37.04 | 37.68 | 1.017 | 38.51 | 40.42 | 1.050 |  |  |
| `wire_codec/decrypt/request_decode` | 8174.88 | 8193.02 | 1.002 | 8357.67 | 8728.99 | 1.044 |  |  |
| `wire_codec/decrypt/request_encode` | 326.31 | 349.78 | 1.072 | 339.77 | 352.31 | 1.037 | p50 | unexplained |
| `wire_codec/decrypt/result_decode` | 89.02 | 97.38 | 1.094 | 90.11 | 103.32 | 1.147 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/decrypt/result_encode` | 27.38 | 28.01 | 1.023 | 29.83 | 29.93 | 1.003 |  |  |
| `wire_codec/discoverByAttributes/request_decode` | 413.61 | 436.28 | 1.055 | 441.40 | 456.79 | 1.035 | p50 | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/discoverByAttributes/request_encode` | 102.73 | 105.57 | 1.028 | 104.94 | 107.33 | 1.023 |  |  |
| `wire_codec/discoverByAttributes/result_decode` | 1528.48 | 1579.93 | 1.034 | 1544.63 | 1896.91 | 1.228 | p99 | unexplained (p99 alone) |
| `wire_codec/discoverByAttributes/result_encode` | 567.04 | 416.15 | 0.734 | 573.58 | 451.88 | 0.788 | both | `3cf87636` (#385) |
| `wire_codec/discoverByIdentityKey/request_decode` | 252.62 | 283.27 | 1.121 | 278.57 | 293.93 | 1.055 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/discoverByIdentityKey/request_encode` | 162.33 | 150.75 | 0.929 | 166.38 | 157.47 | 0.946 | both | unexplained |
| `wire_codec/discoverByIdentityKey/result_decode` | 1525.91 | 1611.97 | 1.056 | 1609.76 | 1665.84 | 1.035 | p50 | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/discoverByIdentityKey/result_encode` | 560.90 | 420.07 | 0.749 | 568.97 | 437.63 | 0.769 | both | `3cf87636` (#385) |
| `wire_codec/encrypt/request_decode` | 8124.44 | 8184.11 | 1.007 | 9563.85 | 11372.36 | 1.189 | p99 | unexplained (p99 alone) |
| `wire_codec/encrypt/request_encode` | 338.88 | 353.39 | 1.043 | 343.05 | 367.76 | 1.072 | p99 | unexplained (p99 alone) |
| `wire_codec/encrypt/result_decode` | 89.35 | 98.56 | 1.103 | 90.79 | 103.17 | 1.136 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/encrypt/result_encode` | 56.43 | 56.49 | 1.001 | 64.85 | 61.62 | 0.950 |  |  |
| `wire_codec/getHeaderForHeight/request_decode` | 127.81 | 139.06 | 1.088 | 129.69 | 141.67 | 1.092 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getHeaderForHeight/request_encode` | 74.36 | 73.25 | 0.985 | 77.56 | 78.11 | 1.007 |  |  |
| `wire_codec/getHeaderForHeight/result_decode` | 96.44 | 106.03 | 1.099 | 98.62 | 107.95 | 1.095 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getHeaderForHeight/result_encode` | 57.37 | 65.85 | 1.148 | 58.21 | 66.72 | 1.146 | both | unexplained |
| `wire_codec/getHeight/request_decode` | 98.21 | 107.88 | 1.099 | 102.16 | 113.34 | 1.109 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getHeight/request_encode` | 38.83 | 39.96 | 1.029 | 42.43 | 44.31 | 1.044 |  |  |
| `wire_codec/getHeight/result_decode` | 90.55 | 99.41 | 1.098 | 91.82 | 101.20 | 1.102 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getHeight/result_encode` | 25.82 | 26.47 | 1.025 | 26.36 | 36.09 | 1.369 | p99 | unexplained (p99 alone) |
| `wire_codec/getNetwork/request_decode` | 98.26 | 107.83 | 1.097 | 102.55 | 111.03 | 1.083 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getNetwork/request_encode` | 38.85 | 39.96 | 1.029 | 44.82 | 40.85 | 0.911 | p99 | unexplained (p99 alone) |
| `wire_codec/getNetwork/result_decode` | 83.74 | 91.01 | 1.087 | 86.60 | 91.93 | 1.062 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getNetwork/result_encode` | 23.97 | 23.96 | 1.000 | 24.41 | 28.27 | 1.158 | p99 | unexplained (p99 alone) |
| `wire_codec/getPublicKey/request_decode` | 8097.01 | 8102.12 | 1.001 | 8196.52 | 8464.02 | 1.033 |  |  |
| `wire_codec/getPublicKey/request_encode` | 346.23 | 347.39 | 1.003 | 364.45 | 352.86 | 0.968 |  |  |
| `wire_codec/getPublicKey/result_decode` | 97.01 | 106.31 | 1.096 | 98.70 | 109.63 | 1.111 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getPublicKey/result_encode` | 56.41 | 56.47 | 1.001 | 57.33 | 59.05 | 1.030 |  |  |
| `wire_codec/getVersion/request_decode` | 98.23 | 108.01 | 1.100 | 101.79 | 110.09 | 1.081 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getVersion/request_encode` | 38.80 | 39.96 | 1.030 | 51.75 | 44.23 | 0.855 | p99 | unexplained (p99 alone) |
| `wire_codec/getVersion/result_decode` | 89.16 | 97.47 | 1.093 | 91.35 | 101.96 | 1.116 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/getVersion/result_encode` | 37.01 | 37.69 | 1.018 | 37.84 | 40.15 | 1.061 | p99 | unexplained (p99 alone) |
| `wire_codec/internalizeAction/request_decode` | 1074.34 | 1163.30 | 1.083 | 1115.49 | 1258.07 | 1.128 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/internalizeAction/request_encode` | 305.57 | 277.11 | 0.907 | 315.31 | 293.24 | 0.930 | both | unexplained |
| `wire_codec/internalizeAction/result_decode` | 62.76 | 69.69 | 1.110 | 63.13 | 70.40 | 1.115 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/internalizeAction/result_encode` | 20.55 | 20.54 | 1.000 | 20.79 | 22.37 | 1.076 | p99 | unexplained (p99 alone) |
| `wire_codec/isAuthenticated/request_decode` | 98.16 | 107.78 | 1.098 | 99.12 | 112.74 | 1.137 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/isAuthenticated/request_encode` | 38.85 | 40.27 | 1.037 | 39.86 | 44.16 | 1.108 | p99 | unexplained (p99 alone) |
| `wire_codec/isAuthenticated/result_decode` | 84.39 | 91.57 | 1.085 | 85.59 | 97.30 | 1.137 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/isAuthenticated/result_encode` | 24.58 | 24.91 | 1.014 | 26.38 | 27.10 | 1.027 |  |  |
| `wire_codec/listActions/request_decode` | 509.56 | 570.65 | 1.120 | 534.74 | 664.75 | 1.243 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/listActions/request_encode` | 154.60 | 188.73 | 1.221 | 167.17 | 196.87 | 1.178 | both | unexplained |
| `wire_codec/listActions/result_decode` | 778.17 | 880.94 | 1.132 | 811.32 | 901.78 | 1.112 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/listActions/result_encode` | 308.58 | 262.69 | 0.851 | 315.98 | 266.77 | 0.844 | both | unexplained |
| `wire_codec/listCertificates/request_decode` | 565.08 | 589.75 | 1.044 | 576.44 | 631.06 | 1.095 | p99 | unexplained (p99 alone) |
| `wire_codec/listCertificates/request_encode` | 221.26 | 190.51 | 0.861 | 223.90 | 204.14 | 0.912 | both | unexplained |
| `wire_codec/listCertificates/result_decode` | 1056.10 | 1140.54 | 1.080 | 1074.97 | 1217.19 | 1.132 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/listCertificates/result_encode` | 459.69 | 367.35 | 0.799 | 498.24 | 493.43 | 0.990 | p50 | `3cf87636` (#385) |
| `wire_codec/listOutputs/request_decode` | 490.61 | 531.65 | 1.084 | 612.26 | 623.22 | 1.018 | p50 | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/listOutputs/request_encode` | 157.44 | 196.74 | 1.250 | 160.20 | 208.63 | 1.302 | both | unexplained |
| `wire_codec/listOutputs/result_decode` | 370.73 | 423.45 | 1.142 | 377.12 | 459.72 | 1.219 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/listOutputs/result_encode` | 153.60 | 183.71 | 1.196 | 177.30 | 234.46 | 1.322 | both | unexplained |
| `wire_codec/proveCertificate/request_decode` | 727.95 | 838.01 | 1.151 | 742.62 | 851.61 | 1.147 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/proveCertificate/request_encode` | 365.32 | 291.47 | 0.798 | 398.48 | 332.02 | 0.833 | both | `3cf87636` (#385) |
| `wire_codec/proveCertificate/result_decode` | 367.45 | 390.15 | 1.062 | 382.52 | 484.17 | 1.266 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/proveCertificate/result_encode` | 98.40 | 103.56 | 1.053 | 114.84 | 105.31 | 0.917 | both | unexplained |
| `wire_codec/relinquishCertificate/request_decode` | 240.76 | 280.52 | 1.165 | 245.37 | 292.39 | 1.192 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/relinquishCertificate/request_encode` | 168.80 | 153.82 | 0.911 | 174.87 | 175.61 | 1.004 | p50 | unexplained |
| `wire_codec/relinquishCertificate/result_decode` | 62.77 | 65.95 | 1.051 | 63.32 | 69.29 | 1.094 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/relinquishCertificate/result_encode` | 20.56 | 20.56 | 1.000 | 24.15 | 22.82 | 0.945 | p99 | unexplained (p99 alone) |
| `wire_codec/relinquishOutput/request_decode` | 162.40 | 181.37 | 1.117 | 164.81 | 194.04 | 1.177 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/relinquishOutput/request_encode` | 112.32 | 151.22 | 1.346 | 124.40 | 179.83 | 1.445 | both | unexplained |
| `wire_codec/relinquishOutput/result_decode` | 62.76 | 69.66 | 1.110 | 63.27 | 70.50 | 1.114 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/relinquishOutput/result_encode` | 20.55 | 20.54 | 1.000 | 22.43 | 20.94 | 0.933 | p99 | unexplained (p99 alone) |
| `wire_codec/revealCounterpartyKeyLinkage/request_decode` | 289.11 | 318.21 | 1.101 | 301.38 | 330.77 | 1.098 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/revealCounterpartyKeyLinkage/request_encode` | 177.56 | 168.64 | 0.950 | 189.08 | 176.90 | 0.936 | both | unexplained |
| `wire_codec/revealCounterpartyKeyLinkage/result_decode` | 352.58 | 374.54 | 1.062 | 375.69 | 406.51 | 1.082 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/revealCounterpartyKeyLinkage/result_encode` | 178.40 | 173.51 | 0.973 | 183.80 | 177.15 | 0.964 |  |  |
| `wire_codec/revealSpecificKeyLinkage/request_decode` | 8050.97 | 8045.66 | 0.999 | 8242.34 | 8694.31 | 1.055 | p99 | unexplained (p99 alone) |
| `wire_codec/revealSpecificKeyLinkage/request_encode` | 322.55 | 361.89 | 1.122 | 328.01 | 383.89 | 1.170 | both | unexplained |
| `wire_codec/revealSpecificKeyLinkage/result_decode` | 495.28 | 491.96 | 0.993 | 523.76 | 586.47 | 1.120 | p99 | unexplained (p99 alone) |
| `wire_codec/revealSpecificKeyLinkage/result_encode` | 208.91 | 212.67 | 1.018 | 222.27 | 235.68 | 1.060 | p99 | unexplained (p99 alone) |
| `wire_codec/signAction/request_decode` | 577.50 | 646.29 | 1.119 | 583.91 | 656.89 | 1.125 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/signAction/request_encode` | 159.39 | 196.76 | 1.234 | 174.28 | 202.65 | 1.163 | both | unexplained |
| `wire_codec/signAction/result_decode` | 277.18 | 318.83 | 1.150 | 314.40 | 401.65 | 1.278 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/signAction/result_encode` | 182.44 | 170.47 | 0.934 | 232.30 | 172.36 | 0.742 | both | unexplained |
| `wire_codec/verifyHmac/request_decode` | 8147.14 | 8117.82 | 0.996 | 8472.31 | 8616.62 | 1.017 |  |  |
| `wire_codec/verifyHmac/request_encode` | 343.45 | 354.17 | 1.031 | 363.00 | 365.87 | 1.008 |  |  |
| `wire_codec/verifyHmac/result_decode` | 62.80 | 69.69 | 1.110 | 66.91 | 70.43 | 1.053 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/verifyHmac/result_encode` | 20.53 | 20.55 | 1.001 | 20.89 | 22.15 | 1.060 | p99 | unexplained (p99 alone) |
| `wire_codec/verifySignature/request_decode` | 8324.43 | 8307.14 | 0.998 | 9031.16 | 8779.04 | 0.972 |  |  |
| `wire_codec/verifySignature/request_encode` | 344.38 | 367.89 | 1.068 | 347.58 | 394.11 | 1.134 | both | unexplained |
| `wire_codec/verifySignature/result_decode` | 62.78 | 69.70 | 1.110 | 63.22 | 71.62 | 1.133 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/verifySignature/result_encode` | 20.56 | 20.54 | 0.999 | 22.33 | 22.09 | 0.989 |  |  |
| `wire_codec/waitForAuthentication/request_decode` | 98.15 | 107.77 | 1.098 | 100.68 | 115.64 | 1.149 | both | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/waitForAuthentication/request_encode` | 38.79 | 39.92 | 1.029 | 39.32 | 43.12 | 1.097 | p99 | unexplained (p99 alone) |
| `wire_codec/waitForAuthentication/result_decode` | 62.75 | 65.99 | 1.052 | 68.83 | 68.05 | 0.989 | p50 | `5de0f46a`, `c386c117` (#458) |
| `wire_codec/waitForAuthentication/result_encode` | 20.53 | 20.55 | 1.001 | 23.26 | 24.59 | 1.057 | p99 | unexplained (p99 alone) |
