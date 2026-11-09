# Design for #90: the interpreter's throughput on the sibling's corpus

Read at `origin/beta` `e228c61a` on 2026-11-09; sibling `bsv-script-lean@5dc337e1`, node `bitcoin-sv@v1.2.2`. `[X]` read at the line or run here (python and git only; no cargo, no bench); `[D]` told or proposed.

## 1. The exit test and the scoreboard row

Issue #90, quoted: "**Exit test.** Throughput on the corpus up by a measured factor with the conformance run identical." `[X]`

The row it moves: `docs/NORTH-STAR.md:23`, "Script interpreter | Throughput on the sibling's seed corpus; identical conformance verdicts", current cell "not yet measured" `[X]`; epic #101: "throughput on bsv-script-lean's corpus measured and only rising, the conformance run identical on every PR" `[X]`.

"At target with recorded evidence" `[D]`:

1. `BSV_SCRIPT_CORPUS=<sibling>/corpus/seed cargo run --locked --manifest-path tools/bench-compare/Cargo.toml -- --output <dir>` at the base and at the head on one quiet host: `run.json`'s `script_spend/seed_block` p50 and p99. The cell moves only from a producer's published run, never a lane's local numbers (`docs/NORTH-STAR.md:52-54`).
2. `harness/run --impl bsv-rs --corpus seed` (and `--corpus all` for the closing lane) from a scratch copy of the sibling's harness whose `bsv-rs` dependency names the lane's tree by path, before and after: `summary.txt` and `bsv-rs/manifest.json` equal entry by entry.
3. `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance cargo test --features "full,http" --test conformance_scripts`: 5,116 total, 4,120 run, 4,109 passed, 959 unsupported, 37 skipped, 11 known failures, unchanged.
4. The record, `docs/records/90-interpreter-speed.md` (new, the closing lane's): per step the base and head sha, both `run.json` paths, the factor, both harness run stamps, the conformance line, the host's `uptime`.

## 2. Today on beta

| What | Where | `[X]`/`[D]` |
|---|---|---|
| The walk: `validate`, `step`, `execute_opcode` | `src/script/spend/mod.rs:461`, `:521`, `:644` | X |
| Construction: `chunks()` deep-clones each script's chunk vector, then `.into()` an `Arc<[ScriptChunk]>` | `mod.rs:431-432`; `src/script/script.rs:497-500` | X |
| Construction: `truncated_push()` copies each whole script (`to_binary` clones the cached bytes) | `mod.rs:433-434`; `script.rs:121-123`, `:236-239` | X |
| Per step: an `Arc::clone` of the chunk slice; `if_stack.contains(&false)` scanned in `step` and again in `execute_opcode` | `mod.rs:575-578`; `:607`, `:649` | X |
| Per executed push: one fallible `Vec` allocation | `mod.rs:627`; `limits.rs:219-233`; `stack.rs:16-24` | X |
| Per signature check: the script copied at `to_binary` (45), `to_vec` (46), the lock's `to_binary` (51), `find_and_delete` (55, 117), `Script::from_binary` (58) | `src/script/spend/script_code.rs:34-59` | X |
| Per key tried: `subscript.to_binary()` again | `src/script/spend/crypto.rs:416`, called at `:173`, `:302` | X |
| Per error: txid hex through `hex::encode`, both stacks copied, `if_stack` cloned; the fields are public | `mod.rs:758-771`; `src/primitives/encoding.rs:83-85`; `src/script/evaluation_error.rs:111-125` | X |
| The bench: every seed row's inputs through `Spend::new` + `set_flags` + `validate`; the params cloned inside the timing | `benches/script_spend.rs:44-64`, `:179-185` | X |
| The gate: p99 up by more than 5% fails; `benchmarks` compares on a branch dispatch alone (`release.yml`'s call on a tag skips it), never on a push or PR; the corpus fetched at sibling `8840488` | `benches/README.md:45`; `.github/workflows/bench.yml:66`, `:70`, `:103` | X |
| CI: `conformance_scripts` on every push and PR; `fuzz_script_spend` and `fuzz_script_spend_default` nightly | `.github/workflows/ci.yml:751`; `nightly.yml:800-801` | X |

The numbers on record:

| Number | Value | Source |
|---|---|---|
| `script_spend/seed_block`, Apple M1 Max, rustc 1.95.0, at `67559f9d` | p50 30,515,208 ns, p99 33,070,502 ns per pass of 10,000 inputs (3.05 µs an input at p50) | `benches/baseline.json:512` |
| The same, AMD EPYC 7763 4 cores, rustc 1.99.1, at `4b1c4688` | p50 60,031,011 ns, p99 60,916,832 ns (6.00 µs an input) | `benches/baseline.json:1617` |
| The seed corpus | 10,000 rows, 10,000 inputs, one block word (4015663), sha256 `bc0651d0...54b0`; the same sha at sibling `5dc337e1` | `baseline.json:20`; `shasum` here `[X]` |
| The seed's shape | mean locking script 6.4 bytes, longest 19; mean transaction 304 bytes; 80 rows' locking scripts hold byte `0xac` (154 rows' locking or unlocking scripts), 617 rows' scripts a byte from `0xac` to `0xaf` (an upper bound on the rows checking a signature); `bsv-rs@0.7.0` column 5,342 valid, 4,658 invalid | python over `corpus/seed/seed.jsonl` here `[X]` |
| The A8 census (ts-stack's vectors, not the seed), at `099d5d98`, host load 61 to 74 | row 22 `Vec<ScriptChunk>::clone` 2.74% self (4.69% inclusive), its nearest caller `Script::clone`, not `Script::chunks`; row 36 `drop_glue::<Script>` from `execute_opcode` 1.39% (3.74%); rows 32, 33 hex from `Spend::error` 1.77% (4.16%), 1.74% | `docs/a8/census-2026-10-31.md:28-58` |
| Mutation scores, run at `2ff81a44` | `mod.rs` 90.74%, `crypto.rs` 91.37%, `script_code.rs` 98.04%, `flow.rs` 86.49%, `script.rs` 98.97% (floor 80%) | `docs/census/mutants-2026-11-04.md:51-71` |
| The harness's own pin | `bsv-rs = "=0.7.0"`, in process through `Spend::new` | sibling `harness/Cargo.toml:32`, `harness/src/engine.rs:324` |

The queue's blockers (`docs/NORTH-STAR.md:212`): #85, #77, #81 closed (`256c6c23`, `eb7751c9`, `baafa5e8`) `[X]`. Open relatives: #97 (no hosted harness job), #514 (design), #601 (the `a8-alloc` cycle; no such feature in `Cargo.toml` at this sha) `[X]`.

Not on record (named, never estimated): a `script_spend` number at the tip (both entries were recorded in October, before #654, #660 and #378 landed); a profile of the seed workload (the census replays ts-stack's vectors); allocations per input; the shares of the per-input time (construction, the bench's own clone, the walk, an error); the harness's per-entry column at the tip (#601's pre-step); any quiet-host figure.

## 3. The gap

- No factor exists: the base is not measured at the tip, on a quiet host, on one toolchain.
- The seed measures construction, dispatch and one error on 47% of rows, not signature checks or long scripts, where `script_code.rs` copies most.
- Nothing attributes the 3 µs: the steps are ranked from reading; S0 decides the order.
- #601's discipline (a flag, the old path the oracle) and NORTH-STAR's loop (a refactor on identical harness runs) are two gates for the same lines: Q90.1.
- The identical-verdict proof is local until #97.

## 4. The design

No public type, field, signature, error text or fixture moves. `num-bigint`, the budgets, the flag gates and every refusal site stay. No new dependency.

Each step is one lane, one PR, one concern; after S0 each carries the harness run before and after.

| Step | The change | Why it moves the number | The proof | Risk |
|---|---|---|---|---|
| **S0 measure** | No `src/` change. On a quiet host at the tip: `bench-compare --output`; a `samply` profile of the seed workload by the census's method (`docs/a8/census-2026-10-31.md:9`); allocations per input by a counting allocator (as `tests/script_arithmetic_allocations_378.rs:9`); the harness's `seed` and `all` columns, kept per entry | The base of the factor and the attribution that orders S1 to S5; a step under 2% is dropped | `docs/a8/census-<date>-script-spend.{json,md}` with its producing runs | 0.05 |
| **S1 construction** | `Spend::from_parts` (`mod.rs:370-437`) takes the parsed chunks without the deep clone and reads the truncated push from borrowed bytes: crate-visible borrowing accessors on `Script` (`script.rs`, beside `:121`, `:497`); the public accessors unchanged | Per spend today: two chunk-vector clones, two whole-script copies, their frees; census row 22 | RED: a counting-allocator test, `a_spend_is_built_without_copying_its_scripts`; the bench delta; harness `seed` | 0.15 |
| **S2 the walk** | `step` reads the opcode and the push's bytes by index, no `Arc::clone` (`mod.rs:575-579`; the one arm needing the chunk, `:657`, borrows it there); the executing flag computed once and passed (`:607`, `:649`), from a count of false entries kept by `op_if`, `op_else`, `op_endif` (`flow.rs`), as the node's `conditionals.is_active()` (`interpreter.cpp:459`) | Two atomic operations and two scans leave every opcode of every script | RED: a unit test pinning the count against `if_stack` after every conditional opcode; the bench delta; harness `seed`, `flow`; `flow.rs` and `mod.rs` mutation scores not below today's | 0.25 (conditional state is consensus; the one-ELSE rule and `returning` share it) |
| **S3 scriptCode once** | `script_code` returns bytes (`script_code.rs:34`), built in one buffer from borrowed script bytes; `find_and_delete` copies only when it finds a push; `verify_signature` takes `&[u8]` (`crypto.rs:394`), so CHECKMULTISIG serializes nothing per key | Five copies of the script per CHECKSIG become one, n more per CHECKMULTISIG none; census row 36. The seed barely shows it (at most 617 rows hold a signature opcode's byte): its number is `transaction_sign_verify` and Q90.3's workload | RED: `a_checksig_copies_the_script_once` by allocation count; `script_code_tests.rs` and `tests/sighash_scriptcode_654.rs` unchanged; harness `crypto`, `tx`, `sighash`; #601's corner cases (a FORKID push, a codeseparator, the appended lock, `OP_RETURN` data, a cut push) | 0.30 |
| **S4 the error** | `to_hex` writes from a byte table into a sized `String` (`src/primitives/encoding.rs:83`); `Spend::error` returns what it returns today | The seed's 4,658 refusals each build one error; census rows 32, 33; the BEEF rows 17, 19 gain too | No RED (same bytes): `to_hex` equals `hex::encode` at every length to 1,024; bench delta | 0.05 |
| **S5 elements** | Only if S0 puts the push sites' allocator share above 10%: popped element `Vec`s kept in a bounded free list on the `Spend`, reused by `copy_element` (`limits.rs:219`); fallible reservation kept, the budget counting lengths as today | Removes the allocation per push | RED: allocation count per push; the memory witnesses (`tests/script_default_mode_uncapped_331.rs`, `script_stack_memory_witness.rs`) unchanged; harness `all` | 0.45 (retained capacity beside a memory budget: Q90.4) |

Fact-check (2026-11-09), S1: census row 22's nearest `bsv_rs` caller is `<Script as Clone>::clone` (`docs/a8/census-2026-10-31.md:44`), the replay's clones on ts-stack's vectors, not `Spend::from_parts`'s `chunks()`; S1's share on the seed is S0's to measure.

## 5. The slicing

| Order | Lane | Waits on | Gate |
|---|---|---|---|
| 1 | L0 = S0 | a quiet host | the record file with its runs; the captain re-ranks S1 to S5 from it |
| 2 | L1 = S1 and L4 = S4, in parallel | L0, Q90.1 | the suite, the wasm32 slice, harness `seed`, the bench delta |
| 3 | L2 = S2 | L1 landed (both edit `mod.rs:370-640`) | as L1 plus `flow`, adversarial read, mutation floor on `mod.rs` and `flow.rs` |
| 4 | L3 = S3 | L2 landed (`mod.rs` fields), Q90.3 for its number | as L2 plus `crypto`, `tx`, `sighash`; the two fuzz targets for an hour each |
| 5 | L5 = S5 | Q90.4 and L0's figure | harness `all`, the memory witnesses |
| 6 | Lc, the closing lane | all landed | section 1's four items; a `bench.yml` dispatch on `beta`; the baseline re-recorded by dispatch |

Files two lanes touch: `src/script/spend/mod.rs` (L1, L2, L3, L5: serial), `benches/baseline.json` and `CHANGELOG.md` (every lane; the captain's).

Collision surfaces `[X]` by the issues' titles:

- The 0.9.0 blocking set: #782 (PushDrop's wallet-aware lock) is under `src/script/templates/`, not `spend/`; #734 (the coinbase depth rule) is in `Transaction::verify`'s path, which no step edits; #735, #751, #756, #775, #785, #786, #796 are identity and overlay: no shared file.
- #603: `.cargo/mutants.toml` declares equivalent mutants by `file:line:col` (`:80`, `:93`, `:108` for `script.rs`; `:168` for `spend/key_point.rs:39:9`). L1 moves lines of `script.rs`: it re-keys those entries in its PR and lands between #603's script shards.
- #91 and #601's readers half: `src/primitives/encoding.rs` (`to_hex`) is S4's; one of the two lanes owns it, the other rebases.
- #92: `src/primitives/bsv/sighash.rs` and `benches/transaction_sign_verify.rs` are its files; S3 edits neither. A key or signature cache in `crypto.rs` or `key_point.rs` is #92's, after L3.
- #93 to #96, #98 to #100: no shared source; no step adds a dependency to #96's wasm sizes.
- #97: shares section 1's scratch-harness recipe; whichever lands it as a script owns it.
- #601's interpreter half is S1, S3, S4 if Q90.1 is answered (b); #514 stays apart.

## 6. The owner's questions

**Q90.1 The gate: #601's flag or NORTH-STAR's loop?** (a) Every step behind `a8-alloc`, the old path compiled beside it with a differential target, switched on the owner's word (#601). (b) Each step lands as a refactor on identical harness, conformance and fuzz evidence (`docs/NORTH-STAR.md:124-128`). Reference default: the node has one `EvalScript`. Recommendation: (b) for S1 to S4, (a) for S5 alone, since only S5 changes when memory is held. Cost: (a) doubles the touched lines under the 800-line ceiling and the mutation surface, with no downstream gain until the switch; (b) reaches `overlay-engine`'s submit door at the next release with no action by a consumer.

**Q90.2 What factor closes #90?** (a) Any factor above the gate's 5% on both baseline platforms, stated in the record. (b) A named floor. Reference default: none (the issue says "a measured factor"). Recommendation: (a), with p50 and p99 for both platforms; a floor only after L0. No downstream cost.

**Q90.3 The workload.** The seed's scripts average 6.4 bytes and at most 617 of 10,000 rows hold a signature opcode's byte. (a) Keep `seed_block` as the row's one number. (b) Add `script_spend/<corpus>` ids for the sibling's `crypto` and `tx` corpora, additive in `baseline.json` (a workload-inventory change `bench-compare` refuses until re-recorded). Reference default: the row's text names the seed corpus. Recommendation: (b), `seed_block` still the scoreboard's figure, so S3 has a number. Cost: a re-record per platform by dispatch; two more files fetched; the sibling ref at `bench.yml:103` (`8840488`) moves to `5dc337e1`, a pin. No downstream cost.

**Q90.4 Retained capacity under a memory budget (S5 only).** A free list holds bytes the budget does not count. (a) No reuse: S5 dropped. (b) Reuse bounded at a fixed byte figure, stated in the contract. Reference default: the node's `LimitedStack` counts sizes plus 32 bytes an element and releases on pop (`limitedstack.h:163`, `:171`, `limitedstack.cpp:211-219`; this crate's mirror `stack.rs:116-137`). Recommendation: (a) unless L0 shows the share above 10%. Cost of (b): the wasm32 Workers hold up to the bound beyond the counted stack.

**Q90.5 A public borrowed constructor.** `SpendParams` owns its scripts, so every caller clones (`benches/script_spend.rs:50`, `:55`; `src/transaction/verify.rs:324-325`). (a) No public change. (b) An additive constructor taking shared scripts. Reference default: a JavaScript `Spend` holds its scripts by reference `[D]`. Recommendation: (a) now; reopen with L0's share of the clone. Cost of (b): an additive public surface every downstream's semver check reads.

## 7. Stack alignment

The node's rules are the sibling's; only speed moves. The sibling's Lean S3 must keep: `lean/BsvScript/Ops/Crypto.lean` `scriptCodeOf`, `Sighash.lean` `findAndDelete` (cited at `script_code.rs:12-14`). No row of `bsv-stack-lean@13e1fa5d` `docs/MATRIX.md` names interpreter speed `[X]` (grep at the pin); none of its seven charters is on script (by title). Harness page: `bsv-script-lean@5dc337e1:harness/README.md`.

- T1: cost per spend falls; nothing grows with the chain.
- T2: every verdict is the same.
- T3: the row's subject; the p99 gate is its executable form.
- T4: no rule moves; budgets stay local policy.
- T5: the factor is a producer's record, not a lane's claim.
- T6: each step returns a replayable harness run and a test.

## 8. Not in this design

- A script-number type or a small-integer path for arithmetic: #514, after its band is in a census.
- Signature batching, key and sighash caches: #92.
- The readers' allocations (`BeefDecoder`, `BeefIndex`): #91 and #601's readers half.
- An arena, borrowed stack views, a new dependency: rejected by #601's ensemble.
- The harness on every PR: #97. Each lane's Linux witness: CI's, by dispatch.
- Any change of a refusal's words, a budget's semantics or `ScriptEvaluationError`'s shape.
