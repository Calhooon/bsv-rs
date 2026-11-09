# Design #93: merkle path verification and the tracker's header window

Read at `origin/beta` `e228c61a` on 2026-11-09. No cargo run. `[X]` read at the line; `[D]` told, proposed or
derived by arithmetic. References: ts-stack `edf6e03`, bsv-stack-lean
`13e1fa5d748b`, BRCs `5119a9b`.

## 1. The exit test and the scoreboard row

Issue #93 `[X]`: "**Exit test.** The bench improves; the lone-leaf and offset
rules stay (the conformance file `merkle-path-lone-leaf.json`)." Its body:
verify at depth 20 over 10,000 paths, hashing shared across paths in one
block, a local header window consulted before the network ("the toolbox's
HeaderStore is the consumer"); "the owner's offset-0 ruling stands".

Rows it moves: `docs/NORTH-STAR.md:25` ("Merkle path verification: shared-block
paths at the workload specified in #77 and #93", current cell "not yet
measured") and epic #101 ("merkle path verify: depth 20, 10,000 paths, measured
and only rising").

"At target with recorded evidence" as a command and a record:

- Command: `gh workflow run bench.yml --ref beta` (the `benchmarks` job,
  `benches/README.md:146-160`), which runs
  `cargo run --locked --manifest-path tools/bench-compare/Cargo.toml` against
  `benches/baseline.json`; locally `cargo bench --bench merkle_path --features wallet`.
- Record: the run's `run.json` artifact and `scoreboard.json`, with
  `merkle_path/verify_depth20_10000` p50 and p99 below the baseline rows of
  section 2 on the same machine key, then a reviewed `--record` of the lower
  rows (the baseline only falls).
- Unchanged: `cargo test --features "full,http" --test merkle_path_lone_leaf`
  (6 tests, the stack's `conformance/merkle-path-lone-leaf.json` cases `lone`
  and `lone_at_one`), `--test conformance_beef`, `--test merkle_path_two_readers_agree`.

## 2. Today on beta

| What | Where `[X]` |
|---|---|
| `MerklePath::compute_root`: one `RootWalker` per call | `src/transaction/merkle_path.rs:357-376` |
| `RootWalker`: node cache, walks that meet stop, inside one path only (the reference's `computeRootCached`, `MerklePath.ts:335-354`) | `merkle_path.rs:540-721`; `shared` only at `:206` |
| The lone-leaf rule (offset 0 only, else `MissingSibling`) | `merkle_path.rs:595-609`; the stream's twin `src/transaction/beef_stream.rs:425-439` |
| `hash_pair` on display hex, with a legacy reading of malformed text | `merkle_path.rs:724-755` |
| `merkle_parent` on `[u8; 32]` | `src/block/merkle.rs:25-30` |
| `Transaction::verify`'s proof step: `compute_root` then one tracker call per proven transaction, no memo | `src/transaction/verify.rs:212-227` |
| A BEEF's BUMP cloned onto every transaction it proves | `src/transaction/beef.rs:253` |
| `ChainTracker` (`is_valid_root_for_height`, `current_height`, `mining_tip`) | `src/transaction/chain_tracker.rs:154-187` |
| `WhatsOnChainTracker`: one GET per question, no cache | `src/transaction/chain_trackers/whatsonchain.rs:142-181` |
| No `MerklePath::verify` (the reference's, with the coinbase depth rule, is `MerklePath.ts:476-499`; #734 open, nothing landed) | grep of `merkle_path*.rs` |
| The bench: 10,000 separate depth-20 paths, offsets `i * 97`, one `compute_root` and one mock tracker call each | `benches/merkle_path.rs:34-81` |
| File ratchet: `merkle_path.rs` listed at 1,463 lines (ceiling 800) | `docs/ratchets.json:132`, `docs/RATCHETS.md:103` |
| Mutation surface `merkle` is that one file, 80% gate | `.github/scripts/nightly_mutants.py:31`, `.github/workflows/nightly.yml:723-724` |

Numbers on record (`benches/baseline.json`, id `merkle_path/verify_depth20_10000`, 100 samples, per batch of 10,000):

| Machine key | p50 ns | p99 ns | Source commit | Line `[X]` |
|---|---|---|---|---|
| macos-aarch64 / Apple M1 Max / 10 cores | 334,475,208.5 | 1,184,597,998.5 | `67559f9d` | `:507-511` |
| linux-x86_64 / AMD EPYC 7763 64-Core Processor / 4 cores | 224,905,764.0 | 233,875,631.45 | `4b1c4688` | `:1612-1616` |

Not on record: a bench run at `e228c61a`; a profile splitting hashing from hex
and allocation; the tracker request count of one `verify`; the current
mutation score of `merkle_path.rs`; any symbol named `HeaderStore` in
`~/bsv/bsv-wallet-toolbox-rs/src/` at its checkout `a3377ef0` (grep is empty).
What the toolbox has `[X]`: `FallbackChainTracker` with a private `RootCache`
(height to root text, 1,000 entries, lowest height evicted, positives only, no
reorg invalidation), `src/services/providers/fallback_chain_tracker.rs:38-68,160-210`.

## 3. The gap

1. The single walk works on hex text. From the Linux rows: 22.5 us per path;
   20 `sha256d` of 64 bytes is about 4 us by the same file's `sha256` row
   (71 ns) `[D]`, so most of the time is text and allocation, unmeasured.
2. Nothing shares work across separate paths of one block. The bench's 10,000
   walks hash 200,000 pairs; the distinct nodes are 75,160 `[D]`
   (counted over the bench's offsets; 7 levels unshared at spacing 97, then at most `2^(20-h)` per level, bounds it near 86,000).
3. `verify` asks the tracker once per proven transaction, and each
   `compute_root` on a cloned compound BUMP re-indexes its levels.
4. No tracker holds headers locally; every question is a request.
5. No run at the tip is recorded for the row.

## 4. The design

**P0 (prerequisite, refactor).** Move `RootWalker`, `Node`, `SCAN_MAX` and
`hash_pair` (`merkle_path.rs:523-755`) to `src/transaction/merkle_path_walk.rs`
(the `merkle_path_legal.rs` pattern), and add that path to the `merkle`
mutation surface and the 80% gate. No behaviour change. Proof: the suite's
merkle selections and the sibling's `harness/run --impl bsv-rs --corpus seed`
identical before and after; the ratchet row falls by about 230 lines. Risk
0.1. One lane, one PR.

**R1. The byte walk for one path.** In `merkle_path_walk.rs`: when the path is
not the lone-leaf shape and every sibling the walk needs is stored at
`offset ^ 1` as 64 hex digits or a duplicate, decode each once, climb with
`block::merkle_parent`, encode the root once. Any other shape (a computed
sibling, malformed text, the lone leaf, a missing node) takes today's walker
untouched, so every refusal text and the legacy reading at `:737-749` stay.
Moves the number: removes about six allocations and 192 hex digits per level
`[D]`; the lane measures the factor. Identical: public shape, `Error` texts, `tests/vectors/*`, the lone-leaf
cases, `conformance_beef` totals. Proof: a RED
test `the_byte_walk_allocates_once_per_root_93` (an allocation count under
`dhat-profiling`, red on the pre-change copy); a differential
`the_byte_walk_equals_the_text_walk_93` over `linear_root_equivalence_tests`'
generators (`merkle_path.rs:1084-1277`) and every BUMP of
`merkle_path_two_readers_agree`; `fuzz_merkle_path` asserting equality; the
bench delta by `cargo run --locked --manifest-path tools/bench-compare/Cargo.toml`;
the harness run identical. Risk 0.25 (a shape the fast path takes that the
walker reads otherwise). One lane, one PR.

**R2. Shared nodes across paths of one block.** A crate-private `SharedNodes`
(`HashMap<(u8, u64), Hash32>` for one block height, the root beside it). A walk
records every node it computes or is given. A later walk that reaches a held
node with an equal hash stops hashing and compares each remaining given
sibling with the held node at its position; any difference, or a node not
held, returns to hashing. The root text and every refusal are therefore
`compute_root`'s for every path, well formed or not. Used by
`verify` (R3) and exposed per Q93.1. The bench gains a second id,
`merkle_path/verify_shared_depth20_10000`; the existing id stays the gate of
R1. Moves the number: 75,160 hashes in place of 200,000 `[D]`.
Identical: as R1. Proof: RED `a_path_with_a_forged_upper_half_keeps_its_own_root_93`
(red on a trusting cut), a differential against per-path `compute_root` on the
bench workload and the damaged paths of `:1189`, the new baseline rows, the
harness run. Risk 0.35 (the meeting rule's soundness; the map keeps the keyed hasher, as `beef_stream.rs:403-404`). One
lane, one PR, after R1.

**R3. One question per root in one `verify`.** In `verify.rs:172-227`: a
per-call map `(height, root) -> bool` and one `SharedNodes` per height, so a
BEEF proving n transactions under one BUMP asks the tracker once and hashes
each node once. An `Err` is never memoized. Moves requests, not the bench id.
Identical: verdicts and error texts; the call count differs from the
reference's (`Transaction.ts:1311`): Q93.2. Proof: RED `one_verify_asks_a_root_once_93` with a
counting tracker; `transaction_sign_verify` bench not worse; harness identical.
Risk 0.3. One lane, one PR, after #734 (same function).

**R4. The header window.** New `src/transaction/chain_trackers/header_window.rs`
(no `http`, no time, `std::sync::RwLock`, builds on wasm32):
`HeaderWindow` holds at most `capacity` entries height to `block::BlockHeader`,
contiguous by `prev_hash` where neighbours are held; `insert(height, header)`
refuses a header that does not link to a held neighbour; `invalidate_from(height)`
drops that height and above (the host's reorg and invalidation events, the
tracker charter's section 4). `WindowedChainTracker<T: ChainTracker>` answers
`is_valid_root_for_height` from a held header (`merkle_root_hex`,
`src/block/header.rs:207`) with no request and passes a miss to `T`; a miss is
never an answer and a negative is never held (fail closed, matrix row 27).
`current_height` and `mining_tip` pass through. Feeding is Q93.3 and Q93.4.
Moves requests to zero for held heights (bench `chain_tracker/window_hit_10000`). Identical:
the two HTTP trackers and the trait untouched under the recommended options.
Proof: RED `a_held_height_asks_no_network_93` (the inner tracker errs),
`a_reorg_invalidates_from_the_fork_height_93`,
`a_header_that_does_not_link_is_refused_93`; hermetic. Risk 0.45 (a stale window is a wrong verdict;
the shape is the owner's). One lane, one PR, parallel with P0 to R2.

**R5. The record.** A captain's dispatch records the lower rows per machine
(`-f bench_baseline_record=true`), reviewed and committed alone. Risk 0.1.

## 5. The slicing

| Lane | Waits on | Gate | Files |
|---|---|---|---|
| L1 = P0 | #734 landed (it edits `merkle_path.rs` or `verify.rs`) | suite, ratchet, harness identical | `merkle_path.rs`, new `merkle_path_walk.rs`, `mod.rs`, `nightly_mutants.py`, `nightly.yml`, `docs/ratchets.json` |
| L2 = R1 | L1 | RED, differential, fuzz, bench delta, harness | `merkle_path_walk.rs`, `merkle_path.rs:357-376`, `fuzz_merkle_path.rs`, tests |
| L3 = R2 | L2, Q93.1 | as L2 plus the new bench id | `merkle_path_walk.rs`, `benches/merkle_path.rs`, `benches/baseline.json` |
| L4 = R3 | L3, #734, Q93.2 | RED, counting tracker, harness | `verify.rs` |
| L5 = R4 | Q93.3 to Q93.5; parallel with L1 to L3 | RED set, wasm32 slice build | new `header_window.rs`, `chain_trackers/mod.rs`, `transaction/mod.rs`, both `CLAUDE.md` |
| L6 = R5 | L2, L3 on beta | dispatch run | `benches/baseline.json` |

Shared by two lanes: `merkle_path_walk.rs` (L1, L2, L3, in order);
`benches/baseline.json` (L3, L6, and every bench lane of #90, #91, #92).

Collisions with open work: #734 (`verify.rs:212-227`, `merkle_path.rs`,
possibly a new `MerklePath::verify`; it lands before L1 and L4); #603
(`merkle_path.rs` tests, `merkle_path_603_tests.rs`, `nightly_mutants.py:31`;
P0's move changes its surface list); #91 (`beef_stream.rs`: this design leaves
`bump_root` alone); #92 (`verify.rs`, the `transaction_sign_verify` bench's
proof check); #94 (`chain_trackers/whatsonchain.rs`, `block_headers_service.rs`:
R4 adds a file beside them and edits only `mod.rs`); #96 (the `transaction`
slice's size grows by R4); #97 (the harness step this design runs by hand);
#98 (tracker fault tests). By their titles `[D]`, #735, #751, #756, #775, #782, #785, #786,
#796, #90, #95, #99 and #100 share only `CHANGELOG.md` and the root `CLAUDE.md`.

## 6. The owner's questions

**Q93.1 The public door of the shared walk.** (a) none: crate-private, used by
`verify` only; (b) additive `MerklePath::compute_root_shared(&self, txid, &mut SharedRoots)`
with a public opaque `SharedRoots::new(block_height)`; (c) a
`verify_paths(&[(txid, &MerklePath)], tracker)` function. Reference default:
none, its cache is private to one path (`MerklePath.ts:335-354`).
Recommendation: (b), additive and opaque, so the toolbox's
`src/storage/sqlx/proof_root_checks.rs:141` can share nodes across its own loop. Cost: (a) no
gain outside `verify`; (b) and (c) one additive item, taken by the toolbox at
its re-pin, invisible to the workers.

**Q93.2 Fewer tracker calls than the reference in one `verify`.** (a) memoize
`(height, root)` per call; (b) keep one call per proven transaction
(`Transaction.ts:1311`). Recommendation: (a), a stated divergence row (call
count, no verdict). Cost: a dependent's mock that counts calls sees fewer
(the toolbox and CLI tests, to grep before landing); (b) costs every BEEF door
n requests.

**Q93.3 Who feeds the window.** (a) the host alone (`insert`, from its header
service or event feed); (b) also a new defaulted trait method
`ChainTracker::header_for_height -> Result<Option<BlockHeader>, _>` so the
wrapper can fetch and hold on a miss; (c) learn from an inner `true` (a root
text, no header). Reference default: no window at all; the trait is two
required methods and two optional context members (`ChainTracker.ts:26-42`). Recommendation: (a) now, (b) as a later additive
step when a consumer asks; never (c), which is the toolbox `RootCache`'s
unlinked positive. Cost: (a) the toolbox wires its `find_header_for_height`
into `insert`; (b) every implementer inherits a default; (c) no linkage evidence.

**Q93.4 Reorg semantics.** (a) the host must call `invalidate_from`; a window
never fed an event serves a root until evicted; (b) also hold only headers at
least `k` below the fed tip. Reference default: none. The charter: a reorg
rechecks every `mined(h')` at or above the fork height (`docs/charters/tracker.md`
section 4). Recommendation: (a) with (b) at a caller-set `k` whose default is
0, named in the door's brief like the work budget. Cost: a host with no event feed should not enable the window.

**Q93.5 The toolbox consumer.** The issue names "the toolbox's HeaderStore";
none is on record. (a) the toolbox replaces `RootCache` with `HeaderWindow`;
(b) the toolbox keeps its cache and the window serves the CLI and workers.
Recommendation: (a), filed on the toolbox by its captain; R4 does not wait.

**Q93.6 The capacity default and whether any tracker is windowed by default.**
Recommendation: no default wrapping (behaviour unchanged for every dependent);
capacity a required constructor argument, no constant of this crate's.

## 7. Stack alignment

- The owner's offset-0 ruling and its vectors: bsv-stack-lean
  `conformance/merkle-path-lone-leaf.json`, `docs/readings/one-transaction-block-lone-leaf.md`
  section 4; `lean/BeefOfAnySize.lean` `climb` (`:495`), `Bump.lone?`. R1 and
  R2 branch on the lone-leaf shape before any new code.
- `docs/charters/tracker.md` sections 2 and 4: only headers and proofs are
  evidence, the header kept, a reorg rechecks from the fork height (R4).
- `docs/MATRIX.md` row 15 (our transaction is mined: the SDK's root check and
  the lone-leaf divergence) and row 27 (the header service behind: fail closed).
- T1: the window is bounded by `capacity`, the shared map by the paths given.
  T2: a held header is the evidence a root is compared with. T3: no request
  for a held height. T4: unchanged. T5: (c) of Q93.3 refused, a provider's
  word without its header. T6: a RED test per step and the replayed lone-leaf
  cases; no new Lean statement.

## 8. Not in this design

- #734's coinbase depth rule and any `MerklePath::verify`: its own lane, ahead
  of L1 and L4.
- The stream's `bump_root` and `Headers` (a sync `Headers` for the window
  would read a miss as `false`, an invalid verdict for an unavailable header):
  #91 and a later issue.
- Persisting headers, proof-of-work and difficulty checks on fed headers, a
  header feed client: the toolbox and chaintracks.
- Leaves held as bytes in `MerklePathLeaf` (a public field): the next api-break.
- HTTP pooling and retries for the trackers: #94.
