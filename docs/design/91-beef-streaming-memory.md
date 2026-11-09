# Design for #91: the streaming BEEF reader's memory bound, as a bench and a limit a consumer sets

Read at `origin/beta` `e228c61a` (2026-11-09). `[X]` read at the line or by `git`/`gh`/`python3`; `[D]` told or proposed. No cargo ran for this page: every number is a record's, and a number with no record is named in section 2 for the opening lane to take.

## 1. The exit test and the scoreboard row

The issue (#91, open, labels `north-star, hot-path, scoreboard, design, after-cut`, milestone `hardening`) `[X]`: "The charter asks for a reader bounded per element. Measure the high-water mark on 1, 10 and 100 MB BEEFs; make the bound a parameter with a default; refuse past it with a typed error that names the element. **Exit test.** The bench's memory line is flat in BEEF size for the streaming mode."

The row it moves `[X]` (`docs/NORTH-STAR.md:24`): "BEEF streaming reader | Throughput and memory high-water by body size, with the element/index bound identified | `benchmarks`, `benches/baseline.json` and run artifact (#77, #91) | not yet measured". Epic #101's row: "memory flat in BEEF size, the bound a parameter".

"At target with recorded evidence" `[D]`, as a command and a record:

- Command: a dispatch of `bench.yml` (`benchmarks` runs `tools/bench-compare`, `:146`, over `cargo bench --bench beef_stream`).
- Record: `benches/baseline.json` rows `platforms/<machine>/memory[]` at the three sizes per family and mode, and the artifact the `scoreboard` job collects (`bench.yml:173`); `bench-compare` fails the run when the line is not flat (S1's rule). The cell is written from that output (`NORTH-STAR.md:52-54`).
- Beside it, the allocator pin: `RUST_TEST_THREADS=1 cargo nextest run --test memory_profiling --all-features` (`ci.yml:458-459`).

## 2. Today on beta

| What | Where `[X]` | Record |
|---|---|---|
| One element held: a transaction built in `TxBuilder.raw: Vec<u8>`, nothing kept once yielded | `src/transaction/beef_stream.rs:685-703`, `:716-722` | no bound on the element; a 16 KiB chunk (`:1378`) |
| The index: BUMP roots, level-0 txids, one `TxEntry` per txid, edges only under a subject, unspent outputs' scripts | `:1541-1568`, `:1739-1766` | one pass keeps every output's script until it is spent (`wanted: None`, `:1759-1762`) |
| Two-pass mode keeps only the outputs a spend names | `BeefIndex::retaining` `:1820`, `verify_stream_two_pass` `:3339` | needs `Read + Seek` |
| Held children (#240), no bound | `BeefIndex::deferred` `:1894` | counted in bytes already |
| `entries` `:1849`, `spec_size` `:1863`, `retained_outputs` (a walk) `:1876` | | counts; nothing answers "bytes held now" |
| The reader's budgets are the scripts' (work, stack memory per input), local, absent from the cursor | `beef_stream/budget.rs:70-153` | `set_memory_limit` (`:119`, `:148`) is the script stack's |
| `Verdict` and `Stop` are `#[non_exhaustive]` | `:2387`, `:1690` | a new arm is additive |
| The bench: 1 MB and 10 MB only, a chain of 1 KB links (the element COUNT grows with the size), sampled RSS in a fresh process | `benches/beef_stream.rs:27`, `:55-83`, `:94-144` | below |
| The gate reads four RSS rows, checks their arithmetic, prints the slope, judges nothing by it | `tools/bench-compare/src/main.rs:416-440`, `:709-721` | `benches/README.md:76-79` |
| The dhat pins: stream alone under 32 KiB; index under 400 B per element at 1,000, 4,000, 16,000 links, the marginal cost not growing | `tests/memory_profiling.rs:376`, `:435`, `:445` | 351 B per element (`src/transaction/CLAUDE.md`, the atomic paragraph) |

The baseline's memory rows `[X]` (`benches/baseline.json`, `platforms/*/memory`; delta is peak less start RSS):

| Machine | Mode | 1 MB (1,002 entries) | 10 MB (10,002 entries) | Slope, B RSS per B BEEF (computed here) |
|---|---|---|---|---|
| linux-x86_64, EPYC 7763 | structure | 880,640 | 2,580,480 | 0.189 |
| linux-x86_64 | scripts | 884,736 | 2,818,048 | 0.215 |
| macos-aarch64, M1 Max | structure | 901,120 | 4,243,456 | 0.371 |
| macos-aarch64 | scripts | 1,163,264 | 4,472,832 | 0.368 |

Also on record `[X]`: #67's figure at v0.7.0, about 213 B a link (the comment on #91). Row 17's blockers #86 and #77 are CLOSED (`gh issue view`).

**Not on record (never estimated here):** any 100 MB high-water; an allocator-level peak of the bench (sampled RSS can miss a transient, `README.md:74-76`); the peak when the bytes grow and the element count does not; the one-pass peak when large outputs stay unspent; the peak on one large element; the split of the 351 B between table and entry; the runner's time and disk for a 100 MB fixture; the stack's ruling on the bound and the owner's word on the resource semantic (row 17's blockers).

## 3. The gap

1. The bench's one family grows bytes and elements together, so its line cannot be flat: the index is linear in the elements by the charter's own theorem (section 7). No family isolates bytes.
2. 100 MB is not measured; the slope is printed, never judged.
3. No parameter bounds the element or the index; no typed stop names an element.
4. One pass over fat unspent outputs holds their scripts to the end (`:1759-1762`): linear in bytes, unmeasured.
5. Nothing answers the bytes the reader holds; a limit would walk the index per step.
6. #67's question (can an entry be dropped once nothing later can name it) has no recorded answer.

## 4. The design

### S1. The bench says what is flat (no `src/` change)

- **Change.** `benches/beef_stream.rs`: three families, each at 1, 10 and 100 MB, both modes. `count`: today's 1 KB links (the slope is the index). `bytes`: 1,002 entries at every size, the links' unlocking payload grown (`transaction()`, `:29-43`, pushes with `OP_PUSHDATA2`, so 100 KB a link needs `OP_PUSHDATA4`). `outputs`: the bytes in an output nothing spends, read in one pass and by `verify_stream_two_pass`. Each `BSV_BENCH_MEMORY` row gains `family`, `largest_element_bytes` and an allocator peak from a counting `#[global_allocator]` in the probe process (no new dependency), beside the RSS. `bench-compare` (`main.rs:416`) takes the rows by family and judges: on `bytes`, `peak(100 MB) - peak(1 MB) <= largest element + one chunk + a slack the lane measures`; on `count`, bytes per entry under a pinned figure and not rising with size. `benches/README.md:66-79` restated.
- **Why.** The exit test can then pass or fail; gaps 1, 2 and 4 are measured before any code moves. Expected `[D]`: `bytes` flat today; `count` flat per entry; `outputs` not flat in one pass, flat in two.
- **Identical.** Every `src/` byte, vector and verdict; the timing ids.
- **Proof.** `bench-compare`'s tests (the fixture's memory rows, `tests.rs:72-74`) RED on a fabricated non-flat `bytes` row; the dispatch's artifact; the baseline re-recorded by the runner on both platforms.
- **Risk 0.2** (RSS noise: the allocator peak is the judged number). **Size:** one lane, one PR.

### S2. The reader counts what it holds (`src/`, no behaviour change)

- **Change.** Counters kept at the fold: retained script bytes (replacing the walk of `retained_outputs`, `:1876`), entries by class, held bytes (`deferred` has it); the decoder answers the bytes of the element in hand. Additive accessors `BeefIndex::held_bytes()` and `BeefDecoder::element_bytes()`, a model as `spec_size` is. New code in a new file `beef_stream/held.rs` (`beef_stream.rs` is 3,526 lines against the 800-line ceiling).
- **Why.** S3 needs an O(1) answer per step (gap 5).
- **Identical.** Every verdict, cursor byte and error text.
- **Proof.** `memory_profiling`: dhat's peak within a pinned factor of `held_bytes()` at 1,000, 4,000, 16,000 links (RED with a counter left out); `beef_two_readers_agree` and `beef_stream_603_s*` unchanged; the sibling's `harness/run --impl bsv-rs --corpus seed` identical before and after; `cargo fuzz run fuzz_beef_parser`.
- **Risk 0.3** (counter drift on a release path of #240). **Size:** one lane, one PR.

### S3. The limit a consumer sets (public API: the owner's word, Q91.2 and Q91.3)

- **Change `[D]`.** `#[non_exhaustive] StreamMemoryBudget { per_element: Option<u64>, index: Option<u64> }`, the shape of `WorkBudget` (`work_budget.rs`), `new()` unbounded; `with_stream_memory_budget` on `StreamVerifier`, `AsyncStreamVerifier` and `BeefStream`. Enforced in the decoder BEFORE the allocation (a script's length varint precedes its bytes, so `raw.len() + run_len` is judged at the varint; a BUMP's leaves the same) and at the fold for the index (entries, retained scripts, held children). A stop is a new arm on both enums, `ReaderDeclined { offset, element, kind, limit, needed }`: the element's ordinal on the wire, its kind and its leading byte's offset. A LOCAL decline, never `Invalid` nor one of the twenty-six kinds, as work budgets stand beside consensus (#378, #519). Absent from the cursor, set again after `resume`; `Beef::from_binary` takes none.
- **Why.** Gap 3: a Worker learns which element it cannot hold, by type.
- **Identical.** `None` is today's behaviour on every path; cursors; the twenty-six kinds; `Error`'s 56 bytes.
- **Proof.** `tests/beef_stream_memory_bound_91.rs`, each RED on the base: `a_transaction_past_the_element_budget_is_declined_naming_the_element_91` (this crate's writer; a 70 KB element under 64 KiB; ordinal, offset, kind asserted; `Valid` at `None` and at the exact size); `the_decline_precedes_the_allocation_91` (dhat); `an_index_past_its_budget_is_declined_at_the_crossing_element_91`; `a_cursor_carries_no_budget_91`; the async twin. `fuzz_beef_parser` under a small budget: a decline never reads as `Invalid`. Sibling harness identical; semver additive; wasm32 builds.
- **Risk 0.45** (a public shape; the allocation-order claim on the BUMP path). **Size:** one lane, one PR, after the owner's word.

### S4. The entry's constant (optional, by S1's number)

- **Change.** Only if S1's bytes per entry are worth it: `TxEntry` packed (`:1548-1568`) and the table's growth step studied. A refactor, no behaviour change.
- **Proof.** The 400 B pin (`memory_profiling.rs:445`) lowered to the measured figure, RED on the base. **Risk 0.35** (it moves line anchors under #603's `.cargo/mutants.toml`). **Size:** one lane, or dropped.

### S5. The close-out (docs)

#67's answer on #91 (gap 6): in one pass no entry can be dropped, since any later input may name it and the atomic walk reads every edge at the end (`atomic_unreached`); the floor is the Lean's `Index.size`. Then `CLAUDE.md`'s contracts line, `src/transaction/CLAUDE.md`, the changelog, the scoreboard cell from the producer's run.

## 5. The slicing

| Lane | Waits on | Gate | Files |
|---|---|---|---|
| A = S1 | nothing | bench-compare's tests; a `bench.yml` dispatch (CI's Linux witness) | `benches/beef_stream.rs`, `benches/README.md`, `tools/bench-compare/src/{main,tests}.rs`, `benches/baseline.json` (runner-written) |
| B = S2 | nothing; parallel with A | the required set, sibling harness, fuzz | `src/transaction/beef_stream.rs` (calls only), new `beef_stream/held.rs`, `tests/memory_profiling.rs` |
| C = S3 | B landed; Q91.2, Q91.3 answered | the hot-path gate: required set, mutation floor, adversarial read, sibling harness, semver | `beef_stream.rs`, `beef_stream/budget.rs`, new test file, `tests/CLAUDE.md` row, `CHANGELOG.md` |
| D = S4 | A's record | as B | `beef_stream.rs`, `memory_profiling.rs` |
| E = S5 | A and C | docs gates | `CLAUDE.md`, `src/transaction/CLAUDE.md`, `docs/NORTH-STAR.md` |

B, C and D all edit `beef_stream.rs` (serial); B and D edit `memory_profiling.rs`; A shares no file with them.

Collision surfaces (titles `[X]`, the inference `[D]`):

- **The `0.9.0` blocking set** (#734 to #796, the nine, all open): identity, overlay lookup, PushDrop; #734 may touch `verify.rs` or `merkle_path.rs`; none names `beef_stream.rs`. Shared: `CHANGELOG.md`, `CLAUDE.md`, `tests/CLAUDE.md` (the keep-both rebase).
- **#603 (mutants):** `.cargo/mutants.toml` has 11 lines naming `beef_stream`, anchored by line `[X]`; a line moved there moves them (the `mutants-entries` gate); B, C and D each re-anchor in their own PR.
- **#90, #92, #93:** each writes `benches/baseline.json`, `tools/bench-compare/src/main.rs` and `benches/README.md`; the baseline is one runner's record, so the bench lanes land one at a time. #93 owns `bump_root` (`beef_stream.rs:405`).
- **#96, #97:** S3's wasm size delta; the harness run stays local until hosted.

## 6. The owner's questions

**Q91.1. What "flat in BEEF size" means.** (a) Flat in the bytes at a fixed element count, and a pinned constant per element at any count. (b) Flat in the element count too: the index off the heap (a store trait) or dropped entries. Reference-shaped default: the stack's `memory_bounded_per_element` (`lean/BeefOfAnySize.lean:2620-2623` at `13e1fa5d`) bounds the index by `es.length + 2 * claimed + inputs`, linear in elements; the TypeScript reference has no streaming reader (`Beef.ts:1240-1319` at `edf6e03` reads the whole body). Recommendation: (a), with (b) a stack-charter item if the keeper wants it. Cost: (a) nothing to any dependent; (b) a new public trait, a new cursor format and a re-pin for each Worker of `docs/DEPENDENTS.md` (overlay, middleware, message box, wallet infra).

**Q91.2. The bound's semantic and default.** (a) A local decline, default `None`. (b) A default figure. (c) No limit, accounting only. Reference-shaped default: `Beef.ts` at the pin has no bound (by grep); the charter says "a valid BEEF is never refused for its size or its counts" (`beef-of-any-size.md:5`) and leaves a caller a memory tool for "the one element it holds" (`:31`). Recommendation: (a); the stack's word is asked too: the index half goes past `:31`'s one element and the keeper's "no bound" on #240. Cost: (a) the toolbox and the CLI add one arm where they map `Verdict` (a wildcard is there since #240); (b) moves a verdict for every dependent on its next patch; (c) leaves "refuse past it" unmet.

**Q91.3. The public shape.** (a) `StreamMemoryBudget` and a new `ReaderDeclined` arm on `Verdict` and `Stop` (S3). (b) Two plain setters. (c) A new `NotJudgedCause`. Reference: none has the concept. Recommendation: (a): no confusion with `set_memory_limit`, and `NotJudged` carries a txid and an input an element stop lacks. Cost: additive in every case.

**Q91.4. The baseline's schema and the 100 MB rows.** (a) `memory[]` rows gain `family` and the allocator peak; 100 MB a memory probe only. (b) 100 MB also a Criterion timing id. Recommendation: (a); the runner's time for (b) is not on record. Cost: none outside this repository; `baseline.json`'s `schema_version` moves.

**Q91.5. The release line.** #91 is `after-cut`: S2 and S3 land on `beta` after `0.9.0`, additive. Recommendation: yes; this design moves no pin.

## 7. Stack alignment

At `bsv-stack-lean@13e1fa5d` `[X]`: `docs/charters/beef-of-any-size.md:5` (the posture), `:16` (the state: the index and at most one element), `:29-31` (NL-3), `:55` (T1); `lean/BeefOfAnySize.lean:834-835` (`Index.size`), `:2608-2623` (the theorem and what it does not say: "how many bytes an entry takes in a given host"); `docs/MATRIX.md:45` (a BEEF shaped to exhaust the parser: the wallet doors hold the body whole, "memory linear in the BEEF"). BRC-62 `transactions/0062.md:43` at `5119a9b` (the order has streaming validation in mind).

- **T1:** S1 makes "memory does not grow with the body" a judged line, the cost per element stated.
- **T2:** no check removed; a decline is never an acceptance.
- **T3:** one pass stays one pass; the counters are O(1) per fold.
- **T4:** no operator's number decides validity: the stop says declined, never invalid.
- **T5:** the scoreboard cell comes from the producer's JSON.
- **T6:** fixtures by this crate's writer; the RED tests and dhat pins replay.

## 8. Not in this design

- An off-heap index or entry eviction (Q91.1 (b)): a `stack-charter` issue if ruled.
- #749 and #621 item 1: the whole-path `Beef`, their own lanes; #621 item 2 (a public `Judge`) is the keeper's API question.
- The stream's throughput and `bump_root` (#93); wasm budgets (#96); the hosted harness (#97).
- The dependents' doors that hold a body whole (matrix row 45): their captains', after a pin carries S3.
