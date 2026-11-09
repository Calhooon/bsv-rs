# Design: #95, ARC batch submission and per-source words

Read at `origin/beta` `e228c61a` on 2026-11-09. `[X]` is read at the line or run in this lane; `[D]` is told or proposed. This lane ran no cargo. References: ts-stack `edf6e03`, bsv-stack-lean `13e1fa5d748b`, bsv-wallet-toolbox-rs `origin/beta` `545aa38b`.

## 1. The exit test and the scoreboard row

The issue [X] (`gh issue view 95`): "**Exit test.** A batch of 100 posts in one request against a stub; the words per source are typed." `docs/NORTH-STAR.md:94` [X]: "the batch workload uses one stub-server request and preserves typed words per source."

No scoreboard row moves [X]: none of the eight rows of `docs/NORTH-STAR.md:21-30`, nor of epic #101's table, measures a broadcaster. #95 moves the Phase 3 line, which the main-merge gate counts ("every phase (0 to 5) has exited", #101). "At target with recorded evidence" is a test, not a number:

- Command: `cargo test --features "full,http" --test broadcaster_batch_95` (a new file, section 4).
- Record: its output tail in `/Volumes/Lanes/out/bsv-rs/<lane>/exit-95.txt`, and the `test` job's run on the PR (`ci.yml:267`) [D].

## 2. Today on beta

| What | Where | State |
|---|---|---|
| `Broadcaster::broadcast_many` | `src/transaction/broadcaster.rs:204-210` [X] | default: one `broadcast` per transaction, in order |
| `ArcBroadcaster` | `src/transaction/broadcasters/arc.rs:337-394` [X] | deprecated since 0.9.0 (#350, `:333-336`); `broadcast` posts `{rawTx}` (raw hex, `:409`) to `/v1/tx` (`:408`); no override of `broadcast_many` |
| The 2xx verdict | `arc.rs:200-284` `arc_success_verdict` [X] | the reference's rule (`ARC.ts:110-180`), `pub(crate)` in a private `verdict` module |
| Typed faults | `src/transaction/broadcasters/transport_fault.rs:245-284` (`send_failure`, `body_failure`, `answered`) [X]; `BroadcastFailure::transport_fault()` `broadcaster.rs:123-136` [X] | `NEVER_SENT`, `MAY_HAVE_BEEN_RECEIVED`, `RATE_LIMITED` with the wait; every other word is `code: String` (`broadcaster.rs:76`) |
| Tests | `tests/broadcaster_http_tests.rs:291-311` `test_arc_broadcast_many` [X] | pins three `/v1/tx` posts (`.expect(3)`): the opposite of the exit test |
| | `tests/transport_fault_broadcasters.rs:124-327` [X] | the fault words per service, single post only |
| | `tests/vectors/arc_tx_status_verdicts.json` (`arc.rs:588-654`) [X] | single answers only |
| Benches | `benches/` (nine Criterion targets) [X] | none touches HTTP or a broadcaster |
| File ceiling | `arc.rs` is 655 lines [X]; `docs/ratchets.json:6` `files_over_800: 38` [X] | a batch reader inside `arc.rs` would cross 800 |
| The queue's blockers | #87 (its last commit `4dc505ff`), #76, #83: CLOSED [X] | none open |

The reference [X] (`ts-stack@edf6e03 packages/sdk/src/transaction/broadcasters/ARC.ts:345-409`): `broadcastMany` posts one JSON array of `{rawTx}` to `/v1/txs`; `rawTx` is EF hex, raw hex only when a source transaction is missing (`:93-104`); a non-2xx gives every transaction `failedArcResponse` (`:359-361`); an answer that is no array of the batch's length gives every transaction `ERR_INVALID_RESPONSE`, `ARC returned a malformed batch response.` (`:362-364`, `:378`); each item is matched to the submitted txids as a multiset (`:380-402`), an unsubmitted or repeated txid `ERR_TXID_MISMATCH`, `ARC batch acknowledged a transaction that was not submitted.` (`:394-400`), else the single verdict (`:403`); a thrown fetch gives every transaction code `500` (`:405-408`). Results come back in the answer's order, not the request's (`:385`).

The consumer [X]: the toolbox's outbox is its issue #71, OPEN, with no code (`outbox` appears only in its `docs/NORTH-STAR.md:130,187` at `545aa38b`). The toolbox calls no SDK broadcaster: a grep of its `src/` at `545aa38b` for `ArcBroadcaster`, `dyn Broadcaster`, `broadcast_many` returns nothing. It has its own providers: ARC's `POST /v1/txs`, a JSON array of EF hex (`src/services/providers/arc.rs:616-630`), and Arcade's `POST {url}/txs`, concatenated EF binary (`arcade.rs:706-712` at its `a3377ef0`).

## 3. The gap

1. `ArcBroadcaster::broadcast_many` sends N requests; the exit test wants one.
2. No test, vector or recorder covers a batch answer (mixed verdicts, a wrong length, a foreign txid, a repeated txid).
3. A whole-request fault on a batch has no stated reading (the reference's `500` for all; here the three typed words for all, an extension of the stated #87 row).
4. Matrix item 21.a asks for a replay of the disagreeing-broadcasters scenario; none exists in `tests/` [X].
5. ARC is deprecated here (#350) and "this crate adds no ARCade client" (`broadcasters/CLAUDE.md`): the issue's subject is a deprecated type (Q95.1).
6. The named consumer does not consume (section 2): Q95.4.

## 4. The design

Ranked; step 1 alone passes the exit test.

### Step 1: one request for a batch, read as the reference reads it

- **Change.** A new `src/transaction/broadcasters/arc_batch.rs` (keeps `arc.rs` under 800), declared in `broadcasters/mod.rs`; `impl Broadcaster for ArcBroadcaster` gains `broadcast_many` under `#[cfg(feature = "http")]` (`arc.rs:397`), delegating to it. One `POST {url}/v1/txs`, body `[{"rawTx": ..}, ..]` in request order, the single path's headers and timeout (`arc.rs:412-423`). The answer: `fault::answered` before the body (`transport_fault.rs:270`); a non-2xx mapped once by the single path's non-2xx arm (`arc.rs:439-451`, extracted to a shared function) and given to every transaction; a 2xx parsed as `Vec<serde_json::Value>`, the length and multiset rules of `ARC.ts:362-402` in its words, each item through `arc_success_verdict` (made `pub(super)`). A send or body fault is built once and cloned per transaction with that transaction's txid. Without `http` the default stays.
- **Why.** Closes gaps 1 to 3: 100 transactions, one round trip.
- **Identical.** `broadcast` and its bytes; `arc_tx_status_verdicts.json` and its replay; every error text of the single path; the public shape (an override of a trait method on an existing type; no new public item, so `semver` reads no change [D]); Teranode and WhatsOnChain (the sequential default, `teranode.rs:109`, `whatsonchain.rs:213`); the wasm32 slice.
- **Changes on purpose.** `test_arc_broadcast_many` (`.expect(3)` on `/v1/tx`) becomes one post to `/v1/txs`, in its own commit.
- **Proof.** RED before the override, each watched fail on a scratch copy: `a_batch_of_100_posts_in_one_request_95` (wiremock: `/v1/txs` `.expect(1)`, `/v1/tx` `.expect(0)`, the body an array of 100 in order, 100 results); `a_batch_answer_of_another_length_is_invalid_for_every_transaction_95`; `a_batch_item_for_an_unsubmitted_txid_is_a_mismatch_95`; `a_repeated_txid_is_matched_once_per_submission_95`; `a_mixed_batch_keeps_each_items_verdict_95`. Expected values come from a recorder, `tests/support/arc_batch_95.mjs`, running the pinned `ARC.broadcastMany` over an injected `httpClient` under Node 22, written to `tests/vectors/arc_batch_95.json` in its own commit (rule 3; the FIXTURES page and lock updated with it). The sibling run `harness/run --impl bsv-rs --corpus seed` identical before and after (the change is under `src/transaction/`; no verdict code is touched). Gate: rule 7's set.
- **Stated with it.** The CHANGELOG entry and parity note; the #87 divergence row extended (a whole-batch fault is the typed word for every transaction, where the reference answers `500` for each, `ARC.ts:405-408`); a `[{rawTx}]` row in the JSON body census (`src/CLAUDE.md`); the two module `CLAUDE.md` pages.
- **Risk 0.25**: the recorder may show the single path's non-2xx mapping differs from `failedArcResponse` (`ARC.ts:191-229`: the code is the HTTP status, `more` is `{detail, txid}`; here the body's `status` member and `extraInfo`, `arc.rs:441-450`). That is a finding filed apart, never folded in.
- **Size.** One lane, one PR, three commits (vector, test change, fix).

### Step 2: the typed words survive a batch, per instance (tests only)

- **Change.** `tests/broadcaster_batch_95.rs` gains `tests/transport_fault_broadcasters.rs`' fault table for a batch (refused connection, timeout after the write, 429 with `Retry-After`, bare 503, 502, body cut): each of the 100 results reads the same `transport_fault()`; and `two_instances_answering_one_batch_differently_are_two_answers_95`: two stubs, one `SEEN_ON_NETWORK` and one `REJECTED` for the same batch, each instance's results returned unchanged and keyed by the caller under `ArcBroadcaster::url()` (`arc.rs:386`), nothing joined.
- **Why.** Closes gap 4 and the exit test's "typed words per source" with what exists: the SDK composes nothing (matrix row 23).
- **Identical.** All of `src/`. **Proof.** The tests, each red against a planted reading that drops the class. **Risk 0.1.** One lane, test-only, after step 1.

### Step 3 (waits on Q95.5): the body form

The reference sends EF hex with a raw fallback (`ARC.ts:93-104`); this crate's single post sends raw (`arc.rs:409`; `Transaction::to_hex_ef` exists, `src/transaction/transaction.rs:1282`). Step 1 takes Q95.5's answer. The single path's move is its own parity issue and PR (`tests/broadcaster_http_tests.rs:232` changes). **Risk 0.3** (a wire shape). One lane.

### Step 4 (waits on Q95.2): a typed reader of the service's word

Only under Q95.2 (b): an additive `#[non_exhaustive]` enum read from `BroadcastResult` as `transport_fault()` reads `code` (`broadcaster.rs:123-136`), no field added. **Risk 0.35** (public API; bsv-tracker owns the reduction, charter B1). One lane.

### Step 5 (waits on Q95.1): an ARCade batch door

Not designed: Arcade's routes are unreadable on this host; a reading lane precedes any code.

## 5. The slicing

| Order | Lane | Waits on | Gate |
|---|---|---|---|
| 1 | `fix-95-arc-batch` (step 1) | Q95.1 (a), Q95.3, Q95.5 answered or defaulted | the RED tests green, the recorder run twice byte-identical, the sibling run identical, rule 7's set, wasm32 slice |
| 2 | `test-95-batch-words` (step 2) | lane 1 landed | its tests; no `src/` diff |
| 3 | `parity-arc-body-form` (step 3) | Q95.5 | its own vector commit |
| 4, 5 | steps 4, 5 | Q95.2, Q95.1 | the owner's word on the issue |

Lanes 1 and 2 are serial (one test file). Lane 3 touches `arc.rs` and `tests/broadcaster_http_tests.rs`, as lane 1 does: after lane 1, beside lane 2.

**Shared files.** `arc.rs`, `broadcasters/mod.rs`, `tests/broadcaster_http_tests.rs` (lanes 1, 3); and with every lane: `CLAUDE.md` (the divergence list), `CHANGELOG.md`, `src/CLAUDE.md`, `docs/FIXTURES.md` and its lock, `docs/ratchets.json`.

**Collisions with open work.**

- The 0.9.0 blocking set (#734, #735, #751, #756, #775, #782, #785, #786, #796): by their titles [X] they sit in merkle path, identity, overlay and PushDrop; none names a broadcaster file. Shared: `CLAUDE.md`, `CHANGELOG.md`.
- #94 (pooling, typed retries): the nearest neighbour. Its title names the HTTP JSON substrate; its body asks for a shared pooled client and retries on the typed transport fault [X]; whether it reaches ARC's `reqwest::Client` (`arc.rs:368,381`) or `transport_fault.rs` it does not say [D]. This design adds no client, no retry and no line to `transport_fault.rs`; a shared client from #94 arrives through `self.client`.
- #98 (chaos) reuses step 2's stubs; #93 (chain-tracker client) meets this design only at `transport_fault.rs`, untouched here.
- #603 (mutants): its body names no broadcaster file [X]; a new file enters the nightly's census.
- #90, #91, #92, #96, #97, #99, #100: no shared source file; #97 will host the sibling run lane 1 runs by hand.

## 6. The owner's questions

**Q95.1. Which service does the batch client speak, given #350?** (a) ARC's `/v1/txs` on the deprecated `ArcBroadcaster`; (b) a new ARCade client; (c) both; (d) close #95 as overtaken by #350 and the toolbox's own providers. Reference default: (a) (`ARC.ts:345-409`; ARC undeprecated there). Recommendation: (a) now, since it is the reference's own method and passes the exit test with no public change; (b) only on a separate word after a pinned read. Cost: (a) no dependent's build changes; a caller of `broadcast_many` on ARC sees one request for N (the toolbox calls none [X]; the other rows of `docs/DEPENDENTS.md` not grepped [D]). (b) a new public type; the toolbox could retire a provider.

**Q95.2. What is a "typed word per source" in this crate?** (a) what exists: `code` plus `transport_fault()`, the source the instance the caller holds; (b) an additive typed reader of the service's word; (c) a per-source record type. Reference default: (a) (`BroadcastResponse | BroadcastFailure` with a string `code`; matrix row 23: "the SDK needs no reconcile type"). Recommendation: (a) for the exit, (b) only when the outbox asks for it. Cost: (a) none; (b) an enum kept in step with bsv-tracker's `HintStatus`; (c) a public shape the tracker and the toolbox both map.

**Q95.3. Result order.** (a) the answer's order, as the reference returns it (`ARC.ts:385`), a mismatch carrying no txid; (b) the request's order, each submitted transaction given its item or a "not acknowledged" failure. Reference default: (a). Recommendation: (a), stated in the method's doc, since (b) is a divergence row and a word the reference never says. Cost: (a) a caller keys results by `txid`, never by index; (b) kinder to an outbox, one more divergence row.

**Q95.4. Does the toolbox's outbox (its #71) take the SDK's client or keep its own providers?** Reference default: the reference toolbox has its own ARC provider (the toolbox's citation at `arc.rs:93-100`, not re-read [D]). Recommendation: keep the providers until #71's design names the SDK; #95 then exits on parity and the stub test, its "the toolbox's outbox is the consumer" recorded as not yet true. Cost: none to bsv-rs; adoption is a toolbox refactor.

**Q95.5. The batch body form.** (a) EF hex with the raw fallback (`ARC.ts:93-104`); (b) raw hex, as this crate's single post sends (`arc.rs:409`). Recommendation: (a) for the batch, and the single post's difference filed as a parity issue (step 3), since rule 1 says the reference decides and ARC needs the source outputs to validate without a lookup. Cost: none to a build; a stub that matched raw bytes would see EF.

**Q95.6. A scoreboard row for throughput?** The scoreboard has none (section 1). Recommendation: none added; Phase 3 exits on the named test and its record. Cost of adding: a collector change and a producer (#84's surface).

## 7. Stack alignment

The broadcaster charter at `bsv-stack-lean@13e1fa5d748b` `docs/charters/broadcaster.md:15-19` (B1 to B5); `docs/MATRIX.md:23` (the SDK composes nothing); `lean/Sdk.lean:465,479` (`toWallet_is_hint`, `toWallet_keeps_chain`); the draft scenario `corpus/scenarios/sdk-broadcasters-disagree-no-reconcile.md`. B3: a batch is still one submission and one hop per instance. B5: a 46x for a batch is a hint for each of its transactions, never a word.

- T1: one request per batch per instance; cost follows our own transactions.
- T2: untouched; no batch answer is evidence.
- T3: one hop where there were 100.
- T4: no rule moves to an operator.
- T5: no new trusted word; a fault stays a fault for every transaction of the batch.
- T6: the recorder's vector and the stub tests; no Lean statement added.

## 8. Not in this design

- Retries, pooling, `Retry-After` handling, a response body cap: #94 and #98. The batch answer is read whole, as the single one is.
- Quorum, fallback or reconciliation across instances: outside the SDK by matrix row 23.
- The reference's `deploymentId`, callback and custom headers (`ARC.ts:288-313`), absent from `ArcConfig` (`arc.rs:293-300`): its own parity issue.
- A throughput number: none is on record and the exit test asks for none; a wall-clock comparison belongs to #94's stub bench.

**Not found on record:** ARC's `/v1/txs` handler at `arc@e7efc5b` and any batch size limit (no clone on this host; the toolbox's comment at `arc.rs:616` describes a bare array with inline error items, which the reference would read as `ERR_INVALID_RESPONSE` per item [D]); Arcade's routes at its pin; the toolbox outbox contract (no code); the reference's verdicts on batch bodies (lane 1's recorder); any HTTP bench.
