# The designs for phases 2 to 5 (#90 to #100)

Written on 2026-11-09 by eleven design lanes on Claude Fable 5.2, one per issue, each from `origin/beta` at `e228c61a`: the exit test and the scoreboard row it moves, what exists today by `path:line`, the gap, the ranked steps with what each must leave identical and the proof it returns, the slicing into lanes, the owner's questions, and the stack alignment. No lane ran a build or a bench: a number that is not on record is named as a measurement the opening lane takes. `[X]` marks a claim read at the line or run, `[D]` one told or proposed, as the loop in [NORTH-STAR.md](../NORTH-STAR.md) says.

These are proposals. They change no source, no fixture and no public shape; a lane is briefed from a design only after the questions it waits on are answered. The public API's shape, the schema, the pins, any release and any spend stay the owner's (NORTH-STAR.md, "Never without the owner's word").

## The eleven

| Issue | Phase | Design | The lanes that can open without an answer | The lane's confidence |
|---|---|---|---|---|
| [#90](https://github.com/Calhooon/bsv-rs/issues/90) | 2 | [Script interpreter throughput on the sibling's corpus](90-interpreter-speed.md) | L0: measure the tip on a quiet host (the bench, a seed profile, allocations per input); then L1 (`Spend` construction without the clones) and L4 (`to_hex` from a table) in parallel | 0.72 |
| [#91](https://github.com/Calhooon/bsv-rs/issues/91) | 2 | [The streaming BEEF reader's memory bound](91-beef-streaming-memory.md) | A: three bench families at 1, 10 and 100 MB with an allocator peak; B: the reader counts the bytes it holds (no behaviour change) | 0.78 |
| [#92](https://github.com/Calhooon/bsv-rs/issues/92) | 2 | [Signing and verification throughput](92-sign-verify-throughput.md) | L0: measure at the tip, profile verify, add the distinct-key and wallet-path ids; L1 (`sign` without the per-call `SigningKey`, the memoized public key) beside L2 (`verify` without the key's re-encoding) | 0.82 |
| [#93](https://github.com/Calhooon/bsv-rs/issues/93) | 2 | [Merkle path verification and the tracker's header window](93-merkle-verify-and-header-window.md) | L1: move the walker to its own file (a refactor, after #734); L2: the byte walk for one path | 0.72 |
| [#94](https://github.com/Calhooon/bsv-rs/issues/94) | 3 | [The HTTP JSON substrate: pool, retries, bounds](94-http-json-substrate.md) | L1: measure today (a bench and a connections-opened count); L3: split the attempt out (a refactor) | 0.8 |
| [#95](https://github.com/Calhooon/bsv-rs/issues/95) | 3 | [ARC batch submission and per-source words](95-arc-batches.md) | Lane 1: `ArcBroadcaster::broadcast_many` as one `POST /v1/txs`, read as the reference reads it, with a recorded vector (this alone passes the exit test); lane 2: the fault table across a batch (tests) | 0.8 |
| [#96](https://github.com/Calhooon/bsv-rs/issues/96) | 4 | [The wasm32 slices and their size budgets](96-wasm32-budgets.md) | A: the slice table as data and the size record (after the beta.8 cut, since the blocking set moves the sizes); B: the consumer map as an arch test | 0.8 |
| [#97](https://github.com/Calhooon/bsv-rs/issues/97) | 5 | [The sibling's harness on every PR](97-sibling-harness-in-ci.md) | S1: one command (`sibling_harness.py`) and the committed column, which also takes the measurements | 0.8 |
| [#98](https://github.com/Calhooon/bsv-rs/issues/98) | 5 | [The chaos suite for the substrates and transports](98-chaos-suite.md) | see the document's slicing | 0.8 |
| [#99](https://github.com/Calhooon/bsv-rs/issues/99) | 5 | [Reproducible builds, an SBOM, signed releases, semver on every tag](99-release-evidence.md) | L0 after the beta.8 cut (the comparison of two builds of one tag) | 0.82 |
| [#100](https://github.com/Calhooon/bsv-rs/issues/100) | 5 | [The canary and re-pin policy](100-canary-and-repin-policy.md) | lanes A and B after the owner's answers (the policy is the owner's and the consumers' captains') | 0.8 |

The hot-path designs (#90 to #93) each open with a measurement on a quiet host, because no figure at the tip is on record (the baselines date from October); the measurement confirms or reorders the ranked steps before any source moves.

## Decision records

A record writes down what an ensemble of design reads decided, why, and what is built, for whoever works here next. It changes no source either.

| Issue | Record | State |
|---|---|---|
| [#843](https://github.com/Calhooon/bsv-rs/issues/843) | [Identity and framing: the class of #840, the two laws, the decisions of three ensembles and a tie-break, the stable-line path](843-identity-and-framing.md) | decided 2026-11-10 with the owner's word, and more after it (the record's section 9: one id type, the wallet included; the API read's breaks; the node's oracle required); #840's reader fix merged (PR #841, `7df16cf6`), #842's open (PR #846), the ownership break and the id type not built; the record's state lines are kept by the PR that lands what it names |

## The owner's questions

Each design's section 6 carries the options, the reference-shaped default with its line, and what each option costs the dependents. Condensed here, each with the lane's recommendation. Where a question only fixes a measurement, a gate or a record, the captain proceeds on the recommendation and says so on the issue; where it fixes a public shape, a resource semantic, a secret, a pin, a release or a policy, the lanes that wait on it stay closed until the owner answers.

### #90: Script interpreter throughput on the sibling's corpus

- Q90.1 "The gate: #601's flag or NORTH-STAR's loop?" Recommend the loop for S1 to S4, the flag for S5 alone.
- Q90.2 "What factor closes #90?" Recommend any factor above the gate's 5% on both platforms, stated in the record; a floor only after L0.
- Q90.3 "The workload." Recommend adding `script_spend/<corpus>` ids for the sibling's `crypto` and `tx`, with `seed_block` still the scoreboard's figure; the sibling ref at `bench.yml:103` moves from `8840488` to `5dc337e1`.
- Q90.4 "Retained capacity under a memory budget (S5 only)." Recommend no reuse unless L0 shows the share above 10%.
- Q90.5 "A public borrowed constructor." Recommend no public change now; reopen with L0's share of the clone.
- Q90.1 answered with the flag for every step doubles the lanes' size and delays the row: 0.30

### #91: The streaming BEEF reader's memory bound

- Q91.1, what "flat in BEEF size" means: recommend flat in bytes at a fixed element count plus a pinned constant per element (the charter's theorem), not an off-heap index.
- Q91.2, the bound's semantic and default: recommend a local decline with default `None`; the stack's word is needed too, since an index budget goes past the charter's "one element" and the keeper's "no bound" on #240.
- Q91.3, the public shape: recommend the budget struct and a new `ReaderDeclined` arm on `Verdict` and `Stop`.
- Q91.4, baseline schema and 100 MB rows: recommend `memory[]` rows gain `family` and the allocator peak, 100 MB as a memory probe only.
- Q91.5, release line: recommend landing on `beta` after `0.9.0`, additive, no pin moved.

### #92: Signing and verification throughput

- Q92.1 What "batch verification" is: (a) in-crate parallel inputs, additive and native-only.
- Q92.2 Threads inside a crate that starts no runtime: (a) `std::thread::scope` off wasm32, caller's count.
- Q92.3 The resource semantic on a refusal: (c) chunks of the thread count.
- Q92.4 `SigningContext`'s shape for S3: (a) new field in the 0.9.0 break window.
- Q92.5 Caching the shared secret: (a) on by default, zeroized on eviction.
- Q92.6 `derive_private_keys` on `KeyDeriverApi`: (a) trait method with a default body.
- Q92.7 The backend: (a) k256 stays.
- Q92.8 The factor that reads "at target": (b) a named floor, sign p50 at or below half the Linux baseline.

### #93: Merkle path verification and the tracker's header window

- Q93.1 "The public door of the shared walk": none / `compute_root_shared` with an opaque `SharedRoots` / `verify_paths`. Rec: the opaque additive method.
- Q93.2 "Fewer tracker calls than the reference in one `verify`" (`Transaction.ts:1311` asks per transaction). Rec: memoize, as a stated divergence row.
- Q93.3 "Who feeds the window": host alone / a defaulted `header_for_height` trait method / learn from an inner `true`. Rec: host alone now, the trait method later, never the third.
- Q93.4 "Reorg semantics": host calls `invalidate_from` / also hold only headers `k` below the fed tip. Rec: both, `k` caller-set, default 0.
- Q93.5 "The toolbox consumer": replace its `RootCache` with the window / keep it. Rec: replace, filed on the toolbox; R4 does not wait.
- Q93.6 "The capacity default and whether any tracker is windowed by default". Rec: no default wrapping, capacity a required argument.

### #94: The HTTP JSON substrate: pool, retries, bounds

- Q94.1 The public shape of retry: recommend `RetryPolicy` and builder methods on `HttpWalletJson`, default none.
- Q94.2 Default on or off: recommend off through 0.9.x.
- Q94.3 What repeats after `MayHaveBeenReceived`, and after a 503 with `Retry-After`: recommend the 21 non-mutating calls only; a mutating call on a 503 without the busy word is not repeated.
- Q94.4 The deadline (item 20.b, row 35): recommend connect timeout and keep-alive only; a per-call deadline waits on the keeper's ruling.
- Q94.5 `http` enables `dep:tokio` (`sync`, `time`): recommend yes.
- Q94.6 A scoreboard row and its gate: recommend a row with connections gated, time recorded only.
- Q94.7 The class and the 503's wait in the public error: recommend leave `WalletTransport` now, file the change for the next api-break.

### #95: ARC batch submission and per-source words

- Q95.1 "Which service does the batch client speak, given #350?" ARC's `/v1/txs` on the deprecated type now; ARCade only on a separate word after a pinned read.
- Q95.2 "What is a 'typed word per source' in this crate?" What exists: `code` plus `transport_fault()`, the source being the instance the caller holds.
- Q95.3 "Result order." The answer's order, as the reference returns it; callers key by txid.
- Q95.4 "Does the toolbox's outbox (its #71) take the SDK's client or keep its own providers?" Keep its providers until #71's design names the SDK.
- Q95.5 "The batch body form." EF hex with raw fallback for the batch; file the single post's raw form as a parity issue.
- Q95.6 "A scoreboard row for throughput?" None; Phase 3 exits on the named test and its record.

### #96: The wasm32 slices and their size budgets

- Q96.1 The artifact a budget judges: (a) release dead-code `cdylib`, (b) probe, (c) each worker's own `.wasm`. Rec: (a) gated, (b) reported, (c) the workers' captains'.
- Q96.2 The numbers and who may raise one: recorded +5%, +10%, or absolute. Rec: +5%; captain raises under 1% with a cold read, owner above.
- Q96.3 Which event "CI" is. Rec: `features.yml` on dispatch, nightly and tag, plus the combined slice's budget in `checks` if the added build measures under two minutes.
- Q96.4 The named set. Rec: today's six plus `overlay` without `wasm`, names kept.
- Q96.5 Reductions that change the feature shape. Rec: additive only, each its own word.
- Q96.6 The toolchain of the size job. Rec: floating `stable` with `rustc -V` recorded, pinned when #99 lands.

### #97: The sibling's harness on every PR

- Q97.1 The private sibling in a public repository's CI: token, public edition, or in-tree evaluator? Token now, public edition when it exists.
- Q97.2 A PR without the secret (a fork): fail closed or skip loudly? Fail closed.
- Q97.3 A sixth required context or a step of `checks`? A job of its own.
- Q97.4 The witness in public: full tx, ids only, or everything? Full tx for seed; id alone for corpora with withheld rows.
- Q97.5 A ruled divergence before the sibling's table moves: no waiver or a waiver file? No waiver unless a landing ever waits on the sibling.
- Q97.6 The pin `5dc337e1` for the job, the column and `bench.yml`? Yes.

### #98: The chaos suite for the substrates and transports

- Q98.1 "Do the wallet substrates get a default deadline?" No for now; a default only with the stack's word on matrix row 35.
- Q98.2 "Do the overlay facilitators (and storage) answer `Error::TransportFault` in place of `OverlayError` strings?" Yes for the facilitators in 0.9.x, storage after.
- Q98.3 "`WhatsOnChainTracker`'s timeout: what shape?" An additive `with_timeout_ms` builder, default 30,000.
- Q98.4 "Is the WebSocket transport's failure typed now?" Yes, once S2 records the witness.
- Q98.5 "Does 'every PR' admit the docs-only exit, and does the scoreboard gain a chaos input?" Skip as `vectors` does; no collector change.

### #99: Reproducible builds, an SBOM, signed releases, semver on every tag

- Q99.1, the release's lock: track a root `Cargo.lock`, place `tools/ratchet/library.Cargo.lock` at release, or package with no lock. Recommend the library lock.
- Q99.2, the exit test before 1.0: cargo's rule (patches bound now, minors from 1.0, breaks recorded) or an allowance file for a breaking 0.x minor. Recommend cargo's rule now.
- Q99.3, the signature: GitHub attestations, cosign, an owner-held key, or signed tags. Recommend GitHub keyless attestations.
- Q99.4, a GitHub Release per tag (one job gains `contents: write`). Recommend yes, written by the `attest` job alone.
- Q99.5, the SBOM: format and scope. Recommend one CycloneDX JSON over the locked all-features graph.
- Q99.6, the release toolchain: one named cargo or floating `stable`. Recommend pinning at the semver tool's 1.95.0.
- Q99.7, the scoreboard: recommend semver under the Dependents row and a new "Release evidence" row on #101.
- Q99.8, a registry mismatch after publish: red run with the owner deciding the yank, or automatic yank. Recommend the owner decides.

### #100: The canary and re-pin policy

- Q100.1 What "current minor" means on a prerelease line. Recommend: latest minor on `main` for stable rows, latest beta for canary rows.
- Q100.2 Where the three behind go. Recommend: `0.8` now on dates, since 0.9.0's date is not on record.
- Q100.3 Lock schema 2 and the private apps. Recommend: schema 2, apps as name-only entries.
- Q100.4 Whether a red rehearsal holds a prerelease. Recommend: holds unless the lock names the break and migration by a reviewed PR.
- Q100.5 What closes the soak and what "the CLI's gate" is. Recommend: each captain's dated line, no timer; the CLI's captain names the gate's command.
- Q100.6 The pins and the names. Recommend: the keeper carries the dated table to the captains and records answers on #100.
