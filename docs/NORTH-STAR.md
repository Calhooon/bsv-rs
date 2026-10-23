# NORTH STAR: bsv-rs

Build and verify the BSV application stack with one measured Rust implementation
on native and wasm32. This is the crate's row in the shared programme with
[bsv-wallet-cli](https://github.com/Calhooon/bsv-wallet-cli/issues/106) and
[bsv-wallet-toolbox-rs](https://github.com/Calhooon/bsv-wallet-toolbox-rs/issues/80).
[Epic #101](https://github.com/Calhooon/bsv-rs/issues/101) owns the scope;
this page follows the CLI epic's sections. Its `docs/NORTH-STAR.md` was not yet
on `origin/beta` when read on 2026-10-23.

## The scoreboard

Measurements belong to producer outputs, never to hand-edited cells here.
The `scoreboard` job in [ci.yml](../.github/workflows/ci.yml) writes one JSON
document to its job summary and `$RUNNER_TEMP/scoreboard.json`. Each record
keeps its source commit, run and artifact, or identifies a repository baseline.
An available baseline is not a measurement of the current PR. A nightly result
is a current mutation floor only when its producing run covers that commit.
`available` means an input was collected, not that its target passed.

| Area | What the producer must measure or prove | CI producer and JSON input | Current measurement |
|---|---|---|---|
| Script interpreter | Throughput on the sibling's seed corpus; identical conformance verdicts | `benchmarks`, `benches/baseline.json` and run artifact ([#77](https://github.com/Calhooon/bsv-rs/issues/77)); conformance job and artifact pending [#97](https://github.com/Calhooon/bsv-rs/issues/97) | not yet measured |
| BEEF streaming reader | Throughput and memory high-water by body size, with the element/index bound identified | `benchmarks`, `benches/baseline.json` and run artifact ([#77](https://github.com/Calhooon/bsv-rs/issues/77), [#91](https://github.com/Calhooon/bsv-rs/issues/91)) | not yet measured |
| Merkle path verification | Shared-block paths at the workload specified in #77 and #93 | `benchmarks`, `benches/baseline.json` and run artifact ([#77](https://github.com/Calhooon/bsv-rs/issues/77)) | not yet measured |
| Signing and verification | Multi-input signing and batch verification | `benchmarks`, `benches/baseline.json` and run artifact ([#77](https://github.com/Calhooon/bsv-rs/issues/77), [#92](https://github.com/Calhooon/bsv-rs/issues/92)) | not yet measured |
| Wallet wire codec | Encoding and decoding every call's request and result | `benchmarks`, `benches/baseline.json` and run artifact ([#77](https://github.com/Calhooon/bsv-rs/issues/77)) | not yet measured |
| wasm32 | Every consumer's feature slice builds and stays within its approved size budget | `wasm32` pending [#80](https://github.com/Calhooon/bsv-rs/issues/80); machine-readable `wasm-sizes.json` and budgets pending [#96](https://github.com/Calhooon/bsv-rs/issues/96) | not yet measured |
| Code health | Falling ratchets, empty deny ignore list, isolated features, mutation floor per covered file | `ratchet`, `docs/ratchets.json` ([#78](https://github.com/Calhooon/bsv-rs/issues/78)); deny job pending [#79](https://github.com/Calhooon/bsv-rs/issues/79); `features` pending [#80](https://github.com/Calhooon/bsv-rs/issues/80); nightly `mutants`, `mutation-summary.json` pending [#81](https://github.com/Calhooon/bsv-rs/issues/81) | not yet measured |
| Dependents | Consumer builds, semver guard and current pins or dated plans | Job and artifact pending [#83](https://github.com/Calhooon/bsv-rs/issues/83); pin ledger in [DEPENDENTS.md](DEPENDENTS.md), pending that lane | not yet measured |

The existing `test`, `vectors`, `clippy` and `msrv` jobs provide checks and logs;
they do not yet publish these measurements. The scoreboard is a collector,
not a substitute for their gates. Each missing producer is named in its JSON.
At the 2026-10-23 read, none of the listed JSON producers had landed on `beta`;
the job names and inputs above are the intended contracts from their lane briefs.

Collector inputs are deliberately small: benchmark artifacts named with `bench`
containing `benches/baseline.json` or `baseline.json`; ratchet artifacts named
with `ratchet` containing `docs/ratchets.json` or `ratchets.json`; wasm artifacts
named with `wasm` containing `wasm-sizes.json`; and mutation artifacts named with
`mutant` or `mutation` containing `mutation-summary.json`. Paths may have a
directory prefix. Repository baselines are collected separately. These are
collector conventions for producers still to land, not claims that their jobs
exist. The collector reads artifacts from this CI run only; a mutation producer
must supply its summary in this run to populate that input. The separate
`nightly.yml` run keeps its own summary until such forwarding is wired. This
avoids treating an earlier run as the current PR's mutation score and preserves
the reusable release workflow's existing read permissions.

When a producer lands, add its job to `scoreboard.needs`, publish its JSON using
the convention above (or update the collector to the actual name), and update
the relevant cell. Do not transcribe a lane's local numbers into this page.
The collector fails on malformed available JSON or an input read failure;
an absent artifact or baseline remains `not yet measured`.

## The phases

Each line is the issue's exit test, not a claim that it has passed. Workloads,
thresholds and protocol decisions stay with the linked issue and its reference.

### Phase 0: the oracle

- [#75](https://github.com/Calhooon/bsv-rs/issues/75): every check runs on a PR into `beta`, and a beta prerelease tag publishes as a prerelease.
- [#76](https://github.com/Calhooon/bsv-rs/issues/76): any public fixture byte change fails CI unless its fixture changes in its own commit.
- [#77](https://github.com/Calhooon/bsv-rs/issues/77): CI produces the scoreboard's benchmark numbers and a regression fails the PR.
- [#78](https://github.com/Calhooon/bsv-rs/issues/78): a PR that raises a ratcheted count fails.
- [#79](https://github.com/Calhooon/bsv-rs/issues/79): `cargo deny check` passes in CI with an empty ignore list.
- [#80](https://github.com/Calhooon/bsv-rs/issues/80): planted architecture violations fail, each feature builds alone, and wasm32 builds.
- [#81](https://github.com/Calhooon/bsv-rs/issues/81): the nightly publishes the mutation score per file.
- [#82](https://github.com/Calhooon/bsv-rs/issues/82): every reader of external bytes has a fuzz target.
- [#83](https://github.com/Calhooon/bsv-rs/issues/83): breaking minor changes and broken consumer builds fail CI, and the dependents table is current.
- [#84](https://github.com/Calhooon/bsv-rs/issues/84): CI writes the scoreboard from producer outputs, naming absent producers.

### Phase 1: structure

- [#85](https://github.com/Calhooon/bsv-rs/issues/85): interpreter files meet the file-size ceiling, the sibling run is identical, and mutation coverage does not fall.
- [#86](https://github.com/Calhooon/bsv-rs/issues/86): whole and streaming BEEF entry points share fixture and fuzz refusals, and the duplication ratchet falls.
- [#87](https://github.com/Calhooon/bsv-rs/issues/87): architecture lints pass and the toolbox maps the transport fault by type.
- [#88](https://github.com/Calhooon/bsv-rs/issues/88): each documented architecture invariant names its test.
- [#89](https://github.com/Calhooon/bsv-rs/issues/89): all wordlists are text data and BIP39 tests and vectors pass.

### Phase 2: the hot path

- [#90](https://github.com/Calhooon/bsv-rs/issues/90): script throughput improves by a measured factor with identical conformance verdicts.
- [#91](https://github.com/Calhooon/bsv-rs/issues/91): the streaming memory benchmark meets the issue's flat-memory exit test; the charter's element/index accounting and any public limit semantics need resolution before code.
- [#92](https://github.com/Calhooon/bsv-rs/issues/92): the signing/verification benchmark improves by a measured factor and the vectors pass.
- [#93](https://github.com/Calhooon/bsv-rs/issues/93): the merkle benchmark improves and the lone-leaf and offset vectors remain unchanged.

### Phase 3: throughput

- [#94](https://github.com/Calhooon/bsv-rs/issues/94): the stub-server workload measures pooling's effect and public body fixtures stay identical.
- [#95](https://github.com/Calhooon/bsv-rs/issues/95): the batch workload uses one stub-server request and preserves typed words per source.

### Phase 4: fleet-facing

- [#96](https://github.com/Calhooon/bsv-rs/issues/96): CI builds every named wasm32 slice within its approved budget.

### Phase 5: hardening

- [#97](https://github.com/Calhooon/bsv-rs/issues/97): a verdict that differs from the node machine fails the PR with its witness transaction.
- [#98](https://github.com/Calhooon/bsv-rs/issues/98): the substrate and transport chaos suite runs on every PR.
- [#99](https://github.com/Calhooon/bsv-rs/issues/99): two builds of a tag are identical and a breaking change cannot publish as a minor.
- [#100](https://github.com/Calhooon/bsv-rs/issues/100): `RELEASING.md` carries the canary policy and every dependent has a current pin or dated plan.

## The lines

Programme work starts in a lane worktree from `origin/beta` and lands through a
reviewed PR into `beta`. `main` is the stable line for quick fixes. The captain
owns line synchronization, branch protection and release tags under
[#75](https://github.com/Calhooon/bsv-rs/issues/75) and
[RELEASING.md](../RELEASING.md). A beta tag is not admitted to the stack's line.
Neither this page nor a green collector authorizes a release or a pin move.

## The loop

1. Take one ranked item into its own worktree from `origin/beta`. Return the
   change, the proof, and evidence of what stayed identical: fixture diff,
   conformance output and benchmark delta as applicable.
2. A separate review lane on a different model reads the diff and issue cold.
   Keep each PR to one concern. A refactor carries no behavior change; an
   intended behavior change updates its fixture in its own commit.
3. Merge cold-path work on green CI. A hot-path change also needs the pinned
   conformance run, the mutation floor, and adversarial review. Any change under
   `src/script/` or `src/transaction/` carries identical before/after
   `harness/run --impl bsv-rs --corpus seed` results from the sibling; a reviewed
   behavior change needs a witness and the applicable owner's ruling.
4. Run mutation, fuzz and benchmarks nightly. A survivor, crash or regression
   becomes a ranked issue and a replayable witness. The CLI beta is the canary;
   LOW and the stack's witness wallet supply the soak through their captains.

Every claim carries its command and output tail: `[X]` means run, `[D]` means
told or proposed. A missing run is not a pass. The gate and lane boundaries are
in [lanes/README.md](lanes/README.md) and [CLAUDE.md](../CLAUDE.md).

## BRC-100

The interface and wallet protocols use BRCs `5119a9b` (2026-10-19),
read by `git show` or the equivalent pinned source, never an uncommitted
working copy: [BRC-100](https://github.com/bsv-blockchain/BRCs/blob/5119a9b/wallet/0100.md).
[#76](https://github.com/Calhooon/bsv-rs/issues/76) binds public
fixtures to the protocol; the CLI's
[BRC-100 work](https://github.com/Calhooon/bsv-wallet-cli/issues/100) records the
shared reference. Changes to its shape require the owner's word.

## The three crates and their dependents

The pin and feature ledger is [DEPENDENTS.md](DEPENDENTS.md), owned by
[#83](https://github.com/Calhooon/bsv-rs/issues/83) and pending that lane. It
covers the CLI, toolbox, tracker, Cloudflare workers, middleware and template,
and names the captain for each dated re-pin plan. The app path is through that
Cloudflare layer and the toolbox, as mapped in
[epic #101](https://github.com/Calhooon/bsv-rs/issues/101).
Do not copy the changing pin ledger here. The dependent checks and semver guard
gate PRs where the consumer's pin permits; a passing subset does not cover
older pins. The canary and re-pin policy belongs to
[#100](https://github.com/Calhooon/bsv-rs/issues/100).

## Never without the owner's word

The public API's shape, schemas, protocol or wire semantics, cryptography,
reference or dependent pins, a tag or release, and any spend from a wallet.
A `stack-charter` issue also needs the stack's word before landing. Record the
ruling on the issue and in its witness; neither an optimization nor a benchmark
can supply it. In particular, #91's proposed typed resource refusal must be
reconciled with the BEEF charter before changing a public error or verdict.

## Staying in line with bsv-stack-lean

These are reference pointers at the commits read for this page, not new pins
for a consumer or a restatement of machine rules:

| Reference | Read-only pointer at the recorded commit |
|---|---|
| Stack constitution and programme | [NORTH-STAR.md](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/NORTH-STAR.md) |
| Six tests and lane proof discipline | [docs/BSV-NORTH-STAR.md, section 4](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/BSV-NORTH-STAR.md#4-the-six-tests), [docs/lanes/l2-README.md](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/lanes/l2-README.md) |
| SDK and streaming BEEF | [lean/Sdk.lean](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/lean/Sdk.lean), [BEEF charter](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/charters/beef-of-any-size.md), [lean/BeefOfAnySize.lean](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/lean/BeefOfAnySize.lean) |
| SDK event findings and their witnesses | [docs/MATRIX.md](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/MATRIX.md); the queue below links the affected rows at this pin |
| Wallet, broadcaster, messaging and auth | [wallet charter](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/charters/wallet.md), [broadcaster charter](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/charters/broadcaster.md), [messaging/auth charter](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/charters/messaging-auth.md) |
| Script oracle, corpus and reference provenance | [harness/README.md](https://github.com/Calgooon/bsv-script-lean/blob/5dc337e1b089fb841b6635fd40754e27a9647423/harness/README.md), [docs/PROVENANCE.md](https://github.com/Calgooon/bsv-script-lean/blob/5dc337e1b089fb841b6635fd40754e27a9647423/docs/PROVENANCE.md) |

Judge each proposal against T1 to T6 at those pointers. The scoreboard's source
records reduce trusted claims (T5); fixture, conformance and mutation runs make
them replayable (T6). This documentation/collection change makes no chain
verdict, changes no machine rule, and does not itself establish a theorem.

## The ranked research queue

Snapshot: 2026-10-23, all programme work items #75 to #100 open. Epic #101 is
the coordinating issue. This is a proposed execution order `[D]`, not GitHub
dependency metadata. The blocker column distinguishes prerequisites for a
landing or its exit test from work that can proceed in parallel. Re-read the
issues and producer reports before taking an item; closing this lane removes
#84 from the open queue.

| Rank | Item | Blocked on or required before its exit |
|---|---|---|
| 1 | [#75 Beta line](https://github.com/Calhooon/bsv-rs/issues/75) | Owner-authorized prerelease proof; the CI triggers and lane briefs landed in PR #103 |
| 2 | [#76 Public fixtures](https://github.com/Calhooon/bsv-rs/issues/76) | #75 for CI; read the shared BRC pin; development can run beside the other oracle lanes |
| 3 | [#78 Ratchets](https://github.com/Calhooon/bsv-rs/issues/78) | #75 for CI; measure the beta baseline rather than transcribing the issue's counts |
| 4 | [#77 Benchmarks](https://github.com/Calhooon/bsv-rs/issues/77) | #75 for CI; a runner-produced baseline and pinned sibling corpus |
| 5 | [#80 Architecture and feature matrix](https://github.com/Calhooon/bsv-rs/issues/80) | #75 for CI; agree with #78's measured unwrap census |
| 6 | [#81 Mutation floor](https://github.com/Calhooon/bsv-rs/issues/81) | Nightly wiring and a measured floor for every covered file; no assumed score |
| 7 | [#79 Supply-chain gate](https://github.com/Calhooon/bsv-rs/issues/79) | #75 for CI; triage findings as issues with no ignored advisories |
| 8 | [#82 Fuzz readers](https://github.com/Calhooon/bsv-rs/issues/82) | Coordinate nightly wiring with #81 and seed the script target from the sibling |
| 9 | [#83 Dependents and semver](https://github.com/Calhooon/bsv-rs/issues/83) | #75 for CI; consumer access and captains' plans for pins outside the compatible set |
| 10 | [#84 This page and collector](https://github.com/Calhooon/bsv-rs/issues/84) | #75 for hosted execution; absent #77/#78/#80/#81 outputs stay named gaps; #83 owns the ledger |
| 11 | [#87 Typed transport fault](https://github.com/Calhooon/bsv-rs/issues/87) | #76/#80 evidence, toolbox mapping by type, matrix item 11.a below, owner approval of public shape changes |
| 12 | [#89 Wordlists as data](https://github.com/Calhooon/bsv-rs/issues/89) | #78's baseline and unchanged BIP39 vectors |
| 13 | [#85 Interpreter split](https://github.com/Calhooon/bsv-rs/issues/85) | #76/#77/#78/#81 evidence and identical before/after sibling runs |
| 14 | [#86 One BEEF reader](https://github.com/Calhooon/bsv-rs/issues/86) | #76/#77/#78/#81/#82 evidence and identical before/after sibling runs |
| 15 | [#88 Architecture page](https://github.com/Calhooon/bsv-rs/issues/88) | Invariant tests from #76/#80; reflect #85/#86/#87 as they land |
| 16 | [#90 Interpreter speed](https://github.com/Calhooon/bsv-rs/issues/90) | #85 and #77/#81 proof; adversarial review and unchanged oracle verdicts |
| 17 | [#91 Streaming memory](https://github.com/Calhooon/bsv-rs/issues/91) | #86/#77; stack ruling on the element/index bound and the owner's word on public resource semantics |
| 18 | [#92 Signing and verification](https://github.com/Calhooon/bsv-rs/issues/92) | #76/#77/#81 proof; BRC derivation and crypto/API approval before changes |
| 19 | [#93 Merkle and header window](https://github.com/Calhooon/bsv-rs/issues/93) | #76/#77/#83 proof, unchanged offset witnesses, alignment with the toolbox's header consumer |
| 20 | [#94 HTTP pooling and retries](https://github.com/Calhooon/bsv-rs/issues/94) | #87's typed faults, #76's body fixtures, #77's measurement machinery and matrix items 20.a/20.b below |
| 21 | [#95 ARC batches](https://github.com/Calhooon/bsv-rs/issues/95) | #87/#76/#83, the broadcaster charter, the toolbox outbox contract and matrix item 21.a below |
| 22 | [#96 wasm32 budgets](https://github.com/Calhooon/bsv-rs/issues/96) | #80's slice builds, #83's consumer map and approved per-slice budgets |
| 23 | [#97 Hosted sibling harness](https://github.com/Calhooon/bsv-rs/issues/97) | #75/#76; accessible corpus/evaluator at the approved pin; local harness proof remains required meanwhile |
| 24 | [#98 Chaos suite](https://github.com/Calhooon/bsv-rs/issues/98) | #76/#87, then #94/#95 behavior and deadlines tested with stub servers |
| 25 | [#99 Release evidence](https://github.com/Calhooon/bsv-rs/issues/99) | #75/#79/#83 and the owner's release/signing decisions |
| 26 | [#100 Canary and re-pin policy](https://github.com/Calhooon/bsv-rs/issues/100) | #75/#83/#96/#99, consumer captains and the owner's release/pin authorization |

### Stack-matrix research items

These are ranked within their parent items above. The pinned matrix's SDK
column records implementation findings at v0.8.1 alongside the machine's rules;
its rule marker does not assert that this crate carries the rule. They are
research inputs `[D]` here, not witness runs on this branch. The existing open
findings [#65](https://github.com/Calhooon/bsv-rs/issues/65) and
[#66](https://github.com/Calhooon/bsv-rs/issues/66) remain linked to their parent
programme work rather than becoming competing implementations.

| Rank / parent | Research item and pinned matrix row | Blocked on / proof to return |
|---|---|---|
| 11.a / #87 | Transport failure after a write reduced to `NETWORK_ERROR`: [matrix row 26](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/MATRIX.md#L26), [#65 / W-SDK-1](https://github.com/Calhooon/bsv-rs/issues/65) | Owner approval of any public fault shape; replay the pinned send/timeout witness through typed handling and retain the distinction about whether the request may have arrived |
| 20.a / #94 | Bare rate limiting loses its status and wait during body decoding: [matrix row 30](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/MATRIX.md#L30), [#66 / W-SDK-2](https://github.com/Calhooon/bsv-rs/issues/66) | #87's typed faults and #76's fixtures; replay the non-JSON rate-limit witness and check status plus `Retry-After` before deciding any retry |
| 20.b / #94 | Wallet calls carry neither pending state nor a deadline: [matrix row 35](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/MATRIX.md#L35) | Stack/owner decision on the public state and deadline boundary; replay the row's permission-prompt scenario before treating transport timeouts as its solution |
| 21.a / #95 | One courier per call leaves composition with the caller: [matrix row 23](https://github.com/Calgooon/bsv-stack-lean/blob/13e1fa5d748b44da29e8dbf575bf9894825dfebc/docs/MATRIX.md#L23) | Resolve the composition boundary with the broadcaster charter and toolbox outbox; replay the row's disagreeing-broadcasters scenario. The pinned row places composition outside the SDK, so an SDK quorum or reconciliation API needs a separate stack decision |

Phase ordering is a landing plan, not permission to postpone proof: the local
sibling harness and adversarial review gate hot-path work before hosted #97
exists. A new upstream finding re-ranks the queue with its witness and blocker.
