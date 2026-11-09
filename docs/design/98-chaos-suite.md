# Design for #98: the chaos suite for the substrates and transports

Read at `origin/beta` `e228c61a` (2026-11-09). A design only; no cargo run. `[X]` read at the line; `[D]` told or proposed.

## 1. The exit test and the scoreboard row

The issue [X]: "Stub servers answering every fault pattern (timeouts, resets, 5xx with
and without bodies, 503 with and without the busy code, malformed JSON, slow bodies); the
assertions: the typed fault every time, no retry on a refusal, no hang past the bound.
**Exit test.** The suite runs on every PR."

The row: `docs/NORTH-STAR.md:103` (Phase 5). No row of the scoreboard table
(`docs/NORTH-STAR.md:21-30`) or of epic #101's table measures it [X]; it is a phase
exit, not a number. The gate for main (epic #101, 2026-10-27) needs every phase exited, so the evidence is the exit:

- Command: `cargo nextest run --features "full,http,websocket" --test chaos_transports --no-fail-fast`, as a named step `chaos` of the required `checks` job, on every pull request and push that builds.
- Record: the step's `PASS chaos` line and the cell table the binary prints (site, pattern, expected, got, elapsed ms), kept with its run id in `docs/lanes/98-chaos-suite.md`; `tests/arch_ci_chaos_step_98.rs` pins the step and its condition.

## 2. Today on beta

**The types and the classifier** [X]

| What | Where |
|---|---|
| `Error::WalletBusy { detail, retry_after_ms }`, `WalletTransport { status, detail }`, `TransportFault { fault, status, detail }` | `src/error.rs:263`, `:284`, `:303` |
| `TransportFault::{NeverSent, MayHaveBeenReceived, RateLimited}`, `Error::transport_fault()` | `src/error.rs:566-581`, `:613` |
| One classifier: `delivery`, `error_fault`, `body_cut`, `status_fault`, `retry_after_ms` | `src/transaction/broadcasters/transport_fault.rs:37`, `:50`, `:60`, `:67`, `:93` |
| Busy is the body word: `BUSY_CODES = ["STORE_BUSY", "ERR_SERVER_BUSY"]` | `src/wallet/substrates/http_json.rs:881`, read at `:974-986` |
| "The crate never retries by itself" | `src/error.rs:281`, `:299` |

**The sites and their bound** [X]

| Site | Typed fault today | Bound on a hang |
|---|---|---|
| `HttpWalletJson`, `HttpWalletWire` | yes (`http_json/answer.rs:24,69`; `http_wire.rs:180-214`) | none by default: `default_client` sets no timeout (`src/wallet/substrates/origin.rs:83-88`); the caller's through `with_client` |
| `SimplifiedFetchTransport` | yes (`transport_fault.rs` `auth_error`) | 30 s request, 10 s connect, no idle reuse (`src/auth/transports/http/client.rs:42-49`) |
| ARC, Teranode, WoC broadcasters | yes (`send_failure`, `body_failure`, `answered`) | `timeout_ms` 30,000 (`arc.rs:307,423`; `teranode.rs:79,134`; `whatsonchain.rs:91,236`) |
| `BlockHeadersServiceTracker` | yes | `timeout_ms` 30,000 (`block_headers_service.rs:57,154,216`) |
| `WhatsOnChainTracker` | yes (`chain_trackers/whatsonchain.rs`, `fault::tracker_send_error`) | none: `Client::new()` (`:98,108`), no `.timeout`; `tests/transport_fault_trackers.rs:109` says so |
| Overlay lookup facilitator | no: `Error::OverlayError("Request failed: ..")`, `"Lookup failed with HTTP status: .."` (`src/overlay/facilitators.rs:171-178`) | 5,000 ms default (`:143,167`) |
| Overlay broadcast facilitator | no: the same strings (`:293-299`) | none: `Client::new()` (`:229`), no `.timeout` |
| Storage uploader, downloader | no: `OverlayError` strings (`src/storage/uploader.rs:153-408`, `downloader.rs:220,244`) | uploader none (`:84`); downloader 30 s (`:175`) |
| `WebSocketTransport` | no: `Error::TransportError(String)` (`websocket_transport.rs:131`) | read deadline 30 s (`:34`) |
| Socket.IO transport | a send error is `TransportFault::MayHaveBeenReceived` (`socketio/mod.rs:245-247`) | not read at the line [D] |

**The tests** [X]: five files already answer faults from stubs, 49 tests: `tests/transport_fault_wallet.rs` (7), `transport_fault_auth.rs` (9), `transport_fault_broadcasters.rs` (9), `transport_fault_trackers.rs` (7), `wallet_http_json_busy_tests.rs` (17). Their stubs: `wiremock` `=0.6.2` (`Cargo.toml:149`), a refused port (`transport_fault_wallet.rs:86`), a raw listener closing after the request (`transport_fault_auth.rs:89`), a 5 s `set_delay` under a short client timeout. No test dribbles a body, cuts one after its headers at every site, or counts the requests a fault costs.

**CI** [X]: a pull request's `Test Suite` runs only the integration targets its diff reaches (`.github/workflows/ci.yml:303-346`, `:441-446`); the whole suite runs on a push, a dispatch, a tag and the `full-suite` label (`:434-435`). The `vectors` step of `checks` already names `broadcaster_http_tests` and `wallet_http_json_busy_tests` on every building run (`:745-751`). So one of the five fault files (`wallet_http_json_busy_tests`) runs on every PR today, four only when reached; `broadcaster_http_tests` is a sixth HTTP file, not counted in the five. A new test file needs a row in `tests/CLAUDE.md` (`rows_from_sources.py --check`, `ci.yml:336`).

**The reference** [X]: `HTTPWalletJSON.ts` at `edf6e03` carries no timeout, abort signal or retry (grep, no line); `SimplifiedFetchTransport.ts:141,362` runs under `#withDeadline`.

**Not on record**: the five fault files' wall time; the `checks` job's time since the bundling (last row: `vectors` 61 s, `docs/lanes/ci-speed-2.md:33`); the Socket.IO read bound; AuthFetch's request counts per fault; the downstreams' matches on `OverlayError` text.

## 3. The gap

1. No single suite: patterns are spread over five files, four of them outside the every-PR set.
2. Patterns missing everywhere: a slow (dribbled) body, a body cut after the headers at every site, a truncated JSON body, a request count per fault ("no retry on a refusal").
3. "No hang past the bound" has no bound at four sites (wallet substrates by default, `WhatsOnChainTracker`, overlay broadcast, storage uploader).
4. "The typed fault every time" fails at the overlay facilitators, storage and the WebSocket transport: strings.
5. #94 and #95 (the retries, the batch) are open; their cells cannot be written yet.

## 4. The design

**The shape.** One binary, `tests/chaos_transports.rs`, with `tests/chaos_support/mod.rs`: a table of patterns crossed with a table of sites, each cell one test, so a new site or pattern is one row. The stub is a raw `tokio::net::TcpListener` on `127.0.0.1:0` (never a default port) scripted per pattern, since wiremock cannot reset, cut or dribble. Every cell asserts three things: the typed answer (by variant, never text), the count of requests the stub saw, and `elapsed < bound + slack` under an outer `tokio::time::timeout` that fails the cell, never hangs the job.

**The patterns and the expected class** (from the ruling and the classifier as read) [D until run]

| Pattern | Wallet substrates | Auth transport | Broadcasters | Trackers |
|---|---|---|---|---|
| refused | `WalletTransport{None}` | `NeverSent` | `NEVER_SENT` | `NeverSent` |
| accept, never answer; headers then stall; body dribbled past the bound | `WalletTransport{None}` | `MayHaveBeenReceived` | `MAY_HAVE_BEEN_RECEIVED` | `MayHaveBeenReceived` |
| reset before the answer; body cut after headers | `WalletTransport{None}` | `MayHaveBeenReceived` | `MAY_HAVE_BEEN_RECEIVED` | `MayHaveBeenReceived` |
| 502, 503, 504, empty, text or HTML body | `WalletTransport{Some(s)}` | `MayHaveBeenReceived` | same, `more.status` | same |
| 503 or 500 with `STORE_BUSY` / `ERR_SERVER_BUSY`, with and without `Retry-After` | `WalletBusy` (JSON substrate) | still a fault (`transport_fault_auth.rs:156`) | n/a | n/a |
| 429; 503 with `Retry-After` | 429: `RateLimited` with the wait; a 503 with `Retry-After` and no busy code stays `WalletTransport{Some(503)}` (`CHANGELOG.md:20831-20837`, #87) | `RateLimited` | `RATE_LIMITED` | `RateLimited` |
| 500 with and without a body; 400 | the far side's answer: `WalletError` or its refusal class | `AuthError` | the status as code | the provider's answer |
| 200 with malformed, truncated-but-complete or wrong-shape JSON | `WalletError` (serde's words) | `AuthError` | `PARSE_ERROR` | `InvalidResponse` |

Requests seen: exactly 1 in every cell today; AuthFetch's reference retries (401 stale session, 402 payment; `src/auth/clients/auth_fetch.rs:34-37,216-229`) at the reference's count, read by the lane.

**The steps, ranked**

| # | Step | Change | Moves | Stays identical | Proof | Risk | Size |
|---|---|---|---|---|---|---|---|
| S1 | The suite over the typed sites, on every PR | new `tests/chaos_transports.rs`, `tests/chaos_support/mod.rs`, `tests/arch_ci_chaos_step_98.rs`; a `chaos` step in `checks` beside `vectors` (`ci.yml:745`); a `tests/CLAUDE.md` row; `tests/arch_ci_lines.rs` `BUNDLES` and `docs/ARCH-RULES.md` rule 7 | the exit test, gaps 1 and 2 | every `src/` byte, every fixture, the five existing files | the arch test red before the step; a scratch copy with one classifier arm removed (`status_fault`'s 503, `body_cut`) turns named cells red, the kill list in the lane record; wall time measured | 0.2 (a flaky timing cell on a loaded runner) | one lane, one PR |
| S2 | The unbounded and untyped sites pinned as stated cells | cells in the same binary asserting today's answer: the overlay strings, `TransportError`, and "no default bound" proven with the caller's client, never by waiting | gaps 3 and 4 become visible rows, each naming its question | all of `src/` | the cells green on beta; each flips red when its fix lands, which is that fix's RED | 0.1 | one lane, after S1 (same files) |
| S3 | Overlay facilitators answer the typed fault | `src/overlay/facilitators.rs:171-178,293-299` through `fault::error_fault` and `status_fault`; arch rule 3's scan gains the fifth home (`tests/arch_no_string_errors.rs`) | gap 4, the widest untyped surface | the lookup and submit bytes, `tests/overlay_http_tests.rs` verdicts for a 2xx, the reputation accounting (`tests/lookup_tracker_accounting_762.rs`, `lookup_tracker_backoff_769.rs`) | S2's overlay cells red then green; the three overlay files unchanged | 0.45 (a downstream matching `OverlayError` text; the resolver's fallback reads the error) | one lane; needs Q98.2 |
| S4 | A bound where none exists | `WhatsOnChainTracker` and the overlay broadcast facilitator and the storage uploader take a timeout; the wallet substrates per Q98.1 | gap 3 | every answer inside the bound | S2's "no bound" cells replaced by timed cells | 0.35 (a public shape; a slow honest wallet prompt cut off) | one lane per site family; needs Q98.1, Q98.3 |
| S5 | The WebSocket transport's class | `websocket_transport.rs:131,264` to `Error::TransportFault`; a tungstenite stub in the support module | gap 4's last site; #87's "left until a witness" | the frames | the witness cells recorded by S2 | 0.3 | one lane; needs Q98.4 |
| S6 | The retry and batch cells | columns for #94 (retry only on the typed fault and `WalletBusy`, never a refusal; `Retry-After` honoured; attempts counted at the stub) and #95 (one request per batch, typed words per source) | gap 5 | S1's cells | each column red before its lane | 0.2 | folded into #94's and #95's lanes |

Nothing is under `src/script/`; under `src/transaction/` only S4's tracker client moves, so that lane carries the sibling harness run identical before and after. No bench moves: the suite is a gate, not a measurement.

**Timing budget** [D]: a timing cell uses a client bound of 200 to 300 ms against a stalled stub; target, the binary under 30 s. The opening lane measures it and `checks` before and after.

## 5. The slicing

| Lane | Steps | Waits on | Gate |
|---|---|---|---|
| L1 | S1 | nothing | `chaos` green on its own PR; the kill list; the wall time |
| L2 | S2 | L1 (same two files) | green on beta as read; one stated cell per gap site |
| L3 | S3 | L2, Q98.2, and #775 landed or rebased over | overlay cells flip; overlay suites unchanged |
| L4a, L4b | S4 (trackers and overlay; wallet substrates) | L2, Q98.1, Q98.3; L4b also the stack's word on matrix row 35 | timed cells |
| L5 | S5 | L2, Q98.4 | ws cells |
| with #94, #95 | S6 | their designs | their columns |

L3, L4a, L4b and L5 run in parallel after L2: they share only `tests/chaos_transports.rs` (one row each).

**Collisions** [X by the issues' texts]: `src/overlay/facilitators.rs` with #775 (the lookup body bound, the blocking set) and through the resolver's error handling with #785, #786, #796; `src/transaction/chain_trackers/whatsonchain.rs` with #93 (the tracker's local window); the wallet substrates' client and `transport_fault.rs` with #94; `arc.rs` with #95; `.github/workflows/ci.yml` (`checks`) and `tests/arch_ci_pr_runs_the_required_set.rs` with #97, #96 and #99; `tests/CLAUDE.md` and `tests/caller_modules_706.txt` with every lane that adds a test, #603 most of all; `CLAUDE.md` rule 7's sentence with any CI lane. None with #734, #735, #751, #756, #782 (identity, PushDrop, verify), nor #90 to #92.

## 6. The owner's questions

**Q98.1. Do the wallet substrates get a default deadline?** Options: (a) none, the caller's client is the bound, the suite states it; (b) a default (30 s, the auth transport's) with a builder to change or remove it. Reference: `HTTPWalletJSON.ts` at `edf6e03` has none; matrix row 35 (`docs/MATRIX.md:35` at `13e1fa5d`) asks a visible pending state with a deadline and names the SDK as carrier. Recommendation: (a) now, (b) only with the stack's word on row 35, since a transport timeout would cut a waiting permission prompt. Cost: (a) nothing; (b) the CLI and the toolbox see `WalletTransport` where a prompt waited longer than the bound.

**Q98.2. Do the overlay facilitators (and storage) answer `Error::TransportFault` in place of `OverlayError` strings?** Options: (a) yes, as #87 did for the trackers; (b) no, stated cells only. Reference: ts-stack throws untyped errors; #87's ruling asked "every substrate and client". Recommendation: (a) for the facilitators in 0.9.x, storage after. Cost: bsv-overlay-cloudflare, zanaadu's overlay-lib and the toolbox re-read any match on `OverlayError` text; `Error` is `#[non_exhaustive]`, so no build breaks.

**Q98.3. `WhatsOnChainTracker`'s timeout: what shape?** Options: (a) a `with_timeout_ms` builder, default 30,000 as its siblings; (b) a config struct as `BlockHeadersServiceConfig`. Reference: none sets one. Recommendation: (a), additive. Cost: bsv-tracker and chaintracks-cloudflare see a fault after 30 s where they waited without end.

**Q98.4. Is the WebSocket transport's failure typed now?** Options: (a) `TransportFault` on connect and read failures, the witness S2's cells; (b) left as `TransportError`. Recommendation: (a) once S2 records the witness. Cost: none known [D]; the relay and messagebox take `socketio`, and `websocket` is opt-in.

**Q98.5. Does "every PR" admit the docs-only exit, and does the scoreboard gain a chaos input?** Options: (a) `chaos` skips as `vectors` does on a docs-only plan, no collector change; (b) it runs unconditionally and the collector reads a `chaos-summary.json`. Recommendation: (a); a collector schema is the owner's and no row asks for it. Cost: none to a downstream.

## 7. Stack alignment

- The wallet charter's busy row and R8 (a), (i): `docs/charters/wallet.md:128,155,205-207` at `13e1fa5d`; `CHANGELOG.md:21199-21209` (0.8.2, `WalletTransport`), `:20827-20838` (#87), `:21448` (`WalletBusy`).
- `lean/Sdk.lean:107-115,172-178,218,263,487` (`Sdk.Code`, `written_never_neverSent`, `rateLimited_carries_wait`, `timeout_hands_nothing`) through `docs/MATRIX.md:26,30`; the suite replays them at the HTTP edge and proves nothing.
- Messaging and auth charter M6 (`docs/charters/messaging-auth.md:48`): a handshake has a deadline, never a hang.
- T1: a constant cost per site and pattern. T2: no chain fact served. T3: local stubs, one binary. T4: no rule made; the classes are the ruling's. T5: a caller keys on a type, not on a string it must trust. T6: every row of the ruling becomes a replayed cell on every PR.

## 8. Not in this design

The retry policy and pooling (#94) and the ARC batch (#95): their designs, their cells (S6). A pending state and deadline for wallet calls (matrix row 35): the stack's. wasm32: `http` is native-only (`build.rs`, #152), so no wasm cell. Live-network soak: the CLI canary and LOW (#100). A randomised fault schedule: a nightly item filed after L2, not a PR gate. `LivePolicy` and the storage downloader's typed fault: rows of S2, fixes after Q98.2.
