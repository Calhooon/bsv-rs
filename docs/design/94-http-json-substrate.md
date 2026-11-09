# Design: #94, the HTTP JSON substrate's pool, retries and bounds

Read at `origin/beta` `e228c61a` on 2026-11-09. `[X]`: a line read at that sha or a named pin; `[D]`: told or proposed. No cargo, build or bench ran for this page: every number it needs is a measurement of lane L1.

## 1. The exit test and the scoreboard row

Issue #94, verbatim: "**Exit test.** A bench of 1,000 calls against a stub server shows the pool's effect; the fixtures show no change in bodies." Its scope: "A shared client with connection pooling; retries only on the typed transport fault and on `WalletBusy` with its `retry_after_ms`, never on a refusal; `Retry-After` honored on 503; a concurrency bound per substrate; every attempt visible in a span." `[X]`

The phase line is `docs/NORTH-STAR.md:93`. **No scoreboard row exists for it**: the table at `docs/NORTH-STAR.md:21-30` has eight rows, none over HTTP, and epic #101's table has none `[X]`. #94 moves a phase line, and a row only if the owner adds one (Q94.6).

"At target with recorded evidence" `[D]`:

| What | Command | Record |
|---|---|---|
| The pool's effect | `cargo bench --locked --features "wallet,http" --bench wallet_http` (new, L1) | `docs/census/http-substrate-94.md`: command, sha, machine, p50/p99 and connections opened per variant; raw output under `/Volumes/Lanes/out/bsv-rs/<lane>/` |
| Bodies unchanged | `cargo test --features "full,http" --test fixtures_replay --locked` (`ci.yml:760`); `git diff --stat origin/beta -- tests/fixtures/http_json` printing nothing | the same file, both tails |

## 2. Today on beta

| Fact `[X]` | Where |
|---|---|
| `HttpWalletJson { client, base_url, originator }`, `Clone`; `new` builds its own client, `with_client` takes the caller's | `src/wallet/substrates/http_json.rs:87-126` |
| One request per call, no loop (`request_bound`) | `http_json.rs:150-186` |
| The client `new` builds: `redirect::Policy::none()` alone, one per substrate; `HttpWalletWire::new` the same | `substrates/origin.rs:83-88`; `http_wire.rs:72` |
| `WalletClient` discovery builds three substrates, three clients | `src/wallet/client/http.rs:31-45` |
| reqwest `0.12`; at 0.12.28 its defaults pool already (idle 90 s, `pool_max_idle_per_host` `usize::MAX`), `timeout` and `connect_timeout` `None`, `tcp_keepalive` 15 s | `Cargo.toml:96`; reqwest 0.12.28 `src/async_impl/client.rs:299-314` |
| The auth transport turned idle reuse off after a half-dead keep-alive socket hung a deployed caller with no timeout | `src/auth/transports/http/client.rs:27-49` |
| The answer's order: busy word, code-5 review, 429, wallet class, gateway status | `substrates/http_json/answer.rs:17-76` |
| Busy is the body's code; its wait delta seconds only | `http_json.rs:881`, `:976-997` |
| The one classifier: `delivery`, `error_fault`, `status_fault`, `retry_after_ms` | `src/transaction/broadcasters/transport_fault.rs:37-98` |
| The substrates drop the class: every send fault is `WalletTransport { status: None }`; a 503 with `Retry-After` and no busy code keeps no wait | `transport_fault.rs:215-223`; `answer.rs:49-72` |
| "The crate never retries by itself" | `src/error.rs:281`, `:299` |
| 17 busy and transport tests; 5 on both substrates | `tests/wallet_http_json_busy_tests.rs:52-376`; `tests/transport_fault_wallet.rs:84-142` |
| Fixtures: 29 files, 72 entries (56 call, 16 error), replayed by `tests/fixtures_replay.rs`, on the required set | `docs/FIXTURES.md:48`, `:61-68`; `ci.yml:753-760` (`checks`) |
| Nine benches, none over HTTP; the gate measures with `--features wallet`; no HTTP key in `benches/baseline.json` | `tools/bench-compare/src/main.rs:15-25`, `:159` |
| `tracing` is opt-in, used at the wire processor only | `Cargo.toml:196`; `src/wallet/wire/diagnostics.rs:9-28` |
| `http_json.rs` is 1,080 lines; `files_over_800` caps it at 1,113 | `docs/ratchets.json:144-145` |
| The reference: one `fetch` per call, no retry, no timeout; discovery alone bounded | `ts-stack@edf6e03` `HTTPWalletJSON.ts:308-310`, `WalletClient.ts:136-147` |

Blockers the queue names (`docs/NORTH-STAR.md:216`), all closed `[X]`: #87 (`3967d64f`, `75003ae2`), #76 (`86c05170`), #77 (`e8ad97d4`); beside them #73 (`efe12e63`, carried by #87), #65 and #66 (`:236-237`), closed. Item 20.a (row 30) is carried by the classifier. Item 20.b (row 35) has no ruling in the pages this lane read.

**Not on record** (never estimated here): any HTTP timing or connection count; the reqwest version CI resolves (no `Cargo.lock` committed); whether the toolbox or the CLI builds a substrate per process or per call, or retries on its own; a TLS handshake's cost against a wallet; the waits bsv-wallet-cli sends with `STORE_BUSY`; any Linux figure; whether hyper replays a request on a reused connection that closed before a byte left.

## 3. The gap

1. No measurement of the pool's effect.
2. The pool is per substrate: a substrate per call, and the three probes, reuse nothing.
3. The pooled default has no hang hygiene (no connect timeout, no request timeout, a 90 s idle window; TCP keep-alive is reqwest's 15 s default).
4. No retry; the class a safe retry needs and the 503's wait are dropped before the public error.
5. No concurrency bound; no span.
6. Row 35 (pending state, deadline) is undecided.

## 4. The design

Ranked, cheapest proof of the largest effect leading. S1 changes no source and may alone meet the exit test's two sentences; S2 to S6 deliver the scope line. No file under `src/script/` or `src/transaction/` is edited: no sibling harness run is owed.

**S1. Measure today.** New `benches/wallet_http.rs` (`required-features = ["wallet","http"]`) and `tests/wallet_http_pool_94.rs`. A stub on a `tokio::net::TcpListener` at `127.0.0.1:0` (dev `tokio` has `net`, `Cargo.toml:147`) answers `getHeight`'s recorded body and counts accepted connections. Variants, 1,000 calls each at concurrency 1, 8, 64: (A) one substrate; (B) one substrate on a `with_client` client with `pool_max_idle_per_host(0)`; (C) a substrate from `new` per call. A against B is the pool's effect; C is what S2 removes. Identical: everything. Proof: the test asserts connections opened (A at most the concurrency; B and C 1,000), a count host load cannot move; the bench gives p50/p99. Kept out of the p99 gate: its `--features wallet` is part of the baseline's identity (`main.rs:587`), so `http` would re-record every platform. Risk 0.10. One lane.

**S2. The shared default client, with hygiene.** `origin::default_client` returns a clone of one process-wide `OnceLock<Client>` built with `redirect(Policy::none())`, `connect_timeout`, `tcp_keepalive` and a shorter `pool_idle_timeout`; no request timeout (Q94.4). File: `substrates/origin.rs`. Why: C becomes A, the probes share a pool, a dead idle socket is dropped before reuse. Identical: bodies, headers, error texts, the public shape, `with_client`. Proof: RED `substrates_built_by_new_share_one_connection_94` (three substrates, one accept; three before); C's bench delta; `fixtures_replay` and the 22 tests untouched. Risk 0.25: a process global outliving a dropped runtime (a test per runtime; the fallback is a pool per runtime). The three durations are L1's measurements. One lane.

Fact-check (2026-11-09): reqwest 0.12.28 already sets `tcp_keepalive` to 15 s (`client.rs:303`); S2 adds the connect timeout and the shorter idle window, and keep-alive only if L1 measures a shorter one.

**S3. The attempt, split out (refactor, no behaviour change).** Move `request_bound`'s send-and-read to `substrates/http_json/attempts.rs`, returning a crate-private outcome: `Done(R)`, `Busy { wait }`, `Fault { class: TransportFault, wait }`, `Refused(Error)`, each converting to today's exact `Error`. The class is read from `fault::error_fault` and `fault::status_fault` while the `reqwest::Error` and headers are in hand. Why: one seam for S4 to S6; `http_json.rs` shrinks. Proof: the same suites green, `git diff --stat` on `tests/` empty. Risk 0.15. One lane.

**S4. The retry policy, opt-in.** `substrates/retry.rs`: `#[non_exhaustive] pub struct RetryPolicy { max_attempts, base_backoff_ms, max_wait_ms, total_wait_ms }`, `RetryPolicy::none()` the default; `HttpWalletJson::with_retry_policy(self, RetryPolicy) -> Self` (Q94.1). The rule, by type only (ARCH rule 3, `docs/ARCH-RULES.md:108`):

| Outcome | The 7 mutating calls (`createAction`, `signAction`, `abortAction`, `internalizeAction`, `relinquishOutput`, `relinquishCertificate`, `acquireCertificate`) | The other 21 |
|---|---|---|
| `Busy` (the wallet's promise: nothing written) | repeat after the wait | repeat |
| `NeverSent` | repeat | repeat |
| `RateLimited` on 429 | repeat after the wait | repeat |
| `RateLimited` on 503 with `Retry-After` | Q94.3 | repeat after the wait |
| `MayHaveBeenReceived` | **never** | repeat (Q94.3) |
| a refusal, a review, a malformed answer | never | never |

The wait is the server's, capped by `max_wait_ms`; absent, a doubled backoff with jitter; the sum bounded by `total_wait_ms`; the last error returned unchanged; the body serialized once and resent byte for byte; the sleep behind a crate-private seam so tests record waits without waiting. Identical: with `none()`, everything; with a policy, the final error's type and text. Proof, each RED before: busy then success sends two requests and waits the body's delay; a `WERR_*` refusal sends one; `createAction` on a timeout sends one; `getHeight` on a bare 503 repeats; a 503 with `Retry-After: 2` waits 2,000 ms; a wait above the cap is cut; the budget ends the loop. Risk 0.40 (a wrong class on a mutating call is a double action). One lane, after the owner's answers.

Fact-check (2026-11-09): `docs/ARCHITECTURE.md:106` states the invariant "never retried (one request per answer)"; a policy other than `none()` amends that line in the same lane.

**S5. The concurrency bound, opt-in.** `HttpWalletJson::with_max_concurrency(self, NonZeroUsize) -> Self`: a semaphore shared by clones, held for an attempt and released during a wait. Why: a burst becomes a queue, not a busy storm on a contended store. Identical: unbounded when unset. Proof: RED `no_more_than_n_calls_are_in_flight_94` (64 concurrent calls, the stub's in-flight high-water at most n); S1's bench at 64 with and without. Needs a semaphore and a timer under `http` (Q94.5). Risk 0.20. One lane.

**S6. Spans.** Under `tracing` only: a span per call (`call`, `attempts`, `outcome`), an event per attempt (`attempt`, `class`, `status`, `wait_ms`); never a body, a header value or the originator. Proof: RED in the pattern of `tests/wire_tracing_sink.rs`. Risk 0.15. One lane.

**S7. The row.** If Q94.6 says yes: `bench.yml` uploads the record as a `bench` artifact; `docs/NORTH-STAR.md` gains the row. Risk 0.10.

## 5. The slicing

| Lane | Step | Waits on | Gate | Files |
|---|---|---|---|---|
| L1 | S1 | nothing | count test green; record written | `benches/wallet_http.rs`, `tests/wallet_http_pool_94.rs`, `tests/support/`, `Cargo.toml`, `docs/census/` |
| L2 | S2 | L1's durations | RED then green; fixtures identical | `substrates/origin.rs` |
| L3 | S3 | nothing (beside L1, L2) | no test edited | `http_json.rs`, `http_json/attempts.rs` |
| L4 | S4 | L3, Q94.1 to Q94.3 | seven RED tests; cold and adversarial reads | `substrates/retry.rs`, `attempts.rs`, `mod.rs` |
| L5 | S5 | L4, Q94.5 | RED; `features.yml` | `attempts.rs`, `Cargo.toml` |
| L6 | S6 | L4 | RED sink test | `attempts.rs` |
| L7 | S7 | L1, Q94.6 | the collector reads the artifact | `bench.yml`, `docs/NORTH-STAR.md` |

L4, L5, L6 share `attempts.rs` and run in that order; L1 and L5 share `Cargo.toml`.

Collisions `[D]` (from the issues' titles and bodies, not the other lanes' pages):

- **#95**: `transport_fault.rs`, `Cargo.toml`'s `http` line, `bench.yml`. This design reads the classifier and does not edit it.
- **#98**: the stub server; L1's goes in `tests/support/` for #98 to extend; #98 waits on L4.
- **#90 to #93**: `benches/baseline.json`, `tools/bench-compare/src/main.rs`, the `[[bench]]` block, `bench.yml`, the scoreboard table. L1 stays out of the gate and the baseline; only the `[[bench]]` block is shared.
- **#96**: `Cargo.toml` features. `http` stays native-only; no wasm32 slice is reached.
- **#97**: `ci.yml`, one line, if L1's count test joins the required set.
- **The 0.9.0 set** (#734, #735, #751, #756, #775, #782, #785, #786, #796): overlay, identity, merkle and PushDrop files by their titles, none under `src/wallet/substrates/`; #775 meets L3 only if it reuses `result_values/boundary.rs`.
- **#603**: whether `substrates/` is a mutation gate path is not on record.

## 6. The owner's questions

**Q94.1 The public shape of retry.** (a) `RetryPolicy` and builder methods on `HttpWalletJson`, default none; (b) a wrapper over any `WalletInterface`; (c) nothing public, a fixed internal policy. Reference: no retry (`HTTPWalletJSON.ts:308-310`). Recommend (a): additive, and only the substrate still holds the class a safe retry needs. Cost: (a) none until a dependent opts in; (b) cannot tell `NeverSent` from `MayHaveBeenReceived`, unsafe for the toolbox's `createAction`; (c) changes the timing of every `http` dependent (toolbox `full,http`; bsv-storage-cloudflare's parity member) without its word.

**Q94.2 Default on or off.** Reference: off; `src/error.rs:281` promises off. Recommend off through 0.9.x, the CLI beta the canary that turns it on. Cost of on: any retry a dependent already has multiplies attempts.

**Q94.3 What repeats after `MayHaveBeenReceived`, and after a 503 with `Retry-After`.** (a) the 21 non-mutating calls only; (b) nothing; (c) every call. Reference: silent. Lean: `mayHaveBeenReceived`, the caller holds (`lean/Sdk.lean:104-122`). Recommend (a), and a mutating call on a 503 with `Retry-After` and no busy word is not repeated: the charter makes the body's word, never the status, the promise. A repeated `createSignature` can raise a second permission prompt (row 35); the doc comment says so. Cost: (c) can double a wallet's action; (b) leaves reads to each caller.

**Q94.4 The deadline (item 20.b, row 35).** (a) no request timeout, a connect timeout and keep-alive only; (b) a default overall timeout; (c) a per-call deadline with a public pending state. Reference: none after discovery, by design (`WalletClient.ts:146`). Recommend (a) now; (c) is the stack's rule and needs the keeper's ruling before any shape (`docs/NORTH-STAR.md:238`). Cost of (b): a prompt answered late fails in every dependent.

**Q94.5 `http` enables `dep:tokio` (`sync`, `time`)**, or a hand-rolled semaphore on `futures` with `futures-timer`. Recommend tokio: in every native `http` graph through reqwest `[D]`, no new crate. Cost: none expected for `full,http` consumers; `features.yml` and `machete.yml` are the witnesses.

**Q94.6 A scoreboard row and its gate.** (a) a row "HTTP substrate: 1,000 calls", connections gated, time recorded; (b) the record file alone; (c) a p99 gate. Recommend (a): a loopback p99 judges the runner's load, a count does not.

**Q94.7 The class and the 503's wait in the public error.** (a) leave `WalletTransport` as 0.8.2 pinned it; (b) at the next api-break answer `Error::TransportFault { fault, status, detail }` for every wallet fault. Recommend (a) now, (b) filed. Cost of (b): the toolbox's by-type map (#87) and the fixtures pinning `WalletTransport` move.

## 7. Stack alignment

At `bsv-stack-lean@13e1fa5d748b`: the wallet charter's busy row (`docs/charters/wallet.md:128`, R8, `hostAnswer_busy_changes_nothing`); `docs/MATRIX.md` rows 26, 30, 35; `lean/Sdk.lean:107-115`. BRC-100 at `5119a9b` (`wallet/0100.md`) fixes the bodies; none moves.

- T1: cost follows our call count, never the chain.
- T2, T4: not touched.
- T3: one connection reused in place of one per call; a bounded queue in place of a busy storm.
- T5: a repeat only on the wallet's own promise or on a class proving nothing left; no new word trusted.
- T6: the retry table runs as stub-server tests; no Lean statement is added `[D]`.

## 8. Not in this design

- Retry and a bound on `HttpWalletWire` (it shares S2's client; its loop is a lane after L4, the wire having no busy word, `http_wire.rs:188`).
- The broadcasters', trackers', overlay's and storage's clients (`reqwest::Client::new()` at 15 sites): #95 and #93.
- Row 35's pending state and deadline: the keeper's ruling, then its own design.
- The chaos suite (#98, after L4); a TLS stub and a Linux figure (CI's).
- A change to a body, a header, an error text or a fixture: none.
