# Lane fix-98-tracker-timeout: the WhatsOnChain tracker bounds every request (#98)

Started from `d892e206ac5cb4120c78c070775d8a4f8514fa8d`, `origin/beta`'s tip when the lane
opened. Additive hardening, the chaos suite's step S4 (the tracker door): a new default
request timeout, no verdict or wire byte moves.

## The line

`docs/design/98-chaos-suite.md` records, in "The sites and their bound", that
`WhatsOnChainTracker` set no request timeout of its own (`Client::new()`, no `.timeout`),
and gap 3 counts it among the sites with "no bound". Step S4 ("A bound where none exists")
names it, gated on Q98.3. Q98.3 recommends an additive `with_timeout_ms` builder with the
sibling's 30 s default; `docs/design/README.md` records that answer. This lane lands the
tracker door of S4.

## What the tip did, checked line by line

At `d892e206`, `src/transaction/chain_trackers/whatsonchain.rs`:

- The struct built its `reqwest::Client` with `reqwest::Client::new()` (`new`,
  `with_base_url`) and carried no timeout field.
- Both `ChainTracker` methods issued `self.client.get(&url).send()` with no `.timeout(..)`
  between them, where the sibling `BlockHeadersServiceTracker` carries
  `.timeout(from_millis(self.config.timeout_ms))` (30 s default,
  `block_headers_service.rs`).

So a tracker endpoint that answered `200` and then stalled its body never resolved the
`send()` / body-read future: `is_valid_root_for_height`, `current_height`, and any
`Transaction::verify` awaiting the tracker for a proven transaction, held with no end.
On the Cloudflare Workers target the platform bounds `fetch`, so the unbounded wait was a
native-build behaviour (`http` is native-only, CLAUDE.md rule 6).

## The change (additive; the sibling's form; wasm32-safe)

- A module const `pub const DEFAULT_WOC_TIMEOUT_MS: u64 = 30_000;` (mirrors the sibling
  exposing `DEFAULT_HEADERS_URL`).
- A private field `timeout_ms: u64` on `WhatsOnChainTracker`, set to `DEFAULT_WOC_TIMEOUT_MS`
  in `new` / `with_base_url` (no caller builds the struct with a literal, so no migration
  under semver rule 9).
- A builder `pub fn with_timeout_ms(self, u64) -> Self` and a getter
  `pub fn timeout_ms(&self) -> u64`.
- Both requests gain `.timeout(std::time::Duration::from_millis(self.timeout_ms))` between
  `.get(&url)` and `.send()`.
- The `Debug` impl reads the new field, so it is read on every feature combo (including a
  non-`http` build): no dead-code warning without `http`.

wasm32: the `.timeout()` and `client` live under `#[cfg(feature = "http")]`, which the
wasm feature set (`auth,wallet,transaction,overlay,socketio,wasm`, no `http`) compiles out;
the field, builder and getter compile unconditionally. Only `Duration` of `std::time`
(not `SystemTime`); no tokio time driver. wasm32 builds: yes.

A stalled response is now `TransportFault::MayHaveBeenReceived` (the class the sibling
already reports), not an unbounded wait.

## Tests RED before, green after

The RED-before run is a scratch copy of the tip with ONLY the two `.timeout(...)` calls
removed (the new API kept), so the witness compiles and goes RED behaviourally, not as a
compile error. Hermetic (wiremock, in-process); no live network. The margin is the chaos
cell's: server stall 30 s >> outer ceiling 5 s >> request timeout 500 ms.

| Test (name says what THIS crate holds) | File | RED (pre-change scratch) | Green |
|---|---|---|---|
| `the_whatsonchain_door_bounds_a_stalled_response_98` | `tests/transport_fault_trackers.rs` | FAILED in ~5 s: "is_valid_root_for_height was not bounded ... Elapsed" | ok in ~1 s |

Plus two hermetic unit tests (`src/transaction/chain_trackers/whatsonchain.rs`) that pin the
default and the override and are green in both states (they test the API, not the bound):
`the_woc_tracker_default_timeout_is_30s_98`, `the_woc_tracker_with_timeout_ms_overrides_98`.
The stale comment in the existing `a_timeout_is_a_transport_fault_that_may_have_been_received`
test ("WhatsOnChainTracker has no timeout of its own") was updated: it is no longer true.

## Cross-SDK parity

Conformance to the newer reference and the crate's own sibling, with one residual stated.
`ts-stack@edf6e03` (the same lines at `4d0ea63c8`): the tracker runs on `httpClient ?? defaultHttpClient()`
(`WhatsOnChain.ts:64`), whose default client bounds every request at 30 s
(`DEFAULT_HTTP_CLIENT_TIMEOUT_MS`, `HttpClientResponseUtils.ts:4`; `FetchHttpClient.ts:49`,
`NodejsHttpRequestUtils.ts:145-156`), so the 30 s bound matches it. Residual: the older
`ts-sdk@9e3ede6b`'s `FetchHttpClient` has none, and go-sdk@2ca481c takes
`http.DefaultClient`, no timeout, when no client is given
(`transaction/chaintracker/whatsonchain.go:104-108`; a caller adds one through `WithHTTPClient`, `:61-70`). Recorded in the
root `CLAUDE.md` divergence list and in the `### Notes: cross-SDK parity` of the CHANGELOG
entry. Read at the pins, not run.

## Files changed

- `src/transaction/chain_trackers/whatsonchain.rs` (the const, field, builder, getter, the
  two `.timeout`, the Debug field, two unit tests).
- `tests/transport_fault_trackers.rs` (the witness; the stale comment updated).
- `src/transaction/chain_trackers/CLAUDE.md` (the struct/API block, the Debug note, the
  "Request Timeout" section now covers both trackers).
- `CHANGELOG.md` (`### Changed` under `[Unreleased]` + `### Notes: cross-SDK parity`).
- `CLAUDE.md` (one row in the divergence list).
- `docs/design/98-chaos-suite.md` (the sites table, gap 3, the S4 row, Q98.3's reference
  sentence corrected at the pin), `docs/design/README.md` (the Q98.3 answer line).
- `docs/lanes/fix-98-tracker-timeout.md` (this record).

## The fold of 2026-11-15

One commit on `6738a652`, the answer to the three reads of pull request #1001 (the cold
read, the rule read, the strength read) and to the red `checks` job.

1. **The constant is reachable.** `DEFAULT_WOC_TIMEOUT_MS` was `pub` in the private module
   `whatsonchain` and re-exported nowhere, so the "public constant" was no dependent's to
   name, the Documentation gate refused `with_timeout_ms`'s link to it (the red job) and
   the semver step never saw it. It is re-exported where `WhatsOnChainTracker` is, in the
   sibling's form (`DEFAULT_HEADERS_URL`): `src/transaction/chain_trackers/mod.rs` and
   `src/transaction/mod.rs`. Its public paths: `bsv_rs::transaction::DEFAULT_WOC_TIMEOUT_MS`
   and `bsv_rs::transaction::chain_trackers::DEFAULT_WOC_TIMEOUT_MS`. Held by
   `the_whatsonchain_default_timeout_is_named_by_its_public_paths_98`, compile-RED in a
   scratch copy without the two re-exports (E0432, E0425). `RUSTDOCFLAGS="-D warnings"
   cargo doc --no-deps --all-features` is clean. `cargo semver-checks check-release
   --all-features --release-type minor` (0.51.0), against `origin/beta` (`341299f1`) and
   against the lane's base `d892e206`: 202 checks, 202 pass, 58 skip, no semver update
   required; the tool prints no list of additions, and the additions are one constant at
   two paths, two methods and a private field.
2. **The readers' corrections, one set.** Taken by meaning from the rule read's commit
   (`6084b062`), the cold read's (`4a9898aa`) and the strength read's (`c98c824e`), each
   line read again at its source:
   - the reference at the pin `ts-stack@edf6e03` (the same lines at `4d0ea63c8`):
     `WhatsOnChain.ts:64`, `HttpClientResponseUtils.ts:4` (the default taken at `:15`),
     `FetchHttpClient.ts:49`, `NodejsHttpRequestUtils.ts:145-156` (the records said
     `:146-152`, which cut the second timer's body; the span is the guard at `:145`
     through the end of `req.setTimeout` at `:156`);
   - its thrown words on its bound, `WhatsOnChain.ts:190` and `:211`, checked;
   - go-sdk@2ca481c's default client: the three reads cited `:102-107`, `:105-107` and
     `:105-112`. The source: `:104` opens `client`, `:105-108` take `http.DefaultClient`
     when no client was given, `:101-103` are the comment and `:110-113` build the
     options. None of the three spans was exact (the cold read's stopped a line short of
     the closing brace, the rule read's began in the comment, the strength read's ran
     into the options); the records now cite `:104-108`, and `WithHTTPClient` at `:61-70`;
   - `tests/CLAUDE.md`'s count: 11 (10 without `wallet`) at `6738a652` as the cold read
     wrote, 14 (13) after this fold's three tests, with a sentence for each;
   - the root row names the pin `edf6e03`.
3. **The false citation in code.** `whatsonchain.rs`'s comment quoted `requestTimeoutMs ??
   30000`, another transport's expression. It now cites the HTTP client's own lines (the
   list above), as do `src/transaction/chain_trackers/CLAUDE.md` and the records.
4. **The wording rule.** No long dash in anything the pull request adds (the lines are in
   the REPORT and the commit).
5. **The strength read's two asks.**
   - Each `.timeout(...)` removed alone, in a scratch copy: the height call's removed,
     `current_height was not bounded` (`tests/transport_fault_trackers.rs:187`); the root
     call's removed, `is_valid_root_for_height was not bounded` (`:176`); in both, the
     body-stall test and the late cell of the timeout of 0 RED too, 3 of 14.
   - A timeout of 0 and a very large one. The strength read's rustdoc sentence (0 "ends
     every request at once") was written by reading and is false as written: run against
     a local server, a tracker at 0 answered `Ok(true)`. A zero timeout is the timer's
     next tick, and a server on the same host can answer inside it. The rustdoc says what
     is true (0 does not turn the bound off; a request ends as the fault unless its whole
     answer arrives inside the tick; `u64::MAX` is taken without a panic and is in effect
     no bound), and `a_whatsonchain_timeout_of_zero_is_a_fault_and_the_largest_is_no_bound_98`
     holds it: 0 against a late answer is the fault inside 5 s, 0 against a prompt server
     is the fault or the server's answer and never a wrong verdict, `u64::MAX` answers
     both questions.
   - Beside the two asks, the residual both reads scored: no test stalled a WhatsOnChain
     body after its head. `the_whatsonchain_door_bounds_a_body_that_never_ends_98` does,
     on the stub the headers service's cell uses.
6. **Records.** This section; the CHANGELOG entry names the constant's public path, the
   two ends of `with_timeout_ms` and the body-stall witness.

Files of the fold: `src/transaction/chain_trackers/mod.rs`, `src/transaction/mod.rs`,
`src/transaction/chain_trackers/whatsonchain.rs` (comments and rustdoc alone),
`tests/transport_fault_trackers.rs`, `tests/CLAUDE.md`, `src/transaction/CLAUDE.md`,
`src/transaction/chain_trackers/CLAUDE.md`, `CHANGELOG.md`, `CLAUDE.md`,
`docs/design/98-chaos-suite.md`, this record.

Not built: no refusal of a timeout of 0 at `with_timeout_ms` (the reference's client
refuses a `timeoutMs` below 1 or above 600000, `HttpClientResponseUtils.ts:19-21`; a
`Result` on the builder is a public shape, not this fold's to choose).
