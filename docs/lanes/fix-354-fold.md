# #354 fold: the cold review's two findings and notes on `lane/fix-354-unsigned-response-refused` (at e51e658 on 1cdd149)

Work in this worktree on the branch as it stands (four commits; reviewed on Opus: FIX, two findings, four notes; the review's REPORT is in `cca runs --show review-354` on this box). Read `src/auth/transports/CLAUDE.md`, `tests/CLAUDE.md`, #73's and #87's changelog entries (the transport fault classes and `fault_or`/`status_fault`), the branch's changelog entry. Do not read `~/bsv/bsv-low/` or `~/vault/`. Run every gate in the foreground; never end your turn with a gate running in the background. Never push. No test or probe on a default URL; every HTTP test binds its own wiremock server.

## The review's findings

- F1 `src/auth/transports/http/unauthenticated.rs:46-75`: an unsigned answer with status 429, 502, 503 or 504 is a transport fault under #87 and #73 (`fault_or(status_fault(..))`), not an `AuthError`: the named host did not answer in its own voice, a gateway or a limiter did. Classify those four so (the busy promise and the retry-after as #73 reads them), the rest as the refusal; update `tests/transport_unsigned_response_354.rs:171-178` (a case per class) and the rows at `CHANGELOG.md:37-41`, `src/auth/transports/CLAUDE.md:405`, `src/auth/CLAUDE.md:37`.
- F2 `unauthenticated.rs:59-60`, `CHANGELOG.md:91-92`, `CLAUDE.md:129`: "reqwest keeps no reason phrase" is false; hyper's `ReasonPhrase` is reachable through `Response::extensions()` (`hyper::ext::ReasonPhrase`). Read the server's own phrase through it, falling back to the status's canonical one when absent, and pin both (a wiremock answer with a non-standard phrase if wiremock can send one; else a raw loopback listener in the test, or say why neither can); or, if the phrase cannot be read on the crate's reqwest features, restate the sentence as exactly what is true. The divergence line moves with it.

## The review's notes

- `CHANGELOG.md:55-60`: the downstream SHAs named are stale (read each repository's tip and name it).
- `unauthenticated.rs:27-39`: the `charset=` literal sits outside the arch scanner's reach rather than in its `ALLOWED` list: put it where the rule's own CLAUDE.md says an allowed literal goes, with the reason.
- `http.rs:648-650`: the handshake's non-2xx words are a stated difference from the reference's (`SimplifiedFetchTransport.ts:115-140`): keep the statement in the parity note; a follow-up issue is the captain's.
- `http.rs` has two lines of headroom under its ratchet bound: move what F1 and F2 add into `unauthenticated.rs` or a sibling file, never over the bound; `docs/ratchets.json` is not re-recorded.

## Gate

`cargo fmt --check`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo test --features "full,http"` on every test file matching `transport_*`, `auth_*`, `arch_*` (not the `arch_support` module), `fixtures_replay`; `--lib auth::transports`; the doc tests; the wasm32 build of the CLAUDE.md feature set; `cargo semver-checks --release-type minor --baseline-rev 1cdd149`; the ratchet against `origin/beta`.

## Report

A REPORT: the tip, each commit, F1's classes and their pins, F2's reading (the phrase read or the sentence restated, with what is true), the notes applied, RED then green for the new cases, the gate's results, anything unverified.
