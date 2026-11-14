# Lane fix-98-chaos: the three fault patterns three transport_fault files did not hold (#98)

Issue #98, "The chaos suite for the substrates and transports": stub servers
answering every fault pattern, the assertions "the typed fault every time, no
retry on a refusal, no hang past the bound", the exit test "the suite runs on
every PR". The issue has no comment, no decision and no wait (read
2026-11-14). Started from beta `6232488b` (`origin/beta`'s tip at the start);
beta moved to `cb950611` (#912) during the gate and the commit was rebased
onto it, the gate run again there. No file under `src/` changed. Three doors'
files are here: `transport_fault_auth.rs`, `transport_fault_trackers.rs`,
`transport_fault_wallet.rs`. The broadcasters' file is another pull request's.

## What the three files held, and what they did not

| Pattern of the issue | Before | Now |
|---|---|---|
| A timeout (the answer delayed whole) | all three | unchanged, each mock `expect`ed |
| A reset, a refused connection | all three (the reset at auth) | unchanged |
| A body cut | all three, three copies of one raw stub | one stub, `tests/support/body_stub.rs`, its requests counted |
| 5xx with and without a body, 503 with and without the busy code, 429 | all three | unchanged, each mock `expect`ed |
| A slow body: the head, part of the body, then nothing | none | (a), all three |
| Malformed JSON | one cell (the JSON substrate, `not json` at 200) | (b), every door that reads JSON |
| No retry: one request a call | not every mock site, no raw stub | (c), every mock and every raw stub that reads a request |

## The premise, checked on the tip

The brief's premise was written from a read at `b701c06f`. On `6232488b` (the files are the same at `cb950611`):

- The `assert_fault` lines hold (`transport_fault_auth.rs:58`,
  `transport_fault_trackers.rs:72`).
  `transport_fault_wallet.rs:71` is `assert_transport`, not `assert_fault`
  (the substrates answer `WalletTransport`, their own variant).
- "The files' own lost-after-the-request cells use a raw
  `tokio::net::TcpListener`": the body-cut cells do; the auth file's
  connection-lost cell uses `std::net::TcpListener` on a thread.
- The trackers' `answered` helper mounted one mock for any `GET`, asked four
  times (two trackers, two questions): `expect(1)` could not be put on it as
  it stood, so the four questions are mocked by path.

## The doors and their timeouts

| Door | The timeout the test configures | Class under a body that never ends |
|---|---|---|
| `BlockHeadersServiceTracker` (both questions) | `timeout_ms` | `TransportFault`, `MayHaveBeenReceived`, status none |
| `SimplifiedFetchTransport` (handshake and general) | the client's, through `with_client` | `TransportFault`, `MayHaveBeenReceived`, status none |
| `HttpWalletJson`, `HttpWalletWire` | the client's, through `with_client` | `WalletTransport`, status none |

The trackers' cell is on the door the existing timeout cell holds. A paused
tokio clock is not used: the doors' timers are reqwest's over real sockets,
and a paused clock advances whenever the runtime idles on I/O, so the timeout
could fire before the stub's head arrives and the cell would no longer be a
stalled body. The cell reads real time instead: the answer no earlier than the
door's 500 ms less 100 ms, and inside 20 s (forty times the timeout). A door
with no bound fails at the 20 s line and does not hang the suite.

## The doors that read JSON

| Door | Bodies | Answer |
|---|---|---|
| The auth handshake (`200`) | empty, `not json`, two truncated objects, `[]`, `{}`, `null`, a lone BOM, a wrong member type | `Error::AuthError`, `transport_fault()` none |
| `HttpWalletJson` (`200`, `400`, `500`) | empty, a truncated object, `[]`, `null`, a wrong member type, a BOM and a brace | `Error::WalletError`, `transport_fault()` none |
| `WhatsOnChainTracker`, `BlockHeadersServiceTracker` (`200`, both questions) | empty, `not json`, a truncated object, `[]`, `null`, `{}`, wrong member types | `ChainTrackerError::InvalidResponse`, `transport_fault()` none ; ten of the 28 cells stated as differing from the reference (the fold) |

Not JSON doors: the auth general path (the BRC-104 headers and a byte body),
`HttpWalletWire` (a byte frame).

## The reference, read for the two patterns

Read at `ts-stack@edf6e03` (`git show` of the pin; the local checkout's head is
`4d0ea63`), `packages/sdk/src`. No run of the reference was made for this
lane: these are readings.

- The auth handshake's JSON refusal words are #410's, recorded there.
- The JSON substrate's malformed success answer is the row #339 states
  ("refused in `serde_json`'s words").
- The trackers: both sides answer an error for the two bodies that are not
  JSON (`not json`, a truncated object) on both questions, and for all seven
  bodies on the height question; the words are each side's own. On the root
  question the other five bodies (empty, `[]`, `null`, `{}`, a `merkleroot`
  of the wrong type) differ at both trackers, ten cells: the reference
  answers `false` (`WhatsOnChain.ts:183-186`,
  `BlockHeadersService.ts:131-171,247-248`) and this crate
  `InvalidResponse`. Stated and kept (the fold, below). The reference's WhatsOnChain tracker reads the
  height from another answer shape than this crate's (`transaction/chaintrackers/WhatsOnChain.ts`
  at the pin against `src/transaction/chain_trackers/whatsonchain.rs:205-218`):
  seen while reading, not run, outside this lane; a question for the captain.

## RED

The six tests pin landed behaviour, so RED is a mutation of the tip in a
scratch copy (its own target dir, removed after).

Run A, the classes and the bound (the tests as written before the
body-cut stubs were folded into the shared stub: the assertions are the
same): the `.timeout(..)` line removed from the headers service;
`body::read`'s error an `AuthError`; the two substrates' body reads a
`WalletError`; `body_cut` without its `serde_json` exception; the
handshake's parse error a `TransportFault`; the JSON substrate's parse error
and its refusal's last arm a `WalletTransport`. All six RED: the stalled
cell of the trackers `no answer within 20s of a body that never ends`, those
of auth and the wallet on the class; the three JSON cells on the class.

Run B, one request a call (the final tests): a second send planted before the
send at both trackers, both substrates and the handshake. 24 of 29 RED (9 of
11, 7 of 9, 8 of 9); the five green reach no server (three refused
connections, the Socket.IO sink, the typed error over a closed port).

## Can #98 close

Not with this pull request alone: the broadcasters' file is another pull
request's. The three files here are top-level `tests/*.rs`, run by the Test
Suite's whole-suite step on every pull request (`ci.yml`, `--test '*'` under
`full,http,websocket`; `tests/arch_ci_runs_every_test.rs`). What the issue's
title could still be read to cover, and this lane does not: the HTTP doors
outside the transport_fault files (the overlay facilitators, `LivePolicy`,
the storage clients, `AuthFetch`), whose fault cells live in their own files
and were not surveyed here.

## The gate

Each of the three files three times (once `--test-threads=1`), rustfmt,
clippy `--all-targets --all-features -D warnings` on 1.100.0, the `arch_*`
binaries, `rows_from_sources.py --check`, the ratchet against `origin/beta`
and gitleaks, on this commit.

## The fold (the three reads of pull request #990)

On the lane's commit rebased onto beta `e0326bd5`, and again onto `5ad961d7`
when beta moved during the gate (the gate run again there). Three items, no
file under `src/` changed.

1. The trackers' root question, stated. The captain's ruling: this crate
   keeps `InvalidResponse` (a malformed answer from a tracker is a fault a
   caller may retry or route elsewhere, never evidence about the root; #87's
   typed-fault contract; both sides refuse the root). The JSON cell is two
   tests. Of 28 cells (seven bodies, two trackers, two questions):

   | Cells | Which | The reference | Here |
   |---|---|---|---|
   | 10 | root, both trackers, the five bodies read as a value | `false` | `InvalidResponse` |
   | 4 | root, both trackers, the two bodies that are not JSON | an error | `InvalidResponse` |
   | 14 | height, both trackers, all seven | an error | `InvalidResponse` |

   The ten are `..._where_the_reference_answers_false_stated_98`, its table
   `NO_ANSWER` naming both answers for each body; the 18 stay in
   `an_answer_that_is_not_the_questions_json_..._98`.
2. Each wallet substrate bounded by itself. `bounded` wrapped `both_at`, so
   the JSON substrate's 500 ms covered a wire substrate answering at once.
   `BodyStub::stalled_once` holds one call: its own lower bound, its own
   20 s, its own one request.
3. The stalled count, by construction. The earlier test read the stub's
   counter when the call returned; the call returns on its own timer, and a
   stub not yet scheduled to read the request left the counter behind.
   `BodyStub::settled` asks the stub over a connection of its own, and the
   stub answers only after every connection accepted before that one has
   been read to a whole request or to its close; `stalled_once` drops the
   door before it asks, so each of the door's connections reaches one of the
   two. No sleep. What counting cannot repair is a request that never left
   the client inside the timeout (a host stalled for the whole 500 ms before
   hyper wrote it): the stub then reads a close and no request, the call
   stalled on no body, and `stalled_once` makes the call again, three times
   at most, then fails in `no request reached the stub`. The body-cut cells
   read the counter as before: the stub counts before it answers and the
   call's error is the answer's.

RED, a scratch copy of the lane's commit on `e0326bd5` with its own target
dir, both removed:

| Plant | The earlier tests | The fold's |
|---|---|---|
| The wire substrate returns `WalletTransport` at once after its send | green | RED, `wire: answered after 552.208µs, before the door's timeout` |
| The stub sleeps 700 ms before it reads | RED at all three stalled cells, `left: 1, right: 2` | green (4.5 s) |
| A second send at the wire substrate | (run B above) | RED, `wire: 2 requests for one call` |
| WhatsOnChain's root answers `Ok(false)` for a body it cannot read | not run | RED at both JSON cells, `a fault is never a verdict: false` |
