# Lane main-1043-memory-limit: `set_memory_limit` on the two streaming readers of the 0.8 line (#1043)

Started from `origin/main` at `a6b7da07` (0.8.11). A hand port of beta's
`09f75db6` (#373). Logs under `/Volumes/Lanes/out/bsv-rs/main-1043-memory-limit/`.

## What the issue asks

The middleware crates check a payment through the streaming reader and set
its work budget there (#1043): `bsv-middleware-core` builds
`AsyncStreamVerifier::new(None)` and calls `set_work_limit`; `bsv-middleware-rs`
would build both readers and set both budgets. They need the memory budget
beside the work budget, in the 0.9 line's names.

## What this line gets

- `AsyncStreamVerifier::set_memory_limit(&mut self, Option<usize>)` and
  `StreamVerifier::set_memory_limit(&mut self, Option<usize>)`, beside
  `set_work_limit` in a child module, `src/transaction/beef_stream/budget.rs`
  (beta's file and shape): the two budgets travel through the fold as one
  private value, `Budget { work, memory }`, and each spend's parameters take
  `budget.memory` where they took `None`.
- `Some(n)`: the caller's LOCAL budget of `n` bytes per stack for every input
  of every transaction the reading runs a script for. One spent is the
  existing `Verdict::SpendRefused { txid, input, why: SpendRefusal::Resource(limit) }`.
- `None`, the default: this line's default-mode budget of 32,000,000 bytes per
  stack (`SpendParams::memory_limit`, `DEFAULT_MEMORY_LIMIT`), the figure every
  reading used before the setter. On the 0.9 line `None` is uncapped (beta's
  #331). The port states this and does not move it.

## What of the beta commit was left

- `SpendRefusal`'s `Display` (beta's #213), which beta's test reads: not on
  this line; the tests compare the structured figures.
- Beta's `None` as uncapped (#331): it would change the answer of every reader
  that never calls the setter on a script past 32,000,000 bytes.
- The `deferred.rs` and `release_one` hunks: this line has no deferred parents
  (beta's #240).
- The CLAUDE.md table row's wording of beta: rewritten for this line's `None`.

## The tests

- `tests/beef_stream_memory_budget_1043.rs` (11), compile-RED on `a6b7da07`
  (`error[E0599]: no method named set_memory_limit found for struct
  AsyncStreamVerifier` twice, `... StreamVerifier<R, H>` five times): the async
  reader first, then the blocking reader.
- `tests/beef_stream_memory_budget_1043_pins.rs` (3), green on `a6b7da07` and
  after: what must not move.
- The doc test on `AsyncStreamVerifier::set_memory_limit` builds the async
  reader, sets both budgets and reads the decline. The same text, wrapped as a
  test, passes on `origin/beta` `4c5454be` (log `doctext-on-beta.log`; the
  payment is built with `Transaction::with_params`, as beta's `version` is a
  method).

## The gate

The table is in the lane's REPORT; each step's log is
`gate-<step>.log` in the out folder.
