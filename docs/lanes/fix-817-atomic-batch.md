# Lane fix-817-atomic-batch: one preparation for k atomic closures (#817)

Started from `cb950611710f81c1ce4ba0c1976df9f32d680ade`, `origin/beta`'s tip when the lane
opened. Speed, not parity: no answer byte, verdict or error text moves.

## The line

The bucket Calhooon/bsv-rs#817 holds the line "the atomic closure rebuilds a txid map per
call" (from the strength read of PR #801): the binary lookup answer calls
`Beef::to_binary_atomic` once a distinct txid, and each call builds a map over every
transaction of the BEEF. The issue's comments record no decision and no wait on this line.

## What the tip did, checked line by line

At `cb950611`:

- `src/transaction/beef_atomic.rs:47` is `to_binary_atomic`; the shared body `atomic_bytes`
  is `:64-101`. It ran `refresh_mutated` (`src/transaction/beef/index.rs:112-123`, every
  entry), `refuse_unsafe_amount` (`src/transaction/beef_writable.rs:200`, every held
  transaction), then looked for the subject, then `atomic_closure`.
- `atomic_closure` (`:115-197`) built `at: HashMap<String, usize>` over every entry
  (`:116-121`), walked the subject's ancestry, and then ran two loops over every entry of
  the BEEF (`:142`, `:168`), each asking `included.contains` to find the few it kept. The
  two loops are not in the issue's line; they are a fourth and fifth pass a call.
- `src/overlay/facilitators/binary_answer.rs:67-112` called `to_binary_atomic` once a
  distinct txid (the memo `by_txid`, `:80-95`).

So k distinct txids over n entries cost about 5 * k * n entry visits, k * n of them a
`String` clone and a map insert.

One premise did not hold as written: that the closure's map can be the BEEF's own index.
The two agree on every state the doors make, twins included (the last position wins on
both). They part inside the stated hand-edit window of `beef/index.rs`: a txid the index
was never given, left below the indexed count by a hand replacement in `txs`, is missed by
`index_of` and found by the map. The per-call door has always read its ancestors through
the map, so such a parent is in its child's closure today. Reading the index would move
those bytes on a public door. The lane keeps a map and builds it once a batch; the test
`a_parent_the_index_was_never_given_stays_in_its_childs_closure_817` holds the state. A
probe with the index in the map's place passed the differential's nine states (none of
them is in the window: a hand-built transaction of a chosen txid cannot be made, so the
state needs a child whose parent was never merged) and would fail that directed test.

## The change

- `Beef::atomic_batch(&mut self) -> Result<AtomicBatch<'_>>` (crate-private): the refresh,
  the amount refusal and the position map, once. The batch holds `&Beef`, so nothing can
  move under the closures it cuts.
- `AtomicBatch::to_binary_atomic(&self, txid)`: the subject looked for (`does not exist in
  this Beef`), the closure cut and checked, the bytes written; the per-call body moved,
  not rewritten.
- `atomic_closure` takes the map and walks the entries it keeps in entry order (the kept
  positions sorted), where it filtered every entry twice. The order of the copies, of the
  renumbered BUMPs and so of the bytes is the same.
- `Beef::to_binary_atomic` and `to_binary_atomic_subject_last` are a batch of one: the
  same sequence as before (refresh, amount, map, subject, closure, check, write; the map
  moved ahead of the subject's lookup, which it cannot affect).
- `binary_answer.rs` prepares one batch ahead of its loop. With no outpoint it returns
  before preparing, as it called no closure before; with one or more, the leading
  outpoint always reached `to_binary_atomic` ahead of every other check of that outpoint,
  so a refused preparation stands where that call's refusal stood, in the same wrapper
  (`Failed to extract BEEF: ..`).
- A `cfg(test)` module `cost` in `beef_atomic.rs` counts the entries each loop visits (a
  thread-local record of five figures; the fold below), read by the tests through
  `Beef::atomic_cost_taken`. No test asserts a time. Until the fold it counted
  preparations and the entries closures keep.

No public item is added or reshaped. Nothing under `src/transaction/verify.rs`,
`src/transaction/beef_stream*` or any reader is touched.

## The tests and their RED

RED was watched on a scratch copy of `cb950611` (its own target dir, removed) holding the
old `beef_atomic.rs` and `binary_answer.rs` with the counters alone added (a preparation
counted at the head of `atomic_bytes`, an entry counted at each turn of the old copy
loop):

| Test | RED on the scratch copy | Green |
|---|---|---|
| `the_answers_closures_share_one_preparation_of_its_beef_817` (`binary_answer_tests.rs`) | `left: (32, 1024)`, `right: (1, 32)` | yes |
| `the_per_call_door_visits_only_the_closure_it_keeps_817` (`beef/atomic_batch_817_tests.rs`) | `left: (1, 67)`, `right: (1, 1)` | yes |

(Those two figures were read on a scratch counter at each turn of the old loop; on the
pull request's own counter the loops' revert was green. The fold below mends it.)

The other five are pins of what must not move, and three of them need the batch door to
compile, so they have no RED of their own: the differential
`the_batch_door_answers_as_the_per_call_door_on_every_vector_beef_817` (372 BEEFs, nine
states, every txid held and three texts not held, against the old per-call door kept
verbatim as `oracle`; both doors, and the BEEF left the same),
`a_batch_prepares_once_and_each_closure_visits_only_what_it_keeps_817`,
`the_amount_refusal_stands_ahead_of_a_subject_not_held_on_both_doors_817`,
`a_parent_the_index_was_never_given_stays_in_its_childs_closure_817`,
`an_answer_of_no_outpoint_prepares_nothing_817`.

`prepass_621_tests.rs` changes by one word (`pub(super) mod seeds`), so the seed file is
loaded once for both unit test files (clippy's `duplicate_mod`).

## The fold: the counter counts the entries the loops visit

The strength read of pull request #996 (`06102dbe`) found the two cost tests not holding
the cost they are named for: the counter read `atomic_batch` calls and `kept.len()`, and
both read the same whether a closure's loops visit the entries kept or every entry. The
RED of the table above came from a scratch counter at each turn of the OLD loop, another
counter than the tip's. The fold (lane `fix-817-atomic-batch-fold`, on the pull request's
commit rebased onto beta `1acd0854`) moves the counts to where the work is:

| Figure of `cost::Cost` | Counted at |
|---|---|
| `refreshed` | each turn of `refresh_mutated`'s loop (`beef/index.rs`), any door's |
| `amounts` | the entries handed to `refuse_unsafe_amount` (`beef_writable.rs`), any door's |
| `mapped` | each turn of the position map's loop (`Beef::positions`) |
| `bump_loop` | each turn of the closure's loop that renumbers the BUMPs |
| `copy_loop` | each turn of the closure's loop that copies the entries |

`passes()` is the three leading figures and `loops()` the two last. A closure's own BEEF
is refreshed by its `sort_txs` and checked by its `check_writable`, so each closure adds
the entries it keeps to `refreshed` and `amounts`, and none to `mapped`. The map's loop
moved into `Beef::positions` (a `for` over the entries in the place of the iterator
chain, the same map) so the count sits at its turn. The call sites outside the `cost`
module are plain calls under `#[cfg(test)]`, no operator in them.

What the tests assert on the tip:

| Test | `passes()` | `loops()` |
|---|---|---|
| `the_answers_closures_share_one_preparation_of_its_beef_817` (32 entries, 32 closures of 1) | (64, 64, 32) | (32, 32) |
| `the_per_call_door_visits_only_the_closure_it_keeps_817` (67 entries), a proven subject | (68, 68, 67) | (1, 1) |
| the same, the chain's tip (a closure of 4) | (71, 71, 67) | (4, 4) |
| `a_batch_prepares_once_and_each_closure_visits_only_what_it_keeps_817`, the preparation | (67, 67, 67) | (0, 0) |
| the same, 64 closures of 1 | (64, 64, 0) | (64, 64) |
| the same, the tip's closure of 4 | (4, 4, 0) | (4, 4) |
| the same, a subject not held | (0, 0, 0) | (0, 0) |
| `an_answer_of_no_outpoint_prepares_nothing_817` | (0, 0, 0) | (0, 0) |

### Every cost or count assertion of the pull request, under the revert it is named for

One scratch copy of the tree (its own target dir, removed), each revert selected by an
environment variable read in the scratch code, one run of `--lib _817` a revert (20
tests). "Before" is the pull request's commit with its own counter; "after" the fold.
The logs are the lane's (`red-<revert>.log`, `prefold-<revert>.log`).

| Assertion | Revert | Before the fold | After the fold |
|---|---|---|---|
| the three cost tests' loop counts | the BUMP loop over every entry (`included.contains` the filter) | green, 20 of 20 | RED, 3 tests: loops (1024, 32) for (32, 32); (67, 1) for (1, 1); (4288, 64) for (64, 64) |
| the same | the copy loop over every entry | green | RED, 3 tests: (32, 1024); (1, 67); (64, 4288) |
| the same | both loops over every entry | green | RED, 3 tests: (1024, 1024); (67, 67); (4288, 4288) |
| the three cost tests' pass counts | the position map rebuilt a closure | green | RED, 3 tests: mapped 1056 for 32; 134 for 67; 4288 for 0 |
| the same | the amount check run again a closure | green | RED, 3 tests: amounts 1088 for 64; 135 for 68; 4352 for 64 |
| `the_answers_closures_share_one_preparation_of_its_beef_817` | the answer calling the per-call door a distinct txid | RED (33 preparations for 1; the scratch still prepared its unused batch) | RED: passes (1088, 1088, 1056) for (64, 64, 32) |
| `an_answer_of_no_outpoint_prepares_nothing_817` | the early return removed | RED ((1, 0) for (0, 0)) | RED: passes (2, 2, 2) for (0, 0, 0) |
| the differential's floor `read >= 372` | about half the seeds skipped | unchanged by the fold | RED: 168 BEEFs read |
| its floor `bytes >= 2 * read` | no held txid asked | unchanged | RED: 0 closures written |
| its floor `not_held >= 3 * read` | the three texts not held left unasked | unchanged | RED: 845 subjects not held (the txids a state dropped), under 1,116 |
| its floor `prepared_err >= read / 2` | the 2^53 state left as read | unchanged | RED: 0 batches refused whole |
| its floor `refused >= read` | the 2^53 state left as read | unchanged | green on this floor (890 refusals; the run is RED on `prepared_err`) |
| the same | the four refusing states left as read (two version words, the txid-only entry, 2^53) | unchanged | RED: 0 refusals |

The five were green and are mended by the counter. A refresh run again a closure is not
a revert a scratch can make: `AtomicBatch` holds `&Beef` and `refresh_mutated` takes
`&mut self`, so the compiler holds it. The floor `refused` is a floor of reach over four
sources, as its message says (a held subject or an amount), and goes red when none is
reached, not when one is lost; it is left as it is. The figures of a healthy run: 372
read, 4,629 closures written, 2,959 refusals, 9,851 not held, 346 batches refused whole.

Two mutations the strength read named beside the counter, run in the same scratch and
RED on the tests as they stood: the map built from the entries the index finds
(`a_parent_the_index_was_never_given_stays_in_its_childs_closure_817`) and the map with
the earliest position of a txid winning (the differential, a vector BEEF under the hand
push state).

The counter's bound (the fold's cold read, run on a scratch copy of `dde3aeaa`, one
`--lib _817` run each, all 20 green): it counts the turns it sits at and the doors it
sits in, not every spelling of a scan. Three reverts left every test green: both
closure loops over every entry with the kept entries chosen by a `filter` on the
iterator ahead of the loop's body (`self.txs.iter().enumerate().filter(..)`, 67 entries
visited a closure, the counted turns 1); the map collected again a closure by the
iterator chain the pull request replaced, `positions` not called; and the amounts read
again a closure by `BeefTx::amount_refusal` over `txs`, `refuse_unsafe_amount` not
called. A reviewer reads such a change in its diff; no machine of this pull request
does.

The counter costs nothing outside the unit tests: `mod cost`, `Cost` and
`atomic_cost_taken` are `#[cfg(test)]`, and so is each call. The module does not exist
in another build, so a call left outside the attribute cannot compile there (E0433), and
the library is built without `cfg(test)` by `cargo check --all-features`, clippy's
library target and the wasm32 slice, each run by the fold's gate.

## The cost probe

A probe outside the tree (an ignored unit test appended to `binary_answer_tests.rs` in a
scratch copy, release profile, one run each on the lane's host under other lanes' load): a
BEEF of n one-input, one-output transactions with no proof, 4,096 distinct txids asked
through `atomic_outputs`, the parse of the BEEF included. The answer's bytes are the same
before and after (425,984).

| n | BEEF bytes | before: preparations, entry visits of the copy loop | before, ms | after: preparations, entries kept | after, ms |
|---|---|---|---|---|---|
| 4,096 | 253,960 | 4,096; 16,777,216 | 1,048.5 | 1; 4,096 | 13.5 |
| 20,000 | 1,240,008 | 4,096; 81,920,000 | 5,860.1 | 1; 4,096 | 29.9 |
| 100,000 | 6,200,010 | 4,096; 409,600,000 | 43,727.1 | 1; 4,096 | 144.8 |

The times are one run and move with the host; the counts do not.

## Left as it is

- The per-call public door still prepares a call (three passes over the BEEF), as the
  reference's does (`ts-stack@edf6e03` `Beef.ts:392-404`). A caller of this crate with
  many subjects has no public batch; a public one is a new item, not built here.
- The batch builds its map with one `String` an entry. The BEEF's index would save that
  pass at the price of the window's bytes (above).
- `refresh_mutated`'s whole-BEEF scan goes with the deprecated `BeefTx::tx_mut` (the
  bucket's line on `merge_beef`).
