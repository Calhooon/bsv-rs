# Lane fix-868-benford: `fee(.., ChangeDistribution::Random)` and `distribute_change` against the reference (#868)

Started from `origin/beta` at `460e6201`. Logs under `/Volumes/Lanes/out/bsv-rs/fix-868-benford/`.

## The finding, as a run shows it

`Transaction::benford_number` divided by `1_f64.log10()`, zero. The factor is
infinite, `(range * factor) as u64` saturates to `u64::MAX`, and
`min + u64::MAX` (with `min` 1) overflows. What that does depends on the build:

| Build | `origin/beta` `460e6201` | `bsv-rs = "=0.8.5"` (crates.io) |
|---|---|---|
| debug | `panicked at src/transaction/transaction.rs:1676:9: attempt to add with overflow` | `panicked at .../bsv-rs-0.8.5/src/transaction/transaction.rs:1549:9: attempt to add with overflow` |
| release | `n 2, change 12345: output 0 holds 0, not a Benford portion of 12345 ([0, 12345])` | the same message |

In release the add wraps: `1 + u64::MAX` is 0. So every change output but the
last gets 0 and the last gets the whole change. The sum is still right, which
is why `random_change_never_panics_and_sums_to_the_change_868` passes on the
base in release. No output holds `u64::MAX`: that is the cast's value before
the wrap, not an amount written to the transaction.

The test file on the base, as it stood before the fold's split (seven tests,
the equal test among them; commit A's six are counted in the fold's section
below), in a scratch worktree of `origin/beta` with only the test file copied
in, its own target dir:

- Debug, 7 of 7 RED. Four panics in the crate, all `attempt to add with overflow`:
  - `transaction.rs:1676:9`: the divisor, in both random tests.
  - `:1591:13`: `fee`'s input total.
  - `:1598:17`: `fee`'s output total.
  - `:1693:13`: `get_fee`'s input total.

  Two assertions fail:
  - `change 5 over 3`: `left: [2, 2, 1]`, `right: [1, 1, 3]`.
  - `change 1 over 2`: `left: [1, 0]`, `right: [0, 1]`.
- Release, 6 of 7 RED:
  - The Benford message above.
  - The same two assertions.
  - The three overflow cells answer `Ok` (`called Result::unwrap_err() on an Ok value`): the totals wrapped, so `fee` saw no change and removed the change outputs, and `get_fee` answered 0.
- The published 0.8.5, debug and release: the same failures as the base. Its scratch project is `published-085/` in the out folder; the logs are `published-085-{debug,release}.log`.

## `distribute_change` against the reference, line by line

The reference is `ts-stack@edf6e03`, `packages/sdk/src/transaction/Transaction.ts:864-897`.

| Step | Reference | This crate before #868 | Now |
|---|---|---|---|
| change outputs | `outputs.filter(out => out.change === true)` | indices of `o.change` | same |
| none | return (the value stays fee) | return | same |
| random: each but the last | `portion = #benfordNumber(0, remaining)`; `remaining -= portion` | `benford_number(1, remaining)`: minimum **1** | minimum 0 (**conformed**) |
| random: the last | `remaining` | `change - distributed` (the same value) | `remaining` |
| benford formula | `Math.floor(min + (max - min) * log10(1 + 1/d) / log10(10))` | `/ log10(1)`, truncating cast | `/ log10(10)`, `floor` (**the fix**) |
| benford digit | `Random(1)[0] % 9 + 1` | `gen_range(1..=9)` | the same: a different random source, by necessity |
| equal | `floor(change / n)` to every output, then `last += change - perOutput * n` | `change / n`, plus 1 for each of the first `change % n` outputs | unchanged in commit A (stated); the reference's in commit B (**conformed**), the fold's split below |
| order of writes | every output but the last, in order, then the last | random: the same; equal: in order | the same for both arms |
| an output at 0 | allowed (no minimum) | random: the minimum 1 underflowed at `max - min` once the change ran out | allowed |

Change below the output count: the reference's answer is fixed for any change
under `1 / log10(2)`, about 3.32, because `floor(r * f)` is then 0 for every
digit. Change 1 over 3 is `[0, 0, 1]`, 2 over 5 is `[0, 0, 0, 0, 2]`, 3 over 3
is `[0, 0, 3]`. The reference guarantees no change output at least one
satoshi.

Overflow (rule 5). Inside the distribution, after the fix:

- A random portion is at most `0.30103 * remaining`.
- An equal portion is at most `change / n`.

So `remaining -= portion` cannot underflow. That bound needs no `checked_`
step or saturating cast in the arms, and none is planted (a clamp there would
be an equivalent mutant).

Where a caller's amounts can overflow is the totals in `fee` and `get_fee`.
They are checked now, in the reference's `addSatoshiAmount` words. The cells
that reach them:

- `an_input_total_past_u64_is_refused_in_the_reference_words_868`: sources of `u64::MAX` and 1.
- `an_output_total_past_u64_is_refused_in_the_reference_words_868`: an output of `u64::MAX`.
- `get_fee_refuses_a_total_past_u64_and_the_output_sum_saturates_868`.

`total_output_satoshis` returns `u64`, so it saturates where it panicked.

Stated, not conformed, all older than #868 (the root `CLAUDE.md` row and the
`CHANGELOG` parity note). Until commit B, the equal arm's remainder (above).
The reference's `fee`:

- refuses insufficient inputs, where this crate saturates the change to 0;
- bounds amounts at 21e14 satoshis, where this crate bounds them at `u64`.

Its `getFee` answers a negative fee, where this crate saturates to 0.

go-sdk at `2ca481c` (`transaction/fees.go:21-63`) has no random distribution
(`not-implemented`). Its equal arm leaves the remainder to the fee.

## The stable line

`git cherry-pick -x` of the fix onto `origin/main` (`a8186851`, 0.8.5), tried in a scratch worktree and not kept:

- `src/transaction/transaction.rs` and `tests/transaction_tests.rs` apply cleanly.
- `src/transaction/amount.rs` is modify/delete: the file is #844's, which is beta's. The port needs a new `amount.rs` holding `add_amount` alone, plus `mod amount;` in `src/transaction/mod.rs`.
- `CHANGELOG.md`, `CLAUDE.md`, `src/transaction/CLAUDE.md` and `tests/CLAUDE.md` conflict on context, as every pick of a docs change does.

With the docs left as main's and the two-line port above, `tests/transaction_fee_random_change_868.rs` compiles unchanged and passes (7 of 7, the unsplit file; commit A carries six). `tests/transaction_tests.rs` passes too (104).

## The fold: one commit split in two (lane fix-868-benford-fold)

The captain's ruling on the cold read's judgement: the random arm's fix is a
bug fix (a debug panic on a caller's values, a degenerate distribution in
release) and the stable line takes it in 0.8.6; the equal arm's conformity
moves amounts a caller can see (`[2, 2, 1]` becomes `[1, 1, 3]`) where nothing
was broken, has no class under `RELEASING.md`'s direction rule, and stays on
`beta`. `main` takes whole commits, so the one commit (`f80f5bf8`, with both
reads' docs commits `0d57dd7b` and `5033fc92` taken on it) is two:

- **A** (`lane/fix-868-benford-fold`, on `f97e94f6`): the random arm (the
  divisor, `floor`, the minimum 0, each output but the last its portion and
  the last the rest), the totals refused past `u64` (`amount::add_amount` at
  its four sites, `total_output_satoshis` saturating), the test file's six
  tests (the equal test out), the records stating the equal arm's remainder.
  `tests/transaction_tests.rs` unchanged (the old spread stands). On
  `f97e94f6` with the six tests copied in: 6 of 6 RED in debug (five panics at
  `transaction.rs:1676:9`, `:1591:13`, `:1598:17`, `:1693:13`; `left: [1, 0]`,
  `right: [0, 1]`), 5 of 6 in release (the sum test passes: the wrap keeps
  the sum).
