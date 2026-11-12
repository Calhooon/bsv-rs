# Lane fix-871-fee-refusals

`Transaction::fee` and `get_fee` refuse what the reference refuses (Calhooon/bsv-rs#871). Base `8e78516f` (`origin/beta`). Beta only: 0.8.x keeps these answers, stated.

## The reference, by a run

`tests/support/transaction_fee_refusals_871.mjs`: `packages/sdk` at `ts-stack@edf6e03` (`git archive`, bundled with bun), Node v22.18.0, `globalThis.fetch` replaced before the bundle loads with a function that refuses without a request (the default fee model's one URL, `https://arc.gorillapool.io/v1/policy`, recorded, never asked). 65 cells; `fee` and `getFee` on each; two runs byte-identical (`cmp`). Each transaction is built through the reference's constructor (its `addOutput` refuses an output with no amount and an amount past 21e14 before `fee` reads it).

## The recorded table

Reference, this crate at the base, this crate at the tip. `c` marks a change output. The base column is the base's answer from the RED run (`tests/transaction_fee_refusals_871.rs` on a scratch copy of `8e78516f`); a cell it did not print agreed with the reference. The (e) rows' base and tip `fee` answers are the one-satoshi-per-byte rule over `estimate_size` (72 and 124 bytes), the tip's asserted by the (e) test, the base's derived from the same rule; the reference's are `ceil(size * 100 / 1000)` of the same sizes (8 and 13).

| Row | Cell | Door | Reference | Base `8e78516f` | Tip |
|---|---|---|---|---|---|
| a | `a_inputs_cannot_pay_the_outputs_alone` | fee | Err: insufficient | Ok [1001] | the reference |
| a | `a_inputs_cannot_pay_the_outputs_alone` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 0 | the reference |
| a | `a_inputs_cannot_pay_the_outputs_and_the_fee` | fee | Err: insufficient | Ok [950] | the reference |
| a | `a_inputs_cannot_pay_the_outputs_and_the_fee` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 50 | the reference |
| a | `a_one_satoshi_short` | fee | Err: insufficient | Ok [901] | the reference |
| a | `a_one_satoshi_short` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 99 | the reference |
| a | `a_exactly_the_outputs_and_the_fee` | fee | Ok [900] | Ok [900] | the reference |
| a | `a_exactly_the_outputs_and_the_fee` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 100 | the reference |
| a | `a_one_satoshi_over` | fee | Ok [899, 1c] | Ok [899, 1c] | the reference |
| a | `a_one_satoshi_over` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 101 | the reference |
| a | `a_short_with_no_change_output` | fee | Err: insufficient | Ok [950] | the reference |
| a | `a_short_with_no_change_output` | getFee | Ok 50 | Ok 50 | the reference |
| a | `a_surplus_with_no_change_output` | fee | Ok [500] | Ok [500] | the reference |
| a | `a_surplus_with_no_change_output` | getFee | Ok 500 | Ok 500 | the reference |
| a | `a_no_input_and_an_output` | fee | Err: insufficient | Ok [1] | the reference |
| a | `a_no_input_and_an_output` | getFee | Ok -1 | Ok -1 | Ok 0 (stated) |
| a | `a_no_input_and_no_output` | fee | Ok [] | Ok [] | the reference |
| a | `a_no_input_and_no_output` | getFee | Ok 0 | Ok 0 | the reference |
| a | `a_no_input_and_a_fee` | fee | Err: insufficient | Ok [] | the reference |
| a | `a_no_input_and_a_fee` | getFee | Ok 0 | Ok 0 | the reference |
| a | `a_outputs_above_the_inputs_with_no_fee` | fee | Err: insufficient | Ok [200] | the reference |
| a | `a_outputs_above_the_inputs_with_no_fee` | getFee | Ok -100 | Ok -100 | Ok 0 (stated) |
| a | `a_short_under_the_random_distribution` | fee | Err: insufficient | Ok [950] | the reference |
| a | `a_short_under_the_random_distribution` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 50 | the reference |
| b | `b_input_amount_at_21e14` | fee | Ok [2099999999999900] | Ok [2099999999999900] | the reference |
| b | `b_input_amount_at_21e14` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 100 | the reference |
| b | `b_input_amount_past_21e14` | fee | Err: Input 0 source amount must be ... 21e14 | Ok [1] | the reference |
| b | `b_input_amount_past_21e14` | getFee | Err: Input 0 source amount must be ... 21e14 | Ok 2100000000000000 | the reference |
| b | `b_input_amount_at_2p53_minus_1` | fee | Err: Input 0 source amount must be ... 21e14 | Ok [1] | the reference |
| b | `b_input_amount_at_2p53_minus_1` | getFee | Err: Input 0 source amount must be ... 21e14 | Ok 9007199254740990 | the reference |
| b | `b_input_amount_at_2p53` | fee | Err: Input 0 source amount must be ... 21e14 | Ok [1] | the reference |
| b | `b_input_amount_at_2p53` | getFee | Err: Input 0 source amount must be ... 21e14 | Ok 9007199254740991 | the reference |
| b | `b_input_total_at_21e14` | fee | Ok [1, 2099999999999999c] | Ok [1, 2099999999999999c] | the reference |
| b | `b_input_total_at_21e14` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 2099999999999999 | the reference |
| b | `b_input_total_past_21e14` | fee | Err: Transaction input total exceeds the range | Ok [1] | the reference |
| b | `b_input_total_past_21e14` | getFee | Err: Transaction input total exceeds the range | Ok 2100000000000000 | the reference |
| b | `b_input_total_past_2p53` | fee | Err: Transaction input total exceeds the range | Ok [1] | the reference |
| b | `b_input_total_past_2p53` | getFee | Err: Transaction input total exceeds the range | Ok 10499999999999999 | the reference |
| b | `b_output_amount_at_21e14` | fee | Ok [2100000000000000] | Ok [2100000000000000] | the reference |
| b | `b_output_amount_at_21e14` | getFee | Ok 0 | Ok 0 | the reference |
| b | `b_output_amount_past_21e14` | fee | Err: Output 0 amount must be ... 21e14 | Ok [2100000000000001] | the reference |
| b | `b_output_amount_past_21e14` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| b | `b_output_amount_at_2p53_minus_1` | fee | Err: Output 0 amount must be ... 21e14 | Ok [9007199254740991] | the reference |
| b | `b_output_amount_at_2p53_minus_1` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| b | `b_output_amount_at_2p53` | fee | Err: Output 0 amount must be ... 21e14 | Ok [9007199254740992] | the reference |
| b | `b_output_amount_at_2p53` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| b | `b_output_total_at_21e14` | fee | Ok [1000000000000000, 1100000000000000] | Ok [1000000000000000, 1100000000000000] | the reference |
| b | `b_output_total_at_21e14` | getFee | Ok 0 | Ok 0 | the reference |
| b | `b_output_total_past_21e14` | fee | Err: Transaction output total exceeds the range | Ok [1000000000000000, 1100000000000001] | the reference |
| b | `b_output_total_past_21e14` | getFee | Err: Transaction output total exceeds the range | Ok 0 | the reference |
| b | `b_output_total_past_2p53` | fee | Err: Transaction output total exceeds the range | Ok [2100000000000000, 2100000000000000, 2100000000000000, 2100000000000000, 2100000000000000] | the reference |
| b | `b_output_total_past_2p53` | getFee | Err: Transaction output total exceeds the range | Ok 0 | the reference |
| b | `b_fee_at_21e14` | fee | Ok [] | Ok [] | the reference |
| b | `b_fee_at_21e14` | getFee | Ok 2100000000000000 | Ok 2100000000000000 | the reference |
| b | `b_fee_past_21e14` | fee | Err: Computed transaction fee must be ... 21e14 | Ok [] | the reference |
| b | `b_fee_past_21e14` | getFee | Ok 2100000000000000 | Ok 2100000000000000 | the reference |
| b | `b_fee_at_2p53` | fee | Err: Computed transaction fee must be ... 21e14 | Ok [] | the reference |
| b | `b_fee_at_2p53` | getFee | Ok 2100000000000000 | Ok 2100000000000000 | the reference |
| b | `b_change_output_holding_an_amount_past_21e14` | fee | Ok [100, 900c] | Ok [100, 900c] | the reference |
| b | `b_change_output_holding_an_amount_past_21e14` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 0 | the reference |
| c | `c_no_amount_at_output_0_of_3` | fee | Err: Output 0 amount must be ... 21e14 | Ok [None, 10, 10] | the reference |
| c | `c_no_amount_at_output_0_of_3` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 980 | the reference |
| c | `c_no_amount_at_output_1_of_3` | fee | Err: Output 1 amount must be ... 21e14 | Ok [10, None, 10] | the reference |
| c | `c_no_amount_at_output_1_of_3` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 980 | the reference |
| c | `c_no_amount_at_output_2_of_3` | fee | Err: Output 2 amount must be ... 21e14 | Ok [10, 10, None] | the reference |
| c | `c_no_amount_at_output_2_of_3` | getFee | Err: Output 2 amount must be ... 21e14 | Ok 980 | the reference |
| c | `c_source_output_with_no_amount` | fee | Err: Input 0 source amount must be ... 21e14 | Err: no source (fee) | the reference |
| c | `c_source_output_with_no_amount` | getFee | Err: Input 0 source amount must be ... 21e14 | Err: no source (getFee) | the reference |
| c | `c_change_output_with_no_amount` | fee | Ok [10, 990c] | Ok [10, 990c] | the reference |
| c | `c_change_output_with_no_amount` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 990 | the reference |
| d | `d_index_one_past_the_source_outputs` | fee | Err: Input 0 source output does not exist | Err: no source (fee) | the reference |
| d | `d_index_one_past_the_source_outputs` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| d | `d_index_far_past_the_source_outputs` | fee | Err: Input 0 source output does not exist | Err: no source (fee) | the reference |
| d | `d_index_far_past_the_source_outputs` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| d | `d_source_with_no_outputs` | fee | Err: Input 0 source output does not exist | Err: no source (fee) | the reference |
| d | `d_source_with_no_outputs` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| d | `d_second_input_past_its_source` | fee | Err: Input 1 source output does not exist | Err: no source (fee) | the reference |
| d | `d_second_input_past_its_source` | getFee | Err: Input 1 source output does not exist | Err: no source (getFee) | the reference |
| d | `d_no_source_transaction` | fee | Err: no source (fee) | Err: no source (fee) | the reference |
| d | `d_no_source_transaction` | getFee | Err: no source (getFee) | Err: no source (getFee) | the reference |
| order | `order_fee_past_21e14_before_a_missing_source_output` | fee | Err: Computed transaction fee must be ... 21e14 | Err: no source (fee) | the reference |
| order | `order_fee_past_21e14_before_a_missing_source_output` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| order | `order_fee_past_21e14_before_no_source_transaction` | fee | Err: Computed transaction fee must be ... 21e14 | Err: no source (fee) | the reference |
| order | `order_fee_past_21e14_before_no_source_transaction` | getFee | Err: no source (getFee) | Err: no source (getFee) | the reference |
| order | `order_input_amount_before_a_later_missing_output` | fee | Err: Input 0 source amount must be ... 21e14 | Err: no source (fee) | the reference |
| order | `order_input_amount_before_a_later_missing_output` | getFee | Err: Input 0 source amount must be ... 21e14 | Err: no source (getFee) | the reference |
| order | `order_missing_output_before_a_later_input_amount` | fee | Err: Input 0 source output does not exist | Err: no source (fee) | the reference |
| order | `order_missing_output_before_a_later_input_amount` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| order | `order_no_source_before_a_later_missing_output` | fee | Err: no source (fee) | Err: no source (fee) | the reference |
| order | `order_no_source_before_a_later_missing_output` | getFee | Err: no source (getFee) | Err: no source (getFee) | the reference |
| order | `order_missing_output_before_a_later_no_source` | fee | Err: Input 0 source output does not exist | Err: no source (fee) | the reference |
| order | `order_missing_output_before_a_later_no_source` | getFee | Err: Input 0 source output does not exist | Err: no source (getFee) | the reference |
| order | `order_input_total_before_an_output_with_no_amount` | fee | Err: Transaction input total exceeds the range | Ok [None] | the reference |
| order | `order_input_total_before_an_output_with_no_amount` | getFee | Err: Transaction input total exceeds the range | Ok 2100000000000001 | the reference |
| order | `order_input_amount_before_an_output_amount` | fee | Err: Input 0 source amount must be ... 21e14 | Ok [2100000000000001] | the reference |
| order | `order_input_amount_before_an_output_amount` | getFee | Err: Input 0 source amount must be ... 21e14 | Ok 0 | the reference |
| order | `order_output_with_no_amount_before_insufficient` | fee | Err: Output 0 amount must be ... 21e14 | Ok [None, 100] | the reference |
| order | `order_output_with_no_amount_before_insufficient` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| order | `order_output_amount_before_a_later_output_with_no_amount` | fee | Err: Output 0 amount must be ... 21e14 | Ok [2100000000000001, None] | the reference |
| order | `order_output_amount_before_a_later_output_with_no_amount` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| order | `order_output_with_no_amount_before_a_later_output_amount` | fee | Err: Output 0 amount must be ... 21e14 | Ok [None, 2100000000000001] | the reference |
| order | `order_output_with_no_amount_before_a_later_output_amount` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 0 | the reference |
| order | `order_output_total_before_a_later_output_with_no_amount` | fee | Err: Transaction output total exceeds the range | Ok [1000000000000000, 1100000000000001, None] | the reference |
| order | `order_output_total_before_a_later_output_with_no_amount` | getFee | Err: Transaction output total exceeds the range | Ok 0 | the reference |
| order | `order_output_total_before_insufficient` | fee | Err: Transaction output total exceeds the range | Ok [1000000000000000, 1100000000000001] | the reference |
| order | `order_output_total_before_insufficient` | getFee | Err: Transaction output total exceeds the range | Ok 0 | the reference |
| e | `e_default_one_input_one_change` | fee | Ok [1000, 8992c] | Ok [1000, 8928c] | Ok [1000, 8928c] (1 sat/byte, stated) |
| e | `e_default_one_input_one_change` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 9000 | the reference |
| e | `e_default_two_inputs_three_outputs` | fee | Ok [1000, 2000, 4987c] | Ok [1000, 2000, 4876c] | Ok [1000, 2000, 4876c] (1 sat/byte, stated) |
| e | `e_default_two_inputs_three_outputs` | getFee | Err: Output 2 amount must be ... 21e14 | Ok 5000 | the reference |
| e | `e_default_short` | fee | Err: insufficient | Ok [90] (change saturated, removed) | the reference |
| e | `e_default_short` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 5 | the reference |
| f | `f_outputs_exceed_the_inputs_by_one` | fee | Err: insufficient | Ok [1001] | the reference |
| f | `f_outputs_exceed_the_inputs_by_one` | getFee | Ok -1 | Ok -1 | Ok 0 (stated) |
| f | `f_outputs_exceed_the_inputs_by_a_large_amount` | fee | Err: insufficient | Ok [2100000000000000] | the reference |
| f | `f_outputs_exceed_the_inputs_by_a_large_amount` | getFee | Ok -2099999999999999 | Ok -2099999999999999 | Ok 0 (stated) |
| dist | `dist_equal_one_change_output` | fee | Ok [100, 900c] | Ok [100, 900c] | the reference |
| dist | `dist_equal_one_change_output` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 900 | the reference |
| dist | `dist_equal_three_change_outputs_with_a_remainder` | fee | Ok [100, 300c, 300c, 301c] | Ok [100, 300c, 300c, 301c] | the reference |
| dist | `dist_equal_three_change_outputs_with_a_remainder` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 901 | the reference |
| dist | `dist_equal_change_outputs_among_payments` | fee | Ok [425c, 100, 425c] | Ok [425c, 100, 425c] | the reference |
| dist | `dist_equal_change_outputs_among_payments` | getFee | Err: Output 0 amount must be ... 21e14 | Ok 900 | the reference |
| dist | `dist_equal_change_below_the_count` | fee | Ok [100, 0c, 0c, 2c] | Ok [100, 0c, 0c, 2c] | the reference |
| dist | `dist_equal_change_below_the_count` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 2 | the reference |
| dist | `dist_random_one_change_output` | fee | Ok [100, 900c] | Ok [100, 900c] | the reference |
| dist | `dist_random_one_change_output` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 900 | the reference |
| dist | `dist_random_no_change_output` | fee | Ok [100] | Ok [100] | the reference |
| dist | `dist_random_no_change_output` | getFee | Ok 900 | Ok 900 | the reference |
| dist | `dist_random_change_zero_removes_the_change` | fee | Ok [900] | Ok [900] | the reference |
| dist | `dist_random_change_zero_removes_the_change` | getFee | Err: Output 1 amount must be ... 21e14 | Ok 100 | the reference |

## (e), no fee model given: stated

The reference's default is `LivePolicy.getInstance()` (`Transaction.ts:772`): an HTTP fetch of ARC GorillaPool's policy, 100 sat/kB on any failure (`LivePolicy.ts:10,46-99`). `fee(None, ..)` here is one satoshi per byte of `estimate_size`. Not conformed: `fee` takes a number, not a model, so the default would be a network call from this door; ARC is deprecated with no default policy URL (#350); no caller passes `None`: `grep -nE '\.fee\(|get_fee\('` under `src/` and `examples/` finds the module's doc example alone (`src/transaction/mod.rs:39`), and the four downstreams the root `CLAUDE.md` names (`~/bsv/bsv-overlay-cloudflare`, `~/bsv/rust-message-box`, `~/bsv/bsv-middleware-cloudflare-public`, `~/bsv/rust-chaintracks`, each grepped by its path, `--include='*.rs' --exclude-dir=target`, 2026-11-12) call neither `fee` nor `get_fee`; and the reference's sat/kB model refuses an input with no unlocking script or template where `estimate_size` counts it as empty.

## (f), `get_fee` where the outputs exceed the inputs: stated

The reference answers a negative number (`:932`; `-100`, `-1`, `-2099999999999999` recorded); `get_fee` answers 0 (a `u64`). `fee` refuses the same transaction in the reference's words since this change.

## The differential

A scratch crate (`diff/src/main.rs` in the lane's out folder) built against the base copy and the tip, release, 20,000 seeded calls (xorshift, seed `0x871871871`): zero to three inputs (no source one in twenty, an index past the source one in twenty), source amounts and output amounts from a mix (absent, 21e14, 21e14 + 1, 2^53 - 1, 2^53, `u64::MAX`, near 9e14, small), zero to five outputs (one in five change, one change in ten preset), the fee `None`, a small one or an edge one, `Random` one in four (compared by the paid outputs, the change sum and count where two or more change outputs). Each call classed:

| `fee` | count |
|---|---:|
| same Ok | 3,528 |
| same Err | 1,266 |
| Err to another Err (the words: d 1,159, b-amount 1,287, c-source 541, b-fee 144, b-total 44, c 15) | 3,190 |
| Ok to Err (a) | 6,766 |
| Ok to Err (b: amount 3,364, total 838, fee 509) | 4,711 |
| Ok to Err (c) | 539 |
| Ok to another Ok | 0 |
| Err to Ok | 0 |

| `get_fee` | count |
|---|---:|
| same Ok | 7,020 |
| same Err | 1,304 |
| Err to another Err (b-amount 1,214, d 1,204, c-source 563, c 147, b-total 44) | 3,172 |
| Ok to Err (c) | 4,644 |
| Ok to Err (b: amount 3,118, total 742) | 3,860 |
| Ok to another Ok | 0 |
| Err to Ok | 0 |

The well-funded, well-formed class (every input's source output present with an amount at most 21e14, every total and the fee at most 21e14, every non-change output with an amount, the inputs paying the outputs and the fee): 3,528 calls, every one the same `Ok` from `fee`, SHA-256 over their answers `014ca3e13bf433d9c460ea41476231dcfd854676ab50d04d4ea56a9e256c0219` on both sides. `get_fee` on that class: 2,488 same `Ok`, the rest change outputs (`fee` does not read them, `get_fee` does): 1,021 not computed yet (c), 15 preset past 21e14 and 3 totals past it through them (b), one an `Err` in other words.

## RED and plants

On a scratch copy of `8e78516f` with the test and vector added, its own target: 9 of 10 RED, each by its message (the census green). Ten plants on a scratch copy of the tip (one dir, one target, one plant at a time), each RED by a named test of `transaction_fee_refusals_871.rs`:

| Plant | RED |
|---|---|
| the fee's 21e14 check removed | `an_amount_or_a_total_past_21e14_is_refused_871`, `of_two_refusals_..._871`, `an_amount_at_u64_max_..._871` |
| the insufficiency check removed (saturating) | `inputs_that_cannot_pay_..._871`, the (e) and (f) tests |
| an output's absent amount read as 0 | `an_output_with_no_amount_is_refused_871`, `of_two_refusals_..._871` |
| a missing source output named in the missing-source sentence | `a_source_output_that_does_not_exist_is_refused_871`, `of_two_refusals_..._871` |
| a source amount unchecked (`unwrap_or(0)`) | the (b), (c), order and `u64::MAX` tests |
| a total bounded at `u64` only | the (b) and order tests |
| `get_fee` skipping change outputs | the (a), (b), (c) and distribution tests |
| order: the fee checked after the inputs and outputs | `of_two_refusals_..._871`, `an_amount_at_u64_max_..._871` |
| order: the outputs checked before the inputs | `of_two_refusals_..._871` |
| order: a source total before its amount | the (b), order and `u64::MAX` tests |

## Tests changed

`tests/transaction_identity_843.rs`: the property funds its `fee` step with a shortfall input before the call (a fixed txid, no draw, so the seed's sequence is unchanged), and `fee_writes_the_change_through_the_doors_after_the_caches_are_full_843`'s no-change cell asks a fee of 19,000 (the inputs less the payment) where it asked 50,000 over 20,000. `tests/transaction_fee_random_change_868.rs`: the three `u64` cells name the amount, refused ahead of its total. Both asserted the saturation or the `u64` bound this change removes.

## Found, not changed

`Transaction::add_output` refuses a non-change output with no amount, as the reference's `addOutput` does, but not an amount past 21e14, which the reference's refuses (`satoshis must be a non-negative safe integer no greater than 21e14.`, `Transaction.ts:722-730`). Outside #871's table; a sibling door for the captain.
