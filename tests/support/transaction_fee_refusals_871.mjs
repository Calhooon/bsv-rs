// #871 recorder: the reference's `Transaction.fee` and `getFee` on the cells
// at each side of the fee door's edges (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/Transaction.ts:65-86`, `:770-830`,
// `:832-862`, `:899-933`): inputs that cannot pay, an amount or a total at
// and past 21e14, an output with no amount, a source output that does not
// exist, the order of two refusals, no fee model given, the change
// distributions. Only the unmodified SDK supplies the answers. Build the
// bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/transaction_fee_refusals_871.mjs \
//     "$W/sdk.mjs" tests/vectors/transaction_fee_refusals_871.json
//
// No fee model given (row (e)): the reference's default is
// `LivePolicy.getInstance()`, which fetches a policy over HTTP. This
// recorder replaces `globalThis.fetch` BEFORE the bundle loads with a
// function that refuses without a request, so no host is asked and the
// default answers its offline fallback, 100 satoshis per kilobyte
// (`LivePolicy.ts:91-99`); the URL it would have asked is recorded.
//
// A cell names each input by its source's output amounts (`null` an output
// with no amount; `source: null` an input with no source transaction) and
// the index it spends, each output by its amount (`null` none) and its
// change flag, the fee (`null` for no fee model given) and the distribution.
// Every input carries the unlocking script `51` (the default model reads its
// length). The Rust test builds each cell with this crate's own types.
import { writeFileSync } from 'node:fs'

const asked = []
globalThis.fetch = async (url) => {
  asked.push(String(url))
  throw new Error('no network in the #871 recorder')
}

const [, , bundle, out] = process.argv
const { Transaction, LockingScript, UnlockingScript } = await import(bundle)

const M = 2100000000000000 // 21e14
const SAFE = 9007199254740991 // 2^53 - 1
const P53 = 9007199254740992 // 2^53

const i = (amounts, index = 0) => ({ source: amounts, index })
const noSource = { source: null, index: 0 }
const o = (satoshis) => ({ satoshis, change: false })
const chg = (satoshis = null) => ({ satoshis, change: true })
const cell = (name, row, inputs, outputs, fee, distribution = 'equal') => ({
  name, row, inputs, outputs, fee, distribution
})

const CELLS = [
  // (a) inputs that cannot pay.
  cell('a_inputs_cannot_pay_the_outputs_alone', 'a', [i([1000])], [o(1001), chg()], 0),
  cell('a_inputs_cannot_pay_the_outputs_and_the_fee', 'a', [i([1000])], [o(950), chg()], 100),
  cell('a_one_satoshi_short', 'a', [i([1000])], [o(901), chg()], 100),
  cell('a_exactly_the_outputs_and_the_fee', 'a', [i([1000])], [o(900), chg()], 100),
  cell('a_one_satoshi_over', 'a', [i([1000])], [o(899), chg()], 100),
  cell('a_short_with_no_change_output', 'a', [i([1000])], [o(950)], 100),
  cell('a_surplus_with_no_change_output', 'a', [i([1000])], [o(500)], 100),
  cell('a_no_input_and_an_output', 'a', [], [o(1)], 0),
  cell('a_no_input_and_no_output', 'a', [], [], 0),
  cell('a_no_input_and_a_fee', 'a', [], [], 1),
  cell('a_outputs_above_the_inputs_with_no_fee', 'a', [i([100])], [o(200)], 0),
  cell('a_short_under_the_random_distribution', 'a', [i([1000])], [o(950), chg()], 100, 'random'),
  // (b) an amount and a total at 21e14, past it, at 2^53 - 1, at 2^53.
  cell('b_input_amount_at_21e14', 'b', [i([M])], [o(M - 100), chg()], 100),
  cell('b_input_amount_past_21e14', 'b', [i([M + 1])], [o(1)], 0),
  cell('b_input_amount_at_2p53_minus_1', 'b', [i([SAFE])], [o(1)], 0),
  cell('b_input_amount_at_2p53', 'b', [i([P53])], [o(1)], 0),
  cell('b_input_total_at_21e14', 'b', [i([1e15]), i([11e14])], [o(1), chg()], 0),
  cell('b_input_total_past_21e14', 'b', [i([1e15]), i([11e14 + 1])], [o(1)], 0),
  cell('b_input_total_past_2p53', 'b', [i([M]), i([M]), i([M]), i([M]), i([M])], [o(1)], 0),
  cell('b_output_amount_at_21e14', 'b', [i([M])], [o(M)], 0),
  cell('b_output_amount_past_21e14', 'b', [i([M])], [o(M + 1)], 0),
  cell('b_output_amount_at_2p53_minus_1', 'b', [i([M])], [o(SAFE)], 0),
  cell('b_output_amount_at_2p53', 'b', [i([M])], [o(P53)], 0),
  cell('b_output_total_at_21e14', 'b', [i([M])], [o(1e15), o(11e14)], 0),
  cell('b_output_total_past_21e14', 'b', [i([M])], [o(1e15), o(11e14 + 1)], 0),
  cell('b_output_total_past_2p53', 'b', [i([M])], [o(M), o(M), o(M), o(M), o(M)], 0),
  cell('b_fee_at_21e14', 'b', [i([M])], [], M),
  cell('b_fee_past_21e14', 'b', [i([M])], [], M + 1),
  cell('b_fee_at_2p53', 'b', [i([M])], [], P53),
  cell('b_change_output_holding_an_amount_past_21e14', 'b', [i([1000])], [o(100), chg(M + 1)], 0),
  // (c) an output with no amount.
  cell('c_no_amount_at_output_0_of_3', 'c', [i([1000])], [o(null), o(10), o(10)], 0),
  cell('c_no_amount_at_output_1_of_3', 'c', [i([1000])], [o(10), o(null), o(10)], 0),
  cell('c_no_amount_at_output_2_of_3', 'c', [i([1000])], [o(10), o(10), o(null)], 0),
  cell('c_source_output_with_no_amount', 'c', [i([null])], [o(1)], 0),
  cell('c_change_output_with_no_amount', 'c', [i([1000])], [o(10), chg()], 0),
  // (d) a source output that does not exist.
  cell('d_index_one_past_the_source_outputs', 'd', [i([1000], 1)], [o(1)], 0),
  cell('d_index_far_past_the_source_outputs', 'd', [i([1000, 1000], 7)], [o(1)], 0),
  cell('d_source_with_no_outputs', 'd', [i([])], [o(1)], 0),
  cell('d_second_input_past_its_source', 'd', [i([1000]), i([1000], 1)], [o(1)], 0),
  cell('d_no_source_transaction', 'd', [noSource], [o(1)], 0),
  // The order of two refusals.
  cell('order_fee_past_21e14_before_a_missing_source_output', 'order', [i([])], [o(1)], M + 1),
  cell('order_fee_past_21e14_before_no_source_transaction', 'order', [noSource], [o(1)], M + 1),
  cell('order_input_amount_before_a_later_missing_output', 'order', [i([M + 1]), i([], 0)], [o(1)], 0),
  cell('order_missing_output_before_a_later_input_amount', 'order', [i([]), i([M + 1])], [o(1)], 0),
  cell('order_no_source_before_a_later_missing_output', 'order', [noSource, i([])], [o(1)], 0),
  cell('order_missing_output_before_a_later_no_source', 'order', [i([]), noSource], [o(1)], 0),
  cell('order_input_total_before_an_output_with_no_amount', 'order', [i([1e15]), i([11e14 + 1])], [o(null)], 0),
  cell('order_input_amount_before_an_output_amount', 'order', [i([M + 1])], [o(M + 1)], 0),
  cell('order_output_with_no_amount_before_insufficient', 'order', [i([10])], [o(null), o(100)], 0),
  cell('order_output_amount_before_a_later_output_with_no_amount', 'order', [i([M])], [o(M + 1), o(null)], 0),
  cell('order_output_with_no_amount_before_a_later_output_amount', 'order', [i([M])], [o(null), o(M + 1)], 0),
  cell('order_output_total_before_a_later_output_with_no_amount', 'order', [i([M])], [o(1e15), o(11e14 + 1), o(null)], 0),
  cell('order_output_total_before_insufficient', 'order', [i([10])], [o(1e15), o(11e14 + 1)], 0),
  // (e) no fee model given.
  cell('e_default_one_input_one_change', 'e', [i([10000])], [o(1000), chg()], null),
  cell('e_default_two_inputs_three_outputs', 'e', [i([5000]), i([7000, 3000], 1)], [o(1000), o(2000), chg()], null),
  cell('e_default_short', 'e', [i([95])], [o(90), chg()], null),
  // (f) getFee where the outputs exceed the inputs: every cell records it;
  // these two are its own.
  cell('f_outputs_exceed_the_inputs_by_one', 'f', [i([1000])], [o(1001)], 0),
  cell('f_outputs_exceed_the_inputs_by_a_large_amount', 'f', [i([1])], [o(M)], 0),
  // The distributions the crate's enum has, on a funded transaction.
  cell('dist_equal_one_change_output', 'dist', [i([1000])], [o(100), chg()], 0),
  cell('dist_equal_three_change_outputs_with_a_remainder', 'dist', [i([1001])], [o(100), chg(), chg(), chg()], 0),
  cell('dist_equal_change_outputs_among_payments', 'dist', [i([1000])], [chg(), o(100), chg()], 50),
  cell('dist_equal_change_below_the_count', 'dist', [i([102])], [o(100), chg(), chg(), chg()], 0),
  cell('dist_random_one_change_output', 'dist', [i([1000])], [o(100), chg()], 0, 'random'),
  cell('dist_random_no_change_output', 'dist', [i([1000])], [o(100)], 0, 'random'),
  cell('dist_random_change_zero_removes_the_change', 'dist', [i([1000])], [o(900), chg()], 100, 'random')
]

function build (c) {
  const inputs = c.inputs.map(({ source, index }) => ({
    sourceTransaction: source === null
      ? undefined
      : new Transaction(1, [], source.map(satoshis => ({
        satoshis: satoshis === null ? undefined : satoshis,
        lockingScript: LockingScript.fromHex('51')
      })), 0),
    sourceTXID: source === null ? 'aa'.repeat(32) : undefined,
    sourceOutputIndex: index,
    unlockingScript: UnlockingScript.fromHex('51'),
    sequence: 0xffffffff
  }))
  const outputs = c.outputs.map(({ satoshis, change }) => {
    const output = { lockingScript: LockingScript.fromHex('51') }
    if (satoshis !== null) output.satoshis = satoshis
    if (change) output.change = true
    return output
  })
  // The constructor, not addOutput: addOutput refuses an output with no
  // amount and an amount past 21e14 before fee reads it.
  return new Transaction(1, inputs, outputs, 0)
}

const answers = []
for (const c of CELLS) {
  let getFee
  try {
    getFee = { ok: build(c).getFee() }
  } catch (e) {
    getFee = { err: e.message }
  }
  const tx = build(c)
  let fee
  try {
    if (c.fee === null) await tx.fee(undefined, c.distribution)
    else await tx.fee(c.fee, c.distribution)
    fee = {
      ok: tx.outputs.map(out => ({
        satoshis: out.satoshis === undefined ? null : out.satoshis,
        change: out.change === true
      }))
    }
  } catch (e) {
    fee = { err: e.message }
  }
  answers.push({ ...c, get_fee_answer: getFee, fee_answer: fee })
}

const vector = {
  issue: 871,
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/Transaction.ts',
  node: process.version,
  default_fee_model: {
    note: 'fetch replaced before the bundle loaded: no request made; LivePolicy fell back to 100 sat/kB',
    asked: [...new Set(asked)]
  },
  cells: answers
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
console.log(`${answers.length} cells`)
