// The #339 witnesses: a wallet's code-5 bodies as the reference's
// HTTPWalletJSON reads them (`ts-stack@edf6e03`
// `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:117-241`, `:330-341`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C <ts-stack> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wallet_http_json_review_actions_339.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_http_json_review_actions_339.json
//
// For each case it serves the body at the status to the reference's client
// through a fetch that answers it, after the call made with the case's
// args, and records the outcome: the `WERR_REVIEW_ACTIONS` with its five
// members (`review`; bytes as hex) or the words of what it threw
// (`error`). The competing transaction and its BEEF are #327's
// (`identity_revocation_checks_327.json`); a body holds the BEEF as
// `$BEEF`, an outcome as hex.

import { readFileSync, writeFileSync } from 'node:fs'

const [sdkPath, outPath] = process.argv.slice(2)
const { HTTPWalletJSON, Transaction, Utils } = await import(sdkPath)
const competing = JSON.parse(
  readFileSync(new URL('../vectors/identity_revocation_checks_327.json', import.meta.url))
).competing

const C = competing.txid
const BEEF = Utils.toArray(competing.beef, 'hex')
const A = 'aa'.repeat(32)
const B = 'bb'.repeat(32)
const WORDS = 'Undelayed createAction or signAction results require review.'

const sign = (options) => ({
  reference: 'UlJSUlJSUlI=',
  spends: { 0: { unlockingScript: '51' } },
  ...(options === undefined ? {} : { options })
})
const create = (options, outputs = true) => ({
  description: 'review the action',
  ...(outputs ? { outputs: [{ lockingScript: '51', satoshis: 1, outputDescription: 'an output' }] } : {}),
  ...(options === undefined ? {} : { options })
})
const envelope = (members) => ({
  isError: true, code: 5, name: 'WERR_REVIEW_ACTIONS', message: WORDS, ...members
})
const signBody = (members) => envelope({
  txid: A,
  sendWithResults: [{ txid: A, status: 'failed' }],
  reviewActionResults: [{ txid: A, status: 'doubleSpend', competingTxs: [C], competingBeef: BEEF }],
  ...members
})
// The createAction the competing transaction answers: its outputs, version
// and lock time (`validateCreateActionTransaction`, `WalletResultValidation.ts`)
const competingTx = Transaction.fromBEEF(BEEF, C)
const createCompeting = {
  description: 'review the action',
  outputs: competingTx.outputs.map((o) => ({
    lockingScript: o.lockingScript.toHex(), satoshis: o.satoshis, outputDescription: 'an output'
  })),
  ...(competingTx.version === 1 ? {} : { version: competingTx.version }),
  ...(competingTx.lockTime === 0 ? {} : { lockTime: competingTx.lockTime }),
  options: { noSend: true }
}
const result = (members) => ({ txid: A, status: 'doubleSpend', ...members })

const cases = [
  ['sign_double_spend', 'signAction', sign({ sendWith: [B] }), 400, signBody({
    sendWithResults: [{ txid: B, status: 'failed' }, { txid: A, status: 'sending' }],
    reviewActionResults: [
      result({ competingTxs: [C], competingBeef: BEEF }),
      { txid: B, status: 'serviceError' }
    ]
  })],
  ['create_txid_and_change', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, noSendChange: [`${C}.1`], sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['create_five_members', 'createAction', createCompeting, 400, envelope({
    txid: C, tx: BEEF, noSendChange: [`${C}.0`], sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'invalidTx' }]
  })],
  ['create_tx_outputs_not_requested', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, tx: BEEF, sendWithResults: [], reviewActionResults: [{ txid: C, status: 'invalidTx' }]
  })],
  ['envelope_is_error_not_true', 'signAction', sign(), 400, signBody({ isError: 'yes' })],
  ['message_over_4096_bytes', 'signAction', sign(), 400, signBody({ message: 'x'.repeat(4097) })],
  ['send_with_results_absent', 'signAction', sign(), 400, signBody({ sendWithResults: undefined })],
  ['review_results_not_an_array', 'signAction', sign(), 400, signBody({ reviewActionResults: {} })],
  ['review_result_not_an_object', 'signAction', sign(), 400, signBody({ reviewActionResults: [7] })],
  ['review_result_txid_unknown', 'signAction', sign(), 400, signBody({
    reviewActionResults: [{ txid: B, status: 'success' }]
  })],
  ['review_result_txid_repeated', 'signAction', sign(), 400, signBody({
    reviewActionResults: [{ txid: A, status: 'success' }, { txid: A, status: 'success' }]
  })],
  ['review_result_status_unknown', 'signAction', sign(), 400, signBody({
    reviewActionResults: [{ txid: A, status: 'pending' }]
  })],
  ['competing_on_success', 'signAction', sign(), 400, signBody({
    reviewActionResults: [{ txid: A, status: 'success', competingTxs: [C] }]
  })],
  ['competing_txs_not_hex', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingTxs: ['zz'] })]
  })],
  ['competing_txs_the_reviewed', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingTxs: [A] })]
  })],
  ['competing_txs_repeated', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingTxs: [C, C] })]
  })],
  ['competing_beef_without_txs', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingBeef: BEEF })]
  })],
  ['competing_beef_without_the_txid', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingTxs: [B], competingBeef: BEEF })]
  })],
  ['competing_beef_not_a_beef', 'signAction', sign(), 400, signBody({
    reviewActionResults: [result({ competingTxs: [C], competingBeef: [1, 2, 3] })]
  })],
  ['sign_txid_absent', 'signAction', sign(), 400, signBody({
    txid: undefined, sendWithResults: []
  })],
  ['sign_txid_31_bytes', 'signAction', sign(), 400, signBody({ txid: 'aa'.repeat(31) })],
  ['sign_txid_odd_length', 'signAction', sign(), 400, signBody({ txid: 'abc' })],
  ['sign_no_send_change', 'signAction', sign(), 400, signBody({ noSendChange: [`${A}.0`] })],
  ['no_send_change_not_canonical', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, noSendChange: [`${C}.01`], sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['no_send_change_of_another_tx', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, noSendChange: [`${A}.0`], sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['send_with_status_unknown', 'signAction', sign(), 400, signBody({
    sendWithResults: [{ txid: A, status: 'done' }]
  })],
  ['send_with_txid_unknown', 'signAction', sign(), 400, signBody({
    sendWithResults: [{ txid: B, status: 'failed' }]
  })],
  ['send_with_txid_repeated', 'signAction', sign(), 400, signBody({
    sendWithResults: [{ txid: A, status: 'failed' }, { txid: A, status: 'sending' }]
  })],
  ['create_deferred_signing', 'createAction', create({ signAndProcess: false }), 400, envelope({
    txid: C, sendWithResults: [], reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['create_txid_absent', 'createAction', create(), 400, envelope({
    sendWithResults: [], reviewActionResults: []
  })],
  ['create_tx_of_another_txid', 'createAction', create(), 400, envelope({
    txid: A, tx: BEEF, sendWithResults: [], reviewActionResults: [{ txid: A, status: 'success' }]
  })],
  ['create_tx_not_a_beef', 'createAction', create(), 400, envelope({
    txid: C, tx: [1, 2, 3], sendWithResults: [], reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['create_tx_without_txid', 'createAction', create({ sendWith: [B] }, false), 400, envelope({
    tx: BEEF, sendWithResults: [{ txid: B, status: 'sending' }],
    reviewActionResults: [{ txid: B, status: 'success' }]
  })],
  ['create_no_outcome', 'createAction', create({ sendWith: [B] }, false), 400, envelope({
    sendWithResults: [], reviewActionResults: [{ txid: B, status: 'success' }]
  })],
  ['another_call', 'listActions', { labels: ['a label'] }, 400, signBody({})],
  ['review_at_status_500', 'signAction', sign(), 500, signBody({})],
  ['no_results', 'signAction', sign(), 400, envelope({})]
]

const hex = (bytes) => Utils.toHex(Array.from(bytes))

const out = []
for (const [name, call, args, status, body] of cases) {
  const text = JSON.stringify(body)
  const fetch = async () => {
    const bytes = new TextEncoder().encode(text)
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => null },
      body: null,
      arrayBuffer: async () => bytes.buffer
    }
  }
  const wallet = new HTTPWalletJSON('example.com', 'http://localhost:3321', fetch)
  let outcome
  try {
    await wallet[call](structuredClone(args))
    outcome = { answered: true }
  } catch (e) {
    if (e?.name === 'WERR_REVIEW_ACTIONS') {
      outcome = {
        review: {
          message: e.message,
          reviewActionResults: e.reviewActionResults.map((r) => ({
            txid: r.txid,
            status: r.status,
            ...(r.competingTxs === undefined ? {} : { competingTxs: r.competingTxs }),
            ...(r.competingBeef === undefined ? {} : { competingBeef: hex(r.competingBeef) })
          })),
          sendWithResults: e.sendWithResults,
          txid: e.txid ?? null,
          tx: e.tx === undefined ? null : hex(e.tx),
          noSendChange: e.noSendChange ?? null
        }
      }
    } else {
      outcome = { error: e.message }
    }
  }
  // the competing BEEF written once, as `$BEEF` in a body (the reader
  // substitutes the bytes of #327's vector)
  const recorded = JSON.parse(JSON.stringify(body, (_, v) => (v === BEEF ? '$BEEF' : v)))
  out.push({ name, call, args, status, body: recorded, reference: outcome })
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', cases: out }, null, 2) + '\n')
for (const c of out) console.log(c.name, JSON.stringify(c.reference).slice(0, 140))
