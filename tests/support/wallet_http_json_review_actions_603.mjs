// The #603 witnesses of `src/wallet/substrates/http_json/review_actions.rs`:
// the accepting edges of a wallet's code-5 body, as the reference's
// HTTPWalletJSON reads it (`ts-stack@edf6e03`
// `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:126-130`, `:156-170`,
// `:204-242`; `WalletResultValidation.ts:211-214`, `:971-976`, `:1013-1031`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   W=$TMPDIR/kill-review-actions
//   git -C <ts-stack> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wallet_http_json_review_actions_603.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_http_json_review_actions_603.json
//
// As `wallet_http_json_review_actions_339.mjs` does, it serves each body at
// its status to the reference's client through a fetch that answers it and
// records the outcome: the `WERR_REVIEW_ACTIONS` with its five members
// (`review`) or the words thrown (`error`). The large lists are written as
// markers both sides expand alike (`expand`):
//   "@sendwith:N"   the txids T(0) .. T(N-1)
//   "@sends:N"      the send results T(0) .. T(N-2) then A, each `failed`
//   "@reviews:N"    the review results T(0) .. T(N-2) then A, each `success`
//   "@change:X:N"   the outpoints X.0 .. X.(N-1), X the competing txid
// with T(i) = i + 1 as 64 hex digits, zero padded, and A = 'aa' x 32.
// In an outcome every array longer than four entries is recorded as
// `{ length, head, tail }` (its leading two and trailing two entries).
// The competing transaction and its BEEF are #327's
// (`identity_revocation_checks_327.json`), `$BEEF` in a body.

import { readFileSync, writeFileSync } from 'node:fs'

const [sdkPath, outPath] = process.argv.slice(2)
const { HTTPWalletJSON, Utils } = await import(sdkPath)
const competing = JSON.parse(
  readFileSync(new URL('../vectors/identity_revocation_checks_327.json', import.meta.url))
).competing

const C = competing.txid
const BEEF = Utils.toArray(competing.beef, 'hex')
const A = 'aa'.repeat(32)
const B = 'bb'.repeat(32)
const WORDS = 'Undelayed createAction or signAction results require review.'
const T = (i) => (i + 1).toString(16).padStart(64, '0')

const expand = (value) => {
  if (typeof value === 'string') {
    let m
    if ((m = /^@sendwith:(\d+)$/.exec(value))) {
      return Array.from({ length: Number(m[1]) }, (_, i) => T(i))
    }
    if ((m = /^@sends:(\d+)$/.exec(value))) {
      const n = Number(m[1])
      return [...Array.from({ length: n - 1 }, (_, i) => T(i)), A]
        .map((txid) => ({ txid, status: 'failed' }))
    }
    if ((m = /^@reviews:(\d+)$/.exec(value))) {
      const n = Number(m[1])
      return [...Array.from({ length: n - 1 }, (_, i) => T(i)), A]
        .map((txid) => ({ txid, status: 'success' }))
    }
    if ((m = /^@change:X:(\d+)$/.exec(value))) {
      return Array.from({ length: Number(m[1]) }, (_, i) => `${C}.${i}`)
    }
    if (value === '$BEEF') return BEEF
    return value
  }
  if (Array.isArray(value)) return value.map(expand)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, expand(v)]))
  }
  return value
}

const project = (value) => {
  if (Array.isArray(value)) {
    const items = value.map(project)
    return items.length > 4
      ? { length: items.length, head: items.slice(0, 2), tail: items.slice(-2) }
      : items
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, project(v)]))
  }
  return value
}

const sign = (options) => ({
  reference: 'UlJSUlJSUlI=',
  spends: { 0: { unlockingScript: '51' } },
  ...(options === undefined ? {} : { options })
})
const create = (options) => ({
  description: 'review the action',
  outputs: [{ lockingScript: '51', satoshis: 1, outputDescription: 'an output' }],
  options
})
const envelope = (members) => ({
  isError: true, code: 5, name: 'WERR_REVIEW_ACTIONS', message: WORDS, ...members
})
// A request whose sendWith carries 1000 txids: a signAction's is refused at
// 999 (`validationHelpers.ts:871-874`), and so is a createAction's that builds
// a transaction (`:792-799`); a createAction with no input and no output
// builds none (`isNewTx` false) and admits 1000, its result a txid besides.
const R = { description: 'review the action', options: { sendWith: '@sendwith:1000' } }

const cases = [
  // A: 1001 send results read, 1002 refused before any entry
  ['send_with_results_1001', 'createAction', R, 400, envelope({
    txid: A, sendWithResults: '@sends:1001',
    reviewActionResults: [{ txid: A, status: 'success' }]
  })],
  ['send_with_results_1002', 'createAction', R, 400, envelope({
    txid: A, sendWithResults: '@sends:1002',
    reviewActionResults: [{ txid: A, status: 'success' }]
  })],
  // B: 1001 review results read, 1002 refused before any entry
  ['review_results_1001', 'createAction', R, 400, envelope({
    txid: A, sendWithResults: [{ txid: A, status: 'failed' }],
    reviewActionResults: '@reviews:1001'
  })],
  ['review_results_1002', 'createAction', R, 400, envelope({
    txid: A, sendWithResults: [{ txid: A, status: 'failed' }],
    reviewActionResults: '@reviews:1002'
  })],
  // C: a send result `unproven` (`WalletResultValidation.ts:211-214`, BRC-100 `0100.md:1726`)
  ['send_with_unproven', 'signAction', sign({ sendWith: [B] }), 400, envelope({
    txid: A,
    sendWithResults: [{ txid: B, status: 'unproven' }, { txid: A, status: 'sending' }],
    reviewActionResults: [
      { txid: A, status: 'doubleSpend', competingTxs: [C], competingBeef: '$BEEF' },
      { txid: B, status: 'serviceError' }
    ]
  })],
  // D: 100000 change outpoints read, 100001 refused
  ['no_send_change_100000', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, noSendChange: '@change:X:100000', sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  ['no_send_change_100001', 'createAction', create({ noSend: true }), 400, envelope({
    txid: C, noSendChange: '@change:X:100001', sendWithResults: [],
    reviewActionResults: [{ txid: C, status: 'success' }]
  })],
  // E: a competing txid of 64 non-hex characters, or of short hex
  ['competing_txid_64_non_hex', 'signAction', sign(), 400, envelope({
    txid: A, sendWithResults: [{ txid: A, status: 'failed' }],
    reviewActionResults: [{ txid: A, status: 'doubleSpend', competingTxs: ['zz'.repeat(32)] }]
  })],
  ['competing_txid_short_hex', 'signAction', sign(), 400, envelope({
    txid: A, sendWithResults: [{ txid: A, status: 'failed' }],
    reviewActionResults: [{ txid: A, status: 'doubleSpend', competingTxs: ['ab'] }]
  })]
]

const hex = (bytes) => Utils.toHex(Array.from(bytes))

const out = []
for (const [name, call, args, status, body] of cases) {
  const text = JSON.stringify(expand(body))
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
    const r = await wallet[call](expand(args))
    outcome = { answered: { txid: r.txid ?? null, tx: r.tx === undefined ? null : hex(r.tx) } }
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
  out.push({ name, call, args, status, body, reference: project(outcome) })
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, cases: out }, null, 2) + '\n')
for (const c of out) console.log(c.name, JSON.stringify(c.reference).slice(0, 160))
