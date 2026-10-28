// The #365 witnesses: every byte field of a wallet's 200 answer as the
// reference's HTTPWalletJSON reads it (`ts-stack@edf6e03`
// `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:322-341`): the body
// through `normalizeBRC100WalletByteFields` (`BRC100ByteEncoding.ts:5-23`,
// `:164-190`), then `validateWalletResult` (`WalletResultValidation.ts`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C <ts-stack> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/http_json_success_bytes_365.mjs \
//     "$W/sdk.mjs" tests/vectors/http_json_success_bytes_365.json
//
// For each byte field of each call's answer, the field written in seven
// forms (`FORMS`): the array of byte numbers, the historical object form
// `JSON.stringify(new Uint8Array(..))` wrote (`{"0": .., "1": ..}`), every
// byte an integral float (`1.0`), and the array or the object form with its
// first byte `256`, `-1` or `1.5`; ciphertext also with its first byte the
// integer text `-0` in the object form. The body's text is recorded as
// served (`bodyText`), so `1.0` and `-0` cross as written; the outcome is
// the field's bytes as hex (`answered`) or the words thrown (`error`). The
// BEEF and the action requests are #339's (#327's competing transaction).

import { readFileSync, writeFileSync } from 'node:fs'

const [sdkPath, outPath] = process.argv.slice(2)
const { HTTPWalletJSON, PrivateKey, Transaction, Utils } = await import(sdkPath)
const competing = JSON.parse(
  readFileSync(new URL('../vectors/identity_revocation_checks_327.json', import.meta.url))
).competing

const C = competing.txid
const BEEF = Utils.toArray(competing.beef, 'hex')
const competingTx = Transaction.fromBEEF(BEEF, C)
const createCompeting = (options) => ({
  description: 'review the action',
  outputs: competingTx.outputs.map((o) => ({
    lockingScript: o.lockingScript.toHex(), satoshis: o.satoshis, outputDescription: 'an output'
  })),
  ...(competingTx.version === 1 ? {} : { version: competingTx.version }),
  ...(competingTx.lockTime === 0 ? {} : { lockTime: competingTx.lockTime }),
  options
})
const signCompeting = {
  reference: 'UlJSUlJSUlI=',
  spends: { 0: { unlockingScript: competingTx.inputs[0].unlockingScript.toHex() } }
}

const key = (n) => new PrivateKey(n).toPublicKey().toString()
const PROVER = key(1)
const VERIFIER = key(2)
const COUNTERPARTY = key(3)
const PROTOCOL = [2, 'tests three six five']
const CIPHERTEXT = [0, 1, 2, 127, 128, 254, 255]
const HMAC = Array.from({ length: 32 }, (_, i) => i * 8)
const SIGNATURE = new PrivateKey(1).sign([1, 2, 3]).toDER()
const LINKAGE = [9, 8, 7, 6]
const PROOF = [0, 5, 10]

const counterpartyLinkage = (members) => ({
  prover: PROVER, verifier: VERIFIER, counterparty: COUNTERPARTY,
  revelationTime: '2026-10-28T00:00:00.000Z',
  encryptedLinkage: LINKAGE, encryptedLinkageProof: PROOF, ...members
})
const specificLinkage = (members) => ({
  prover: PROVER, verifier: VERIFIER, counterparty: COUNTERPARTY,
  protocolID: PROTOCOL, keyID: '1', proofType: 0,
  encryptedLinkage: LINKAGE, encryptedLinkageProof: PROOF, ...members
})

// [call, args, field path, its bytes, the body with the field at `$BYTES`]
const fields = [
  ['encrypt', { plaintext: [1, 2, 3], protocolID: PROTOCOL, keyID: '1' },
    'ciphertext', CIPHERTEXT, { ciphertext: '$BYTES' }],
  ['decrypt', { ciphertext: [1, 2, 3], protocolID: PROTOCOL, keyID: '1' },
    'plaintext', CIPHERTEXT, { plaintext: '$BYTES' }],
  ['createHmac', { data: [1, 2, 3], protocolID: PROTOCOL, keyID: '1' },
    'hmac', HMAC, { hmac: '$BYTES' }],
  ['createSignature', { data: [1, 2, 3], protocolID: PROTOCOL, keyID: '1' },
    'signature', SIGNATURE, { signature: '$BYTES' }],
  ['revealCounterpartyKeyLinkage', { counterparty: COUNTERPARTY, verifier: VERIFIER },
    'encryptedLinkage', LINKAGE, counterpartyLinkage({ encryptedLinkage: '$BYTES' })],
  ['revealCounterpartyKeyLinkage', { counterparty: COUNTERPARTY, verifier: VERIFIER },
    'encryptedLinkageProof', PROOF, counterpartyLinkage({ encryptedLinkageProof: '$BYTES' })],
  ['revealSpecificKeyLinkage',
    { counterparty: COUNTERPARTY, verifier: VERIFIER, protocolID: PROTOCOL, keyID: '1' },
    'encryptedLinkage', LINKAGE, specificLinkage({ encryptedLinkage: '$BYTES' })],
  ['revealSpecificKeyLinkage',
    { counterparty: COUNTERPARTY, verifier: VERIFIER, protocolID: PROTOCOL, keyID: '1' },
    'encryptedLinkageProof', PROOF, specificLinkage({ encryptedLinkageProof: '$BYTES' })],
  ['listOutputs', { basket: 'a basket' },
    'BEEF', BEEF, { totalOutputs: 0, outputs: [], BEEF: '$BYTES' }],
  ['createAction', createCompeting({ noSend: true }),
    'tx', BEEF, { txid: C, tx: '$BYTES', noSendChange: [`${C}.0`] }],
  ['createAction', createCompeting({ signAndProcess: false }),
    'signableTransaction.tx', BEEF,
    { signableTransaction: { tx: '$BYTES', reference: 'UlJSUlJSUlI=' } }],
  ['signAction', signCompeting, 'tx', BEEF, { txid: C, tx: '$BYTES' }]
]

const arrayText = (items) => `[${items.join(',')}]`
const objectText = (items) => `{${items.map((b, i) => `"${i}":${b}`).join(',')}}`
const first = (bytes, text) => [text, ...bytes.slice(1).map(String)]
const FORMS = [
  ['array', (b) => arrayText(b.map(String))],
  ['object', (b) => objectText(b.map(String))],
  ['integral_floats', (b) => arrayText(b.map((n) => `${n}.0`))],
  ['array_256', (b) => arrayText(first(b, '256'))],
  ['array_minus_1', (b) => arrayText(first(b, '-1'))],
  ['array_1_5', (b) => arrayText(first(b, '1.5'))],
  ['object_256', (b) => objectText(first(b, '256'))],
  ['object_minus_1', (b) => objectText(first(b, '-1'))],
  ['object_1_5', (b) => objectText(first(b, '1.5'))]
]
// the integer text `-0`, which `Number.isInteger` reads as a byte
const NEGATIVE_ZERO = ['object_minus_0', (b) => objectText(first(b, '-0'))]

const hex = (bytes) => Utils.toHex(Array.from(bytes, (n) => n))
const at = (value, path) => path.split('.').reduce((v, k) => v?.[k], value)

const out = []
for (const [call, args, field, bytes, body] of fields) {
  const forms = field === 'ciphertext' ? [...FORMS, NEGATIVE_ZERO] : FORMS
  for (const [form, write] of forms) {
    const bodyText = JSON.stringify(body).replace('"$BYTES"', write(bytes))
    const fetch = async () => {
      const encoded = new TextEncoder().encode(bodyText)
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: null,
        arrayBuffer: async () => encoded.buffer
      }
    }
    const wallet = new HTTPWalletJSON('example.com', 'http://localhost:3321', fetch)
    let reference
    try {
      const result = await wallet[call](structuredClone(args))
      const value = at(result, field)
      reference = { answered: value === undefined ? null : hex(value) }
    } catch (e) {
      reference = { error: e.message }
    }
    const name = `${call}_${field.replace('.', '_')}_${form}`
    out.push({ name, call, args, field, form, bodyText, reference })
  }
}
writeFileSync(
  outPath,
  JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, cases: out }, null, 2) + '\n'
)
for (const c of out) console.log(c.name, JSON.stringify(c.reference).slice(0, 120))
