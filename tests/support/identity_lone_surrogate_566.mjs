// #566: lone UTF-16 surrogate escapes in an `ls_identity` revelation token's
// certificate JSON. The reference's discovery reads the token's text with
// `JSON.parse` (`ts-stack@edf6e03`
// `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:88`,
// `certificateRecord`, under `decodeIdentityOutput`, `:497-559`), which keeps
// a lone surrogate as a lone code unit; the certificate's `toBinary`, which
// its `verify` signs over, writes a name or a value through `TextEncoder`
// (`packages/sdk/src/auth/certificates/Certificate.ts:73-75,288-295`,
// `primitives/utils.ts:197-203`, `primitives/UTF8.ts:1-5`), which writes a
// lone surrogate as U+FFFD's three bytes. Each case is a token the
// reference's own `PushDrop.lock` writes for the subject 9 (`[json]`,
// `[1, 'identity']`, key ID `1`, `anyone`, for self, signed), its JSON the
// reference's published certificate with one member carrying a lone
// surrogate escape, the certificate re-signed by the certifier 7 where a
// field changed, judged by `parseResults` (`:671-707`) with the evidence
// limits raised as #553's recorder does: `read` with the fields and the
// decrypted fields as the reference holds them, each name and value also as
// the bytes `TextEncoder` writes for it; `skipped`; or `refused`.
//
// The bundle is #553's (the SDK and the toolbox's identityUtils at edf6e03):
//   W=/Volumes/Lanes/out/bsv-rs/fix-566-lone-surrogate-identity-fields/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json and entry of tests/support/identity_certificate_record_553.mjs, entry566.ts)
//   (cd "$W" && bun build entry566.ts --target node --format esm --outfile "$W/ref566.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_lone_surrogate_566.mjs \
//     "$W/ref566.mjs" > tests/vectors/identity_lone_surrogate_566.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads,
// so two runs print the same file.
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#566 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, IdentityEvidenceVerifier, ProtoWallet, PrivateKey, PushDrop, LockingScript, Transaction, MerklePath,
  MasterCertificate, Certificate, Utils
} = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const certifier7 = new ProtoWallet(key(7))
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const IDENTITY = [1, 'identity']
const subject = key(9).toPublicKey().toString()
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }
const encoder = new TextEncoder()
const bytesOf = (text) => Utils.toHex(Array.from(encoder.encode(text)))

// A certificate the certifier 7 issues to 9 over `revealedFields` (each
// encrypted, revealed to anyone), with `plainFields` added as text and the
// whole signed again by 7 (`Certificate.sign`) after `alter` changes the
// fields, published in the member
// order publiclyRevealAttributes writes (`{...certificate, keyring}`).
const published = async (revealedFields, plainFields = {}, alter = () => {}) => {
  const issued = await MasterCertificate.issueCertificateForSubject(
    certifier7, subject, revealedFields,
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(2))
  )
  const fields = { ...issued.fields, ...plainFields }
  alter(fields)
  const certificate = new Certificate(issued.type, issued.serialNumber, subject, issued.certifier,
    issued.revocationOutpoint, fields)
  await certificate.sign(certifier7)
  const keyring = await MasterCertificate.createKeyringForVerifier(
    wallet9, issued.certifier, ANYONE, issued.fields, Object.keys(revealedFields), issued.masterKeyring,
    issued.serialNumber
  )
  return {
    type: certificate.type, subject, serialNumber: certificate.serialNumber, certifier: certificate.certifier,
    revocationOutpoint: certificate.revocationOutpoint, signature: certificate.signature, fields, keyring
  }
}

const lock = async (text) => new PushDrop(wallet9).lock([Utils.toArray(text, 'utf8')], IDENTITY, '1', 'anyone', true, true)

// A name and a value as the reference holds them (JSON text, a lone unit
// written `\udXXX`) and as `TextEncoder` writes them.
const entries = (record) => Object.entries(record).map(([name, value]) => ({
  name: JSON.stringify(name), value: JSON.stringify(value), name_bytes: bytesOf(name), value_bytes: bytesOf(value)
}))

const judged = async (lockingScript) => {
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  tx.addOutput({ satoshis: 1, lockingScript })
  tx.merklePath = new MerklePath(900, [[{ offset: 0, hash: tx.id('hex'), txid: true }]])
  const lookup = { type: 'output-list', outputs: [{ beef: tx.toBEEF(), outputIndex: 0 }] }
  const verifier = new IdentityEvidenceVerifier(tracker, 'bsv-rs#566', { scriptBytes: 1024 * 1024 })
  try {
    const read = await parseResults(lookup, tracker, verifier)
    return read.length === 1
      ? { outcome: 'read', fields: entries(read[0].fields), decrypted_fields: entries(read[0].decryptedFields) }
      : { outcome: 'skipped' }
  } catch (e) {
    return { outcome: 'refused', words: String(e.message) }
  } finally {
    verifier.dispose()
  }
}

const REVEALED = { email: 'alice@example.com' }
const base = await published(REVEALED, { name: 'QWxpY2U=' })
// The record changed after the certifier signed it (a member the certifier's
// signature does not cover, or one that makes the record no certificate)
const changed = (change) => {
  const record = structuredClone(base)
  change(record)
  return JSON.stringify(record)
}
// A lone unit in the middle of a base64 or hex member
const broken = (text) => text.slice(0, 4) + '\uD800' + text.slice(5)

const cases = []
for (const [name, check, text] of [
  ['control', 'the reference\'s own record, no surrogate', JSON.stringify(base)],
  ['field_value_high', 'an unrevealed field value ending in a lone high surrogate: TextEncoder writes U+FFFD, the signature over it',
    JSON.stringify(await published(REVEALED, { note: 'abc\uD800' }))],
  ['field_value_low', 'an unrevealed field value opening with a lone low surrogate',
    JSON.stringify(await published(REVEALED, { note: '\uDC00abc' }))],
  ['field_value_high_then_non_low', 'a high surrogate followed by a unit that is no low surrogate',
    JSON.stringify(await published(REVEALED, { note: '\uD800A' }))],
  ['field_value_reversed_pair', 'a low surrogate before a high one: two lone units',
    JSON.stringify(await published(REVEALED, { note: '\uDC00\uD800' }))],
  ['field_value_upper_case_escape', 'the escape in upper case, JSON\'s other spelling',
    JSON.stringify(await published(REVEALED, { note: 'abc\uD800' })).replace('\\ud800', '\\uD800')],
  ['field_name', 'an unrevealed field name carrying a lone surrogate',
    JSON.stringify(await published(REVEALED, { ['n\uD800']: 'dmFsdWU=' }))],
  ['revealed_field_name', 'a revealed field name carrying a lone surrogate: the keyring name matches it unit for unit and its key ID derives from TextEncoder\'s bytes',
    JSON.stringify(await published({ ['e\uD800']: 'alice@example.com' }))],
  ['keyring_value', 'a keyring value carrying a lone surrogate: not base64, the anyone decryption fails',
    changed((r) => { r.keyring.email = r.keyring.email.slice(0, 8) + '\uD800' + r.keyring.email.slice(9) })],
  ['keyring_name_not_a_field', 'a keyring name whose lone unit differs from the field\'s: no field of that name, :122-125',
    JSON.stringify(await published(REVEALED, { ['n\uD800']: 'dmFsdWU=' })).replace('"keyring":{', '"keyring":{"n\\ud801":"AAAA",')],
  ['field_names_two_lone_units', 'two field names differing only in their lone unit: one name each, the same TextEncoder bytes in the binary twice',
    JSON.stringify(await published(REVEALED, { ['n\uD800']: 'dmFsdWU=', ['n\uD801']: 'dmFsdWU=' }))],
  ['field_names_lone_and_replacement', 'a field name with a lone unit beside one with U+FFFD itself',
    JSON.stringify(await published(REVEALED, { ['n\uD800']: 'dmFsdWU=', ['n�']: 'dmFsdWU=' }))],
  ['field_names_lone_and_private_use', 'a field name with a lone unit beside one with U+E000: ICU sorts the lone unit before U+E000, U+FFFD after it',
    JSON.stringify(await published(REVEALED, { ['x\uD800']: 'dmFsdWU=', ['x']: 'dmFsdWU=' }))],
  ['member_name', 'a ninth member named by a lone surrogate, :100-105', changed((r) => { r['\uD800'] = 'x' })],
  ['type', 'type no canonical base64, Certificate.ts:233', changed((r) => { r.type = broken(r.type) })],
  ['serial_number', 'serialNumber no canonical base64, Certificate.ts:237', changed((r) => { r.serialNumber = broken(r.serialNumber) })],
  ['subject', 'subject no key, the locking key\'s counterparty, :528-533', changed((r) => { r.subject = broken(r.subject) })],
  ['certifier', 'certifier no key, Certificate.ts:240-254', changed((r) => { r.certifier = broken(r.certifier) })],
  ['revocation_outpoint', 'revocationOutpoint no 64-hex txid, Certificate.ts:260-270', changed((r) => { r.revocationOutpoint = broken(r.revocationOutpoint) })],
  ['signature', 'signature no hex, Certificate.ts:434', changed((r) => { r.signature = broken(r.signature) })],
  ['revealed_field_value', 'a revealed field value carrying a lone surrogate, signed: no canonical base64, the anyone decryption fails (VerifiableCertificate.ts:187-191)',
    JSON.stringify(await published(REVEALED, {}, (f) => { f.email = f.email.slice(0, 8) + '\uD800' + f.email.slice(9) }))]
]) {
  if (!/\\u[dD][89abAB]|\\u[dD][c-fC-F]/.test(text) && name !== 'control') throw new Error(`${name}: no surrogate escape in the text`)
  const lockingScript = await lock(text)
  cases.push({ name, check, text, locking_script: lockingScript.toHex(), ...(await judged(lockingScript)) })
}

process.stdout.write(JSON.stringify({
  description: '#566: lone UTF-16 surrogate escapes in an ls_identity revelation token\'s certificate JSON, ' +
    'with parseResults\' outcome and, where read, the fields as the reference holds them and as TextEncoder writes them',
  reference: 'ts-stack@edf6e03 packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:87-132,497-559,671-707; ' +
    'packages/sdk/src/auth/certificates/Certificate.ts:73-75,280-296; packages/sdk/src/primitives/UTF8.ts:1-5',
  node: process.version,
  recorder: 'tests/support/identity_lone_surrogate_566.mjs',
  subject,
  cases
}, null, 2) + '\n')
