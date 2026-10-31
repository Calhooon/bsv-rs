// #553: the record checks and byte bounds the reference's discovery runs on
// an `ls_identity` revelation token (`ts-stack@edf6e03`
// `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:497-559`,
// `decodeIdentityOutput`, and `certificateRecord`, `:87-132`), which the
// SDK's `IdentityClient.resolveByIdentityKey` and `resolveByAttributes`
// (`packages/sdk/src/identity/IdentityClient.ts:559-655`) reach through their
// wallet's `discoverByIdentityKey` and `discoverByAttributes` (the toolbox's
// `Wallet.ts:904-1010`, `parseResults`, `identityUtils.ts:671-707`). Each
// case is a token the reference's own `PushDrop.lock` writes for the subject
// (the scalar 9: `[json]`, `[1, 'identity']`, key ID `1`, `anyone`, for self,
// signed), its JSON the reference's published certificate changed in one
// respect, judged by `parseResults` (a count of 1: read; 0: skipped; a
// throw: the whole answer refused).
//
// The bundle is the SDK and the toolbox's identityUtils at edf6e03, the
// toolbox's `@bsv/sdk` imports resolved to the same SDK source:
//   W=<lane folder>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   cat > "$W/tsconfig.json" <<'EOF'
//   { "compilerOptions": { "baseUrl": ".", "paths": {
//     "@bsv/sdk": ["packages/sdk/mod.ts"],
//     "@bsv/sdk/primitives/utils": ["packages/sdk/src/primitives/utils.ts"]
//   } } }
//   EOF
//   cat > "$W/entry553.ts" <<'EOF'
//   export * from './packages/sdk/mod.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOF
//   (cd "$W" && bun build entry553.ts --target node --format esm --outfile "$W/ref553.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_certificate_record_553.mjs \
//     "$W/ref553.mjs" > tests/vectors/identity_certificate_record_553.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads,
// so two runs print the same file. The lookup output is a one-transaction
// block's proven transaction (its BUMP a lone leaf at offset 0), judged under
// a chain tracker that admits every root: the evidence passes, so the record
// alone decides, save the evidence layer's own script bound (below).
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#553 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, IdentityEvidenceVerifier, ProtoWallet, PrivateKey, PushDrop, LockingScript, Transaction, MerklePath,
  MasterCertificate, Certificate, IdentityClient, Utils, Hash
} = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const IDENTITY = [1, 'identity']
const subject = key(9).toPublicKey().toString()
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }

// The JSON the reference's publiclyRevealAttributes publishes for a
// certificate of `fields` issued by 7 to 9, revealing `revealed`.
const published = async (fields, revealed) => {
  const issued = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(key(7)), subject, fields,
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(2))
  )
  const certificate = {
    type: issued.type, subject: issued.subject, serialNumber: issued.serialNumber,
    certifier: issued.certifier, revocationOutpoint: issued.revocationOutpoint,
    signature: issued.signature, fields: { ...issued.fields }
  }
  const keyring = await MasterCertificate.createKeyringForVerifier(
    wallet9, issued.certifier, ANYONE, certificate.fields, revealed, issued.masterKeyring, issued.serialNumber
  )
  let token
  await new IdentityClient({
    async proveCertificate () { return { keyringForVerifier: { ...keyring } } },
    async getPublicKey (args) { return wallet9.getPublicKey(args) },
    async createSignature (args) { return wallet9.createSignature(args) },
    async createAction (args) { token = args.outputs[0].lockingScript; return {} }
  }, { networkPreset: 'mainnet' }).publiclyRevealAttributes(certificate, revealed).catch(() => {})
  return { token, text: Utils.toUTF8(PushDrop.decode(LockingScript.fromHex(token)).fields[0]) }
}

const lock = async (bytes) => new PushDrop(wallet9).lock([bytes], IDENTITY, '1', 'anyone', true, true)
const utf8 = (text) => Utils.toArray(text, 'utf8')

// `parseResults` twice: with the verifier the toolbox's wallet builds
// (`Wallet.ts:919`, the default evidence limits: a transaction whose scripts
// pass 256 KiB throws `limit` before the record is read,
// `TransactionEvidence.ts:155-172`, and the throw refuses the whole
// discovery, `identityUtils.ts:632`, `Wallet.ts:950-955`), and with the
// script bound raised to 1 MiB, so `decodeIdentityOutput` alone decides.
const judged = async (lookup, verifier) => {
  try {
    const read = await parseResults(lookup, tracker, verifier)
    return read.length === 1
      ? { outcome: 'read', decrypted_fields: Object.keys(read[0].decryptedFields) }
      : { outcome: 'skipped' }
  } catch (e) {
    return { outcome: 'refused', words: String(e.message) }
  } finally {
    verifier?.dispose()
  }
}
const verdict = async (lockingScript) => {
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  tx.addOutput({ satoshis: 1, lockingScript })
  tx.merklePath = new MerklePath(900, [[{ offset: 0, hash: tx.id('hex'), txid: true }]])
  const lookup = { type: 'output-list', outputs: [{ beef: tx.toBEEF(), outputIndex: 0 }] }
  return {
    wallet: await judged(lookup),
    decode: await judged(lookup, new IdentityEvidenceVerifier(tracker, 'bsv-rs#553', { scriptBytes: 1024 * 1024 }))
  }
}

const two = await published({ email: 'alice@example.com', name: 'Alice' }, ['email'])
const base = JSON.parse(two.text)
// The reference's text with spaces after it to `size` bytes (JSON's own
// whitespace: the members unchanged, the signature over the bytes padded).
// Its token is recorded by recipe (the spaces, the field signature, the
// script's SHA-256), the script itself 256 KiB.
const padding = (size) => size - utf8(two.text).length
const padded = (size) => utf8(two.text + ' '.repeat(padding(size)))
const changed = (change) => {
  const record = structuredClone(base)
  change(record)
  return utf8(JSON.stringify(record))
}
// A certificate of `n` fields the certifier 7 signs (`Certificate.sign`; the
// issuer caps a certificate it encrypts at 100 fields): `f000` encrypted by
// the issuer and revealed to anyone, the rest base64 text, published in the
// member order publiclyRevealAttributes writes (`{...certificate, keyring}`).
const many = async (n) => {
  const issued = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(key(7)), subject, { f000: 'value 0' },
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(3))
  )
  const fields = { ...issued.fields }
  for (let i = 1; i < n; i++) fields[`f${String(i).padStart(3, '0')}`] = Utils.toBase64(utf8(`value ${i}`))
  const certificate = new Certificate(issued.type, issued.serialNumber, subject, issued.certifier,
    issued.revocationOutpoint, fields)
  await certificate.sign(new ProtoWallet(key(7)))
  const keyring = await MasterCertificate.createKeyringForVerifier(
    wallet9, issued.certifier, ANYONE, { f000: fields.f000 }, ['f000'], issued.masterKeyring, issued.serialNumber
  )
  return JSON.stringify({
    type: certificate.type, subject, serialNumber: certificate.serialNumber, certifier: certificate.certifier,
    revocationOutpoint: certificate.revocationOutpoint, signature: certificate.signature, fields, keyring
  })
}
const MAX = 256 * 1024

const cases = []
for (const [name, check, bytes] of [
  ['reference', 'the reference\'s own token', null],
  ['byte_order_mark', 'toUTF8Strict (TextDecoder) drops a leading BOM, :88', [0xef, 0xbb, 0xbf, ...utf8(two.text)]],
  ['certificate_at_bound', 'the certificate 1 to 256 KiB, :503-508', padded(MAX)],
  ['certificate_over_bound', 'the certificate 1 to 256 KiB, :503-508', padded(MAX + 1)],
  ['extra_member', 'no member but the eight, :100-105', changed((r) => { r.note = 'x' })],
  ['missing_keyring', 'every one of the eight, :106', changed((r) => { delete r.keyring })],
  ['missing_revocation_outpoint', 'every one of the eight, :106', changed((r) => { delete r.revocationOutpoint })],
  ['keyring_not_object', 'fields and keyring plain objects, :107-111', changed((r) => { r.keyring = [] })],
  ['empty_keyring', 'keyring 1 to 100 names, :112-121', changed((r) => { r.keyring = {} })],
  ['keyring_name_not_a_field', 'every keyring name a field\'s, :122-125', changed((r) => { r.keyring.phone = r.keyring.email })],
  ['keyring_value_not_string', 'every keyring value a string, :126-129', changed((r) => { r.keyring.name = 5 })],
  ['keyring_value_over_bound', 'every keyring value at most 2048 UTF-16 units, :126-129', changed((r) => { r.keyring.name = 'A'.repeat(2049) })],
  ['fields_at_bound', 'fields 1 to 100 names, :112-121', utf8(await many(100))],
  ['fields_over_bound', 'fields 1 to 100 names, :112-121', utf8(await many(101))],
  ['type_not_string', 'a member that is no certificate\'s, verify false, :540-550', changed((r) => { r.type = 5 })],
  // verify is toBinary under a catch (Certificate.ts:425-440), so its text
  // rules skip a record too (#553's fold)
  ['revocation_txid_alone', 'the index absent read as 0, Certificate.ts:262', changed((r) => { r.revocationOutpoint = '00'.repeat(32) })],
  ['revocation_outpoint_null', 'the outpoint a string, Certificate.ts:257-259', changed((r) => { r.revocationOutpoint = null })],
  ['revocation_outpoint_empty', 'a 64-hex txid, Certificate.ts:260-270', changed((r) => { r.revocationOutpoint = '' })],
  ['revocation_outpoint_number', 'the outpoint a string, Certificate.ts:257-259', changed((r) => { r.revocationOutpoint = 0 })],
  ['revocation_index_leading_zero', 'the index 0 or [1-9][0-9]*, Certificate.ts:266', changed((r) => { r.revocationOutpoint = '00'.repeat(32) + '.00' })],
  ['revocation_index_signed', 'the index 0 or [1-9][0-9]*, Certificate.ts:266', changed((r) => { r.revocationOutpoint = '00'.repeat(32) + '.+0' })],
  ['field_value_number', 'every field value a string, Certificate.ts:63-72,281', changed((r) => { r.fields.extra = 5 })],
  ['field_value_null', 'every field value a string, Certificate.ts:63-72,281', changed((r) => { r.fields.extra = null })],
  ['type_unpadded', 'type canonical base64, Certificate.ts:233, WalletByteEncoding.ts:39-46', changed((r) => { r.type = r.type.replace(/=+$/, '') })],
  ['serial_number_unpadded', 'serialNumber canonical base64, Certificate.ts:237, WalletByteEncoding.ts:39-46', changed((r) => { r.serialNumber = r.serialNumber.replace(/=+$/, '') })],
  ['type_whitespace', 'type canonical base64, Certificate.ts:233, WalletByteEncoding.ts:39-46', changed((r) => { r.type = r.type.slice(0, 4) + '\n' + r.type.slice(4) })]
]) {
  const lockingScript = bytes === null ? LockingScript.fromHex(two.token) : await lock(bytes)
  const script = bytes !== null && bytes.length > 4096
    ? {
        padding: padding(bytes.length),
        signature: Utils.toHex(PushDrop.decode(lockingScript).fields[1]),
        locking_script_sha256: Utils.toHex(Hash.sha256(lockingScript.toBinary()))
      }
    : { locking_script: lockingScript.toHex() }
  cases.push({ name, check, certificate_bytes: (bytes ?? utf8(two.text)).length, ...script, ...(await verdict(lockingScript)) })
}

process.stdout.write(JSON.stringify({
  description: '#553: the toolbox discovery\'s record checks and byte bounds on revelation tokens the ' +
    'reference signs for the subject, with parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:87-132,497-559,671-707',
  node: process.version,
  recorder: 'tests/support/identity_certificate_record_553.mjs',
  subject,
  reference_text: two.text,
  cases
}, null, 2) + '\n')
