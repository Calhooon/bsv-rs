// The #297 witness: the reference's certificate bounds and decrypt wrappers.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_bounds_297.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_certificate_bounds_297.json
//
// Each case names a site and its input in parameters both sides build the
// same way (a frame's bytes are given whole); the verdict is `ok` (with the
// SHA-256 of `toBinary(false)` where the site writes, the plaintext's length
// where it decrypts) or the words the reference throws. A verdict does not
// depend on the randomness of a field's key or IV, so the keys alone are fixed:
// certifier 43, subject 47, verifier 41 (each private key 32 bytes of that
// value), type 32 bytes of 1, serial 32 bytes of 2.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, MasterCertificate, VerifiableCertificate, ProtoWallet, PrivateKey, SymmetricKey, Hash, Utils } =
  await import(pathToFileURL(sdkPath).href)

const key = (byte) => PrivateKey.fromHex(byte.toString(16).padStart(2, '0').repeat(32))
const [certifier, subject, verifier] = [key(43), key(47), key(41)]
const TYPE = Utils.toBase64(new Array(32).fill(1))
const SERIAL = Utils.toBase64(new Array(32).fill(2))
const ZERO_OUTPOINT = '00'.repeat(32) + '.0'
const PROTOCOL = [2, 'certificate field encryption']

/** A record with own data properties, `__proto__` among them as a key. */
function record (entries) {
  const out = {}
  for (const [k, v] of entries) {
    Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true })
  }
  return out
}

/** The base64 text of `n` bytes of 0x41. */
const b64 = (n) => Utils.toBase64(new Array(n).fill(0x41))

async function verdict (f) {
  try {
    return { ok: await f() }
  } catch (e) {
    return { error: e.message }
  }
}

const sha = (bytes) => Utils.toHex(Hash.sha256(bytes))
const cases = []
const add = async (id, site, input, f) => cases.push({ id, site, input, verdict: await verdict(f) })

// --- Certificate.toBinary (`Certificate.ts:44-129`, `:281-297`) ---------------
const certificate = (fields) =>
  new Certificate(TYPE, SERIAL, subject.toPublicKey().toString(), certifier.toPublicKey().toString(), ZERO_OUTPOINT, fields)
const namesCase = async (id, names) =>
  add(id, 'to_binary', { names, value: 'QQ==' }, () => sha(certificate(record(names.map((n) => [n, 'QQ==']))).toBinary(false)))
await namesCase('name_of_50_bytes', ['n'.repeat(50)])
await namesCase('name_of_51_bytes', ['n'.repeat(51)])
await namesCase('empty_name', [''])
await namesCase('name_of_25_two_byte_characters', ['é'.repeat(25)])
await namesCase('name_of_51_bytes_in_two_byte_characters', ['é'.repeat(25) + 'a'])
await namesCase('name___proto__', ['__proto__'])
await namesCase('name_constructor', ['constructor'])
await namesCase('name_prototype', ['prototype'])
const countCase = async (id, count) =>
  add(id, 'to_binary', { count, value: 'QQ==' }, () =>
    sha(certificate(Object.fromEntries(Array.from({ length: count }, (_, i) => [`f${i}`, 'QQ==']))).toBinary(false)))
await countCase('100000_fields', 100000)
await countCase('100001_fields', 100001)

// --- Certificate.fromBinary (`Certificate.ts:356-387`) ------------------------
const head = certificate({}).toBinary(false)
head.pop() // the field count
const varint = (n) => { const w = new Utils.Writer(); w.writeVarIntNum(n); return w.toArray() }
const utf8 = (s) => Utils.toArray(s, 'utf8')
const frame = (count, rest) => [...head, ...varint(count), ...rest]
const fieldBytes = (nameBytes, value) => [...varint(nameBytes.length), ...nameBytes, ...varint(value.length), ...value]
const frameCase = async (id, bytes) =>
  add(id, 'from_binary', { hex: Utils.toHex(bytes) }, () => Object.keys(Certificate.fromBinary(bytes).fields).length)
await frameCase('frame_name_length_0', frame(1, [0, 1, 0x41]))
await frameCase('frame_name_of_50_bytes', frame(1, fieldBytes(utf8('n'.repeat(50)), [])))
await frameCase('frame_name_of_51_bytes', frame(1, fieldBytes(utf8('n'.repeat(51)), [])))
await frameCase('frame_name___proto__', frame(1, fieldBytes(utf8('__proto__'), [])))
await frameCase('frame_count_100001', frame(100001, []))
await frameCase('frame_count_1_in_3_bytes', frame(1, fieldBytes(utf8('a'), [])))
await frameCase('frame_count_2_in_5_bytes', frame(2, [...fieldBytes(utf8('a'), []), 1, 0x62]))

// --- the MasterCertificate constructor (`MasterCertificate.ts:195-233`) -------
// A spec is the base64 of n bytes ({bytes: n}) or a text ({text}).
const spec = (s) => (s.text !== undefined ? s.text : b64(s.bytes))
const masterNewCase = async (id, fields, keyring) =>
  add(id, 'master_new', { fields, keyring }, () => {
    const m = new MasterCertificate(TYPE, SERIAL, subject.toPublicKey().toString(), certifier.toPublicKey().toString(),
      ZERO_OUTPOINT, record(fields.map(([n, s]) => [n, spec(s)])), record(keyring.map(([n, s]) => [n, spec(s)])))
    return sha(m.toBinary(false))
  })
await masterNewCase('keyring_entry_of_2048_bytes', [['name', { bytes: 48 }]], [['name', { bytes: 2048 }]])
await masterNewCase('keyring_entry_of_2049_bytes', [['name', { bytes: 48 }]], [['name', { bytes: 2049 }]])
await masterNewCase('keyring_entry_missing', [['name', { bytes: 48 }]], [])
await masterNewCase('keyring_entry_empty', [['name', { bytes: 48 }]], [['name', { text: '' }]])
await masterNewCase('keyring_entry_of_2049_bytes_for_no_field', [['name', { bytes: 48 }]],
  [['name', { bytes: 80 }], ['other', { bytes: 2049 }]])
await masterNewCase('keyring_entry_not_canonical', [['name', { bytes: 48 }]], [['name', { text: 'QQ' }]])
await masterNewCase('field_not_canonical', [['name', { text: 'QQ' }]], [['name', { bytes: 80 }]])
const many = (n) => Array.from({ length: n }, (_, i) => [`f${i}`, { bytes: 48 }])
await masterNewCase('100_fields', many(100), many(100))
await masterNewCase('101_fields', many(101), many(101))
await masterNewCase('field_name_constructor', [['constructor', { bytes: 48 }]], [['constructor', { bytes: 80 }]])
await masterNewCase('field_name_of_51_bytes', [['n'.repeat(51), { bytes: 48 }]], [['n'.repeat(51), { bytes: 80 }]])

// --- createCertificateFields (`MasterCertificate.ts:254-305`) -----------------
const certifierWallet = new ProtoWallet(certifier)
const subjectWallet = new ProtoWallet(subject)
const verifierWallet = new ProtoWallet(verifier)
const subjectHex = subject.toPublicKey().toString()
const certifierHex = certifier.toPublicKey().toString()
const verifierHex = verifier.toPublicKey().toString()
const createCase = async (id, plaintexts, wallet = certifierWallet, ciphertextBytes = null) =>
  add(id, 'create_certificate_fields', { plaintexts, ciphertext_bytes: ciphertextBytes }, async () => {
    const r = await MasterCertificate.createCertificateFields(wallet, subjectHex,
      Object.fromEntries(plaintexts.map(([n, len]) => [n, 'A'.repeat(len)])))
    return Object.keys(r.certificateFields).length
  })
await createCase('plaintext_of_65536_bytes', [['name', 65536]])
await createCase('plaintext_of_65537_bytes', [['name', 65537]])
await createCase('101_plaintext_fields', Array.from({ length: 101 }, (_, i) => [`f${i}`, 1]))
/** A wallet whose encrypt answers `n` bytes; the rest the subject's ProtoWallet. */
const bloated = (inner, n) => ({
  encrypt: async () => ({ ciphertext: new Array(n).fill(0x41) }),
  decrypt: (args, o) => inner.decrypt(args, o)
})
await createCase('wallet_ciphertext_of_2048_bytes', [['name', 5]], bloated(certifierWallet, 2048), 2048)
await createCase('wallet_ciphertext_of_2049_bytes', [['name', 5]], bloated(certifierWallet, 2049), 2049)

// --- decryption --------------------------------------------------------------
// One field `name` of `plaintext_bytes` bytes of 'A', its key encrypted from
// the certifier to the subject (the master keyring) and from the subject to
// the verifier under `<serial> name` (the verifier's keyring), as the
// reference's own methods write them, its size bound bypassed.
async function issued (plaintextBytes) {
  const fieldKey = SymmetricKey.fromRandom()
  const field = Utils.toBase64(fieldKey.encrypt(new Array(plaintextBytes).fill(0x41)))
  const { ciphertext: masterEntry } = await certifierWallet.encrypt({
    plaintext: fieldKey.toArray('be', 32), protocolID: PROTOCOL, keyID: 'name', counterparty: subjectHex
  })
  const { ciphertext: verifierEntry } = await subjectWallet.encrypt({
    plaintext: fieldKey.toArray('be', 32), protocolID: PROTOCOL, keyID: `${SERIAL} name`, counterparty: verifierHex
  })
  return {
    fields: { name: field },
    masterKeyring: { name: Utils.toBase64(masterEntry) },
    verifierKeyring: { name: Utils.toBase64(verifierEntry) }
  }
}

/**
 * The four decrypting sites on one input: `mutate` changes the issued
 * records, `reveal` is createKeyringForVerifier's fieldsToReveal.
 */
async function decryptCases (id, input, mutate = () => {}, reveal = ['name'], sites = null) {
  const c = await issued(input.plaintext_bytes ?? 5)
  mutate(c)
  const run = {
    master_decrypt_field: () => MasterCertificate.decryptField(subjectWallet, c.masterKeyring, 'name', c.fields.name, certifierHex)
      .then((r) => r.decryptedFieldValue.length),
    master_decrypt_fields: () => MasterCertificate.decryptFields(subjectWallet, c.masterKeyring, c.fields, certifierHex)
      .then((r) => Object.keys(r).length),
    create_keyring_for_verifier: () => MasterCertificate.createKeyringForVerifier(subjectWallet, certifierHex, verifierHex,
      c.fields, reveal, c.masterKeyring, SERIAL).then((r) => Object.keys(r).length),
    verifiable_decrypt_fields: () => new VerifiableCertificate(TYPE, SERIAL, subjectHex, certifierHex, ZERO_OUTPOINT,
      c.fields, c.verifierKeyring).decryptFields(verifierWallet).then((r) => Object.values(r).map((v) => v.length).reduce((a, b) => a + b, 0))
  }
  for (const site of sites ?? Object.keys(run)) await add(id, site, { ...input, reveal }, run[site])
}
await decryptCases('plaintext_of_65536_bytes', { plaintext_bytes: 65536 })
await decryptCases('plaintext_of_65537_bytes', { plaintext_bytes: 65537 })
await decryptCases('plaintext_of_0_bytes', { plaintext_bytes: 0 })
await decryptCases('master_keyring_entry_of_2049_bytes', { master_keyring_entry_bytes: 2049 },
  (c) => { c.masterKeyring.name = b64(2049) }, ['name'],
  ['master_decrypt_field', 'master_decrypt_fields', 'create_keyring_for_verifier'])
await decryptCases('master_keyring_empty', { master_keyring_empty: true },
  (c) => { c.masterKeyring = {} }, ['name'], ['master_decrypt_field', 'master_decrypt_fields'])
await decryptCases('field_text_unpadded', { field_text_unpadded: true },
  (c) => { c.fields.name = c.fields.name.replace(/=+$/, '') })
await decryptCases('verifier_keyring_entry_of_2049_bytes', { verifier_keyring_entry_bytes: 2049 },
  (c) => { c.verifierKeyring.name = b64(2049) }, ['name'], ['verifiable_decrypt_fields'])
await decryptCases('verifier_keyring_empty', { verifier_keyring_empty: true },
  (c) => { c.verifierKeyring = {} }, ['name'], ['verifiable_decrypt_fields'])
await decryptCases('verifier_keyring_of_101_entries', { verifier_keyring_entries: 101 },
  (c) => { for (let i = 0; i < 100; i++) c.verifierKeyring[`f${i}`] = b64(48) }, ['name'], ['verifiable_decrypt_fields'])
await decryptCases('verifier_keyring_entry_for_no_field', { verifier_keyring_ghost: true },
  (c) => { c.verifierKeyring = { ghost: b64(48) } }, ['name'], ['verifiable_decrypt_fields'])
await decryptCases('verifier_keyring_name___proto__', { verifier_keyring_proto: true },
  (c) => { c.verifierKeyring = record([['__proto__', b64(48)]]) }, ['name'], ['verifiable_decrypt_fields'])
await decryptCases('reveal_a_field_not_carried', {}, () => {}, ['ghost'], ['create_keyring_for_verifier'])
await decryptCases('reveal_a_field_twice', {}, () => {}, ['name', 'name'], ['create_keyring_for_verifier'])
await decryptCases('reveal_101_fields', {}, () => {}, Array.from({ length: 101 }, (_, i) => `f${i}`),
  ['create_keyring_for_verifier'])
for (const n of [2048, 2049]) {
  const c = await issued(5)
  await add(`wallet_ciphertext_of_${n}_bytes`, 'create_keyring_for_verifier', { ciphertext_bytes: n, reveal: ['name'] }, () =>
    MasterCertificate.createKeyringForVerifier(bloated(subjectWallet, n), certifierHex, verifierHex, c.fields, ['name'],
      c.masterKeyring, SERIAL).then((r) => Object.keys(r).length))
}

console.log(JSON.stringify({
  description: 'The reference\'s certificate bounds and decrypt wrappers (#297), recorded by tests/support/certificate_bounds_297.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  cases
}, null, 2))
