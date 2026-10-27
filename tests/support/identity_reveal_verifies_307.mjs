// The #307 witnesses: the reference's `publiclyRevealAttributes` checks the
// certificate's fields and the names to reveal, then verifies the master
// certificate, before it calls the wallet (`ts-stack@edf6e03`
// `packages/sdk/src/identity/IdentityClient.ts:420-467`), and after
// proveCertificate checks the keyring's names and values (`:478-499`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_reveal_verifies_307.mjs \
//     "$W/sdk.mjs" > tests/vectors/identity_reveal_verifies_307.json
//
// Every witness is a wallet certificate (certifier key 7, subject key 9,
// type 32 bytes of 1, serial 32 bytes of 2, the zero revocation outpoint,
// the fields `email` and `name` as base64 text) and the names to reveal,
// each a change of one thing from the signed certificate revealing `email`.
// A wallet that counts its calls answers proveCertificate with a keyring of
// the names asked, getPublicKey and createSignature with key 5's, and
// createAction with no transaction; `refusal` is the reference's words
// (`null` when it reached createAction), `wallet_calls` the calls it made
// before the refusal or before createAction. A keyring witness names the
// keyring the wallet answers instead (`keyring`), the refusal's class
// (`refusal_name`, `Error` or `WERR_INVALID_PARAMETER`) and, when it
// reached createAction, the keyring the PushDrop carries (`published_keyring`). The signatures are RFC 6979's, so two runs print the same file.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, IdentityClient, LockingScript, ProtoWallet, PrivateKey, PushDrop, Utils } =
  await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const b64 = (text) => Utils.toBase64(Utils.toArray(text, 'utf8'))
const TYPE = Utils.toBase64(new Array(32).fill(1))
const SERIAL = Utils.toBase64(new Array(32).fill(2))
const TXID = '00'.repeat(32)
const FIELDS = { email: b64('v-email'), name: b64('v-name') }

async function signed (certifier, fields = FIELDS, outpoint = TXID + '.0') {
  const c = new Certificate(TYPE, SERIAL, key(9).toPublicKey().toString(),
    key(7).toPublicKey().toString(), outpoint, { ...fields })
  await c.sign(new ProtoWallet(certifier))
  return {
    type: c.type,
    subject: c.subject,
    serialNumber: c.serialNumber,
    certifier: c.certifier,
    revocationOutpoint: c.revocationOutpoint,
    signature: c.signature,
    fields: { ...c.fields }
  }
}

const good = await signed(key(7))
const unsafeFields = await signed(key(7))
unsafeFields.fields = JSON.parse('{"__proto__":"AA==","email":"' + FIELDS.email + '"}')

const cases = [
  ['signed', 'signed by the certifier', good, ['email']],
  ['signed_both_fields', 'signed by the certifier, both fields revealed', good, ['email', 'name']],
  ['unsigned', 'the empty signature', { ...good, signature: '' }, ['email']],
  ['other_key', 'signed by key 11, the certificate naming key 7', { ...good, signature: (await signed(key(11))).signature }, ['email']],
  ['field_changed', 'a field value changed after signing', { ...good, fields: { ...FIELDS, email: b64('v-other') } }, ['email']],
  ['not_der', 'eight bytes that are not DER', { ...good, signature: '3006ffffffffffff' }, ['email']],
  ['not_hex', 'a signature text that is not hex', { ...good, signature: 'zz' }, ['email']],
  ['empty_subject', 'the subject the empty string', { ...good, subject: '' }, ['email']],
  ['txid_alone', 'signed over <txid>.0, the outpoint the txid alone', { ...good, revocationOutpoint: TXID }, ['email']],
  ['no_fields', 'no fields', { ...good, fields: {} }, ['email']],
  ['unsafe_field', 'a field named __proto__', unsafeFields, ['email']],
  ['none_revealed', 'no names to reveal', good, []],
  ['too_many', '101 names to reveal', good, Array.from({ length: 101 }, (_, i) => 'f' + i)],
  ['empty_name', 'the empty name', good, ['']],
  ['long_name', 'a name of 51 bytes', good, ['e'.repeat(51)]],
  ['control_name', 'a name with U+0001', good, ['e\u0001']],
  ['unsafe_name', 'the name constructor', good, ['constructor']],
  ['duplicate_name', 'email twice', good, ['email', 'email']],
  ['absent_name', 'a name the certificate does not carry', good, ['phone']],
  ['unsigned_absent_name', 'the empty signature and an absent name: the name refused first', { ...good, signature: '' }, ['phone']],
  ['keyring_unsafe_proto', 'the keyring carrying __proto__ beside email', good, ['email'], JSON.parse('{"email":"AAAA","__proto__":"AAAA"}')],
  ['keyring_unsafe_constructor', 'the keyring naming constructor alone, one name as asked', good, ['email'], { constructor: 'AAAA' }],
  ['keyring_unrequested', 'the keyring naming email and name, email asked', good, ['email'], { email: 'AAAA', name: 'AAAA' }],
  ['keyring_other_name', 'the keyring naming name alone, email asked', good, ['email'], { name: 'AAAA' }],
  ['keyring_missing', 'the empty keyring', good, ['email'], {}],
  ['keyring_not_base64', 'a value with !', good, ['email'], { email: 'AA!A' }],
  ['keyring_empty', 'the empty value', good, ['email'], { email: '' }],
  ['keyring_whitespace_only', 'a value of whitespace alone', good, ['email'], { email: ' \t\n' }],
  ['keyring_padding_inside', 'a = before the last two places', good, ['email'], { email: 'A=AA' }],
  ['keyring_short', 'three characters, no padding', good, ['email'], { email: 'AAA' }],
  ['keyring_one_char', 'one character', good, ['email'], { email: 'A' }],
  ['keyring_oversized', '2732 characters, 2049 bytes', good, ['email'], { email: 'A'.repeat(2732) }],
  ['keyring_at_bound', '2731 characters and =, 2048 bytes', good, ['email'], { email: 'A'.repeat(2731) + '=' }],
  ['keyring_trimmed', 'a value with whitespace around it', good, ['email'], { email: ' \tAAAA\n ' }],
  ['keyring_bom_trimmed', 'a value after U+FEFF, which JavaScript trims', good, ['email'], { email: '\uFEFFAAAA' }],
  ['keyring_nel_kept', 'a value after U+0085, which JavaScript does not trim', good, ['email'], { email: '\u0085AAAA' }],
  ['keyring_noncanonical', 'AB==, its last bits not zero, read by shape only', good, ['email'], { email: 'AB==' }],
  ['keyring_both_fields_trimmed', 'both fields revealed, each value padded with spaces', good, ['email', 'name'], { email: ' AAAA', name: 'AAAA ' }]
]

function countingWallet (keyring) {
  const inner = new ProtoWallet(key(5))
  const wallet = {
    calls: [],
    published: undefined,
    async proveCertificate (args) {
      wallet.calls.push('proveCertificate')
      return { keyringForVerifier: keyring ?? Object.fromEntries(args.fieldsToReveal.map((f) => [f, 'AAAA'])) }
    },
    async getPublicKey (args) { wallet.calls.push('getPublicKey'); return inner.getPublicKey(args) },
    async createSignature (args) { wallet.calls.push('createSignature'); return inner.createSignature(args) },
    async createAction (args) {
      wallet.calls.push('createAction')
      const script = LockingScript.fromHex(args.outputs[0].lockingScript)
      wallet.published = JSON.parse(Utils.toUTF8(PushDrop.decode(script).fields[0])).keyring
      return {}
    }
  }
  return wallet
}

const witnesses = []
for (const [name, origin, certificate, fieldsToReveal, keyring] of cases) {
  const wallet = countingWallet(keyring)
  const client = new IdentityClient(wallet, {}, 'identity-client')
  let refusal = null
  let refusalName = null
  try {
    await client.publiclyRevealAttributes(structuredClone(certificate), [...fieldsToReveal])
  } catch (e) {
    refusal = e.message
    refusalName = e.name
  }
  const reached = wallet.calls.includes('createAction')
  const witness = {
    name,
    origin,
    certificate,
    fieldsToReveal,
    refusal: reached ? null : refusal,
    wallet_calls: reached ? wallet.calls.indexOf('createAction') : wallet.calls.length
  }
  if (keyring !== undefined) {
    witness.keyring = keyring
    witness.refusal_name = reached ? null : refusalName
    witness.published_keyring = reached ? wallet.published : null
  }
  witnesses.push(witness)
}

console.log(JSON.stringify({
  description: 'publiclyRevealAttributes refuses before any wallet call a certificate whose fields, names to reveal or signature the reference refuses, and before createAction a keyring whose names or values it refuses, publishing the values trimmed (#307)',
  reference: '@bsv/sdk at ts-stack@edf6e03 (packages/sdk, bundled with bun build), run under Node ' + process.version + ' by tests/support/identity_reveal_verifies_307.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/identity/IdentityClient.ts:420-499',
  witnesses
}, null, 2))
