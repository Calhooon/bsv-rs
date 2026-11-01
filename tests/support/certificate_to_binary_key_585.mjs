// #585: the reference's `Certificate.toBinary` on a certificate whose subject or
// certifier is one key text of a list, and `Certificate.verify` on the same
// certificate carrying the signature its certifier made over the canonical form
// (`ts-stack@edf6e03` `packages/sdk/src/auth/certificates/Certificate.ts`:
// `toBinary` `:240-254`, `assertCompressedPublicKey` `:136-143`, `verify`
// `:425-440`), the reading the identity parsers' verification makes
// (the toolbox's `identityUtils.ts:497-559`; this crate's
// `src/identity/client_record.rs`).
// Each case records, per field, `to_binary` as `{ ok, key }` (the 33 key bytes
// written, hex) or `{ ok: false, message }` (the thrown error's message), and
// `verify` (the boolean). The texts are the canonical key, upper-case hex, a
// space-padded text, #498's lenient forms (uncompressed, hybrid, odd length),
// an x at or above p and an x that is no point's.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-585/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf '%s\n' \
//     "import Certificate from './packages/sdk/src/auth/certificates/Certificate.js'" \
//     "import ProtoWallet from './packages/sdk/src/wallet/ProtoWallet.js'" \
//     "import PrivateKey from './packages/sdk/src/primitives/PrivateKey.js'" \
//     "export { Certificate, ProtoWallet, PrivateKey }" > "$W/entry585.ts"
//   (cd "$W" && bun build entry585.ts --target node --format esm --outfile "$W/cert.mjs")
//   node tests/support/certificate_to_binary_key_585.mjs "$W/cert.mjs" > tests/vectors/certificate_to_binary_key_585.json
import { pathToFileURL } from 'url'

const [bundle] = process.argv.slice(2)
const { Certificate, ProtoWallet, PrivateKey } = await import(pathToFileURL(bundle).href)

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const hex64 = n => n.toString(16).padStart(64, '0')
const toHex = bytes => bytes.map(b => b.toString(16).padStart(2, '0')).join('')

// The scalars this crate's tests use: the subject 37, the certifier 31
const scalar = n => new PrivateKey(n.toString(16).padStart(64, '0'), 16)
const subjectKey = scalar(37)
const certifierKey = scalar(31)
const TYPE = Buffer.alloc(32, 6).toString('base64')
const SERIAL = Buffer.alloc(32, 7).toString('base64')
const OUTPOINT = `${'ab'.repeat(32)}.0`
const FIELDS = { name: 'QWxpY2U=' }

const signed = new Certificate(
  TYPE, SERIAL, subjectKey.toPublicKey().toString(), certifierKey.toPublicKey().toString(),
  OUTPOINT, { ...FIELDS }
)
await signed.sign(new ProtoWallet(certifierKey))

// The key forms of one canonical text
function forms (pub) {
  const compressed = pub.toString()
  const uncompressed = pub.encode(false, 'hex')
  const odd = (parseInt(uncompressed.slice(-2), 16) & 1) === 1
  return [
    ['compressed', compressed],
    ['upper_case', compressed.toUpperCase()],
    ['surrounding_space', ` ${compressed} `],
    ['uncompressed', uncompressed],
    ['hybrid', `${odd ? '07' : '06'}${uncompressed.slice(2)}`],
    ['odd_length', compressed.slice(1)],
    ['x_above_p', `02${hex64(P + 1n)}`],
    ['x_no_point', `02${'00'.repeat(32)}`]
  ]
}

// The key's place in `toBinary`'s bytes: after the type and serial number
const OFFSET = { subject: 64, certifier: 97 }

function judge (field, text) {
  const cert = new Certificate(
    signed.type, signed.serialNumber,
    field === 'subject' ? text : signed.subject,
    field === 'certifier' ? text : signed.certifier,
    signed.revocationOutpoint, { ...signed.fields }, signed.signature
  )
  let toBinary
  try {
    const bytes = cert.toBinary(false)
    toBinary = { ok: true, key: toHex(bytes.slice(OFFSET[field], OFFSET[field] + 33)) }
  } catch (error) {
    toBinary = { ok: false, message: error.message }
  }
  return cert.verify().then(verify => ({ to_binary: toBinary, verify }))
}

const cases = []
for (const field of ['subject', 'certifier']) {
  const pub = field === 'subject' ? subjectKey.toPublicKey() : certifierKey.toPublicKey()
  for (const [name, text] of forms(pub)) {
    cases.push({ field, name, text, ...(await judge(field, text)) })
  }
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03',
  node: process.version,
  type: TYPE,
  serial_number: SERIAL,
  revocation_outpoint: OUTPOINT,
  fields: FIELDS,
  subject: signed.subject,
  certifier: signed.certifier,
  signature: signed.signature,
  cases
}, null, 2) + '\n')
