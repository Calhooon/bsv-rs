// #610: the key bytes the reference's `Certificate.toBinary` writes for a
// subject or certifier text, or the message it throws (`ts-stack@edf6e03`
// `packages/sdk/src/auth/certificates/Certificate.ts`: `toBinary` `:240-254`,
// `assertCompressedPublicKey` `:136-143`), the operation
// `auth::certificates::certificate_key_bytes` is named for. #585's eight texts
// (`certificate_to_binary_key_585.mjs`) and the shapes around them: either
// prefix and case, white space, the lenient forms, lengths beside 66, other
// prefixes, non-hex and non-ASCII characters, and x at, above and far above p.
// Each case records `to_binary` as `{ ok, key }` (the 33 key bytes written,
// hex) or `{ ok: false, message }` (the thrown error's message).
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-610-certificate-key-bytes/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/certificate_key_bytes_610.mjs "$W/sdk.mjs" > tests/vectors/certificate_key_bytes_610.json
import { pathToFileURL } from 'url'

const [bundle] = process.argv.slice(2)
const { Certificate, PrivateKey } = await import(pathToFileURL(bundle).href)

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const hex64 = n => n.toString(16).padStart(64, '0')
const toHex = bytes => bytes.map(b => b.toString(16).padStart(2, '0')).join('')

// The scalars this crate's tests use: the subject 37 (an `03` key), the
// certifier 31 (an `02` key)
const scalar = n => new PrivateKey(n.toString(16).padStart(64, '0'), 16)
const KEYS = {
  subject: scalar(37).toPublicKey(),
  certifier: scalar(31).toPublicKey()
}
const TYPE = Buffer.alloc(32, 6).toString('base64')
const SERIAL = Buffer.alloc(32, 7).toString('base64')
const OUTPOINT = `${'ab'.repeat(32)}.0`

function forms (pub) {
  const compressed = pub.toString()
  const uncompressed = pub.encode(false, 'hex')
  const odd = (parseInt(uncompressed.slice(-2), 16) & 1) === 1
  const mixed = [...compressed].map((c, i) => (i % 2 ? c.toUpperCase() : c)).join('')
  const x = compressed.slice(2)
  return [
    ['compressed', compressed],
    ['other_prefix', `${compressed.startsWith('02') ? '03' : '02'}${x}`],
    ['upper_case', compressed.toUpperCase()],
    ['mixed_case', mixed],
    ['surrounding_space', ` ${compressed} `],
    ['leading_space', ` ${compressed}`],
    ['trailing_newline', `${compressed}\n`],
    ['uncompressed', uncompressed],
    ['hybrid', `${odd ? '07' : '06'}${uncompressed.slice(2)}`],
    ['odd_length', compressed.slice(1)],
    ['empty', ''],
    ['short_64', compressed.slice(0, 64)],
    ['long_68', `${compressed}00`],
    ['hex_prefix', `0x${compressed}`],
    ['prefix_04', `04${x}`],
    ['prefix_05', `05${x}`],
    ['prefix_00', `00${x}`],
    ['non_hex', `${compressed.slice(0, 65)}g`],
    ['non_ascii', `${compressed.slice(0, 65)}é`],
    ['x_above_p', `02${hex64(P + 1n)}`],
    ['x_at_p', `02${hex64(P)}`],
    ['x_max', `03${'ff'.repeat(32)}`],
    ['x_no_point', `02${'00'.repeat(32)}`]
  ]
}

// The key's place in `toBinary`'s bytes: after the type and serial number
const OFFSET = { subject: 64, certifier: 97 }

function judge (field, text) {
  const cert = new Certificate(
    TYPE, SERIAL,
    field === 'subject' ? text : KEYS.subject.toString(),
    field === 'certifier' ? text : KEYS.certifier.toString(),
    OUTPOINT, { name: 'QWxpY2U=' }
  )
  try {
    const bytes = cert.toBinary(false)
    return { ok: true, key: toHex(bytes.slice(OFFSET[field], OFFSET[field] + 33)) }
  } catch (error) {
    return { ok: false, message: error.message }
  }
}

const cases = []
for (const field of ['subject', 'certifier']) {
  for (const [name, text] of forms(KEYS[field])) {
    cases.push({ field, name, text, to_binary: judge(field, text) })
  }
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03',
  node: process.version,
  cases
}, null, 2) + '\n')
