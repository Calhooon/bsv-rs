// The #299 witnesses: the reference's `Certificate.verify` answers `false`
// to every failure under it (`ts-stack@edf6e03` `Certificate.ts:425-440`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_verify_false_299.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_certificate_verify_false_299.json
//
// Every witness is one certificate (certifier key 7, subject key 9, type 32
// bytes of 1, serial 32 bytes of 2, the zero revocation outpoint, one field
// `email` = the base64 text of "v-email") with the signature the witness
// carries as hex, `null` for none; `reference_verify` is what the
// reference's `verify` answers, and `threw` whether it threw (it never does).
// The signatures are RFC 6979's, so two runs print the same file.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, ProtoWallet, PrivateKey, Signature, BigNumber, Curve, Utils } =
  await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const TYPE = Utils.toBase64(new Array(32).fill(1))
const SERIAL = Utils.toBase64(new Array(32).fill(2))
const OUTPOINT = '00'.repeat(32) + '.0'
const FIELDS = { email: Utils.toBase64(Utils.toArray('v-email', 'utf8')) }

const certificate = (certifier, signature) =>
  new Certificate(TYPE, SERIAL, key(9).toPublicKey().toString(), certifier.toPublicKey().toString(),
    OUTPOINT, { ...FIELDS }, signature)

async function signedBy (certifier) {
  const c = certificate(certifier)
  await c.sign(new ProtoWallet(certifier))
  return c.signature
}

const valid = await signedBy(key(7))
const otherKey = await signedBy(key(11))
const der = Signature.fromDER(Utils.toArray(valid, 'hex'))
const n = new Curve().n
const highS = new Signature(der.r, n.sub(der.s)).toDER('hex')

const cases = [
  ['valid', 'signed by the certifier under BRC-52\'s derivation', valid],
  ['absent', 'no signature (`undefined`)', null],
  ['empty', 'the empty hex string', ''],
  ['not_der', 'eight bytes that are not DER', '3006ffffffffffff'],
  ['truncated_der', 'the valid signature less its last byte', valid.slice(0, -2)],
  ['other_key', 'signed by key 11 under the derivation, the certificate naming key 7', otherKey],
  ['zero_r', 'DER of r = 0, s = 1', '3006020100020101'],
  ['high_s', 'the valid signature with s replaced by n - s', highS],
  ['not_hex', 'a signature text that is not hex', 'zz']
]

const witnesses = []
for (const [name, origin, signature] of cases) {
  let verdict
  let threw = false
  try {
    verdict = await certificate(key(7), signature ?? undefined).verify()
  } catch {
    threw = true
  }
  witnesses.push({ name, origin, signature_hex: signature, reference_verify: verdict ?? null, threw })
}

console.log(JSON.stringify({
  description: 'Certificate.verify answers false, never an error (#299): the reference\'s verdict on one certificate under nine signatures',
  reference: '@bsv/sdk at ts-stack@edf6e03 (packages/sdk, bundled with bun build), run under Node ' + process.version + ' by tests/support/certificate_verify_false_299.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/auth/certificates/Certificate.ts:425-440',
  witnesses
}, null, 2))
