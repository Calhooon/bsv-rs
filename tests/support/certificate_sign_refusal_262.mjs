// The #262 witness: the reference's `sign` on a certificate already signed.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_sign_refusal_262.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_certificate_sign_refusal_262.json
//
// It signs #251's one-field `email` certificate under the reference's `sign`,
// signs it again and records the words the reference throws
// (`Certificate.ts:450-453`), then clears the signature as the reference's
// caller does (`signature = undefined`), signs a third time and records the
// bytes, which equal a single signing's.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, ProtoWallet, PrivateKey, Utils } = await import(pathToFileURL(sdkPath).href)

const certifier = new PrivateKey(7)
const subject = new PrivateKey(9)
const email = new Certificate(
  Utils.toBase64(new Array(32).fill(1)),
  Utils.toBase64(new Array(32).fill(2)),
  subject.toPublicKey().toString(),
  certifier.toPublicKey().toString(),
  '00'.repeat(32) + '.0',
  { email: Utils.toBase64(Utils.toArray('v-email', 'utf8')) }
)
const wallet = new ProtoWallet(certifier)
await email.sign(wallet)
const signedOnce = Utils.toHex(email.toBinary(true))

let refusal = null
try {
  await email.sign(wallet)
} catch (e) {
  refusal = e.message
}
const afterRefusal = Utils.toHex(email.toBinary(true))

email.signature = undefined
await email.sign(wallet)
const signedAgain = Utils.toHex(email.toBinary(true))

console.log(JSON.stringify({
  description: 'The reference\'s Certificate.sign on a certificate already signed (#262), recorded by tests/support/certificate_sign_refusal_262.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  signed_once: signedOnce,
  refusal,
  unchanged_by_refusal: afterRefusal === signedOnce,
  signed_after_clearing: signedAgain
}, null, 2))
