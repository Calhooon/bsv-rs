// The #251 witnesses: BRC-52's certificate signature in the reference.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_signature_251.mjs \
//     "$W/sdk.mjs" tests/vectors/auth_certificate_signature_251.json
//
// It signs the one-field `email` certificate under the reference's `sign`
// (`Certificate.ts:458-462`) and prints its bytes, then runs the
// reference's `verify` (`Certificate.ts:428-431`) on every witness the
// vector file carries and prints the verdicts the file records.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, vectorPath] = process.argv.slice(2)
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
await email.sign(new ProtoWallet(certifier))
console.log('node', process.version)
console.log('reference_signed_email', Utils.toHex(email.toBinary(true)))

if (vectorPath) {
  const v = JSON.parse(fs.readFileSync(vectorPath, 'utf8'))
  for (const w of v.witnesses) {
    const c = Certificate.fromBinary(Utils.toArray(w.hex, 'hex'))
    console.log('verify', w.name, await c.verify())
  }
}
