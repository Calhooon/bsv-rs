// #587: the reference's `getVerifiableCertificates` on a wallet listing
// certificates whose certifier or type is in or outside the requested set
// (`ts-stack@edf6e03` `packages/sdk/src/auth/utils/getVerifiableCertificates.ts:46-108`,
// the membership `includes()` and the type's fields at `:76-81`, before
// proveCertificate at `:82-91`; the set's certifiers canonical through
// `assertAuthIdentityKey`, `AuthMessageValidation.ts:124`).
// Each case records `verdict` as `{ ok: true, count }` (the certificates
// returned) or `{ ok: false, message }` (the thrown error's message), and
// `proveCalls`, the wallet's proveCertificate calls before the verdict.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-587/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf '%s\n' \
//     "import { getVerifiableCertificates } from './packages/sdk/src/auth/utils/getVerifiableCertificates.js'" \
//     "import PrivateKey from './packages/sdk/src/primitives/PrivateKey.js'" \
//     "export { getVerifiableCertificates, PrivateKey }" > "$W/entry587.ts"
//   (cd "$W" && bun build entry587.ts --target node --format esm --outfile "$W/gvc.mjs")
//   node tests/support/verifiable_certificates_membership_587.mjs "$W/gvc.mjs" > tests/vectors/verifiable_certificates_membership_587.json
import { pathToFileURL } from 'url'

const [bundle] = process.argv.slice(2)
const { getVerifiableCertificates, PrivateKey } = await import(pathToFileURL(bundle).href)

// The scalars this crate's tests use: `PrivateKey::from_bytes(&[n; 32])`
const key = n => new PrivateKey(n.toString(16).padStart(2, '0').repeat(32), 16).toPublicKey().toString()
const b64 = n => Buffer.alloc(32, n).toString('base64')

const SUBJECT = key(42)
const CERTIFIER = key(43)
const OUTSIDE = key(45)
const VERIFIER = key(44)
const TYPE = b64(1)

const listed = (certifier, type = TYPE) => ({
  type,
  serialNumber: b64(2),
  subject: SUBJECT,
  certifier,
  revocationOutpoint: `${'00'.repeat(32)}.0`,
  signature: '',
  fields: {}
})

const requested = { certifiers: [CERTIFIER], types: { [TYPE]: ['name'] } }

const cases = [
  ['in_set', [listed(CERTIFIER)]],
  ['certifier_outside_set', [listed(OUTSIDE)]],
  ['certifier_upper_case', [listed(CERTIFIER.toUpperCase())]],
  ['type_outside_set', [listed(CERTIFIER, b64(3))]],
  ['outside_after_inside', [listed(CERTIFIER), listed(OUTSIDE)]],
  ['outside_before_inside', [listed(OUTSIDE), listed(CERTIFIER)]]
]

const out = []
for (const [name, certificates] of cases) {
  let proveCalls = 0
  const wallet = {
    listCertificates: async () => ({ totalCertificates: certificates.length, certificates }),
    proveCertificate: async () => { proveCalls++; return { keyringForVerifier: {} } }
  }
  let verdict
  try {
    const result = await getVerifiableCertificates(wallet, requested, VERIFIER, 'test')
    verdict = { ok: true, count: result.length }
  } catch (error) {
    verdict = { ok: false, message: error.message }
  }
  out.push({ name, certifiers: certificates.map(c => c.certifier), types: certificates.map(c => c.type), verdict, proveCalls })
}

console.log(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk/src/auth/utils/getVerifiableCertificates.ts:76-81',
  node: process.version,
  requested,
  verifier: VERIFIER,
  cases: out
}, null, 2))
