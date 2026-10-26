// The #261 witnesses: a certificate's field value is its base64 text, its UTF-8 bytes on the wire.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk-edf6e03.mjs")
//   cargo test --features auth --test auth_certificate_field_value_261 -- --ignored --nocapture \
//     print_a_certificate_issued_here_for_the_reference   # its JSON object saved as rust_issued.json
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_field_value_261.mjs \
//     "$W/sdk-edf6e03.mjs" rust_issued.json > tests/vectors/certificate_field_value_261.json
//
// It issues an encrypted-field certificate with the reference's
// `MasterCertificate.issueCertificateForSubject` (`MasterCertificate.ts:437-497`),
// its randomness fixed (globalThis.crypto.getRandomValues replaced by a
// SHA-256 counter stream before the SDK loads), and records its JSON, its
// `toBinary(true)`, the SHA-256 of its `toBinary(false)`, the keyrings, the
// reference's `verify()` verdict and the plaintexts the reference decrypts
// (`MasterCertificate.decryptFields`, `VerifiableCertificate.decryptFields`).
// Then it reads the certificate issued by this crate (rust_issued.json) and
// records the reference's `toBinary(true)` of its JSON, its `verify()`
// verdict and the plaintexts the reference decrypts from it.
import fs from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) {
    const block = createHash('sha256').update(`bsv-rs#261 ${counter++}`).digest()
    out.push(...block)
  }
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: {
    getRandomValues (arr) {
      arr.set(stream(arr.length))
      return arr
    }
  }
})

const [sdkPath, rustIssuedPath] = process.argv.slice(2)
const { Certificate, MasterCertificate, VerifiableCertificate, ProtoWallet, PrivateKey, Hash, Utils } =
  await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const pub = (n) => key(n).toPublicKey().toString()
const sha256Hex = (bytes) => Utils.toHex(Hash.sha256(bytes))
const anyone = key(1)

// The reference's certificate: certifier 31, subject 37, verifier 41.
const plaintexts = { name: 'Alice Example', email: 'alice@example.com', city: 'Zoë\'s Café' }
const names = Object.keys(plaintexts).sort()
const issued = await MasterCertificate.issueCertificateForSubject(
  new ProtoWallet(key(31)),
  pub(37),
  plaintexts,
  Utils.toBase64(new Array(32).fill(6)),
  async () => '00'.repeat(32) + '.0',
  Utils.toBase64(new Array(32).fill(7))
)
const subjectWallet = new ProtoWallet(key(37))
const verifierKeyring = await MasterCertificate.createKeyringForVerifier(
  subjectWallet, pub(31), pub(41), issued.fields, names, issued.masterKeyring, issued.serialNumber
)
const anyoneKeyring = await MasterCertificate.createKeyringForVerifier(
  subjectWallet, pub(31), anyone.toPublicKey().toString(), issued.fields, names,
  issued.masterKeyring, issued.serialNumber
)
const reference = {
  origin: 'issued by the reference\'s MasterCertificate.issueCertificateForSubject (certifier key 31, subject key 37, type 32 x 0x06, serial 32 x 0x07, revocation outpoint 32 zero bytes index 0), keyrings by createKeyringForVerifier for verifier key 41 and for the anyone key (1); randomness the script\'s SHA-256 counter stream',
  keys: { certifier: 31, subject: 37, verifier: 41 },
  plaintexts,
  certificate: {
    type: issued.type,
    serialNumber: issued.serialNumber,
    subject: issued.subject,
    certifier: issued.certifier,
    revocationOutpoint: issued.revocationOutpoint,
    fields: { ...issued.fields },
    signature: issued.signature
  },
  master_keyring: { ...issued.masterKeyring },
  verifier_keyring: { ...verifierKeyring },
  anyone_keyring: { ...anyoneKeyring },
  binary_hex: Utils.toHex(issued.toBinary(true)),
  preimage_sha256: sha256Hex(issued.toBinary(false)),
  reference_verify: await issued.verify(),
  reference_master_plaintexts: { ...await MasterCertificate.decryptFields(subjectWallet, issued.masterKeyring, issued.fields, pub(31)) },
  reference_verifier_plaintexts: { ...await new VerifiableCertificate(issued.type, issued.serialNumber, issued.subject, issued.certifier, issued.revocationOutpoint, issued.fields, verifierKeyring, issued.signature).decryptFields(new ProtoWallet(key(41))) },
  reference_anyone_plaintexts: { ...await new VerifiableCertificate(issued.type, issued.serialNumber, issued.subject, issued.certifier, issued.revocationOutpoint, issued.fields, anyoneKeyring, issued.signature).decryptFields(new ProtoWallet(anyone)) }
}

// The certificate issued by this crate, read by the reference from its JSON.
const r = JSON.parse(fs.readFileSync(rustIssuedPath, 'utf8'))
const c = r.certificate
const here = new Certificate(c.type, c.serialNumber, c.subject, c.certifier, c.revocationOutpoint, c.fields, c.signature)
const rust = {
  ...r,
  reference_to_binary_hex: Utils.toHex(here.toBinary(true)),
  reference_verify: await here.verify(),
  reference_master_plaintexts: { ...await MasterCertificate.decryptFields(new ProtoWallet(key(r.keys.subject)), r.master_keyring, c.fields, c.certifier) },
  reference_verifier_plaintexts: { ...await new VerifiableCertificate(c.type, c.serialNumber, c.subject, c.certifier, c.revocationOutpoint, c.fields, r.verifier_keyring, c.signature).decryptFields(new ProtoWallet(key(r.keys.verifier))) }
}

console.log(JSON.stringify({
  description: 'A certificate field value is the UTF-8 bytes of its base64 text, held, written and signed (#261): a certificate the reference issued with encrypted fields and one issued by this crate, each with the reference\'s verify() verdict and the plaintexts the reference decrypts',
  reference: `@bsv/sdk at ts-stack@edf6e03 (packages/sdk, bundled with bun build), run under Node ${process.version} by tests/support/certificate_field_value_261.mjs`,
  brc: 'BRC-52 at brcs@5119a9b peer-to-peer/0052.md:41,97',
  commands: 'see the header of tests/support/certificate_field_value_261.mjs',
  reference_issued: reference,
  rust_issued: rust
}, null, 2))
