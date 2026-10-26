// The #268 witnesses: the three certificate types' JSON is the reference's.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk-edf6e03.mjs")
//   cargo test --features auth --test auth_certificate_json_268 -- --ignored --nocapture \
//     print_the_certificates_issued_here_for_the_reference   # its JSON array saved as rust_issued.json
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_json_268.mjs \
//     "$W/sdk-edf6e03.mjs" rust_issued.json > tests/vectors/certificate_json_268.json
//
// It issues three certificates with the reference's
// `MasterCertificate.issueCertificateForSubject` (`MasterCertificate.ts:437-497`),
// three fields and one with the outpoint `<64 zeros>.0`, and one with the
// reference's default outpoint, the txid alone (#268's fold), its randomness fixed (globalThis.crypto.getRandomValues
// replaced by a SHA-256 counter stream before the SDK loads), a keyring for a
// verifier by `createKeyringForVerifier`, and records the reference's
// `JSON.stringify` of a `Certificate`, the `MasterCertificate` and a
// `VerifiableCertificate` of each, its `toBinary(true)`, its `verify()` verdict
// and the plaintexts it decrypts. Then it reads the JSON texts this crate wrote
// (rust_issued.json) as the reference reads a certificate's JSON
// (`Certificate.fromObject`, `Certificate.ts:505-525`, and the two subclasses'
// constructors, as `Peer`'s `#restoreOwnedCertificates` reads a peer's,
// `Peer.ts:341-357`) and records its `JSON.stringify` of each, its
// `toBinary(true)`, its `verify()` verdict on the three and the plaintexts it
// decrypts.
import fs from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) {
    const block = createHash('sha256').update(`bsv-rs#268 ${counter++}`).digest()
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
const { Certificate, MasterCertificate, VerifiableCertificate, ProtoWallet, PrivateKey, Utils } =
  await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const pub = (n) => key(n).toPublicKey().toString()

// The three types read from one JSON object each, as the reference reads them.
const readThree = (texts) => {
  const c = JSON.parse(texts.certificate)
  const m = JSON.parse(texts.master)
  const v = JSON.parse(texts.verifiable)
  return {
    certificate: Certificate.fromObject(c),
    master: new MasterCertificate(m.type, m.serialNumber, m.subject, m.certifier, m.revocationOutpoint, m.fields, m.masterKeyring, m.signature),
    verifiable: new VerifiableCertificate(v.type, v.serialNumber, v.subject, v.certifier, v.revocationOutpoint, v.fields, v.keyring, v.signature)
  }
}
const verdicts = async (three, keys) => ({
  reference_to_binary_hex: Utils.toHex(three.certificate.toBinary(true)),
  reference_verify: (await three.certificate.verify()) && (await three.master.verify()) && (await three.verifiable.verify()),
  reference_master_plaintexts: { ...await MasterCertificate.decryptFields(new ProtoWallet(key(keys.subject)), three.master.masterKeyring, three.master.fields, three.master.certifier) },
  reference_verifier_plaintexts: { ...await three.verifiable.decryptFields(new ProtoWallet(key(keys.verifier))) }
})

// The reference's certificates: certifier 31, subject 37, verifier 41.
const keys = { certifier: 31, subject: 37, verifier: 41 }
const referenceIssued = []
// The third takes the reference's default revocation outpoint, the txid
// alone (`MasterCertificate.ts:442`, `'00'.repeat(32)`).
for (const [plaintexts, getRevocationOutpoint] of [
  [{ name: 'Alice Example', email: 'alice@example.com', city: 'Zoë\'s Café' }, async () => '00'.repeat(32) + '.0'],
  [{ name: 'Alice Example' }, async () => '00'.repeat(32) + '.0'],
  [{ name: 'Alice Example' }, undefined]
]) {
  const names = Object.keys(plaintexts).sort()
  const issued = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(key(keys.certifier)),
    pub(keys.subject),
    plaintexts,
    Utils.toBase64(new Array(32).fill(6)),
    getRevocationOutpoint,
    Utils.toBase64(new Array(32).fill(7))
  )
  const keyring = await MasterCertificate.createKeyringForVerifier(
    new ProtoWallet(key(keys.subject)), pub(keys.certifier), pub(keys.verifier),
    issued.fields, names, issued.masterKeyring, issued.serialNumber
  )
  const certificate = new Certificate(issued.type, issued.serialNumber, issued.subject, issued.certifier, issued.revocationOutpoint, issued.fields, issued.signature)
  const verifiable = new VerifiableCertificate(issued.type, issued.serialNumber, issued.subject, issued.certifier, issued.revocationOutpoint, issued.fields, keyring, issued.signature)
  const json = {
    certificate: JSON.stringify(certificate),
    master: JSON.stringify(issued),
    verifiable: JSON.stringify(verifiable)
  }
  const v = await verdicts({ certificate, master: issued, verifiable }, keys)
  referenceIssued.push({
    origin: `issued by the reference's MasterCertificate.issueCertificateForSubject (certifier key 31, subject key 37, type 32 x 0x06, serial 32 x 0x07, revocation outpoint ${getRevocationOutpoint ? '32 zero bytes index 0' : 'the reference\'s default, 32 zero bytes as the txid alone'}), a keyring by createKeyringForVerifier for verifier key 41; each JSON text the reference\'s JSON.stringify of the instance; randomness the script's SHA-256 counter stream`,
    keys,
    plaintexts,
    json,
    binary_hex: v.reference_to_binary_hex,
    reference_verify: v.reference_verify,
    reference_master_plaintexts: v.reference_master_plaintexts,
    reference_verifier_plaintexts: v.reference_verifier_plaintexts
  })
}

// The certificates issued by this crate, read by the reference from their JSON.
const rustIssued = []
for (const r of JSON.parse(fs.readFileSync(rustIssuedPath, 'utf8'))) {
  const three = readThree(r.json)
  rustIssued.push({
    ...r,
    reference_json: {
      certificate: JSON.stringify(three.certificate),
      master: JSON.stringify(three.master),
      verifiable: JSON.stringify(three.verifiable)
    },
    ...await verdicts(three, r.keys)
  })
}

console.log(JSON.stringify({
  description: 'The three certificate types\' JSON is the reference\'s (#268): the reference\'s JSON.stringify of a Certificate, a MasterCertificate and a VerifiableCertificate it issued, and the JSON this crate writes for the three, read by the reference, with its toBinary(true), verify() verdict, decrypted plaintexts and JSON.stringify of what it read',
  reference: `@bsv/sdk at ts-stack@edf6e03 (packages/sdk, bundled with bun build), run under Node ${process.version} by tests/support/certificate_json_268.mjs`,
  commands: 'see the header of tests/support/certificate_json_268.mjs',
  reference_issued: referenceIssued,
  rust_issued: rustIssued
}, null, 2))
