// Re-record #379's six shared vectors from ts-stack PR 1423 at 9a2787b8c.
// Set W to an existing directory outside the checkout and NODE22 to Node 22.
//   git -C ~/bsv/ts-stack archive 9a2787b8c packages/sdk | tar -x -C "$W"
//   bun build "$W/packages/sdk/mod.ts" --target node --format esm --outfile "$W/sdk.mjs"
//   "$NODE22" tests/support/hmac_key_379.mjs "$W/sdk.mjs" \
//     "$W/packages/sdk/src/wallet/__tests/ProtoWallet.brc56-hmac-key.test.ts"
// Redirect stdout to tests/vectors/wallet_hmac_key_379.json. No network calls.
// With a third argument (the Rust issuer's JSON), record the certificate and
// its HMAC after verifying both and decrypting both keyrings in the reference.
// The Rust input is emitted with CARGO_TARGET_DIR outside the checkout:
//   BSV_HMAC_ISSUED_OUTPUT="$W/rust-issued.json" cargo test --features auth \
//     --test auth_hmac_issuance_379 record_a_certificate_issued_here_for_the_reference \
//     -- --ignored --exact
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import vm from 'node:vm'
import { pathToFileURL } from 'node:url'

assert.match(process.version, /^v22\./, 'record with Node 22')
const [sdkPath, sourcePath, issuedPath] = process.argv.slice(2)
const { Certificate, MasterCertificate, VerifiableCertificate, ProtoWallet, KeyDeriver, PrivateKey, Utils, Hash } =
  await import(pathToFileURL(sdkPath).href)
const source = fs.readFileSync(sourcePath, 'utf8')
const sourceSha256 = createHash('sha256').update(source).digest('hex')
assert.equal(sourceSha256, '7ddbea38147c839ca50d4a80c13ff1a216cb92092c49692fb82aff24e70e1fdb', 'use the test table at 9a2787b8c')
const constant = (name) => source.match(new RegExp(`const ${name} = '([^']+)'`))[1]
const rootKey = constant('ROOT_KEY')
const counterparty = constant('COUNTERPARTY')
const protocolID = [2, 'hmac key vectors']
const data = '4252432d353620484d41432074657374'
// Read the literal table as data, preserving its property names and bytes.
const literal = source.match(/const VECTORS: Vector\[\] = (\[[\s\S]*?\n\])/)[1]
const vectors = JSON.parse(JSON.stringify(vm.runInNewContext(`(${literal})`, { COUNTERPARTY: counterparty })))
assert.equal(vectors.length, 6)
const key = PrivateKey.fromHex(rootKey)
const wallet = new ProtoWallet(key)
const deriver = new KeyDeriver(key)
const results = []
for (const row of vectors) {
  const args = { protocolID, keyID: row.keyID, counterparty: row.counterparty, data: Utils.toArray(data, 'hex') }
  assert.equal(Utils.toHex(deriver.deriveSymmetricKey(protocolID, row.keyID, row.counterparty).toArray()), row.hmacKey)
  assert.equal(Utils.toHex((await wallet.createHmac(args)).hmac), row.hmac)
  assert.equal((await wallet.verifyHmac({ ...args, hmac: Utils.toArray(row.hmac, 'hex') })).valid, true)
  if (row.rejectedTag !== undefined) {
    const paddedKey = Utils.toArray('00'.repeat(row.leadingZeroBytes) + row.hmacKey, 'hex')
    assert.equal(Utils.toHex(Hash.sha256hmac(paddedKey, args.data)), row.rejectedTag)
    await assert.rejects(wallet.verifyHmac({ ...args, hmac: Utils.toArray(row.rejectedTag, 'hex') }), /HMAC is not valid/)
  }
  results.push({ keyID: row.keyID, counterparty: row.counterparty, standardValid: true, legacyValid: row.rejectedTag === undefined })
}
const reference = {
  commit: '9a2787b8cb8c16a9fec50b713e3624322912258e',
  node: process.version,
  source: 'packages/sdk/src/wallet/__tests/ProtoWallet.brc56-hmac-key.test.ts',
  sourceSha256
}
if (issuedPath === undefined) {
  console.log(JSON.stringify({ reference, rootKey, rootPublicKey: constant('ROOT_PUBLIC_KEY'), counterparty, protocolID, data, vectors, results }, null, 2))
} else {
  const issued = JSON.parse(fs.readFileSync(issuedPath, 'utf8'))
  const cert = Certificate.fromBinary(Utils.toArray(issued.binaryHex, 'hex'))
  assert.equal(await cert.verify(), true)
  assert.equal(Utils.toHex(cert.toBinary(true)), issued.binaryHex)
  const hmacArgs = { protocolID, keyID: 'k95', counterparty: 'self', data: Utils.toArray(issued.binaryHex, 'hex') }
  assert.equal((await wallet.verifyHmac({ ...hmacArgs, hmac: Utils.toArray(issued.hmac, 'hex') })).valid, true)
  assert.equal(Utils.toHex((await wallet.createHmac(hmacArgs)).hmac), issued.hmac)
  const subject = new ProtoWallet(new PrivateKey(issued.keys.subject))
  const verifier = new ProtoWallet(new PrivateKey(issued.keys.verifier))
  const masterPlaintexts = await MasterCertificate.decryptFields(subject, issued.masterKeyring, cert.fields, cert.certifier)
  const verifierPlaintexts = await new VerifiableCertificate(cert.type, cert.serialNumber, cert.subject, cert.certifier, cert.revocationOutpoint, cert.fields, issued.verifierKeyring, cert.signature).decryptFields(verifier)
  assert.deepEqual({ ...masterPlaintexts }, issued.plaintexts)
  assert.deepEqual({ ...verifierPlaintexts }, issued.plaintexts)
  const encryptionKeys = Object.keys(issued.plaintexts).map(name => ({
    name,
    master: Utils.toHex(new KeyDeriver(new PrivateKey(issued.keys.certifier)).deriveSymmetricKey([2, 'certificate field encryption'], name, cert.subject).toArray()),
    verifier: Utils.toHex(new KeyDeriver(new PrivateKey(issued.keys.subject)).deriveSymmetricKey([2, 'certificate field encryption'], `${cert.serialNumber} ${name}`, new PrivateKey(issued.keys.verifier).toPublicKey()).toArray())
  }))
  console.log(JSON.stringify({ reference, rootKey, protocolID, keyID: 'k95', ...issued, referenceCertificateValid: true, referenceHmacValid: true, referenceMasterPlaintexts: masterPlaintexts, referenceVerifierPlaintexts: verifierPlaintexts, encryptionKeys }, null, 2))
}
