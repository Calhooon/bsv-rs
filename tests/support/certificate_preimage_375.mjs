// #375: execute Peer.ts:1203's certificate-response signature verification.
// Usage: node certificate_preimage_375.mjs <edf6e03 sdk.mjs> <input.json> <output.json>
// The Rust Peer creates the input. No transport/nonce-handshake probe is run.
import fs from 'node:fs'
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'

if (process.version !== 'v22.18.0') throw new Error('use Node v22.18.0')
const { ProtoWallet, PrivateKey, VerifiableCertificate, Utils } = await import(pathToFileURL(process.argv[2]))
const input = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))
const wallet = new ProtoWallet(new PrivateKey(input.deterministicTestKeys.receiverScalar))
const cases = []
for (const row of input.cases) {
  const message = JSON.parse(row.responseText)
  const preimage = JSON.stringify(message.certificates)
  assert.equal(preimage, row.signedText)
  assert.equal(Buffer.from(message.signature).toString('hex'), row.signatureHex)
  assert.deepEqual(message.certificates[0], row.certificate)
  // These are the arguments in Peer.processCertificateResponse:1203-1213.
  const { valid } = await wallet.verifySignature({
    data: Utils.toArray(preimage, 'utf8'),
    signature: message.signature,
    protocolID: [2, 'auth message signature'],
    keyID: `${message.nonce ?? ''} ${message.yourNonce ?? ''}`,
    counterparty: message.identityKey
  })
  assert.equal(valid, true)
  const c = message.certificates[0]
  const cert = new VerifiableCertificate(c.type, c.serialNumber, c.subject,
    c.certifier, c.revocationOutpoint, c.fields, c.keyring, c.signature)
  assert.equal(await cert.verify(), true)
  const fields = await cert.decryptFields(wallet)
  for (const name of Object.keys(c.fields)) assert.equal(fields[name], name)
  cases.push({ ...row, reference: { preimage, verify: valid, certificateVerify: true, fieldsDecrypted: true } })
}
fs.writeFileSync(process.argv[4], JSON.stringify({
  ...input,
  referenceSdk: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  nodeVersion: process.version,
  referenceSite: 'Peer.processCertificateResponse, packages/sdk/src/auth/Peer.ts:1203-1213 (signature path); ProtoWallet.verifySignature',
  cases
}, null, 2) + '\n')
