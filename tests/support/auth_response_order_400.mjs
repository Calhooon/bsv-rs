// #400: record the real reference Peer's certificateResponse preimage.
// Usage: node auth_response_order_400.mjs <edf6e03 sdk.mjs> <output.json>
// Bundle the pinned packages/sdk/mod.ts with bun first. No network transport.
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

let counter = 0
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (array) {
    const bytes = []
    while (bytes.length < array.length) {
      bytes.push(...createHash('sha256').update(`bsv-rs#400 ${counter++}`).digest())
    }
    array.set(bytes.slice(0, array.length))
    return array
  } }
})
const { Peer, SessionManager, ProtoWallet, PrivateKey, MasterCertificate,
  VerifiableCertificate, createNonce, Utils } = await import(pathToFileURL(process.argv[2]))
const holder = new PrivateKey(22)
const verifier = new PrivateKey(21)
const certifier = new PrivateKey(23)
let preimage
class Wallet extends ProtoWallet {
  async createSignature (args, originator) {
    if (args.protocolID[1] === 'auth message signature') preimage = Utils.toUTF8(args.data)
    return super.createSignature(args, originator)
  }
}
const wallet = new Wallet(holder)
const master = await MasterCertificate.issueCertificateForSubject(
  new ProtoWallet(certifier), holder.toPublicKey().toString(),
  { 10: 'ten', 2: 'two', z: 'last', a: 'after z' }, Utils.toBase64(new Array(32).fill(3)),
  async () => '00'.repeat(32) + '.0', Utils.toBase64(new Array(32).fill(9))
)
const keyring = await MasterCertificate.createKeyringForVerifier(
  wallet, certifier.toPublicKey().toString(), verifier.toPublicKey().toString(),
  master.fields, ['10', '2', 'z', 'a'], master.masterKeyring, master.serialNumber
)
const certificate = new VerifiableCertificate(master.type, master.serialNumber,
  master.subject, master.certifier, master.revocationOutpoint, master.fields,
  keyring, master.signature)
const sessions = new SessionManager()
sessions.addSession({ isAuthenticated: true, sessionNonce: await createNonce(wallet),
  peerNonce: await createNonce(new ProtoWallet(verifier)),
  peerIdentityKey: verifier.toPublicKey().toString(), lastUpdate: Date.now(),
  certificatesRequired: false, certificatesValidated: true,
  certificatePolicy: { certifiers: [], types: {} } })
let message
const peer = new Peer(wallet, { async onData () {}, async send (value) { message = value } }, undefined, sessions)
await peer.ready
await peer.sendCertificateResponse(verifier.toPublicKey().toString(), [certificate])
if (preimage !== JSON.stringify(message.certificates)) throw new Error('reference preimage mismatch')
// Keep the same signed certificate and message; vary only numeric property order.
const reorderMap = map => '{' + ['10', '2', 'z', 'a'].map(key => JSON.stringify(key) + ':' + JSON.stringify(map[key])).join(',') + '}'
let input = JSON.stringify(message)
for (const name of ['fields', 'keyring']) {
  input = input.replace(JSON.stringify(message.certificates[0][name]), reorderMap(message.certificates[0][name]))
}
if (JSON.stringify(JSON.parse(input).certificates) !== preimage) throw new Error('changed certificate value')
const body = message.certificates[0]
const reorderedBody = '{"extension":"discarded",' + Object.keys(body).reverse()
  .filter(key => body[key] !== undefined)
  .map(key => JSON.stringify(key) + ':' + JSON.stringify(body[key])).join(',') + '}'
const reordered = JSON.stringify(message).replace(JSON.stringify(body), reorderedBody)
const verified = []
for (const text of [input, reordered]) {
  let observed, valid
  class Receiver extends ProtoWallet {
    async verifySignature (args, originator) {
      const result = await super.verifySignature(args, originator)
      if (args.protocolID[1] === 'auth message signature') {
        observed = Utils.toUTF8(args.data)
        valid = result.valid
      }
      return result
    }
  }
  const receiverSessions = new SessionManager()
  receiverSessions.addSession({ isAuthenticated: true,
    sessionNonce: message.yourNonce, peerNonce: Utils.toBase64(new Array(48).fill(77)),
    peerIdentityKey: holder.toPublicKey().toString(), lastUpdate: Date.now(),
    certificatesRequired: false, certificatesValidated: true,
    certificatePolicy: { certifiers: [master.certifier], types: { [master.type]: ['2', '10', 'z', 'a'] } } })
  let receive
  const receiver = new Peer(new Receiver(verifier), {
    async onData (callback) { receive = callback }, async send () {}
  }, undefined, receiverSessions)
  await receiver.ready
  await receive(JSON.parse(text))
  if (observed !== preimage || valid !== true) throw new Error('reference receiver mismatch')
  verified.push({ preimage: observed, valid })
}
fs.writeFileSync(process.argv[3], JSON.stringify({ source: 'ts-stack@edf6e03',
  node: process.version, reference_site: 'packages/sdk/src/auth/Peer.ts:341-357,1140,1203',
  input_message: input, reference_preimage: preimage,
  reordered_message: reordered, reference_verified: verified,
  verifier_key: verifier.toHex() }, null, 2) + '\n')
