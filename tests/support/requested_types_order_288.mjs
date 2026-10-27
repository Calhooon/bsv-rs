// The #288 witnesses: a certificateRequest's policy in the reference, its
// `types` in insertion order.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/requested_types_order_288.mjs record "$W/sdk.mjs" > "$W/reference.json"
//   AUTH_288_REFERENCE="$W/reference.json" AUTH_288_CRATE_OUT="$W/crate.json" \
//     cargo test --features full --test auth_requested_types_order_288 -- --ignored
//   $NODE tests/support/requested_types_order_288.mjs verify "$W/sdk.mjs" "$W/reference.json" \
//     "$W/crate.json" > tests/vectors/auth_requested_types_order_288.json
//
// `record` writes `JSON.stringify` of a policy naming three certificate types
// in an order no sort gives (`Peer.ts:451-453` signs those bytes), and drives
// two reference `Peer`s over an in-memory transport carrying each message as
// `JSON.stringify` text: a handshake, then the verifier's certificateRequest
// with that policy, logging the bytes its wallet signed. `verify` hands the
// certificateRequest this crate wrote (`crate.json`, the ignored Rust test's
// output) to a reference `Peer` holding the session and records the bytes its
// wallet verified, the verdict, and the policy its listener received.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [mode, sdkPath, referencePath, cratePath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { Peer, SessionManager, ProtoWallet, PrivateKey, createNonce, Utils } = sdk

const SIGNED = 'auth message signature'
const scalar = n => new PrivateKey(n)
const verifierKey = scalar(21)
const holderKey = scalar(22)
const certifierKey = scalar(23)
const crateKey = scalar(31)
const hex = k => k.toPublicKey().toString()
const b64 = byte => Utils.toBase64(new Array(32).fill(byte))

// Three types, in an order no sort gives
const policy = {
  certifiers: [hex(certifierKey)],
  types: {
    [b64(7)]: ['nickname'],
    [b64(2)]: ['name', 'email'],
    [b64(5)]: ['z', 'a']
  }
}

const bytes = data => (data[0] === 0x5b || data[0] === 0x7b)
  ? { data: Utils.toUTF8(data) }
  : { data_hex: Utils.toHex(data) }

// A ProtoWallet that logs the bytes of every BRC-103 signature it makes or checks
class LoggingWallet extends ProtoWallet {
  constructor (key, name, log) {
    super(key)
    this.name = name
    this.log = log
  }

  async createSignature (args, originator) {
    const result = await super.createSignature(args, originator)
    if (args.protocolID[1] === SIGNED) {
      this.log.signed.push({ by: this.name, keyID: args.keyID, ...bytes(args.data) })
    }
    return result
  }

  async verifySignature (args, originator) {
    let valid
    try {
      valid = (await super.verifySignature(args, originator)).valid
    } catch (e) {
      valid = false
    }
    if (args.protocolID[1] === SIGNED) {
      this.log.verified.push({ by: this.name, keyID: args.keyID, ...bytes(args.data), valid })
    }
    return { valid }
  }
}

// One end of an in-memory pair: a message travels as its JSON.stringify text
class TextTransport {
  constructor (name, log) {
    this.name = name
    this.log = log
    this.errors = []
  }

  async send (message) {
    const text = JSON.stringify(message)
    this.log.messages.push({ from: this.name, messageType: message.messageType, text })
    const other = this.other
    setTimeout(() => {
      other.callback(JSON.parse(text)).catch(e => other.errors.push(String(e.message ?? e)))
    }, 0)
  }

  async onData (callback) {
    this.callback = callback
  }
}

if (mode === 'record') {
  const log = { messages: [], signed: [], verified: [] }
  const verifierWallet = new LoggingWallet(verifierKey, 'verifier', log)
  const holderWallet = new LoggingWallet(holderKey, 'holder', log)
  const toVerifier = new TextTransport('holder', log)
  const toHolder = new TextTransport('verifier', log)
  toVerifier.other = toHolder
  toHolder.other = toVerifier
  const verifier = new Peer(verifierWallet, toHolder)
  const holder = new Peer(holderWallet, toVerifier)
  await verifier.ready
  await holder.ready

  const requested = new Promise((resolve, reject) => {
    holder.listenForCertificatesRequested(async (sender, set) => resolve(JSON.stringify(set)))
    setTimeout(() => reject(new Error('no certificateRequest received')), 5000)
  })
  await verifier.toPeer([1, 2, 3], hex(holderKey))
  await verifier.requestCertificates(policy, hex(holderKey))
  const holderReceived = await requested

  const request = log.messages.find(m => m.messageType === 'certificateRequest')
  const parsed = JSON.parse(request.text)
  const signed = log.signed.find(s => s.keyID === `${parsed.nonce} ${parsed.yourNonce}`)

  console.log(JSON.stringify({
    node: process.version,
    reference: 'ts-stack@edf6e03 packages/sdk',
    keys: {
      verifier: verifierKey.toHex(),
      holder: holderKey.toHex(),
      certifier: certifierKey.toHex(),
      this_crate: crateKey.toHex()
    },
    policy_text: JSON.stringify(policy),
    reference_request: {
      text: request.text,
      signed: signed.data,
      signed_equals_policy_text: signed.data === JSON.stringify(policy),
      holder_received_policy_text: holderReceived,
      holder_verified: log.verified.filter(v => v.keyID === signed.keyID).map(v => v.valid)
    },
    transport_errors: [...toVerifier.errors, ...toHolder.errors],
    reference_session_nonce: await createNonce(verifierWallet),
    this_crate_session_nonce: Utils.toBase64(new Array(48).fill(77))
  }, null, 2))
} else if (mode === 'verify') {
  const vector = JSON.parse(fs.readFileSync(referencePath, 'utf8'))
  const crate = JSON.parse(fs.readFileSync(cratePath, 'utf8'))
  const results = []
  for (const m of crate.messages) {
    const log = { messages: [], signed: [], verified: [] }
    const wallet = new LoggingWallet(verifierKey, 'verifier', log)
    const sessions = new SessionManager()
    sessions.addSession({
      isAuthenticated: true,
      sessionNonce: vector.reference_session_nonce,
      peerNonce: vector.this_crate_session_nonce,
      peerIdentityKey: hex(crateKey),
      lastUpdate: Date.now(),
      certificatesRequired: false,
      certificatesValidated: true,
      certificatePolicy: { certifiers: [], types: {} }
    })
    const transport = new TextTransport('verifier', log)
    transport.other = { errors: [], callback: async () => {} }
    const peer = new Peer(wallet, transport, undefined, sessions)
    await peer.ready
    let received = null
    peer.listenForCertificatesRequested(async (sender, set) => { received = JSON.stringify(set) })
    let error = null
    try {
      await transport.callback(JSON.parse(m.text))
    } catch (e) {
      error = String(e.message ?? e)
    }
    const check = log.verified[0]
    results.push({
      ...m,
      reference_verified_bytes: check === undefined ? null : check.data,
      reference_verified_bytes_equal_member_text: check === undefined ? null : check.data === m.member_text,
      reference_signature_valid: check === undefined ? null : check.valid,
      reference_received_policy_text: received,
      reference_error: error
    })
  }
  console.log(JSON.stringify({
    issue: 'bsv-rs#288',
    description: 'A certificateRequest policy whose types name three certificate types in an order no sort gives. policy_text: the reference\'s JSON.stringify(policy), the bytes Peer.ts:451-453 signs; reference_request: two reference Peers\' certificateRequest over an in-memory transport carrying JSON.stringify text; this_crate_messages: the certificateRequest this crate wrote, handed to a reference Peer holding the session.',
    ...vector,
    this_crate_messages: results
  }, null, 2))
} else {
  throw new Error(`unknown mode ${mode}`)
}
