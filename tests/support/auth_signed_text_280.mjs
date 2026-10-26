// The #280 witnesses: BRC-103's signed certificate texts in the reference.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/auth_signed_text_280.mjs record "$W/sdk.mjs" > "$W/reference.json"
//   AUTH_280_REFERENCE="$W/reference.json" AUTH_280_CRATE_OUT="$W/crate.json" \
//     cargo test --features full --test auth_signed_text_280 -- --ignored
//   $NODE tests/support/auth_signed_text_280.mjs verify "$W/sdk.mjs" "$W/reference.json" \
//     "$W/crate.json" > tests/vectors/auth_signed_text_280.json
//
// `record` drives two reference `Peer`s over an in-memory transport pair that
// carries each message as `JSON.stringify` text and hands the other side its
// `JSON.parse`: a handshake, a certificateRequest whose policy names five
// certificate types, and a certificateResponse carrying a certificate with
// three fields and a three-key keyring. It logs every message text and the
// bytes each wallet signed and verified (`Peer.ts:453`, `:1068`, `:1140`,
// `:1203`), and a session nonce the verifier's wallet made for `verify`.
// `verify` hands each message this crate wrote (`crate.json`, the ignored
// Rust test's output) to a reference `Peer` holding that session and records
// the bytes its wallet verified and the verdict.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [mode, sdkPath, referencePath, cratePath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { Peer, SessionManager, ProtoWallet, PrivateKey, MasterCertificate, VerifiableCertificate, createNonce, Utils } = sdk

const SIGNED = 'auth message signature'
const scalar = n => new PrivateKey(n)
const verifierKey = scalar(21)
const holderKey = scalar(22)
const certifierKey = scalar(23)
const crateKey = scalar(31)
const hex = k => k.toPublicKey().toString()
const b64 = byte => Utils.toBase64(new Array(32).fill(byte))

// The signed bytes: UTF-8 text for a JSON member, hex for nonces and payloads
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
  const certifierWallet = new ProtoWallet(certifierKey)

  // Three fields and a three-key keyring, in an order no sort gives
  const certificateType = b64(3)
  const plain = { name: 'Alice', email: 'alice@example.com', country: 'NZ' }
  const master = await MasterCertificate.issueCertificateForSubject(
    certifierWallet, hex(holderKey), plain, certificateType, async () => '00'.repeat(32) + '.0', b64(9)
  )
  const keyring = await MasterCertificate.createKeyringForVerifier(
    holderWallet, hex(certifierKey), hex(verifierKey), master.fields,
    ['name', 'email', 'country'], master.masterKeyring, master.serialNumber
  )
  const verifiable = new VerifiableCertificate(
    master.type, master.serialNumber, master.subject, master.certifier,
    master.revocationOutpoint, master.fields, keyring, master.signature
  )

  const toVerifier = new TextTransport('holder', log)
  const toHolder = new TextTransport('verifier', log)
  toVerifier.other = toHolder
  toHolder.other = toVerifier
  const verifier = new Peer(verifierWallet, toHolder)
  const holder = new Peer(holderWallet, toVerifier)
  await verifier.ready
  await holder.ready

  holder.listenForCertificatesRequested(async (verifierIdentity) => {
    await holder.sendCertificateResponse(verifierIdentity, [verifiable])
  })
  const received = new Promise((resolve, reject) => {
    verifier.listenForCertificatesReceived((sender, certificates) => resolve(certificates.length))
    setTimeout(() => reject(new Error('no certificates received')), 5000)
  })
  // Five types, in an order no sort gives
  const policy = {
    certifiers: [hex(certifierKey)],
    types: {
      [b64(8)]: ['nickname'],
      [certificateType]: ['name', 'email', 'country'],
      [b64(6)]: ['b', 'a'],
      [b64(1)]: ['phone'],
      [b64(4)]: ['z', 'y', 'x']
    }
  }
  await verifier.toPeer([1, 2, 3], hex(holderKey))
  await verifier.requestCertificates(policy, hex(holderKey))
  const count = await received

  // Each signed member is a substring of the text sent, byte for byte
  for (const m of log.messages) {
    const parsed = JSON.parse(m.text)
    const member = { certificateRequest: 'requestedCertificates', certificateResponse: 'certificates' }[m.messageType]
    if (member === undefined) continue
    const memberText = JSON.stringify(parsed[member])
    const signed = log.signed.find(s => s.keyID === `${parsed.nonce} ${parsed.yourNonce}`)
    m.member = member
    m.member_text_in_message = m.text.includes(`"${member}":${memberText}`)
    m.signed_bytes_equal_member_text = signed?.data === memberText
  }

  console.log(JSON.stringify({
    node: process.version,
    reference: 'ts-stack@edf6e03 packages/sdk',
    certificates_received_by_verifier: count,
    transport_errors: [...toVerifier.errors, ...toHolder.errors],
    keys: {
      verifier: verifierKey.toHex(),
      holder: holderKey.toHex(),
      certifier: certifierKey.toHex(),
      this_crate: crateKey.toHex()
    },
    certificate_type: certificateType,
    reference_session_nonce: await createNonce(verifierWallet),
    this_crate_session_nonce: Utils.toBase64(new Array(48).fill(77)),
    reference_exchange: log
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
    peer.listenForCertificatesRequested(async () => {})
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
      reference_error: error
    })
  }
  console.log(JSON.stringify({
    issue: 'bsv-rs#280',
    description: 'BRC-103 signs a certificateRequest over its requestedCertificates JSON text and a certificateResponse over its certificates text, the text as transmitted. reference_exchange: two reference Peers over an in-memory transport that carries JSON.stringify text; this_crate_messages: texts this crate wrote, handed to a reference Peer holding the session.',
    ...vector,
    this_crate_messages: results
  }, null, 2))
} else {
  throw new Error(`unknown mode ${mode}`)
}
