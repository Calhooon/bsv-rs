// The #294 witnesses: the reference's `Peer` refuses a malformed requested
// certificate set on its own policy and on a received message.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/requested_set_validation_294.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_requested_set_validation_294.json
//
// For each policy: `constructor`, a `Peer` built with it as its own policy
// (`Peer.ts:158`); `sender`, `requestCertificates` with it after a handshake
// between two reference `Peer`s (`:434`), the signatures made and messages
// sent after the call; `receiver`, a certificateRequest carrying it, signed
// by the requester's wallet over `JSON.stringify(policy)`, handed to a
// reference `Peer` holding the requester's session (`snapshotAuthMessage`,
// `:767`, through `AuthMessageValidation.ts:345-346`, `:367`): its error, the
// signatures it checked, and whether its listener ran. The receiver's
// message text is recorded so this crate's `Peer` reads the same bytes.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { Peer, SessionManager, ProtoWallet, PrivateKey, createNonce, Utils } = sdk

const SIGNED = 'auth message signature'
const scalar = n => new PrivateKey(n)
const requesterKey = scalar(41)
const verifierKey = scalar(42)
const certifierKey = scalar(43)
const hex = k => k.toPublicKey().toString()
const b64 = (byte, length = 32) => Utils.toBase64(new Array(length).fill(byte))

// Each policy as given: `given_types` is the order it was written in
const cases = [
  ['type_id_of_31_bytes', [[b64(1, 31), ['name']]]],
  ['type_id_of_33_bytes', [[b64(1, 33), ['name']]]],
  ['type_id_not_base64', [['not base64!', ['name']]]],
  ['type_id_integer_like', [[b64(1), ['name']], ['42', ['name']]]],
  ['type_id_of_32_bytes', [[b64(1), ['name']]]]
].map(([name, types]) => ({
  name,
  given_types: types.map(([type]) => type),
  policy: { certifiers: [hex(certifierKey)], types: Object.fromEntries(types) }
}))

const words = error => error === null ? null : String(error.message ?? error)

class LoggingWallet extends ProtoWallet {
  constructor (key, log) {
    super(key)
    this.log = log
  }

  async createSignature (args, originator) {
    if (args.protocolID[1] === SIGNED) this.log.signed += 1
    return await super.createSignature(args, originator)
  }

  async verifySignature (args, originator) {
    if (args.protocolID[1] === SIGNED) this.log.verified += 1
    return await super.verifySignature(args, originator)
  }
}

// One end of an in-memory pair: a message travels as its JSON.stringify text
class TextTransport {
  constructor (log) {
    this.log = log
    this.errors = []
  }

  async send (message) {
    const text = JSON.stringify(message)
    this.log.sent.push(message.messageType)
    const other = this.other
    setTimeout(() => {
      other.callback(JSON.parse(text)).catch(e => other.errors.push(words(e)))
    }, 0)
  }

  async onData (callback) {
    this.callback = callback
  }
}

const settle = () => new Promise(resolve => setTimeout(resolve, 50))

async function constructorVerdict (policy) {
  try {
    const transport = new TextTransport({ sent: [] })
    // eslint-disable-next-line no-new
    new Peer(new ProtoWallet(requesterKey), transport, policy)
    return null
  } catch (e) {
    return words(e)
  }
}

async function senderVerdict (policy) {
  const log = { signed: 0, verified: 0, sent: [] }
  const holderLog = { signed: 0, verified: 0, sent: [] }
  const toHolder = new TextTransport(log)
  const toRequester = new TextTransport(holderLog)
  toHolder.other = toRequester
  toRequester.other = toHolder
  const requester = new Peer(new LoggingWallet(requesterKey, log), toHolder)
  const holder = new Peer(new LoggingWallet(verifierKey, holderLog), toRequester)
  await requester.ready
  await holder.ready
  let received = null
  holder.listenForCertificatesRequested(async (sender, set) => { received = JSON.stringify(set) })
  await requester.toPeer([1, 2, 3], hex(verifierKey))
  await settle()
  const before = { signed: log.signed, sent: log.sent.length }
  let error = null
  try {
    await requester.requestCertificates(policy, hex(verifierKey))
  } catch (e) {
    error = e
  }
  await settle()
  return {
    error: words(error),
    signatures_made: log.signed - before.signed,
    messages_sent: log.sent.slice(before.sent),
    holder_received_policy_text: received
  }
}

async function receiverVerdict (requestedCertificates) {
  const log = { signed: 0, verified: 0, sent: [] }
  const wallet = new LoggingWallet(verifierKey, log)
  const sessionNonce = await createNonce(wallet)
  const requesterSessionNonce = b64(77, 48)
  const nonce = b64(57)
  const data = requestedCertificates === undefined ? [] : Utils.toArray(JSON.stringify(requestedCertificates), 'utf8')
  const { signature } = await new ProtoWallet(requesterKey).createSignature({
    data,
    protocolID: [2, SIGNED],
    keyID: `${nonce} ${sessionNonce}`,
    counterparty: hex(verifierKey)
  })
  const request = {
    version: '0.1',
    messageType: 'certificateRequest',
    identityKey: hex(requesterKey),
    nonce,
    initialNonce: requesterSessionNonce,
    yourNonce: sessionNonce,
    requestedCertificates,
    signature
  }
  const text = JSON.stringify(request)

  const sessions = new SessionManager()
  sessions.addSession({
    isAuthenticated: true,
    sessionNonce,
    peerNonce: requesterSessionNonce,
    peerIdentityKey: hex(requesterKey),
    lastUpdate: Date.now(),
    certificatesRequired: false,
    certificatesValidated: true,
    certificatePolicy: { certifiers: [], types: {} }
  })
  const transport = new TextTransport(log)
  transport.other = { errors: [], callback: async () => {} }
  const peer = new Peer(wallet, transport, undefined, sessions)
  await peer.ready
  let received = null
  peer.listenForCertificatesRequested(async (sender, set) => { received = JSON.stringify(set) })
  let error = null
  try {
    await transport.callback(JSON.parse(text))
  } catch (e) {
    error = e
  }
  return {
    message_text: text,
    session_nonce: sessionNonce,
    requester_session_nonce: requesterSessionNonce,
    error: words(error),
    signatures_checked: log.verified,
    listener_received_policy_text: received
  }
}

const results = []
for (const c of cases) {
  results.push({
    name: c.name,
    given_types: c.given_types,
    policy_text: JSON.stringify(c.policy),
    constructor: { error: await constructorVerdict(c.policy) },
    sender: await senderVerdict(c.policy),
    receiver: await receiverVerdict(c.policy)
  })
}
const absent = await receiverVerdict(undefined)

console.log(JSON.stringify({
  issue: 'bsv-rs#294',
  description: 'The reference Peer\'s verdicts on a requested certificate set: constructor, a Peer built with the policy as its own (Peer.ts:158); sender, requestCertificates after a handshake (Peer.ts:434), signatures made and messages sent after the call; receiver, a signed certificateRequest carrying the policy handed to a Peer holding the requester\'s session (snapshotAuthMessage, Peer.ts:767; AuthMessageValidation.ts:345-346, :367). given_types is the order the policy was written in; policy_text is JSON.stringify of it (an integer-like key moves first).',
  node: process.version,
  reference: 'ts-stack@edf6e03 packages/sdk',
  keys: {
    requester: requesterKey.toHex(),
    verifier: verifierKey.toHex(),
    certifier: certifierKey.toHex()
  },
  cases: results,
  absent_requested_certificates: { receiver: absent }
}, null, 2))
