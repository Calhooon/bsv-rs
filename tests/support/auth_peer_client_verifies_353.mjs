// The #353 witnesses: the reference Peer's verdict on a client's initial
// response and general messages from a forging server.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/upstream/bsv-blockchain/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/auth_peer_client_verifies_353.mjs "$W/sdk.mjs" \
//     > tests/vectors/auth_peer_client_verifies_353.json
//
// A reference client `Peer` (scalar 41) asks for a session pinned to the
// server (scalar 42). For each initial-response case the script answers its
// initialRequest itself, forging one field, and records what the client's
// `onData` callback throws (`Peer.ts:886-930`). For each general-message
// case an honest reference server `Peer` completes the handshake, then the
// script hands the client a general message from the server's key forging
// one field, and records the verdict (`Peer.ts:1270-1314`). `null` is
// accepted. Each case runs with the client on a `ProtoWallet` (`proto`), whose
// `verifySignature` and `verifyHmac` throw on a miss, and on one that answers
// `{ valid: false }` instead (`answering`), so the Peer's own words are
// reached. `tests/auth_peer_client_verifies_353.rs` asserts this crate's
// `Peer::start` gives each verdict, in the same words save the stated ones.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { Peer, ProtoWallet, PrivateKey, createNonce, Utils } = sdk

const SIGNED = [2, 'auth message signature']
const clientKey = new PrivateKey(41)
const serverKey = new PrivateKey(42)
const malloryKey = new PrivateKey(43)
const hex = k => k.toPublicKey().toString()
const wallet = k => new ProtoWallet(k)

// A wallet that answers a miss rather than throwing it
class AnsweringWallet extends ProtoWallet {
  async verifySignature (args, originator) {
    try { return await super.verifySignature(args, originator) } catch { return { valid: false } }
  }

  async verifyHmac (args, originator) {
    try { return await super.verifyHmac(args, originator) } catch { return { valid: false } }
  }
}
let clientWallet = wallet

// One end of an in-memory pair; `deliver` hands the other side a message
// and returns its verdict
class Wire {
  constructor () { this.sent = [] }
  async send (message) {
    const text = JSON.stringify(message)
    this.sent.push(JSON.parse(text))
    if (this.other?.callback != null) {
      setTimeout(() => { this.other.callback(JSON.parse(text)).catch(() => {}) }, 0)
    }
  }

  async onData (callback) { this.callback = callback }
  async deliver (message) {
    try {
      await this.callback(JSON.parse(JSON.stringify(message)))
      return null
    } catch (e) {
      return String(e.message ?? e)
    }
  }
}

const tick = () => new Promise(resolve => setTimeout(resolve, 20))
const sign = async (key, counterparty, keyID, data) =>
  (await wallet(key).createSignature({ data, protocolID: SIGNED, keyID, counterparty }, 'test')).signature

// The client's initialRequest, answered by `respond`
async function initialCase (pinned, respond) {
  const wire = new Wire()
  const client = new Peer(clientWallet(clientKey), wire, undefined, undefined, false)
  await client.ready
  const handshake = client.getAuthenticatedSession(pinned)
  handshake.catch(() => {})
  await tick()
  const request = wire.sent.find(m => m.messageType === 'initialRequest')
  return await wire.deliver(await respond(request.initialNonce))
}

async function initialResponse (responder, yourNonce, { keyID, nonceOf = responder } = {}) {
  const responderNonce = await createNonce(wallet(nonceOf), undefined, 'test')
  const data = [...Utils.toArray(yourNonce, 'base64'), ...Utils.toArray(responderNonce, 'base64')]
  return {
    version: '0.1',
    messageType: 'initialResponse',
    identityKey: hex(responder),
    initialNonce: responderNonce,
    yourNonce,
    signature: await sign(responder, hex(clientKey), keyID ?? `${yourNonce} ${responderNonce}`, data)
  }
}

// An honest handshake with a reference server, then `forge` the general message
async function generalCase (forge) {
  const toServer = new Wire()
  const toClient = new Wire()
  toServer.other = toClient
  toClient.other = toServer
  const client = new Peer(clientWallet(clientKey), toServer, undefined, undefined, false)
  const server = new Peer(wallet(serverKey), toClient, undefined, undefined, false)
  await client.ready
  await server.ready
  const session = await client.getAuthenticatedSession(hex(serverKey))
  const payload = [1, 2, 3]
  const nonce = Utils.toBase64(new Array(32).fill(7))
  const message = {
    version: '0.1',
    messageType: 'general',
    identityKey: hex(serverKey),
    nonce,
    yourNonce: session.sessionNonce,
    payload,
    signature: await sign(serverKey, hex(clientKey), `${nonce} ${session.sessionNonce}`, payload)
  }
  return await toServer.deliver(await forge(message, session))
}

const run = async () => ({
  initial_response_honest: await initialCase(hex(serverKey), n => initialResponse(serverKey, n)),
  initial_response_wrong_signature: await initialCase(hex(serverKey), n =>
    initialResponse(serverKey, n, { keyID: `${n} not-the-nonce` })),
  initial_response_another_identity: await initialCase(hex(serverKey), n => initialResponse(malloryKey, n)),
  initial_response_wrong_nonce: await initialCase(hex(serverKey), async () =>
    initialResponse(serverKey, await createNonce(wallet(serverKey), undefined, 'test'))),
  general_honest: await generalCase(m => m),
  general_wrong_your_nonce: await generalCase(async m =>
    ({ ...m, yourNonce: await createNonce(wallet(serverKey), undefined, 'test') })),
  general_no_nonce: await generalCase(async (m, s) => {
    const { nonce, ...rest } = m
    return { ...rest, signature: await sign(serverKey, hex(clientKey), ` ${s.sessionNonce}`, m.payload) }
  }),
  general_wrong_signature: await generalCase(async (m, s) =>
    ({ ...m, signature: await sign(malloryKey, hex(clientKey), `${m.nonce} ${s.sessionNonce}`, m.payload) })),
  general_another_identity: await generalCase(async (m, s) =>
    ({
      ...m,
      identityKey: hex(malloryKey),
      signature: await sign(malloryKey, hex(clientKey), `${m.nonce} ${s.sessionNonce}`, m.payload)
    }))
})

const proto = await run()
clientWallet = k => new AnsweringWallet(k)
const answering = await run()
const cases = Object.fromEntries(
  Object.keys(proto).map(name => [name, { proto: proto[name], answering: answering[name] }])
)

process.stdout.write(JSON.stringify({
  source: '@bsv/sdk at ts-stack@edf6e03 (packages/sdk/src/auth/Peer.ts), Node v22.18.0',
  keys: { client: 41, server: 42, mallory: 43 },
  identities: { client: hex(clientKey), server: hex(serverKey), mallory: hex(malloryKey) },
  cases
}, null, 2) + '\n')
process.exit(0)
