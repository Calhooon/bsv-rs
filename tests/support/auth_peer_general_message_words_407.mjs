// #407: record what the actual reference Peer propagates from its wallet.
// Build the pinned clones, without modifying them or using installed packages:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$STACK"
//   (cd "$STACK/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$STACK/sdk.mjs")
//   git -C ~/bsv/ts-sdk archive 9e3ede6b | tar -x -C "$SDK"
//   (cd "$SDK" && bun build mod.ts --target node --format esm --outfile "$SDK/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/auth_peer_general_message_words_407.mjs \
//     "$STACK/sdk.mjs" "$SDK/sdk.mjs" > tests/vectors/auth_peer_general_message_words_407.json
//
// Each case completes an honest handshake through two reference Peers, then
// delivers one general message through the registered transport callback.
// The answering wallet is explicitly an adapter: ProtoWallet itself throws.
// Record only deterministic inputs and verdicts, not random handshake nonces.
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const paths = process.argv.slice(2)
if (paths.length !== 2) throw new Error('Expected ts-stack and ts-sdk bundles')
const refs = ['ts-stack@edf6e03', 'ts-sdk@9e3ede6b']
const malformed = Array.from(Buffer.from('not a signature', 'utf8'))

class Wire {
  async onData (callback) { this.callback = callback }
  async send (message) {
    const copy = JSON.parse(JSON.stringify(message))
    setTimeout(() => this.other.callback(copy).catch(() => {}), 0)
  }
  async deliver (message) {
    try {
      await this.callback(JSON.parse(JSON.stringify(message)))
      return { error: null }
    } catch (e) {
      return { error: e.message, ...(e.code === undefined ? {} : { code: e.code }) }
    }
  }
}

async function record (path) {
  const { Peer, ProtoWallet, PrivateKey, Utils } = await import(pathToFileURL(path).href)
  const client = new PrivateKey(41)
  const server = new PrivateKey(42)
  const stranger = new PrivateKey(43)
  const hex = key => key.toPublicKey().toString()
  class AnsweringWallet extends ProtoWallet {
    async verifySignature (args) {
      try { return await super.verifySignature(args) } catch { return { valid: false } }
    }
  }

  async function general (kind, answering) {
    const toServer = new Wire()
    const toClient = new Wire()
    toServer.other = toClient
    toClient.other = toServer
    const receiverWallet = answering ? new AnsweringWallet(client) : new ProtoWallet(client)
    const receiver = new Peer(receiverWallet, toServer, undefined, undefined, false)
    const sender = new Peer(new ProtoWallet(server), toClient, undefined, undefined, false)
    await receiver.ready
    await sender.ready
    let delivered = 0
    receiver.listenForGeneralMessages(() => { delivered++ })
    const session = await receiver.getAuthenticatedSession(hex(server))
    const nonce = Utils.toBase64(new Array(32).fill(7))
    const args = {
      data: [1, 2, 3],
      protocolID: [2, 'auth message signature'],
      keyID: `${nonce} ${session.sessionNonce}`,
      counterparty: hex(client)
    }
    const signer = kind === 'other_key' ? stranger : server
    const { signature } = await new ProtoWallet(signer).createSignature(args)
    const verdict = await toServer.deliver({
      version: '0.1', messageType: 'general', identityKey: hex(server),
      nonce, yourNonce: session.sessionNonce, payload: args.data,
      signature: kind === 'malformed' ? malformed : signature
    })
    return { ...verdict, delivered }
  }

  const cases = {}
  for (const kind of ['honest', 'other_key', 'malformed']) {
    cases[kind] = {
      proto: await general(kind, false),
      answering: await general(kind, true)
    }
  }
  return { identities: { client: hex(client), server: hex(server), stranger: hex(stranger) }, cases }
}

const references = {}
for (let i = 0; i < paths.length; i++) references[refs[i]] = await record(paths[i])
process.stdout.write(JSON.stringify({
  node: process.version,
  keys: { client: 41, server: 42, stranger: 43 },
  malformed,
  references
}, null, 2) + '\n')
