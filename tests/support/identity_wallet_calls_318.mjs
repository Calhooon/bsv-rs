// The #318 witnesses: the wallet calls the reference's IdentityClient makes
// (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts`), each
// with the originator it passes, for a client constructed with no originator
// (`:369-377`, the third argument absent) and for one constructed with
// `identity-client`; the arguments of `revokeCertificateRevelation`'s
// createAction and signAction (`:845-863`, `:896-911`) recorded as its wallet
// received them.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_wallet_calls_318.mjs \
//     "$W/sdk.mjs" > tests/vectors/identity_wallet_calls_318.json
//
// The certificate is the #310 and #315 witnesses' (certifier key 7, subject
// key 9, the same SHA-256 counter stream installed before the SDK loads), so
// two runs print the same file. The client's options name the network
// (`networkPreset: 'mainnet'`, this crate's default), so no getNetwork call is
// made. The reveal runs first, its createAction answering no transaction; the
// token its createAction carried is then the output of a source transaction
// (one made-up input, output 0 the token), which `LookupResolver.query`
// (replaced on the prototype, nothing leaves the process) answers for the
// revocation. The revocation's createAction answers a signable transaction
// spending output 0 of the source (the input's unlocking script empty, as a
// wallet hands a signable input out) to one `OP_FALSE OP_RETURN` output, and its
// signAction answers no transaction, so the reference throws `Failed to sign
// transaction`, aborts the action and stops before its broadcast.
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) {
    out.push(...createHash('sha256').update(`bsv-rs#310 ${counter++}`).digest())
  }
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath] = process.argv.slice(2)
const {
  IdentityClient, LookupResolver, MasterCertificate, ProtoWallet, PrivateKey, Script,
  Transaction, Utils
} = await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const pub = (n) => key(n).toPublicKey().toString()
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))
const issued = await MasterCertificate.issueCertificateForSubject(
  new ProtoWallet(key(7)),
  pub(9),
  { email: 'alice@example.com', name: 'Alice Example' },
  Utils.toBase64(new Array(32).fill(1)),
  async () => '00'.repeat(32) + '.0',
  Utils.toBase64(new Array(32).fill(2))
)
const certificate = {
  type: issued.type,
  subject: issued.subject,
  serialNumber: issued.serialNumber,
  certifier: issued.certifier,
  revocationOutpoint: issued.revocationOutpoint,
  signature: issued.signature,
  fields: { ...issued.fields }
}
const subjectWallet = new ProtoWallet(key(9))
const fieldsToReveal = ['email']
const keyring = await MasterCertificate.createKeyringForVerifier(
  subjectWallet, certificate.certifier, ANYONE, certificate.fields, fieldsToReveal,
  issued.masterKeyring, certificate.serialNumber
)

// The wallet: every call recorded by name with its originator; the key calls
// the subject's ProtoWallet's.
const recording = (state) => {
  const note = (name, originator) => state.calls.push({ name, originator: originator ?? null })
  return {
    async proveCertificate (args, o) { note('proveCertificate', o); return { keyringForVerifier: { ...keyring } } },
    async getPublicKey (args, o) { note('getPublicKey', o); return subjectWallet.getPublicKey(args) },
    async createSignature (args, o) { note('createSignature', o); return subjectWallet.createSignature(args) },
    async verifySignature (args, o) { note('verifySignature', o); return subjectWallet.verifySignature(args) },
    async createAction (args, o) {
      note('createAction', o)
      state.createAction.push(structuredClone(args))
      if (state.source === undefined) return {}
      const partial = new Transaction()
      partial.addInput({
        sourceTransaction: state.source,
        sourceOutputIndex: 0,
        unlockingScript: new Script(),
        sequence: 0xffffffff
      })
      partial.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a') })
      state.signable = partial.toAtomicBEEF(true)
      return { signableTransaction: { tx: state.signable, reference: REFERENCE } }
    },
    async signAction (args, o) {
      note('signAction', o)
      state.signAction.push(structuredClone(args))
      return {}
    },
    async abortAction (args, o) {
      note('abortAction', o)
      state.abortAction.push(structuredClone(args))
      return { aborted: true }
    }
  }
}

const witnesses = []
for (const [name, originator] of [['no_originator', undefined], ['configured', 'identity-client']]) {
  counter = 0
  const state = { calls: [], createAction: [], signAction: [], abortAction: [] }
  const client = new IdentityClient(recording(state), { networkPreset: 'mainnet' }, originator)

  try {
    await client.publiclyRevealAttributes(structuredClone(certificate), [...fieldsToReveal])
  } catch (e) {
    if (e.message !== 'Public reveal failed: failed to create action!') throw e
  }
  const revealCalls = state.calls.splice(0)
  const lockingScript = state.createAction.splice(0)[0].outputs[0].lockingScript

  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: Script.fromHex('51'),
    sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: Script.fromHex(lockingScript) })
  state.source = source
  const lookupBeef = source.toBEEF(true)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: lookupBeef, outputIndex: 0 }] }
  }

  let stopped = null
  try {
    await client.revokeCertificateRevelation(certificate.serialNumber)
  } catch (e) {
    stopped = e.message
  }
  if (stopped !== 'Failed to sign transaction') throw new Error(`unexpected stop: ${stopped}`)
  if (state.createAction.length !== 1 || state.signAction.length !== 1) {
    throw new Error('expected one createAction and one signAction')
  }

  witnesses.push({
    name,
    configured_originator: originator ?? null,
    reveal_calls: revealCalls,
    revoke_calls: state.calls,
    revoke_stopped: stopped,
    lookup_beef: lookupBeef,
    signable_tx: state.signable,
    signable_reference: REFERENCE,
    create_action: state.createAction[0],
    create_action_members: Object.keys(state.createAction[0]),
    create_action_input_members: Object.keys(state.createAction[0].inputs[0]),
    create_action_option_members: Object.keys(state.createAction[0].options),
    sign_action: state.signAction[0],
    sign_action_members: Object.keys(state.signAction[0]),
    sign_action_option_members: Object.keys(state.signAction[0].options),
    abort_action: state.abortAction[0]
  })
}

console.log(JSON.stringify({
  description: 'the originator IdentityClient passes on each wallet call (none when none is configured, the configured one otherwise) and the createAction and signAction arguments revokeCertificateRevelation sends (no label, no signAndProcess; returnTXIDOnly false; the reference as received) (#318)',
  reference: '@bsv/sdk at ts-stack@edf6e03 (bundled with bun build), run under Node ' + process.version + ' by tests/support/identity_wallet_calls_318.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/identity/IdentityClient.ts:369-377,471-477,502-528,711-730,804-813,845-863,884-911,942',
  keys: { certifier: 7, subject: 9 },
  certificate,
  fields_to_reveal: fieldsToReveal,
  keyring: { ...keyring },
  witnesses
}, null, 2))
