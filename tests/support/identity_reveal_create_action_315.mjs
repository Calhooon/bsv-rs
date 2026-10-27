// The #315 witnesses: the createAction arguments the reference's
// `publiclyRevealAttributes` sends (`ts-stack@edf6e03`
// `packages/sdk/src/identity/IdentityClient.ts:513-528`), recorded from a
// wallet that keeps its createAction call, and how the reference's own
// argument validation (`validateCreateActionArgs`,
// `packages/sdk/src/wallet/validationHelpers.ts:749-806`) reads the options
// the call leaves out.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_reveal_create_action_315.mjs \
//     "$W/sdk.mjs" > tests/vectors/identity_reveal_create_action_315.json
//
// The certificate is the #310 witnesses' (`identity_reveal_rest_310.mjs`: the
// reference's `MasterCertificate.issueCertificateForSubject`, certifier key 7,
// subject key 9, the same SHA-256 counter stream installed before the SDK
// loads), so two runs print the same file. The wallet revealing is the
// subject's ProtoWallet of key 9; proveCertificate answers the keyring
// `createKeyringForVerifier` writes for the anyone key, createAction records
// its arguments and answers no transaction, so nothing is broadcast.
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
const { IdentityClient, MasterCertificate, ProtoWallet, PrivateKey, Utils, Validation } =
  await import(pathToFileURL(sdkPath).href)

const key = (n) => new PrivateKey(n)
const pub = (n) => key(n).toPublicKey().toString()
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
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

const witnesses = []
for (const [name, fieldsToReveal] of [
  ['email', ['email']],
  ['both_fields', ['email', 'name']]
]) {
  const keyring = await MasterCertificate.createKeyringForVerifier(
    subjectWallet, certificate.certifier, ANYONE, certificate.fields, fieldsToReveal,
    issued.masterKeyring, certificate.serialNumber
  )
  const created = []
  const wallet = {
    async proveCertificate () { return { keyringForVerifier: { ...keyring } } },
    async getPublicKey (args) { return subjectWallet.getPublicKey(args) },
    async createSignature (args) { return subjectWallet.createSignature(args) },
    async createAction (args, originator) {
      created.push({ args: structuredClone(args), originator })
      return {}
    }
  }
  const client = new IdentityClient(wallet, {}, 'identity-client')
  try {
    await client.publiclyRevealAttributes(structuredClone(certificate), [...fieldsToReveal])
  } catch (e) {
    if (e.message !== 'Public reveal failed: failed to create action!') throw e
  }
  if (created.length !== 1) throw new Error(`expected one createAction call, got ${created.length}`)
  const [{ args, originator }] = created
  const validated = Validation.validateCreateActionArgs(args)
  witnesses.push({
    name,
    fields_to_reveal: fieldsToReveal,
    keyring: { ...keyring },
    originator,
    create_action: args,
    members: Object.keys(args),
    output_members: Object.keys(args.outputs[0]),
    option_members: Object.keys(args.options),
    validated_options: {
      signAndProcess: validated.options.signAndProcess,
      acceptDelayedBroadcast: validated.options.acceptDelayedBroadcast,
      randomizeOutputs: validated.options.randomizeOutputs,
      noSend: validated.options.noSend,
      isDelayed: validated.isDelayed,
      isSendWith: validated.isSendWith,
      isNewTx: validated.isNewTx,
      isSignAction: validated.isSignAction,
      labels: validated.labels,
      output_tags: validated.outputs[0].tags,
      output_basket: validated.outputs[0].basket ?? null
    }
  })
}

console.log(JSON.stringify({
  description: 'the createAction arguments publiclyRevealAttributes sends (description, one output of satoshis, lockingScript and outputDescription, options randomizeOutputs false, nothing else) and the reference validation\'s reading of what it leaves out (#315)',
  reference: '@bsv/sdk at ts-stack@edf6e03 (bundled with bun build), run under Node ' + process.version + ' by tests/support/identity_reveal_create_action_315.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/identity/IdentityClient.ts:513-528; packages/sdk/src/wallet/validationHelpers.ts:651-668,749-806',
  keys: { certifier: 7, subject: 9 },
  certificate,
  witnesses
}, null, 2))
