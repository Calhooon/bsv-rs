// The #310 witnesses: the identity token the reference's `publiclyRevealAttributes`
// builds and the overlay's identity reader admits (`ts-stack@edf6e03`
// `packages/sdk/src/identity/IdentityClient.ts:501-537`), and its refusal when
// createAction answers no transaction (`:537`).
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/overlays/topics/src/identity | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   mkdir -p "$W/node_modules/@bsv/sdk"; ln -s "$W/packages/sdk/mod.ts" "$W/packages/sdk/src" "$W/node_modules/@bsv/sdk/"
//   echo '{"name":"@bsv/sdk","type":"module","exports":{".":"./mod.ts","./primitives/utils":"./src/primitives/utils.ts"}}' \
//     > "$W/node_modules/@bsv/sdk/package.json"
//   (cd "$W/packages/overlays/topics/src/identity" && bun build identityTokenValidation.ts --target node --format esm --outfile "$W/reader.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_reveal_rest_310.mjs \
//     "$W/sdk.mjs" "$W/reader.mjs" > tests/vectors/identity_reveal_rest_310.json
//
// The certificate is issued by the reference's
// `MasterCertificate.issueCertificateForSubject` (certifier key 7, subject key
// 9, plaintexts `email` and `name`), the randomness a SHA-256 counter stream
// installed before the SDK loads, so two runs print the same file. The wallet
// revealing is the subject's (a ProtoWallet of key 9, as the reader asks: the
// token's key is the subject's), proveCertificate answering the keyring
// `createKeyringForVerifier` writes for the anyone key in the order asked,
// createAction capturing its arguments and answering no transaction. Each
// witness records the reference's wallet calls with their arguments, the
// locking script, the refusal, and the verdict of the overlay's reader
// (`packages/overlays/topics/src/identity/identityTokenValidation.ts:92-154`,
// called by `IdentityTopicManager.ts:24`) with the plaintexts it decrypts. One
// more witness records the reader's verdict on the token this crate built
// before #310: unsigned, its key `forSelf: false`.
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

const [sdkPath, readerPath] = process.argv.slice(2)
const { IdentityClient, LockingScript, MasterCertificate, ProtoWallet, PrivateKey, PushDrop, Utils } =
  await import(pathToFileURL(sdkPath).href)
const { validateIdentityOutput } = await import(pathToFileURL(readerPath).href)

const key = (n) => new PrivateKey(n)
const pub = (n) => key(n).toPublicKey().toString()
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const plaintexts = { email: 'alice@example.com', name: 'Alice Example' }
const issued = await MasterCertificate.issueCertificateForSubject(
  new ProtoWallet(key(7)),
  pub(9),
  plaintexts,
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

const hexArgs = (args) => {
  const out = { ...args }
  if (Array.isArray(out.data)) out.data = Utils.toHex(out.data)
  return out
}

async function reader (lockingScriptHex) {
  try {
    const { decryptedFields } = await validateIdentityOutput(
      { lockingScript: LockingScript.fromHex(lockingScriptHex), satoshis: 1 },
      new ProtoWallet('anyone')
    )
    return { admitted: true, decrypted_fields: decryptedFields }
  } catch (e) {
    return { admitted: false, refusal: e.message }
  }
}

const witnesses = []
for (const [name, fieldsToReveal] of [
  ['email', ['email']],
  ['both_fields', ['email', 'name']],
  ['both_fields_name_first', ['name', 'email']]
]) {
  const keyring = await MasterCertificate.createKeyringForVerifier(
    subjectWallet, certificate.certifier, ANYONE, certificate.fields, fieldsToReveal,
    issued.masterKeyring, certificate.serialNumber
  )
  const calls = []
  let created
  const wallet = {
    async proveCertificate (args) {
      calls.push({ method: 'proveCertificate', args: { fieldsToReveal: args.fieldsToReveal, verifier: args.verifier } })
      return { keyringForVerifier: { ...keyring } }
    },
    async getPublicKey (args) {
      calls.push({ method: 'getPublicKey', args: hexArgs(args) })
      return subjectWallet.getPublicKey(args)
    },
    async createSignature (args) {
      calls.push({ method: 'createSignature', args: hexArgs(args) })
      return subjectWallet.createSignature(args)
    },
    async createAction (args) {
      calls.push({ method: 'createAction' })
      created = args
      return {}
    }
  }
  const client = new IdentityClient(wallet, {}, 'identity-client')
  let refusal = null
  let refusalName = null
  try {
    await client.publiclyRevealAttributes(structuredClone(certificate), [...fieldsToReveal])
  } catch (e) {
    refusal = e.message
    refusalName = e.name
  }
  const lockingScript = created.outputs[0].lockingScript
  const decoded = PushDrop.decode(LockingScript.fromHex(lockingScript))
  witnesses.push({
    name,
    fields_to_reveal: fieldsToReveal,
    keyring: { ...keyring },
    wallet_calls: calls,
    create_action: created,
    locking_script: lockingScript,
    published_json: Utils.toUTF8(decoded.fields[0]),
    signature: Utils.toHex(decoded.fields[1]),
    refusal,
    refusal_name: refusalName,
    reader: await reader(lockingScript)
  })
}

// The token this crate built before #310: the JSON alone, its key `forSelf: false`.
const unsigned = await new PushDrop(subjectWallet).lock(
  [Utils.toArray(witnesses[0].published_json, 'utf8')], [1, 'identity'], '1', 'anyone', false, false
)

console.log(JSON.stringify({
  description: 'the identity token publiclyRevealAttributes builds (a PushDrop signed by the subject under [1, identity] key 1 for anyone, its key forSelf), admitted by the overlay\'s identity reader, and the refusal when createAction answers no transaction (#310)',
  reference: '@bsv/sdk and packages/overlays/topics at ts-stack@edf6e03 (bundled with bun build), run under Node ' + process.version + ' by tests/support/identity_reveal_rest_310.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/identity/IdentityClient.ts:501-537; packages/sdk/src/script/templates/PushDrop.ts:146-202; packages/overlays/topics/src/identity/identityTokenValidation.ts:92-154',
  keys: { certifier: 7, subject: 9 },
  plaintexts,
  certificate,
  witnesses,
  unsigned_token: {
    origin: 'the token this crate built before #310: PushDrop.lock([json], [1, identity], 1, anyone, forSelf false, includeSignature false)',
    locking_script: unsigned.toHex(),
    reader: await reader(unsigned.toHex())
  }
}, null, 2))
