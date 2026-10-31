// #568: an identity's `abbreviatedKey` through the reference's save and read of a
// contact (`ts-stack@edf6e03` `packages/sdk/src/identity/`; the keeper's ruling (4)
// of 2026-10-31 17:1xZ). The reference's contact is its identity
// (`ContactsManager.ts:28`, `Contact = DisplayableIdentity & { metadata? }`):
// `IdentityClient.saveContact` (`IdentityClient.ts:974-979`) hands the identity to
// `ContactsManager.saveContact` (`ContactsManager.ts:527-528`), whose
// `validateContact` (`:171-198`) keeps `abbreviatedKey` as given (`:185`,
// `boundedString` to 256, empty allowed; an absent one refused by `ownData`,
// `:47-53`, so a reference record always carries one), and `resolveByIdentityKey`
// with contacts (`IdentityClient.ts:575-576`) returns the record read as the
// identity. The value is computed at one site, `parseIdentity` (`:1166`,
// `subject.substring(0, 10)...`), never this crate's `Contact` form
// (`02abcd...wxyz`). Recorded under Node v22.18.0, per case:
//   identity   the identity handed to IdentityClient.saveContact
//   saved      the record its token carries (#encryptAndLock :748-772), decrypted
//   resolved   resolveByIdentityKey({ identityKey }, { useContacts: true })'s
//              answer with that token listed: the contact as the identity
//
//   W=/Volumes/Lanes/out/bsv-rs/fix-568-from-identity-abbreviated-key/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf "export * from './mod.js'\n" > "$W/packages/sdk/entry568.ts"
//   (cd "$W/packages/sdk" && bun build entry568.ts --target node --format esm --outfile "$W/sdk568.mjs")
//   node tests/support/from_identity_abbreviated_key_568.mjs "$W/sdk568.mjs" > tests/vectors/from_identity_abbreviated_key_568.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads.
// The wallet is the ProtoWallet of 9 in process; listOutputs answers the
// listing given; createAction records and stops. No network, no port.
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#568 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { IdentityClient, ProtoWallet, PrivateKey, PushDrop, LockingScript, Utils, KNOWN_IDENTITY_TYPES } = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const STOP = 'bsv-rs#568 recorder: createAction recorded'
const CONTACT = [2, 'contact']

const contactsWallet = (state) => {
  const wallet = {}
  for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac',
    'verifyHmac', 'encrypt', 'decrypt']) {
    wallet[name] = async (args) => wallet9[name](args)
  }
  wallet.listOutputs = async () => state.listed ?? { totalOutputs: 0, outputs: [] }
  wallet.createAction = async (args) => { state.created = structuredClone(args); throw new Error(STOP) }
  wallet.discoverByIdentityKey = async () => { throw new Error('bsv-rs#568 recorder: no discovery') }
  return wallet
}

// The identity the reference's parseIdentity gives for an email certificate
// of subject n: its abbreviatedKey `subject.substring(0, 10)...`.
const parsed = (n, email) => IdentityClient.parseIdentity({
  type: KNOWN_IDENTITY_TYPES.emailCert,
  subject: key(n).toPublicKey().toString(),
  decryptedFields: { email },
  certifierInfo: { name: 'Example Certifier', iconUrl: 'https://example.com/certifier.png' }
})

const cases = [
  ['parsed_identity', parsed(3, 'alice@example.com')],
  ['another_clients_text', { ...parsed(4, 'bob@example.com'), abbreviatedKey: 'Bob (desk 4)' }],
  ['empty', { ...parsed(5, 'carol@example.com'), abbreviatedKey: '' }]
]

const out = { cases: [] }
for (const [name, identity] of cases) {
  const state = {}
  let words = null
  try { await new IdentityClient(contactsWallet(state)).saveContact(identity) } catch (e) { words = String(e.message) }
  if (words !== STOP) throw new Error(`${name} saveContact: ${words}`)
  const output = state.created.outputs[0]
  const keyID = JSON.parse(output.customInstructions).keyID
  const [ciphertext] = PushDrop.decode(LockingScript.fromHex(output.lockingScript)).fields
  const saved = JSON.parse(Utils.toUTF8((await wallet9.decrypt({
    protocolID: CONTACT, keyID, counterparty: 'self', ciphertext
  })).plaintext))
  const listing = {
    listed: {
      totalOutputs: 1,
      outputs: [{
        outpoint: `${'22'.repeat(32)}.0`,
        satoshis: 1,
        lockingScript: output.lockingScript,
        spendable: true,
        customInstructions: output.customInstructions
      }]
    }
  }
  const resolved = await new IdentityClient(contactsWallet(listing))
    .resolveByIdentityKey({ identityKey: identity.identityKey }, { useContacts: true })
  if (resolved.length !== 1) throw new Error(`${name}: ${resolved.length} identities resolved`)
  out.cases.push({
    name,
    identity,
    key_id: keyID,
    custom_instructions: output.customInstructions,
    locking_script: output.lockingScript,
    saved,
    resolved: resolved[0]
  })
}
console.log(JSON.stringify(out, null, 2))
