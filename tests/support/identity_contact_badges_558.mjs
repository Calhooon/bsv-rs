// #558: an identity's badges through the reference's two conversions and this
// crate's (`ts-stack@edf6e03` `packages/sdk/src/identity/`; the keeper's reading
// of 2026-10-31 13:1xZ). The reference's contact is its identity
// (`ContactsManager.ts:28`, `Contact = DisplayableIdentity & { metadata? }`), so
// neither direction is a function there: `IdentityClient.saveContact`
// (`IdentityClient.ts:974-979`) hands the identity to `ContactsManager.saveContact`
// (`ContactsManager.ts:527-528`), whose `validateContact` (`:171-198`) keeps every
// display field, the badges as given; `resolveByIdentityKey` with contacts
// (`IdentityClient.ts:559-591`, `:575-576`) returns the contacts read as the
// identities, the stored badges as stored. Recorded under Node v22.18.0, per case:
//   identity   the identity handed to IdentityClient.saveContact
//   saved      the record its token carries (#encryptAndLock :748-772), decrypted
//   resolved   resolveByIdentityKey({ identityKey }, { useContacts: true })'s
//              answer with that token listed: the contact as the identity
// Each identity's abbreviatedKey is the one this crate computes (#559 is the
// stored abbreviated key's own row), so the whole record compares.
//
// The entry re-exports ContactsManager, which `mod.ts` does not export:
//   W=<lane folder>/ref-558
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry558.ts" <<'EOF'
//   export * from './mod.js'
//   import { ContactsManager as CM558 } from './src/identity/ContactsManager.js'
//   export const ContactsManager558 = CM558
//   EOF
//   (cd "$W/packages/sdk" && bun build entry558.ts --target node --format esm --outfile "$W/sdk558.mjs")
//   node tests/support/identity_contact_badges_558.mjs "$W/sdk558.mjs" > tests/vectors/identity_contact_badges_558.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads.
// The wallet is the ProtoWallet of 9 in process; listOutputs answers the
// listing given; createAction records and stops. No network, no port.
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#558 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { IdentityClient, ProtoWallet, PrivateKey, PushDrop, LockingScript, Utils, defaultIdentity } = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const STOP = 'bsv-rs#558 recorder: createAction recorded'
const CONTACT = [2, 'contact']

const contactsWallet = (state) => {
  const wallet = {}
  for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac',
    'verifyHmac', 'encrypt', 'decrypt']) {
    wallet[name] = async (args) => wallet9[name](args)
  }
  wallet.listOutputs = async () => state.listed ?? { totalOutputs: 0, outputs: [] }
  wallet.createAction = async (args) => { state.created = structuredClone(args); throw new Error(STOP) }
  wallet.discoverByIdentityKey = async () => { throw new Error('bsv-rs#558 recorder: no discovery') }
  return wallet
}
// The abbreviated key as this crate computes it (`Contact::to_displayable_identity`).
const abbreviated = (k) => `${k.slice(0, 6)}...${k.slice(-4)}`
const identityOf = (n, display) => {
  const identityKey = key(n).toPublicKey().toString()
  return { ...display, abbreviatedKey: abbreviated(identityKey), identityKey }
}

const cases = [
  ['badged', identityOf(3, {
    name: 'Alice Example',
    avatarURL: 'https://example.com/alice.png',
    badgeIconURL: 'https://example.com/badge.png',
    badgeLabel: 'Email certified by Example',
    badgeClickURL: 'https://example.com/verify'
  })],
  ['reference_defaults', identityOf(4, {
    name: 'Bob Example',
    avatarURL: defaultIdentity.avatarURL,
    badgeIconURL: defaultIdentity.badgeIconURL,
    badgeLabel: defaultIdentity.badgeLabel,
    badgeClickURL: defaultIdentity.badgeClickURL
  })],
  ['empty_badges', identityOf(5, {
    name: 'Carol Example',
    avatarURL: 'https://example.com/carol.png',
    badgeIconURL: '',
    badgeLabel: '',
    badgeClickURL: ''
  })]
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
