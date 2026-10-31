// #559: a contact's stored `abbreviatedKey` through this crate's update
// (`ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts`). The reference
// computes the value at one site, `IdentityClient.parseIdentity` (`IdentityClient.ts:1044`,
// `:1166`: `subject.substring(0, 10)...`); its contacts manager stores what it is
// given: `saveContact` (:527-528) and `#encryptAndLock` (:748-749) write
// `validateContact`'s record, `abbreviatedKey` the caller's (:185, `boundedString`
// to 256 characters, empty allowed). Recorded under Node v22.18.0:
//   cases[i].reference.save  the reference's saveContact of a contact whose
//                            abbreviatedKey is not this crate's computed form
//                            (`02abcd...wxyz`): its token, plaintext and
//                            getContacts' read of it
//   cases[i].reference.updated  that contact, its name changed: the record an
//                            update that keeps the stored value writes
//   crate.<side>[name]       this crate's token on <side> (tip, base): the
//                            reference's token read here, its name changed and
//                            saved through update_contact; read back by the
//                            reference's getContacts, with its verdict
//
// The entry re-exports ContactsManager, which `mod.ts` does not export:
//   W=/Volumes/Lanes/out/bsv-rs/fix-559-contact-abbreviated-key/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry559.ts" <<'EOF'
//   export * from './mod.js'
//   import { ContactsManager as CM559 } from './src/identity/ContactsManager.js'
//   export const ContactsManager559 = CM559
//   EOF
//   (cd "$W/packages/sdk" && bun build entry559.ts --target node --format esm --outfile "$W/sdk559.mjs")
// Two passes, as this crate's tokens read the reference's from the vector:
//   node tests/support/contact_abbreviated_key_559.mjs "$W/sdk559.mjs" > tests/vectors/contact_abbreviated_key_559.json
//   CONTACT_ABBREVIATED_KEY_559_OUT=$W/tokens-tip.json cargo test --features full \
//     --test identity_contact_abbreviated_key_559 -- --ignored --exact record_this_crates_tokens_559
//   (the same on a scratch copy of the base, to $W/tokens-base.json)
//   node tests/support/contact_abbreviated_key_559.mjs "$W/sdk559.mjs" $W/tokens-tip.json \
//     $W/tokens-base.json > tests/vectors/contact_abbreviated_key_559.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads,
// and every crate read comes after the reference's own records, so both passes
// print the same reference section. The wallet is the ProtoWallet of 9 in
// process; listOutputs answers the listing given; createAction records and stops.
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#559 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath, tipPath, basePath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { ContactsManager559: ContactsManager, ProtoWallet, PrivateKey, PushDrop, LockingScript, Utils } = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const STOP = 'bsv-rs#559 recorder: createAction recorded'
const CONTACT = [2, 'contact']

const contactsWallet = (state) => {
  const wallet = {}
  for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac',
    'verifyHmac', 'encrypt', 'decrypt']) {
    wallet[name] = async (args) => wallet9[name](args)
  }
  wallet.listOutputs = async () => state.listed ?? { totalOutputs: 0, outputs: [] }
  wallet.createAction = async (args) => { state.created = structuredClone(args); throw new Error(STOP) }
  return wallet
}
const readBack = async (lockingScript, customInstructions) => {
  const state = {
    listed: {
      totalOutputs: 1,
      outputs: [{
        outpoint: `${'22'.repeat(32)}.0`, satoshis: 1, lockingScript, spendable: true, customInstructions
      }]
    }
  }
  const dropped = []
  const warn = console.warn
  console.warn = (...args) => dropped.push(args[1] instanceof Error ? args[1].message : String(args[1]))
  try {
    const contacts = await new ContactsManager(contactsWallet(state)).getContacts(undefined, true)
    return { contacts, dropped }
  } finally {
    console.warn = warn
  }
}
// This crate's computed form (`Contact::to_displayable_identity`), which no
// case's stored value equals.
const computed = (k) => `${k.slice(0, 6)}...${k.slice(-4)}`

// Three stored values another client could set: parseIdentity's form, a
// caller's own text, and the empty string `boundedString` allows.
const CASES = [
  ['parse_identity', 3, (k) => `${k.substring(0, 10)}...`],
  ['caller_text', 5, () => 'Alice (work key)'],
  ['empty', 6, () => '']
]
const UPDATED_NAME = 'Alice Updated'

const out = { cases: [], crate: {} }
for (const [name, n, abbreviatedOf] of CASES) {
  const identityKey = key(n).toPublicKey().toString()
  const contact = {
    name: 'Alice Example',
    avatarURL: 'https://example.com/alice.png',
    abbreviatedKey: abbreviatedOf(identityKey),
    identityKey,
    badgeIconURL: '',
    badgeLabel: '',
    badgeClickURL: ''
  }
  if (contact.abbreviatedKey === computed(identityKey)) throw new Error(`${name}: the computed form`)
  const state = {}
  let words = null
  try { await new ContactsManager(contactsWallet(state)).saveContact(contact) } catch (e) { words = String(e.message) }
  if (words !== STOP) throw new Error(`saveContact: ${words}`)
  const output = state.created.outputs[0]
  const keyID = JSON.parse(output.customInstructions).keyID
  const [ciphertext] = PushDrop.decode(LockingScript.fromHex(output.lockingScript)).fields
  const plaintext = Utils.toUTF8((await wallet9.decrypt({ protocolID: CONTACT, keyID, counterparty: 'self', ciphertext })).plaintext)
  out.cases.push({
    name,
    computed_here: computed(identityKey),
    reference: {
      save: {
        contact,
        key_id: keyID,
        custom_instructions: output.customInstructions,
        locking_script: output.lockingScript,
        plaintext,
        read_back: await readBack(output.lockingScript, output.customInstructions)
      },
      updated: { ...contact, name: UPDATED_NAME }
    }
  })
}

const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b)
for (const [side, path] of [['tip', tipPath], ['base', basePath]]) {
  if (path === undefined) continue
  const tokens = JSON.parse(readFileSync(path, 'utf8'))
  out.crate[side] = {}
  for (const c of out.cases) {
    const token = tokens[c.name]
    const read = await readBack(token.locking_script, JSON.stringify({ keyID: token.key_id }))
    out.crate[side][c.name] = {
      key_id: token.key_id,
      locking_script: token.locking_script,
      read_back: read,
      equal: read.contacts.length === 1 && equal(read.contacts[0], c.reference.updated)
    }
  }
}
console.log(JSON.stringify(out, null, 2))
