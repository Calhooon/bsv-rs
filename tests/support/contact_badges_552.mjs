// #552: a contact's three badge fields through the reference's ContactsManager
// and this crate's (`ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts`;
// the keeper's reading of 2026-10-31 12:1xZ). `validateContact` (:171-192) takes
// every display field (:35-43) through `ownData` (:47-53) and its validator, so a
// record the reference reads carries `badgeIconURL`, `badgeLabel` and
// `badgeClickURL` as strings. Recorded under Node v22.18.0:
//   reference.save   the reference's saveContact of a contact with the three badges
//                    set: its token (#encryptAndLock :748-772), its plaintext, and
//                    getContacts' read of it (:475-514)
//   reverse.contact  the record this crate's add_contact is handed for the reverse
//   crate.<side>     this crate's tokens on <side> (tip, base): `update`, the
//                    reference's token read by this crate, its name changed and
//                    saved through update_contact; `save`, reverse.contact saved by
//                    add_contact; each read back by the reference's getContacts,
//                    with its verdict: the record read equals the one expected
//
// The entry re-exports ContactsManager, which `mod.ts` does not export:
//   W=$TMPDIR/ref-552
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry552.ts" <<'EOF'
//   export * from './mod.js'
//   import { ContactsManager as CM552 } from './src/identity/ContactsManager.js'
//   export const ContactsManager552 = CM552
//   EOF
//   (cd "$W/packages/sdk" && bun build entry552.ts --target node --format esm --outfile "$W/sdk552.mjs")
// Two passes, as this crate's tokens read the reference's from the vector:
//   node tests/support/contact_badges_552.mjs "$W/sdk552.mjs" > tests/vectors/contact_badges_552.json
//   CONTACT_BADGES_552_OUT=$TMPDIR/tokens-tip.json cargo test --features full \
//     --test identity_contact_badges_552 -- --ignored --exact record_this_crates_tokens_552
//   (the same on a scratch copy of the base, to $TMPDIR/tokens-base.json)
//   node tests/support/contact_badges_552.mjs "$W/sdk552.mjs" $TMPDIR/tokens-tip.json \
//     $TMPDIR/tokens-base.json > tests/vectors/contact_badges_552.json
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
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#552 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath, tipPath, basePath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { ContactsManager552: ContactsManager, ProtoWallet, PrivateKey, PushDrop, LockingScript, Utils } = sdk

const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const STOP = 'bsv-rs#552 recorder: createAction recorded'
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
// The abbreviated key as this crate computes it (`Contact::to_displayable_identity`),
// so the field this crate does not hold reads back the same.
const abbreviated = (k) => `${k.slice(0, 6)}...${k.slice(-4)}`

const identityKey = key(3).toPublicKey().toString()
const contact = {
  name: 'Alice Example',
  avatarURL: 'https://example.com/alice.png',
  abbreviatedKey: abbreviated(identityKey),
  identityKey,
  badgeIconURL: 'https://example.com/badge.png',
  badgeLabel: 'Verified by Example',
  badgeClickURL: 'https://example.com/verify'
}
const UPDATED_NAME = 'Alice Updated'
const reverseKey = key(4).toPublicKey().toString()
const reverse = {
  name: 'Bob Example',
  avatarURL: '',
  abbreviatedKey: abbreviated(reverseKey),
  identityKey: reverseKey,
  badgeIconURL: 'https://example.com/bob-badge.png',
  badgeLabel: 'Met in person',
  badgeClickURL: 'https://example.com/bob'
}

const out = { reference: {}, reverse: { contact: reverse }, crate: {} }
{
  const state = {}
  let words = null
  try { await new ContactsManager(contactsWallet(state)).saveContact(contact) } catch (e) { words = String(e.message) }
  if (words !== STOP) throw new Error(`saveContact: ${words}`)
  const output = state.created.outputs[0]
  const keyID = JSON.parse(output.customInstructions).keyID
  const [ciphertext] = PushDrop.decode(LockingScript.fromHex(output.lockingScript)).fields
  const plaintext = Utils.toUTF8((await wallet9.decrypt({ protocolID: CONTACT, keyID, counterparty: 'self', ciphertext })).plaintext)
  out.reference.save = {
    contact,
    key_id: keyID,
    custom_instructions: output.customInstructions,
    locking_script: output.lockingScript,
    plaintext,
    read_back: await readBack(output.lockingScript, output.customInstructions)
  }
  out.reference.updated = { ...contact, name: UPDATED_NAME }
}

const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b)
for (const [side, path] of [['tip', tipPath], ['base', basePath]]) {
  if (path === undefined) continue
  const tokens = JSON.parse(readFileSync(path, 'utf8'))
  out.crate[side] = {}
  for (const [name, expected] of [['update', out.reference.updated], ['save', reverse]]) {
    const token = tokens[name]
    const read = await readBack(token.locking_script, JSON.stringify({ keyID: token.key_id }))
    out.crate[side][name] = {
      key_id: token.key_id,
      locking_script: token.locking_script,
      read_back: read,
      equal: read.contacts.length === 1 && equal(read.contacts[0], expected)
    }
  }
}
console.log(JSON.stringify(out, null, 2))
