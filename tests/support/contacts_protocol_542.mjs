// #542: the contact protocol the reference's ContactsManager uses for every
// contact operation, `[2, 'contact']` with counterparty 'self'
// (`ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts:30`; the
// identity tag's HMAC `:572-583`, the encryption `:748-772`, the token's lock
// `:767-772`, its authentication `:431-472`, the decryption `:494-501`, the
// spend `:821-830`), recorded with the reference's own writer and reader.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules); `mod.ts`
// does not export ContactsManager, so the entry re-exports it:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry542.ts" <<'EOF'
//   export * from './mod.js'
//   import { ContactsManager as CM542 } from './src/identity/ContactsManager.js'
//   export const ContactsManager542 = CM542
//   EOF
//   (cd "$W/packages/sdk" && bun build entry542.ts --target node --format esm --outfile "$W/sdk542.mjs")
// This crate's own tokens are an input, written by the ignored recorder of
// `tests/identity_contacts_protocol_542.rs` on the base and on the tip
// (`CONTACTS_542_OUT=<file> cargo test --features identity --test
// identity_contacts_protocol_542 -- --ignored --exact record_this_crates_contact_token_542`),
// gathered as `{"base": <file>, "tip": <file>}`:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/contacts_protocol_542.mjs \
//     "$W/sdk542.mjs" crate.json > tests/vectors/contacts_protocol_542.json
//
// The randomness is #310's SHA-256 counter stream, installed before the SDK
// loads, so two runs print the same file (the key ID and the IV). The wallet
// is the ProtoWallet of the scalar 9 under a recorder: listOutputs answers the
// listing set, else none; createAction records its arguments and throws, so
// saveContact stops after the reference has written its token.
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
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

const [sdkPath, cratePath] = process.argv.slice(2)
const {
  ContactsManager542: ContactsManager, ProtoWallet, PrivateKey, PushDrop, LockingScript, Utils
} = await import(pathToFileURL(sdkPath).href)

const PROTOCOL = [2, 'contact']
const LEVEL_ONE = [1, 'contact']
const STOP = 'bsv-rs#542 recorder: createAction recorded'

const recording = (state) => {
  const inner = new ProtoWallet(new PrivateKey(9))
  const wallet = {}
  for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac',
    'verifyHmac', 'encrypt', 'decrypt']) {
    wallet[name] = async (args) => inner[name](args)
  }
  wallet.listOutputs = async () => state.listed ?? { totalOutputs: 0, outputs: [] }
  wallet.createAction = async (args) => {
    state.createAction.push(structuredClone(args))
    throw new Error(STOP)
  }
  return { inner, wallet }
}

const words = async (run) => {
  try {
    return { value: await run() }
  } catch (e) {
    return { error: String(e.message) }
  }
}

// The reference's own verdict on a listed token: getContacts' contacts, and
// the reason its Promise.allSettled drops one (`:507-513`, console.warn).
const readBack = async (lockingScript, keyID) => {
  const state = {
    createAction: [],
    listed: {
      totalOutputs: 1,
      outputs: [{
        outpoint: `${'22'.repeat(32)}.0`,
        satoshis: 1,
        lockingScript,
        spendable: true,
        customInstructions: JSON.stringify({ keyID })
      }]
    }
  }
  const { wallet } = recording(state)
  const warnings = []
  const warn = console.warn
  console.warn = (...args) => warnings.push(args.map(a => a instanceof Error ? a.message : String(a)).join(' '))
  try {
    const contacts = await new ContactsManager(wallet).getContacts(undefined, true)
    return { contacts: contacts.length, dropped: warnings }
  } finally {
    console.warn = warn
  }
}

// The keys and the decryption under a protocol, through the reference's wallet.
const underProtocol = async (inner, protocolID, keyID, ciphertext) => ({
  locking_public_key: (await inner.getPublicKey({ protocolID, keyID, counterparty: 'self', forSelf: true })).publicKey,
  decrypt: await words(async () => Utils.toUTF8((await inner.decrypt({ protocolID, keyID, counterparty: 'self', ciphertext })).plaintext))
})

const identityKey = new PrivateKey(Utils.toHex(new Array(32).fill(3)), 'hex').toPublicKey().toString()
const contact = {
  name: 'Alice Example',
  avatarURL: '',
  abbreviatedKey: identityKey.slice(0, 10),
  identityKey,
  badgeIconURL: '',
  badgeLabel: '',
  badgeClickURL: ''
}

// The reference writes its token.
const state = { createAction: [] }
const { inner } = recording(state)
const saved = await words(() => new ContactsManager(recording(state).wallet).saveContact(contact))
if (saved.error !== STOP) throw new Error(`saveContact: ${saved.error}`)
const output = state.createAction[0].outputs[0]
const keyID = JSON.parse(output.customInstructions).keyID
const decoded = PushDrop.decode(LockingScript.fromHex(output.lockingScript))
const ciphertext = decoded.fields[0]
const write = {
  key_id: keyID,
  custom_instructions: output.customInstructions,
  tag: output.tags[0],
  locking_script: output.lockingScript,
  locking_public_key: decoded.lockingPublicKey.toString(),
  ciphertext: Utils.toHex(ciphertext),
  field_signature: Utils.toHex(decoded.fields[1]),
  field_signature_verifies: (await inner.verifySignature({
    protocolID: PROTOCOL, keyID, counterparty: 'self', data: ciphertext, signature: decoded.fields[1]
  })).valid,
  under_contact_protocol: await underProtocol(inner, PROTOCOL, keyID, ciphertext),
  under_level_one: await underProtocol(inner, LEVEL_ONE, keyID, ciphertext),
  read_back: await readBack(output.lockingScript, keyID)
}

// This crate's tokens, base and tip, read by the reference.
const crate = {}
if (cratePath !== undefined) {
  const files = JSON.parse(readFileSync(cratePath, 'utf8'))
  for (const [name, file] of Object.entries(files)) {
    const token = JSON.parse(readFileSync(file, 'utf8'))
    const fields = PushDrop.decode(LockingScript.fromHex(token.locking_script))
    crate[name] = {
      ...token,
      token_locking_public_key: fields.lockingPublicKey.toString(),
      token_fields: fields.fields.length,
      under_contact_protocol: await underProtocol(inner, PROTOCOL, token.key_id, fields.fields[0]),
      read_back: await readBack(token.locking_script, token.key_id)
    }
  }
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk/src/identity/ContactsManager.ts',
  node: process.version,
  wallet_scalar: 9,
  protocol: { security_level: PROTOCOL[0], protocol: PROTOCOL[1], counterparty: 'self' },
  contact,
  write,
  crate
}, null, 2) + '\n')
