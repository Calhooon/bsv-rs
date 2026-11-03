// #718: the identity and contacts sites' canonical PushDrop checks, the
// reference's words and verdicts on one set of token shapes (`ts-stack@edf6e03`,
// Node 22). None of these sites calls `decodeCanonicalPushDrop`: each reads
// with `PushDrop.decode` at its default position (`PushDrop.ts:63-121`: the
// key the first chunk, the second chunk never read, the fields from the third)
// and then runs its own checks:
//   contacts    #authenticateContactScript (ContactsManager.ts:431-466): the
//               field count, the ciphertext 1 to 66560 bytes and the
//               signature 8 to 80, the canonical five chunks, the lock, the
//               signature; its words recorded from getContacts, which drops a
//               refused output with console.warn (:475-514)
//   revocation  revokeCertificateRevelation's lookup loop
//               (IdentityClient.ts:768-824): the count, the canonical
//               envelope, the lock, ...; a refused output skipped, the run's
//               words those of no authenticated output (:827-829)
// The toolbox discovery (`identityUtils.ts:497-559`, `decodeIdentityOutput`)
// is read, not run: every refusal under its `try` returns null.
//
// `mod.ts` does not export ContactsManager, so the entry re-exports it:
//   W=<lane out>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry718.ts" <<'X'
//   export * from './mod.js'
//   import { ContactsManager as CM718 } from './src/identity/ContactsManager.js'
//   export const ContactsManager718 = CM718
//   X
//   (cd "$W/packages/sdk" && bun build entry718.ts --target node --format esm --outfile "$W/sdk718.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_contacts_canonical_718.mjs \
//     "$W/sdk718.mjs" > tests/vectors/identity_contacts_canonical_718.json
//
// A shape is described (the first chunk, the second opcode or none, the field
// lengths, every field byte 0x61, the drops the PushDrop writer writes) and
// pinned by the SHA-256 of its bytes, which the Rust tests' own writer must
// reproduce. No randomness is read: every refusal comes before one.
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  ContactsManager718: ContactsManager, IdentityClient, ProtoWallet, PrivateKey, LockingScript,
  Transaction, LookupResolver, Utils, OP
} = sdk

const KEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const BAD_KEY = '05' + '61'.repeat(32)
const BYTE = 0x61
const KEY_ID = Utils.toBase64(new Array(32).fill(6))
const SERIAL = Utils.toBase64(new Array(32).fill(1))
const NOP = 0x61
const CHECKSIG = OP.OP_CHECKSIG
const shapes = [
  { name: 'empty_script', first: 'none', second_op: null, field_lengths: [] },
  { name: 'key_only', first: 'key', second_op: null, field_lengths: [] },
  { name: 'first_chunk_without_data', first: 'nop', second_op: CHECKSIG, field_lengths: [10, 8] },
  { name: 'tag_05_key', first: 'bad_key', second_op: NOP, field_lengths: [10, 8] },
  { name: 'no_checksig_in_bounds', first: 'key', second_op: NOP, field_lengths: [10, 8] },
  { name: 'no_checksig_oversized_ciphertext', first: 'key', second_op: NOP, field_lengths: [66561, 8] },
  { name: 'no_checksig_short_signature', first: 'key', second_op: NOP, field_lengths: [10, 7] },
  { name: 'no_checksig_three_fields_oversized', first: 'key', second_op: NOP, field_lengths: [66561, 8, 8] },
  { name: 'checksig_oversized_ciphertext', first: 'key', second_op: CHECKSIG, field_lengths: [66561, 8] },
  { name: 'checksig_in_bounds', first: 'key', second_op: CHECKSIG, field_lengths: [10, 8] }
]

// The PushDrop writer's minimal push (no field here is one byte of 1 to 16;
// the 66561-byte ciphertext takes OP_PUSHDATA4).
function push (data) {
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 0xff) return { op: OP.OP_PUSHDATA1, data }
  if (data.length <= 0xffff) return { op: OP.OP_PUSHDATA2, data }
  return { op: OP.OP_PUSHDATA4, data }
}

function script (shape) {
  const chunks = []
  if (shape.first === 'key') chunks.push({ op: 33, data: Utils.toArray(KEY, 'hex') })
  if (shape.first === 'bad_key') chunks.push({ op: 33, data: Utils.toArray(BAD_KEY, 'hex') })
  if (shape.first === 'nop') chunks.push({ op: NOP })
  if (shape.second_op !== null) chunks.push({ op: shape.second_op })
  chunks.push(...shape.field_lengths.map((length) => push(new Array(length).fill(BYTE))))
  for (let left = shape.field_lengths.length; left > 1; left -= 2) chunks.push({ op: OP.OP_2DROP })
  if (shape.field_lengths.length % 2 === 1) chunks.push({ op: OP.OP_DROP })
  return new LockingScript(chunks)
}

async function words (run) {
  try { await run(); return null } catch (e) { return String(e.message) }
}

const wallet9 = new ProtoWallet(new PrivateKey(9))

// contacts: getContacts over one listed output, the dropped output's words.
async function contactWords (hex) {
  const wallet = {}
  for (const name of ['getPublicKey', 'verifySignature', 'decrypt']) {
    wallet[name] = async (args) => wallet9[name](args)
  }
  wallet.listOutputs = async () => ({
    totalOutputs: 1,
    outputs: [{
      outpoint: `${'22'.repeat(32)}.0`, satoshis: 1, lockingScript: hex, spendable: true,
      customInstructions: JSON.stringify({ keyID: KEY_ID })
    }]
  })
  const dropped = []
  const warn = console.warn
  console.warn = (...args) => dropped.push(args[1] instanceof Error ? args[1].message : String(args[1]))
  try {
    const contacts = await new ContactsManager(wallet).getContacts(undefined, true)
    return { contacts: contacts.length, dropped }
  } finally {
    console.warn = warn
  }
}

// revocation: the lookup answering one output whose output 0 is the shape.
async function revocation (lock) {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: lock })
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
  const wallet = {
    async getPublicKey (args) { return wallet9.getPublicKey(args) },
    async verifySignature (args) { return wallet9.verifySignature(args) },
    async getNetwork () { return { network: 'mainnet' } },
    async createAction () { throw new Error('bsv-rs#718 recorder: createAction reached') }
  }
  return words(() => new IdentityClient(wallet, { networkPreset: 'mainnet' }).revokeCertificateRevelation(SERIAL))
}

const cases = []
for (const shape of shapes) {
  const s = script(shape)
  const hex = s.toHex()
  const bytes = Buffer.from(hex, 'hex')
  cases.push({
    ...shape,
    script_bytes: bytes.length,
    script_sha256: createHash('sha256').update(bytes).digest('hex'),
    contacts: await contactWords(hex),
    revocation_words: await revocation(LockingScript.fromHex(hex))
  })
}
console.log(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk (bun build entry718.ts), Node ' + process.version,
  key: KEY,
  bad_key: BAD_KEY,
  field_byte: BYTE,
  key_id: KEY_ID,
  serial_number: SERIAL,
  cases
}, null, 2))
