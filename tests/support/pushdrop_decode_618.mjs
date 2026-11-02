// #618: what the reference's public `PushDrop.decode` reads (`ts-stack@edf6e03`
// `packages/sdk/src/script/templates/PushDrop.ts:63-121`), at its default
// position, 'before', and at 'after', for a key-only script and a token whose
// second chunk is not OP_CHECKSIG, and the shapes around them: the writer's
// tokens at both positions, the lock alone, a lock-after token whose first
// field is a point, the empty script, one chunk that is no key; and (the
// fold) a DROP or 2DROP that ends the read, a field before a DROP, an
// OP_RESERVED field, and OP_0 and OP_1 fields, each at both positions.
//
// Each token is the reference's own `lock` (a ProtoWallet on the scalar 9,
// no signature), its chunks then replaced, removed or cut with the
// reference's `Script`; a reading is the fields' hex, the key's compressed
// hex (`PublicKey.toString`), or the words the decode throws.
//
// `sites`: the same two shapes at each of the six #537 sites' reference
// counterparts, every one of which refuses them (`decodeCanonicalPushDrop`,
// `PushDropValidation.ts:54-79`; `IdentityClient.ts:130-147`;
// `ContactsManager.ts:225-242`). Each site's token is its #537 recording's
// not-a-point case read at 'after' and written lock-before as
// `canonicalScript` writes it (`PushDropValidation.ts:40-51`); the key alone
// is its first chunk, the token without CHECKSIG its second chunk replaced
// by OP_1. Each site is run as #537's recorder runs it.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk618.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_decode_618.mjs \
//     "$W/sdk618.mjs" > tests/vectors/pushdrop_decode_618.json
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'url'

let counter = 0
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: {
    getRandomValues (array) {
      const bytes = []
      while (bytes.length < array.length) {
        bytes.push(...createHash('sha256').update(`618:${counter++}`).digest())
      }
      array.set(bytes.slice(0, array.length))
      return array
    }
  }
})

const [sdkPath] = process.argv.slice(2)
const {
  ProtoWallet, PrivateKey, PushDrop, LockingScript, Transaction, IdentityClient,
  LookupResolver, RegistryClient, decodeAndVerifyRegistryToken, decodeAndVerifyKVStoreToken,
  OverlayAdminTokenTemplate, decodeAndVerifyUHRPAdvertisement, StorageDownloader, Utils, OP
} = await import(pathToFileURL(sdkPath).href)

const PROTOCOL = [2, 'pushdrop decode']
const KEY_ID = '1'
const FIELDS = [[0x68, 0x69], [5], []]

const wallet = new ProtoWallet(new PrivateKey(9))
const lock = async (fields, position) => await new PushDrop(wallet).lock(
  fields.map((field) => [...field]), PROTOCOL, KEY_ID, 'self', false, false, position
)
const before = await lock(FIELDS, 'before')
const after = await lock(FIELDS, 'after')
const key = before.chunks[0]
const uncompressed = Utils.toArray(
  PrivateKey.fromHex('09'.padStart(64, '0')).toPublicKey().encode(false, 'hex'), 'hex')
const G = PrivateKey.fromHex('01'.padStart(64, '0')).toPublicKey().encode(true)
const offCurve = [2, ...new Array(32).fill(0)]
const script = (chunks) => new LockingScript(chunks)
const pointFirst = await lock([G, [0x68, 0x69]], 'after')
const hi = { op: 2, data: [0x68, 0x69] }

const definitions = [
  ['lock_before_three_fields', before],
  ['lock_after_three_fields', after],
  ['lock_only', script(before.chunks.slice(0, 2))],
  ['key_only', script([key])],
  ['key_only_uncompressed', script([{ op: 65, data: uncompressed }])],
  ['key_only_off_curve', script([{ op: 33, data: offCurve }])],
  ['no_checksig', script([key, { op: OP.OP_1 }, ...before.chunks.slice(2)])],
  ['no_checksig_nop', script([key, { op: OP.OP_NOP }, ...before.chunks.slice(2)])],
  ['no_checksig_no_field', script([key, { op: OP.OP_1 }])],
  ['no_checksig_off_curve',
    script([{ op: 33, data: offCurve }, { op: OP.OP_1 }, ...before.chunks.slice(2)])],
  ['lock_after_point_first', pointFirst],
  ['empty', script([])],
  ['one_chunk_op_true', script([{ op: OP.OP_1 }])],
  ['one_chunk_short_push', script([{ op: 5, data: [1, 2, 3, 4, 5] }])],
  // The #618 fold: a DROP that ends the read and the fields with no data
  // (`PushDrop.ts:96-115`), at each lock position.
  ...[
    ['checksig_drop', [{ op: OP.OP_DROP }]],
    ['checksig_2drop', [{ op: OP.OP_2DROP }]],
    ['checksig_field_drop', [hi, { op: OP.OP_DROP }]],
    ['reserved_field', [hi, { op: OP.OP_RESERVED }, { op: OP.OP_2DROP }]],
    ['op_0_op_1_fields', [{ op: OP.OP_0 }, { op: OP.OP_1 }, { op: OP.OP_2DROP }]]
  ].flatMap(([name, chunks]) => [
    [name, script([key, { op: OP.OP_CHECKSIG }, ...chunks])],
    [`${name}_lock_after`, script([...chunks, key, { op: OP.OP_CHECKSIG }])]
  ])
]

const read = (locking, position) => {
  try {
    const { fields, lockingPublicKey } = PushDrop.decode(locking, position)
    return {
      fields: fields.map((field) => Utils.toHex(field)),
      locking_public_key: lockingPublicKey.toString(),
      error: null
    }
  } catch (error) {
    return { fields: null, locking_public_key: null, error: error.message }
  }
}

const cases = definitions.map(([name, locking]) => ({
  name,
  locking_script: locking.toHex(),
  before: read(locking, 'before'),
  after: read(locking, 'after')
}))

// The six sites, run as tests/support/pushdrop_lock_position_537.mjs runs them.
const recorded537 = JSON.parse(readFileSync(new URL('../vectors/pushdrop_lock_position_537.json',
  import.meta.url)))
const push = (data) => {
  if (data.length === 0 || (data.length === 1 && data[0] === 0)) return { op: 0 }
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return { op: 0x50 + data[0] }
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 0xff) return { op: 0x4c, data }
  return { op: 0x4d, data }
}
const relockedBefore = (hex) => {
  const token = PushDrop.decode(LockingScript.fromHex(hex), 'after')
  const chunks = [{ op: 33, data: token.lockingPublicKey.encode(true) }, { op: OP.OP_CHECKSIG },
    ...token.fields.map(push)]
  for (let remaining = token.fields.length; remaining > 1; remaining -= 2) chunks.push({ op: OP.OP_2DROP })
  if (token.fields.length % 2 === 1) chunks.push({ op: OP.OP_DROP })
  return new LockingScript(chunks)
}
const shapes = (token) => [
  ['key_only', new LockingScript([token.chunks[0]])],
  ['no_checksig', new LockingScript([token.chunks[0], { op: OP.OP_1 }, ...token.chunks.slice(2)])]
]
const words = async (run) => {
  try { await run(); return null } catch (error) { return error.message }
}
const sourceOf = (locking) => {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: locking })
  return source
}
const answering = (locking) => {
  const source = sourceOf(locking)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
}
const operator = new ProtoWallet(PrivateKey.fromHex('09'.padStart(64, '0')))
const issued = JSON.parse(readFileSync(new URL('../vectors/certificate_field_value_261.json',
  import.meta.url))).reference_issued

const runs = {
  // IdentityClient.ts:773, its catch at :823 skipping the output.
  identity_client: async (locking) => {
    answering(locking)
    const client = new IdentityClient(operator, { networkPreset: 'mainnet' })
    return { site_words: await words(() =>
      client.revokeCertificateRevelation(issued.certificate.serialNumber)), outcome: 'skipped' }
  },
  // ContactsManager.ts:432, dropped by the allSettled at :478,507-513.
  contacts_cache: async (locking, c) => {
    const warned = []
    const warn = console.warn
    console.warn = (...args) => warned.push(args[1]?.message ?? String(args[1]))
    const contacts = await new IdentityClient({
      ...Object.fromEntries(['getPublicKey', 'decrypt', 'verifySignature', 'createHmac']
        .map(method => [method, (args, originator) => operator[method](args, originator)])),
      async listOutputs () {
        return { totalOutputs: 1, outputs: [{ outpoint: `${'22'.repeat(32)}.0`, satoshis: 1,
          spendable: true, lockingScript: locking.toHex(),
          customInstructions: JSON.stringify({ keyID: c.key_id }) }] }
      }
    }).getContacts(undefined, true)
    console.warn = warn
    return { site_words: warned[0] ?? null, outcome: contacts.length === 0 ? 'skipped' : 'accepted' }
  },
  // registryTokenValidation.ts:28, RegistryClient.ts:392 catch.
  registry_client: async (locking, c) => {
    const queries = { basket: { basketID: 'basket1' }, protocol: { name: 'Proto' }, certificate: { name: 'Cert' } }
    answering(locking)
    const records = await new RegistryClient(operator, { networkPreset: 'mainnet' })
      .resolve(c.definition_type, queries[c.definition_type])
    return { site_words: await words(() => decodeAndVerifyRegistryToken(c.definition_type, locking)),
      outcome: records.length === 0 ? 'skipped' : 'accepted' }
  },
  // kvStoreTokenValidation.ts:88, kvStoreInterpreter.ts:48 catch.
  kvstore_interpreter: async (locking) => ({
    site_words: await words(() => decodeAndVerifyKVStoreToken(locking)), outcome: 'skipped' }),
  // OverlayAdminTokenTemplate.ts:164, thrown from :237-239.
  overlay_admin_token: async (locking) => ({
    site_words: await words(() => OverlayAdminTokenTemplate.decode(locking)), outcome: 'refused' }),
  // UHRPAdvertisementValidation.ts:40, StorageDownloader.ts:121 catch.
  storage_downloader: async (locking, c) => {
    answering(locking)
    const hosts = await new StorageDownloader({ networkPreset: 'mainnet' }).resolve(c.uhrp_url)
    return { site_words: await words(() => decodeAndVerifyUHRPAdvertisement(locking)),
      outcome: hosts.length === 0 ? 'skipped' : 'accepted' }
  }
}
const sites = []
for (const entry of recorded537.sites) {
  const siteCases = []
  for (const c of entry.cases.filter((c) => c.kind === 'lock_after_not_a_point')) {
    const token = relockedBefore(c.script)
    for (const [shape, locking] of shapes(token)) {
      siteCases.push({ name: `${c.name.replace('lock_after_not_a_point', shape)}`,
        shape, from_537: c.name, locking_script: locking.toHex(),
        decode: read(locking, 'before'), ...(await runs[entry.site](locking, c)) })
    }
  }
  sites.push({ site: entry.site, reference_call: entry.reference_call,
    reference_outcome: entry.reference_outcome, cases: siteCases })
}

process.stdout.write(JSON.stringify({
  issue: 618,
  reference: 'ts-stack@edf6e03 packages/sdk/src/script/templates/PushDrop.ts:63-121',
  runtime: `node ${process.version}`,
  fields: FIELDS.map((field) => Utils.toHex(field)),
  cases,
  sites
}, null, 2) + '\n')
