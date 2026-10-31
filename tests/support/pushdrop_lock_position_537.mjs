// #537: what each of the six sites' reference counterparts does with a
// PushDrop token written lock-after (`ts-stack@edf6e03`, Node 22). Every
// counterpart decodes at `PushDrop.decode`'s default position, 'before'
// (`packages/sdk/src/script/templates/PushDrop.ts:63-78`), so the key is read
// from the first chunk. Two kinds per site: `lock_after_not_a_point` (the
// first field is no point encoding: the key parse refuses it) and
// `lock_after_point_first` (the corner: the first field IS a valid point, the
// reference reads it as the key and its later validation decides).
//
// Each case records the `PushDrop.decode` call's result, the words the site's
// own validation throws, and the site's outcome from a run of the site itself
// where the site is a method (`revokeCertificateRevelation`, `getContacts`,
// `RegistryClient.resolve`, `StorageDownloader.resolve`, with
// `LookupResolver.prototype.query` answering the token and the wallet a
// `ProtoWallet`); the kvstore interpreter's and the admin token's
// counterparts are functions and are called as they are.
//
// The scripts are written here from their fields; the Rust tests read them.
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_lock_position_537.mjs \
//     "$W/sdk.mjs" > tests/vectors/pushdrop_lock_position_537.json
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

let counter = 0
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: {
    getRandomValues (array) {
      const bytes = []
      while (bytes.length < array.length) {
        bytes.push(...createHash('sha256').update(`537:${counter++}`).digest())
      }
      array.set(bytes.slice(0, array.length))
      return array
    }
  }
})

const sdk = await import(process.argv[2])
const {
  PushDrop, LockingScript, Transaction, PrivateKey, ProtoWallet, IdentityClient,
  LookupResolver, RegistryClient, decodeAndVerifyRegistryToken, decodeAndVerifyKVStoreToken,
  OverlayAdminTokenTemplate, decodeAndVerifyUHRPAdvertisement, StorageDownloader,
  StorageUtils, Utils, OP
} = sdk

const utf8 = (text) => Utils.toArray(text, 'utf8')
const hex = (bytes) => Utils.toHex(bytes)
const G = PrivateKey.fromHex('01'.padStart(64, '0')).toPublicKey().encode(true)
const operatorKey = PrivateKey.fromHex('09'.padStart(64, '0'))
const operator = operatorKey.toPublicKey().toString()
const signature = (data) => operatorKey.sign(data).toDER()

// PushDropValidation.ts:13-23's minimal push, then the drops and the key last.
const push = (data) => {
  if (data.length === 0 || (data.length === 1 && data[0] === 0)) return { op: 0 }
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return { op: 0x50 + data[0] }
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 0xff) return { op: 0x4c, data }
  return { op: 0x4d, data }
}
const lockAfter = (fields) => {
  const chunks = fields.map(push)
  for (let remaining = fields.length; remaining > 1; remaining -= 2) chunks.push({ op: OP.OP_2DROP })
  if (fields.length % 2 === 1) chunks.push({ op: OP.OP_DROP })
  chunks.push({ op: 33, data: G }, { op: OP.OP_CHECKSIG })
  return new LockingScript(chunks)
}
const sourceOf = (script) => {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: script })
  return source
}
const answering = (script) => {
  const source = sourceOf(script)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
}
const decoded = (script) => {
  try {
    const token = PushDrop.decode(script)
    return { ok: true, key: token.lockingPublicKey.toString(), fields: token.fields.length }
  } catch (error) {
    return { ok: false, error: error.message }
  }
}
const words = async (run) => {
  try { await run(); return null } catch (error) { return error.message }
}

const wallet = new ProtoWallet(operatorKey)
const pair = (fields) => [
  { name: 'lock_after_not_a_point', kind: 'lock_after_not_a_point', fields },
  { name: 'lock_after_point_first', kind: 'lock_after_point_first', fields: [G, ...fields] }
]
const sites = []

// 1. IdentityClient.ts:773, in revokeCertificateRevelation's lookup loop
// (:768-824; a refused output is skipped by the catch at :823).
{
  const issued = JSON.parse(readFileSync(new URL('../vectors/certificate_field_value_261.json',
    import.meta.url))).reference_issued
  const json = utf8(JSON.stringify({ ...issued.certificate, keyring: issued.anyone_keyring }))
  const cases = []
  for (const c of pair([json, signature(json)])) {
    const script = lockAfter(c.fields)
    answering(script)
    const client = new IdentityClient(wallet, { networkPreset: 'mainnet' })
    const site = await words(() => client.revokeCertificateRevelation(issued.certificate.serialNumber))
    cases.push({ name: c.name, kind: c.kind, script: script.toHex(), decode: decoded(script),
      site_words: site, outcome: 'skipped' })
  }
  sites.push({ site: 'identity_client', reference_call: 'IdentityClient.ts:773',
    reference_outcome: 'IdentityClient.ts:823 catch: the output skipped', cases })
}

// 2. ContactsManager.ts:432 (#authenticateContactScript), reached from
// #decryptContactOutputs (:475-514): a refused output is dropped by
// Promise.allSettled with a console.warn.
{
  const keyID = Utils.toBase64(new Array(32).fill(5))
  const plaintext = utf8(JSON.stringify({ name: 'Alice', identityKey: operator }))
  const { ciphertext } = await wallet.encrypt({ plaintext, protocolID: [2, 'contact'], keyID,
    counterparty: 'self' })
  const cases = []
  for (const c of pair([ciphertext, signature(ciphertext)])) {
    const script = lockAfter(c.fields)
    const warned = []
    const warn = console.warn
    console.warn = (...args) => warned.push(args[1]?.message ?? String(args[1]))
    const contacts = await new IdentityClient({
      ...Object.fromEntries(['getPublicKey', 'decrypt', 'verifySignature', 'createHmac']
        .map(method => [method, (args, originator) => wallet[method](args, originator)])),
      async listOutputs () {
        return { totalOutputs: 1, outputs: [{ outpoint: `${'22'.repeat(32)}.0`, satoshis: 1,
          spendable: true, lockingScript: script.toHex(), customInstructions: JSON.stringify({ keyID }) }] }
      }
    }).getContacts(undefined, true)
    console.warn = warn
    cases.push({ name: c.name, kind: c.kind, script: script.toHex(), decode: decoded(script),
      site_words: warned[0] ?? null, outcome: contacts.length === 0 ? 'skipped' : 'accepted',
      key_id: keyID, plaintext: Utils.toUTF8(plaintext) })
  }
  sites.push({ site: 'contacts_cache', reference_call: 'ContactsManager.ts:432',
    reference_outcome: 'ContactsManager.ts:478,507-513 allSettled: the output dropped', cases })
}

// 3. RegistryClient.ts:732 (#parseLockingScript, decodeAndVerifyRegistryToken,
// registryTokenValidation.ts:28), from resolve (:384-393) and
// listOwnRegistryEntries (:415-446): a refused output is skipped by the catch.
{
  const definitions = {
    basket: { query: { basketID: 'basket1' },
      fields: ['basket1', 'Basket', 'https://icon.example', 'A basket', 'https://doc.example', operator] },
    protocol: { query: { name: 'Proto' },
      fields: ['[1,"proto name"]', 'Proto', 'https://icon.example', 'A protocol', 'https://doc.example', operator] },
    certificate: { query: { name: 'Cert' },
      fields: ['certtype', 'Cert', 'https://icon.example', 'A certificate', 'https://doc.example', '{}', operator] }
  }
  const cases = []
  for (const [type, definition] of Object.entries(definitions)) {
    for (const c of pair(definition.fields.map(utf8))) {
      const script = lockAfter(c.fields)
      answering(script)
      const records = await new RegistryClient(wallet, { networkPreset: 'mainnet' })
        .resolve(type, definition.query)
      cases.push({ name: `${type}_${c.name}`, kind: c.kind, definition_type: type,
        script: script.toHex(), decode: decoded(script),
        site_words: await words(() => decodeAndVerifyRegistryToken(type, script)),
        outcome: records.length === 0 ? 'skipped' : 'accepted' })
    }
  }
  sites.push({ site: 'registry_client', reference_call: 'registryTokenValidation.ts:28',
    reference_outcome: 'RegistryClient.ts:392,445 catch: the output skipped', cases })
}

// 4. kvStoreInterpreter.ts:37 (decodeAndVerifyKVStoreToken,
// kvStoreTokenValidation.ts:88): a refused token is no value (:48 catch).
{
  const fields = [utf8('[1,"kvstore"]'), utf8('alpha'), utf8('one'), G]
  const cases = []
  for (const c of pair([...fields, signature(fields.flat())])) {
    const script = lockAfter(c.fields)
    cases.push({ name: c.name, kind: c.kind, script: script.toHex(), decode: decoded(script),
      site_words: await words(() => decodeAndVerifyKVStoreToken(script)), outcome: 'skipped' })
  }
  sites.push({ site: 'kvstore_interpreter', reference_call: 'kvStoreTokenValidation.ts:88',
    reference_outcome: 'kvStoreInterpreter.ts:48 catch: no value', cases })
}

// 5. OverlayAdminTokenTemplate.ts:164 (decodeAdvertisement), from the static
// decode (:237-239): the refusal is thrown to the caller.
{
  const fields = [utf8('SHIP'), G, utf8('https://ship.example'), utf8('tm_test')]
  const cases = []
  for (const c of pair([...fields, signature(fields.flat())])) {
    const script = lockAfter(c.fields)
    cases.push({ name: c.name, kind: c.kind, script: script.toHex(), decode: decoded(script),
      site_words: await words(() => OverlayAdminTokenTemplate.decode(script)), outcome: 'refused' })
  }
  sites.push({ site: 'overlay_admin_token', reference_call: 'OverlayAdminTokenTemplate.ts:164',
    reference_outcome: 'OverlayAdminTokenTemplate.ts:237-239: thrown', cases })
}

// 6. UHRPAdvertisementValidation.ts:40, from StorageDownloader.resolve
// (StorageDownloader.ts:116, :121 catch: the output skipped). A UHRP token's
// first field is the host's identity key, so its realistic lock-after form is
// the corner; the other kind carries 32 bytes there.
{
  const hash = new Array(32).fill(0x44)
  const url = StorageUtils.getURLForHash(hash)
  const expiry = [0xfe, ...Utils.toArray((4102444800).toString(16).padStart(8, '0'), 'hex').reverse()]
  const rest = [hash, utf8('https://host.example/file'), expiry, [0x10]]
  const cases = []
  for (const c of [
    { name: 'lock_after_not_a_point', kind: 'lock_after_not_a_point', first: new Array(32).fill(0x11) },
    { name: 'lock_after_point_first', kind: 'lock_after_point_first', first: G }
  ]) {
    const fields = [c.first, ...rest]
    const script = lockAfter([...fields, signature(fields.flat())])
    answering(script)
    const hosts = await new StorageDownloader({ networkPreset: 'mainnet' }).resolve(url)
    cases.push({ name: c.name, kind: c.kind, script: script.toHex(), decode: decoded(script),
      site_words: await words(() => decodeAndVerifyUHRPAdvertisement(script)),
      outcome: hosts.length === 0 ? 'skipped' : 'accepted', uhrp_url: url })
  }
  sites.push({ site: 'storage_downloader', reference_call: 'UHRPAdvertisementValidation.ts:40',
    reference_outcome: 'StorageDownloader.ts:121 catch: the output skipped', cases })
}

process.stdout.write(JSON.stringify({
  description: '#537: each site\'s reference counterpart on a lock-after PushDrop token, ' +
    'decoded at PushDrop.decode\'s default lock position (before, PushDrop.ts:63-78)',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  recorder: 'tests/support/pushdrop_lock_position_537.mjs',
  sites
}, null, 2) + '\n')
