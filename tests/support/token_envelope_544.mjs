// #544: the six token-decode sites' reference counterparts on the reference's
// own tokens and on tokens changed in one respect (`ts-stack@edf6e03`,
// Node 22): each counterpart's envelope, signature and field-set checks, its
// refusal words and its outcome from a run of the site where the site is a
// method. The sites and their reference reads:
//   contacts   ContactsManager.ts:414-472 (#readKeyID, #authenticateContactScript,
//              #parseContactPlaintext, validateContact :171-209), from getContacts
//              (:475-514, a refused output dropped by Promise.allSettled) and
//              saveContact (:527-528, validateContact before any wallet call)
//   identity   IdentityClient.ts:768-824 (revokeCertificateRevelation's lookup
//              loop: two fields, the canonical envelope, the locking key, the
//              certificate, verifySignature; a refused output skipped)
//   registry   registryTokenValidation.ts:19-64 (decodeAndVerifyRegistryToken),
//              from RegistryClient.resolve (a refused output skipped)
//   kvstore    kvStoreTokenValidation.ts:86-122 (decodeAndVerifyKVStoreToken),
//              from kvStoreInterpreter (kvStoreInterpreter.ts:28-50, no value)
//   overlay    OverlayAdminTokenTemplate.ts:162-215 (decodeAdvertisement, the
//              static decode :237-239, thrown) and decodeAndVerifyOverlayAdvertisement
//              (:198-215, the author; LookupResolver.ts:2206, SHIPBroadcaster.ts:775)
//   storage    UHRPAdvertisementValidation.ts:37-112 (decodeAndVerifyUHRPAdvertisement),
//              from StorageDownloader.resolve (StorageDownloader.ts:62-126: the
//              hash binding and expiry at :117, a refused output skipped)
//
// `mod.ts` exports neither ContactsManager, kvStoreInterpreter nor
// decodeAndVerifyOverlayAdvertisement, so the entry re-exports them:
//   W=$TMPDIR/ref-544
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   cat > "$W/packages/sdk/entry544.ts" <<'EOF'
//   export * from './mod.js'
//   import { ContactsManager as CM544 } from './src/identity/ContactsManager.js'
//   import { kvStoreInterpreter as KVI544 } from './src/kvstore/kvStoreInterpreter.js'
//   import { decodeAndVerifyOverlayAdvertisement as DVOA544 } from './src/overlay-tools/OverlayAdminTokenTemplate.js'
//   export const ContactsManager544 = CM544
//   export const kvStoreInterpreter544 = KVI544
//   export const decodeAndVerifyOverlayAdvertisement544 = DVOA544
//   EOF
//   (cd "$W/packages/sdk" && bun build entry544.ts --target node --format esm --outfile "$W/sdk544.mjs")
// This crate's tokens are an input, written by the ignored recorder of
// `tests/identity_contacts_envelope_544.rs` on the tip
// (`TOKENS_544_OUT=<file> cargo test --features full --test
// identity_contacts_envelope_544 -- --ignored --exact record_this_crates_tokens_544`);
// the base's contact token is #542's vector's tip token (the same writer):
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/token_envelope_544.mjs \
//     "$W/sdk544.mjs" <tokens.json> > tests/vectors/token_envelope_544.json
//
// The randomness is a SHA-256 counter stream installed before the SDK loads,
// so two runs print the same file. Every wallet is a ProtoWallet in process;
// every lookup is `LookupResolver.prototype.query` answering one output.
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#544 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (arr) { arr.set(stream(arr.length)); return arr } }
})

const [sdkPath, tokensPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const {
  ContactsManager544: ContactsManager, kvStoreInterpreter544: kvStoreInterpreter,
  decodeAndVerifyOverlayAdvertisement544: decodeAndVerifyOverlayAdvertisement,
  ProtoWallet, PrivateKey, PushDrop, LockingScript, Transaction, LookupResolver, IdentityClient,
  MasterCertificate, RegistryClient, decodeAndVerifyRegistryToken, decodeAndVerifyKVStoreToken,
  OverlayAdminTokenTemplate, decodeAndVerifyUHRPAdvertisement, StorageDownloader, StorageUtils,
  Utils, OP
} = sdk

const utf8 = (text) => Utils.toArray(text, 'utf8')
const hex = (bytes) => Utils.toHex(bytes)
const key = (n) => new PrivateKey(n)
const wallet9 = new ProtoWallet(key(9))
const STOP = 'bsv-rs#544 recorder: createAction recorded'
const tokens = tokensPath === undefined ? {} : JSON.parse(readFileSync(tokensPath, 'utf8'))

const words = async (run) => {
  try { await run(); return null } catch (e) { return String(e.message) }
}
// A canonical push (PushDropValidation.ts:13-23).
const push = (data) => {
  if (data.length === 0 || (data.length === 1 && data[0] === 0)) return { op: 0 }
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return { op: 0x50 + data[0] }
  if (data.length <= 75) return { op: data.length, data }
  if (data.length <= 0xff) return { op: 0x4c, data }
  return { op: 0x4d, data }
}
// Lock-before by hand: the key, OP_CHECKSIG, the fields, then the drops given.
const script = (lockKey, fields, drops) => new LockingScript([
  { op: 33, data: Utils.toArray(lockKey, 'hex') }, { op: OP.OP_CHECKSIG },
  ...fields.map(push), ...drops.map((op) => ({ op }))
])
const canonicalDrops = (n) => {
  const drops = []
  for (let left = n; left > 1; left -= 2) drops.push(OP.OP_2DROP)
  if (n % 2 === 1) drops.push(OP.OP_DROP)
  return drops
}
const signed = (lockKey, fields) => script(lockKey, fields, canonicalDrops(fields.length))
const loose = (lockKey, fields) => script(lockKey, fields, fields.map(() => OP.OP_DROP))
const sourceOf = (lock) => {
  const source = new Transaction()
  source.addInput({
    sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
    unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
  })
  source.addOutput({ satoshis: 1, lockingScript: lock })
  return source
}
const answering = (lock) => {
  const source = sourceOf(lock)
  LookupResolver.prototype.query = async function () {
    return { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  }
}
const otherSignature = (data) => key(13).sign(data).toDER()

// ---------------------------------------------------------------- contacts
// The ProtoWallet of 9 under a recorder: listOutputs answers the listing set,
// createAction records and stops, so saveContact ends after its token.
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
const contactReadBack = async (lockingScript, customInstructions) => {
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
const CONTACT = [2, 'contact']
const identityKey = key(3).toPublicKey().toString()
const contact = {
  name: 'Alice Example',
  avatarURL: 'https://example.com/alice.png',
  abbreviatedKey: `${identityKey.slice(0, 6)}...${identityKey.slice(-4)}`,
  identityKey,
  badgeIconURL: '',
  badgeLabel: '',
  badgeClickURL: ''
}
const metadata = { notes: 'Met at a conference', tags: ['friends'] }
const contacts = {}
{
  const state = {}
  const saved = await words(() => new ContactsManager(contactsWallet(state)).saveContact(contact, metadata))
  if (saved !== STOP) throw new Error(`saveContact: ${saved}`)
  const output = state.created.outputs[0]
  const keyID = JSON.parse(output.customInstructions).keyID
  const lock = LockingScript.fromHex(output.lockingScript)
  const decoded = PushDrop.decode(lock)
  const [ciphertext, signature] = decoded.fields
  const plaintext = Utils.toUTF8((await wallet9.decrypt({ protocolID: CONTACT, keyID, counterparty: 'self', ciphertext })).plaintext)
  contacts.write = {
    key_id: keyID,
    custom_instructions: output.customInstructions,
    locking_script: output.lockingScript,
    locking_public_key: decoded.lockingPublicKey.toString(),
    fields: decoded.fields.length,
    plaintext,
    read_back: await contactReadBack(output.lockingScript, output.customInstructions)
  }
  // One change each to the reference's token, its key ID kept.
  const lockKey = decoded.lockingPublicKey.toString()
  const otherKeyID = Utils.toBase64(new Array(32).fill(6))
  const pd = new PushDrop(wallet9)
  const encryptSigned = async (text) => {
    const c = (await wallet9.encrypt({ protocolID: CONTACT, keyID, counterparty: 'self', plaintext: utf8(text) })).ciphertext
    const s = (await wallet9.createSignature({ protocolID: CONTACT, keyID, counterparty: 'self', data: c })).signature
    return signed(lockKey, [c, s])
  }
  const changed = [
    ['one_field', await pd.lock([ciphertext], CONTACT, keyID, 'self', false, false)],
    ['three_fields', await pd.lock([ciphertext, ciphertext], CONTACT, keyID, 'self')],
    ['bad_signature', signed(lockKey, [ciphertext, otherSignature(ciphertext)])],
    ['short_signature', signed(lockKey, [ciphertext, [1, 2, 3, 4, 5, 6, 7]])],
    ['noncanonical_envelope', loose(lockKey, [ciphertext, signature])],
    ['wrong_lock_key', await pd.lock([ciphertext], CONTACT, otherKeyID, 'self')],
    ['added_at_record', await encryptSigned(JSON.stringify({ identityKey, name: 'Alice Example', addedAt: 1700000000000, tags: [] }))],
    ['unknown_member_record', await encryptSigned(JSON.stringify({ ...contact, nickname: 'Al' }))],
    ['uppercase_key_record', await encryptSigned(JSON.stringify({ ...contact, identityKey: identityKey.toUpperCase() }))]
  ]
  contacts.changed = []
  for (const [name, changedLock] of changed) {
    contacts.changed.push({
      name,
      locking_script: changedLock.toHex(),
      read_back: await contactReadBack(changedLock.toHex(), output.customInstructions)
    })
  }
  contacts.bad_key_id = await contactReadBack(output.lockingScript, JSON.stringify({ keyID: 'not base64' }))
  // saveContact's own refusals, before any wallet call (:527-528).
  contacts.save_refusals = []
  for (const [name, record, meta] of [
    ['empty_name', { ...contact, name: '' }, undefined],
    ['noncanonical_key', { ...contact, identityKey: identityKey.toUpperCase() }, undefined],
    ['unsafe_avatar', { ...contact, avatarURL: 'javascript:alert(1)' }, undefined],
    ['metadata_not_object', contact, [1]],
    ['metadata_unsafe_name', contact, JSON.parse('{"__proto__": 1}')]
  ]) {
    const state = {}
    contacts.save_refusals.push({
      name, contact: record, metadata: meta ?? null,
      words: await words(() => new ContactsManager(contactsWallet(state)).saveContact(record, meta)),
      wallet_called: state.created !== undefined
    })
  }
  // This crate's tokens: the base's (#542's vector's tip) and the tip's.
  const base = JSON.parse(readFileSync(new URL('../vectors/contacts_protocol_542.json', import.meta.url))).crate.tip
  contacts.crate = {}
  for (const [name, token] of [['base', base], ['tip', tokens.contacts]]) {
    if (token === undefined) continue
    const instructions = JSON.stringify({ keyID: token.key_id })
    contacts.crate[name] = {
      key_id: token.key_id,
      locking_script: token.locking_script,
      fields: PushDrop.decode(LockingScript.fromHex(token.locking_script)).fields.length,
      read_back: await contactReadBack(token.locking_script, instructions)
    }
  }
}

// ---------------------------------------------------------------- identity
const ANYONE = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const identity = {}
{
  const subject = key(9).toPublicKey().toString()
  const issued = await MasterCertificate.issueCertificateForSubject(
    new ProtoWallet(key(7)), subject, { email: 'alice@example.com', name: 'Alice' },
    Utils.toBase64(new Array(32).fill(1)), async () => '00'.repeat(32) + '.0',
    Utils.toBase64(new Array(32).fill(2))
  )
  const certificate = {
    type: issued.type, subject: issued.subject, serialNumber: issued.serialNumber,
    certifier: issued.certifier, revocationOutpoint: issued.revocationOutpoint,
    signature: issued.signature, fields: { ...issued.fields }
  }
  const keyring = await MasterCertificate.createKeyringForVerifier(
    wallet9, issued.certifier, ANYONE, certificate.fields, ['email'], issued.masterKeyring, issued.serialNumber
  )
  let token
  await new IdentityClient({
    async proveCertificate () { return { keyringForVerifier: { ...keyring } } },
    async getPublicKey (args) { return wallet9.getPublicKey(args) },
    async createSignature (args) { return wallet9.createSignature(args) },
    async createAction (args) { token = args.outputs[0].lockingScript; return {} }
  }, { networkPreset: 'mainnet' }).publiclyRevealAttributes(certificate, ['email']).catch(() => {})
  const decoded = PushDrop.decode(LockingScript.fromHex(token))
  const [json, signature] = decoded.fields
  const lockKey = decoded.lockingPublicKey.toString()
  const pd = new PushDrop(wallet9)
  const IDENTITY = [1, 'identity']
  const verdict = async (lock) => {
    answering(lock)
    const wallet = {
      async getPublicKey (args) { return wallet9.getPublicKey(args) },
      async verifySignature (args) { return wallet9.verifySignature(args) },
      async getNetwork () { return { network: 'mainnet' } },
      async createAction () { throw new Error(STOP) }
    }
    const thrown = await words(() => new IdentityClient(wallet, { networkPreset: 'mainnet' })
      .revokeCertificateRevelation(certificate.serialNumber))
    return { outcome: thrown === STOP ? 'authenticated' : 'skipped', words: thrown === STOP ? null : thrown }
  }
  identity.certificate = certificate
  identity.keyring = keyring
  identity.cases = []
  for (const [name, lock] of [
    ['reference', LockingScript.fromHex(token)],
    ['one_field', await pd.lock([json], IDENTITY, '1', 'anyone', true, false)],
    ['three_fields', await pd.lock([json, json], IDENTITY, '1', 'anyone', true, true)],
    ['noncanonical_envelope', loose(lockKey, [json, signature])],
    ['wrong_lock_key', signed(subject, [json, signature])],
    ['bad_signature', signed(lockKey, [json, otherSignature(json)])]
  ]) {
    identity.cases.push({ name, locking_script: lock.toHex(), ...(await verdict(lock)) })
  }
}

// ---------------------------------------------------------------- registry
const registry = {}
{
  const operator = key(9).toPublicKey().toString()
  const fields = ['basket1', 'Basket', 'https://icon.example/basket.png', 'A basket',
    'https://doc.example/basket', operator].map(utf8)
  const BASKET = [1, 'basketmap']
  const good = await new PushDrop(wallet9).lock(fields.map((f) => [...f]), BASKET, '1', 'anyone', true, true)
  const d = PushDrop.decode(good)
  const lockKey = d.lockingPublicKey.toString()
  const signature = d.fields[6]
  registry.cases = []
  for (const [name, lock] of [
    ['reference', good],
    ['unsigned', await new PushDrop(wallet9).lock(fields.map((f) => [...f]), BASKET, '1', 'anyone', true, false)],
    ['noncanonical_envelope', loose(lockKey, [...fields, signature])],
    ['wrong_lock_key', signed(operator, [...fields, signature])],
    ['bad_signature', signed(lockKey, [...fields, otherSignature(fields.flat())])]
  ]) {
    answering(lock)
    const records = await new RegistryClient(wallet9, { networkPreset: 'mainnet' }).resolve('basket', { basketID: 'basket1' })
    registry.cases.push({
      name, locking_script: lock.toHex(),
      words: await words(() => decodeAndVerifyRegistryToken('basket', lock)),
      outcome: records.length === 1 ? 'resolved' : 'skipped'
    })
  }
}

// ---------------------------------------------------------------- kvstore
const kvstore = {}
{
  const controller = key(9).toPublicKey().toString()
  const protocolID = [1, 'kvstore']
  const keyName = 'alpha'
  const data = [utf8(JSON.stringify(protocolID)), utf8(keyName), utf8('one'), Utils.toArray(controller, 'hex')]
  const tags = utf8(JSON.stringify(['t1']))
  const pd = new PushDrop(wallet9)
  const good = await pd.lock(data.map((f) => [...f]), protocolID, keyName, 'anyone', true, true)
  const d = PushDrop.decode(good)
  const lockKey = d.lockingPublicKey.toString()
  const signature = d.fields[4]
  const ctx = { key: keyName, protocolID, controller }
  const raw = [utf8('kvstore'), utf8(keyName), utf8('one'), Utils.toArray(controller, 'hex')]
  kvstore.context = ctx
  kvstore.cases = []
  for (const [name, lock] of [
    ['reference', good],
    ['reference_tags', await pd.lock([...data, tags].map((f) => [...f]), protocolID, keyName, 'anyone', true, true)],
    ['raw_protocol', await pd.lock(raw.map((f) => [...f]), protocolID, keyName, 'anyone', true, true)],
    ['unsigned', await pd.lock(data.map((f) => [...f]), protocolID, keyName, 'anyone', true, false)],
    ['noncanonical_envelope', loose(lockKey, [...data, signature])],
    ['wrong_lock_key', signed(controller, [...data, signature])],
    ['bad_signature', signed(lockKey, [...data, otherSignature(data.flat())])]
  ]) {
    const value = await kvStoreInterpreter(sourceOf(lock), 0, ctx)
    kvstore.cases.push({
      name, locking_script: lock.toHex(),
      words: await words(() => decodeAndVerifyKVStoreToken(lock)),
      value: value ?? null
    })
  }
}

// ---------------------------------------------------------------- overlay
const overlay = {}
{
  const template = new OverlayAdminTokenTemplate(wallet9)
  const ship = await template.lock('SHIP', 'https://ship.example', 'tm_test')
  const slap = await template.lock('SLAP', 'https://slap.example', 'ls_test')
  const d = PushDrop.decode(ship)
  const lockKey = d.lockingPublicKey.toString()
  const [protocol, identityKeyBytes, domain, topic, signature] = d.fields
  const ds = PushDrop.decode(slap)
  const slapKey = ds.lockingPublicKey.toString()
  const slapData = ds.fields.slice(0, 4)
  const slapSignature = ds.fields[4]
  const SHIP = [2, 'service host interconnect']
  const pd = new PushDrop(wallet9)
  const signedFields = async (fields) => pd.lock(fields.map((f) => [...f]), SHIP, '1', 'anyone', true, true)
  const uncompressed = Utils.toArray(key(9).toPublicKey().encode(false, 'hex'), 'hex')
  const judged = async (name, lock, expected) => ({
    name, locking_script: lock.toHex(), expected: expected ?? null,
    decode_words: await words(() => OverlayAdminTokenTemplate.decode(lock)),
    verify_words: await words(() => decodeAndVerifyOverlayAdvertisement(lock, expected))
  })
  overlay.cases = [
    await judged('reference_ship', ship, 'SHIP'),
    await judged('reference_slap', slap, 'SLAP'),
    await judged('legacy_unsigned', await pd.lock([protocol, identityKeyBytes, domain, topic].map((f) => [...f]), SHIP, '1', 'anyone', true, false)),
    await judged('bad_protocol', await signedFields([utf8('SHOP'), identityKeyBytes, domain, topic])),
    await judged('http_domain', await signedFields([protocol, identityKeyBytes, utf8('http://ship.example'), topic])),
    await judged('domain_with_path', await signedFields([protocol, identityKeyBytes, utf8('https://ship.example/x'), topic])),
    await judged('bad_topic', await signedFields([protocol, identityKeyBytes, domain, utf8('tm_Test')])),
    await judged('uncompressed_identity', await signedFields([protocol, uncompressed, domain, topic])),
    await judged('short_signature', signed(lockKey, [protocol, identityKeyBytes, domain, topic, [1, 2, 3, 4, 5, 6, 7]])),
    await judged('noncanonical_envelope', loose(lockKey, [protocol, identityKeyBytes, domain, topic, signature])),
    await judged('wrong_signer', signed(lockKey, [protocol, identityKeyBytes, domain, topic, otherSignature([protocol, identityKeyBytes, domain, topic].flat())])),
    await judged('wrong_lock_key', signed(key(9).toPublicKey().toString(), [protocol, identityKeyBytes, domain, topic, signature])),
    await judged('protocol_mismatch', slap, 'SHIP'),
    await judged('slap_wrong_signer', signed(slapKey, [...slapData, otherSignature(slapData.flat())]), 'SLAP'),
    await judged('slap_wrong_lock_key', signed(key(9).toPublicKey().toString(), [...slapData, slapSignature]), 'SLAP')
  ]
  overlay.crate = []
  for (const [name, lockHex, expected] of [['ship', tokens.overlay_ship, 'SHIP'], ['slap', tokens.overlay_slap, 'SLAP']]) {
    if (lockHex !== undefined) overlay.crate.push(await judged(name, LockingScript.fromHex(lockHex), expected))
  }
}

// ---------------------------------------------------------------- storage
const storage = {}
{
  const host = key(9).toPublicKey().toString()
  const hash = new Array(32).fill(0x44)
  const url = StorageUtils.getURLForHash(hash)
  const compact = (n) => [0xfe, ...Utils.toArray(n.toString(16).padStart(8, '0'), 'hex').reverse()]
  const fields = (over = {}) => [
    Utils.toArray(host, 'hex'), over.hash ?? hash, utf8(over.location ?? 'https://host.example/file'),
    over.expiry ?? compact(4102444800), [0x10]
  ]
  const UHRP = [2, 'uhrp advertisement']
  const pd = new PushDrop(wallet9)
  const advertise = async (over, sign = true) => pd.lock(fields(over).map((f) => [...f]), UHRP, '1', 'anyone', true, sign)
  const good = await advertise({})
  const d = PushDrop.decode(good)
  const lockKey = d.lockingPublicKey.toString()
  const signature = d.fields[5]
  storage.uhrp_url = url
  storage.cases = []
  for (const [name, lock] of [
    ['reference', good],
    ['other_file', await advertise({ hash: new Array(32).fill(0x55) })],
    ['expired', await advertise({ expiry: [1] })],
    ['http_location', await advertise({ location: 'http://host.example/file' })],
    ['unsigned', await advertise({}, false)],
    ['noncanonical_envelope', loose(lockKey, [...fields(), signature])],
    ['wrong_lock_key', signed(host, [...fields(), signature])],
    ['bad_signature', signed(lockKey, [...fields(), otherSignature(fields().flat())])]
  ]) {
    answering(lock)
    const hosts = await new StorageDownloader({ networkPreset: 'mainnet' }).resolve(url)
    storage.cases.push({
      name, locking_script: lock.toHex(),
      words: await words(() => decodeAndVerifyUHRPAdvertisement(lock)),
      hosts
    })
  }
}

process.stdout.write(JSON.stringify({
  description: '#544: the six token-decode sites\' reference counterparts on the reference\'s ' +
    'tokens and on tokens changed in one respect, with their words and outcomes',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  recorder: 'tests/support/token_envelope_544.mjs',
  contacts,
  identity,
  registry,
  kvstore,
  overlay,
  storage
}, null, 2) + '\n')
