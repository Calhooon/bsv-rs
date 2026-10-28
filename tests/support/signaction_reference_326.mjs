// The #326 witnesses: the signAction arguments the reference's ContactsManager
// (`ts-stack@edf6e03` `packages/sdk/src/identity/ContactsManager.ts:813-834`,
// `:981-1001`) and its two key-value stores, through `completeBoundAction`
// (`packages/sdk/src/wallet/completeBoundAction.ts:1111-1120`;
// `kvstore/GlobalKVStore.ts:319-389`, `:473-488`; `kvstore/LocalKVStore.ts:413-425`,
// `:515-537`), send their wallet, recorded as the wallet received them, with
// the createAction each answers.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules); `mod.ts`
// does not export ContactsManager, so the entry re-exports it under a name of
// its own (one bundle, so the clients share the SDK's classes):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf "export * from './mod.js'\nimport { ContactsManager as CM326 } from './src/identity/ContactsManager.js'\nexport const ContactsManager326 = CM326\n" \
//     > "$W/packages/sdk/entry326.ts"
//   (cd "$W/packages/sdk" && bun build entry326.ts --target node --format esm --outfile "$W/sdk326.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signaction_reference_326.mjs \
//     "$W/sdk326.mjs" > tests/vectors/signaction_reference_326.json
//
// #344 extends this recorder with --kvstore-tags. For that mode also export
// decodeAndVerifyKVStoreToken344 and kvStoreInterpreter344 from the entry's
// src/kvstore/kvStoreTokenValidation.js and kvStoreInterpreter.js, respectively.
// Rebuild that entry with the bun command above, then record with:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signaction_reference_326.mjs \
//     "$W/sdk326.mjs" --kvstore-tags > tests/vectors/kvstore_tags_344.json
// The store writes the accepted tokens; the SDK's PushDrop writer signs the
// malformed tag witnesses (which GlobalKVStore.set itself refuses to write).
// No token bytes or signatures are constructed by hand.
//
// The randomness is #310's SHA-256 counter stream, installed before the SDK
// loads, so two runs print the same file. The wallet is the ProtoWallet of the
// scalar 9 under a recorder: createAction answers a signable transaction (its
// reference the base64 text of eight bytes of 0x52) built from the arguments,
// the requested inputs spending the recorded sources and the requested outputs
// in order (a made-up funding input when none is requested), except a call
// that leaves `signAndProcess` set (the contacts manager's new output), which
// answers the finished transaction; signAction answers no transaction, so each
// client throws, aborts the action and stops before any broadcast. Each client
// first writes its token through its own create path (the contacts manager's
// `saveContact` with no listed output; each store's `set` with no token, whose
// signAction is recorded too), and the listing or the lookup
// (`LookupResolver.query`, replaced on the prototype; nothing leaves the
// process) then answers that token for the update and the removal.
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

const [sdkPath] = process.argv.slice(2)
const {
  ContactsManager326: ContactsManager, GlobalKVStore, LocalKVStore, LookupResolver, ProtoWallet, PrivateKey,
  Script, Transaction, Utils, PushDrop, decodeAndVerifyKVStoreToken344, kvStoreInterpreter344
} = await import(pathToFileURL(sdkPath).href)

const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))

// A transaction paying `outputs` from one made-up input: a token's source.
const sourceOf = (outputs) => {
  const tx = new Transaction()
  tx.addInput({
    sourceTXID: '11'.repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: Script.fromHex('51'),
    sequence: 0xffffffff
  })
  for (const o of outputs) {
    tx.addOutput({ satoshis: o.satoshis, lockingScript: Script.fromHex(o.lockingScript) })
  }
  return tx
}

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
    const outputs = args.outputs ?? []
    if (args.inputs === undefined && args.options?.signAndProcess !== false) {
      const finished = sourceOf(outputs)
      state.created = finished
      return { txid: finished.id('hex'), tx: finished.toAtomicBEEF() }
    }
    const partial = new Transaction()
    for (const input of args.inputs ?? []) {
      const [txid, vout] = input.outpoint.split('.')
      partial.addInput({
        sourceTransaction: state.sources[txid],
        sourceOutputIndex: Number(vout),
        unlockingScript: new Script(),
        sequence: 0xffffffff
      })
    }
    if ((args.inputs ?? []).length === 0) {
      const funding = sourceOf([{
        satoshis: outputs.reduce((n, o) => n + o.satoshis, 0),
        lockingScript: '51'
      }])
      partial.addInput({
        sourceTransaction: funding,
        sourceOutputIndex: 0,
        unlockingScript: new Script(),
        sequence: 0xffffffff
      })
    }
    for (const o of outputs) {
      partial.addOutput({ satoshis: o.satoshis, lockingScript: Script.fromHex(o.lockingScript) })
    }
    return { signableTransaction: { tx: partial.toAtomicBEEF(), reference: REFERENCE } }
  }
  wallet.signAction = async (args) => {
    state.signAction.push(structuredClone(args))
    return {}
  }
  wallet.abortAction = async (args) => {
    state.abortAction.push(structuredClone(args))
    return { aborted: true }
  }
  return wallet
}

// One call's record: the signAction as received (bytes as hex text), its JSON
// text (what the HTTP JSON substrate sends: a member whose value is undefined
// is not written), its members, its options' members, and the options of the
// createAction it completes.
const record = (state, stopped) => {
  if (state.signAction.length !== 1) throw new Error(`expected one signAction, got ${state.signAction.length}`)
  const sign = state.signAction.splice(0)[0]
  const create = state.createAction.splice(0).at(-1)
  const abort = state.abortAction.splice(0)
  const outputs = (create.outputs ?? []).map((o) => ({ satoshis: o.satoshis, lockingScript: o.lockingScript }))
  return {
    stopped,
    sign_action: sign,
    sign_action_json: JSON.stringify(sign),
    sign_action_members: Object.keys(sign),
    sign_action_option_members: sign.options === undefined ? null : Object.keys(sign.options),
    spend_indexes: Object.keys(sign.spends),
    create_action_outputs: outputs,
    create_action_options: create.options ?? null,
    create_action_option_members: create.options === undefined ? null : Object.keys(create.options),
    abort_action: abort
  }
}

const stop = async (f) => {
  try {
    await f()
  } catch (e) {
    return e.message
  }
  throw new Error('the client did not stop')
}

const fresh = () => ({ createAction: [], signAction: [], abortAction: [], sources: {} })

if (process.argv.includes('--kvstore-tags')) {
  counter = 0
  const state = fresh()
  const wallet = recording(state)
  let answer = { type: 'output-list', outputs: [] }
  const store = new GlobalKVStore({
    wallet,
    networkPreset: 'local',
    lookupResolver: { async query () { return answer } }
  })
  const controller = (await wallet.getPublicKey({ identityKey: true })).publicKey
  const protocolID = [1, 'kvstore']
  const key = 'alpha'
  const cases = []
  const observe = async (name, script, writer) => {
    const source = sourceOf([{ satoshis: 1, lockingScript: script.toHex() }])
    answer = { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
    let decoded = null
    let error = null
    try {
      decoded = await decodeAndVerifyKVStoreToken344(script)
    } catch (e) {
      error = e.message
    }
    const entry = await store.get({ key, controller, protocolID })
    const value = await kvStoreInterpreter344(source, 0, { key, controller, protocolID })
    cases.push({
      name, writer, script: script.toHex(), fields: PushDrop.decode(script).fields.map(Utils.toHex),
      decoded, error, entry: entry ?? null, interpreted: value ?? null
    })
    answer = { type: 'output-list', outputs: [] }
  }
  for (const [name, tags] of [
    ['untagged', undefined], ['empty_tags_omitted', []], ['tagged', ['t']],
    ['32_tags', Array.from({ length: 32 }, (_, i) => `tag${i}`)],
    ['256_byte_tag', ['é'.repeat(128)]], ['distinct_unicode_tags', ['é', 'e\u0301']]
  ]) {
    const run = record(state, await stop(() => store.set(key, 'one', { tags })))
    await observe(name, Script.fromHex(run.create_action_outputs[0].lockingScript), 'GlobalKVStore.set')
  }
  const baseFields = PushDrop.decode(Script.fromHex(cases[0].script)).fields.slice(0, -1)
  for (const [name, tags] of [
    ['explicit_empty_tags', []], ['null_tags', null], ['object_tags', {}],
    ['33_tags_before_bad_element', [null, ...Array.from({ length: 32 }, (_, i) => `tag${i}`)]],
    ['empty_tag', ['']], ['257_byte_tag', ['é'.repeat(128) + 'x']],
    ['non_string_tag', [7]], ['duplicate_tag', ['t', 't']],
    ['invalid_length_before_duplicate', ['', '']],
    ['duplicate_before_later_invalid_length', ['t', 't', '']]
  ]) {
    const script = await new PushDrop(wallet).lock(
      [...baseFields, Utils.toArray(JSON.stringify(tags), 'utf8')], protocolID, key, 'anyone', true
    )
    await observe(name, script, 'PushDrop.lock')
  }
  for (const [name, tagBytes] of [['empty_tag_bytes', []], ['zero_tag_byte', [0]]]) {
    const script = await new PushDrop(wallet).lock(
      [...baseFields, tagBytes], protocolID, key, 'anyone', true
    )
    await observe(name, script, 'PushDrop.lock')
  }
  console.log(JSON.stringify({
    description: '#344: public KVStore tag presence, bounds and refusal order; actual SDK writer output',
    reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9, built from git archive with bun; Node ' + process.version,
    site: 'kvStoreTokenValidation.ts:58-74,88-118; kvStoreInterpreter.ts:33-50; GlobalKVStore.ts:279-304,627-659',
    wallet_key: 9, cases
  }, null, 2))
  process.exit(0)
}

// The contacts manager.
counter = 0
const contacts = {}
{
  const state = fresh()
  const manager = new ContactsManager(recording(state))
  const contact = {
    name: 'Bob Example',
    identityKey: new PrivateKey(3).toPublicKey().toString(),
    avatarURL: 'https://example.com/bob.png',
    abbreviatedKey: '',
    badgeIconURL: '',
    badgeLabel: '',
    badgeClickURL: ''
  }
  await manager.saveContact(contact)
  const created = state.createAction.splice(0)[0]
  const source = state.created
  state.sources[source.id('hex')] = source
  state.listed = {
    totalOutputs: 1,
    BEEF: source.toBEEF(),
    outputs: [{
      outpoint: `${source.id('hex')}.0`,
      satoshis: 1,
      spendable: true,
      customInstructions: created.outputs[0].customInstructions
    }]
  }
  contacts.update = record(state, await stop(() => manager.saveContact({ ...contact, name: 'Bob Updated' })))
  contacts.remove = record(state, await stop(() => manager.removeContact(contact.identityKey)))
}

// A store's token: the output of the first set's createAction, carried by a
// source transaction at output 0.
const tokenOf = (state, run) => {
  const output = run.create_action_outputs[0]
  const source = sourceOf([output])
  state.sources[source.id('hex')] = source
  return source
}

// The global key-value store: its token written with no token found, then
// updated and removed with the lookup answering it.
counter = 0
const global = {}
{
  const state = fresh()
  let answer = { type: 'output-list', outputs: [] }
  LookupResolver.prototype.query = async function () { return answer }
  const store = new GlobalKVStore({ wallet: recording(state) })
  global.set_new = record(state, await stop(() => store.set('alpha', 'one')))
  const source = tokenOf(state, global.set_new)
  answer = { type: 'output-list', outputs: [{ beef: source.toBEEF(), outputIndex: 0 }] }
  global.set_update = record(state, await stop(() => store.set('alpha', 'two')))
  global.remove = record(state, await stop(() => store.remove('alpha')))
}

// The local key-value store: the same, the listing answering the token.
counter = 0
const local = {}
{
  const state = fresh()
  const store = new LocalKVStore(recording(state), 'kvstore default')
  local.set_new = record(state, await stop(() => store.set('alpha', 'one')))
  const source = tokenOf(state, local.set_new)
  state.listed = {
    totalOutputs: 1,
    BEEF: source.toBEEF(),
    outputs: [{
      outpoint: `${source.id('hex')}.0`,
      satoshis: source.outputs[0].satoshis,
      spendable: true,
      lockingScript: source.outputs[0].lockingScript.toHex(),
      tags: ['alpha']
    }]
  }
  local.set_update = record(state, await stop(() => store.set('alpha', 'two')))
  local.remove = record(state, await stop(() => store.remove('alpha')))
}

console.log(JSON.stringify({
  description: 'the signAction arguments the reference\'s ContactsManager (updating and removing a contact) and its GlobalKVStore and LocalKVStore (through completeBoundAction: a set with no token, an update, a removal) send their wallet: the reference as createAction answered it, its base64 text; the contacts manager no options; the stores { acceptDelayedBroadcast, returnTXIDOnly: false, noSend, sendWith } carried from the createAction (#326)',
  reference: '@bsv/sdk at ts-stack@edf6e03 (bundled with bun build, an entry re-exporting mod.ts and ContactsManager as ContactsManager326), run under Node ' + process.version + ' by tests/support/signaction_reference_326.mjs',
  site: 'ts-stack@edf6e03 packages/sdk/src/identity/ContactsManager.ts:776-834,941-1001; packages/sdk/src/wallet/completeBoundAction.ts:1022-1032,1111-1120; packages/sdk/src/kvstore/GlobalKVStore.ts:319-389,473-488; packages/sdk/src/kvstore/LocalKVStore.ts:413-425,515-537',
  wallet_key: 9,
  signable_reference: REFERENCE,
  contacts,
  global,
  local
}, null, 2))
