// #904's seventh fold: a differential replay of the contacts manager's cache
// against the reference's (`ts-stack@edf6e03`
// `packages/sdk/src/identity/ContactsManager.ts`). A mode of the #326
// recorder (`signaction_reference_326.mjs --contacts-replay`, the same bundle
// and the same SHA-256 counter stream, reset before every sequence), so two
// runs print the same file:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signaction_reference_326.mjs \
//     "$W/sdk326.mjs" --contacts-replay > tests/vectors/contacts_replay.json
//
// The sequences are generated here, from the seed `SEED`, by `generate`
// below (a SHA-256 counter of its own, apart from the SDK's stream): each a
// list of steps over three contacts (the scalars 3, 4 and 5), each step one
// public call that touches the cache (a plain read, a forced read, a read by
// identity key, a save, an update, a removal, a clear), or rarely a step of
// the wallet alone (`pad`: the basket filled with outputs that are no
// contact's to 999, 1000 or 1001 entries, for the listing's bound), with zero to two
// faults of the wallet named by the call, its turn within the step and a
// mode (two modes on one call apply together, `throw` ahead of the rest). Then
// one directed sequence per survivor of the six re-reads (`DIRECTED`), each
// written out by hand as steps (never as answers: every answer is the
// reference's, run here).
//
// The wallet is the ProtoWallet of the scalar 9 over a basket it keeps: a
// listing answers the basket's entries in the order they were added
// (filtered by a tag when one is asked; the transactions merged into one
// BEEF for `entire transactions`, the scripts for `locking scripts`); a
// createAction without inputs commits its outputs at once; one with inputs
// answers a signable transaction spending the outpoints asked from the
// input BEEF and commits it at signAction (the spent entries dropped, the
// new outputs added after the rest); abortAction drops the pending action.
// `tests/support/contacts_replay_wallet.rs` is the same wallet for the Rust
// replay (`tests/contacts_replay.rs`).
//
// Each step records what a caller observes: the outcome (the error's
// message), the contacts answered (key and name, in order), the wallet's
// calls in order and the arguments the pull request pins (listOutputs',
// createAction's descriptions, inputs and outputs, signAction's spend keys
// and reference, abortAction's reference). Beside them one column is this
// crate's own rule, not the reference's (its record has no saved-at time,
// `ContactsManager.ts:171-198`): `added_at`, each answered contact's
// saved-at time as `contacts_cache.rs` keeps it (the time of its latest
// save while the cache held it, else 0), computed by `savedAt` below.
//
// The steps the generator does not make, each a stated residue of
// `docs/lanes/fix-contacts.md`: a save, an update or a read by key while the
// reference's cache is cold (its `saveContact` loads the whole basket before its tagged listing,
// `:529-531`, and its `getContacts(identityKey)` loads where this crate's
// `get_contact` reads the cache alone), and an update of a contact the cache
// lacks (`update_contact` is this crate's door, refused `ContactNotFound`).
import { createHash } from 'crypto'

const SEED = 'bsv-rs#904 fold7'
const SEQUENCES = 320
const MIN_STEPS = 4
const MAX_STEPS = 16

const hex = (bytes) => Buffer.from(bytes).toString('hex')

// The generator's own randomness: SHA-256 of `<SEED> <n>`, a byte at a time.
const generatorStream = () => {
  let n = 0
  let pool = []
  const byte = () => {
    if (pool.length === 0) pool = [...createHash('sha256').update(`${SEED} ${n++}`).digest()]
    return pool.shift()
  }
  // An integer in [0, k), by rejection on two bytes.
  const below = (k) => {
    const limit = 65536 - (65536 % k)
    for (;;) {
      const v = byte() * 256 + byte()
      if (v < limit) return v % k
    }
  }
  return { below, pick: (list) => list[below(list.length)] }
}

const BASES = ['Bob', 'Carol', 'Dave']

// The faults a step can carry, by its operation: [call, turn, mode].
const READ_FAULTS = [
  ['listOutputs', 1, 'throw'],
  ['getPublicKey', 1, 'throw'], ['getPublicKey', 2, 'throw'], ['getPublicKey', 3, 'throw'],
  ['verifySignature', 1, 'throw'], ['verifySignature', 2, 'throw'], ['verifySignature', 3, 'throw'],
  ['decrypt', 1, 'throw'], ['decrypt', 2, 'throw'], ['decrypt', 3, 'throw']
]
const SAVE_FAULTS = [
  ['createHmac', 1, 'throw'], ['listOutputs', 1, 'throw'],
  ['getPublicKey', 1, 'throw'], ['getPublicKey', 2, 'throw'],
  ['verifySignature', 1, 'throw'], ['decrypt', 1, 'throw'], ['encrypt', 1, 'throw'],
  ['createSignature', 1, 'throw'], ['createSignature', 2, 'throw'],
  ['createAction', 1, 'throw'], ['createAction', 1, 'no_tx'],
  ['createAction', 1, 'duplicate_input'], ['createAction', 1, 'missing_input'], ['createAction', 1, 'output'],
  ['signAction', 1, 'throw'], ['signAction', 1, 'no_tx'],
  ['signAction', 1, 'signed_version'], ['signAction', 1, 'signed_output'], ['signAction', 1, 'signed_script'],
  ['abortAction', 1, 'throw']
]
const REMOVE_FAULTS = [
  ['createHmac', 1, 'throw'], ['listOutputs', 1, 'throw'],
  ['getPublicKey', 1, 'throw'], ['verifySignature', 1, 'throw'], ['decrypt', 1, 'throw'],
  ['createAction', 1, 'throw'], ['createAction', 1, 'no_tx'],
  ['createAction', 1, 'duplicate_input'], ['createAction', 1, 'missing_input'],
  ['createSignature', 1, 'throw'],
  ['signAction', 1, 'throw'], ['signAction', 1, 'no_tx'],
  ['signAction', 1, 'signed_version'], ['signAction', 1, 'signed_script'],
  ['abortAction', 1, 'throw']
]

// The reference's cache as its code keeps it (`ContactsManager.ts:311-378`,
// `:527-570`, `:891-938`): warm once a load succeeded, cold at the start,
// after a failed load and after a clear (a new manager over the same
// wallet); the keys it holds. `step` applies one step's outcome to it.
const cacheModel = () => ({ warm: false, keys: [] })

// Zero, one or two faults; a second fault is drawn from the call of the one already drawn
// half the time, so two modes of one call (two faults of one signable or
// signed transaction) are reached as often as two calls.
const faultsFor = (g, menu) => {
  const roll = g.below(20)
  const count = roll < 8 ? 0 : roll < 14 ? 1 : 2
  const faults = []
  while (faults.length < count) {
    const same = faults.length === 1 && g.below(2) === 0
      ? menu.filter(x => x[0] === faults[0][0] && x[1] === faults[0][1])
      : menu
    const f = g.pick(same)
    if (!faults.some(x => x[0] === f[0] && x[1] === f[1] && x[2] === f[2])) faults.push(f)
  }
  return faults.map(([call, turn, mode]) => ({ call, turn, mode }))
}

// One sequence of steps. The model of the reference's cache decides which
// operations are allowed; it is advanced by the reference's own outcome as
// the steps are run (`run` below), so the generator draws a step, the
// reference runs it, and the next draw reads the cache it left.
const drawStep = (g, model, index) => {
  const ops = ['plain', 'plain', 'plain', 'forced', 'forced', 'remove', 'remove', 'clear']
  if (model.warm) ops.push('by_key', 'save', 'save', 'save', 'save', 'save', 'save')
  if (model.warm && model.keys.length > 0) ops.push('update', 'update')
  // A rare step of the wallet, no call of the manager's: the basket filled
  // with outputs that are no contact's (no custom instructions, `OP_1`) to
  // 999, 1000 or 1001 entries, so a load meets the listing's bound
  // (`ContactsManager.ts:361-366`).
  if (g.below(40) === 0) return { op: 'pad', total: 999 + g.below(3) }
  // A caller's retry: after a step that failed, half the time the same call
  // again without its faults (a removal that failed after its spend was
  // committed, retried, meets a basket that no longer holds the contact).
  if (model.last !== undefined && !model.last.ok && g.below(2) === 0) {
    const { faults, ...again } = model.last.step
    if (again.op !== 'update' || model.keys.includes(again.contact)) {
      if (again.op === 'save' || again.op === 'update') again.added_at = 1_000_000 + index * 1000 + again.contact
      if (model.warm || !['save', 'update', 'by_key'].includes(again.op)) return again
    }
  }
  const op = g.pick(ops)
  const step = { op }
  if (op === 'plain' || op === 'forced') step.faults = faultsFor(g, READ_FAULTS)
  if (op === 'by_key') step.contact = g.below(3)
  // A removal names a cached contact three times in four (one the chain
  // holds, so its spend is reached), any contact otherwise.
  if (op === 'remove') {
    step.contact = model.keys.length > 0 && g.below(4) !== 0 ? g.pick(model.keys) : g.below(3)
  }
  if (op === 'remove') step.faults = faultsFor(g, REMOVE_FAULTS)
  if (op === 'save') step.contact = g.below(3)
  if (op === 'update') step.contact = model.keys[g.below(model.keys.length)]
  if (op === 'save' || op === 'update') {
    step.name = g.below(2) === 0 ? `${BASES[step.contact]} Example` : `${BASES[step.contact]} v${index}`
    step.added_at = 1_000_000 + index * 1000 + step.contact
    step.faults = faultsFor(g, SAVE_FAULTS)
  }
  if (step.faults !== undefined && step.faults.length === 0) delete step.faults
  return step
}

// The directed sequences: one per survivor of the six re-reads of #904
// (`docs/lanes/fix-contacts.md`, "The seventh fold"), each the scenario its
// re-read named, the answers the reference's.
const save = (contact, name, at, faults) => ({ op: 'save', contact, name, added_at: at, ...(faults ? { faults } : {}) })
const f = (call, mode = 'throw', turn = 1) => ({ call, turn, mode })
const DIRECTED = {
  // fold: the removal path's bound input taken as 0 (`contacts_actions.rs`, P1).
  removal_bound_input: [{ op: 'forced' }, save(0, 'Bob Example', 1),
    { op: 'remove', contact: 0, faults: [f('createAction', 'duplicate_input')] },
    { op: 'remove', contact: 0, faults: [f('createAction', 'missing_input')] }, { op: 'plain' }],
  // fold2: the update signing before its refusal.
  update_signs_before_refusal: [{ op: 'forced' }, save(0, 'Bob Example', 1),
    { op: 'update', contact: 0, name: 'Bob v2', added_at: 2, faults: [f('createAction', 'duplicate_input')] },
    { op: 'update', contact: 0, name: 'Bob v3', added_at: 3, faults: [f('createAction', 'output')] }, { op: 'plain' }],
  // fold2: a removal that fails at its spend dropping the cached contact.
  removal_failure_keeps_cache: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    { op: 'remove', contact: 0, faults: [f('signAction', 'no_tx')] }, { op: 'plain' },
    { op: 'remove', contact: 0, faults: [f('signAction')] }, { op: 'plain' }],
  // fold3: the removal clearing every cached contact.
  removal_of_one_of_two: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    { op: 'remove', contact: 0 }, { op: 'plain' }, { op: 'by_key', contact: 1 }],
  // fold3: the update's two signable checks swapped.
  update_two_signable_faults: [{ op: 'forced' }, save(0, 'Bob Example', 1),
    { op: 'update', contact: 0, name: 'Bob v2', added_at: 2, faults: [f('createAction', 'duplicate_input'), f('createAction', 'output')] },
    { op: 'update', contact: 0, name: 'Bob v3', added_at: 3, faults: [f('createAction', 'missing_input'), f('createAction', 'output')] }],
  // fold4: plant A, a failed forced refresh over a loaded cache.
  failed_refresh_over_loaded: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    { op: 'forced' }, { op: 'forced', faults: [f('listOutputs')] }, { op: 'plain' }, { op: 'plain' }],
  // fold5: R2, a failed forced refresh over a loaded empty cache.
  failed_refresh_over_empty: [{ op: 'forced' }, { op: 'forced', faults: [f('listOutputs')] },
    { op: 'plain' }, { op: 'plain' }],
  // fold6b: K2, two contacts' saved-at times through a forced refresh.
  saved_at_of_two: [{ op: 'forced' }, save(0, 'Bob Example', 1700), save(1, 'Carol Example', 1800),
    { op: 'forced' }, { op: 'plain' }],
  // fold6b: K8, a plain read over two cached contacts.
  plain_read_of_two: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    { op: 'forced' }, { op: 'plain' }, { op: 'clear' }, { op: 'plain' }, { op: 'plain' }],
  // fold6b: K10, a cold plain read caching what it loaded.
  cold_plain_read_caches: [{ op: 'forced' }, save(0, 'Bob Example', 1), { op: 'clear' },
    { op: 'plain' }, { op: 'plain' }],
  // fold6b: K4 and K5, the load's limit and include (every listing's arguments).
  load_arguments: [{ op: 'plain' }, { op: 'forced' }],
  // the listing's bound at 1000 and 1001 entries (the bound's row 13 until this fold).
  listing_bound: [{ op: 'forced' }, save(0, 'Bob Example', 1), { op: 'pad', total: 1000 },
    { op: 'forced' }, { op: 'clear' }, { op: 'plain' }, { op: 'pad', total: 1001 }, { op: 'forced' }, { op: 'plain' }],
  // three contacts, cached and loaded.
  three_contacts: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    save(2, 'Dave Example', 3), { op: 'plain' }, { op: 'forced', faults: [f('decrypt', 'throw', 2)] },
    { op: 'plain' }, { op: 'forced' }, { op: 'remove', contact: 1 }, { op: 'plain' }]
}

export async function recordContactsReplay ({
  ContactsManager, ProtoWallet, PrivateKey, Transaction, Script, Beef, Utils, sourceOf, resetCounter
}) {
  const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))
  const KEYS = [3, 4, 5].map(n => new PrivateKey(n).toPublicKey().toString())

  // The wallet over its basket. `world.step` is the running step's state:
  // its faults, each call's turn, the calls and the arguments recorded.
  const basketWallet = (world) => {
    const inner = new ProtoWallet(new PrivateKey(9))
    const enter = (name) => {
      const step = world.step
      step.calls.push(name)
      step.turns[name] = (step.turns[name] ?? 0) + 1
      const modes = step.faults.filter(x => x.call === name && x.turn === step.turns[name]).map(x => x.mode)
      if (modes.includes('throw')) throw new Error(`${name} failed`)
      return modes
    }
    const wallet = {}
    for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'createHmac', 'encrypt', 'decrypt']) {
      wallet[name] = async (args) => { enter(name); return inner[name](args) }
    }
    wallet.listOutputs = async (args) => {
      enter('listOutputs')
      const tags = args.tags ?? []
      world.step.args.push({ call: 'listOutputs', basket: args.basket, include: args.include ?? null, tags, limit: args.limit ?? null, include_custom_instructions: args.includeCustomInstructions ?? null })
      const listed = world.basket.filter(e => tags.length === 0 || e.tags.some(t => tags.includes(t)))
      const scripts = args.include === 'locking scripts'
      const outputs = listed.map(e => ({
        outpoint: `${e.tx.id('hex')}.${e.vout}`,
        satoshis: e.satoshis,
        spendable: true,
        customInstructions: e.customInstructions,
        ...(scripts ? { lockingScript: e.lockingScript } : {})
      }))
      const result = { totalOutputs: outputs.length, outputs }
      if (args.include === 'entire transactions' && listed.length > 0) {
        const beef = new Beef()
        for (const e of listed) beef.mergeTransaction(e.tx)
        result.BEEF = beef.toBinary()
      }
      return result
    }
    wallet.createAction = async (args) => {
      const mode = enter('createAction')
      world.step.args.push({
        call: 'createAction',
        description: args.description,
        input_beef: args.inputBEEF !== undefined,
        inputs: args.inputs === undefined ? null : args.inputs.map(i => ({ input_description: i.inputDescription, unlocking_script_length: i.unlockingScriptLength ?? null })),
        outputs: (args.outputs ?? []).map(o => ({ output_description: o.outputDescription, satoshis: o.satoshis, basket: o.basket ?? null, tags: o.tags ?? null, custom_instructions: o.customInstructions !== undefined })),
        labels: args.labels ?? null,
        options: args.options ?? null
      })
      if (mode.includes('no_tx')) return {}
      const outputs = args.outputs ?? []
      if (args.inputs === undefined) {
        const finished = sourceOf(outputs)
        outputs.forEach((o, vout) => {
          if (o.basket === 'contacts') {
            world.basket.push({ tx: finished, vout, satoshis: o.satoshis, lockingScript: o.lockingScript, customInstructions: o.customInstructions, tags: o.tags ?? [] })
          }
        })
        return { txid: finished.id('hex'), tx: finished.toAtomicBEEF() }
      }
      const partial = new Transaction()
      for (const input of args.inputs) {
        const [txid, vout] = input.outpoint.split('.')
        partial.addInput({
          sourceTransaction: Transaction.fromBEEF(args.inputBEEF, txid),
          sourceOutputIndex: Number(vout),
          unlockingScript: new Script(),
          sequence: 0xffffffff
        })
      }
      if (outputs.length === 0) partial.addOutput({ satoshis: 0, lockingScript: Script.fromHex('006a') })
      for (const o of outputs) partial.addOutput({ satoshis: o.satoshis, lockingScript: Script.fromHex(o.lockingScript) })
      if (mode.includes('duplicate_input')) {
        const lead = partial.inputs[0]
        partial.addInput({ sourceTransaction: lead.sourceTransaction, sourceOutputIndex: lead.sourceOutputIndex, unlockingScript: new Script(), sequence: 0xffffffff })
      }
      if (mode.includes('missing_input')) partial.inputs[0].sourceOutputIndex = 1
      if (mode.includes('output')) partial.outputs[0].satoshis = 0
      world.pending = { args, partial }
      return { signableTransaction: { tx: partial.toAtomicBEEF(), reference: REFERENCE } }
    }
    wallet.signAction = async (args) => {
      const mode = enter('signAction')
      world.step.args.push({ call: 'signAction', spends: Object.keys(args.spends), reference: args.reference, options: args.options ?? null })
      if (mode.includes('no_tx')) return {}
      const { args: asked, partial } = world.pending
      world.pending = null
      const signed = Transaction.fromAtomicBEEF(partial.toAtomicBEEF())
      for (const [index, spend] of Object.entries(args.spends)) {
        signed.inputs[Number(index)].unlockingScript = Script.fromHex(spend.unlockingScript)
      }
      if (mode.includes('signed_version')) signed.version = 2
      if (mode.includes('signed_output')) signed.outputs[0].satoshis = 0
      if (mode.includes('signed_script')) signed.inputs[0].unlockingScript = Script.fromHex('00')
      const spent = asked.inputs.map(i => i.outpoint)
      world.basket = world.basket.filter(e => !spent.includes(`${e.tx.id('hex')}.${e.vout}`))
      ;(asked.outputs ?? []).forEach((o, vout) => {
        if (o.basket === 'contacts') {
          const out = signed.outputs[vout]
          world.basket.push({ tx: signed, vout, satoshis: out.satoshis, lockingScript: out.lockingScript.toHex(), customInstructions: o.customInstructions, tags: o.tags ?? [] })
        }
      })
      return { txid: signed.id('hex'), tx: signed.toAtomicBEEF() }
    }
    wallet.abortAction = async (args) => {
      enter('abortAction')
      world.step.args.push({ call: 'abortAction', reference: args.reference })
      world.pending = null
      return { aborted: true }
    }
    return wallet
  }

  const record = (contact, name) => ({
    name,
    identityKey: KEYS[contact],
    avatarURL: '',
    abbreviatedKey: '',
    badgeIconURL: '',
    badgeLabel: '',
    badgeClickURL: ''
  })

  // Runs one sequence on the reference: each step drawn (by `draw`, from the
  // model of the reference's cache) or given, run, and recorded.
  const run = async (draw, length) => {
    resetCounter()
    const world = { basket: [], pending: null, step: null }
    const wallet = basketWallet(world)
    let manager = new ContactsManager(wallet)
    const model = cacheModel()
    // This crate's saved-at rule (`contacts_cache.rs`), not the reference's.
    let savedAt = new Map()
    const steps = []
    for (let index = 0; index < length; index++) {
      const step = draw(model, index)
      world.step = { faults: step.faults ?? [], turns: {}, calls: [], args: [] }
      let answer = null
      let order = null
      let outcome
      const wasWarm = model.warm
      try {
        if (step.op === 'plain' || step.op === 'forced') {
          answer = await manager.getContacts(undefined, step.op === 'forced')
          order = step.op === 'plain' && wasWarm ? 'cache' : 'listing'
        } else if (step.op === 'by_key') {
          answer = await manager.getContacts(KEYS[step.contact])
          order = 'cache'
        } else if (step.op === 'save' || step.op === 'update') {
          await manager.saveContact(record(step.contact, step.name))
        } else if (step.op === 'remove') {
          await manager.removeContact(KEYS[step.contact])
        } else if (step.op === 'clear') {
          manager = new ContactsManager(wallet)
        } else if (step.op === 'pad') {
          const missing = step.total - world.basket.length
          if (missing > 0) {
            const junk = sourceOf(Array.from({ length: missing }, () => ({ satoshis: 1, lockingScript: '51' })))
            for (let vout = 0; vout < missing; vout++) {
              world.basket.push({ tx: junk, vout, satoshis: 1, lockingScript: '51', customInstructions: undefined, tags: [] })
            }
          }
        }
        outcome = { ok: true }
      } catch (e) {
        outcome = { error: e.message }
      }
      // The model read against the reference itself: a plain read over a
      // warm cache asks the wallet nothing, and a save over one does not
      // load the basket before its tagged listing (`:323-328`, `:529-531`).
      if (step.op === 'plain' && wasWarm && world.step.calls.length !== 0) {
        throw new Error(`the cache model is wrong: a warm plain read asked ${world.step.calls}`)
      }
      if ((step.op === 'save' || step.op === 'update') && world.step.args[0]?.include === 'locking scripts') {
        throw new Error('the cache model is wrong: a save loaded the basket')
      }
      // The reference's cache after the step, as its code leaves it.
      const ok = outcome.ok === true
      if ((step.op === 'plain' && !wasWarm) || step.op === 'forced') {
        if (ok) {
          model.warm = true
          model.keys = answer.map(c => KEYS.indexOf(c.identityKey))
          savedAt = new Map(model.keys.map(k => [k, savedAt.get(k) ?? 0]))
        } else {
          model.warm = false
          model.keys = []
          savedAt = new Map()
        }
      }
      if ((step.op === 'save' || step.op === 'update') && ok) {
        if (!model.keys.includes(step.contact)) model.keys.push(step.contact)
        savedAt.set(step.contact, step.added_at)
      }
      if (step.op === 'remove' && ok) {
        model.keys = model.keys.filter(k => k !== step.contact)
        savedAt.delete(step.contact)
      }
      if (step.op === 'clear') {
        model.warm = false
        model.keys = []
        savedAt = new Map()
      }
      model.last = { step, ok }
      steps.push({
        ...step,
        outcome,
        answer: answer === null ? null : answer.map(c => ({ identity_key: c.identityKey, name: c.name, added_at: savedAt.get(KEYS.indexOf(c.identityKey)) ?? 0 })),
        order,
        calls: world.step.calls,
        args: world.step.args
      })
    }
    return steps
  }

  const g = generatorStream()
  const generated = []
  for (let n = 0; n < SEQUENCES; n++) {
    const length = MIN_STEPS + g.below(MAX_STEPS - MIN_STEPS + 1)
    generated.push(await run((model, index) => drawStep(g, model, index), length))
  }
  const directed = {}
  for (const [name, given] of Object.entries(DIRECTED)) {
    directed[name] = await run((model, index) => given[index], given.length)
  }

  return {
    description: '#904 seventh fold: a differential replay of the contacts manager\'s cache. Sequences of public calls (a plain read, a forced read, a read by identity key, a save, an update, a removal, a clear) over three contacts and a wallet keeping a basket, with zero to two wallet faults a step, run on the reference ContactsManager; per step the outcome, the contacts answered, the wallet\'s calls in order and the pinned arguments. `added_at` is this crate\'s own rule (contacts_cache.rs), not the reference\'s.',
    reference: '@bsv/sdk at ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 (bundled with bun build, the #326 entry), run under Node ' + process.version + ' by tests/support/signaction_reference_326.mjs --contacts-replay (tests/support/contacts_replay_reference.mjs)',
    site: 'ts-stack@edf6e03 packages/sdk/src/identity/ContactsManager.ts:311-378,527-570,587-659,699-856,859-1021',
    seed: SEED,
    wallet_key: 9,
    contact_keys: KEYS,
    signable_reference: REFERENCE,
    sequences: generated,
    directed
  }
}

// One sequence per line, so the file reads and diffs by sequence.
export function writeContactsReplay (record) {
  const { sequences, directed, ...head } = record
  const lines = []
  lines.push('{')
  for (const [k, v] of Object.entries(head)) lines.push(`  ${JSON.stringify(k)}: ${JSON.stringify(v)},`)
  lines.push('  "sequences": [')
  sequences.forEach((s, i) => lines.push(`    ${JSON.stringify(s)}${i + 1 < sequences.length ? ',' : ''}`))
  lines.push('  ],')
  lines.push('  "directed": {')
  const names = Object.keys(directed)
  names.forEach((name, i) => lines.push(`    ${JSON.stringify(name)}: ${JSON.stringify(directed[name])}${i + 1 < names.length ? ',' : ''}`))
  lines.push('  }')
  lines.push('}')
  return lines.join('\n')
}
