// #904's seventh fold: a differential replay of the contacts manager's cache
// against the reference's (`ts-stack@edf6e03`
// `packages/sdk/src/identity/ContactsManager.ts`). A mode of the #326
// recorder (`signaction_reference_326.mjs --contacts-replay`, the same bundle
// and the same SHA-256 counter stream, reset before every sequence), so two
// runs print the same file:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signaction_reference_326.mjs \
//     "$W/sdk326.mjs" --contacts-replay > tests/vectors/contacts_replay.json
//
// The sequences are generated here in two passes, each from a seed of its
// own (a SHA-256 counter apart from the SDK's stream). The pass of #904's
// seventh fold, from `SEED`, by `drawStep`: each sequence a
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
// The pass of #959, from `SEED_959`, by `drawStep959` (the steps of the
// seventh fold's pass are unchanged by it, draw for draw): four contacts
// (the scalar 6 with the three), every member `validateContact` keeps drawn
// for a save and an update (`ContactsManager.ts:171-198`: the avatar, the
// abbreviated key, the three badge members and the metadata, each a value
// the validator returns as given), and a save, an update and a read by key
// drawn over a cold cache too (`cold: true` on the step: the reference's
// `saveContact` and `getContacts(identityKey)` load the whole basket there,
// `:529-531`, `:331-338`). A sequence that leaves the basket holding two
// outputs of one key is not kept (the stated cell of #959: a read by key
// answers every entry of the key there and the first here); the count of
// those is `discarded_959`.
//
// Each step records what a caller observes: the outcome (the error's
// message), the contacts answered (every member of the record, in order),
// the wallet's calls in order and the arguments pinned (listOutputs',
// createAction's descriptions, inputs and outputs, signAction's spend keys
// and reference, abortAction's reference, and since #959 createHmac's
// protocol, key ID, counterparty and data and encrypt's protocol and
// counterparty). Beside them one column is this
// crate's own rule, not the reference's (its record has no saved-at time,
// `ContactsManager.ts:171-198`): `added_at`, each answered contact's
// saved-at time as `contacts_cache.rs` keeps it (the time of its latest
// save while the cache held it, else 0), computed by `savedAt` below.
//
// The steps the generator does not make: an update of a contact a warm
// cache lacks (`update_contact` is this crate's door, refused
// `ContactNotFound`), and a member value the validator rewrites (a
// `badgeClickURL` the URL parser serializes otherwise, an empty `metadata`
// object): those are the two directed sequences
// `save_caches_the_validated_record_959` and its cold twin.
//
// The cells of #991's fold (`STATED_959`, recorded as `stated_959`, beside
// the sequences and never among them: `tests/contacts_replay.rs`'s replay
// does not run them; the name is the fold's, kept so the recorded line is
// the one beta held): three sequences, each a save of exactly such a value
// (a `badgeClickURL` of `https://example.com`, which `safeNavigation`
// returns as `https://example.com/`, `:104-122`; an empty `metadata`
// object; tags and notes given inside `metadata`), and since #959's fold
// two more after them (notes alone inside `metadata`; tags alone), read from the warm cache
// (a plain read and a read by key) and after a forced refresh. The
// reference caches the record `validateContact` returned (`:527-534`,
// `:566`), so its warm answer is its refreshed one, and so is this crate's
// since #959's conforming lane, held cell by cell by
// `a_save_caches_the_validated_record_959`.
import { createHash } from 'crypto'

const SEED = 'bsv-rs#904 fold7'
const SEQUENCES = 320
const SEED_959 = 'bsv-rs#959'
const SEQUENCES_959 = 200
const MIN_STEPS = 4
const MAX_STEPS = 16

const hex = (bytes) => Buffer.from(bytes).toString('hex')

// The generator's own randomness: SHA-256 of `<SEED> <n>`, a byte at a time.
const generatorStream = (seed = SEED) => {
  let n = 0
  let pool = []
  const byte = () => {
    if (pool.length === 0) pool = [...createHash('sha256').update(`${seed} ${n++}`).digest()]
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

const BASES = ['Bob', 'Carol', 'Dave', 'Erin']

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
const cacheModel = () => ({ warm: false, keys: [], chain: [] })

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

// #959's pass. The faults a step can carry there: the seventh fold's and
// the later turns a load ahead of the step's own calls moves them to (a cold
// save's tagged listing is its second listing; with four contacts loaded
// its own key call is its fifth).
const turns = (call, from, to) => Array.from({ length: to - from + 1 }, (_, i) => [call, from + i, 'throw'])
const READ_FAULTS_959 = [
  ['listOutputs', 1, 'throw'],
  ...turns('getPublicKey', 1, 4), ...turns('verifySignature', 1, 4), ...turns('decrypt', 1, 4)
]
const SAVE_FAULTS_959 = [
  ...SAVE_FAULTS,
  ['listOutputs', 2, 'throw'],
  ...turns('getPublicKey', 3, 6), ...turns('verifySignature', 2, 5), ...turns('decrypt', 2, 5),
  ['createSignature', 3, 'throw']
]

// The member values drawn for a save and an update, each one the validator
// returns as given (`safeResource`, `boundedString`, `safeNavigation` on a
// URL already in its serialized form, `sanitizeMetadata`).
const AVATARS = ['', 'https://example.com/avatar.png', 'ipfs://avatar']
const ICONS = ['', 'https://example.com/badge.svg']
const LABELS = ['', 'Friend', 'Work contact']
const CLICKS = ['', 'https://example.com/', 'https://example.com/badge?of=contact']
const METADATA = [
  undefined, undefined,
  { notes: 'met at a conference' },
  { tags: ['work', 'Friend'] },
  { notes: 'n', tags: ['a'], alias: 'b', rank: 2 },
  { nested: { list: [1, 2, { deep: null }], flag: true } }
]
const membersFor = (g, contact) => {
  const members = {
    avatar_url: g.pick(AVATARS),
    abbreviated_key: g.pick(['', `${BASES[contact].toLowerCase()}...`, 'abbreviated']),
    badge_icon_url: g.pick(ICONS),
    badge_label: g.pick(LABELS),
    badge_click_url: g.pick(CLICKS)
  }
  const metadata = g.pick(METADATA)
  if (metadata !== undefined) members.metadata = metadata
  return members
}

// One step of #959's pass. A save and a read by key are drawn whatever the
// cache; an update of a contact the warm cache holds, or over a cold cache of
// one the chain is taken to hold (`model.chain`: the keys saved and not
// removed, by the steps' outcomes).
const drawStep959 = (g, model, index) => {
  const ops = ['plain', 'plain', 'plain', 'forced', 'forced', 'remove', 'clear',
    'by_key', 'by_key', 'save', 'save', 'save', 'save', 'save', 'save', 'save']
  const held = model.warm ? model.keys : model.chain
  if (held.length > 0) ops.push('update', 'update', 'update')
  if (g.below(60) === 0) return { op: 'pad', total: 999 + g.below(3) }
  if (model.last !== undefined && !model.last.ok && g.below(2) === 0) {
    const { faults, ...again } = model.last.step
    if (again.op === 'update' && model.warm && !model.keys.includes(again.contact)) again.op = 'save'
    if (again.op === 'save' || again.op === 'update') again.added_at = 2_000_000 + index * 1000 + again.contact
    return again
  }
  const op = g.pick(ops)
  const step = { op }
  if (op === 'plain' || op === 'forced') step.faults = faultsFor(g, READ_FAULTS_959)
  if (op === 'by_key') {
    step.contact = g.below(4)
    step.faults = faultsFor(g, READ_FAULTS_959)
  }
  if (op === 'remove') {
    step.contact = held.length > 0 && g.below(4) !== 0 ? g.pick(held) : g.below(4)
    step.faults = faultsFor(g, REMOVE_FAULTS)
  }
  // A save names a contact not held two times in three, so four are
  // cached and listed often.
  if (op === 'save') {
    const missing = [0, 1, 2, 3].filter(k => !held.includes(k))
    step.contact = missing.length > 0 && g.below(3) !== 0 ? g.pick(missing) : g.below(4)
  }
  if (op === 'update') step.contact = g.pick(held)
  if (op === 'save' || op === 'update') {
    step.name = g.below(2) === 0 ? `${BASES[step.contact]} Example` : `${BASES[step.contact]} v${index}`
    step.added_at = 2_000_000 + index * 1000 + step.contact
    step.members = membersFor(g, step.contact)
    step.faults = faultsFor(g, SAVE_FAULTS_959)
  }
  if (step.faults !== undefined && step.faults.length === 0) delete step.faults
  return step
}

// The directed sequences: one per survivor of the six re-reads of #904
// (`docs/lanes/fix-contacts.md`, "The seventh fold"), each the scenario its
// re-read named, the answers the reference's.
const save = (contact, name, at, faults, members) => ({ op: 'save', contact, name, added_at: at, ...(members ? { members } : {}), ...(faults ? { faults } : {}) })
const update = (contact, name, at, members, faults) => ({ ...save(contact, name, at, faults, members), op: 'update' })
const FULL = { avatar_url: 'https://example.com/avatar.png', abbreviated_key: 'bob...', badge_icon_url: 'https://example.com/badge.svg', badge_label: 'Friend', badge_click_url: 'https://example.com/', metadata: { notes: 'met at a conference', tags: ['work', 'Friend'], alias: 'b' } }
const OTHER = { avatar_url: 'ipfs://avatar', abbreviated_key: 'abbreviated', badge_icon_url: '', badge_label: 'Work contact', badge_click_url: 'https://example.com/badge?of=contact', metadata: { rank: 2 } }
// Member values the validator rewrites or keeps in a form of its own
// (`safeNavigation`'s `parsed.toString()`, `:104-122`; `sanitizeMetadata` on
// an empty object and on empty `tags`, `:161-169`).
const REWRITTEN = { avatar_url: '', abbreviated_key: 'bob...', badge_icon_url: '', badge_label: '', badge_click_url: 'https://example.com', metadata: {} }
const REWRITTEN_AGAIN = { avatar_url: '', abbreviated_key: '', badge_icon_url: '', badge_label: 'Friend', badge_click_url: 'HTTPS://EXAMPLE.com:443/a b?q=1#f', metadata: { tags: [] } }
const TAGGED = { avatar_url: '', abbreviated_key: 'carol...', badge_icon_url: '', badge_label: '', badge_click_url: 'http://localhost', metadata: { notes: '', tags: ['Work'], alias: 'c' } }
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
    { op: 'plain' }, { op: 'forced' }, { op: 'remove', contact: 1 }, { op: 'plain' }],
  // #959: a save over a cold cache, empty and holding one; a cold update.
  cold_save_959: [save(0, 'Bob Example', 1), { op: 'plain' }, { op: 'clear' },
    save(1, 'Carol Example', 2), { op: 'plain' }, { op: 'clear' },
    update(0, 'Bob v2', 3), { op: 'plain' }, { op: 'forced' }],
  // #959: a cold save whose load fails, and one whose tagged listing fails after its load.
  cold_save_listing_faults_959: [{ op: 'forced' }, save(0, 'Bob Example', 1), { op: 'clear' },
    save(1, 'Carol Example', 2, [f('listOutputs')]), { op: 'plain' }, { op: 'clear' },
    save(1, 'Carol Example', 3, [f('listOutputs', 'throw', 2)]), { op: 'plain' }],
  // #959: a read by key over a cold cache, then warm; one whose load fails.
  cold_read_by_key_959: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    { op: 'clear' }, { op: 'by_key', contact: 1 }, { op: 'by_key', contact: 0 }, { op: 'by_key', contact: 2 },
    { op: 'clear' }, { op: 'by_key', contact: 0, faults: [f('listOutputs')] }, { op: 'by_key', contact: 0 }],
  // #959: every member written by a save and replaced by an update, cached and loaded.
  members_replaced_by_an_update_959: [{ op: 'forced' }, save(0, 'Bob Example', 1, undefined, FULL),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, update(0, 'Bob v2', 2, OTHER), { op: 'plain' },
    { op: 'forced' }, update(0, 'Bob v3', 3, {}), { op: 'plain' }, { op: 'forced' }],
  // #959: four contacts; the head removed, the third updated, the head saved again.
  four_contacts_959: [{ op: 'forced' }, save(0, 'Bob Example', 1), save(1, 'Carol Example', 2),
    save(2, 'Dave Example', 3), save(3, 'Erin Example', 4), { op: 'plain' },
    update(2, 'Dave v2', 5, OTHER), { op: 'plain' }, { op: 'remove', contact: 0 }, { op: 'plain' },
    save(0, 'Bob Example', 6), { op: 'plain' }, { op: 'forced' }, { op: 'remove', contact: 2 }, { op: 'plain' }],
  // #959 (the conforming lane): a save caches the record the validator
  // returned (`:527`, `:566`), so a read answered from the cache equals the
  // read after a refresh: a `badgeClickURL` the URL parser serializes
  // otherwise, an empty `metadata`, tags and notes given through it.
  save_caches_the_validated_record_959: [{ op: 'forced' }, save(0, 'Bob Example', 1, undefined, REWRITTEN),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' },
    update(0, 'Bob v2', 2, REWRITTEN_AGAIN), { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' },
    save(1, 'Carol Example', 3, undefined, TAGGED), { op: 'plain' }, { op: 'forced' }],
  // #959 (the conforming lane): the same over a cold cache, the save loading the basket ahead of it.
  cold_save_caches_the_validated_record_959: [save(0, 'Bob Example', 1, undefined, REWRITTEN), { op: 'plain' },
    { op: 'by_key', contact: 0 }, { op: 'clear' }, update(0, 'Bob v2', 2, REWRITTEN_AGAIN), { op: 'plain' },
    { op: 'clear' }, { op: 'by_key', contact: 0 }, { op: 'forced' }]
}

// The cells of #991's fold: a save of a value the validator rewrites, read
// warm and after a forced refresh (steps alone: every answer is the
// reference's).
const EMPTY = { avatar_url: '', abbreviated_key: '', badge_icon_url: '', badge_label: '', badge_click_url: '' }
const STATED_959 = {
  click_url_the_validator_rewrites: [{ op: 'forced' },
    save(0, 'Bob Example', 1, undefined, { ...EMPTY, badge_click_url: 'https://example.com' }),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' }, { op: 'plain' }],
  empty_metadata_object: [{ op: 'forced' },
    save(0, 'Bob Example', 1, undefined, { ...EMPTY, metadata: {} }),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' }, { op: 'plain' }],
  tags_and_notes_inside_metadata: [{ op: 'forced' },
    save(0, 'Bob Example', 1, undefined, { ...EMPTY, metadata: { tags: ['work'], notes: 'met at a conference' } }),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' }, { op: 'plain' }],
  // #959's fold (the strength read's minor): one of the two members alone.
  notes_alone_inside_metadata: [{ op: 'forced' },
    save(0, 'Bob Example', 1, undefined, { ...EMPTY, metadata: { notes: 'met at a conference' } }),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' }, { op: 'plain' }],
  tags_alone_inside_metadata: [{ op: 'forced' },
    save(0, 'Bob Example', 1, undefined, { ...EMPTY, metadata: { tags: ['work'] } }),
    { op: 'plain' }, { op: 'by_key', contact: 0 }, { op: 'forced' }, { op: 'plain' }]
}

export async function recordContactsReplay ({
  ContactsManager, ProtoWallet, PrivateKey, Transaction, Script, Beef, Utils, sourceOf, resetCounter
}) {
  const REFERENCE = Utils.toBase64(new Array(8).fill(0x52))
  const KEYS = [3, 4, 5, 6].map(n => new PrivateKey(n).toPublicKey().toString())

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
    for (const name of ['getPublicKey', 'createSignature', 'verifySignature', 'decrypt']) {
      wallet[name] = async (args) => { enter(name); return inner[name](args) }
    }
    wallet.createHmac = async (args) => {
      enter('createHmac')
      world.step.args.push({ call: 'createHmac', protocol_id: args.protocolID, key_id: args.keyID, counterparty: args.counterparty ?? null, data: hex(args.data) })
      return inner.createHmac(args)
    }
    wallet.encrypt = async (args) => {
      enter('encrypt')
      world.step.args.push({ call: 'encrypt', protocol_id: args.protocolID, counterparty: args.counterparty ?? null })
      return inner.encrypt(args)
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

  const record = (step) => {
    const members = step.members ?? {}
    const contact = {
      name: step.name,
      identityKey: KEYS[step.contact],
      avatarURL: members.avatar_url ?? '',
      abbreviatedKey: members.abbreviated_key ?? '',
      badgeIconURL: members.badge_icon_url ?? '',
      badgeLabel: members.badge_label ?? '',
      badgeClickURL: members.badge_click_url ?? ''
    }
    if (members.metadata !== undefined) contact.metadata = structuredClone(members.metadata)
    return contact
  }
  // The identity keys the basket holds in two outputs (the stated cell).
  const heldTwice = (world) => {
    const tags = world.basket.filter(e => e.tags.length > 0).map(e => e.tags[0])
    return new Set(tags).size !== tags.length
  }

  // Runs one sequence on the reference: each step drawn (by `draw`, from the
  // model of the reference's cache) or given, run, and recorded.
  const run = async (draw, length) => {
    resetCounter()
    const world = { basket: [], pending: null, step: null }
    const wallet = basketWallet(world)
    let manager = new ContactsManager(wallet)
    const model = cacheModel()
    let twice = false
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
          await manager.saveContact(record(step))
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
      if (wasWarm && (step.op === 'save' || step.op === 'update') && world.step.args[0]?.include === 'locking scripts') {
        throw new Error('the cache model is wrong: a save loaded the basket')
      }
      // The reference's cache after the step, as its code leaves it.
      const ok = outcome.ok === true
      // A save, an update or a read by key over a cold cache loads the
      // basket ahead of its own calls (`:529-531`, `:331-338`); the load
      // fails with its listing alone (its reads are settled, `:507-513`).
      // What it cached is read back from the reference, which asks the
      // wallet nothing for it.
      const cold = !wasWarm && ['save', 'update', 'by_key'].includes(step.op)
      if (cold) {
        const loadFailed = world.step.calls[0] === 'listOutputs' &&
          (outcome.error === 'listOutputs failed' && world.step.calls.length === 1 ||
            (outcome.error ?? '').startsWith('Invalid contacts result'))
        if (world.step.calls[0] !== 'listOutputs') throw new Error('the cache model is wrong: a cold step did not load')
        if (!loadFailed) {
          const recorded = world.step
          world.step = { faults: [], turns: {}, calls: [], args: [] }
          const cached = await manager.getContacts()
          if (world.step.calls.length !== 0) throw new Error('the cache model is wrong: a cold step left the cache cold')
          world.step = recorded
          model.warm = true
          model.keys = cached.map(c => KEYS.indexOf(c.identityKey))
          savedAt = new Map(model.keys.map(k => [k, 0]))
        }
      }
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
        if (!model.chain.includes(step.contact)) model.chain.push(step.contact)
        savedAt.set(step.contact, step.added_at)
      }
      if (step.op === 'remove' && ok) {
        model.keys = model.keys.filter(k => k !== step.contact)
        model.chain = model.chain.filter(k => k !== step.contact)
        savedAt.delete(step.contact)
      }
      if (step.op === 'clear') {
        model.warm = false
        model.keys = []
        savedAt = new Map()
      }
      model.last = { step, ok }
      twice ||= heldTwice(world)
      steps.push({
        ...step,
        ...(cold ? { cold: true } : {}),
        outcome,
        answer: answer === null
          ? null
          : answer.map(c => ({
            identity_key: c.identityKey,
            name: c.name,
            added_at: savedAt.get(KEYS.indexOf(c.identityKey)) ?? 0,
            avatar_url: c.avatarURL,
            abbreviated_key: c.abbreviatedKey,
            badge_icon_url: c.badgeIconURL,
            badge_label: c.badgeLabel,
            badge_click_url: c.badgeClickURL,
            metadata: c.metadata ?? null
          })),
        order,
        calls: world.step.calls,
        args: world.step.args
      })
    }
    return { steps, twice }
  }

  const g = generatorStream()
  const generated = []
  for (let n = 0; n < SEQUENCES; n++) {
    const length = MIN_STEPS + g.below(MAX_STEPS - MIN_STEPS + 1)
    const { steps, twice } = await run((model, index) => drawStep(g, model, index), length)
    if (twice) throw new Error(`sequence ${n} of the seventh fold's pass holds a key twice`)
    generated.push(steps)
  }
  // #959's pass: a stream of its own, so the pass above is drawn as it was.
  const g959 = generatorStream(SEED_959)
  let discarded = 0
  while (generated.length < SEQUENCES + SEQUENCES_959) {
    const length = MIN_STEPS + g959.below(MAX_STEPS - MIN_STEPS + 1)
    const { steps, twice } = await run((model, index) => drawStep959(g959, model, index), length)
    if (twice) discarded++
    else generated.push(steps)
  }
  const directed = {}
  for (const [name, given] of Object.entries(DIRECTED)) {
    const { steps, twice } = await run((model, index) => given[index], given.length)
    if (twice) throw new Error(`directed ${name} holds a key twice`)
    directed[name] = steps
  }
  // After every sequence above, so each of them is recorded as it was.
  const stated = {}
  for (const [name, given] of Object.entries(STATED_959)) {
    const { steps, twice } = await run((model, index) => given[index], given.length)
    if (twice) throw new Error(`stated ${name} holds a key twice`)
    stated[name] = steps
  }

  return {
    description: '#904 seventh fold and #959: a differential replay of the contacts manager\'s cache. Sequences of public calls (a plain read, a forced read, a read by identity key, a save, an update, a removal, a clear) over three contacts (four, with every member of the record drawn and the cold-cache save, update and read by key, in the sequences after the leading 320) and a wallet keeping a basket, with zero to two wallet faults a step, run on the reference ContactsManager; per step the outcome, the contacts answered (every member validateContact keeps), the wallet\'s calls in order and the pinned arguments. `added_at` is this crate\'s own rule (contacts_cache.rs), not the reference\'s.',
    reference: '@bsv/sdk at ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 (bundled with bun build, the #326 entry), run under Node ' + process.version + ' by tests/support/signaction_reference_326.mjs --contacts-replay (tests/support/contacts_replay_reference.mjs)',
    site: 'ts-stack@edf6e03 packages/sdk/src/identity/ContactsManager.ts:311-378,527-570,587-659,699-856,859-1021',
    seed: SEED,
    seed_959: SEED_959,
    generated: { fold7: SEQUENCES, bucket_959: SEQUENCES_959 },
    discarded_959: discarded,
    wallet_key: 9,
    contact_keys: KEYS,
    signable_reference: REFERENCE,
    stated_959: stated,
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
