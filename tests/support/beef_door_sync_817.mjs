// #817's recorder: what the reference's doors answer and write after an
// entry is edited in place, and which BUMP index an entry takes after a
// combine (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts`).
//
// The doors that synchronize the nested transaction mutations
// (`synchronizeNestedTransactionMutations`, `:342-352`): `mergeBump` (`:688`),
// `mergeRawTx` (`:836`), `mergeTransaction` (`:876`), `findTxid` (`:498`, so
// `mergeTxidOnly`, `:920`, and the two signing lookups, `:616`, `:640`),
// `mergeBeef` (`:976`); `makeTxidOnly` (`:552-565`) does not. The BUMP txid
// map (`#ensureBumpTxidIndex`, `:576-586`) holds the index last set: built
// as the last BUMP holding each hash, set again by `#findOrInsertBump` for a
// combined or a pushed BUMP (`indexBumpTxids`, `:60-64`, `:791-811`), and
// dropped where `#synchronizeNestedBumpMutations` (`:296-309`) finds the
// BUMPs changed since its snapshot (a combine always: `MerklePath.combine`
// builds new levels, `MerklePath.ts:508-537`); the snapshot is taken by the
// reader (`:1268-1270`) and by the first BUMP-synchronizing door.
//
// Only the unmodified SDK writes the bytes and supplies the answers. Build
// the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/beef_door_sync_817.mjs "$W/sdk.mjs" tests/vectors/beef_door_sync_817.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, BeefTx, MerklePath, Transaction, Script, Utils } = await import(bundle)

const ONE = () => Script.fromHex('51')
const spend = (txid, vout) => ({
  sourceTXID: txid,
  sourceOutputIndex: vout,
  unlockingScript: ONE(),
  sequence: 0xffffffff
})
const make = (prev, sats, lockTime) =>
  new Transaction(1, [spend(prev.repeat(32), 0)], [{ satoshis: sats, lockingScript: ONE() }], lockTime)
// U held and edited in place to V (U with a lock time of 1, as #621's fourth
// fold has it); X proven at two heights; W X's sibling in the first block.
const u = make('bb', 2000, 0)
const v = make('bb', 2000, 1)
const x = make('dd', 3000, 0)
const w = make('ee', 5000, 0)
// #817's fold: U with its input moved to another source (the edit
// `edit:u_input_to_y`, the input list a refresh reads again).
const y = make('cc', 2000, 0)
// #817's fold of the rebuild: P and C, C spending P, for the sort marks
// after an edit (the strength read's S3).
const p = make('ab', 4000, 0)
const c = new Transaction(1, [spend(p.id('hex'), 0)], [{ satoshis: 3500, lockingScript: ONE() }], 0)
const TXS = { u, v, x, w, y, p, c }
const NAMES = Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [tx.id('hex'), name]))
const X = x.id('hex')
const W = w.id('hex')

const BUMPS = {
  // X and W siblings in a block at 900000, X flagged.
  b0: () => new MerklePath(900000, [[{ offset: 0, hash: X, txid: true }, { offset: 1, hash: W }]]),
  // The same block's path with W flagged: combines into b0 (one height, one root).
  b0w: () => new MerklePath(900000, [[{ offset: 0, hash: X }, { offset: 1, hash: W, txid: true }]]),
  // X alone in a block at 900001 (a second proof of X: a reorg).
  b1: () => new MerklePath(900001, [[{ offset: 0, hash: X, txid: true }]]),
  // V alone in a block at 900002.
  v_alone: () => new MerklePath(900002, [[{ offset: 0, hash: v.id('hex'), txid: true }]]),
  // #817's fold: X alone in a block at 900003 (a third proof of X).
  b2: () => new MerklePath(900003, [[{ offset: 0, hash: X, txid: true }]]),
  // #817's fold: another block at 900000 (another root): two roots at one
  // height, which this crate's `verify_valid` refuses before its sort.
  bz: () => new MerklePath(900000, [[{ offset: 0, hash: 'ab'.repeat(32), txid: true }]])
}

const name = txid => NAMES[txid] ?? txid
const bumpOf = (beef, mp) => (mp == null ? null : beef.bumps.indexOf(mp))
// A step: `bump:<b>` (`mergeBump`), `raw:<t>` (`mergeRawTx`), `txid:<t>`
// (`mergeTxidOnly`), `tx:<t>` (`mergeTransaction`, no path), `graph:<t>@<b>`
// (`mergeTransaction` of the transaction carrying the BUMP as its path),
// `edit:u_to_v` (the held U given a lock time of 1 in place), `sort:`
// (`sortTxs`), `reread:` (the BEEF replaced by its own bytes read back),
// `find:<t>` (`findTxid`), `make:<t>` (`makeTxidOnly`), `findbump:<t>`
// (`findBump`, its index in `bumps`), `sign:<t>` (`findTransactionForSigning`),
// `atomic:<t>` (`findAtomicTransaction`). A lookup's answer is recorded.
// #817's fold adds `editpub:u_to_v` (the edit through `beef.txs`, the entry
// at U's position), `edit:u_input_to_y` (U's input moved to Y's source),
// `mut:<t>` (`findTxid`, the door `find_txid_mut` is here), `inputs:<t>`
// (the found entry's `inputTxids`, each named), `atomicpath:<t>`
// (`findAtomicTransaction`'s path, its block height), `clone:` (the BEEF
// replaced by its `clone()`), `hex:` (`toHex`, the text dropped), `valid:`
// (`verifyValid`) and `atomicbin:<t>` (`toBinaryAtomic`, the bytes dropped).
// The edit door's lane (#817, `Beef::edit_tx`) adds the hand edits of the
// public `txs`, no door between: `drop:<t>` (the entry spliced out, as the
// toolbox's `retain`), `push:<t>` (`BeefTx.fromRawTx` of it pushed),
// `swap:` (the entries at 0 and 1 exchanged) and `replace:<a>_<b>` (the
// entry of `a` replaced in its place by `BeefTx.fromRawTx` of `b`).
// The fold of the rebuild adds `wire:` (the BEEF replaced by the bytes its
// `toWriter` writes, unsorted, read back), `noop:<t>` (the held entry's
// lock time set to its own value in place), `edit:y_input_to_u` (Y's input
// moved to U's txid in place) and `order:` (the entries' names in held
// order, no sort), and a case's `after` steps, applied to the target after
// its `mergeBeef`. The second fold of the rebuild adds `twin:<t>` (the BEEF
// replaced by one read from bytes holding `t` as a txid alone and then
// raw, the strength read's F1).
const apply = (beef, steps, answers) => {
  for (const step of steps) {
    const [kind, arg] = step.split(':')
    if (kind === 'reread') {
      beef = Beef.fromString(beef.toHex(), 'hex')
      continue
    }
    if (kind === 'twin') {
      const writer = new Utils.Writer()
      writer.writeUInt32LE(0xefbe0002)
      writer.writeVarIntNum(0)
      writer.writeVarIntNum(2)
      writer.writeUInt8(2)
      writer.writeReverse(Utils.toArray(TXS[arg].id('hex'), 'hex'))
      writer.writeUInt8(0)
      writer.write(TXS[arg].toBinary())
      beef = Beef.fromBinary(writer.toArray())
      continue
    }
    if (kind === 'sort') {
      beef.sortTxs()
      continue
    }
    if (kind === 'clone') {
      beef = beef.clone()
      continue
    }
    if (kind === 'hex') {
      beef.toHex()
      continue
    }
    if (kind === 'valid') {
      beef.verifyValid()
      continue
    }
    if (kind === 'atomicbin') {
      beef.toBinaryAtomic(TXS[arg].id('hex'))
      continue
    }
    if (kind === 'drop') {
      beef.txs.splice(beef.txs.findIndex(t => t.txid === TXS[arg].id('hex')), 1)
      continue
    }
    if (kind === 'push') {
      beef.txs.push(BeefTx.fromRawTx(TXS[arg].toBinary()))
      continue
    }
    if (kind === 'swap') {
      const [a, b] = [beef.txs[0], beef.txs[1]]
      beef.txs[0] = b
      beef.txs[1] = a
      continue
    }
    if (kind === 'replace') {
      const [a, b] = arg.split('_')
      const at = beef.txs.findIndex(t => t.txid === TXS[a].id('hex'))
      beef.txs[at] = BeefTx.fromRawTx(TXS[b].toBinary())
      continue
    }
    if (kind === 'wire') {
      const writer = new Utils.Writer()
      beef.toWriter(writer)
      beef = Beef.fromBinary(writer.toArray())
      continue
    }
    if (kind === 'noop') {
      const e = beef.findTxid(TXS[arg].id('hex'))
      e.tx.lockTime = e.tx.lockTime
      continue
    }
    if (step === 'edit:y_input_to_u') {
      beef.findTxid(y.id('hex')).tx.inputs[0].sourceTXID = u.id('hex')
      continue
    }
    if (kind === 'order') {
      answers.push({ step, answer: beef.txs.map(t => name(t.txid)) })
      continue
    }
    if (kind === 'editpub') {
      beef.txs[beef.txs.findIndex(t => t.txid === u.id('hex'))].tx.lockTime = 1
      continue
    }
    if (step === 'edit:u_input_to_y') {
      beef.findTxid(u.id('hex')).tx.inputs[0].sourceTXID = 'cc'.repeat(32)
      continue
    }
    if (kind === 'bump') beef.mergeBump(BUMPS[arg]())
    else if (kind === 'raw') beef.mergeRawTx(TXS[arg].toBinary())
    else if (kind === 'txid') beef.mergeTxidOnly(TXS[arg].id('hex'))
    else if (kind === 'tx') beef.mergeTransaction(Transaction.fromHex(TXS[arg].toHex()))
    else if (kind === 'graph') {
      const [t, b] = arg.split('@')
      const tx = Transaction.fromHex(TXS[t].toHex())
      tx.merklePath = BUMPS[b]()
      beef.mergeTransaction(tx)
    } else if (kind === 'edit') beef.findTxid(u.id('hex')).tx.lockTime = 1
    else if (kind === 'find' || kind === 'mut') {
      const e = beef.findTxid(TXS[arg].id('hex'))
      answers.push({ step, answer: e == null ? null : name(e.txid) })
    } else if (kind === 'inputs') {
      const e = beef.findTxid(TXS[arg].id('hex'))
      answers.push({ step, answer: e == null ? null : e.inputTxids.map(t => name(t)) })
    } else if (kind === 'atomicpath') {
      const t = beef.findAtomicTransaction(TXS[arg].id('hex'))
      answers.push({ step, answer: t?.merklePath == null ? null : t.merklePath.blockHeight })
    } else if (kind === 'make') {
      const e = beef.makeTxidOnly(TXS[arg].id('hex'))
      answers.push({ step, answer: e == null ? null : name(e.txid) })
    } else if (kind === 'findbump') {
      answers.push({ step, answer: bumpOf(beef, beef.findBump(TXS[arg].id('hex'))) })
    } else if (kind === 'sign' || kind === 'atomic') {
      const id = TXS[arg].id('hex')
      const t = kind === 'sign' ? beef.findTransactionForSigning(id) : beef.findAtomicTransaction(id)
      answers.push({ step, answer: t == null ? null : name(t.id('hex')) })
    } else throw new Error(`no step ${step}`)
  }
  return beef
}

const CASES = [
  // Finding 1: U held raw, edited in place to V, then each door.
  { name: 'an_edit_then_merge_raw_tx_finds_the_edited_entry_held', target: ['raw:u', 'edit:u_to_v', 'raw:v'] },
  { name: 'an_edit_then_merge_transaction_finds_the_edited_entry_held', target: ['raw:u', 'edit:u_to_v', 'tx:v'] },
  { name: 'an_edit_then_merge_txid_only_finds_the_edited_entry_held', target: ['raw:u', 'edit:u_to_v', 'txid:v'] },
  { name: 'an_edit_then_find_txid_answers_the_edited_txid', target: ['raw:u', 'edit:u_to_v', 'find:v', 'find:u'] },
  { name: 'an_edit_then_merge_bump_proves_the_edited_entry', target: ['raw:u', 'edit:u_to_v', 'bump:v_alone', 'find:v'] },
  { name: 'an_edit_then_the_signing_lookups_answer_the_edited_txid', target: ['raw:u', 'edit:u_to_v', 'sign:v', 'atomic:v'] },
  // Finding 3: `makeTxidOnly` after the edit, by the old txid and the new.
  { name: 'an_edit_then_make_txid_only_of_the_old_txid', target: ['raw:u', 'edit:u_to_v', 'make:u'] },
  { name: 'an_edit_then_make_txid_only_of_the_new_txid', target: ['raw:u', 'edit:u_to_v', 'make:v'] },
  // Finding 2: X held by b0 and b1; a source's BUMP combines into b0 (the
  // reader's scenario) or into b1 (its mirror), then X raw.
  { name: 'a_combine_into_the_earlier_bump_gives_its_txids_that_index', target: ['bump:b0', 'bump:b1'], source: ['bump:b0w', 'raw:x'] },
  { name: 'a_combine_into_the_later_bump_gives_its_txids_that_index', target: ['bump:b0', 'bump:b1'], source: ['bump:b1', 'raw:x'] },
  { name: 'a_combine_gives_a_txid_only_entry_that_index', target: ['bump:b0', 'bump:b1'], source: ['bump:b0w', 'txid:x'] },
  { name: 'a_combine_through_merge_bump_survives_merge_raw_tx', target: ['bump:b0', 'bump:b1', 'bump:b0w', 'raw:x'] },
  { name: 'a_combine_is_forgotten_at_the_next_bump_sync', target: ['bump:b0', 'bump:b1', 'bump:b0w', 'sort:', 'raw:x'] },
  { name: 'a_combine_is_forgotten_at_find_bump', target: ['bump:b0', 'bump:b1', 'bump:b0w', 'findbump:x', 'raw:x'] },
  { name: 'a_combine_before_any_bump_sync_survives_the_first', target: ['graph:x@b0', 'graph:x@b1', 'graph:w@b0w', 'findbump:x', 'make:x'] },
  { name: 'a_combine_before_any_bump_sync_survives_a_sort', target: ['graph:x@b0', 'graph:x@b1', 'graph:w@b0w', 'sort:', 'findbump:x', 'raw:x'] },
  { name: 'a_combine_after_a_read_is_forgotten_at_find_bump', target: ['bump:b0', 'bump:b1', 'reread:', 'graph:w@b0w', 'findbump:x', 'raw:x'] },
  // #817's fold. The edit through the public `txs`, after a lookup.
  { name: 'an_edit_through_txs_after_a_lookup_is_found_by_its_new_txid', target: ['raw:x', 'raw:u', 'find:u', 'editpub:u_to_v', 'find:v', 'find:u', 'raw:v'] },
  // S1: the refresh at the top of `mergeBump` (`:688`), seen by `makeTxidOnly`.
  { name: 'an_edit_then_merge_bump_then_make_txid_only_of_the_new_txid', target: ['raw:u', 'edit:u_to_v', 'bump:v_alone', 'make:v'] },
  // S2: `findTxid` as the mutable door while an edit waits.
  { name: 'an_edit_then_find_txid_mut_answers_the_edited_txid', target: ['raw:u', 'edit:u_to_v', 'mut:v', 'mut:u'] },
  // FIX-2: the edited entry's input list, read by the lookup.
  { name: 'an_edit_of_an_input_then_find_txid_reads_the_new_input_list', target: ['raw:u', 'edit:u_input_to_y', 'inputs:y'] },
  // S3: a push after an unsynced combine takes the pushed index.
  { name: 'a_push_after_an_unsynced_combine_takes_the_pushed_index', target: ['graph:x@b0', 'graph:x@b1', 'graph:w@b0w', 'graph:x@b2', 'raw:x'] },
  // S4: the atomic walk's map keeps an unsynced combine's index.
  { name: 'an_unsynced_combine_is_the_atomic_paths_index', target: ['graph:x@b0', 'graph:x@b1', 'graph:w@b0w', 'atomicpath:x'] },
  // S5: each BUMP-synchronizing door drops a standing combine's index.
  { name: 'a_combine_is_forgotten_at_find_atomic_transaction', target: ['raw:u', 'bump:b0', 'bump:b1', 'bump:b0w', 'atomic:u', 'raw:x'] },
  { name: 'a_combine_is_forgotten_at_merge_beef', target: ['bump:b0', 'bump:b1', 'bump:b0w'], source: ['raw:x'] },
  { name: 'a_combine_is_forgotten_at_verify_valid', target: ['bump:b0', 'bump:b1', 'bump:b0w', 'valid:', 'raw:x'] },
  { name: 'a_combine_is_forgotten_at_verify_valid_refusing_before_its_sort', target: ['bump:b0', 'bump:b1', 'bump:bz', 'bump:b0w', 'valid:', 'raw:x'] },
  { name: 'a_combine_after_a_sort_is_forgotten_at_to_hex', target: ['bump:b0', 'bump:b1', 'sort:', 'bump:b0w', 'hex:', 'raw:x'] },
  { name: 'a_combine_is_forgotten_at_to_binary_atomic', target: ['raw:u', 'bump:b0', 'bump:b1', 'bump:b0w', 'atomicbin:u', 'raw:x'] },
  // S6: a combine that changes no leaf still drops the index at the next sync.
  { name: 'a_combine_changing_no_leaf_is_forgotten_at_the_next_sync', target: ['graph:x@b0', 'graph:x@b1', 'graph:w@b0w', 'bump:b0', 'sort:', 'findbump:x'] },
  // FIX-1: a clone of a BEEF read from bytes takes the snapshot again
  // (`:1619-1620`); a clone of one never serialized does not; a clone of one
  // serialized since takes it too (the stated cell).
  { name: 'a_combine_on_a_clone_of_a_read_beef_is_forgotten_at_find_bump', target: ['bump:b0', 'bump:b1', 'reread:', 'clone:', 'graph:w@b0w', 'findbump:x', 'raw:x'] },
  { name: 'a_combine_on_a_clone_of_an_unread_beef_survives_find_bump', target: ['bump:b0', 'bump:b1', 'clone:', 'graph:w@b0w', 'findbump:x', 'raw:x'] },
  { name: 'a_combine_on_a_clone_of_a_serialized_beef', target: ['bump:b0', 'bump:b1', 'hex:', 'clone:', 'graph:w@b0w', 'findbump:x', 'raw:x'] },
  // The edit door's lane (#817): the edit then the writer and `mergeBeef`,
  // the edit onto a txid another entry holds, and the hand edits of `txs`.
  { name: 'an_edit_then_to_hex_writes_the_edited_entry_once', target: ['raw:x', 'raw:u', 'edit:u_to_v'] },
  { name: 'an_edit_then_merge_beef_finds_the_edited_entry_held', target: ['raw:u', 'edit:u_to_v'], source: ['raw:v'] },
  { name: 'an_edit_onto_a_txid_another_entry_holds', target: ['raw:u', 'raw:v', 'edit:u_to_v', 'find:v'] },
  { name: 'a_hand_drop_then_the_lookups_and_merge_raw_tx', target: ['raw:x', 'raw:u', 'raw:w', 'drop:x', 'find:w', 'find:u', 'find:x', 'raw:w'] },
  { name: 'a_hand_push_then_find_txid_and_merge_raw_tx', target: ['raw:x', 'push:w', 'find:w', 'raw:w'] },
  { name: 'a_hand_swap_then_find_each_and_merge_raw_tx', target: ['raw:x', 'raw:u', 'swap:', 'find:x', 'find:u', 'raw:x'] },
  { name: 'a_hand_replace_keeping_the_count_then_find_and_merge_raw_tx', target: ['raw:x', 'raw:u', 'replace:x_w', 'find:w', 'find:x', 'raw:w'] },
  // The fold of the rebuild (the strength read's S3): an edit keeping the
  // txid of a BEEF read children first leaves its read order to `mergeBeef`;
  // an input moved to a later entry after a write sorts the next write.
  { name: 'a_children_first_beef_read_then_an_edit_keeping_the_txid_merged_into_an_empty_beef', target: [], source: ['raw:c', 'raw:p', 'wire:', 'noop:c'], after: ['order:'] },
  { name: 'a_write_then_an_input_moved_to_a_later_entry_writes_the_parent_first', target: ['raw:y', 'raw:u', 'hex:', 'edit:y_input_to_u'] },
  // The second fold of the rebuild (the strength read's F1): a BEEF read
  // holding U as a txid alone and then raw, the raw entry edited to V; U is
  // still held by the first entry, found, and not merged a third time.
  { name: 'a_twin_read_from_bytes_then_an_edit_keeps_the_other_entry_found', target: ['twin:u', 'edit:u_to_v', 'find:u', 'find:v', 'txid:u', 'find:u'] }
]

const entries = beef =>
  beef.txs.map(t => ({
    name: name(t.txid),
    bump_index: t.bumpIndex ?? null,
    form: t.isTxidOnly ? 'txid' : 'raw'
  }))

const cases = CASES.map(c => {
  const answers = []
  let beef = apply(new Beef(), c.target, answers)
  if (c.source != null) beef.mergeBeef(apply(new Beef(), c.source, []))
  if (c.after != null) beef = apply(beef, c.after, answers)
  return { ...c, answers, beef: beef.toHex(), bumps: beef.bumps.length, entries: entries(beef) }
})

const doc = {
  comment: 'bsv-rs#817: doors after an edit in place and the BUMP index after a combine, recorded from ts-stack@edf6e03 packages/sdk by tests/support/beef_door_sync_817.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  txs: Object.fromEntries(Object.entries(TXS).map(([n, t]) => [n, { txid: t.id('hex'), raw: t.toHex() }])),
  bumps: Object.fromEntries(Object.entries(BUMPS).map(([n, b]) => [n, b().toHex()])),
  cases
}
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')
