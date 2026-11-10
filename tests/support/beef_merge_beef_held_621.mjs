// #621's fold recorder: the BEEF the reference's `mergeBeef` writes when the
// target already holds an entry of the source's txid (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/Beef.ts`: `mergeBeef`, `:971-986`, snapshots
// the source through `fromBinaryStrict(toBinary())`, merges its BUMPs through
// `#mergeBumpEntry`, then each entry through `#mergeBeefTxEntry`, `:950-967`:
// a txid-only entry appended only where nothing is held, a raw or parsed one
// only where nothing or a txid alone is held; an entry held raw or parsed is
// left as it is). Only the unmodified SDK writes the bytes and supplies the
// answers. Build the bundle at the pin and run under Node 22, as the #764
// recorder is run:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_merge_beef_held_621.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_merge_beef_held_621.json
//
// The vector carries every input (the transactions' and the BUMPs' bytes and
// each case's target and source steps), so the Rust test rebuilds both BEEFs
// with this crate's writer, merges, and compares the bytes.
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, MerklePath, Transaction, Script } = await import(bundle)

const ONE = () => Script.fromHex('51')
const spend = (txid, vout) => ({
  sourceTXID: txid,
  sourceOutputIndex: vout,
  unlockingScript: ONE(),
  sequence: 0xffffffff
})
// T and U unrelated, C spending T's output.
const t = new Transaction(1, [spend('aa'.repeat(32), 0)], [{ satoshis: 1000, lockingScript: ONE() }], 0)
const T = t.id('hex')
const u = new Transaction(1, [spend('bb'.repeat(32), 0)], [{ satoshis: 2000, lockingScript: ONE() }], 0)
const c = new Transaction(1, [spend(T, 0)], [{ satoshis: 900, lockingScript: ONE() }], 0)
// #621's second fold: X proven in a target, Y named by its txid alone, A
// spending Y and B spending X.
const x = new Transaction(1, [spend('dd'.repeat(32), 0)], [{ satoshis: 3000, lockingScript: ONE() }], 0)
const X = x.id('hex')
const y = new Transaction(1, [spend('cc'.repeat(32), 0)], [{ satoshis: 4000, lockingScript: ONE() }], 0)
const a = new Transaction(1, [spend(y.id('hex'), 0)], [{ satoshis: 3900, lockingScript: ONE() }], 0)
const b = new Transaction(1, [spend(X, 0)], [{ satoshis: 2900, lockingScript: ONE() }], 0)
// #621's fourth fold: V is U with a lock time of 1, the transaction a held
// U becomes when edited in place.
const v = new Transaction(1, [spend('bb'.repeat(32), 0)], [{ satoshis: 2000, lockingScript: ONE() }], 1)
const TXS = { t, u, c, x, y, a, b, v }
const NAMES = Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [tx.id('hex'), name]))

// #621's third fold: the BUMP built in memory with its level 0 out of
// offset order, carried as its leaves (its hex alone is read back sorted).
const UNSORTED = {
  tu_800003_unsorted: {
    height: 800003,
    path: [[{ offset: 1, hash: T, txid: true }, { offset: 0, hash: u.id('hex'), txid: true }]]
  }
}

const BUMPS = {
  // T alone in a block at 800000, and again at 800001 (a reorg's second proof).
  t_800000: () => new MerklePath(800000, [[{ offset: 0, hash: T, txid: true }]]),
  t_800001: () => new MerklePath(800001, [[{ offset: 0, hash: T, txid: true }]]),
  // X alone in a block at 800002 (#621's second fold).
  x_800002: () => new MerklePath(800002, [[{ offset: 0, hash: X, txid: true }]]),
  // #621's third fold: T and U siblings in a block at 800003, level 0 held
  // out of offset order (T at 1 written before U at 0), as a caller builds it.
  tu_800003_unsorted: () => new MerklePath(800003, UNSORTED.tu_800003_unsorted.path),
  // #621's third fold: U alone in a block at 800004, a BUMP proving no entry
  // of the source it is merged into.
  u_800004: () => new MerklePath(800004, [[{ offset: 0, hash: u.id('hex'), txid: true }]])
}

// A step: `bump:<name>` (`mergeBump`), `raw:<name>` (`mergeRawTx`),
// `txid:<name>` (`mergeTxidOnly`) or `graph:c_of_t` (`mergeTransaction` of C
// carrying T, unproven, as its input's source), or `link:c_to_t` (the held
// entry C's parsed transaction given T as its input's source, in memory, T no
// entry of the BEEF; #621's second fold), or `reread:` (the BEEF replaced by
// `Beef.fromString` of its own `toHex`, a BEEF read from bytes, its cache
// held; #621's third fold), or `edit:u_to_v` (the held U's parsed transaction
// given a lock time of 1 in place, so it is V; #621's fourth fold).
const graph = () => {
  const child = Transaction.fromHex(c.toHex())
  child.inputs[0].sourceTransaction = Transaction.fromHex(t.toHex())
  return child
}
const apply = (beef, steps) => {
  for (const step of steps) {
    if (step === 'reread:') {
      beef = Beef.fromString(beef.toHex(), 'hex')
      continue
    }
    const [kind, name] = step.split(':')
    if (kind === 'bump') beef.mergeBump(BUMPS[name]())
    else if (kind === 'raw') beef.mergeRawTx(TXS[name].toBinary())
    else if (kind === 'txid') beef.mergeTxidOnly(TXS[name].id('hex'))
    else if (kind === 'graph') beef.mergeTransaction(graph())
    else if (kind === 'edit') beef.findTxid(u.id('hex')).tx.lockTime = 1
    else if (kind === 'link') beef.findTxid(c.id('hex')).tx.inputs[0].sourceTransaction = Transaction.fromHex(t.toHex())
    else throw new Error(`no step ${step}`)
  }
  return beef
}

const CASES = [
  // The rule read's scenario: T held raw under its 800000 BUMP (index 0); the
  // source carries T raw and a BUMP at 800001 that also holds T. T is held,
  // so it is left alone: index 0, both BUMPs written.
  { name: 'held_raw_keeps_its_bump_index', target: ['bump:t_800000', 'raw:t'], source: ['bump:t_800001', 'raw:t'] },
  // The same with T held raw and unproven: the source's BUMP proves it at its
  // merge (`#mergeBumpEntry`), the entry itself left alone.
  { name: 'held_unproven_raw_takes_the_merged_bump', target: ['raw:t'], source: ['bump:t_800001', 'raw:t'] },
  // C held from `mergeTransaction` with its source link to T: kept, the link
  // with it.
  { name: 'held_parsed_entry_keeps_its_links', target: ['graph:c_of_t'], source: ['raw:c'] },
  // T held txid-only under its BUMP: upgraded to the raw entry in its place,
  // its index found again.
  { name: 'held_txid_only_is_upgraded', target: ['bump:t_800000', 'txid:t', 'raw:u'], source: ['raw:t'] },
  // A txid-only source entry over a held raw one: the raw one kept.
  { name: 'txid_only_source_keeps_the_held_raw', target: ['raw:t'], source: ['txid:t'] },
  // Nothing held: appended after the target's entries, indexed by the BUMP.
  { name: 'nothing_held_is_appended', target: ['raw:u'], source: ['bump:t_800000', 'raw:t'] },
  // #621's second fold, the rule read's scenario: X held proven; the source
  // built in memory (A spending Y, B spending X, Y by its txid) and never
  // serialized before the merge. The reference merges its snapshot, in the
  // order its toBinary sorts it (B, Y, A), so the target writes Y, X, B, A.
  {
    name: 'source_merged_in_its_written_order',
    target: ['bump:x_800002', 'raw:x'],
    source: ['raw:a', 'raw:b', 'txid:y']
  },
  // #621's second fold: the source's C parsed and linked in memory to T, no
  // entry of the source. The snapshot holds C's bytes alone: C appended raw,
  // no link, T not merged.
  { name: 'linked_parsed_source_entry_merges_its_bytes_alone', target: ['raw:u'], source: ['raw:c', 'link:c_to_t'] },
  // #621's second fold: a source read from bytes is merged in the order read,
  // unsorted (its toBinary returns the bytes fromBinary read, Beef.ts:360-364,
  // :1268-1270). Read back, T is a txid alone with no index (the wire carries
  // none) after X proven, so a sort would put T first; the target writes X, T.
  {
    name: 'read_source_merged_in_its_wire_order',
    target: [],
    source: ['bump:x_800002', 'bump:t_800000', 'raw:x', 'txid:t']
  },
  // #621's third fold, the rule read's FIX: a source BUMP built in memory
  // with its level 0 out of offset order. The snapshot reads it back with
  // every level sorted by offset (MerklePath.ts:148-149), so the target,
  // holding no BUMP of that root, writes U at 0 before T at 1.
  {
    name: 'unsorted_source_bump_merged_sorted',
    target: [],
    source: ['bump:tu_800003_unsorted', 'raw:t']
  },
  // #621's third fold, the cold read's FIX: a source read from bytes (X, T
  // as read, T a txid alone), then a fresh txid merged into it: its cache is
  // ended (#markMutated, :926), so its toBinary sorts, and the target writes
  // the sort's order, not the order read.
  {
    name: 'read_source_then_txid_merged_is_sorted',
    target: [],
    source: ['bump:x_800002', 'bump:t_800000', 'raw:x', 'txid:t', 'reread:', 'txid:y']
  },
  // The same source read from bytes, then given a BUMP proving none of its
  // entries (mergeBump, #markMutated(false), :690: the cache ended, the sort
  // the read BEEF already needs): T, X where the order read is X, T.
  {
    name: 'read_source_then_bump_merged_is_sorted',
    target: [],
    source: ['bump:x_800002', 'bump:t_800000', 'raw:x', 'txid:t', 'reread:', 'bump:u_800004']
  },
  // #621's fourth fold, the rule read's FIX: the target holds U and edits it
  // in place to V; mergeBeef synchronizes the target first (Beef.ts:976,
  // :342-352), so V is found held and the source's V left alone.
  { name: 'edited_target_entry_held_raw', target: ['raw:u', 'edit:u_to_v'], source: ['raw:v'] },
  // The same with V a txid alone in the source.
  { name: 'edited_target_entry_held_txid_only', target: ['raw:u', 'edit:u_to_v'], source: ['txid:v'] }
]

const entries = beef =>
  beef.txs.map(x => ({ tx: NAMES[x.txid], bump_index: x.bumpIndex ?? null, txid_only: x.isTxidOnly }))

const cases = CASES.map(cs => {
  const target = apply(new Beef(), cs.target)
  const source = apply(new Beef(), cs.source)
  // The source is not serialized before the merge (#621's second fold): its
  // bytes are read after, the snapshot `mergeBeef` took.
  target.mergeBeef(source)
  const sourceHex = source.toHex()
  // The source read back from its bytes merged into a fresh target (#621's
  // second fold): what the reference writes for the read-back source.
  const readBackTarget = apply(new Beef(), cs.target)
  readBackTarget.mergeBeef(Beef.fromString(sourceHex, 'hex'))
  const cHeld = target.findTxid(c.id('hex'))
  const links =
    cHeld == null || cHeld.tx == null ? null : cHeld.tx.inputs.map(i => i.sourceTransaction != null)
  return {
    name: cs.name,
    target: cs.target,
    source: cs.source,
    source_beef: sourceHex,
    beef: target.toHex(),
    bumps: target.bumps.length,
    entries: entries(target),
    c_links: links,
    read_back_beef: readBackTarget.toHex()
  }
})

const vector = {
  issue: 621,
  reference: 'ts-stack@edf6e03 packages/sdk (Beef.ts:950-967, :971-986)',
  runtime: `node ${process.version}`,
  txs: Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [name, { txid: tx.id('hex'), raw: tx.toHex() }])),
  bumps: Object.fromEntries(Object.entries(BUMPS).map(([name, mp]) => [name, mp().toHex()])),
  unsorted_bumps: UNSORTED,
  cases
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
