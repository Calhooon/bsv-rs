// #757 recorder: the BUMP index the reference writes into an entry that two
// BUMPs of one BEEF prove, and the path `#addInputProof` attaches to a
// transaction that already carries one (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/Beef.ts`: `#tryToValidateBumpIndex`,
// `:1329-1340`, reads the level-0 index of `:576-585`, a `Map.set` over the
// BUMPs in order, so the LAST BUMP holding the txid; `#mergeBumpEntry`,
// `:774-786`, gives an entry without an index the BUMP being merged;
// `#addInputProof`, `:649-668`, sets `current.merklePath = mp` whenever
// `findBump` answers and descends a transaction only when it does not).
// Only the unmodified SDK writes the bytes and supplies the answers. Build
// the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_bump_index_757.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_bump_index_757.json
//
// The vector carries every input (the transactions' and the BUMPs' bytes,
// each case's merge steps), so the Rust test rebuilds each BEEF with this
// crate's writer and compares the bytes.
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
// The #732 recorder's parent and child, and a grandchild spending the child.
const parent = new Transaction(
  1,
  [spend('aa'.repeat(32), 0)],
  [{ satoshis: 1000, lockingScript: ONE() }, { satoshis: 2000, lockingScript: ONE() }],
  0
)
const P = parent.id('hex')
const child = new Transaction(1, [spend(P, 0), spend(P, 1)], [{ satoshis: 2500, lockingScript: ONE() }], 0)
const C = child.id('hex')
const grandchild = new Transaction(1, [spend(C, 0)], [{ satoshis: 2400, lockingScript: ONE() }], 0)
const G = grandchild.id('hex')
const TXS = { parent, child, grandchild }
const SIBLING = 'bb'.repeat(32)

// The BUMPs, by name, each a root of its own.
const BUMPS = {
  // The parent alone at height 800000: the root is the txid.
  alone_800000: () => new MerklePath(800000, [[{ offset: 0, hash: P, txid: true }]]),
  // The parent at offset 0 beside a sibling, at height 800001.
  left_800001: () => new MerklePath(800001, [[{ offset: 0, hash: P, txid: true }, { offset: 1, hash: SIBLING }]]),
  // The parent at offset 1 beside a sibling, at height 800000 (one height, another root).
  right_800000: () => new MerklePath(800000, [[{ offset: 0, hash: SIBLING }, { offset: 1, hash: P, txid: true }]]),
  // The parent as an unflagged sibling of a flagged leaf, at height 800002.
  sibling_800002: () =>
    new MerklePath(800002, [[{ offset: 0, hash: SIBLING, txid: true }, { offset: 1, hash: P }]]),
  // The child alone at height 800003: the path a caller sets on it.
  child_800003: () => new MerklePath(800003, [[{ offset: 0, hash: C, txid: true }]]),
  // The grandchild alone at height 800004: a BUMP that does not hold the parent (#766).
  grandchild_800004: () => new MerklePath(800004, [[{ offset: 0, hash: G, txid: true }]])
}

// Item 1: merge steps (`bump:<name>`, `raw:<tx>`, `txid:<tx>`), then the
// written BEEF, the parent's index, and the atomic BEEF of each subject.
const INDEX_CASES = [
  { name: 'raw_after_both', steps: ['bump:alone_800000', 'bump:left_800001', 'raw:parent'], atomic: ['parent'] },
  {
    name: 'raw_after_both_reversed',
    steps: ['bump:left_800001', 'bump:alone_800000', 'raw:parent'],
    atomic: ['parent']
  },
  {
    name: 'raw_after_one_height_two_roots',
    steps: ['bump:alone_800000', 'bump:right_800000', 'raw:parent'],
    atomic: ['parent']
  },
  { name: 'raw_between', steps: ['bump:alone_800000', 'raw:parent', 'bump:left_800001'], atomic: ['parent'] },
  { name: 'raw_before_both', steps: ['raw:parent', 'bump:alone_800000', 'bump:left_800001'], atomic: ['parent'] },
  {
    name: 'raw_after_both_with_child',
    steps: ['bump:alone_800000', 'bump:left_800001', 'raw:parent', 'raw:child'],
    atomic: ['parent', 'child']
  },
  { name: 'txid_only_after_both', steps: ['bump:alone_800000', 'bump:left_800001', 'txid:parent'], atomic: [] },
  {
    name: 'raw_after_a_sibling_leaf',
    steps: ['bump:alone_800000', 'bump:sibling_800002', 'raw:parent'],
    atomic: ['parent']
  },
  // The fold of #757: a txid-only entry's BUMP in an atomic BEEF
  // (`#copySelectedTransactions`, `:448-470`), `makeTxidOnly`'s index
  // (`:550-565`), and an entry merged before a BUMP holding it as a sibling
  // (`#tryMarkTxProvenByBump`, `:813-822`).
  {
    name: 'txid_only_after_both_with_child',
    steps: ['bump:alone_800000', 'bump:left_800001', 'txid:parent', 'raw:child'],
    atomic: ['child']
  },
  {
    name: 'made_txid_only_between_with_child',
    steps: ['bump:alone_800000', 'raw:parent', 'bump:left_800001', 'raw:child', 'txidonly:parent'],
    atomic: ['child']
  },
  { name: 'raw_before_a_sibling_leaf', steps: ['raw:parent', 'bump:sibling_800002'], atomic: ['parent'] },
  // #766: a txid-only entry that reaches the atomic writer without an index
  // (`index:parent=none`, as one read from bytes carries none), and one whose
  // index names a BUMP that does not hold its txid (`index:parent=1`): the
  // reference's `#copySelectedTransactions` (`:448-470`) copies a BUMP only
  // for an entry `#hasMatchingBump` (`:436-446`) proves, so neither atomic
  // BEEF carries a BUMP and the copied entry's index is `undefined`.
  {
    name: 'txid_only_without_an_index_with_child',
    steps: ['bump:alone_800000', 'bump:left_800001', 'txid:parent', 'raw:child', 'index:parent=none'],
    atomic: ['child']
  },
  {
    name: 'txid_only_naming_a_bump_without_its_txid_with_child',
    steps: ['bump:alone_800000', 'bump:grandchild_800004', 'txid:parent', 'raw:child', 'index:parent=1'],
    atomic: ['child']
  }
]

const build = steps => {
  const beef = new Beef()
  for (const step of steps) {
    const [kind, name] = step.split(':')
    if (kind === 'bump') beef.mergeBump(BUMPS[name]())
    else if (kind === 'raw') beef.mergeRawTx(TXS[name].toBinary())
    else if (kind === 'txidonly') beef.makeTxidOnly(TXS[name].id('hex'))
    else if (kind === 'index') {
      const [tx, index] = name.split('=')
      beef.findTxid(TXS[tx].id('hex')).bumpIndex = index === 'none' ? undefined : Number(index)
    }
    else beef.mergeTxidOnly(TXS[name].id('hex'))
  }
  return beef
}

const index_cases = INDEX_CASES.map(c => {
  const beef = build(c.steps)
  return {
    name: c.name,
    steps: c.steps,
    beef: beef.toHex(),
    parent_bump_index: beef.findTxid(P).bumpIndex,
    atomic: c.atomic.map(name => ({
      subject: name,
      beef: Buffer.from(beef.toBinaryAtomic(TXS[name].id('hex'))).toString('hex')
    }))
  }
})

// Item 2: a BEEF read back, a caller's path set on one of its transactions,
// then `findAtomicTransaction` of the subject.
const path = mp => (mp == null ? null : { block_height: mp.blockHeight, root: mp.computeRoot() })
const PATH_CASES = [
  // The BEEF proves the parent; the caller sets another path on it.
  { name: 'proven_parent_of_the_subject', steps: ['raw:parent', 'raw:child', 'bump:alone_800000'], set_on: 'parent', set: 'left_800001', subject: 'child' },
  { name: 'proven_subject', steps: ['raw:parent', 'raw:child', 'bump:alone_800000'], set_on: 'parent', set: 'left_800001', subject: 'parent' },
  // The BEEF does not prove the child; the caller sets a path on it.
  { name: 'unproven_parent_of_the_subject', steps: ['raw:parent', 'raw:child', 'raw:grandchild', 'bump:alone_800000'], set_on: 'child', set: 'child_800003', subject: 'grandchild' },
  // The BEEF proves the child, whose inputs it carries raw; the caller sets
  // another path on it: replaced, and nothing below it linked.
  { name: 'proven_parent_with_its_input_in_the_beef', steps: ['raw:parent', 'raw:child', 'raw:grandchild', 'bump:child_800003'], set_on: 'child', set: 'alone_800000', subject: 'grandchild' }
]
const path_cases = PATH_CASES.map(c => {
  const written = build(c.steps).toHex()
  const read = Beef.fromString(written, 'hex')
  read.findTxid(TXS[c.set_on].id('hex')).tx.merklePath = BUMPS[c.set]()
  const atomic = read.findAtomicTransaction(TXS[c.subject].id('hex'))
  // The walk from the subject, depth-first: each transaction's path and
  // whether each of its inputs is linked.
  const seen = []
  const stack = [atomic]
  const visited = new Set()
  while (stack.length > 0) {
    const tx = stack.pop()
    const id = tx.id('hex')
    if (visited.has(id)) continue
    visited.add(id)
    seen.push({
      txid: id,
      merkle_path: path(tx.merklePath),
      inputs_linked: tx.inputs.map(input => input.sourceTransaction != null)
    })
    for (let i = tx.inputs.length - 1; i >= 0; i--) {
      if (tx.inputs[i].sourceTransaction != null) stack.push(tx.inputs[i].sourceTransaction)
    }
  }
  return { name: c.name, steps: c.steps, beef: written, set_on: c.set_on, set: c.set, subject: c.subject, walk: seen }
})

const vector = {
  issue: 757,
  reference: 'ts-stack@edf6e03 packages/sdk (Beef.ts:448-470, :550-565, :576-585, :649-668, :774-786, :813-822, :1329-1340)',
  runtime: `node ${process.version}`,
  txs: Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [name, { txid: tx.id('hex'), raw: tx.toHex() }])),
  bumps: Object.fromEntries(Object.entries(BUMPS).map(([name, mp]) => [name, mp().toHex()])),
  index_cases,
  path_cases
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
