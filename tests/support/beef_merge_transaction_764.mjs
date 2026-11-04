// #764 recorder: the BEEF the reference's `mergeTransaction` writes for a
// transaction carrying a merkle path or source transactions
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts`: `mergeTransaction`
// and `#mergeTransactionGraph`, `:875-901`, pop each transaction off a stack
// and run `#mergeTransactionEntry`, `:849-856`, which merges
// `current.merklePath` through `#mergeBumpEntry`, `:774-786`, and takes the
// returned index, else asks `#tryToValidateBumpIndex`, `:1329-1340`; an entry
// that ends with no index queues its inputs' `sourceTransaction`s,
// `#queueSourceTransactions`, `:858-863`, at `:897`). Only the unmodified SDK
// writes the bytes and supplies the answers. Build the bundle at the pin and
// run under Node 22, as the #757 recorder is run:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_merge_transaction_764.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_merge_transaction_764.json
//
// The vector carries every input (the transactions' and the BUMPs' bytes,
// each case's prior merge steps and the graph handed to `mergeTransaction`),
// so the Rust test rebuilds each BEEF with this crate's writer and compares
// the bytes.
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
// The #757 recorder's parent, child (spending both of the parent's outputs)
// and grandchild.
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
// #764's fold: a grandparent with two outputs, two parents each spending
// one of them, and a child spending both parents (two distinct parents).
const grand = new Transaction(
  1,
  [spend('cc'.repeat(32), 0)],
  [{ satoshis: 3000, lockingScript: ONE() }, { satoshis: 4000, lockingScript: ONE() }],
  0
)
const G = grand.id('hex')
const left = new Transaction(1, [spend(G, 0)], [{ satoshis: 2900, lockingScript: ONE() }], 0)
const right = new Transaction(1, [spend(G, 1)], [{ satoshis: 3900, lockingScript: ONE() }], 0)
const L = left.id('hex')
const R = right.id('hex')
const twin = new Transaction(1, [spend(L, 0), spend(R, 0)], [{ satoshis: 6700, lockingScript: ONE() }], 0)
const TXS = { parent, child, grandchild, grand, left, right, twin }
const NAMES = Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [tx.id('hex'), name]))

const BUMPS = {
  // The parent alone at height 800000: the root is the txid.
  alone_800000: () => new MerklePath(800000, [[{ offset: 0, hash: P, txid: true }]]),
  // The child alone at height 800003.
  child_800003: () => new MerklePath(800003, [[{ offset: 0, hash: C, txid: true }]]),
  // #764's fold: the grandparent, the left and the right parent alone.
  grand_800010: () => new MerklePath(800010, [[{ offset: 0, hash: G, txid: true }]]),
  left_800011: () => new MerklePath(800011, [[{ offset: 0, hash: L, txid: true }]]),
  right_800012: () => new MerklePath(800012, [[{ offset: 0, hash: R, txid: true }]])
}

// A graph node: the transaction by name, the path it carries (a BUMP by name
// or null) and the sources its inputs carry (`{ input, ...node }`). Two inputs
// naming one node carry one object, as a transaction spending two outputs of
// one parent carries it.
const parentProven = { tx: 'parent', path: 'alone_800000', sources: [] }
const parentUnproven = { tx: 'parent', path: null, sources: [] }
const CASES = [
  // (a) A lone proven transaction into an empty BEEF: bumps [alone], index 0.
  { name: 'lone_proven', steps: [], merge: parentProven },
  // A lone unproven one: the control, no BUMP on either side.
  { name: 'lone_unproven', steps: [], merge: parentUnproven },
  // (b) A child carrying its proven parent on both inputs: one BUMP, the
  // parent indexed, the child raw.
  {
    name: 'child_of_a_proven_parent',
    steps: [],
    merge: { tx: 'child', path: null, sources: [{ input: 0, ...parentProven }, { input: 1, ...parentProven }] }
  },
  // A child carrying an unproven parent: both raw, no BUMP.
  {
    name: 'child_of_an_unproven_parent',
    steps: [],
    merge: { tx: 'child', path: null, sources: [{ input: 0, ...parentUnproven }, { input: 1, ...parentUnproven }] }
  },
  // (c) A chain of three, the middle proven: the walk stops there, the
  // grandparent (the parent) absent.
  {
    name: 'chain_stops_at_a_proven_middle',
    steps: [],
    merge: {
      tx: 'grandchild',
      path: null,
      sources: [
        {
          input: 0,
          tx: 'child',
          path: 'child_800003',
          sources: [{ input: 0, ...parentUnproven }, { input: 1, ...parentUnproven }]
        }
      ]
    }
  },
  // A chain of three proven at its root: every one merged, one BUMP.
  {
    name: 'chain_proven_at_the_root',
    steps: [],
    merge: {
      tx: 'grandchild',
      path: null,
      sources: [
        {
          input: 0,
          tx: 'child',
          path: null,
          sources: [{ input: 0, ...parentProven }, { input: 1, ...parentProven }]
        }
      ]
    }
  },
  // (d) A child whose parent the BEEF holds already: no duplicate entry.
  {
    name: 'parent_already_raw',
    steps: ['raw:parent'],
    merge: { tx: 'child', path: null, sources: [{ input: 0, ...parentUnproven }, { input: 1, ...parentUnproven }] }
  },
  // The parent and its BUMP held already, the parent carried with the same
  // path: the BUMP found (combined), no second one.
  {
    name: 'parent_already_proven',
    steps: ['bump:alone_800000', 'raw:parent'],
    merge: { tx: 'child', path: null, sources: [{ input: 0, ...parentProven }, { input: 1, ...parentProven }] }
  },
  // The merged transaction carries no path but a BUMP of the BEEF proves it:
  // its entry ends with an index, so its sources are not walked.
  {
    name: 'subject_proven_by_a_held_bump',
    steps: ['bump:child_800003'],
    merge: { tx: 'child', path: null, sources: [{ input: 0, ...parentUnproven }, { input: 1, ...parentUnproven }] }
  },
  // #764's fold. Two distinct unproven parents: the walk merges the first
  // input's source before the second's (`#queueSourceTransactions` pushes
  // them reversed), and the sort keeps that order between them.
  {
    name: 'two_distinct_unproven_parents',
    steps: [],
    merge: {
      tx: 'twin',
      path: null,
      sources: [
        { input: 0, tx: 'left', path: null, sources: [] },
        { input: 1, tx: 'right', path: null, sources: [] }
      ]
    }
  },
  // The grandparent reached through both parents, carried without a path
  // under the first and with one under the second: the walk merges it once,
  // on the first input's branch (the once-per-call set, `:893-894`), so no
  // BUMP is written and it stays unproven.
  {
    name: 'a_grandparent_reached_twice_is_merged_once',
    steps: [],
    merge: {
      tx: 'twin',
      path: null,
      sources: [
        { input: 0, tx: 'left', path: null, sources: [{ input: 0, tx: 'grand', path: null, sources: [] }] },
        { input: 1, tx: 'right', path: null, sources: [{ input: 0, tx: 'grand', path: 'grand_800010', sources: [] }] }
      ]
    }
  },
  // Two unrelated unproven transactions held, the first merged again: it is
  // replaced in its place (`#replaceOrAppendTx`, `:531-540`), so it is
  // written first still.
  {
    name: 'a_held_unproven_transaction_merged_again_keeps_its_place',
    steps: ['raw:left', 'raw:right'],
    merge: { tx: 'left', path: null, sources: [] }
  },
  // The same with both proven.
  {
    name: 'a_held_proven_transaction_merged_again_keeps_its_place',
    steps: ['bump:left_800011', 'bump:right_800012', 'raw:left', 'raw:right'],
    merge: { tx: 'left', path: 'left_800011', sources: [] }
  },
  // The same through `mergeRawTx` (`#mergeRawTxEntry`, `:842-847`): no
  // `mergeTransaction` call.
  {
    name: 'a_held_raw_transaction_merged_raw_again_keeps_its_place',
    steps: ['raw:left', 'raw:right', 'raw:left'],
    merge: null
  },
  // A graph merged twice: the second call replaces every entry in its place,
  // the bytes those of one call.
  {
    name: 'chain_proven_at_the_root_merged_twice',
    steps: [],
    times: 2,
    merge: {
      tx: 'grandchild',
      path: null,
      sources: [
        {
          input: 0,
          tx: 'child',
          path: null,
          sources: [{ input: 0, ...parentProven }, { input: 1, ...parentProven }]
        }
      ]
    }
  }
]

// The graph as transactions, each node one object however many inputs name it.
const materialize = (node, made = new Map()) => {
  const key = JSON.stringify(node)
  if (made.has(key)) return made.get(key)
  const tx = Transaction.fromHex(TXS[node.tx].toHex())
  if (node.path != null) tx.merklePath = BUMPS[node.path]()
  for (const source of node.sources) {
    const { input, ...rest } = source
    tx.inputs[input].sourceTransaction = materialize(rest, made)
  }
  made.set(key, tx)
  return tx
}

const cases = CASES.map(c => {
  const beef = new Beef()
  for (const step of c.steps) {
    const [kind, name] = step.split(':')
    if (kind === 'bump') beef.mergeBump(BUMPS[name]())
    else beef.mergeRawTx(TXS[name].toBinary())
  }
  let merged = null
  if (c.merge != null) {
    for (let i = 0; i < (c.times ?? 1); i++) merged = beef.mergeTransaction(materialize(c.merge))
  }
  const hex = beef.toHex()
  return {
    name: c.name,
    steps: c.steps,
    ...(c.times == null ? {} : { times: c.times }),
    merge: c.merge,
    returned: merged == null ? null : NAMES[merged.txid],
    beef: hex,
    bumps: beef.bumps.length,
    entries: beef.txs.map(t => ({ tx: NAMES[t.txid], bump_index: t.bumpIndex ?? null, txid_only: t.isTxidOnly }))
  }
})

const vector = {
  issue: 764,
  reference: 'ts-stack@edf6e03 packages/sdk (Beef.ts:774-786, :849-863, :875-901, :1329-1340)',
  runtime: `node ${process.version}`,
  txs: Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [name, { txid: tx.id('hex'), raw: tx.toHex() }])),
  bumps: Object.fromEntries(Object.entries(BUMPS).map(([name, mp]) => [name, mp().toHex()])),
  cases
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
