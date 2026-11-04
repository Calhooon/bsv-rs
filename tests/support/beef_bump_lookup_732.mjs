// #732 recorder: which BUMP the reference attaches to a transaction that two
// BUMPs of one BEEF hold at level 0 (`Beef.ts:570-585` at edf6e03: the index
// of level-0 leaves is a `Map.set` loop over the BUMPs in order, so the last
// BUMP holding a txid wins; `#addInputProof`, `:649-680`, makes it the
// transaction's `merklePath`). Only the unmodified SDK writes the bytes and
// supplies the verdicts. Build the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_bump_lookup_732.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_bump_lookup_732.json
//
// Each case merges its transactions, then its BUMPs (in that order the two
// SDKs give the parent the same wire bump index, the earliest BUMP's), writes the
// BEEF with the reference's writer, reads it back with `Beef.fromBinary`
// (which pushes every BUMP as read, `:1257-1261`, merging none) and records
// `findBump` and the path `findAtomicTransaction` attaches.
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, MerklePath, Transaction, Script, Utils } = await import(bundle)

const ONE = () => Script.fromHex('51')
const parent = new Transaction(
  1,
  [{ sourceTXID: 'aa'.repeat(32), sourceOutputIndex: 0, unlockingScript: ONE(), sequence: 0xffffffff }],
  [{ satoshis: 1000, lockingScript: ONE() }, { satoshis: 2000, lockingScript: ONE() }],
  0
)
const P = parent.id('hex')
const child = new Transaction(
  1,
  [0, 1].map(vout => ({ sourceTXID: P, sourceOutputIndex: vout, unlockingScript: ONE(), sequence: 0xffffffff })),
  [{ satoshis: 2500, lockingScript: ONE() }],
  0
)
const SIBLING = 'bb'.repeat(32)

// The BUMPs, by name: each holds the parent's txid at level 0, each a root of its own.
const BUMPS = {
  // The parent alone at height 800000: the root is the txid.
  alone_800000: () => new MerklePath(800000, [[{ offset: 0, hash: P, txid: true }]]),
  // The parent at offset 0 beside a sibling, at height 800001.
  left_800001: () => new MerklePath(800001, [[{ offset: 0, hash: P, txid: true }, { offset: 1, hash: SIBLING }]]),
  // The parent at offset 1 beside a sibling, at height 800000 (one height, another root).
  right_800000: () => new MerklePath(800000, [[{ offset: 0, hash: SIBLING }, { offset: 1, hash: P, txid: true }]])
}

const CASES = [
  { name: 'two_heights', bumps: ['alone_800000', 'left_800001'], subject: 'parent' },
  { name: 'two_heights_reversed', bumps: ['left_800001', 'alone_800000'], subject: 'parent' },
  { name: 'one_height_two_roots', bumps: ['alone_800000', 'right_800000'], subject: 'parent' },
  { name: 'a_parent_proven_twice', bumps: ['alone_800000', 'left_800001'], subject: 'child' }
]

const path = mp => ({ block_height: mp.blockHeight, root: mp.computeRoot() })

const cases = CASES.map(c => {
  const beef = new Beef()
  beef.mergeRawTx(parent.toBinary())
  if (c.subject === 'child') beef.mergeRawTx(child.toBinary())
  for (const name of c.bumps) beef.mergeBump(BUMPS[name]())
  const hex = beef.toHex()
  const read = Beef.fromBinary(Utils.toArray(hex, 'hex'))
  const subject = c.subject === 'parent' ? P : child.id('hex')
  const atomic = read.findAtomicTransaction(subject)
  const attached =
    c.subject === 'parent'
      ? [path(atomic.merklePath)]
      : atomic.inputs.map(input => path(input.sourceTransaction.merklePath))
  return {
    name: c.name,
    bumps: c.bumps,
    beef: hex,
    subject,
    bumps_read: read.bumps.length,
    parent_bump_index: read.findTxid(P).bumpIndex,
    bump_roots: read.bumps.map(path),
    find_bump: path(read.findBump(P)),
    attached
  }
})

const vector = {
  issue: 732,
  reference: 'ts-stack@edf6e03 packages/sdk (Beef.ts:570-585, :639-680, :1257-1261)',
  runtime: `node ${process.version}`,
  parent: { txid: P, raw: parent.toHex() },
  child: { txid: child.id('hex'), raw: child.toHex() },
  sibling: SIBLING,
  cases
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
