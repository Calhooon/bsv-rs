// The #167 witnesses: a duplicate-flagged leaf at an even offset in the
// reference's `MerklePath`.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/even_offset_duplicate_167.mjs \
//     "$W/sdk.mjs" > tests/vectors/merkle_path_even_offset_duplicate_167.json
//
// Each shape is written by the reference's writer (`toHex`, built with no
// check) and read back by its reader with the defaults (`fromHex`: legal
// offsets only, every root checked, `MerklePath.ts:161-168`, `:191-262`);
// an accepted shape records `computeRoot` from every hash of level 0
// (`:347-376`, `nextCachedHash` `:49-62`), a refused one the words thrown.
// `unchecked` is the same reading with `legalOffsetsOnly` false, as
// `MerklePath::new_unchecked` reads a path.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { MerklePath, Hash, Utils } = await import(pathToFileURL(sdkPath).href)

// A hash for a seed, display hex.
const H = i => Utils.toHex(Hash.sha256([i & 0xff, (i >> 8) & 0xff]))
const hash = (offset, i) => ({ offset, hash: H(i) })
const txid = (offset, i) => ({ offset, hash: H(i), txid: true })
const dup = offset => ({ offset, duplicate: true })
// The node over a txid whose right sibling is a duplicate, by the reference.
const selfPair = i => new MerklePath(1, [[dup(0), txid(1, i)]]).computeRoot(H(i))

const shapes = [
  {
    name: 'level-0-duplicate-left-of-the-txid',
    note: 'the txid at offset 1, the duplicate at 0: its sibling, paired with itself',
    path: [[dup(0), txid(1, 1)]]
  },
  {
    name: 'level-1-duplicate-left-of-the-path',
    note: 'the txid at 3, its sibling at 2; level 1 carries the duplicate at 0, the path node at 1',
    path: [[hash(2, 2), txid(3, 3)], [dup(0)]]
  },
  {
    name: 'level-2-duplicate-left-of-the-path',
    note: 'the txid at 5; level 1 carries 3; level 2 the duplicate at 0, the path node at 1',
    path: [[hash(4, 4), txid(5, 5)], [hash(3, 13)], [dup(0)]]
  },
  {
    name: 'two-txids-the-left-duplicate-node-carried-above',
    note: 'txids at 1 and 2, the duplicate at 0; level 1 carries the node over 0 and 1, so the txid at 2 needs no node computed from the duplicate',
    path: [[dup(0), txid(1, 1), txid(2, 2), hash(3, 3)], [{ offset: 0, hash: selfPair(1) }]]
  },
  {
    name: 'two-txids-the-left-duplicate-node-carried-wrong',
    note: 'the same, level 1 carrying another hash at 0: the two txids climb to two roots',
    path: [[dup(0), txid(1, 1), txid(2, 2), hash(3, 3)], [hash(0, 99)]]
  },
  {
    name: 'two-txids-a-node-computed-from-the-left-duplicate',
    note: 'txids at 1 and 2, the duplicate at 0, level 1 empty: the txid at 2 needs level 1 offset 0, computed from the duplicate on its left',
    path: [[dup(0), txid(1, 1), txid(2, 2), hash(3, 3)], []]
  },
  {
    name: 'two-paths-level-3-computed-from-the-left-duplicate',
    note: 'txids at 4 and 8; level 2 carries the duplicate at 0 and level 3 nothing: the path from 8 needs level 3 offset 0, whose left child is the duplicate (the differential seed of #167)',
    path: [
      [txid(4, 4), hash(5, 5), txid(8, 8), hash(9, 9)],
      [hash(3, 13), hash(5, 15)],
      [dup(0), hash(3, 23)],
      []
    ]
  },
  {
    name: 'two-paths-a-right-child-computed-from-the-left-duplicate',
    note: 'txids at 3 and 4, the duplicate at 2; level 1 carries 0 and 3: the path from 4 needs level 2 offset 0, whose right child (level 1 offset 1) is computed from the duplicate',
    path: [[dup(2), txid(3, 3), txid(4, 4), hash(5, 5)], [hash(0, 10), hash(3, 13)], []]
  },
  {
    name: 'a-duplicate-at-the-path-nodes-own-offset',
    note: 'the txid at 1; level 1 carries the duplicate at 0, the path node\'s own offset, and the sibling at 1',
    path: [[hash(0, 0), txid(1, 1)], [dup(0), hash(1, 11)]]
  }
]

function verdict (read) {
  try {
    const mp = read()
    const roots = {}
    for (const leaf of mp.path[0]) {
      if (leaf.hash != null) roots[leaf.hash] = mp.computeRoot(leaf.hash)
    }
    const distinct = [...new Set(Object.values(roots))]
    return { accepted: true, root: distinct.length === 1 ? distinct[0] : null, roots }
  } catch (e) {
    return { accepted: false, refusal: e.message }
  }
}

const out = {
  description:
    'bsv-rs#167: a duplicate-flagged leaf at an even offset as @bsv/sdk reads it. Each shape is the BUMP the reference writes (hex), its leaves in display hex, and the reference\'s verdict on fromHex with its defaults: the root computeRoot gives from every hash of level 0, or the words it throws; unchecked is the verdict with legalOffsetsOnly false. Written by tests/support/even_offset_duplicate_167.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts',
  node: process.version,
  shapes: []
}
for (const s of shapes) {
  const height = 1
  const hex = new MerklePath(height, s.path, false, false).toHex()
  const record = { name: s.name, note: s.note, block_height: height, path: s.path, hex }
  record.verdict = verdict(() => MerklePath.fromHex(hex))
  record.unchecked = verdict(() => MerklePath.fromBinary(Utils.toArray(hex, 'hex'), false))
  out.shapes.push(record)
}
console.log(JSON.stringify(out, null, 2))
