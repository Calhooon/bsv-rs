// The #641 witnesses: a level 0 made only of duplicate-flagged leaves (no
// txid leaf, no hash leaf) in the reference's `MerklePath`.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/merkle_path_641.mjs \
//     "$W/sdk.mjs" > tests/vectors/merkle_path_641.json
//
// Each shape is written by the reference's writer (`toHex` of a path built
// with no check, `new MerklePath(h, path, false, false)`) and recorded four
// ways: the constructor with its defaults and with `legalOffsetsOnly` false
// (`MerklePath.ts:185-264`; the root check asks `computeRootCached` for a
// root from a leaf with no hash, which finds none and throws at `:342-343`),
// `fromHex` of the bytes (`:104-168`, through the same constructor), and
// `computeRoot()` on the unchecked instance (`:375-381`).
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { MerklePath, Hash, Utils } = await import(pathToFileURL(sdkPath).href)

const H = i => Utils.toHex(Hash.sha256([i & 0xff, (i >> 8) & 0xff]))
const dup = offset => ({ offset, duplicate: true })

const shapes = [
  { name: 'one-duplicate-at-0', note: 'one level, one duplicate at offset 0', path: [[dup(0)]] },
  { name: 'one-duplicate-at-1', note: 'one level, one duplicate at offset 1', path: [[dup(1)]] },
  { name: 'two-duplicates', note: 'one level, duplicates at 0 and 1', path: [[dup(0), dup(1)]] },
  { name: 'duplicate-under-an-empty-level', note: 'a duplicate at 0, level 1 empty', path: [[dup(0)], []] },
  {
    name: 'duplicate-under-a-hash',
    note: 'a duplicate at 0, level 1 carrying a hash at 1: no level-0 hash names a legal offset there',
    path: [[dup(0)], [{ offset: 1, hash: H(1) }]]
  }
]

function words (f) {
  try {
    const r = f()
    return { accepted: true, result: typeof r === 'string' ? r : null }
  } catch (e) {
    return { accepted: false, refusal: e.message, class: e.constructor.name }
  }
}

const out = {
  description:
    'bsv-rs#641: a level 0 made only of duplicate-flagged leaves as @bsv/sdk reads it. Each shape is the BUMP the reference writes (hex) and its leaves; checked is the constructor with its defaults, unchecked with legalOffsetsOnly false, from_hex is fromHex of the bytes, compute_root is computeRoot() on the path built with no check: accepted, or the words thrown and the error class. Written by tests/support/merkle_path_641.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts',
  node: process.version,
  shapes: []
}
for (const s of shapes) {
  const height = 1
  const raw = new MerklePath(height, s.path, false, false)
  const hex = raw.toHex()
  out.shapes.push({
    name: s.name,
    note: s.note,
    block_height: height,
    path: s.path,
    hex,
    checked: words(() => { new MerklePath(height, s.path) }),
    unchecked: words(() => { new MerklePath(height, s.path, false) }),
    from_hex: words(() => { MerklePath.fromHex(hex) }),
    compute_root: words(() => raw.computeRoot())
  })
}
console.log(JSON.stringify(out, null, 2))
