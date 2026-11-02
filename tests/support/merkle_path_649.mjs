// The #649 witnesses: a path with no levels at all (`path` empty) in the
// reference's `MerklePath`.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/merkle_path_649.mjs \
//     "$W/sdk.mjs" > tests/vectors/merkle_path_649.json
//
// The constructor refuses an empty path (`MerklePath.ts:198-200`), so no
// reader yields one: the bytes are the reference's writer (`toHex`,
// `:271-293`) of a one-leaf path whose `path` is then set to `[]` through the
// public field, the only way to hold one. Each shape is recorded at every
// door (the constructor with its defaults and with `legalOffsetsOnly` false,
// `fromHex` of the bytes, `:104-168`) and every walk on that instance:
// `computeRoot()` with no txid (`:375-382`) and with one (`indexOf`,
// `:327-333`), `trim()` (`:544-600`) and `combine` (`:508-537`) either way.
// None asks whether level 0 exists.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { MerklePath, Hash, Utils } = await import(pathToFileURL(sdkPath).href)

const H = i => Utils.toHex(Hash.sha256([i & 0xff, (i >> 8) & 0xff]))

function words (f) {
  try {
    const r = f()
    return { accepted: true, result: typeof r === 'string' ? r : null }
  } catch (e) {
    return { accepted: false, refusal: e.message, class: e.constructor.name }
  }
}

// A path with no levels, held as the reference holds one: through the field.
function empty (height) {
  const mp = MerklePath.fromCoinbaseTxidAndHeight(H(0), height)
  mp.path = []
  return mp
}

const out = {
  description:
    'bsv-rs#649: a path with no levels as @bsv/sdk reads it. Each shape is the BUMP the reference writes for a path whose levels were emptied through the public field (hex); checked is the constructor with its defaults, unchecked with legalOffsetsOnly false, from_hex is fromHex of the bytes; compute_root is computeRoot() and compute_root_txid computeRoot(txid) on the emptied path, trim its trim(), combine_into_empty a one-leaf path of the same height combined into it, combine_empty_into it combined into that path: accepted, or the words thrown and the error class. Written by tests/support/merkle_path_649.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts',
  node: process.version,
  shapes: []
}
for (const [name, height] of [['no-levels-at-1', 1], ['no-levels-at-813706', 813706]]) {
  const hex = empty(height).toHex()
  const txid = H(0)
  out.shapes.push({
    name,
    note: `block height ${height}, no levels`,
    block_height: height,
    path: [],
    txid,
    hex,
    checked: words(() => { new MerklePath(height, []) }),
    unchecked: words(() => { new MerklePath(height, [], false) }),
    from_hex: words(() => { MerklePath.fromHex(hex) }),
    compute_root: words(() => empty(height).computeRoot()),
    compute_root_txid: words(() => empty(height).computeRoot(txid)),
    trim: words(() => { empty(height).trim() }),
    combine_into_empty: words(() => {
      empty(height).combine(MerklePath.fromCoinbaseTxidAndHeight(txid, height))
    }),
    combine_empty_into: words(() => {
      MerklePath.fromCoinbaseTxidAndHeight(txid, height).combine(empty(height))
    })
  })
}
console.log(JSON.stringify(out, null, 2))
