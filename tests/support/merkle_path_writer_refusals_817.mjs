// The #817 witnesses: what the reference's `MerklePath` writer does with a
// path its bytes cannot carry faithfully, and with the other states a held
// path can be in, beside its constructor's and `computeRoot`'s reading of a
// hash that is not hex.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/merkle_path_writer_refusals_817.mjs \
//     "$W/sdk.mjs" > tests/vectors/merkle_path_writer_refusals_817.json
//
// A path is held as a caller holds one through the public fields: an object
// of the class whose `blockHeight` and `path` are set directly (the
// constructor refuses several of these states, `MerklePath.ts:185-264`, the
// fields do not). `write` is `toHex()` (`:321-323`, through `toWriter`,
// `:271-293`); `to_binary` is `toBinary()` (`:300-304`), recorded to show the
// two doors agree. `checked` is `new MerklePath(h, path)`, `unchecked` the
// same with `legalOffsetsOnly` false, `compute_root` is `computeRoot()` on the
// held path (`:375-411`). Each door is accepted (with its hex or root) or the
// words thrown and the error class. A leaf's `txid` and `duplicate` members
// are written only when true, as this crate's `false` is the reference's
// absent member, except in the one cell that records an explicit `false`.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { MerklePath, Hash, Utils } = await import(pathToFileURL(sdkPath).href)

const H = i => Utils.toHex(Hash.sha256([i & 0xff, (i >> 8) & 0xff]))
const NON_HEX = 'zz' + H(1).slice(2)

function words (f) {
  try {
    const r = f()
    return { accepted: true, result: typeof r === 'string' ? r : null }
  } catch (e) {
    return { accepted: false, refusal: e.message, class: e.constructor.name }
  }
}

const copy = path => path.map(level => level.map(leaf => ({ ...leaf })))

function held (blockHeight, path) {
  const mp = Object.create(MerklePath.prototype)
  mp.blockHeight = blockHeight
  mp.path = copy(path)
  return mp
}

const levels = (n) => {
  const path = [[{ offset: 0, hash: H(0), txid: true }]]
  for (let h = 1; h < n; h++) path.push([{ offset: 1, hash: H(h) }])
  return path
}

const cells = [
  ['non_hex_leaf_hash', [[{ offset: 0, hash: NON_HEX, txid: true }]]],
  ['non_hex_short_hash', [[{ offset: 0, hash: 'xyz', txid: true }]]],
  ['hashless_leaf', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1 }]]],
  ['hash_of_63_digits', [[{ offset: 0, hash: H(0).slice(1), txid: true }]]],
  ['hash_of_62_digits', [[{ offset: 0, hash: H(0).slice(2), txid: true }]]],
  ['hash_of_66_digits', [[{ offset: 0, hash: H(0) + 'ab', txid: true }]]],
  ['empty_hash', [[{ offset: 0, hash: '', txid: true }]]],
  ['levels_256', levels(256)],
  ['duplicate_carrying_a_hash', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1), duplicate: true }]]],
  ['zero_levels', []],
  ['levels_65', levels(65)],
  ['levels_255', levels(255)],
  ['empty_level_0', [[]]],
  ['duplicate_offsets', [[{ offset: 0, hash: H(0), txid: true }, { offset: 0, hash: H(1) }]]],
  ['illegal_offset_and_mismatched_root', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1) }], [{ offset: 5, hash: H(2) }]]],
  ['duplicate_flagged_txid', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, txid: true, duplicate: true }]]],
  ['upper_case_hash', [[{ offset: 0, hash: H(0).toUpperCase(), txid: true }]]],
  ['leaves_out_of_offset_order', [[{ offset: 1, hash: H(1) }, { offset: 0, hash: H(0), txid: true }]]],
  ['txid_flag_above_level_0', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1) }], [{ offset: 1, hash: H(2), txid: true }]]],
  ['lone_leaf_at_offset_1', [[{ offset: 1, hash: H(0), txid: true }]]],
  ['explicit_txid_false', [[{ offset: 0, hash: H(0), txid: false }]]],
  ['constructor_non_hex_sibling', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: NON_HEX }]]],
  ['constructor_non_hex_txid', [[{ offset: 0, hash: NON_HEX, txid: true }, { offset: 1, hash: H(1) }]]],
  ['constructor_non_hex_hash_no_walk_reads', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1) }], [{ offset: 1, hash: H(2) }, { offset: 3, hash: NON_HEX }]]],
  // The fold's cells (the reads of 2026-11-09): a non-hex hash beside a
  // state this crate refuses in its own words, the reference's throw first.
  ['levels_256_with_non_hex_leaf', [[{ offset: 0, hash: NON_HEX, txid: true }], ...levels(256).slice(1)]],
  ['hashless_leaf_then_non_hex', [[{ offset: 0 }, { offset: 1, hash: NON_HEX, txid: true }]]],
  ['hash_of_62_digits_then_non_hex', [[{ offset: 0, hash: H(0).slice(2), txid: true }, { offset: 1, hash: NON_HEX }]]],
  ['hashless_leaf_at_1_then_non_hex_above', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1 }], [{ offset: 1, hash: NON_HEX }]]],
  ['duplicate_carrying_a_non_hex_hash', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: NON_HEX, duplicate: true }]]],
  ['computed_node_pairing_non_hex', [[{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1) }, { offset: 2, hash: NON_HEX }, { offset: 3, hash: H(3) }], []]]
]

const BLOCK_HEIGHT = 800000
const out = {
  description:
    'bsv-rs#817: the reference MerklePath writer and constructor on held paths. Each cell is a path held through the public fields at block height 800000; write is toHex(), to_binary toBinary() as hex, checked new MerklePath(h, path), unchecked the same with legalOffsetsOnly false, compute_root computeRoot() on the held path: accepted with the hex or root, or the words thrown and the error class. Written by tests/support/merkle_path_writer_refusals_817.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts',
  node: process.version,
  block_height: BLOCK_HEIGHT,
  cells: []
}
for (const [name, path] of cells) {
  out.cells.push({
    name,
    path,
    write: words(() => held(BLOCK_HEIGHT, path).toHex()),
    to_binary: words(() => Utils.toHex(held(BLOCK_HEIGHT, path).toBinary())),
    checked: words(() => { new MerklePath(BLOCK_HEIGHT, copy(path)) }),
    unchecked: words(() => { new MerklePath(BLOCK_HEIGHT, copy(path), false) }),
    compute_root: words(() => held(BLOCK_HEIGHT, path).computeRoot())
  })
}
console.log(JSON.stringify(out, null, 2))
