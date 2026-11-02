// #603: `src/transaction/merkle_path.rs`'s surviving mutants (the constructor's
// offset and height rules, `combine`, `trim`) judged by the reference's
// `MerklePath` (`ts-stack@edf6e03` `packages/sdk/src/transaction/MerklePath.ts`:
// the constructor `:185-262`, the level bound `:198-199`, the legal offsets
// `:220-235`, the root check `:242-261`; `combine` `:508-537`; `trim`
// `:544-594`) over BUMPs of two recorded corpora:
//   - the sibling's `corpus/wire/bump.jsonl` (bsv-script-lean@5a4c0b0a, sha256
//     8943c437a78d1c01e7cb47a765ac8d0e1a50933128c9167372bf3937825778da: 22
//     BUMPs as WhatsOnChain serves them, four compound and nine degenerate
//     shapes), each row copied by its id;
//   - the conformance corpus's `vectors/sdk/transactions/merkle-path.json`
//     (ts-stack@edf6e03, sha256
//     5c5f967a44a318da991faef59a253c404c0cd2b107475fd6509b8f472cb07243),
//     `mp-parse-001` and `mp-combine-001` copied by their ids.
// A derived shape names its source row and the change, made here on the
// reference's own reading of the row.
//
// `construct`: a path, the reference's verdict on `new MerklePath(h, path)`
// (`legal`, its defaults: legal offsets only, every root checked) and with
// `legalOffsetsOnly` false (`unchecked`), as `MerklePath::new` and
// `new_unchecked` read a path; an accepted one records `computeRoot` from every
// hash of level 0, a refused one the words thrown.
// `combine`: two BUMPs of one block, `a.combine(b)` and `a.toHex()` after, or
// the words thrown; with the roots the result computes.
// `trim`: a BUMP, `trim()` and `toHex()` after.
//
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-603-merkle-path/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/merkle_path_603.mjs "$W/sdk.mjs" \
//     <bsv-script-lean clone>/corpus/wire/bump.jsonl \
//     <ts-stack clone>/conformance/vectors/sdk/transactions/merkle-path.json \
//     > tests/vectors/merkle_path_603.json
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, bumpRowsPath, conformancePath] = process.argv.slice(2)
const { MerklePath, Utils } = await import(pathToFileURL(sdkPath).href)

const rows = new Map(
  readFileSync(bumpRowsPath, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)).map(r => [r.id, r])
)
const conformance = new Map(JSON.parse(readFileSync(conformancePath, 'utf8')).vectors.map(v => [v.id, v]))
const row = id => rows.get(id)
const read = hex => MerklePath.fromHex(hex)
// The path as the reference holds it, each leaf's fields as read.
const levels = mp => mp.path.map(level => level.map(leaf => ({ ...leaf })))

function roots (mp) {
  const out = {}
  for (const leaf of mp.path[0]) {
    if (leaf.hash != null) out[leaf.hash] = mp.computeRoot(leaf.hash)
  }
  return out
}

function verdict (make) {
  try {
    const mp = make()
    const r = roots(mp)
    const distinct = [...new Set(Object.values(r))]
    return { accepted: true, root: distinct.length === 1 ? distinct[0] : null, roots: r }
  } catch (e) {
    return { accepted: false, refusal: e.message }
  }
}

const construct = []
function recordConstruct (id, source, derivation, blockHeight, path) {
  construct.push({
    id,
    source,
    derivation,
    block_height: blockHeight,
    path,
    legal: verdict(() => new MerklePath(blockHeight, path)),
    unchecked: verdict(() => new MerklePath(blockHeight, path, false))
  })
}

// Every row the reference reads, as it reads it.
for (const [id, r] of rows) {
  let mp
  try { mp = read(r.hex) } catch { continue }
  recordConstruct(id, `bsv-script-lean corpus/wire/bump.jsonl ${id} (${r.shape})`, 'the row as the reference reads it', mp.blockHeight, levels(mp))
}
for (const id of ['mp-parse-001', 'mp-combine-001']) {
  const v = conformance.get(id)
  const mp = read(v.input.bump_hex ?? v.input.combined_bump_hex)
  recordConstruct(id, `ts-stack conformance vectors/sdk/transactions/merkle-path.json ${id}`, 'the vector\'s BUMP as the reference reads it', mp.blockHeight, levels(mp))
}

// A leaf at an offset no level-0 hash climbs through (`:230-235`), its hash
// another of the row's own.
function offPath (id, source, level, offset) {
  const mp = read(row(source).hex)
  const path = levels(mp)
  const hash = path[level][0].hash
  path[level].push({ offset, hash })
  path[level].sort((a, b) => a.offset - b.offset)
  recordConstruct(id, `bsv-script-lean corpus/wire/bump.jsonl ${source}`,
    `a leaf added at level ${level}, offset ${offset}, carrying the hash of that level's first leaf`, mp.blockHeight, path)
}
offPath('bump-008-off-path-level-1', 'bump-008', 1, 3)
offPath('bump-018-off-path-level-11', 'bump-018', 11, 0)
offPath('bump-014-off-path-level-5', 'bump-014', 5, 2)

// The level bound: a client txid at offset 0 (bump-001's, block 1's lone
// transaction) with the duplicate marker as its sibling at every level, 54
// and 64 levels; and bump-029, bump-008's levels with empty levels appended
// to 65.
const lone = read(row('bump-001').hex)
const coinbase = lone.path[0][0].hash
const duplicates = n => [[{ offset: 0, hash: coinbase, txid: true }, { offset: 1, duplicate: true }],
  ...Array.from({ length: n - 1 }, () => [{ offset: 1, duplicate: true }])]
for (const n of [54, 64]) {
  recordConstruct(`bump-001-duplicates-${n}-levels`, 'bsv-script-lean corpus/wire/bump.jsonl bump-001',
    `bump-001's txid at offset 0, the duplicate marker at offset 1 on each of ${n} levels`, lone.blockHeight, duplicates(n))
}
// The root a duplicate climbs to, one level at a time by the reference's own
// walk (a duplicate sibling pairs the working hash with itself, `:60`).
const pairWithItself = w => new MerklePath(1, [[{ offset: 0, hash: w, txid: true }, { offset: 1, duplicate: true }]]).computeRoot(w)
const foldRoots = {}
let w = coinbase
for (let n = 1; n <= 64; n++) {
  w = pairWithItself(w)
  if (n === 54 || n === 64) foldRoots[n] = w
}
{
  const src = read(row('bump-008').hex)
  const path = [...levels(src), ...Array.from({ length: 65 - src.path.length }, () => [])]
  // bump-029's bytes are these levels': the source row's levels in ascending
  // offset order (the reference's writer), the tree height byte 65 and an
  // empty level's count byte per level appended.
  const hex008 = src.toHex()
  const reader = new Utils.Reader(Utils.toArray(hex008, 'hex'))
  reader.readVarIntNum()
  const at = reader.pos * 2
  const derived = hex008.slice(0, at) + (65).toString(16) + hex008.slice(at + 2) + '00'.repeat(65 - src.path.length)
  if (derived !== row('bump-029').hex) throw new Error('bump-029 is not bump-008 with empty levels to 65')
  construct.push({
    id: 'bump-029',
    source: 'bsv-script-lean corpus/wire/bump.jsonl bump-029 (tree-height-65)',
    derivation: 'bump-008\'s levels with empty levels appended to 65, the row\'s own bytes',
    block_height: src.blockHeight,
    path,
    hex: row('bump-029').hex,
    from_hex: verdict(() => read(row('bump-029').hex)),
    legal: verdict(() => new MerklePath(src.blockHeight, path)),
    unchecked: verdict(() => new MerklePath(src.blockHeight, path, false))
  })
}

// `combine`: every ordered pair of two mainnet rows of one block.
const combine = []
const mainnet = [...rows.values()].filter(r => r.shape === 'mainnet')
for (const a of mainnet) {
  for (const b of mainnet) {
    if (a.id === b.id) continue
    const ma = read(a.hex)
    if (ma.blockHeight !== read(b.hex).blockHeight || ma.path.length === 1) continue
    const record = { id: `${a.id}+${b.id}`, a: a.id, a_hex: a.hex, b: b.id, b_hex: b.hex }
    try {
      ma.combine(read(b.hex))
      record.result_hex = ma.toHex()
      record.result = verdict(() => read(record.result_hex))
    } catch (e) {
      record.refusal = e.message
    }
    combine.push(record)
  }
}
// A shorter `this`: bump-005's level-1 hash at offset 0 and the node the
// reference computes at level 1 offset 1 (`findOrComputeLeaf`, `:421-468`),
// as one level; the same root as bump-005's.
{
  const other = read(row('bump-005').hex)
  const left = other.path[1].find(l => l.offset === 0).hash
  const right = other.findOrComputeLeaf(1, 1).hash
  const path = [[{ offset: 0, hash: left }, { offset: 1, hash: right }]]
  const self = new MerklePath(other.blockHeight, path)
  const record = {
    id: 'bump-005-under-its-level-1',
    a: 'bump-005\'s level 1 as one level',
    a_path: levels(self),
    a_root: self.computeRoot(),
    b: 'bump-005',
    b_hex: row('bump-005').hex,
    // The row as the reference reads it and writes it: its levels in
    // ascending offset order (`:149`), WhatsOnChain's level 0 being 3, 2.
    b_sorted_hex: other.toHex(),
    b_root: other.computeRoot()
  }
  try {
    self.combine(other)
    record.result_hex = self.toHex()
    record.result_path = levels(self)
    record.result = verdict(() => read(record.result_hex))
  } catch (e) {
    record.refusal = e.message
  }
  combine.push(record)
}

// `trim`: the compound rows, and the same with one client txid's flag
// cleared (its leaf and its sibling then a pair without a client txid).
const trim = []
function recordTrim (id, source, derivation, mp) {
  const hex = mp.toHex()
  const record = { id, source, derivation, hex }
  try {
    const t = read(hex)
    t.trim()
    record.result_hex = t.toHex()
    record.result = verdict(() => read(record.result_hex))
  } catch (e) {
    record.refusal = e.message
  }
  trim.push(record)
}
for (const id of ['bump-023', 'bump-024', 'bump-025', 'bump-026']) {
  recordTrim(id, `bsv-script-lean corpus/wire/bump.jsonl ${id} (compound)`, 'the row as read', read(row(id).hex))
  const mp = read(row(id).hex)
  for (const leaf of mp.path[0].filter(l => l.txid === true)) {
    const cleared = read(row(id).hex)
    delete cleared.path[0].find(l => l.offset === leaf.offset).txid
    recordTrim(`${id}-unflagged-${leaf.offset}`, `bsv-script-lean corpus/wire/bump.jsonl ${id} (compound)`,
      `the client txid flag of level 0 offset ${leaf.offset} cleared`, cleared)
  }
}

console.log(JSON.stringify({
  description:
    '#603: the reference\'s MerklePath constructor, combine and trim over BUMPs of the sibling\'s corpus/wire/bump.jsonl and the conformance corpus\'s merkle-path.json, each copied by its id; a derived shape names its source and the change. Written by tests/support/merkle_path_603.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts',
  corpora: {
    sibling: 'bsv-script-lean@5a4c0b0a corpus/wire/bump.jsonl sha256 8943c437a78d1c01e7cb47a765ac8d0e1a50933128c9167372bf3937825778da',
    conformance: 'ts-stack@edf6e03 conformance/vectors/sdk/transactions/merkle-path.json sha256 5c5f967a44a318da991faef59a253c404c0cd2b107475fd6509b8f472cb07243'
  },
  node: process.version,
  duplicate_fold_roots: foldRoots,
  construct,
  combine,
  trim
}, null, 2))
