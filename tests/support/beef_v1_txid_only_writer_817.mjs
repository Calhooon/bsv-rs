// #817 recorder: what the reference's writer does with a V1 BEEF holding a
// txid-only entry (`ts-stack@edf6e03` `packages/sdk/src/transaction/BeefTx.ts`
// `toWriter`, `:240-290`: the V1 branch calls `writeTx`, whose
// `getRawTxBytes` answers nothing for a txid-only entry, so it throws
// `a valid serialized Transaction is expected`, `:253-258`). Each case reads
// the V1 BEEF of a proven parent and its child (the reference's writer's
// bytes, which the Rust test checks equal to this crate's `to_beef_v1`),
// takes the case's step and writes; the words thrown are recorded, and the
// same state with `version` set to V2 written by the reference (the bytes
// this crate's writer writes for that state, its V1 form refused in the
// reference's words), read back by the reference's own `fromBinary`. Only the unmodified
// SDK writes the bytes and supplies the answers. Build the bundle at the pin
// and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_v1_txid_only_writer_817.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_v1_txid_only_writer_817.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, BeefTx, MerklePath, Transaction, Script, BEEF_V1, BEEF_V2 } = await import(bundle)

const ONE = () => Script.fromHex('51')
const spend = (txid, vout) => ({
  sourceTXID: txid,
  sourceOutputIndex: vout,
  unlockingScript: ONE(),
  sequence: 0xffffffff
})
// The Rust test's `proven_parent_and_child`.
const parent = new Transaction(1, [spend('81'.repeat(32), 0)], [{ satoshis: 2000, lockingScript: ONE() }], 0)
const P = parent.id('hex')
parent.merklePath = new MerklePath(817000, [[{ offset: 0, hash: P, txid: true }]])
const child = new Transaction(1, [{ ...spend(P, 0), sourceTransaction: parent }], [{ satoshis: 1000, lockingScript: ONE() }], 0)
const C = child.id('hex')
const FRESH = '8170000000000000000000000000000000000000000000000000000000000817'

const v1Beef = new Beef(BEEF_V1)
v1Beef.mergeTransaction(child)
const v1 = v1Beef.toBinary()
const v1Hex = Buffer.from(v1).toString('hex')

const STEPS = {
  merge_txid_only: (b) => b.mergeTxidOnly(FRESH),
  make_txid_only: (b) => b.makeTxidOnly(P),
  merge_beef_v2_txid_only: (b) => {
    const source = new Beef()
    source.mergeTxidOnly(FRESH)
    b.mergeBeef(source)
  }
}

const words = (f) => {
  try {
    f()
    return null
  } catch (e) {
    return e.message
  }
}

const cases = []
for (const [name, step] of Object.entries(STEPS)) {
  const beef = Beef.fromBinary(v1)
  step(beef)
  const thrown = words(() => beef.toHex())
  const v2 = Beef.fromBinary(v1)
  step(v2)
  v2.version = BEEF_V2
  const oursHex = v2.toHex()
  const back = Beef.fromBinary(Array.from(Buffer.from(oursHex, 'hex')))
  cases.push({
    name,
    reference: { thrown, v2_read_back_txs: back.txs.length, v2_read_back_bumps: back.bumps.length },
    ours_hex: oursHex
  })
}
{
  const beef = Beef.fromBinary(v1)
  beef.makeTxidOnly(P)
  cases.push({
    name: 'to_binary_atomic_make_txid_only',
    reference: { thrown: words(() => beef.toBinaryAtomic(C)) }
  })
}


// --- Additions for the BEEF writers' lane (#817, `fix-817-beef-writers`):
// every cell the writers, `mergeBeef`, `mergeRawTx`, `mergeTxidOnly` and
// `mergeBump` meet, each recorded as what the reference's door throws or
// writes and what its own readers make of the bytes written. Additions only:
// the four cases above are unchanged.
const hex = (b) => Buffer.from(b).toString('hex')
const unhex = (h) => Array.from(Buffer.from(h, 'hex'))
const attempt = (f) => {
  try {
    return { ok: f() ?? null }
  } catch (e) {
    return { thrown: e.message }
  }
}
// What the reference's two readers answer for bytes it wrote.
const readBack = (h) => ({
  from_binary: attempt(() => {
    const b = Beef.fromBinary(unhex(h))
    return { version: b.version, txs: b.txs.length, bumps: b.bumps.length, txids: b.txs.map((t) => (t.isTxidOnly ? t._txid : t.txid)) }
  }),
  from_binary_strict: attempt(() => {
    const b = Beef.fromBinaryStrict(unhex(h))
    return { version: b.version, txs: b.txs.length, bumps: b.bumps.length, txids: b.txs.map((t) => (t.isTxidOnly ? t._txid : t.txid)) }
  })
})
// Writes `beef` and reads the bytes back: the writer's cell.
const writeCell = (name, build) => {
  const beef = build()
  const w = attempt(() => beef.toHex())
  const cell = { name, write: w }
  if (w.ok != null) cell.read_back = readBack(w.ok)
  return cell
}
const childRaw = hex(child.toBinary())
const parentRaw = hex(parent.toBinary())
const BAD_WORD = 0xefbe0003
const writers = [
  writeCell('version_word_efbe0003', () => {
    const b = Beef.fromBinary(v1)
    b.version = BAD_WORD
    return b
  }),
  writeCell('version_word_atomic', () => {
    const b = Beef.fromBinary(v1)
    b.version = 0x01010101
    return b
  }),
  writeCell('version_word_zero', () => {
    const b = Beef.fromBinary(v1)
    b.version = 0
    return b
  }),
  writeCell('version_word_with_txid_only', () => {
    const b = Beef.fromBinary(v1)
    b.version = BAD_WORD
    b.mergeTxidOnly(FRESH)
    return b
  }),
  writeCell('version_word_with_non_hex_bump_hash', () => {
    const b = Beef.fromBinary(v1)
    b.version = BAD_WORD
    b.bumps[0].path[0][0].hash = 'zz'.repeat(32)
    return b
  }),
  writeCell('v1_txid_only_with_non_hex_bump_hash', () => {
    const b = Beef.fromBinary(v1)
    b.mergeTxidOnly(FRESH)
    b.bumps[0].path[0][0].hash = 'zz'.repeat(32)
    return b
  }),
  writeCell('txid_only_non_hex', () => {
    const b = new Beef()
    b.mergeTxidOnly('zz'.repeat(32))
    return b
  }),
  writeCell('txid_only_62_digits', () => {
    const b = new Beef()
    b.mergeTxidOnly('ab'.repeat(31))
    return b
  }),
  writeCell('txid_only_66_digits', () => {
    const b = new Beef()
    b.mergeTxidOnly('ab'.repeat(33))
    return b
  }),
  writeCell('txid_only_63_digits', () => {
    const b = new Beef()
    b.mergeTxidOnly('a' + 'bc'.repeat(31))
    return b
  }),
  writeCell('txid_only_upper_case', () => {
    const b = new Beef()
    b.mergeTxidOnly('AB'.repeat(32))
    return b
  }),
  writeCell('txid_only_non_hex_short', () => {
    const b = new Beef()
    b.mergeTxidOnly('zz')
    return b
  }),
  writeCell('txid_only_empty_after_merge_threw', () => {
    const b = new Beef()
    try {
      b.mergeTxidOnly('')
    } catch (e) {}
    return b
  }),
  writeCell('txid_only_empty_with_non_hex_bump_hash', () => {
    const b = Beef.fromBinary(v1)
    b.version = BEEF_V2
    b.bumps[0].path[0][0].hash = 'zz'.repeat(32)
    try {
      b.mergeTxidOnly('')
    } catch (e) {}
    return b
  }),
  writeCell('raw_with_index_truncated', () => {
    const b = new Beef()
    b.mergeRawTx(unhex(childRaw.slice(0, 20)), 0)
    return b
  }),
  writeCell('raw_with_index_trailing_byte', () => {
    const b = new Beef()
    b.mergeRawTx(unhex(childRaw + '00'), 0)
    return b
  }),
  writeCell('raw_without_index_trailing_byte', () => {
    const b = new Beef()
    b.mergeRawTx(unhex(childRaw + '00'))
    return b
  }),
  writeCell('raw_index_out_of_range', () => {
    const b = new Beef()
    b.mergeRawTx(unhex(childRaw), 5)
    return b
  }),
  writeCell('raw_both_versions_v1', () => Beef.fromBinary(v1))
]
// The raw-transaction door: what `mergeRawTx` throws for bytes that are not
// exactly one transaction, with and without a BUMP index.
const RAWS = {
  empty: '',
  truncated_version: '010000',
  truncated_in_input: childRaw.slice(0, 20),
  truncated_lock_time: childRaw.slice(0, childRaw.length - 2),
  trailing_byte: childRaw + '00',
  non_canonical_input_count: childRaw.slice(0, 8) + 'fd0100' + childRaw.slice(10),
  one_transaction: childRaw
}
const rawDoor = []
for (const [name, h] of Object.entries(RAWS)) {
  for (const index of [undefined, 0]) {
    const b = new Beef()
    const merged = attempt(() => {
      const t = b.mergeRawTx(unhex(h), index)
      return { txid: t.txid, input_txids: t.inputTxids }
    })
    rawDoor.push({ name, bump_index: index ?? null, merge: merged, txs_after: b.txs.length })
  }
}
// The txid door.
const txidDoor = []
for (const [name, t] of Object.entries({ empty: '', non_hex: 'zz', short_hex: 'abcd' })) {
  const b = new Beef()
  txidDoor.push({ name, merge: attempt(() => b.mergeTxidOnly(t)._txid), txs_after: b.txs.length, write_after: attempt(() => b.toHex()) })
}
// The BEEF door: `mergeBeef` of a source in each state, the target's bytes
// before and after.
const target = () => {
  const b = new Beef()
  b.mergeRawTx(unhex(parentRaw))
  return b
}
const mergeCell = (name, buildSource) => {
  const t = target()
  const before = t.toHex()
  const r = attempt(() => t.mergeBeef(buildSource()))
  return { name, merge: r.thrown != null ? r : { ok: null }, target_unchanged: t.toHex() === before }
}
const mergeDoor = [
  mergeCell('v1_source_with_txid_only', () => {
    const b = Beef.fromBinary(v1)
    b.mergeTxidOnly(FRESH)
    return b
  }),
  mergeCell('source_version_word', () => {
    const b = Beef.fromBinary(v1)
    b.version = BAD_WORD
    return b
  }),
  mergeCell('source_txid_only_non_hex', () => {
    const b = new Beef()
    b.mergeTxidOnly('zz'.repeat(32))
    return b
  }),
  mergeCell('source_txid_only_62_digits', () => {
    const b = new Beef()
    b.mergeTxidOnly('ab'.repeat(31))
    return b
  }),
  mergeCell('source_raw_trailing_byte_with_index', () => {
    const b = new Beef()
    b.mergeRawTx(unhex(childRaw + '00'), 0)
    return b
  }),
  mergeCell('source_bump_non_hex_hash', () => {
    const b = Beef.fromBinary(v1)
    b.bumps[0].path[0][0].hash = 'zz'.repeat(32)
    return b
  }),
  mergeCell('source_bump_two_leaves_at_one_offset', () => {
    const b = Beef.fromBinary(v1)
    b.bumps[0].path[0].push({ offset: 0, hash: '11'.repeat(32) })
    return b
  }),
  mergeCell('source_bump_no_levels', () => {
    const b = Beef.fromBinary(v1)
    b.bumps[0].path = []
    return b
  }),
  mergeCell('source_bump_duplicate_with_hash', () => {
    const b = Beef.fromBinary(v1)
    b.bumps[0].path[0].push({ offset: 1, duplicate: true, hash: '11'.repeat(32) })
    return b
  }),
  mergeCell('source_version_word_and_txid_only_62_digits', () => {
    const b = new Beef()
    b.mergeTxidOnly('ab'.repeat(31))
    b.version = BAD_WORD
    return b
  }),
  mergeCell('source_version_word_and_bump_no_levels', () => {
    const b = Beef.fromBinary(v1)
    b.bumps[0].path = []
    b.version = BAD_WORD
    return b
  }),
  mergeCell('source_valid', () => Beef.fromBinary(v1))
]
// The BUMP door: a BUMP of a held height whose root does not compute.
const bumpDoor = []
{
  const b = Beef.fromBinary(v1)
  const bad = new MerklePath(817000, [[{ offset: 0, hash: P, txid: true }]])
  bad.path[0][0].hash = undefined
  bumpDoor.push({ name: 'held_height_root_does_not_compute', merge: attempt(() => b.mergeBump(bad)), bumps_after: b.bumps.length })
  const c = new Beef()
  const bad2 = new MerklePath(817000, [[{ offset: 0, hash: P, txid: true }]])
  bad2.path[0][0].hash = undefined
  bumpDoor.push({ name: 'no_held_height_root_does_not_compute', merge: attempt(() => c.mergeBump(bad2)), bumps_after: c.bumps.length })
}

// --- Additions for the rebase lane (#817, `fix-817-beef-writers-rebase`): a
// BEEF holding one txid twice (the ensemble's handed cell). Each state is
// built two ways: read from bytes written by hand (the reader keeps every
// entry, `Beef.ts:1262-1266`) and pushed by hand into `txs` (`BeefTx.fromRawTx`,
// `BeefTx.fromTxid`); then `toHex` and the reference's two readers of the
// bytes written, and `mergeBeef` of the state into an empty BEEF.
const v1Hex4 = v1Hex.slice(0, 8)
const bumpHex = (() => {
  const b = Beef.fromBinary(v1)
  return hex(b.bumps[0].toBinary())
})()
const DOUBLED = {
  raw_twice: { bumps: '', entries: [['raw', childRaw], ['raw', childRaw]] },
  raw_then_txid_only: { bumps: '', entries: [['raw', childRaw], ['txid', C]] },
  txid_only_then_raw: { bumps: '', entries: [['txid', C], ['raw', childRaw]] },
  proven_raw_twice: { bumps: bumpHex, entries: [['proven', parentRaw], ['proven', parentRaw]] },
  proven_raw_then_txid_only: { bumps: bumpHex, entries: [['proven', parentRaw], ['txid', P]] }
}
const revHex = (t) => Buffer.from(t, 'hex').reverse().toString('hex')
const doubledBytes = (d, version) => {
  let h = version === BEEF_V1 ? v1Hex4 : '0200beef'
  h += d.bumps === '' ? '00' : '01' + d.bumps
  h += '0' + d.entries.length
  for (const [kind, x] of d.entries) {
    if (version === BEEF_V1) h += kind === 'proven' ? x + '0100' : x + '00'
    else if (kind === 'raw') h += '00' + x
    else if (kind === 'proven') h += '0100' + x
    else h += '02' + revHex(x)
  }
  return h
}
const doubledPushed = (d, version) => {
  const b = new Beef(version)
  if (d.bumps !== '') b.mergeBump(MerklePath.fromHex(d.bumps))
  for (const [kind, x] of d.entries) {
    if (kind === 'txid') b.txs.push(BeefTx.fromTxid(x))
    else b.txs.push(BeefTx.fromRawTx(unhex(x), kind === 'proven' ? 0 : undefined))
  }
  return b
}
const doubledCell = (name, version) => {
  const d = DOUBLED[name]
  const bytes = doubledBytes(d, version)
  const cell = { name, version, bytes }
  for (const [how, build] of [
    ['read', () => Beef.fromBinary(unhex(bytes))],
    ['pushed', () => doubledPushed(d, version)]
  ]) {
    const built = attempt(() => {
      build()
      return true
    })
    if (built.thrown != null) {
      cell[how] = { built }
      continue
    }
    const b = build()
    const held = b.txs.length
    const w = attempt(() => b.toHex())
    const r = { held, write: w }
    if (w.ok != null) r.read_back = readBack(w.ok)
    const m = new Beef()
    r.merge_into_empty = attempt(() => {
      m.mergeBeef(build())
      return {
        txs: m.txs.length,
        txids: m.txs.map((t) => (t.isTxidOnly ? t._txid : t.txid)),
        txid_only: m.txs.map((t) => t.isTxidOnly)
      }
    })
    cell[how] = r
  }
  return cell
}
const doubledTxid = []
for (const name of Object.keys(DOUBLED)) {
  for (const version of [BEEF_V2, BEEF_V1]) {
    if (version === BEEF_V1 && DOUBLED[name].entries.some(([k]) => k === 'txid')) continue
    doubledTxid.push(doubledCell(name, version))
  }
}

// The entries' order after a refusal (#817's fold, the rule read): the
// reference's `#getSerializedBytes` (`Beef.ts:360-373`) runs
// `#ensureSerializableState` (each entry's `txid` getter, `Internal` for a
// txid-only entry with an empty txid, `BeefTx.ts:105-116`) before
// `#ensureSortedForSerialization`, and every other throw inside `toWriter`
// after it. Each cell holds the child merged raw ahead of its parent (a sort
// needed), then its fault; the txids are read after the throw.
const order = (b) => b.txs.map((t) => (t.isTxidOnly ? t._txid : t.txid))
const unsorted = () => {
  const b = new Beef()
  b.mergeRawTx(unhex(childRaw))
  b.mergeRawTx(unhex(parentRaw))
  return b
}
const SORT_FAULTS = {
  empty_txid: (b) => {
    try {
      b.mergeTxidOnly('')
    } catch (e) {}
  },
  non_hex_txid: (b) => b.mergeTxidOnly('zz'.repeat(32)),
  v1_txid_only: (b) => {
    b.version = BEEF_V1
    b.mergeTxidOnly(FRESH)
  },
  version_word: (b) => {
    b.version = 0x01020304
  }
}
const sortOnRefusal = []
for (const [name, fault] of Object.entries(SORT_FAULTS)) {
  const b = unsorted()
  fault(b)
  const before = order(b)
  const w = attempt(() => b.toHex())
  sortOnRefusal.push({ name, before, write: w, after: order(b) })
}

const vector = {
  description:
    "The reference's BEEF writers and merge doors on each state, recorded at the pin: the words each throws, or the bytes it writes and what its strict reader reads back. This crate refuses in the reference's words where the reference throws; each cell where the reference writes and this crate refuses or reads otherwise is asserted as stated by name in the tests (#817)",
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  v1_hex: v1Hex,
  parent_txid: P,
  child_txid: C,
  fresh_txid: FRESH,
  cases,
  child_raw: childRaw,
  parent_raw: parentRaw,
  writers,
  raw_door: rawDoor,
  txid_door: txidDoor,
  merge_door: mergeDoor,
  bump_door: bumpDoor,
  doubled_txid: doubledTxid,
  sort_on_refusal: sortOnRefusal
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
