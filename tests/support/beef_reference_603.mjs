// The #603 recorder: src/transaction/beef.rs's surviving mutants, each killed
// by the reference's answer on a row of the sibling's wire corpus.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_reference_603.mjs \
//     "$W/sdk.mjs" ~/bsv/bsv-script-lean/corpus/wire > tests/vectors/beef_reference_603.json
//
// The inputs are the rows of bsv-script-lean@387dab35's `corpus/wire/beef.jsonl`
// and `atomic-beef.jsonl` named below, copied by id with their bytes; every
// expectation is the reference's `Beef.ts` (`packages/sdk/src/transaction/Beef.ts`
// at edf6e03) on them. The tests are `src/transaction/beef/reference_603_tests.rs`
// and, for the `stream_s2_*` cases (#603 shard S2 of `beef_stream.rs`, rows byte-identical
// at bsv-script-lean@5dc337e1), `tests/beef_stream_603_s2.rs`.
import fs from 'fs'
import path from 'path'
import { pathToFileURL } from 'url'

const [sdkPath, corpusDir] = process.argv.slice(2)
const { Beef, BeefTx, MerklePath, P2PKH, PrivateKey, Transaction, Utils } = await import(
  pathToFileURL(sdkPath).href
)

const ROWS = [
  'beef-001', 'beef-002', 'beef-003', 'beef-004', 'beef-014', 'beef-015', 'beef-023', 'beef-026',
  'beef-029', 'beef-030', 'atomic-beef-001'
]
// Shard S4 of src/transaction/beef_stream.rs (the judge and the remainder):
// these rows join the recording; the cases below are `s4_*`, the tests
// `tests/beef_stream_603_s4.rs`.
ROWS.push('beef-031', 'atomic-beef-023', 'atomic-beef-025')
const rows = {}
for (const file of ['beef.jsonl', 'atomic-beef.jsonl']) {
  for (const line of fs.readFileSync(path.join(corpusDir, file), 'utf8').split('\n')) {
    if (line.trim() === '') continue
    const row = JSON.parse(line)
    if (ROWS.includes(row.id)) rows[row.id] = { hex: row.hex, subject: row.subject ?? null }
  }
}
const bytes = id => Utils.toArray(rows[id].hex, 'hex')
const read = id => Beef.fromBinary(bytes(id))
const BEEF_V1 = 4022206465

// beef-023: version 1, the parent (block 9's coinbase) with its BUMP, then the child.
const family = read('beef-023')
const parent = family.txs[0]
const child = family.txs[1]
const parentBump = family.bumps[parent.bumpIndex]

const cases = {}

// merge_bump (Beef.ts:687-811): a BUMP of the same height and root is combined, not added.
{
  const b = read('beef-001')
  b.mergeBeef(bytes('beef-001'))
  cases.merge_beef_into_itself = { row: 'beef-001', bumps: b.bumps.length, hex: b.toHex() }
}

// update_bump_indices (#mergeBumpEntry, :774-789): a BUMP merged after the raw
// transaction it proves marks that transaction proven.
{
  const b = new Beef(BEEF_V1)
  b.mergeRawTx(parent.rawTx)
  b.mergeRawTx(child.rawTx)
  b.mergeBump(MerklePath.fromHex(parentBump.toHex()))
  cases.bump_merged_after_its_transaction = { row: 'beef-023', hex: b.toHex() }
}

// mark_mutated (#markMutated, :325-332; #ensureSortedForSerialization, :354-358):
// a merge after a serialization sorts again.
{
  const b = new Beef(BEEF_V1)
  b.mergeBump(MerklePath.fromHex(parentBump.toHex()))
  b.mergeRawTx(child.rawTx)
  const first = b.toHex()
  b.mergeRawTx(parent.rawTx)
  cases.parent_merged_after_a_serialization = { row: 'beef-023', first, second: b.toHex() }
}

// find_bump (:570-574).
{
  const b = read('beef-001')
  const found = b.findBump(rows['beef-001'].subject)
  cases.find_bump = {
    row: 'beef-001',
    txid: rows['beef-001'].subject,
    block_height: found.blockHeight,
    root: found.computeRoot(),
    absent: family.findBump(child.txid) === undefined
  }
}

// find_transaction_for_signing (:615-631): the transaction, each input's source
// transaction taken from the BEEF.
{
  const b = read('beef-023')
  const tx = b.findTransactionForSigning(child.txid)
  cases.find_transaction_for_signing = {
    row: 'beef-023',
    txid: child.txid,
    found: tx.id('hex'),
    sources: tx.inputs.map(i => (i.sourceTransaction == null ? null : i.sourceTransaction.id('hex'))),
    absent: b.findTransactionForSigning('00'.repeat(32)) === undefined
  }
}

// find_atomic_transaction (:639-668): the source transaction linked, its BUMP attached.
{
  const b = read('beef-023')
  const tx = b.findAtomicTransaction(child.txid)
  const source = tx.inputs[0].sourceTransaction
  cases.find_atomic_transaction = {
    row: 'beef-023',
    txid: child.txid,
    source: source.id('hex'),
    source_block_height: source.merklePath.blockHeight
  }
}

// from_reader (:1240-1284): one BEEF from the front, the byte after it left.
{
  const reader = new Utils.Reader(bytes('beef-030'))
  const b = Beef.fromReader(reader)
  cases.from_reader = { row: 'beef-030', hex: b.toHex(), left: reader.bin.length - reader.pos }
}

// is_atomic (:482-495).
cases.is_atomic = {
  rows: { 'beef-001': read('beef-001').isAtomic(), 'atomic-beef-001': read('atomic-beef-001').isAtomic() }
}

// clone_shallow (clone, :1605-1622).
cases.clone = { row: 'beef-023', hex: read('beef-023').clone().toHex() }

// to_log_string (toLogString, :1698-1733).
cases.to_log_string = { row: 'beef-023', log: read('beef-023').toLogString() }

// bump_roots (#collectBumpTxids and #confirmComputedRoot, :1112-1127, :1153-1167):
// two BUMPs at one height agree on its root or the BEEF is refused.
{
  const b = read('beef-001')
  b.bumps.push(MerklePath.fromHex(b.bumps[0].toHex()))
  cases.two_bumps_one_root = { row: 'beef-001', hex: b.toHex(), valid: b.verifyValid().valid }
}
{
  const b = read('beef-001')
  const other = read('beef-002').bumps[0]
  b.bumps.push(new MerklePath(b.bumps[0].blockHeight, other.path))
  cases.two_bumps_two_roots = {
    row: 'beef-001',
    other_row: 'beef-002',
    hex: b.toHex(),
    valid: b.verifyValid().valid
  }
}

// entries_as_folded (#verifyBumpIndexLeaves, :1129-1139): a BUMP index naming a
// BUMP that does not carry the txid, and one naming no BUMP.
{
  const b = read('beef-023')
  b.findTxid(child.txid).bumpIndex = 0
  cases.bump_index_names_a_bump_without_the_txid = { row: 'beef-023', valid: b.verifyValid().valid }
}
cases.bump_index_names_no_bump = { row: 'beef-029', valid: read('beef-029').verifyValid().valid }

// sort_txs (partitionTxs, :1450-1472): a raw transaction with no input is not a
// txid-only entry; it sorts after the proven ones.
{
  const b = new Beef(BEEF_V1)
  b.mergeBump(MerklePath.fromHex(parentBump.toHex()))
  b.mergeRawTx(parent.rawTx)
  const out = parent.tx.outputs[0]
  const noInput = new Transaction(1, [], [{ satoshis: out.satoshis, lockingScript: out.lockingScript }], 0)
  const raw = noInput.toBinary()
  b.mergeRawTx(raw)
  const sr = b.sortTxs()
  cases.raw_transaction_without_inputs = {
    row: 'beef-023',
    raw: Utils.toHex(raw),
    txid_only: sr.txidOnly,
    order: b.txs.map(t => t.txid)
  }
}

// verify_structure (verifyValid, :1065-1073): a ring held in the input cache is
// `notValid`, with no input missing, and refused.
{
  const b = new Beef(BEEF_V1)
  const one = read('beef-002').txs[0]
  const two = read('beef-004').txs[0]
  const a = b.mergeRawTx(one.rawTx)
  const c = b.mergeRawTx(two.rawTx)
  a.inputTxids = [c.txid]
  c.inputTxids = [a.txid]
  const sr = b.sortTxs()
  cases.ring_in_the_input_cache = {
    rows: ['beef-002', 'beef-004'],
    missing_inputs: sr.missingInputs,
    not_valid: sr.notValid.slice().sort(),
    valid: b.verifyValid().valid
  }
}

// The bump clean-up's guard (#reindexBumps, :1649-1660): no BUMP is removed
// while the BUMP indices named are as many as the BUMPs, an index past the
// BUMPs among them.
{
  const b = new Beef(BEEF_V1)
  const proven = read('beef-002')
  b.mergeBump(MerklePath.fromHex(proven.bumps[0].toHex()))
  b.mergeRawTx(proven.txs[0].rawTx)
  b.bumps.push(MerklePath.fromHex(read('beef-004').bumps[0].toHex()))
  const t = b.mergeRawTx(read('beef-004').txs[0].rawTx)
  t.bumpIndex = 5
  b.trimKnownTxids([])
  cases.reindex_guard_with_an_index_past_the_bumps = { rows: ['beef-002', 'beef-004'], bumps: b.bumps.length }
}

// #603 shard S2, src/transaction/beef_stream.rs's index folds (`BeefIndex::fold_bump`,
// `fold_tx`, `fold_txid_only`): the BEEFs the stream reads in `tests/beef_stream_603_s2.rs`,
// each with the reference's verdict (`verifyValid(true)`, :1054-1090) and the roots it
// checked. A frame whose order the reference's sort would change is written entry by
// entry by the reference's own writer (`Beef.toWriter`, :1169-1181, no sort). The Lean's
// summaries of the same bytes are `tests/support/beef_stream_603_s2.lean`'s.
const BEEF_V2 = 4022206466
const framed = (version, bumps, txs) => {
  const b = new Beef(version)
  b.bumps = bumps
  b.txs = txs
  const w = new Utils.Writer()
  b.toWriter(w)
  return Utils.toHex(w.toArray())
}
const verdict = hex => {
  const r = Beef.fromString(hex).verifyValid(true)
  return { valid: r.valid, roots: r.roots }
}
const shape = m => ({
  height: m.blockHeight,
  levels: m.path.length,
  leaves: m.path.reduce((n, l) => n + l.length, 0),
  txids: m.path[0].filter(l => l.txid === true).length
})

// mergeBump (:687-811): two BUMPs at one height with one root are combined into one that
// proves both txids (beef-014 and beef-015, block 500000); a second BUMP (beef-023's,
// block 9) proves one; makeTxidOnly (:552-563) leaves beef-014's transaction as a txid
// the combined BUMP proves; beef-015's transaction has three inputs.
{
  const b = new Beef(BEEF_V2)
  b.mergeBeef(bytes('beef-014'))
  b.mergeBeef(bytes('beef-015'))
  b.mergeBeef(bytes('beef-023'))
  b.makeTxidOnly(read('beef-014').txs[0].txid)
  const hex = b.toHex()
  const again = Beef.fromString(hex)
  cases.stream_s2_two_bumps_combined_and_a_txid_only_entry = {
    rows: ['beef-014', 'beef-015', 'beef-023'],
    hex,
    bumps: again.bumps.map(shape),
    txs: again.txs.map(t => ({ txid: t.txid, txid_only: t.isTxidOnly, bump_index: t.bumpIndex ?? null })),
    ...verdict(hex)
  }
}

// One BUMP whose level 0 carries one txid at two offsets (beef-003's transaction at 0
// and at 1, a tree of height 1), its transaction naming it.
{
  const t = read('beef-003').txs[0]
  const m = new MerklePath(100000, [[
    { offset: 0, hash: t.txid, txid: true },
    { offset: 1, hash: t.txid, txid: true }
  ]])
  const hex = framed(BEEF_V1, [m], [BeefTx.fromRawTx(t.rawTx, 0)])
  cases.stream_s2_one_bump_carries_one_txid_twice = { row: 'beef-003', hex, bumps: [shape(m)], ...verdict(hex) }
}

// One txid carried by two BUMPs (beef-003's own at block 100000, and one at 800000 where
// beef-004's txid is its sibling), the transaction naming the later (#verifyBumpIndexLeaves,
// :1129-1139: the BUMP its index names carries it).
{
  const t = read('beef-003').txs[0]
  const own = read('beef-003').bumps[0]
  const later = new MerklePath(800000, [[
    { offset: 0, hash: read('beef-004').txs[0].txid },
    { offset: 1, hash: t.txid, txid: true }
  ]])
  const hex = framed(BEEF_V1, [MerklePath.fromHex(own.toHex()), later], [BeefTx.fromRawTx(t.rawTx, 1)])
  cases.stream_s2_one_txid_in_two_bumps_named_by_the_later = {
    rows: ['beef-003', 'beef-004'],
    hex,
    bumps: [shape(own), shape(later)],
    ...verdict(hex)
  }
}

// beef-026 (the child ahead of its parent, the parent under its BUMP) with the parent a
// txid-only entry: the reference sorts before it checks (sortTxs, :1065).
{
  const row = read('beef-026')
  const childTx = row.txs[0]
  const parentTx = row.txs[1]
  const hex = framed(
    BEEF_V2,
    [MerklePath.fromHex(row.bumps[0].toHex())],
    [BeefTx.fromRawTx(childTx.rawTx), BeefTx.fromTxid(parentTx.txid)]
  )
  cases.stream_s2_child_before_its_txid_only_parent = { row: 'beef-026', hex, ...verdict(hex) }
}
cases.stream_s2_child_before_its_parent = { row: 'beef-026', hex: rows['beef-026'].hex, ...verdict(rows['beef-026'].hex) }

// A parent P under a BUMP of block 800000 (beef-001's coinbase txid its sibling at offset
// 0) and two children spending P:0 with P2PKH under one key: C0 (version 1, lock time 0)
// and C1 (the sibling's finality row `finality/threshold-500000000`'s transaction: version
// 2, lock time 500000000, sequence 0). The scripts are the reference's verdict
// (`Transaction.verify('scripts only')`).
const key = PrivateKey.fromString('0000000000000000000000000000000000000000000000000000000000000603', 'hex')
const lock = new P2PKH().lock(key.toAddress())
const p = new Transaction(1, [{
  sourceTXID: read('beef-001').txs[0].txid, sourceOutputIndex: 0,
  unlockingScript: new P2PKH().lock(key.toAddress()), sequence: 0xffffffff
}], [{ satoshis: 1000, lockingScript: lock }], 0)
const pBump = new MerklePath(800000, [[
  { offset: 0, hash: read('beef-001').txs[0].txid },
  { offset: 1, hash: p.id('hex'), txid: true }
]])
p.merklePath = pBump
const spender = async (version, lockTime, sequence) => {
  const c = new Transaction(version, [{
    sourceTransaction: p, sourceOutputIndex: 0, unlockingScriptTemplate: new P2PKH().unlock(key), sequence
  }], [{ satoshis: 900, lockingScript: lock }], lockTime)
  await c.sign()
  return c
}
const c0 = await spender(1, 0, 0xffffffff)
const c1 = await spender(2, 500000000, 0)
const scripts = async c => c.verify('scripts only')
const pRaw = p.toBinary()
const pEntry = () => BeefTx.fromRawTx(pRaw, 0)
{
  const hex = framed(BEEF_V2, [pBump], [BeefTx.fromTxid(p.id('hex')), pEntry(), BeefTx.fromRawTx(c0.toBinary())])
  const merged = new Beef(BEEF_V2)
  merged.mergeBeef(Utils.toArray(hex, 'hex'))
  cases.stream_s2_txid_only_entry_then_its_transaction = {
    hex,
    parent: p.id('hex'),
    child: c0.id('hex'),
    scripts: await scripts(c0),
    valid: verdict(hex).valid,
    merged_valid: merged.verifyValid(true).valid,
    merged_txs: merged.txs.length,
    roots: merged.verifyValid(true).roots
  }
}
{
  const hex = framed(BEEF_V1, [pBump], [pEntry(), pEntry(), BeefTx.fromRawTx(c0.toBinary())])
  const merged = new Beef(BEEF_V1)
  merged.mergeBeef(Utils.toArray(hex, 'hex'))
  cases.stream_s2_transaction_twice = {
    hex,
    parent: p.id('hex'),
    child: c0.id('hex'),
    scripts: await scripts(c0),
    valid: verdict(hex).valid,
    merged_valid: merged.verifyValid(true).valid,
    merged_txs: merged.txs.length,
    roots: merged.verifyValid(true).roots
  }
}
{
  const hex = framed(BEEF_V1, [pBump], [pEntry(), BeefTx.fromRawTx(c1.toBinary())])
  cases.stream_s2_lock_time_at_the_threshold = {
    finality_row: 'finality/threshold-500000000',
    hex,
    child: c1.id('hex'),
    child_raw: c1.toHex(),
    version: c1.version,
    lock_time: c1.lockTime,
    sequences: c1.inputs.map(i => i.sequence),
    scripts: await scripts(c1),
    ...verdict(hex)
  }
}

// ---- Shard S4 (src/transaction/beef_stream.rs's judge and remainder, #603) ----

// A chain tracker that answers every root with `carried` and fails a height read:
// Beef.verify (:1020-1035) asks the tracker for the roots and nothing else.
const tracker = carried => ({
  isValidRootForHeight: async () => carried,
  currentHeight: async () => {
    throw new Error('the height is not read')
  }
})
const outcome = f => {
  try {
    return { ok: f() }
  } catch (e) {
    return { error: e.message }
  }
}

// BRC-95's subject (Transaction.fromAtomicBEEF, Transaction.ts:302-313): the
// subject the prefix names is found as a raw transaction of the BEEF; the same
// bytes with the subject absent (atomic-beef-025) are refused.
cases.s4_atomic_subject = {
  rows: ['atomic-beef-023', 'atomic-beef-025'],
  prefix_subject: read('atomic-beef-023').atomicTxid,
  found: outcome(() => Transaction.fromAtomicBEEF(bytes('atomic-beef-023')).id('hex')),
  missing_prefix_subject: read('atomic-beef-025').atomicTxid,
  missing: outcome(() => Transaction.fromAtomicBEEF(bytes('atomic-beef-025')).id('hex'))
}

// A subject the caller names that the BEEF does not carry (Transaction.fromBEEF
// with a txid, Transaction.ts:282-285): beef-023 asked for atomic-beef-025's subject.
cases.s4_named_subject_absent = {
  row: 'beef-023',
  subject: rows['atomic-beef-025'].subject,
  found: outcome(() => Transaction.fromBEEF(bytes('beef-023'), rows['atomic-beef-025'].subject).id('hex')),
  raw_txids: read('beef-023').txs.filter(t => !t.isTxidOnly).map(t => t.txid)
}

// The roots against the tracker (Beef.verify, :1020-1035): every root carried,
// then no root carried; the height is never read for a BEEF of proven roots.
{
  const roots = {}
  for (const id of ['beef-001', 'beef-023']) {
    const b = read(id)
    roots[id] = {
      carried: await b.verify(tracker(true)),
      not_carried: await b.verify(tracker(false)),
      bumps: b.bumps.map(m => ({ block_height: m.blockHeight, root: m.computeRoot() }))
    }
  }
  cases.s4_roots_against_the_tracker = { rows: roots }
}

// The outpoints the unproven transactions of beef-023 and beef-001 spend: each
// raw transaction without a BUMP, its inputs as parsed (BeefTx, Beef.ts).
{
  const spent = {}
  for (const id of ['beef-001', 'beef-023']) {
    spent[id] = read(id)
      .txs.filter(t => !t.isTxidOnly && t.bumpIndex === undefined)
      .flatMap(t => t.tx.inputs.map(i => ({ txid: i.sourceTXID, vout: i.sourceOutputIndex })))
  }
  cases.s4_unproven_spends = { rows: spent }
}

// A truncated BEEF (beef-031) is refused by the reader (Beef.fromBinary, :1240-1309).
cases.s4_truncated = { row: 'beef-031', read: outcome(() => read('beef-031').toHex()) }

console.log(
  JSON.stringify(
    {
      reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk/src/transaction/Beef.ts',
      node: process.version,
      sibling: 'bsv-script-lean@387dab351273e9018cffb595ef40521f39e4b8d3 corpus/wire',
      // S4's rows (beef-031, atomic-beef-023, atomic-beef-025) were read at
      // 5dc337e1, where every row above it is byte-identical.
      sibling_s4: 'bsv-script-lean@5dc337e1 corpus/wire',
      rows,
      cases
    },
    null,
    2
  )
)
