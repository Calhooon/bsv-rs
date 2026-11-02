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
// at edf6e03) on them. The tests are `src/transaction/beef/reference_603_tests.rs`.
import fs from 'fs'
import path from 'path'
import { pathToFileURL } from 'url'

const [sdkPath, corpusDir] = process.argv.slice(2)
const { Beef, MerklePath, Transaction, Utils } = await import(
  pathToFileURL(sdkPath).href
)

const ROWS = ['beef-001', 'beef-002', 'beef-004', 'beef-023', 'beef-029', 'beef-030', 'atomic-beef-001']
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

console.log(
  JSON.stringify(
    {
      reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk/src/transaction/Beef.ts',
      node: process.version,
      sibling: 'bsv-script-lean@387dab351273e9018cffb595ef40521f39e4b8d3 corpus/wire',
      rows,
      cases
    },
    null,
    2
  )
)
