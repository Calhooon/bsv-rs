// #736: the evidence check's bounds graph-wide and a parent written twice,
// `parseEvidence` (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/TransactionEvidence.ts:93-201`) called
// directly on BEEFs the reference's writer builds, under
// `defaultTransactionEvidenceLimits` (`:61-77`), with `parseResults`'
// outcome under the toolbox wallet's verifier (a tracker admitting every
// root, tip 1000), as in #730's recorder
// (`tests/support/identity_evidence_730.mjs`, whose helpers this file copies
// and whose vector it leaves untouched).
//
// The shapes:
// - `graph_inputs_over_bound`, `graph_inputs_at_bound`: an unproven subject
//   of 2048 inputs spending an unproven parent of 2049 (of 2048) inputs,
//   which spends a proven grandparent with no inputs (a lone leaf at offset
//   0, height 900); the walk's running sum `inputs` (`:166-171`) reaches
//   4097 at the parent (`limit`, `:170-171`) or 4096 over the graph (read).
//   The grandparent has no inputs so that the graph's sum is the subject's
//   and the parent's alone: a proven transaction's inputs count too (`:169`,
//   before the proof ends its branch at `:173`).
// - `graph_script_bytes_over_bound`, `graph_script_bytes_at_bound`: an
//   unproven subject whose scripts are 131072 bytes (the token and an
//   OP_PUSHDATA4 padding output) spending a PROVEN parent whose scripts are
//   131073 (131072) bytes; neither crosses `limits.scriptBytes` alone, the
//   running sum `scriptBytes` (`:168`, `graphScriptBytes` over every
//   visited transaction, proven ones included) reaches 262145 (`limit`) or
//   262144 (read).
// - `parent_raw_then_txid_only`, `parent_txid_only_then_raw`: one unproven
//   parent written as a raw entry and as a txid-only entry, in both orders,
//   between its proven grandparent and the subject. The index keeps the
//   later entry (`Beef.#rebuildTxIndexes`, `Beef.ts:516-524`): raw then
//   txid-only leaves the subject's input without a source (`:143`,
//   `invalid-evidence`), txid-only then raw links it (read). Neither
//   `Beef.toBinary` nor `mergeRawTx`/`mergeTxidOnly` writes both entries,
//   so the bytes are `Beef.toWriter` over `txs` set by hand (the entries
//   `BeefTx.fromTx` and `BeefTx.fromTxid`), unsorted.
//
// Each shape's `site` is the replayed refusal's line, `refused_at` the line
// with the node it names; `selected_txid` is `parseEvidence`'s txid or its
// error; `outcome` is `parseResults`' (read, skipped, or `refused: <words>`
// when it rethrows, `identityUtils.ts:630-634`). A shape over 4096 bytes
// carries its `beef_sha256` and `beef_bytes` alone, and its `size` (the
// count or padding its builder takes).
//
// The bundle (the recipe of tests/support/identity_evidence_730.mjs):
//   W=/Volumes/Lanes/out/bsv-rs/fix-736/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry736.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry736.ts --target node --format esm --outfile "$W/ref736.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_736.mjs \
//     "$W/ref736.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_736.json
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits: limits, Beef, BeefTx, LockingScript,
  UnlockingScript, Transaction, MerklePath, Utils
} = sdk
const record553 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const token = record553.cases[0].locking_script
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }

// One input spending `source` (a transaction, or a txid) at `vout` with
// `unlocking`.
const addSpend = (tx, source, vout, unlocking) => {
  const input = typeof source === 'string' ? { sourceTXID: source } : { sourceTransaction: source }
  tx.addInput({
    ...input, sourceOutputIndex: vout,
    unlockingScript: UnlockingScript.fromHex(unlocking), sequence: 0xffffffff
  })
}
// One input spending `source` at 0 with `unlocking`, one 1-satoshi output
// locked by `lock`.
const spending = (source, unlocking, lock) => {
  const tx = new Transaction()
  addSpend(tx, source, 0, unlocking)
  tx.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(lock) })
  return tx
}
// A block of one transaction at `height`: its BUMP a lone leaf at offset 0.
const loneLeaf = (txid, height) => new MerklePath(height, [[{ offset: 0, hash: txid, txid: true }]])
// `tx` merged raw with a BUMP of its own at `height`.
const proven = (beef, tx, height) => beef.mergeRawTx(tx.toBinary(), beef.mergeBump(loneLeaf(tx.id('hex'), height)))
// A push of `n` zero bytes under OP_PUSHDATA4, as a locking script.
const padding = (n) => {
  const w = new Utils.Writer()
  w.writeUInt8(0x4e)
  w.writeUInt32LE(n)
  w.write(new Array(n).fill(0))
  return LockingScript.fromBinary(w.toArray())
}

const grandparent = spending('22'.repeat(32), '51', '51')
const tokenBytes = Utils.toArray(token, 'hex').length
// The subject's scripts in the script-bytes shapes: half the bound, the
// token and a padding output of `subjectPadding` bytes pushed (5 + n).
const half = limits.scriptBytes / 2
const subjectPadding = half - tokenBytes - 5

// limits.inputs over the graph: a proven grandparent with no inputs and
// `parentInputs` outputs, an unproven parent spending each of them with
// `subjectInputs` outputs, the unproven subject spending each of those.
const graphInputs = (subjectInputs, parentInputs) => {
  const g = new Transaction()
  for (let i = 0; i < parentInputs; i++) g.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
  // The sources named by txid, each id computed once: `toBinary` over
  // `sourceTransaction` links hashes the source again for every input.
  const gTxid = g.id('hex')
  const parent = new Transaction()
  for (let i = 0; i < parentInputs; i++) addSpend(parent, gTxid, i, '')
  for (let i = 0; i < subjectInputs; i++) parent.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
  const parentTxid = parent.id('hex')
  const subject = new Transaction()
  for (let i = 0; i < subjectInputs; i++) addSpend(subject, parentTxid, i, '')
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  beef.mergeRawTx(parent.toBinary())
  proven(beef, g, 900)
  return [beef.toBinary(), subject]
}
// limits.scriptBytes over the graph: the unproven subject's scripts
// `half` bytes, its proven parent's `7 + n` (the unlocking `51`, the
// locking `51`, a padding output of `n` bytes pushed).
const graphScriptBytes = (n) => {
  const parent = spending('22'.repeat(32), '51', '51')
  parent.addOutput({ satoshis: 0, lockingScript: padding(n) })
  const subject = spending(parent, '', token)
  subject.addOutput({ satoshis: 0, lockingScript: padding(subjectPadding) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  proven(beef, parent, 900)
  return [beef.toBinary(), subject]
}
// One unproven parent written raw and txid-only, `rawBefore` naming the
// order, between the proven grandparent and the subject: the entries
// set by hand and written by `Beef.toWriter`, unsorted.
const parentTwice = (rawBefore) => {
  const parent = spending(grandparent, '', '51')
  const subject = spending(parent, '', token)
  const beef = new Beef()
  const bumpIndex = beef.mergeBump(loneLeaf(grandparent.id('hex'), 900))
  const raw = BeefTx.fromTx(parent)
  const txidOnly = BeefTx.fromTxid(parent.id('hex'))
  beef.txs = [
    BeefTx.fromTx(grandparent, bumpIndex),
    ...(rawBefore ? [raw, txidOnly] : [txidOnly, raw]),
    BeefTx.fromTx(subject)
  ]
  const w = new Utils.Writer()
  beef.toWriter(w)
  return [w.toArray(), subject, parent]
}

// The replayed refusal (`parseEvidence`'s own error carries no line):
// `parseEvidence`'s steps through the reference's public `Beef` methods
// (#730's replay).
const replay = (bytes, outputIndex) => {
  if (bytes.length > limits.candidateBytes) return ['TransactionEvidence.ts:101', `${bytes.length} bytes`]
  const beef = Beef.fromBinaryStrict(bytes)
  if (beef.txs.length > limits.transactions) return ['TransactionEvidence.ts:117', `${beef.txs.length} transactions`]
  const target = beef.atomicTxid ?? beef.txs.at(-1)?.txid
  const tx = beef.findAtomicTransaction(target)
  if (tx === undefined) return ['TransactionEvidence.ts:120-121', `findAtomicTransaction(${target}) is undefined`]
  if (outputIndex >= tx.outputs.length) {
    return ['TransactionEvidence.ts:126', `${tx.id('hex')} has ${tx.outputs.length} outputs, outputIndex ${outputIndex}`]
  }
  const pending = [tx]
  const visited = new Set()
  const spent = new Set()
  let inputCount = 0
  let scriptCount = 0
  while (pending.length > 0) {
    const current = pending.pop()
    const id = current.id('hex')
    if (visited.has(id)) continue
    visited.add(id)
    for (const output of current.outputs) scriptCount += output.lockingScript.toBinary().length
    for (const input of current.inputs) scriptCount += input.unlockingScript?.toBinary().length ?? 0
    inputCount += current.inputs.length
    if (inputCount > limits.inputs || scriptCount > limits.scriptBytes) {
      return ['TransactionEvidence.ts:170-171', `${id}: ${inputCount} inputs, ${scriptCount} script bytes`]
    }
    if (current.merklePath != null) continue
    if (current.inputs.length === 0) return ['TransactionEvidence.ts:174', `${id} is unproven with no inputs`]
    for (const input of current.inputs) {
      if (input.sourceTransaction == null) {
        return ['TransactionEvidence.ts:143', `${id} input ${input.sourceTXID}.${input.sourceOutputIndex} has no source transaction`]
      }
      const sourceTxid = input.sourceTransaction.id('hex')
      if (input.sourceTXID !== undefined && input.sourceTXID !== sourceTxid) {
        return ['TransactionEvidence.ts:145-146', `${id} input names ${input.sourceTXID}, its source is ${sourceTxid}`]
      }
      const outpoint = `${sourceTxid}.${input.sourceOutputIndex}`
      if (spent.has(outpoint)) return ['TransactionEvidence.ts:149', `${id} input ${outpoint} spent twice`]
      spent.add(outpoint)
      pending.push(input.sourceTransaction)
    }
  }
  return [null, null]
}

const selected = (beef, outputIndex) => {
  try {
    return parseEvidence({ beef, outputIndex }, limits).txid
  } catch (e) {
    return `refused: ${e.message}`
  }
}
const judged = async (beef, outputIndex) => {
  const lookup = { type: 'output-list', outputs: [{ beef, outputIndex }] }
  try {
    const read = await parseResults(lookup, tracker)
    return read.length === 1 ? 'read' : 'skipped'
  } catch (e) {
    return `refused: ${e.message}`
  }
}

const shapes = []
const add = async (name, check, writer, [bytes, subject], size = null, outputIndex = 0) => {
  const [site, detail] = replay(bytes, outputIndex)
  const selectedTxid = selected(bytes, outputIndex)
  const code = selectedTxid.startsWith('refused: Transaction evidence: ')
    ? selectedTxid.slice('refused: Transaction evidence: '.length)
    : null
  const shape = {
    name, check, writer, size, output_index: outputIndex, subject_txid: subject.id('hex'),
    beef_bytes: bytes.length,
    beef_sha256: createHash('sha256').update(Buffer.from(bytes)).digest('hex')
  }
  if (bytes.length <= 4096) shape.beef = Utils.toHex(bytes)
  Object.assign(shape, {
    selected_txid: selectedTxid, code, site,
    refused_at: site === null ? null : `${site}: ${detail}`,
    outcome: await judged(bytes, outputIndex)
  })
  shapes.push(shape)
}

const graphWriter = 'Beef.toBinary, merged the unproven subject, the unproven parent, the proven grandparent'
const subjectInputs = limits.inputs / 2
await add('graph_inputs_over_bound',
  'limits.inputs over the graph, 2048 at the subject and 2049 at its unproven parent, :170-171',
  graphWriter, graphInputs(subjectInputs, subjectInputs + 1), subjectInputs + 1)
await add('graph_inputs_at_bound',
  'limits.inputs over the graph, 2048 at the subject and 2048 at its unproven parent, :170-171',
  graphWriter, graphInputs(subjectInputs, subjectInputs), subjectInputs)
const parentAt = limits.scriptBytes - half - 7
const scriptWriter = 'Beef.toBinary, merged the unproven subject, then its parent proven; both padded by an OP_PUSHDATA4 output'
await add('graph_script_bytes_over_bound',
  'limits.scriptBytes over the graph, 131072 at the subject and 131073 at its PROVEN parent, :168-171',
  scriptWriter, graphScriptBytes(parentAt + 1), parentAt + 1)
await add('graph_script_bytes_at_bound',
  'limits.scriptBytes over the graph, 131072 at the subject and 131072 at its PROVEN parent, :168-171',
  scriptWriter, graphScriptBytes(parentAt), parentAt)
const [rawBeforeBytes, rawBeforeSubject, parent] = parentTwice(true)
await add('parent_raw_then_txid_only',
  'one parent raw then txid-only: the later entry wins the index (Beef.ts:516-524), the input has no source, :143',
  'Beef.toWriter over txs set by hand: the proven grandparent, the parent raw, the parent txid-only, the subject',
  [rawBeforeBytes, rawBeforeSubject])
const [txidBeforeBytes, txidBeforeSubject] = parentTwice(false)
await add('parent_txid_only_then_raw',
  'one parent txid-only then raw: the later entry wins the index (Beef.ts:516-524), the walk links it, read',
  'Beef.toWriter over txs set by hand: the proven grandparent, the parent txid-only, the parent raw, the subject',
  [txidBeforeBytes, txidBeforeSubject])

process.stdout.write(JSON.stringify({
  description: '#736: the reference\'s parseEvidence on ls_identity lookup BEEFs (the inputs and scriptBytes ' +
    'limits as running sums over the unconfirmed graph, a proven parent\'s scripts counted, at and over their ' +
    'bounds; one parent written raw and txid-only in both orders): the code, the line, the selected txid, and ' +
    'parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:61-77,93-201; ' +
    'packages/sdk/src/transaction/Beef.ts:516-524,639-680,1169-1181; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_736.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  limits: { inputs: limits.inputs, script_bytes: limits.scriptBytes },
  subject_inputs: subjectInputs,
  subject_padding: subjectPadding,
  grandparent_txid: grandparent.id('hex'),
  twice_parent_txid: parent.id('hex'),
  shapes
}, null, 2) + '\n')
