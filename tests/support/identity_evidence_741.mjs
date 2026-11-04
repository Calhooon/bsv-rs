// #741: the evidence check's inputs bound over two unproven branches,
// `parseEvidence` (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/TransactionEvidence.ts:93-201`) called
// directly on BEEFs the reference's writer builds, under
// `defaultTransactionEvidenceLimits` (`:61-77`), with `parseResults`'
// outcome under the toolbox wallet's verifier (a tracker admitting every
// root, tip 1000). The helpers are #736's
// (`tests/support/identity_evidence_736.mjs`, copied; its vector untouched).
//
// The shapes: a subject of 2 inputs spending output 0 of two unproven
// parents P1 and P2, P1 of 2047 inputs and P2 of `size` inputs, each input
// spending its own output of one proven grandparent G with no inputs (a
// lone leaf at offset 0, height 900). The walk's running sums over every
// visited transaction (`assertUnconfirmedGraph`, `:155-177`) reach
// 2 + 2047 + 2047 = 4096 over the graph (`two_branches_at_bound`, read) or
// 2 + 2047 + 2048 = 4097 (`two_branches_over_bound`, `limit` at
// `:170-171`); along either path alone (the subject, one parent, G) the sum
// is at most 2050. The stack pops P2 before P1 (pushed in input order), so
// the refusal names P1, the second branch.
//
// The fields are #736's: `site` the replayed refusal's line, `refused_at`
// with the node it names, `selected_txid` `parseEvidence`'s txid or its
// error, `outcome` `parseResults'` (read, skipped, or `refused: <words>`,
// `identityUtils.ts:630-634`); each BEEF over 4096 bytes carries its
// `beef_sha256` and `beef_bytes` alone.
//
// The bundle (#736's recipe):
//   W=/Volumes/Lanes/out/bsv-rs/fix-741/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry741.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry741.ts --target node --format esm --outfile "$W/ref741.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_741.mjs \
//     "$W/ref741.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_741.json
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits: limits, Beef, LockingScript,
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
// A block of one transaction at `height`: its BUMP a lone leaf at offset 0.
const loneLeaf = (txid, height) => new MerklePath(height, [[{ offset: 0, hash: txid, txid: true }]])
// `tx` merged raw with a BUMP of its own at `height`.
const proven = (beef, tx, height) => beef.mergeRawTx(tx.toBinary(), beef.mergeBump(loneLeaf(tx.id('hex'), height)))

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

// The proven grandparent with no inputs and `p1 + p2` outputs, P1 spending
// its outputs 0 to p1 - 1 and P2 the next p2, each parent one output, the
// subject spending output 0 of P1 then of P2. Sources named by txid, each
// id computed once (#736's note on `toBinary` over `sourceTransaction`).
const twoBranches = (p1, p2) => {
  const g = new Transaction()
  for (let i = 0; i < p1 + p2; i++) g.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
  const gTxid = g.id('hex')
  const parent = (from, count) => {
    const tx = new Transaction()
    for (let i = from; i < from + count; i++) addSpend(tx, gTxid, i, '')
    tx.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
    return tx
  }
  const first = parent(0, p1)
  const second = parent(p1, p2)
  const subject = new Transaction()
  addSpend(subject, first.id('hex'), 0, '')
  addSpend(subject, second.id('hex'), 0, '')
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  beef.mergeRawTx(first.toBinary())
  beef.mergeRawTx(second.toBinary())
  proven(beef, g, 900)
  return [beef.toBinary(), subject, { g: gTxid, p1: first.id('hex'), p2: second.id('hex') }]
}

const writer = 'Beef.toBinary, merged the unproven subject, P1, P2, the proven grandparent'
const p1Inputs = limits.inputs / 2 - 1
const txids = {}
for (const [name, p2, check] of [
  ['two_branches_over_bound', p1Inputs + 1,
    'limits.inputs over two unproven branches, 2 at the subject, 2047 at P1, 2048 at P2: 4097, :170-171'],
  ['two_branches_at_bound', p1Inputs,
    'limits.inputs over two unproven branches, 2 at the subject, 2047 at P1, 2047 at P2: 4096, read']
]) {
  const [bytes, subject, ids] = twoBranches(p1Inputs, p2)
  txids[name] = ids
  await add(name, check, writer, [bytes, subject], p2)
}

process.stdout.write(JSON.stringify({
  description: '#741: the reference\'s parseEvidence on ls_identity lookup BEEFs (the inputs limit as a ' +
    'running sum over two unproven branches of one proven grandparent, at and over its bound, each path ' +
    'alone within it): the code, the line, the selected txid, and parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:61-77,93-201; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_741.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  limits: { inputs: limits.inputs, script_bytes: limits.scriptBytes },
  subject_inputs: 2,
  p1_inputs: p1Inputs,
  txids,
  shapes
}, null, 2) + '\n')
