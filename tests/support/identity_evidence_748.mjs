// #748: the evidence walk's visited set (`assertUnconfirmedGraph`,
// `ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts:155-177`,
// the set at `:162-166`), `parseEvidence` (`:93-201`) called directly on
// BEEFs the reference's writer builds, under
// `defaultTransactionEvidenceLimits` (`:61-77`), with `parseResults`'
// outcome under the toolbox wallet's verifier (a tracker admitting every
// root, tip 1000). The helpers are #741's
// (`tests/support/identity_evidence_741.mjs`, copied, the replay given a
// switch removing the visited set's skip; its vector untouched).
//
// The shapes, each reaching one node of the graph twice:
// - `shared_unproven_grandparent`: the subject spends P1:0 and P2:0, both
//   unproven; P1 spends G:0 and P2 spends G:1; G is unproven and spends
//   GG:0 (2 satoshis, G's two outputs 1 each); GG is proven with no
//   inputs. G is pushed twice and walked once;
//   without the set G is walked twice, GG:0 spent twice (`:149`).
// - `proven_grandparent_reached_twice`: the subject spends P1:0 and P2:0,
//   both unproven, P1 spending G:0 and P2 G:1; G proven with 4092 inputs
//   whose sources are absent (the txid `ab..ab`, outputs 0 to 4091): the
//   sum is 2 + 1 + 1 + 4092 = 4096, read; without the set G is summed twice,
//   8188, `limit` at `:170-171`.
//
// The fields are #741's, with `replay_without_visited` the replay's line
// and node with the set's skip removed (null for a read) and `g_pushes` how
// many times the walk pushes G.
//
// The bundle (#741's recipe, entry748.ts the same three exports):
//   W=/Volumes/Lanes/out/bsv-rs/fix-748/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry748.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry748.ts --target node --format esm --outfile "$W/ref748.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_748.mjs \
//     "$W/ref748.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_748.json
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
// (#730's replay); with `useVisited` false the visited set's skip
// (`:164-166`) removed, the mutation #748 pins against.
const replay = (bytes, outputIndex, useVisited = true) => {
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
    if (useVisited && visited.has(id)) continue
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
const add = async (name, check, writer, [bytes, subject], gPushes, outputIndex = 0) => {
  const [site, detail] = replay(bytes, outputIndex)
  const [mutSite, mutDetail] = replay(bytes, outputIndex, false)
  const selectedTxid = selected(bytes, outputIndex)
  const code = selectedTxid.startsWith('refused: Transaction evidence: ')
    ? selectedTxid.slice('refused: Transaction evidence: '.length)
    : null
  const shape = {
    name, check, writer, output_index: outputIndex, subject_txid: subject.id('hex'),
    beef_bytes: bytes.length,
    beef_sha256: createHash('sha256').update(Buffer.from(bytes)).digest('hex')
  }
  if (bytes.length <= 4096) shape.beef = Utils.toHex(bytes)
  Object.assign(shape, {
    selected_txid: selectedTxid, code, site,
    refused_at: site === null ? null : `${site}: ${detail}`,
    outcome: await judged(bytes, outputIndex),
    g_pushes: gPushes,
    replay_without_visited: mutSite === null ? null : `${mutSite}: ${mutDetail}`
  })
  shapes.push(shape)
}

const opTrue = () => LockingScript.fromHex('51')
const spending = (sources, outputs = 1, satoshis = 1) => {
  const tx = new Transaction()
  for (const [txid, vout] of sources) addSpend(tx, txid, vout, '')
  for (let i = 0; i < outputs; i++) tx.addOutput({ satoshis, lockingScript: opTrue() })
  return tx
}
// P1 spending G:0 and P2 G:1, the subject spending P1:0 then P2:0, its
// output the reference's token; the BEEF merged the subject, P1, P2, then
// `under` (G and what it stands on). Sources named by txid.
const twoParentsOfG = (gTxid, under) => {
  const one = spending([[gTxid, 0]])
  const two = spending([[gTxid, 1]])
  const subject = spending([[one.id('hex'), 0], [two.id('hex'), 0]], 0)
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  beef.mergeRawTx(one.toBinary())
  beef.mergeRawTx(two.toBinary())
  under(beef)
  return [beef.toBinary(), subject, { p1: one.id('hex'), p2: two.id('hex') }]
}

const absent = 'ab'.repeat(32)
const gInputs = limits.inputs - 4
const txids = {}

{
  // GG's one output of 2 satoshis, so G's two outputs of 1 do not exceed
  // its input (`Transaction.verify` under the toolbox's verifier).
  const gg = spending([], 1, 2)
  const ggTxid = gg.id('hex')
  const g = spending([[ggTxid, 0]], 2)
  const gTxid = g.id('hex')
  const [bytes, subject, ids] = twoParentsOfG(gTxid, (beef) => {
    beef.mergeRawTx(g.toBinary())
    proven(beef, gg, 900)
  })
  txids.shared_unproven_grandparent = { ...ids, g: gTxid, gg: ggTxid }
  await add('shared_unproven_grandparent',
    'the visited set over a shared unproven grandparent G: pushed by P1 and by P2, walked once, GG:0 spent once; read',
    'Beef.toBinary, merged the unproven subject, P1, P2, G, the proven GG', [bytes, subject], 2)
}
{
  const g = spending(Array.from({ length: gInputs }, (_, i) => [absent, i]), 2)
  const gTxid = g.id('hex')
  const [bytes, subject, ids] = twoParentsOfG(gTxid, (beef) => proven(beef, g, 900))
  txids.proven_grandparent_reached_twice = { ...ids, g: gTxid }
  await add('proven_grandparent_reached_twice',
    'the visited set over a proven grandparent G of 4092 inputs reached by P1 and by P2: 2 + 1 + 1 + 4092 = 4096 once, read',
    'Beef.toBinary, merged the unproven subject, P1, P2, the proven G', [bytes, subject], 2)
}

process.stdout.write(JSON.stringify({
  description: '#748: the reference\'s parseEvidence on ls_identity lookup BEEFs reaching one node of the ' +
    'unconfirmed graph twice (an unproven grandparent shared by two unproven parents; a proven grandparent ' +
    'of 4092 inputs reached by both): the code, the line, the selected txid, parseResults\' outcome, and the ' +
    'replay with the visited set\'s skip removed',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:61-77,93-201; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_748.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  limits: { inputs: limits.inputs, script_bytes: limits.scriptBytes },
  absent_source_txid: absent,
  g_inputs: gInputs,
  txids,
  shapes
}, null, 2) + '\n')
