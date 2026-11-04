// #730: the reference's evidence check on an `ls_identity` lookup output,
// `parseEvidence` (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/TransactionEvidence.ts:93-201`), called
// directly on BEEFs the reference's writer builds, under
// `defaultTransactionEvidenceLimits` (`:61-77`), with `parseResults`'
// outcome under the toolbox wallet's verifier (a tracker admitting every
// root), as in #728's recorder (`tests/support/identity_beef_subject_728.mjs`,
// whose helpers this file copies and whose vector it leaves untouched).
//
// The shapes: a second spend of one outpoint inside the unconfirmed graph
// (`:149`); an unproven transaction with no inputs (`:174`); a proven
// subject of 4096 and of 4097 inputs (`:170-171`, `limits.inputs`); a
// proven subject whose scripts are 262144 and 262145 bytes (`:170-171`,
// `limits.scriptBytes`); an Atomic BEEF of 256 and of 257 transactions,
// the subject proven, the rest txid-only entries outside its graph
// (`:117`, `limits.transactions`); an Atomic BEEF of 1048576 and of 1048577
// bytes, the subject proven beside a padded proven transaction outside its
// graph (`:101`, `limits.candidateBytes`); a proven parent whose own parent
// is absent (an agreement: read); and #728's shape 4 with the grandparent
// present raw and proven by its own BUMP, the parent's BUMP still naming
// another txid (read: `Beef.ts:649-666` links the grandparent and the walk
// stops at its proof, `TransactionEvidence.ts:173`). The output index past
// the outputs is #728's shape 1, not repeated. The `sourceTXID` check
// (`:145-146`) is probed and recorded as unreached from bytes: a raw
// entry's index txid and its transaction's id agree on every script form
// tried (a truncated push, one after `OP_RETURN`, a short push), the
// reference's scripts keeping their bytes.
//
// Each shape's `site` is the replayed refusal's line, `refused_at` the line
// with the node it names; `selected_txid` is `parseEvidence`'s txid or its
// error; `outcome` is `parseResults`' (read, skipped, or `refused: <words>`
// when it rethrows, `identityUtils.ts:630-634`). A shape over 4096 bytes
// carries its `beef_sha256` and `beef_bytes` alone, and its `size` (the
// count or padding its builder takes), so the vector stays small.
//
// The bundle (the recipe of tests/support/identity_certificate_record_553.mjs):
//   W=/Volumes/Lanes/out/bsv-rs/fix-730/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry730.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry730.ts --target node --format esm --outfile "$W/ref730.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_730.mjs \
//     "$W/ref730.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_730.json
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits: limits, Beef, LockingScript,
  UnlockingScript, Transaction, MerklePath, Utils, Hash
} = sdk
const record553 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const token = record553.cases[0].locking_script
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }
const another = '33'.repeat(32)

// One input spending `source` (a transaction, or a txid) at 0 with
// `unlocking`, one 1-satoshi output locked by `lock`.
const spending = (source, unlocking, lock) => {
  const tx = new Transaction()
  const input = typeof source === 'string' ? { sourceTXID: source } : { sourceTransaction: source }
  tx.addInput({
    ...input, sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlocking), sequence: 0xffffffff
  })
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
// An Atomic BEEF prefix naming `txid`, written by hand before `beef`'s
// bytes (`toBinaryAtomic` keeps the subject's graph alone).
const atomic = (txid, beef) => {
  const w = new Utils.Writer()
  w.writeUInt32LE(0x01010101)
  w.write(Utils.toArray(txid, 'hex').reverse())
  w.write(beef.toBinary())
  return w.toArray()
}

const grandparent = spending('22'.repeat(32), '51', '51')

// :149: two unproven parents spending the proven grandparent's output 0,
// the subject spending both.
const secondSpend = () => {
  const a = spending(grandparent, '51', '51')
  const b = spending(grandparent, '52', '51')
  const subject = new Transaction()
  for (const parent of [a, b]) {
    subject.addInput({
      sourceTransaction: parent, sourceOutputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff
    })
  }
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  beef.mergeRawTx(a.toBinary())
  beef.mergeRawTx(b.toBinary())
  proven(beef, grandparent, 900)
  return [beef.toBinary(), subject]
}
// :174: an unproven subject with no inputs.
const noInputs = () => {
  const subject = new Transaction()
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  return [beef.toBinary(), subject]
}
// limits.inputs: a proven subject of `n` inputs, each `11..11:i`.
const inputs = (n) => {
  const subject = new Transaction()
  for (let i = 0; i < n; i++) {
    subject.addInput({
      sourceTXID: '11'.repeat(32), sourceOutputIndex: i,
      unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff
    })
  }
  subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
  const beef = new Beef()
  proven(beef, subject, 900)
  return [beef.toBinary(), subject]
}
// limits.scriptBytes: a proven subject, the token and a padding output of
// `n` bytes pushed (the scripts `token + 5 + n` bytes, the unlocking empty).
const scriptBytes = (n) => {
  const subject = spending('11'.repeat(32), '', token)
  subject.addOutput({ satoshis: 0, lockingScript: padding(n) })
  const beef = new Beef()
  proven(beef, subject, 900)
  return [beef.toBinary(), subject]
}
// limits.transactions: `n` txid-only entries (`00..01` up) beside the
// proven subject, under an Atomic prefix naming the subject.
const transactions = (n) => {
  const subject = spending('11'.repeat(32), '', token)
  const beef = new Beef()
  for (let i = 1; i <= n; i++) beef.mergeTxidOnly(i.toString(16).padStart(64, '0'))
  proven(beef, subject, 900)
  return [atomic(subject.id('hex'), beef), subject]
}
// limits.candidateBytes: the proven subject beside a proven transaction
// outside its graph padded by `n` bytes, under an Atomic prefix naming the
// subject.
const candidateBytes = (n) => {
  const subject = spending('11'.repeat(32), '', token)
  const outside = spending('44'.repeat(32), '', '51')
  outside.addOutput({ satoshis: 0, lockingScript: padding(n) })
  const beef = new Beef()
  proven(beef, subject, 900)
  proven(beef, outside, 901)
  return [atomic(subject.id('hex'), beef), subject]
}
// A proven parent whose own parent is absent, the unproven subject spending it.
const provenParent = () => {
  const subject = spending(grandparent, '', token)
  const beef = new Beef()
  beef.mergeRawTx(subject.toBinary())
  proven(beef, grandparent, 900)
  return [beef.toBinary(), subject]
}
// #728's shape 4 with the grandparent present raw and proven by its own BUMP.
const anotherBumpGrandparentProven = () => {
  const parent = spending(grandparent, '', '51')
  const subject = spending(parent, '', token)
  const beef = new Beef()
  // The grandparent at 900, a lone leaf at offset 0 being a coinbase the
  // verifier's tracker (tip 1000) must see 100 blocks deep
  beef.mergeRawTx(parent.toBinary(), beef.mergeBump(loneLeaf(another, 901)))
  proven(beef, grandparent, 900)
  beef.mergeRawTx(subject.toBinary())
  return [beef.toBinary(), subject, parent]
}

// The smallest size whose builder's bytes reach `target`, by the length
// one size gives (each builder's length grows one byte per size step past
// its varints, so two corrections land it).
const sized = (build, target, start) => {
  let n = start
  for (let i = 0; i < 4; i++) {
    const length = build(n)[0].length
    if (length === target) return n
    n += target - length
  }
  throw new Error(`no size reaches ${target}`)
}

// The replayed refusal (`parseEvidence`'s own error carries no line):
// `parseEvidence`'s steps through the reference's public `Beef` methods.
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

// The `sourceTXID` probe: a raw parent whose locking script is each form,
// the index txid against its transaction's id.
const probe = ['4c05aa', '6a4c05aa', '0201'].map(lock => {
  const w = new Utils.Writer()
  w.writeUInt32LE(1)
  w.writeVarIntNum(1)
  w.write(Utils.toArray('22'.repeat(32), 'hex'))
  w.writeUInt32LE(0)
  w.writeVarIntNum(1)
  w.writeUInt8(0x51)
  w.writeUInt32LE(0xffffffff)
  w.writeVarIntNum(1)
  w.writeUInt64LE(1)
  const script = Utils.toArray(lock, 'hex')
  w.writeVarIntNum(script.length)
  w.write(script)
  w.writeUInt32LE(0)
  const raw = w.toArray()
  const beef = new Beef()
  beef.mergeRawTx(raw)
  const indexed = Beef.fromBinaryStrict(beef.toBinary()).txs[0]
  return {
    locking_script: lock,
    index_txid: indexed.txid,
    transaction_id: indexed.tx.id('hex'),
    raw_hash: Utils.toHex(Hash.hash256(raw).reverse())
  }
})

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

const tokenBytes = Utils.toArray(token, 'hex').length
const scriptBound = limits.scriptBytes - tokenBytes - 5
const candidateBound = sized(candidateBytes, limits.candidateBytes, 1000)

await add('second_spend_in_graph', 'a second spend of one outpoint, :149',
  'Beef.toBinary, merged the subject, both parents, the proven grandparent', secondSpend())
await add('unproven_no_inputs', 'an unproven transaction with no inputs, :174',
  'Beef.toBinary', noInputs())
await add('inputs_at_bound', 'limits.inputs, 4096, :170-171',
  'Beef.toBinary, the subject proven', inputs(limits.inputs), limits.inputs)
await add('inputs_over_bound', 'limits.inputs, 4096, :170-171',
  'Beef.toBinary, the subject proven', inputs(limits.inputs + 1), limits.inputs + 1)
await add('script_bytes_at_bound', 'limits.scriptBytes, 262144, :170-171',
  'Beef.toBinary, the subject proven, the token and an OP_PUSHDATA4 padding output', scriptBytes(scriptBound), scriptBound)
await add('script_bytes_over_bound', 'limits.scriptBytes, 262144, :170-171',
  'Beef.toBinary, the subject proven, the token and an OP_PUSHDATA4 padding output', scriptBytes(scriptBound + 1), scriptBound + 1)
await add('transactions_at_bound', 'limits.transactions, 256, :117',
  'an Atomic prefix naming the subject by hand, then Beef.toBinary of 255 txid-only entries and the proven subject',
  transactions(limits.transactions - 1), limits.transactions - 1)
await add('transactions_over_bound', 'limits.transactions, 256, :117',
  'an Atomic prefix naming the subject by hand, then Beef.toBinary of 256 txid-only entries and the proven subject',
  transactions(limits.transactions), limits.transactions)
await add('candidate_bytes_at_bound', 'limits.candidateBytes, 1048576, :101',
  'an Atomic prefix naming the subject by hand, then Beef.toBinary of the proven subject and a padded proven transaction outside its graph',
  candidateBytes(candidateBound), candidateBound)
await add('candidate_bytes_over_bound', 'limits.candidateBytes, 1048576, :101',
  'an Atomic prefix naming the subject by hand, then Beef.toBinary of the proven subject and a padded proven transaction outside its graph',
  candidateBytes(candidateBound + 1), candidateBound + 1)
await add('proven_parent_absent_grandparent', 'a proven transaction ends its branch, :173',
  'Beef.toBinary, merged the unproven subject, then its parent proven', provenParent())
const [anotherBytes, anotherSubject, anotherParent] = anotherBumpGrandparentProven()
await add('bump_names_another_txid_grandparent_proven',
  'the parent\'s BUMP names another txid, the grandparent proven by its own: no BUMP index read, :173',
  'Beef.toBinary, the parent merged with the index of a BUMP naming ' + another + ', the grandparent proven, the subject',
  [anotherBytes, anotherSubject])

process.stdout.write(JSON.stringify({
  description: '#730: the reference\'s parseEvidence on ls_identity lookup BEEFs (a second spend in the graph, ' +
    'an unproven transaction without inputs, the inputs, scriptBytes, transactions and candidateBytes limits at and ' +
    'over their bounds, a proven parent ending the walk, #728\'s shape 4 with its grandparent proven): the code, the ' +
    'line, the selected txid, and parseResults\' outcome; the sourceTXID check probed',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:61-77,93-201; ' +
    'packages/sdk/src/transaction/Beef.ts:570-574,639-680; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_730.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  limits: {
    candidate_bytes: limits.candidateBytes, transactions: limits.transactions,
    inputs: limits.inputs, script_bytes: limits.scriptBytes
  },
  another_txid: another,
  grandparent_txid: grandparent.id('hex'),
  another_parent_txid: anotherParent.id('hex'),
  source_txid_probe: {
    check: 'TransactionEvidence.ts:145-146, sourceTXID against the source\'s id',
    reached_from_bytes: probe.some(p => p.index_txid !== p.transaction_id),
    forms: probe
  },
  shapes
}, null, 2) + '\n')
