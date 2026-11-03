// #721: which transaction of an `ls_identity` lookup output's BEEF the
// reference's discovery reads the revelation token from. The toolbox's
// `IdentityEvidenceVerifier.parse` (`ts-stack@edf6e03`
// `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-612`)
// hands the output to `TransactionEvidenceCoordinator.verify`, whose
// `parseEvidence` loads `beef.atomicTxid ?? beef.txs.at(-1)?.txid` through
// `findAtomicTransaction` and checks `outputIndex` on that transaction
// (`packages/sdk/src/transaction/TransactionEvidence.ts:110-127,179-198`);
// `decodeIdentityOutput` (`identityUtils.ts:497-559`) reads the verified
// output's locking script. Each shape is the same two transactions: a
// proven parent (its BUMP a lone leaf at offset 0, output 0 `OP_TRUE`) and
// the subject spending it with an empty unlocking script, its output 0 the
// reference's own revelation token of #553's vector (cases[0]); `single` is
// the subject proven alone. The bytes are written by the reference's
// `Beef.toWriter` in the order held (no sort), an Atomic BEEF's prefix and
// subject before it, so a shape's order is the one named. Judged by
// `parseResults` under the toolbox wallet's verifier (the default evidence
// limits, a tracker admitting every root): 1 read, 0 skipped.
//
// The bundle is #553's recipe with `parseEvidence` exported beside it:
//   W=<lane folder>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry721.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry721.ts --target node --format esm --outfile "$W/ref721.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_beef_subject_721.mjs \
//     "$W/ref721.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_beef_subject_721.json
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits, Beef, LockingScript, UnlockingScript,
  Transaction, MerklePath, Utils
} = sdk
const record553 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const token = record553.cases[0].locking_script
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }

const parent = new Transaction()
parent.addInput({
  sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
  unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
})
parent.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
const parentPath = new MerklePath(900, [[{ offset: 0, hash: parent.id('hex'), txid: true }]])
parent.merklePath = parentPath

const subject = new Transaction()
subject.addInput({
  sourceTransaction: parent, sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff
})
subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })

const alone = new Transaction()
alone.addInput({
  sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
  unlockingScript: LockingScript.fromHex('51'), sequence: 0xffffffff
})
alone.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
const alonePath = new MerklePath(900, [[{ offset: 0, hash: alone.id('hex'), txid: true }]])

// The BEEF of `entries` ([raw, proven?]) in the order given, atomic for
// `atomic` when named.
const write = (bump, entries, atomic) => {
  const beef = new Beef()
  const index = beef.mergeBump(bump)
  for (const [tx, proven] of entries) beef.mergeRawTx(tx.toBinary(), proven ? index : undefined)
  const writer = new Utils.Writer()
  if (atomic !== undefined) {
    writer.writeUInt32LE(0x01010101)
    writer.write(Utils.toArray(atomic, 'hex').reverse())
  }
  beef.toWriter(writer)
  return writer.toArray()
}

const judged = async (beef) => {
  const lookup = { type: 'output-list', outputs: [{ beef, outputIndex: 0 }] }
  try {
    const read = await parseResults(lookup, tracker)
    return read.length === 1 ? 'read' : 'skipped'
  } catch (e) {
    return `refused: ${e.message}`
  }
}
const selected = (beef) => {
  try {
    return parseEvidence({ beef, outputIndex: 0 }, defaultTransactionEvidenceLimits).txid
  } catch (e) {
    return `refused: ${e.message}`
  }
}

const shapes = []
for (const [name, order, beef] of [
  ['single', 'the subject alone, proven', write(alonePath, [[alone, true]])],
  ['parent_first', 'parent then subject, the order TS 2 and TS 3 toBEEF write', write(parentPath, [[parent, true], [subject, false]])],
  ['atomic_parent_first', 'Atomic BEEF of the subject, parent then subject, the order toAtomicBEEF writes', write(parentPath, [[parent, true], [subject, false]], subject.id('hex'))],
  ['subject_first', 'subject then parent, no atomic header', write(parentPath, [[subject, false], [parent, true]])],
  ['atomic_subject_first', 'Atomic BEEF of the subject, subject then parent', write(parentPath, [[subject, false], [parent, true]], subject.id('hex'))]
]) {
  shapes.push({ name, order, beef: Utils.toHex(beef), selected_txid: selected(beef), outcome: await judged(beef) })
}

process.stdout.write(JSON.stringify({
  description: '#721: the transaction of an ls_identity output\'s BEEF the reference\'s discovery reads ' +
    'the token from (atomicTxid, else the last on the wire), with parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:110-127,179-198; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:497-559,600-612',
  node: process.version,
  recorder: 'tests/support/identity_beef_subject_721.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  parent_txid: parent.id('hex'),
  subject_txid: subject.id('hex'),
  single_txid: alone.id('hex'),
  shapes
}, null, 2) + '\n')
