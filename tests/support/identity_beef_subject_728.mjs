// #728: four BEEF shapes of an `ls_identity` lookup output that the #721 and
// #725 vectors leave, against the reference's `parseEvidence`
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`):
// `loadEvidenceTransaction` picks `beef.atomicTxid ?? beef.txs.at(-1)?.txid`,
// loads it through `findAtomicTransaction` (undefined for a txid-only entry,
// `:120-121`) and refuses an `outputIndex` past its outputs (`:126`), then
// `assertUnconfirmedGraph` walks the unconfirmed graph and refuses an input
// whose source transaction is absent (`:143`, `:155-177`). Each shape is
// judged by `parseResults` under the toolbox wallet's verifier (the default
// evidence limits, a tracker admitting every root), as in #725's recorder
// (`tests/support/identity_beef_subject_725.mjs`, whose helpers this file
// copies and whose vector it leaves untouched).
//
// The shapes:
// - `output_index_past_outputs`: #725's `chain` bytes (a proven grandparent,
//   an unproven parent and the one-output subject, `Beef.toBinary`) served
//   with `outputIndex` 1;
// - `txid_only_last`: the token's transaction, proven, then a txid-only
//   entry (proven by its own BUMP at another height), no atomic header,
//   written by `Beef.toBinary`, whose sort keeps the txid-only entry last;
// - `atomic_txid_only_subject`: the same BEEF written by
//   `Beef.toBinaryAtomic(txid-only entry)`, which keeps the subject alone;
// - `atomic_txid_only_subject_beside_token`: an Atomic BEEF prefix naming
//   the txid-only entry written by hand before `txid_only_last`'s bytes
//   (`toBinaryAtomic` drops the token's transaction, outside the subject's
//   graph), so the token's transaction is the entry a wrong pick would read;
// - `bump_names_another_txid`: a raw parent merged with the index of a BUMP
//   whose one leaf names another txid, and the raw unproven subject spending
//   it, written by `Beef.toBinary` (`mergeRawTx` keeps an explicit index).
//
// The bundle is #725's recipe:
//   W=/Volumes/Lanes/out/bsv-rs/fix-728/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry728.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry728.ts --target node --format esm --outfile "$W/ref728.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_beef_subject_728.mjs \
//     "$W/ref728.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_beef_subject_728.json
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

// #725's transactions.
const alone = spending('11'.repeat(32), '51', token)
const parent = spending('11'.repeat(32), '51', '51')
const subject = spending(parent, '', token)
const grandparent = parent
const middle = spending(grandparent, '', '51')
const tip = spending(middle, '', token)

const chain = () => {
  const beef = new Beef()
  beef.mergeRawTx(tip.toBinary())
  beef.mergeRawTx(middle.toBinary())
  beef.mergeRawTx(grandparent.toBinary(), beef.mergeBump(loneLeaf(grandparent.id('hex'), 900)))
  return beef
}
const txidOnlyLast = () => {
  const beef = new Beef()
  beef.mergeRawTx(alone.toBinary(), beef.mergeBump(loneLeaf(alone.id('hex'), 900)))
  beef.mergeBump(loneLeaf(parent.id('hex'), 901))
  beef.mergeTxidOnly(parent.id('hex'))
  return beef
}
const besideToken = () => {
  const writer = new Utils.Writer()
  writer.writeUInt32LE(0x01010101)
  writer.write(Utils.toArray(parent.id('hex'), 'hex').reverse())
  writer.write(txidOnlyLast().toBinary())
  return writer.toArray()
}
const anotherBump = () => {
  const beef = new Beef()
  beef.mergeRawTx(parent.toBinary(), beef.mergeBump(loneLeaf(another, 900)))
  beef.mergeRawTx(subject.toBinary())
  return beef
}

const names = {
  [alone.id('hex')]: 'alone',
  [parent.id('hex')]: 'parent',  // the chain's grandparent
  [subject.id('hex')]: 'subject',
  [middle.id('hex')]: 'middle',
  [tip.id('hex')]: 'tip'
}
const wireOrder = (bytes) => Beef.fromBinary(bytes).txs.map(btx =>
  `${names[btx.txid] ?? btx.txid}${btx.isTxidOnly ? ' (txid only)' : ''}` +
  `${btx.bumpIndex !== undefined ? ` (BUMP ${btx.bumpIndex})` : ''}`)

// Which check refused, replayed through the reference's public `Beef`
// methods (`parseEvidence`'s own error carries no reason): the target
// `findAtomicTransaction` does not find (`:118-121`), an output index past
// its outputs (`:126`), or an input of the unconfirmed graph without its
// source transaction (`:143`).
const reason = (bytes, outputIndex) => {
  const beef = Beef.fromBinaryStrict(bytes)
  const target = beef.atomicTxid ?? beef.txs.at(-1)?.txid
  const tx = beef.findAtomicTransaction(target)
  if (tx === undefined) return `TransactionEvidence.ts:120-121: findAtomicTransaction(${target}) is undefined`
  if (outputIndex >= tx.outputs.length) {
    return `TransactionEvidence.ts:126: ${tx.id('hex')} has ${tx.outputs.length} outputs, outputIndex ${outputIndex}`
  }
  const pending = [tx]
  while (pending.length > 0) {
    const current = pending.pop()
    if (current.merklePath != null) continue
    for (const input of current.inputs) {
      if (input.sourceTransaction == null) {
        return `TransactionEvidence.ts:143: ${current.id('hex')} input ${input.sourceTXID}.${input.sourceOutputIndex} has no source transaction`
      }
      pending.push(input.sourceTransaction)
    }
  }
  return null
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
const selected = (beef, outputIndex) => {
  try {
    return parseEvidence({ beef, outputIndex }, defaultTransactionEvidenceLimits).txid
  } catch (e) {
    return `refused: ${e.message}`
  }
}

const shapes = []
for (const [name, writer, beef, outputIndex] of [
  ['output_index_past_outputs', 'Beef.toBinary, merged tip, middle, grandparent (#725\'s chain)', chain().toBinary(), 1],
  ['txid_only_last', 'Beef.toBinary, merged the token\'s transaction then the txid-only entry', txidOnlyLast().toBinary(), 0],
  ['atomic_txid_only_subject', 'Beef.toBinaryAtomic(the txid-only entry)', txidOnlyLast().toBinaryAtomic(parent.id('hex')), 0],
  ['atomic_txid_only_subject_beside_token', 'an Atomic BEEF prefix naming the txid-only entry by hand, then txid_only_last\'s Beef.toBinary', besideToken(), 0],
  ['bump_names_another_txid', 'Beef.toBinary, the parent merged with the index of a BUMP naming ' + another, anotherBump().toBinary(), 0]
]) {
  shapes.push({
    name, writer, output_index: outputIndex, wire_order: wireOrder(beef), beef: Utils.toHex(beef),
    selected_txid: selected(beef, outputIndex), refused_at: reason(beef, outputIndex),
    outcome: await judged(beef, outputIndex)
  })
}

process.stdout.write(JSON.stringify({
  description: '#728: four BEEF shapes of an ls_identity output (an outputIndex past the subject\'s outputs, ' +
    'a txid-only entry last, an atomic header naming a txid-only entry, a parent\'s BUMP naming another txid): ' +
    'parseEvidence\'s selected txid or refusal, with parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:110-128,143,155-198; ' +
    'packages/sdk/src/transaction/Beef.ts:570-574,639-664; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:497-559,600-612',
  node: process.version,
  recorder: 'tests/support/identity_beef_subject_728.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  another_txid: another,
  alone_txid: alone.id('hex'),
  parent_txid: parent.id('hex'),
  subject_txid: subject.id('hex'),
  middle_txid: middle.id('hex'),
  tip_txid: tip.id('hex'),
  shapes
}, null, 2) + '\n')
