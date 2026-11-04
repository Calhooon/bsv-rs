// #725: three BEEF shapes of an `ls_identity` lookup output that the #721
// vector leaves, against the reference's `parseEvidence`
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`):
// `loadEvidenceTransaction` picks `beef.atomicTxid ?? beef.txs.at(-1)?.txid`
// and loads it through `findAtomicTransaction` (`:110-127`), then
// `assertUnconfirmedGraph` walks the unconfirmed graph and refuses an input
// whose source transaction is absent (`:143`, `:155-177`). Each shape is
// judged by `parseResults` under the toolbox wallet's verifier (the default
// evidence limits, a tracker admitting every root), as in #721's recorder
// (`tests/support/identity_beef_subject_721.mjs`, whose vector this file
// leaves untouched).
//
// The shapes:
// - `absent_atomic_txid`: the token's transaction alone, proven, after an
//   Atomic BEEF prefix naming a txid absent from the entries (written in the
//   order held: `toBinaryAtomic` refuses an absent subject);
// - `txid_only_parent` and `txid_only_parent_atomic`: a txid-only parent
//   (proven by its BUMP) and the raw unproven subject spending it, written
//   by the reference's sorting writers (`Beef.toBinary`, `toBinaryAtomic`);
// - `chain` and `chain_atomic`: a proven grandparent, an unproven parent and
//   the unproven subject, merged subject first and written by the same two
//   writers, whose sort puts the grandparent first and the subject last.
//
// The bundle is #721's recipe:
//   W=/Volumes/Lanes/out/bsv-rs/fix-725/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry725.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry725.ts --target node --format esm --outfile "$W/ref725.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_beef_subject_725.mjs \
//     "$W/ref725.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_beef_subject_725.json
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
const absent = '22'.repeat(32)

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
const loneLeaf = (tx) => new MerklePath(900, [[{ offset: 0, hash: tx.id('hex'), txid: true }]])

const alone = spending('11'.repeat(32), '51', token)
const parent = spending('11'.repeat(32), '51', '51')
const subject = spending(parent, '', token)
// The chain's grandparent is the parent of the other shapes (and of #721's).
const grandparent = parent
const middle = spending(grandparent, '', '51')
const tip = spending(middle, '', token)

const held = () => {
  const beef = new Beef()
  const index = beef.mergeBump(loneLeaf(alone))
  beef.mergeRawTx(alone.toBinary(), index)
  const writer = new Utils.Writer()
  writer.writeUInt32LE(0x01010101)
  writer.write(Utils.toArray(absent, 'hex').reverse())
  beef.toWriter(writer)
  return writer.toArray()
}
const txidOnly = () => {
  const beef = new Beef()
  beef.mergeBump(loneLeaf(parent))
  beef.mergeTxidOnly(parent.id('hex'))
  beef.mergeRawTx(subject.toBinary())
  return beef
}
const chain = () => {
  const beef = new Beef()
  beef.mergeRawTx(tip.toBinary())
  beef.mergeRawTx(middle.toBinary())
  beef.mergeRawTx(grandparent.toBinary(), beef.mergeBump(loneLeaf(grandparent)))
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
  `${names[btx.txid] ?? btx.txid}${btx.isTxidOnly ? ' (txid only)' : ''}`)

// Which check refused, replayed through the reference's public `Beef`
// methods (`parseEvidence`'s own error carries no reason): the target
// `findAtomicTransaction` does not find (`:118-121`), or an input of the
// unconfirmed graph without its source transaction (`:143`).
const reason = (bytes) => {
  const beef = Beef.fromBinaryStrict(bytes)
  const target = beef.atomicTxid ?? beef.txs.at(-1)?.txid
  const tx = beef.findAtomicTransaction(target)
  if (tx === undefined) return `TransactionEvidence.ts:120-121: findAtomicTransaction(${target}) is undefined`
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
for (const [name, writer, beef] of [
  ['absent_atomic_txid', 'Beef.toWriter after an Atomic BEEF prefix naming ' + absent + ', the order held', held()],
  ['txid_only_parent', 'Beef.toBinary', txidOnly().toBinary()],
  ['txid_only_parent_atomic', 'Beef.toBinaryAtomic(subject)', txidOnly().toBinaryAtomic(subject.id('hex'))],
  ['chain', 'Beef.toBinary, merged tip, middle, grandparent', chain().toBinary()],
  ['chain_atomic', 'Beef.toBinaryAtomic(tip), merged tip, middle, grandparent', chain().toBinaryAtomic(tip.id('hex'))]
]) {
  shapes.push({
    name, writer, wire_order: wireOrder(beef), beef: Utils.toHex(beef),
    selected_txid: selected(beef), refused_at: reason(beef), outcome: await judged(beef)
  })
}

process.stdout.write(JSON.stringify({
  description: '#725: three BEEF shapes of an ls_identity output (an absent atomic txid, a txid-only parent ' +
    'before a raw unproven subject, a three-transaction chain): parseEvidence\'s selected txid or refusal, ' +
    'with parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:110-127,143,155-198; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:497-559,600-612',
  node: process.version,
  recorder: 'tests/support/identity_beef_subject_725.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  absent_txid: absent,
  alone_txid: alone.id('hex'),
  parent_txid: parent.id('hex'),
  grandparent_txid: grandparent.id('hex'),
  subject_txid: subject.id('hex'),
  middle_txid: middle.id('hex'),
  tip_txid: tip.id('hex'),
  shapes
}, null, 2) + '\n')
