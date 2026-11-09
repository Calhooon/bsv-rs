// #731: an Atomic BEEF whose subject X is written twice, a raw entry and a
// txid-only entry, in both orders, against the reference's `parseEvidence`
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`):
// `Beef.fromBinaryStrict` keeps every entry in the order written
// (`Beef.ts:1263-1265`) and the atomic txid (`:1245-1247`, `:1267`); the
// target is `beef.atomicTxid` (`TransactionEvidence.ts:118`); the index
// `#rebuildTxIndexes` builds by `Map.set` in order holds the later entry of
// a txid (`Beef.ts:516-524`), so `findAtomicTransaction(X)` (`:639-645`)
// answers `undefined` when the txid-only entry is later (`invalid-evidence`
// at `TransactionEvidence.ts:120-121`, the toolbox's verifier skipping the
// output) and the transaction when the raw entry is later (read). Each shape
// is judged by `parseResults` under the toolbox wallet's verifier (the
// default evidence limits, a tracker admitting every root), as in #728's
// recorder (`tests/support/identity_beef_subject_728.mjs`, whose helpers
// this file copies and whose vector it leaves untouched).
//
// Over #725's transactions (`alone` proven at 900; `parent` proven at 900
// and the unproven `subject` spending it), four shapes, each an Atomic BEEF
// prefix naming X (`0x01010101`, X's txid reversed) written by hand before
// `Beef.toWriter` over `txs` set by hand (`mergeRawTx` and `mergeTxidOnly`
// deduplicate, so no merge writes both entries; #736's `parentTwice`):
// - `proven_subject_raw_then_txid_only`: BUMP(alone, 900);
//   `[BeefTx.fromTx(alone, 0), BeefTx.fromTxid(alone)]`;
// - `proven_subject_txid_only_then_raw`: the two entries swapped;
// - `unproven_subject_raw_then_txid_only`: BUMP(parent, 900);
//   `[fromTx(parent, 0), fromTx(subject), fromTxid(subject)]`;
// - `unproven_subject_txid_only_then_raw`: the subject's entries swapped.
//
// The bundle (#728's recipe):
//   W=/Volumes/Lanes/out/bsv-rs/fix-731/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry731.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry731.ts --target node --format esm --outfile "$W/ref731.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_731.mjs \
//     "$W/ref731.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_731.json
import { readFileSync } from 'fs'
import { createHash } from 'crypto'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits, Beef, BeefTx, LockingScript,
  UnlockingScript, Transaction, MerklePath, Utils
} = sdk
const record553 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const token = record553.cases[0].locking_script
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }

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

// An Atomic BEEF prefix naming `x` by hand, then `Beef.toWriter` over the
// entries `entries(bumpIndex)` given, the BUMP `proven`'s lone leaf at 900.
const atomicTwice = (x, proven, entries) => {
  const beef = new Beef()
  const bumpIndex = beef.mergeBump(loneLeaf(proven.id('hex'), 900))
  beef.txs = entries(bumpIndex)
  const writer = new Utils.Writer()
  writer.writeUInt32LE(0x01010101)
  writer.write(Utils.toArray(x.id('hex'), 'hex').reverse())
  beef.toWriter(writer)
  return writer.toArray()
}

const names = {
  [alone.id('hex')]: 'alone',
  [parent.id('hex')]: 'parent',
  [subject.id('hex')]: 'subject'
}
const wireOrder = (bytes) => Beef.fromBinary(bytes).txs.map(btx =>
  `${names[btx.txid] ?? btx.txid}${btx.isTxidOnly ? ' (txid only)' : ''}` +
  `${btx.bumpIndex !== undefined ? ` (BUMP ${btx.bumpIndex})` : ''}`)

// #728's replay of the refusal (`parseEvidence`'s own error carries no
// reason): the target `findAtomicTransaction` does not find (`:118-121`),
// an output index past its outputs (`:126`), or an input of the unconfirmed
// graph without its source transaction (`:143`).
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
for (const [name, x, writer, beef] of [
  ['proven_subject_raw_then_txid_only', alone,
    'an Atomic prefix naming alone, then Beef.toWriter over [fromTx(alone, 0), fromTxid(alone)], BUMP(alone, 900)',
    atomicTwice(alone, alone, (b) => [BeefTx.fromTx(alone, b), BeefTx.fromTxid(alone.id('hex'))])],
  ['proven_subject_txid_only_then_raw', alone,
    'an Atomic prefix naming alone, then Beef.toWriter over [fromTxid(alone), fromTx(alone, 0)], BUMP(alone, 900)',
    atomicTwice(alone, alone, (b) => [BeefTx.fromTxid(alone.id('hex')), BeefTx.fromTx(alone, b)])],
  ['unproven_subject_raw_then_txid_only', subject,
    'an Atomic prefix naming subject, then Beef.toWriter over [fromTx(parent, 0), fromTx(subject), fromTxid(subject)], BUMP(parent, 900)',
    atomicTwice(subject, parent, (b) => [BeefTx.fromTx(parent, b), BeefTx.fromTx(subject), BeefTx.fromTxid(subject.id('hex'))])],
  ['unproven_subject_txid_only_then_raw', subject,
    'an Atomic prefix naming subject, then Beef.toWriter over [fromTx(parent, 0), fromTxid(subject), fromTx(subject)], BUMP(parent, 900)',
    atomicTwice(subject, parent, (b) => [BeefTx.fromTx(parent, b), BeefTx.fromTxid(subject.id('hex')), BeefTx.fromTx(subject)])]
]) {
  const xTxid = x.id('hex')
  shapes.push({
    name, writer, subject_txid: xTxid, output_index: 0, wire_order: wireOrder(beef),
    index_entry: Beef.fromBinaryStrict(beef).findTxid(xTxid).isTxidOnly ? 'txid only' : 'raw',
    beef_bytes: beef.length,
    beef_sha256: createHash('sha256').update(Buffer.from(beef)).digest('hex'),
    beef: Utils.toHex(beef),
    selected_txid: selected(beef, 0), refused_at: reason(beef, 0),
    outcome: await judged(beef, 0)
  })
}

process.stdout.write(JSON.stringify({
  description: '#731: an Atomic BEEF whose subject is written twice (raw and txid-only, in both orders; ' +
    'proven and unproven): the entry the index holds, parseEvidence\'s selected txid or refusal, with ' +
    'parseResults\' outcome',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:116-126; ' +
    'packages/sdk/src/transaction/Beef.ts:497-500,516-524,639-645,1169-1180,1245-1267; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_731.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  alone_txid: alone.id('hex'),
  parent_txid: parent.id('hex'),
  subject_txid: subject.id('hex'),
  shapes
}, null, 2) + '\n')
