// #818: the transactions bound of the reference's `parseEvidence` counts the
// BEEF's ENTRIES, a repeated txid counted each time it is written
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts:116-117`:
// `const beef = Beef.fromBinaryStrict(bytes)`,
// `if (beef.txs.length > limits.transactions) throw new TransactionEvidenceError('limit')`;
// `Beef.fromBinaryStrict` keeps every entry in the order written,
// `Beef.ts:1263-1265`). #730's `transactions_at_bound` and
// `transactions_over_bound` hold distinct txids alone, so a count of distinct
// txids passed them. Two shapes, each an Atomic BEEF prefix naming the proven
// subject (`0x01010101`, its txid reversed) written by hand before
// `Beef.toWriter` over `txs` set by hand (`mergeTxidOnly` deduplicates, so no
// merge writes a txid twice; #731's writer): `n` txid-only entries (`00..01`
// up), the entry `00..01` again, then the subject raw with its BUMP (a lone
// leaf at 900):
// - `repeat_at_bound`: n = 254, 255 distinct txids in 256 entries, read;
// - `repeat_over_bound`: n = 255, 256 distinct txids in 257 entries, `limit`
//   at `:117`.
//
// The bundle is tests/support/identity_evidence_731.mjs's (`ref731.mjs`,
// #728's recipe with `parseEvidence` exported):
//   W=<lane folder>/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry731.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry731.ts --target node --format esm --outfile "$W/ref731.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_818.mjs \
//     "$W/ref731.mjs" tests/vectors/identity_certificate_record_553.json \
//     > tests/vectors/identity_evidence_818.json
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

// #730's subject: `11..11:0` spent with an empty script, one 1-satoshi
// output locked by the reference's revelation token.
const subject = new Transaction()
subject.addInput({
  sourceTXID: '11'.repeat(32), sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex(''), sequence: 0xffffffff
})
subject.addOutput({ satoshis: 1, lockingScript: LockingScript.fromHex(token) })
const subjectTxid = subject.id('hex')
const filler = (i) => i.toString(16).padStart(64, '0')

const repeated = (n) => {
  const beef = new Beef()
  const bumpIndex = beef.mergeBump(new MerklePath(900, [[{ offset: 0, hash: subjectTxid, txid: true }]]))
  const entries = []
  for (let i = 1; i <= n; i++) entries.push(BeefTx.fromTxid(filler(i)))
  entries.push(BeefTx.fromTxid(filler(1)))
  entries.push(BeefTx.fromTx(subject, bumpIndex))
  beef.txs = entries
  const writer = new Utils.Writer()
  writer.writeUInt32LE(0x01010101)
  writer.write(Utils.toArray(subjectTxid, 'hex').reverse())
  beef.toWriter(writer)
  return writer.toArray()
}

// The replayed refusal (`parseEvidence`'s own error carries no line).
const replay = (bytes) => {
  const beef = Beef.fromBinaryStrict(bytes)
  if (beef.txs.length > limits.transactions) return `TransactionEvidence.ts:117: ${beef.txs.length} transactions`
  return null
}
const selected = (beef) => {
  try {
    return parseEvidence({ beef, outputIndex: 0 }, limits)
  } catch (e) {
    return e
  }
}
const judged = async (beef) => {
  try {
    const read = await parseResults({ type: 'output-list', outputs: [{ beef, outputIndex: 0 }] }, tracker)
    return read.length === 1 ? 'read' : 'skipped'
  } catch (e) {
    return `refused: ${e.message}`
  }
}

const shapes = []
for (const [name, n] of [['repeat_at_bound', limits.transactions - 2], ['repeat_over_bound', limits.transactions - 1]]) {
  const beef = repeated(n)
  const read = Beef.fromBinaryStrict(beef)
  const answer = selected(beef)
  const refusedAt = replay(beef)
  shapes.push({
    name,
    writer: `an Atomic prefix naming the subject by hand, then Beef.toWriter over ${n} txid-only entries, ` +
      'the txid-only entry 00..01 again and the proven subject',
    size: n,
    entries: read.txs.length,
    distinct_txids: new Set(read.txs.map(btx => btx.txid)).size,
    repeated_txid: filler(1),
    output_index: 0,
    subject_txid: subjectTxid,
    beef_bytes: beef.length,
    beef_sha256: createHash('sha256').update(Buffer.from(beef)).digest('hex'),
    selected_txid: answer instanceof Error ? `refused: ${answer.message}` : answer.txid,
    code: answer instanceof Error ? answer.code : null,
    site: refusedAt === null ? null : refusedAt.split(': ')[0],
    refused_at: refusedAt,
    outcome: await judged(beef)
  })
}

process.stdout.write(JSON.stringify({
  description: '#818: an Atomic BEEF holding one txid-only entry twice, at and over the transactions bound: ' +
    'parseEvidence counts entries (beef.txs.length), so 255 distinct txids in 256 entries are read and ' +
    '256 distinct txids in 257 entries are a limit',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/TransactionEvidence.ts:116-117; ' +
    'packages/sdk/src/transaction/Beef.ts:1263-1265; ' +
    'packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634,671-707',
  node: process.version,
  recorder: 'tests/support/identity_evidence_818.mjs',
  token_from: 'tests/vectors/identity_certificate_record_553.json cases[0].locking_script',
  limits: { transactions: limits.transactions },
  shapes
}, null, 2) + '\n')
