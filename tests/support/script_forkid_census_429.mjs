// Re-judge #429's census rows with an unmodified, bundled SDK under Node 22.
// Arguments: SDK bundle, reference label, conformance directory, audit IDs JSON
// (or the checked-in script_forkid_census_429.json recording to replay its IDs).
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const { Spend, Transaction, LockingScript, UnlockingScript } =
  await import(pathToFileURL(process.argv[2]).href)
const corpus = JSON.parse(readFileSync(join(process.argv[4], 'vectors/sdk/scripts/evaluation.json')))
const audit = JSON.parse(readFileSync(process.argv[5]))
const ids = Array.isArray(audit) ? audit : audit.cases.map(c => c.id)

function parameters(input) {
  const lock = LockingScript.fromHex(input.script_pubkey_hex)
  const credit = new Transaction(1, [{
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0xffffffff,
    unlockingScript: new UnlockingScript([{ op: 0 }, { op: 0 }]), sequence: 0xffffffff
  }], [{ lockingScript: lock, satoshis: input.amount_satoshis }], 0)
  return {
    sourceTXID: credit.id('hex'), sourceOutputIndex: 0, sourceSatoshis: input.amount_satoshis,
    lockingScript: lock, transactionVersion: input.tx_version, otherInputs: [],
    outputs: [{ lockingScript: new LockingScript(), satoshis: input.amount_satoshis }],
    inputIndex: 0, unlockingScript: UnlockingScript.fromHex(input.script_sig_hex),
    inputSequence: 0xffffffff, lockTime: 0
  }
}

function evaluate(params, flags) {
  try {
    for (const p of params) {
      const spend = new Spend({ ...p, ...(flags === undefined ? {} : { verifyFlags: flags }) })
      if (!spend.validate()) return { valid: false }
    }
    return { valid: true }
  } catch (e) {
    return { error: e.message.split('\n')[0] }
  }
}

function transactionParameters(input) {
  const tx = Transaction.fromHex(input.tx_hex)
  return tx.inputs.map((vin, i) => {
    const prevout = input.prevouts.find(p => p.txid === vin.sourceTXID && p.vout === vin.sourceOutputIndex)
    if (!prevout) throw new Error(`Missing prevout for input ${i}`)
    return {
      sourceTXID: vin.sourceTXID, sourceOutputIndex: vin.sourceOutputIndex,
      sourceSatoshis: prevout.amount_satoshis,
      lockingScript: LockingScript.fromHex(prevout.script_pubkey_hex),
      transactionVersion: tx.version, otherInputs: tx.inputs.filter((_, n) => n !== i),
      outputs: tx.outputs, inputIndex: i, unlockingScript: vin.unlockingScript,
      inputSequence: vin.sequence ?? 0xffffffff, lockTime: tx.lockTime
    }
  })
}

const cases = ids.map(id => {
  const vector = corpus.vectors.find(v => v.id === id)
  if (!vector) throw new Error(`Missing row: ${id}`)
  const isScript = vector.input.fixture_type === 'node-script'
  const params = isScript ? [parameters(vector.input)] : transactionParameters(vector.input)
  const words = isScript ? [vector.input.flags] : vector.input.flag_sets
  return {
    id, expected: vector.expected, default: evaluate(params),
    words: words.map(flags => ({ flags, ...evaluate(params, flags) }))
  }
})
console.log(JSON.stringify({ reference: process.argv[3], node: process.version, cases }, null, 2))
