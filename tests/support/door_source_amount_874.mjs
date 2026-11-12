// Record #874's "Beside it": the reference's default `Spend` on a P2PKH spend
// whose source amount is 2^53 - 1, 2^53, 2^63 and 2^64 - 1, at versions 1 and
// 2. The cells are this crate's writer's (`record_the_cells_874` in
// tests/verify_input_door_source_amount_874.rs prints them).
// Build the unmodified reference in scratch space, then run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/door_source_amount_874.mjs \
//     "$W/sdk.mjs" cells.json > tests/vectors/door_source_amount_874.json
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const { Spend, Transaction, LockingScript } =
  await import(pathToFileURL(process.argv[2]).href)
const cells = JSON.parse(readFileSync(process.argv[3], 'utf8'))

function run(cell) {
  const tx = Transaction.fromHex(cell.tx)
  const input = tx.inputs[0]
  // The reference's `sourceSatoshis` is a JavaScript number: the decimal
  // text read by `Number`, 2^64 - 1 rounded to 2^64.
  const sourceSatoshis = Number(cell.amount)
  const spend = new Spend({
    sourceTXID: input.sourceTXID,
    sourceOutputIndex: input.sourceOutputIndex,
    sourceSatoshis,
    lockingScript: LockingScript.fromHex(cell.lock),
    transactionVersion: tx.version,
    otherInputs: [],
    outputs: tx.outputs,
    inputIndex: 0,
    unlockingScript: input.unlockingScript,
    inputSequence: input.sequence,
    lockTime: tx.lockTime
  })
  try {
    return { valid: spend.validate() }
  } catch (error) {
    return { error: error.message.split('\n')[0] }
  }
}

const cases = cells.map(cell => ({
  ...cell,
  source_satoshis_as_number: Number(cell.amount).toString(),
  reference_default: run(cell)
}))
process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk, bundled by bun, Node v22.18.0',
  note: 'Spend without verifyFlags (the default mode) on each cell; the cells are bsv-rs writer bytes',
  cases
}, null, 2) + '\n')
