// #660: the witnesses beside this crate's cells. The cells (point, shape,
// unlock, lock, mode, version, the node's derived verdict) are this crate's
// writer's, from the ignored Rust recorder:
//   PUBKEY_ENCODING_660_CELLS="$OUT/cells.json" cargo test --test pubkey_encoding_660 \
//     -- --ignored record_the_cells_660
// Build the unmodified reference from its clone and record under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pubkey_encoding_660.mjs \
//     "$W/sdk.mjs" "$OUT/cells.json" ~/bsv/bsv-script-lean > tests/vectors/pubkey_encoding_660.json
// The reference's `Spend` runs each default-mode cell (no verifyFlags, the
// reference's default). The sibling's Lean evaluator (`eval/bsvs eval`, the
// node's rules at bitcoin-sv v1.2.3) runs each cell under a word: `block` is
// `--consensus true`, `standard` `--consensus false`; the post-Genesis cells
// spend at 900000 a coin of 800000, the post-Chronicle cells at 967896 a coin
// of 950000, each run's eras checked against the cell's.
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'

const { Spend, LockingScript, UnlockingScript } = await import(pathToFileURL(process.argv[2]).href)
const cells = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const lean = process.argv[4]

function reference (c) {
  const spend = new Spend({
    sourceTXID: '07'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1000,
    transactionVersion: c.version, otherInputs: [], outputs: [], inputIndex: 0,
    inputSequence: 0xffffffff, lockTime: 0,
    lockingScript: LockingScript.fromHex(c.lock),
    unlockingScript: UnlockingScript.fromHex(c.unlock)
  })
  try {
    return { referenceValid: spend.validate(), referenceError: null }
  } catch (error) {
    return { referenceValid: null, referenceError: error.message.split('\n')[0] }
  }
}

const le32 = n => {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(n >>> 0)
  return b.toString('hex')
}
const varint = n => {
  if (n >= 0xfd) throw new Error('a short script only')
  return n.toString(16).padStart(2, '0')
}

function leanRun (c) {
  const tx = le32(c.version) + '01' + '07'.repeat(32) + le32(0) +
    varint(c.unlock.length / 2) + c.unlock + 'ffffffff' +
    '01' + 'e803000000000000' + '0151' + le32(0)
  const chronicle = c.mode.endsWith('post-chronicle')
  const prevouts = JSON.stringify([{
    txid: '07'.repeat(32), vout: 0, script: c.lock, satoshis: 1000,
    height: chronicle ? 950000 : 800000
  }])
  const r = spawnSync('eval/bsvs', ['eval', '--tx', tx, '--prevouts', prevouts,
    '--spend-height', chronicle ? '967896' : '900000',
    '--consensus', c.mode.startsWith('block') ? 'true' : 'false'], { cwd: lean, encoding: 'utf8' })
  const o = JSON.parse(r.stdout)
  const input = o.inputs[0]
  const era = chronicle ? 'post-chronicle' : 'post-genesis'
  if (input.params.era !== era || input.params.utxo_era !== era) {
    throw new Error(`era ${input.params.era}/${input.params.utxo_era} for ${c.mode}`)
  }
  return { spec: o.spec, lean: o.verdict, leanError: input.code ?? null }
}

let spec = null
const out = cells.map(c => {
  const row = { ...c, lean: null, leanError: null, referenceValid: null, referenceError: null }
  if (c.mode === 'default') return { ...row, ...reference(c) }
  const l = leanRun(c)
  if (spec !== null && spec !== l.spec) throw new Error(`spec ${l.spec} after ${spec}`)
  spec = l.spec
  return { ...row, lean: l.lean, leanError: l.leanError }
})

console.log(JSON.stringify({
  reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version,
  spec,
  cells: out
}, null, 2))
