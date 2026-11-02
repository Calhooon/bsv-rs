// #654: the scriptCode of a signature check, recorded three ways.
// Node 22.18.0; arguments: an unmodified ts-stack@edf6e03 SDK bundle
// (`git archive edf6e03 packages/sdk`, `bun build mod.ts --target node --format esm`),
// the cases file this crate's ignored recorder writes
// (`SIGHASH_SCRIPTCODE_654_OUT=<file> cargo test --test sighash_scriptcode_654 record -- --ignored`),
// the sibling's Lean evaluator (`bsv-script-lean@387dab35`, `lake build bsvs` in a
// scratch copy of its `lean/`). Writes tests/vectors/sighash_scriptcode_654.json to stdout.
// Every case runs in the reference's default `Spend` (no flags) and in the
// evaluator under each word of this crate's modes (`eval --flags <word>`, the
// block words on the block path, the standard words on the mempool path); the
// evaluator's `sighash` digests each of the case's three scriptCodes. Never hand-edited.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node, '22.18.0')
const [sdkPath, casesPath, bsvs] = process.argv.slice(2)
const { Spend, LockingScript, UnlockingScript } = await import(pathToFileURL(sdkPath).href)
const recording = JSON.parse(readFileSync(casesPath, 'utf8'))
const TXID = '5a'.repeat(32)

function tsDefault (c) {
  const spend = new Spend({
    sourceTXID: TXID,
    sourceOutputIndex: 0,
    sourceSatoshis: 10000,
    lockingScript: LockingScript.fromHex(c.lock),
    transactionVersion: c.version,
    otherInputs: [],
    outputs: [{ satoshis: 9000, lockingScript: LockingScript.fromHex('51') }],
    inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(c.unlock),
    inputSequence: 0xffffffff,
    lockTime: 0
  })
  try {
    return `Ok(${spend.validate()})`
  } catch (e) {
    return `Err(${e.message.split('\n')[0]})`
  }
}

function lean (args) {
  return execFileSync(bsvs, args, { encoding: 'utf8' }).trim()
}

const prevouts = c => JSON.stringify([{ txid: TXID, vout: 0, script: c.lock, satoshis: 10000, height: 967000 }])

const cases = recording.cases.map(c => {
  const leanVerdicts = {}
  const leanCodes = {}
  for (const [mode, word] of Object.entries(recording.words)) {
    const consensus = mode.startsWith('block') ? 'true' : 'false'
    const out = JSON.parse(lean(['eval', '--tx', c.tx, '--prevouts', prevouts(c), '--flags', String(word), '--consensus', consensus]))
    leanVerdicts[mode] = String(out.verdict === 'valid')
    leanCodes[mode] = out.code
  }
  const sighash = code => lean(['sighash', '--tx', c.tx, '--scriptcode', code, '--type', String(c.scope), '--amount', '10000'])
  return {
    name: c.name,
    version: c.version,
    lock: c.lock,
    unlock: c.unlock,
    scope: c.scope,
    signed_over: c.signed_over,
    script_code_chronicle: c.script_code_chronicle,
    script_code_pre_chronicle: c.script_code_pre_chronicle,
    script_code_before_654: c.script_code_before_654,
    lean_sighash: {
      chronicle: sighash(c.script_code_chronicle),
      pre_chronicle: sighash(c.script_code_pre_chronicle),
      before_654: sighash(c.script_code_before_654)
    },
    tx: c.tx,
    rust: c.rust,
    lean: leanVerdicts,
    lean_code: leanCodes,
    ts_default: tsDefault(c)
  }
})

process.stdout.write(JSON.stringify({
  issue: 654,
  reference: 'ts-stack@edf6e03 packages/sdk Spend, default mode (no flags), Node v22.18.0',
  node: 'bsv-script-lean@387dab35 eval/bsvs (bitcoin-sv v1.2.3 6504a3af rules): --flags <word>, --consensus true for the block words and false for the standard words, prevout height 967000, spend height 967896',
  words: recording.words,
  cases
}, null, 2) + '\n')
