// Record #816's push-only grid: the reference's `Spend` on an unlocking
// script that is push-only and two that are not, at versions 1 and 2, in its
// default mode and under explicit flags with and without SIGPUSHONLY.
// Followed: tests/support/script_chronicle_default_397.mjs (the same bundle).
// Build the unmodified reference in scratch space, then run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_push_only_default_816.mjs \
//     "$W/sdk.mjs" > tests/vectors/script_push_only_default_816.json
import { pathToFileURL } from 'node:url'

const { Spend, LockingScript, UnlockingScript } =
  await import(pathToFileURL(process.argv[2]).href)

// A signature-shaped push: 71 bytes (`0x47`), a DER header and filler. No
// signature is checked, so no key material is involved.
const SIG = '47' + '3044' + '01'.repeat(69)
const UNLOCKS = [
  ['push-only', SIG],
  ['op1-drop-then-push', '5175' + SIG],
  ['push-dup-drop', SIG + '7675']
]
// OP_DROP OP_1: one item left, so CLEANSTACK holds wherever it applies.
const LOCK = '7551'
// undefined: the reference's default mode (no verifyFlags).
const MODES = [
  ['default', undefined],
  ['SIGPUSHONLY', 'SIGPUSHONLY'],
  ['SIGPUSHONLY,CHRONICLE', 'SIGPUSHONLY,CHRONICLE'],
  ['CHRONICLE', 'CHRONICLE']
]

function record(mode, flags, version, unlockName, unlock) {
  const params = {
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    transactionVersion: version, otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlock), lockingScript: LockingScript.fromHex(LOCK),
    inputSequence: 0xffffffff, lockTime: 0
  }
  if (flags !== undefined) params.verifyFlags = flags
  const spend = new Spend(params)
  let result
  try {
    result = { valid: spend.validate() }
  } catch (error) {
    result = { error: error.message.split('\n')[0] }
  }
  return { mode, version, unlock_name: unlockName, unlock, lock: LOCK,
    push_only: spend.unlockingScript.isPushOnly(), ...result }
}

const cases = []
for (const [mode, flags] of MODES) {
  for (const version of [1, 2]) {
    for (const [name, unlock] of UNLOCKS) cases.push(record(mode, flags, version, name, unlock))
  }
}
// #816's relaxing lane: the default mode's version edges. `#isRelaxed()` is
// `transactionVersion > 1` on the number `readUInt32LE` reads, so version 0
// is strict and 2^31 and 2^32 - 1 are relaxed (the unsigned reading, #418).
const versionEdges = []
for (const version of [0, 2147483648, 4294967295]) {
  for (const [name, unlock] of UNLOCKS) versionEdges.push(record('default', undefined, version, name, unlock))
}
console.log(JSON.stringify({ reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version, cases, version_edges: versionEdges }, null, 2))
