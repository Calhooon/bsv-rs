// Record #397's default-mode Chronicle opcodes and signature-hash gate.
// Build the unmodified reference in scratch space, then run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_chronicle_default_397.mjs \
//     "$W/sdk.mjs" > tests/vectors/script_chronicle_default_397.json
import { pathToFileURL } from 'node:url'

const { Spend, LockingScript, UnlockingScript, PrivateKey, TransactionSignature, Hash, Utils } =
  await import(pathToFileURL(process.argv[2]).href)

function params(version, unlock, lock) {
  return {
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    transactionVersion: version, otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlock), lockingScript: LockingScript.fromHex(lock),
    inputSequence: 0xffffffff, lockTime: 0
  }
}

function record(name, version, unlock, lock) {
  const spend = new Spend(params(version, unlock, lock))
  let result
  try {
    result = { valid: spend.validate() }
  } catch (error) {
    result = { error: error.message.split('\n')[0] }
  }
  return { name, version: version ?? null, unlock, lock, ...result,
    stack: spend.stack.map(item => Utils.toHex(item)) }
}

const opcodes = []
// The three historical script_invalid rows whose default verdicts change.
opcodes.push(record('OP_VER-invalid-vector-18', 1, '51', '6362675168'))
opcodes.push(record('OP_VERIF-invalid-vector-19', 1, '00', '6365675168'))
opcodes.push(record('OP_VERNOTIF-invalid-vector-21', 1, '00', '6366675168'))
for (const version of [1, 2, 0, -1, 0x12345678, undefined]) {
  opcodes.push(record('OP_VER', version, '', '62'))
}
for (const version of [1, 2]) {
  const encoded = version === 1 ? '01000000' : '02000000'
  for (const [name, opcode] of [['OP_VERIF', '65'], ['OP_VERNOTIF', '66']]) {
    for (const [kind, unlock] of [
      ['equal', '04' + encoded], ['different', '0403000000'],
      ['number', version === 1 ? '51' : '52'], ['five-bytes', '05' + encoded + '00'],
      ['empty-item', '00'], ['underflow', '']
    ]) {
      opcodes.push(record(`${name}-${kind}`, version, unlock, opcode + '51670068'))
    }
    opcodes.push(record(`${name}-skipped`, version, '', '0063' + opcode + '68516851'))
  }
  for (const [name, opcode] of [['OP_2MUL', '8d'], ['OP_2DIV', '8e']]) {
    for (const [kind, unlock] of [
      ['positive', '57'], ['negative', '0187'], ['negative-one', '4f'],
      ['zero', '00'], ['bytes', '026e6f'], ['non-minimal', '020100'],
      ['negative-zero', '0180'], ['underflow', '']
    ]) {
      opcodes.push(record(`${name}-${kind}`, version, unlock, opcode))
    }
    opcodes.push(record(`${name}-skipped`, version, '', '0063' + opcode + '6851'))
  }
}

function signature(version, scope) {
  const key = new PrivateKey(7)
  const lock = new LockingScript().writeBin(key.toPublicKey().encode(true)).writeOpCode(0xac)
  const p = params(version, '', lock.toHex())
  const digest = Hash.hash256(TransactionSignature.formatBytes({ ...p, subscript: lock, scope }))
  const raw = key.sign(Hash.sha256(TransactionSignature.formatBytes({ ...p, subscript: lock, scope })))
  const sig = new TransactionSignature(raw.r, raw.s, scope)
  const unlock = new UnlockingScript().writeBin(sig.toChecksigFormat()).toHex()
  return { ...record(`CHECKSIG-${scope.toString(16)}`, version, unlock, lock.toHex()),
    digest: Utils.toHex(digest) }
}

const signatures = []
for (const version of [1, 2]) {
  for (const scope of [0x41, 0x61]) signatures.push(signature(version, scope))
}
console.log(JSON.stringify({ reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version, opcodes, signatures }, null, 2))
