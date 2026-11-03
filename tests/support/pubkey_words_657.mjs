// #657: the reference's words for a badly encoded public key (and, for
// comparison, a badly encoded signature) at the four signature opcodes.
// Record the unmodified reference built from its clone under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pubkey_words_657.mjs \
//     "$W/sdk.mjs" > tests/vectors/pubkey_words_657.json
import { pathToFileURL } from 'node:url'

const { Spend, LockingScript, UnlockingScript, PrivateKey, PublicKey, TransactionSignature, Hash, Utils } =
  await import(pathToFileURL(process.argv[2]).href)

const MODES = {
  'default-v1': { version: 1, flags: null },
  'default-v2': { version: 2, flags: null },
  'strict-word': { version: 2, flags: ['GENESIS', 'UTXO_AFTER_GENESIS', 'SIGHASH_FORKID', 'STRICTENC'] }
}
const OPCODES = { OP_CHECKSIG: 0xac, OP_CHECKSIGVERIFY: 0xad, OP_CHECKMULTISIG: 0xae, OP_CHECKMULTISIGVERIFY: 0xaf }

const key = new PrivateKey(7)
const point = key.toPublicKey()
const x = point.getX().toHex(32)
const y = point.getY().toHex(32)
const P = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'
const pPlus1 = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30'

// The least x whose x^3 + 7 has no square root: a compressed key off the curve.
function offCurveX () {
  for (let i = 1; ; i++) {
    const candidate = i.toString(16).padStart(64, '0')
    try { PublicKey.fromString('02' + candidate) } catch { return candidate }
  }
}
const flipLast = h => h.slice(0, -2) + ((parseInt(h.slice(-2), 16) ^ 1).toString(16).padStart(2, '0'))

const KEYS = {
  'compressed-control': point.toDER('hex'),
  'uncompressed-control': '04' + x + y,
  'hybrid-06': '06' + x + y,
  'hybrid-07': '07' + x + y,
  'tag-04-33-bytes': '04' + x,
  'tag-05-33-bytes': '05' + x,
  'compressed-34-bytes': point.toDER('hex') + '00',
  'uncompressed-66-bytes': '04' + x + y + '00',
  'short-32-bytes': point.toDER('hex').slice(0, 64),
  'empty': '',
  'compressed-off-curve': '02' + offCurveX(),
  'uncompressed-off-curve': '04' + x + flipLast(y),
  'compressed-x-p-plus-1': '02' + pPlus1
}

const signed = key.sign(Hash.sha256(Utils.toArray('657', 'utf8')))
const GOOD_SIG = new TransactionSignature(signed.r, signed.s, 0x41).toChecksigFormat()
const SIGS = {
  'der-low-s': Utils.toHex(GOOD_SIG),
  'empty': '',
  'der-truncated': '30060201010201' + '41'
}

function scripts (opcode, keyHex, sigHex) {
  const k = Utils.toArray(keyHex, 'hex')
  const s = Utils.toArray(sigHex, 'hex')
  const multisig = opcode === 0xae || opcode === 0xaf
  const lock = new LockingScript()
  if (multisig) lock.writeOpCode(0x51)
  lock.writeBin(k)
  if (multisig) lock.writeOpCode(0x51)
  lock.writeOpCode(opcode)
  if (opcode === 0xad || opcode === 0xaf) lock.writeOpCode(0x51)
  const unlock = new UnlockingScript()
  if (multisig) unlock.writeOpCode(0x00)
  unlock.writeBin(s)
  return { lock: lock.toHex(), unlock: unlock.toHex() }
}

function evaluate (mode, opcodeName, keyName, sigName) {
  const m = MODES[mode]
  const { lock, unlock } = scripts(OPCODES[opcodeName], KEYS[keyName], SIGS[sigName])
  const spend = new Spend({
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    transactionVersion: m.version, otherInputs: [], outputs: [], inputIndex: 0,
    inputSequence: 0xffffffff, lockTime: 0,
    lockingScript: LockingScript.fromHex(lock), unlockingScript: UnlockingScript.fromHex(unlock),
    ...(m.flags ? { verifyFlags: m.flags } : {})
  })
  let result
  try {
    result = { valid: spend.validate() }
  } catch (error) {
    result = { error: error.message.split('\n')[0] }
  }
  return {
    name: `${mode}/${opcodeName}/${keyName}/${sigName}`,
    mode, version: m.version, flags: m.flags, opcode: opcodeName,
    point: KEYS[keyName], sig: SIGS[sigName], lock, unlock, ...result
  }
}

const cases = []
for (const mode of Object.keys(MODES)) {
  for (const opcodeName of Object.keys(OPCODES)) {
    for (const keyName of Object.keys(KEYS)) {
      for (const sigName of ['der-low-s', 'empty']) cases.push(evaluate(mode, opcodeName, keyName, sigName))
    }
    for (const keyName of ['compressed-control', 'hybrid-06', 'tag-04-33-bytes']) {
      cases.push(evaluate(mode, opcodeName, keyName, 'der-truncated'))
    }
  }
}
console.log(JSON.stringify({
  reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version,
  fieldPrime: P,
  cases
}, null, 2))
