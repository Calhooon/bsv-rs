// Record the unmodified reference built from its clone under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_signature_words_417.mjs \
//     "$W/sdk.mjs" > tests/vectors/script_signature_words_417.json
// The same recorder also runs on ts-sdk@9e3ede6b (pass that label as argv[3]).
// Pass --forkid-gate as argv[4] to record #429's original/BIP143 digest
// controls and explicit words. Pass a recording path instead to replay it.
// Pass --script-invalid-forkid and script_invalid.json to re-judge rows 408/409.
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'

const { Spend, LockingScript, UnlockingScript, PrivateKey, TransactionSignature, BigNumber, Hash, Utils } =
  await import(pathToFileURL(process.argv[2]).href)

function parameters(version, lock, mode) {
  return {
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    transactionVersion: version, otherInputs: [], outputs: [], inputIndex: 0,
    inputSequence: 0xffffffff, lockTime: 0, lockingScript: lock,
    unlockingScript: new UnlockingScript(),
    ...(mode === 'der-off' ? { verifyFlags: [] } : {}),
    ...(mode.startsWith('forkid-') ? { verifyFlags: [
      'GENESIS', 'UTXO_AFTER_GENESIS', 'SIGHASH_FORKID',
      ...(mode === 'forkid-strict-word' ? ['STRICTENC'] : [])
    ] } : {})
  }
}

function recordForkIdGate(version, wrongDigest, mode) {
  const key = new PrivateKey(7)
  const lock = new LockingScript().writeBin(key.toPublicKey().encode(true)).writeOpCode(0xac)
  const params = parameters(version, lock, mode)
  const signing = { ...params, subscript: lock, scope: 0x01, sighashForkIdEnabled: true }
  const original = TransactionSignature.formatBytes(signing)
  // Force the BIP143 algorithm but keep the signed hash-type word at 0x01.
  // A signature over this digest must fail the default's original dispatch.
  const bip143 = TransactionSignature.formatBip143(signing)
  const preimage = wrongDigest ? bip143 : original
  const raw = key.sign(Hash.sha256(preimage))
  const sig = new TransactionSignature(raw.r, raw.s, 0x01)
  params.unlockingScript = new UnlockingScript().writeBin(sig.toChecksigFormat())
  return evaluate({
    name: `v${version}-${wrongDigest ? 'bip143' : 'original'}-${mode}`,
    version, mode, scope: 0x01, unlock: params.unlockingScript.toHex(), lock: lock.toHex(),
    signedDigest: wrongDigest ? 'bip143' : 'original',
    originalDigest: Utils.toHex(Hash.hash256(original)),
    bip143Digest: Utils.toHex(Hash.hash256(bip143))
  })
}

function record(name, version, scope, highS = false, mode = 'default') {
  const key = new PrivateKey(7)
  const lock = new LockingScript().writeBin(key.toPublicKey().encode(true)).writeOpCode(0xac)
  const params = parameters(version, lock, mode)
  const signing = { ...params, subscript: lock, scope,
    sighashForkIdEnabled: mode !== 'der-off' }
  const preimage = TransactionSignature.formatBytes(signing)
  const raw = key.sign(Hash.sha256(preimage))
  const order = new BigNumber('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')
  const sig = new TransactionSignature(raw.r, highS ? order.sub(raw.s) : raw.s, scope)
  params.unlockingScript = new UnlockingScript().writeBin(sig.toChecksigFormat())
  return evaluate({ name, version, mode, scope, highS, unlock: params.unlockingScript.toHex(),
    lock: lock.toHex(), digest: Utils.toHex(Hash.hash256(preimage)) })
}

function evaluate(c) {
  const params = parameters(c.version, LockingScript.fromHex(c.lock), c.mode)
  params.unlockingScript = UnlockingScript.fromHex(c.unlock)
  const spend = new Spend(params)
  let lowSChecks = 0
  const hasLowS = TransactionSignature.prototype.hasLowS
  // Observe the public predicate without changing its result: a hash-type
  // refusal must precede low-S, including a signature failing both checks.
  TransactionSignature.prototype.hasLowS = function () {
    lowSChecks++
    return hasLowS.call(this)
  }
  let result
  try {
    result = { valid: spend.validate() }
  } catch (error) {
    result = { error: error.message.split('\n')[0] }
  } finally {
    TransactionSignature.prototype.hasLowS = hasLowS
  }
  const { valid, error, lowSChecks: previousChecks, ...input } = c
  return { ...input, lowSChecks, ...result }
}

const cases = process.argv[4] === '--script-invalid-forkid'
  ? [408, 409].map(index => {
    const c = JSON.parse(readFileSync(process.argv[5], 'utf8'))[index]
    return evaluate({ name: `script-invalid-${index}`, index, version: 1, mode: 'default',
      unlock: c.scriptSig, lock: c.scriptPubKey, flags: c.flags, comment: c.comment })
  })
  : process.argv[4] === '--forkid-gate'
  ? ['default', 'forkid-strict-word', 'forkid-implied-word'].flatMap(mode =>
    [1, 2].flatMap(version => [false, true].map(wrong => recordForkIdGate(version, wrong, mode))))
  : process.argv[4]
  ? JSON.parse(readFileSync(process.argv[4], 'utf8')).cases.map(evaluate)
  : [
  record('defined-low-s', 1, 0x41),
  record('undefined-hash-type', 1, 0x44),
  record('high-s', 1, 0x41, true),
  record('undefined-hash-type-and-high-s', 1, 0x44, true),
  record('chronicle-at-version-1', 1, 0x61),
  record('high-s-at-version-2', 2, 0x41, true),
  record('der-off-chronicle', 1, 0x61, false, 'der-off'),
  record('der-off-forkid-present', 1, 0x41, false, 'der-off'),
  record('der-off-forkid-absent', 1, 0x01, false, 'der-off')
]
console.log(JSON.stringify({
  reference: process.argv[3] ?? 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version, cases
}, null, 2))
