// Record #418's transaction versions at and above 2^31 in the reference.
// The reference reads the version unsigned (`Transaction.ts:471`,
// `readUInt32LE`) and relaxes its rules at `transactionVersion > 1`
// (`Spend.ts:319-321`, `:343-345`): 0x80000000 and 0xFFFFFFFF are relaxed in
// both modes there. Build the unmodified reference in scratch space, then run
// under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   source ~/.nvm/nvm.sh && nvm use 22   (recorded with v22.18.0; v22.23.3 writes the same bytes)
//   node tests/support/script_transaction_version_sign_418.mjs \
//     "$W/sdk.mjs" > tests/vectors/script_transaction_version_sign_418.json
import { pathToFileURL } from 'node:url'

const {
  Spend, LockingScript, UnlockingScript, PrivateKey, TransactionSignature, Transaction,
  BigNumber, Hash, Utils
} = await import(pathToFileURL(process.argv[2]).href)

const VERSIONS = [1, 2, 0x7fffffff, 0x80000000, 0xffffffff]
// The names of `ScriptFlags::standard(ProtocolEra::PostChronicle)` (0x3D47FF),
// the node's mempool word for a post-Chronicle block and coin.
const STANDARD_POST_CHRONICLE = [
  'P2SH', 'STRICTENC', 'DERSIG', 'LOW_S', 'NULLDUMMY', 'SIGPUSHONLY', 'MINIMALDATA',
  'DISCOURAGE_UPGRADABLE_NOPS', 'CLEANSTACK', 'CHECKLOCKTIMEVERIFY', 'CHECKSEQUENCEVERIFY',
  'NULLFAIL', 'SIGHASH_FORKID', 'GENESIS', 'UTXO_AFTER_GENESIS', 'CHRONICLE',
  'UTXO_AFTER_CHRONICLE'
]
const N = new BigNumber('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)

function params(version, unlock, lock, flags) {
  const p = {
    sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: 1,
    transactionVersion: version, otherInputs: [], outputs: [], inputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(unlock), lockingScript: LockingScript.fromHex(lock),
    inputSequence: 0xffffffff, lockTime: 0
  }
  if (flags !== undefined) p.verifyFlags = flags
  return p
}

function record(rule, version, mode, unlock, lock) {
  const spend = new Spend(params(version, unlock, lock, mode === 'flags' ? STANDARD_POST_CHRONICLE : undefined))
  let result
  try {
    result = { valid: spend.validate() }
  } catch (error) {
    result = { error: error.message.split('\n')[0] }
  }
  return { rule, version, mode, unlock, lock, ...result,
    stack: spend.stack.map(item => Utils.toHex(item)) }
}

const key = new PrivateKey(7)
const checksigLock = new LockingScript().writeBin(key.toPublicKey().encode(true)).writeOpCode(0xac)

// A signature over the digest the reference's sighash dispatches to at this
// version (the version is a preimage field), low S or its high-S twin.
function signed(version, scope, high) {
  const p = params(version, '', checksigLock.toHex())
  const preimage = TransactionSignature.formatBytes({ ...p, subscript: checksigLock, scope })
  const raw = key.sign(Hash.sha256(preimage))
  const s = high ? N.sub(raw.s) : raw.s
  const sig = new TransactionSignature(raw.r, s, scope)
  return {
    unlock: new UnlockingScript().writeBin(sig.toChecksigFormat()).toHex(),
    digest: Utils.toHex(Hash.hash256(preimage))
  }
}

const cases = []
for (const mode of ['default', 'flags']) {
  for (const version of VERSIONS) {
    cases.push(record('MINIMALDATA', version, mode, '4c0102', '5287'))
    cases.push(record('CLEANSTACK', version, mode, '5151', '51'))
    cases.push(record('NULLDUMMY', version, mode, '51', '0000ae'))
    const highS = signed(version, 0x41, true)
    cases.push({ ...record('LOW_S', version, mode, highS.unlock, checksigLock.toHex()),
      digest: highS.digest })
    const chronicle = signed(version, 0x61, false)
    cases.push({ ...record('CHRONICLE_HASH_TYPE', version, mode, chronicle.unlock,
      checksigLock.toHex()), digest: chronicle.digest })
    cases.push(record('OP_VER', version, mode, '', '62'))
  }
}

// The unsigned read: the version's four bytes, then one input and one output.
const body = '01' + '00'.repeat(32) + '00000000' + '00' + 'ffffffff' +
  '01' + '0000000000000000' + '00' + '00000000'
const reads = ['00000080', 'ffffffff'].map(bytes => ({
  bytes, hex: bytes + body, version: Transaction.fromHex(bytes + body).version
}))

// The strength read's three cells (#418's fold), recorded apart so `cases`
// keeps its 60: the six rules at version 0 in both modes (strict there, as at
// 1); an undefined base hash type (`ALL|FORKID` with base 4, scope 0x44, low S
// over the version's ALL|FORKID digest) in the default mode at every version
// (the reference's DER wrapper at every version, `Spend.ts:609-625`); a
// non-push-only unlocking script (`OP_1 OP_DROP` before `OP_1`) under the
// flags at every version (`SIGPUSHONLY`, `Spend.ts:364-368`).
const foldCases = []
for (const mode of ['default', 'flags']) {
  foldCases.push(record('MINIMALDATA', 0, mode, '4c0102', '5287'))
  foldCases.push(record('CLEANSTACK', 0, mode, '5151', '51'))
  foldCases.push(record('NULLDUMMY', 0, mode, '51', '0000ae'))
  const highS = signed(0, 0x41, true)
  foldCases.push({ ...record('LOW_S', 0, mode, highS.unlock, checksigLock.toHex()),
    digest: highS.digest })
  const chronicle = signed(0, 0x61, false)
  foldCases.push({ ...record('CHRONICLE_HASH_TYPE', 0, mode, chronicle.unlock,
    checksigLock.toHex()), digest: chronicle.digest })
  foldCases.push(record('OP_VER', 0, mode, '', '62'))
}
function undefinedHashType(version) {
  const p = params(version, '', checksigLock.toHex())
  const preimage = TransactionSignature.formatBytes({ ...p, subscript: checksigLock, scope: 0x41 })
  const raw = key.sign(Hash.sha256(preimage))
  const sig = new TransactionSignature(raw.r, raw.s, 0x44)
  return new UnlockingScript().writeBin(sig.toChecksigFormat()).toHex()
}
for (const version of [0, ...VERSIONS]) {
  foldCases.push(record('UNDEFINED_HASH_TYPE', version, 'default', undefinedHashType(version),
    checksigLock.toHex()))
}
for (const version of [0, ...VERSIONS]) {
  foldCases.push(record('SIGPUSHONLY', version, 'flags', '5175', '51'))
}

console.log(JSON.stringify({ reference: 'ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9',
  node: process.version, flags: STANDARD_POST_CHRONICLE, cases, reads,
  fold_cases: foldCases }, null, 2))
