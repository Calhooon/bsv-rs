// #603: the reference's `RPuzzle` (`ts-stack@edf6e03`
// `packages/sdk/src/script/templates/RPuzzle.ts`): `lock` `:40-70` (the value
// pushed as `{ op: value.length, data: value }`, `:65`) and `unlock(...).sign`
// `:96-121` (`privateKey.sign(sha256(preimage), undefined, true, k)`, `:113`:
// the K value given, low-S forced), on the spend its own test builds
// (`__tests/RPuzzle.test.ts:19-51`: k = 12345678, the private key 1, the R
// value with a 0 byte before a high first byte, `:11-17`).
// `lock` records, per length, `lock` (the reference's locking script, hex) and
// `push` (the reference's minimal push of the same value, `Script.writeBin`,
// `Script.ts:340-352`, hex); the value's byte i is (7i + 1) mod 256.
// `spend` records, per puzzle type and signature scope, the locking script, the
// source and the signed spending transaction, the unlocking script (hex) and
// `Spend.validate()`.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-603-rpuzzle/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf '%s\n' \
//     "import RPuzzle from './packages/sdk/src/script/templates/RPuzzle.js'" \
//     "import Script from './packages/sdk/src/script/Script.js'" \
//     "import Spend from './packages/sdk/src/script/Spend.js'" \
//     "import LockingScript from './packages/sdk/src/script/LockingScript.js'" \
//     "import Transaction from './packages/sdk/src/transaction/Transaction.js'" \
//     "import PrivateKey from './packages/sdk/src/primitives/PrivateKey.js'" \
//     "import BigNumber from './packages/sdk/src/primitives/BigNumber.js'" \
//     "import Curve from './packages/sdk/src/primitives/Curve.js'" \
//     "import * as Hash from './packages/sdk/src/primitives/Hash.js'" \
//     "export { RPuzzle, Script, Spend, LockingScript, Transaction, PrivateKey, BigNumber, Curve, Hash }" \
//     > "$W/entry603.ts"
//   (cd "$W" && bun build entry603.ts --target node --format esm --outfile "$W/rpuzzle.mjs")
//   node tests/support/rpuzzle_lock_and_spend_603.mjs "$W/rpuzzle.mjs" > tests/vectors/rpuzzle_lock_and_spend_603.json
import { pathToFileURL } from 'url'

const [bundle] = process.argv.slice(2)
const { RPuzzle, Script, Spend, LockingScript, Transaction, PrivateKey, BigNumber, Curve, Hash } =
  await import(pathToFileURL(bundle).href)

const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')

const lock = [0, 20, 32, 33, 75, 76, 77, 100, 255, 256].map(length => {
  const value = Array.from({ length }, (_, i) => (7 * i + 1) % 256)
  return {
    length,
    lock: new RPuzzle().lock(value).toHex(),
    push: new Script().writeBin(value).toHex()
  }
})

// `__tests/RPuzzle.test.ts:11-17`
const getRValue = k => {
  const c = new Curve()
  let r = c.g.mul(k).x.umod(c.n).toArray()
  if (r[0] > 127) r = [0, ...r]
  return r
}

const K = 12345678
const KEY = 1
const k = new BigNumber(K)
const privateKey = new PrivateKey(KEY)
const r = getRValue(k)
const hashes = {
  raw: v => v,
  SHA1: Hash.sha1,
  SHA256: Hash.sha256,
  HASH256: Hash.hash256,
  RIPEMD160: Hash.ripemd160,
  HASH160: Hash.hash160
}
const scopes = [
  ['all', false],
  ['none', false],
  ['single', false],
  ['all', true],
  ['none', true],
  ['single', true]
]

const spend = []
for (const type of Object.keys(hashes)) {
  for (const [signOutputs, anyoneCanPay] of scopes) {
    // `__tests/RPuzzle.test.ts:19-51`
    const puz = new RPuzzle(type)
    const lockingScript = puz.lock(hashes[type](r))
    const sourceTx = new Transaction(1, [], [{ lockingScript, satoshis: 1 }], 0)
    const spendTx = new Transaction(
      1,
      [{ sourceTransaction: sourceTx, sourceOutputIndex: 0, sequence: 0xffffffff }],
      [{ lockingScript: LockingScript.fromASM('OP_1'), satoshis: 1 }],
      0
    )
    const unlockingScript = await puz.unlock(k, privateKey, signOutputs, anyoneCanPay).sign(spendTx, 0)
    spendTx.inputs[0].unlockingScript = unlockingScript
    const valid = new Spend({
      sourceTXID: sourceTx.id('hex'),
      sourceOutputIndex: 0,
      sourceSatoshis: 1,
      lockingScript,
      transactionVersion: 1,
      otherInputs: [],
      outputs: spendTx.outputs,
      inputIndex: 0,
      unlockingScript,
      inputSequence: 0xffffffff,
      lockTime: 0
    }).validate()
    spend.push({
      type,
      signOutputs,
      anyoneCanPay,
      locking: lockingScript.toHex(),
      source: sourceTx.toHex(),
      spending: spendTx.toHex(),
      unlocking: unlockingScript.toHex(),
      valid
    })
  }
}

console.log(
  JSON.stringify(
    {
      source: 'ts-stack@edf6e03 packages/sdk/src/script/templates/RPuzzle.ts',
      node: process.version,
      k: K,
      private_key: KEY,
      r: toHex(r),
      lock,
      spend
    },
    null,
    2
  )
)
