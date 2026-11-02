// #625: what the reference does with a hybrid (`06`/`07`) public key, the
// door `P2PK::lock` stands at in this crate. The reference has no P2PK
// template (`ts-stack@edf6e03` `packages/sdk/src/script/templates/index.ts`:
// P2PKH, RPuzzle, PushDrop), so its doors for such a key are the parser
// (`Point.fromDER` `src/primitives/Point.ts:303-330`, `fromString` `:345-348`,
// through `PublicKey.fromString`/`fromDER` `src/primitives/PublicKey.ts:49-70`)
// and the interpreter (`Spend.#checkPublicKeyEncoding`
// `src/script/Spend.ts:687-716`, under `#shouldEnforceStrictEncoding`
// `:388-393`, called by OP_CHECKSIG at `:1669`).
//
// The key is the sibling corpus's signer `key("a")` (bsv-script-lean
// `harness/src/bin/crypto_cases.rs:100-103`), in its uncompressed form and
// both hybrid tags (its y is odd: `07` is the tag the reference's parser
// takes, `06` the one it refuses). For each form the recorder writes the
// `<key> OP_CHECKSIG` lock with the reference's own `Script` writer, signs a
// spend of it with the reference's P2PKH unlock (its signature chunk alone,
// over the P2PK lock as the subscript), the shape of the corpus's
// `crypto-00014` (one input of the corpus's outpoint, 1000 satoshis, one
// output of 1 satoshi to `OP_1`), at versions 1 and 2, and records `Spend`'s
// verdict under the default flags and under the explicit word
// `SIGHASH_FORKID` without STRICTENC named (a FORKID signature verifies under
// no explicit word without it; `#shouldEnforceStrictEncoding` is true
// whenever it is named, `:388-393`).
//
// The #625 fold adds `multisig`: the reference's CHECKMULTISIG verdict on
// small m-of-n locks (n from 1 to 4, every m) with a bad key (a compressed
// key retagged `04`, `06` or `07`) at each index, and with tag `07` at each
// pair of indices; the keys are `MULTISIG_LABEL` + index. Each lock is
// written by the reference's `Script` writer (`OP_m <keys> OP_n
// OP_CHECKMULTISIG`) and spent at versions 1 and 2 by `OP_0` and m
// signatures (the P2PKH unlock's signature chunk over the lock, in index
// order) of the m highest-indexed good keys, a bad index's own private key
// filling the count where fewer than m are good; `Spend`'s verdict recorded
// under the default flags and the explicit `SIGHASH_FORKID` word (the
// message's leading line). The walk
// checks the keys from the last pushed backwards (`Spend.ts:1752-1838`:
// `ikey` from the stack's second item), so a bad key is avoided when the
// keys after the highest bad index meet m.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-625-fold/ref
//   git -C ~/bsv/upstream/bsv-blockchain/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/p2pk_hybrid_625.mjs "$W/sdk.mjs" > tests/vectors/p2pk_hybrid_625.json
import { pathToFileURL } from 'url'

const [bundle] = process.argv.slice(2)
const sdk = await import(pathToFileURL(bundle).href)
const {
  Hash, PrivateKey, PublicKey, P2PKH, LockingScript, UnlockingScript,
  Transaction, Spend, OP
} = sdk

const toHex = bytes => bytes.map(b => b.toString(16).padStart(2, '0')).join('')
const fromHex = hex => [...Buffer.from(hex, 'hex')]

const LABEL = 'bsv-script-lean/corpus/crypto/key/a'
const priv = new PrivateKey(toHex(Hash.sha256([...Buffer.from(LABEL, 'utf8')])), 16)
const uncompressed = priv.toPublicKey().encode(false, 'hex')
const body = uncompressed.slice(2)
const yOdd = (parseInt(body.slice(-2), 16) & 1) === 1

// crypto-00014's outpoint (`corpus/crypto/cases.jsonl`, its `prevouts[0]`)
const SOURCE_TXID = '159ff4190afe9befdb517be71452eb74c5917307be47a87ab2cffd11856d4810'
const SATOSHIS = 1000

function attempt (f) {
  try {
    return { ok: true, value: f() }
  } catch (e) {
    return { ok: false, message: e.message }
  }
}

function verdict (spend) {
  try {
    return { ok: spend.validate() }
  } catch (e) {
    return { ok: false, message: e.message }
  }
}

async function spendOf (lock, version) {
  const tx = new Transaction(version, [{
    sourceTXID: SOURCE_TXID,
    sourceOutputIndex: 0,
    sequence: 0xffffffff,
    unlockingScript: new UnlockingScript()
  }], [{ satoshis: 1, lockingScript: LockingScript.fromHex('51') }], 0)
  const p2pkh = new P2PKH().unlock(priv, 'all', false, SATOSHIS, lock)
  const signed = await p2pkh.sign(tx, 0)
  // The P2PK unlock: the signature chunk alone
  const unlock = new UnlockingScript([signed.chunks[0]])
  tx.inputs[0].unlockingScript = unlock
  const params = verifyFlags => {
    const p = {
      sourceTXID: SOURCE_TXID,
      sourceOutputIndex: 0,
      sourceSatoshis: SATOSHIS,
      lockingScript: lock,
      transactionVersion: version,
      otherInputs: [],
      outputs: tx.outputs,
      inputIndex: 0,
      unlockingScript: unlock,
      inputSequence: 0xffffffff,
      lockTime: 0
    }
    if (verifyFlags !== undefined) p.verifyFlags = verifyFlags
    return p
  }
  return {
    version,
    tx: tx.toHex(),
    unlock: unlock.toHex(),
    default_flags: verdict(new Spend(params())),
    explicit_sighash_forkid: verdict(new Spend(params(['SIGHASH_FORKID'])))
  }
}

const forms = [
  ['uncompressed', uncompressed],
  ['hybrid_06', `06${body}`],
  ['hybrid_07', `07${body}`]
]

const cases = []
for (const [name, key] of forms) {
  const fromString = attempt(() => PublicKey.fromString(key).toString())
  const fromDER = attempt(() => PublicKey.fromDER(fromHex(key)).toString())
  const lock = new LockingScript()
    .writeBin(fromHex(key))
    .writeOpCode(OP.OP_CHECKSIG)
  const spends = []
  for (const version of [1, 2]) spends.push(await spendOf(lock, version))
  cases.push({
    name,
    point: key,
    public_key_from_string: fromString.ok
      ? { ok: true, compressed: fromString.value }
      : { ok: false, message: fromString.message },
    public_key_from_der: fromDER.ok
      ? { ok: true, compressed: fromDER.value }
      : { ok: false, message: fromDER.message },
    lock: lock.toHex(),
    spends
  })
}

const MULTISIG_LABEL = 'bsv-rs/625/multisig/key/'
const MULTISIG_TAGS = [0x04, 0x06, 0x07]
const multisigKey = i =>
  new PrivateKey(toHex(Hash.sha256([...Buffer.from(`${MULTISIG_LABEL}${i}`, 'utf8')])), 16)

function multisigShapes () {
  const shapes = []
  for (let n = 1; n <= 4; n++) {
    for (let m = 1; m <= n; m++) {
      for (const tag of MULTISIG_TAGS) {
        for (let j = 0; j < n; j++) shapes.push({ m, n, tag, bad: [j] })
      }
      for (let a = 0; a < n; a++) {
        for (let b = a + 1; b < n; b++) shapes.push({ m, n, tag: 0x07, bad: [a, b] })
      }
    }
  }
  return shapes
}

async function multisigSpendOf (lock, version, signers) {
  const tx = new Transaction(version, [{
    sourceTXID: SOURCE_TXID,
    sourceOutputIndex: 0,
    sequence: 0xffffffff,
    unlockingScript: new UnlockingScript()
  }], [{ satoshis: 1, lockingScript: LockingScript.fromHex('51') }], 0)
  const unlock = new UnlockingScript().writeOpCode(OP.OP_0)
  for (const signer of signers) {
    const signed = await new P2PKH().unlock(signer, 'all', false, SATOSHIS, lock).sign(tx, 0)
    unlock.writeBin(signed.chunks[0].data)
  }
  const params = verifyFlags => {
    const p = {
      sourceTXID: SOURCE_TXID,
      sourceOutputIndex: 0,
      sourceSatoshis: SATOSHIS,
      lockingScript: lock,
      transactionVersion: version,
      otherInputs: [],
      outputs: tx.outputs,
      inputIndex: 0,
      unlockingScript: unlock,
      inputSequence: 0xffffffff,
      lockTime: 0
    }
    if (verifyFlags !== undefined) p.verifyFlags = verifyFlags
    return p
  }
  return {
    version,
    unlock: unlock.toHex(),
    default_flags: brief(verdict(new Spend(params()))),
    explicit_sighash_forkid: brief(verdict(new Spend(params(['SIGHASH_FORKID']))))
  }
}

// The sweep keeps the message's leading line (the words, not the context)
function brief (v) {
  return v.ok ? v : { ok: false, message: v.message.split('\n')[0] }
}

const multisig = []
for (const { m, n, tag, bad } of multisigShapes()) {
  const lock = new LockingScript().writeOpCode(OP.OP_1 + m - 1)
  for (let i = 0; i < n; i++) {
    const key = multisigKey(i).toPublicKey().encode(true)
    if (bad.includes(i)) key[0] = tag
    lock.writeBin(key)
  }
  lock.writeOpCode(OP.OP_1 + n - 1).writeOpCode(OP.OP_CHECKMULTISIG)
  const indices = [...Array(n).keys()]
  const good = indices.filter(i => !bad.includes(i)).reverse()
  const chosen = good.slice(0, m)
  for (const i of bad) if (chosen.length < m) chosen.push(i)
  chosen.sort((x, y) => x - y)
  const spends = []
  for (const version of [1, 2]) {
    spends.push(await multisigSpendOf(lock, version, chosen.map(multisigKey)))
  }
  multisig.push({ m, n, tag, bad, signers: chosen, lock: lock.toHex(), spends })
}

console.log(JSON.stringify({
  source: '@bsv/sdk at ts-stack@edf6e03 (packages/sdk), Node v22.18.0; tests/support/p2pk_hybrid_625.mjs',
  reference_has_p2pk_template: typeof sdk.P2PK !== 'undefined',
  key_label: LABEL,
  y_odd: yOdd,
  source_txid: SOURCE_TXID,
  satoshis: SATOSHIS,
  cases,
  multisig_label: MULTISIG_LABEL,
  multisig
}, null, 2))
