// The #842 fold's witness of the reference's interpreter: what `Spend`'s
// default mode (no flags) answers for `<sig> <key> OP_CHECKSIG` and
// `<sig> <key> OP_CHECKSIG OP_NOT` at versions 1 and 2, for this crate's
// signer's signature and each shape built from it: a lone-zero R, a lone-zero
// S, an R past 32 bytes, an S past 32 bytes, and the shapes of #842; and what
// `Signature.toDER` writes for a zero R, a zero S and both, and what
// `Signature.fromDER` reads back from each; and `Signature.fromDER` on a
// length byte of exactly 0x7f and 0x80 at the sequence, at R and at S
// (`der_lengths`: the edges of `getLength`'s short form, `Signature.ts:45-52`),
// one of them a 129-byte DER whose sequence length is 0x7f.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_signature_der_842.mjs \
//     "$W/sdk.mjs" > tests/vectors/script_signature_der_842.json
//
// The spend is `tests/script_signature_der_842.rs`'s: the source txid 32
// bytes of 07, output 0, 1000 satoshis, no other input, no output, sequence
// 0xffffffff, lock time 0, the key 32 bytes of 2b, the scope ALL|FORKID (0x41)
// over the locking script's digest (the reference's `formatBytes`, signed by
// `ECDSA.sign` with low S, RFC 6979 as this crate's signer). Per cell the
// verdict, `true`, or the words thrown.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const {
  Spend, LockingScript, UnlockingScript, Script, TransactionSignature, Signature, PrivateKey,
  ECDSA, BigNumber, Hash, Utils
} = await import(pathToFileURL(sdkPath).href)

const hex = Utils.toHex
const bytes = (h) => Utils.toArray(h, 'hex')
const key = PrivateKey.fromHex('2b'.repeat(32))
const txid = '07'.repeat(32)
// The words alone: the sentence before the evaluation context the
// reference appends, without its `Script evaluation error: ` prefix.
const run = (f) => {
  try { return String(f()) } catch (e) {
    return 'ERR:' + e.message.split('\n')[0].replace(/^Script evaluation error: /, '')
  }
}

const lockOf = (not) => {
  const s = new Script()
  s.writeBin(key.toPublicKey().encode(true))
  s.writeOpCode(0xac)
  if (not) s.writeOpCode(0x91)
  return s
}
const params = (lock, version) => ({
  sourceTXID: txid,
  sourceOutputIndex: 0,
  sourceSatoshis: 1000,
  transactionVersion: version,
  otherInputs: [],
  outputs: [],
  inputIndex: 0,
  subscript: lock,
  inputSequence: 0xffffffff,
  lockTime: 0,
  scope: 0x41
})
const derOf = (lock, version) => {
  const hash = new BigNumber(Hash.hash256(TransactionSignature.formatBytes(params(lock, version))))
  return ECDSA.sign(hash, key, true).toDER()
}
const spend = (der, lock, version) => run(() => {
  const unlock = new Script()
  unlock.writeBin([...der, 0x41])
  return new Spend({
    sourceTXID: txid,
    sourceOutputIndex: 0,
    sourceSatoshis: 1000,
    lockingScript: LockingScript.fromHex(lock.toHex()),
    transactionVersion: version,
    otherInputs: [],
    outputs: [],
    unlockingScript: UnlockingScript.fromHex(unlock.toHex()),
    inputSequence: 0xffffffff,
    inputIndex: 0,
    lockTime: 0
  }).validate()
})

const parts = (der) => [der.slice(4, 4 + der[3]), der.slice(6 + der[3])]
const seq = (r, s) => { const body = [0x02, r.length, ...r, 0x02, s.length, ...s]; return [0x30, body.length, ...body] }
const strip = (v) => { let i = 0; while (i < v.length && v[i] === 0) i++; return v.slice(i) }
const past32 = (v) => [1, ...new Array(32 - strip(v).length).fill(0), ...strip(v)]
const shapes = (der) => {
  const [r, s] = parts(der)
  const longR = [0x02, 0x81, r.length, ...r, 0x02, s.length, ...s]
  const longS = [0x02, r.length, ...r, 0x02, 0x81, s.length, ...s]
  return [
    ['canonical', der],
    ['r_lone_zero', seq([0], s)],
    ['s_lone_zero', seq(r, [0])],
    ['r_past_32_bytes', seq(past32(r), s)],
    ['s_past_32_bytes', seq(r, past32(s))],
    ['suffix_1', [...der, 0x00]],
    ['suffix_2', [...der, 0x00, 0x01]],
    ['suffix_33', [...der, ...Array.from({ length: 33 }, (_, i) => i)]],
    ['sequence_length_short', [0x30, der[1] - 1, ...der.slice(2)]],
    ['sequence_length_long_over_a_byte', [0x30, der[1] + 1, ...der.slice(2), 0x00]],
    ['long_form_sequence', [0x30, 0x81, ...der.slice(1)]],
    ['long_form_r', [0x30, longR.length, ...longR]],
    ['long_form_s', [0x30, longS.length, ...longS]],
    ['r_padded', seq([0, 0, ...strip(r)], s)],
    ['s_padded', seq(r, [0, ...s])],
    ['six_bytes', bytes('300402000200')]
  ]
}

const out = {
  reference: 'ts-stack@edf6e03 packages/sdk (Spend.ts:376-386,606-629, Signature.ts:44-97,201-250, ECDSA.ts:236-239), Node ' + process.version,
  spend: [],
  to_der: [],
  der_lengths: []
}
for (const version of [1, 2]) {
  const plain = lockOf(false)
  const not = lockOf(true)
  // One DER per lock: the digest covers the locking script.
  for (const [lockName, lock] of [['checksig', plain], ['checksig_not', not]]) {
    const der = derOf(lock, version)
    for (const [name, b] of shapes(der)) {
      out.spend.push({ version, lock: lockName, name, der: hex(b), default: spend(b, lock, version) })
    }
  }
}
const nonzero = new BigNumber('5', 16)
for (const [name, r, s] of [['r_zero', new BigNumber(0), nonzero], ['s_zero', nonzero, new BigNumber(0)], ['both_zero', new BigNumber(0), new BigNumber(0)]]) {
  const der = new Signature(r, s).toDER()
  out.to_der.push({
    name,
    der: hex(der),
    from_der: run(() => { const t = Signature.fromDER(der); return `ok ${t.r.toString(16)} ${t.s.toString(16)}` })
  })
}
{
  const der = derOf(lockOf(false), 1)
  const [r, s] = parts(der)
  const withSeq = (body) => [0x30, body.length, ...body]
  const r61 = [1, ...new Array(60).fill(0x11)]
  const s62 = [1, ...new Array(61).fill(0x22)]
  for (const [name, b] of [
    ['sequence_7f', [0x30, 0x7f, ...der.slice(2)]],
    ['sequence_80', [0x30, 0x80, ...der.slice(2)]],
    ['sequence_7f_129_bytes', [0x30, 0x7f, 0x02, 61, ...r61, 0x02, 62, ...s62]],
    ['r_7f', withSeq([0x02, 0x7f, ...r, 0x02, s.length, ...s])],
    ['r_80', withSeq([0x02, 0x80, ...r, 0x02, s.length, ...s])],
    ['s_7f', withSeq([0x02, r.length, ...r, 0x02, 0x7f, ...s])],
    ['s_80', withSeq([0x02, r.length, ...r, 0x02, 0x80, ...s])]
  ]) {
    out.der_lengths.push({
      name,
      der: hex(b),
      from_der: run(() => { const t = Signature.fromDER(b); return `ok ${t.r.toString(16)} ${t.s.toString(16)}` })
    })
  }
}
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
