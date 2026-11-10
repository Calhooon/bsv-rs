// The #842 witness: the reference's DER signature reader and the SDK doors
// that read a DER signature through it, on the six shapes of the finding.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/signature_der_842.mjs \
//     "$W/sdk.mjs" > tests/vectors/signature_der_842.json
//
// Three signatures, each the reference's own (RFC 6979, so this crate's signer
// writes the same bytes): a BRC-77 signed message (signer 43, anyone, the key
// ID 32 bytes of 1, the message `68656c6c6f`), a BSM signature (key 43, the
// same message) and a ProtoWallet signature (key 43, protocol
// `[2, 'tests']`, key ID `1`, counterparty self, data `010203`). Each shape is
// built from a signature's DER: bytes after it (1, 2 and 33), its sequence
// length one short and one long over a byte after it, the sequence's, R's and
// S's length in the long form `81 <len>`, unneeded zeros before R and one
// before S, R past 32 bytes (`01` before its 32); `reader`
// adds inputs that only the reader takes: the empty input, six bytes
// `300402000200`, a lone byte. Per cell the verdict, `ok` with the values
// read (`r`, `s` as hex, `0` for zero) or `true`/`false` at a verifying door,
// or the words thrown.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const {
  Signature, TransactionSignature, PrivateKey, ProtoWallet, SignedMessage, BSM, Utils
} = await import(pathToFileURL(sdkPath).href)

const hex = Utils.toHex
const bytes = (h) => Utils.toArray(h, 'hex')
const key = PrivateKey.fromHex('2b'.repeat(32))
const message = bytes('68656c6c6f')
const value = (bn) => BigInt('0x' + (bn.toString(16) || '0')).toString(16)
const run = async (f) => {
  try { return await f() } catch (e) { return 'ERR:' + e.message }
}
const read = (r) => `ok ${value(r.r)} ${value(r.s)}`

// The BRC-77 signed message with a fixed key ID, as `SignedMessage.sign`
// builds it (`SignedMessage.ts:28-58`) with `Random(32)` replaced.
const keyID = new Array(32).fill(1)
const anyone = new PrivateKey(1).toPublicKey()
const signingKey = key.deriveChild(anyone, `2-message signing-${Utils.toBase64(keyID)}`)
const messageDer = signingKey.sign(message).toDER()
const prefix = [...bytes('42423301'), ...key.toPublicKey().encode(true), 0, ...keyID]
const signedMessage = [...prefix, ...messageDer]
if (!SignedMessage.verify(message, signedMessage)) throw new Error('the signed message must verify')

const bsmDer = BSM.sign(message, key, 'raw').toDER()
const wallet = new ProtoWallet(key)
const walletArgs = { protocolID: [2, 'tests'], keyID: '1', counterparty: 'self' }
const walletDer = (await wallet.createSignature({ ...walletArgs, data: [1, 2, 3] })).signature

const parts = (der) => [der.slice(4, 4 + der[3]), der.slice(6 + der[3])]
const seq = (r, s) => { const body = [0x02, r.length, ...r, 0x02, s.length, ...s]; return [0x30, body.length, ...body] }
const strip = (v) => { let i = 0; while (i < v.length && v[i] === 0) i++; return v.slice(i) }
const shapes = (der) => {
  const [r, s] = parts(der)
  const longR = [0x02, 0x81, r.length, ...r, 0x02, s.length, ...s]
  const longS = [0x02, r.length, ...r, 0x02, 0x81, s.length, ...s]
  const big = [1, ...new Array(32 - strip(r).length).fill(0), ...strip(r)]
  return [
    ['canonical', der],
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
    ['r_past_32_bytes', seq(big, s)]
  ]
}

const cells = (der) => shapes(der).map(([name, b]) => ({ name, der: hex(b) }))
const out = {
  reference: 'ts-stack@edf6e03 packages/sdk (Signature.ts:44-97, TransactionSignature.ts:460-472, SignedMessage.ts:65-105, BSM.ts:71-74, ProtoWallet.ts:358-394), Node ' + process.version,
  signed_message: { prefix: hex(prefix), der: hex(messageDer), cases: [] },
  bsm: { der: hex(bsmDer), cases: [] },
  proto_wallet: { der: hex(walletDer), cases: [] },
  reader: []
}
for (const c of cells(messageDer)) {
  const b = bytes(c.der)
  out.signed_message.cases.push({
    ...c,
    from_der: await run(() => read(Signature.fromDER(b))),
    from_checksig_format: await run(() => { const t = TransactionSignature.fromChecksigFormat([...b, 0x41]); return `${read(t)} ${t.scope}` }),
    verify: await run(() => String(SignedMessage.verify(message, [...prefix, ...b])))
  })
}
for (const c of cells(bsmDer)) {
  out.bsm.cases.push({
    ...c,
    verify: await run(() => String(BSM.verify(message, Signature.fromDER(bytes(c.der)), key.toPublicKey())))
  })
}
for (const c of cells(walletDer)) {
  out.proto_wallet.cases.push({
    ...c,
    verify: await run(async () => String((await wallet.verifySignature({ ...walletArgs, data: [1, 2, 3], signature: bytes(c.der) })).valid))
  })
}
for (const [name, h] of [['empty', ''], ['lone_sequence_tag', '30'], ['six_bytes', '300402000200'], ['seven_bytes', '30050200020100'], ['seven_bytes_s_one', '30050200020101']]) {
  out.reader.push({
    name,
    der: h,
    from_der: await run(() => read(Signature.fromDER(bytes(h)))),
    from_checksig_format: await run(() => { const t = TransactionSignature.fromChecksigFormat([...bytes(h), 0x41]); return `${read(t)} ${t.scope}` })
  })
}
out.reader.push({
  name: 'checksig_empty',
  der: '',
  from_checksig_format: await run(() => { const t = TransactionSignature.fromChecksigFormat([]); return `${read(t)} ${t.scope}` })
})
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
