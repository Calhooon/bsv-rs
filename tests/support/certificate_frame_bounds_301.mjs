// The #301 witness: the reference's certificate frame and signature bounds.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_frame_bounds_301.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_certificate_frame_bounds_301.json
//
// Each case names a site and its input in parameters both sides build the
// same way: the fields `f00`, `f01`, ... with values of the given lengths in
// `A`, the signature's hex, and for `from_binary` the frame as the unsigned
// prefix `toBinary(false)` writes with the signature's bytes appended. The
// verdict is `ok` (the SHA-256 of the bytes `toBinary` writes, the number of
// fields `fromBinary` reads) or the words the reference throws. Keys: certifier
// 43, subject 47 (each private key 32 bytes of that value), type 32 bytes of 1,
// serial 32 bytes of 2, the revocation outpoint the zero sentinel.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, PrivateKey, ProtoWallet, Hash, Utils } = await import(pathToFileURL(sdkPath).href)

const key = (byte) => PrivateKey.fromHex(byte.toString(16).padStart(2, '0').repeat(32))
const [certifier, subject] = [key(43), key(47)]
const TYPE = Utils.toBase64(new Array(32).fill(1))
const SERIAL = Utils.toBase64(new Array(32).fill(2))
const ZERO_OUTPOINT = '00'.repeat(32) + '.0'

// A DER signature of 72 bytes, r and s 33 bytes each (the high bit of the
// first value byte set), and the same with one byte more.
const integer = '00' + '80' + '00'.repeat(30) + '01'
const SIGNATURE_72 = '3046' + '0221' + integer + '0221' + integer
const SIGNATURE_73 = SIGNATURE_72 + '00'

const MIB = 1024 * 1024
// 16 fields: the head 163 bytes, the count 1, each field 9 bytes of framing;
// with a 72-byte signature the values fill the frame to 16 MiB exactly.
const EXACT = [...new Array(15).fill(MIB), 16 * MIB - 163 - 1 - 16 * 9 - 72 - 15 * MIB]
const OVER = [...EXACT.slice(0, 15), EXACT[15] + 1]
// The unsigned prefix alone one byte over: the 72 bytes the signature took and one.
const UNSIGNED_OVER = [...EXACT.slice(0, 15), EXACT[15] + 73]

const fields = (lengths) =>
  Object.fromEntries(lengths.map((n, i) => [`f${String(i).padStart(2, '0')}`, 'A'.repeat(n)]))
const certificate = (lengths, signature) =>
  new Certificate(TYPE, SERIAL, subject.toPublicKey().toString(), certifier.toPublicKey().toString(),
    ZERO_OUTPOINT, fields(lengths), signature)

async function verdict (f) {
  try {
    return { ok: await f() }
  } catch (e) {
    return { error: e.message }
  }
}

const sha = (bytes) => Utils.toHex(Hash.sha256(bytes))
const cases = []
const add = async (id, site, input, f) => cases.push({ id, site, input, verdict: await verdict(f) })

// --- Certificate.toBinary (`Certificate.ts:300-319`) --------------------------
const write = async (id, lengths, signature, includeSignature) =>
  add(id, 'to_binary', { value_lengths: lengths, signature, include_signature: includeSignature },
    () => sha(certificate(lengths, signature).toBinary(includeSignature)))
await write('frame_of_16777216_bytes', EXACT, SIGNATURE_72, true)
await write('frame_of_16777217_bytes', OVER, SIGNATURE_72, true)
await write('unsigned_frame_of_16777145_bytes', OVER, SIGNATURE_72, false)
await write('unsigned_frame_of_16777217_bytes', UNSIGNED_OVER, SIGNATURE_72, false)
await write('signature_of_72_bytes', [4], SIGNATURE_72, true)
await write('signature_of_73_bytes', [4], SIGNATURE_73, true)
await write('signature_of_73_bytes_left_out', [4], SIGNATURE_73, false)

// --- Certificate.fromBinary (`Certificate.ts:87-91`, `:390-397`) --------------
const read = async (id, lengths, signature) =>
  add(id, 'from_binary', { value_lengths: lengths, signature }, () => {
    const bytes = [...certificate(lengths).toBinary(false), ...Utils.toArray(signature, 'hex')]
    return Object.keys(Certificate.fromBinary(bytes).fields).length
  })
await read('frame_of_16777216_bytes', EXACT, SIGNATURE_72)
await read('frame_of_16777217_bytes', OVER, SIGNATURE_72)
await read('signature_of_72_bytes', [4], SIGNATURE_72)
await read('signature_of_73_bytes', [4], SIGNATURE_73)

// --- Certificate.verify and sign over toBinary(false) (`Certificate.ts:427`, `:458`)
// The certifier's BRC-52 child signs the over-bound preimage, built by hand
// (`toBinary` refuses to write it), so `false` is the bound's and not a bad
// signature's; the signature is RFC 6979's, recorded for the other side.
const varint = (n) => { const w = new Utils.Writer(); w.writeVarIntNum(n); return w.toArray() }
const head = certificate([]).toBinary(false)
head.pop() // the field count
const preimage = [...head, ...varint(UNSIGNED_OVER.length)]
UNSIGNED_OVER.forEach((n, i) => {
  const name = Utils.toArray(`f${String(i).padStart(2, '0')}`, 'utf8')
  preimage.push(...varint(name.length), ...name, ...varint(n))
  for (let k = 0; k < n; k++) preimage.push(0x41)
})
const { signature: childSignature } = await new ProtoWallet(certifier).createSignature({
  data: preimage, protocolID: [2, 'certificate signature'], keyID: `${TYPE} ${SERIAL}`, counterparty: 'anyone'
})
const overSignature = Utils.toHex(childSignature)
await add('unsigned_frame_of_16777217_bytes', 'verify',
  { value_lengths: UNSIGNED_OVER, preimage_length: preimage.length, preimage_sha256: sha(preimage), signature: overSignature },
  () => certificate(UNSIGNED_OVER, overSignature).verify())
await add('unsigned_frame_of_16777217_bytes', 'sign', { value_lengths: UNSIGNED_OVER },
  async () => { await certificate(UNSIGNED_OVER).sign(new ProtoWallet(certifier)); return 'signed' })
process.stdout.write(JSON.stringify({
  description: "The reference's certificate frame and signature bounds (#301), recorded by tests/support/certificate_frame_bounds_301.mjs",
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  cases
}, null, 2) + '\n')
