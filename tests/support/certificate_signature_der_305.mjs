// The #305 witness: the reference's certificate signature DER, parsed at
// `toBinary`, `fromBinary` and `verify` and re-encoded at `fromBinary`.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_signature_der_305.mjs \
//     "$W/sdk.mjs" > tests/vectors/auth_certificate_signature_der_305.json
//
// One certificate: certifier 43, subject 47 (each private key 32 bytes of that
// value), type 32 bytes of 1, serial 32 bytes of 2, the revocation outpoint the
// zero sentinel, one field `f00` whose value is the first of `AAAA`, `AAAB`, ...
// whose BRC-52 signature (RFC 6979, the certifier's child, counterparty anyone)
// has an `r` with its high bit set, so `r` carries the zero byte DER asks for
// and one case can drop it. Each case is a signature's hex, derived from that
// signature; per case three verdicts: `from_binary` (the unsigned prefix
// `toBinary(false)` writes with the signature's bytes appended: the signature
// `fromBinary` keeps, hex, and that certificate's `verify`), `to_binary` (the
// bytes `toBinary(true)` writes after the unsigned prefix, hex) and `verify`
// (the certificate constructed with the signature's hex), each `ok` or the
// words the reference throws.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Certificate, PrivateKey, ProtoWallet, Signature, BigNumber, Utils } = await import(pathToFileURL(sdkPath).href)

const key = (byte) => PrivateKey.fromHex(byte.toString(16).padStart(2, '0').repeat(32))
const [certifier, subject] = [key(43), key(47)]
const TYPE = Utils.toBase64(new Array(32).fill(1))
const SERIAL = Utils.toBase64(new Array(32).fill(2))
const ZERO_OUTPOINT = '00'.repeat(32) + '.0'
const certificate = (value, signature) =>
  new Certificate(TYPE, SERIAL, subject.toPublicKey().toString(), certifier.toPublicKey().toString(),
    ZERO_OUTPOINT, { f00: value }, signature)

async function signed (value) {
  const cert = certificate(value)
  await cert.sign(new ProtoWallet(certifier))
  return cert.signature
}

// The first value whose signature's r has its high bit set (33 bytes in DER).
let value
let canonical
for (let i = 0; ; i++) {
  value = 'AAA' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[i]
  canonical = await signed(value)
  if (canonical.slice(6, 8) === '21') break
}

// The DER's parts: r and s as written (r with its zero byte).
const der = Utils.toArray(canonical, 'hex')
const rLen = der[3]
const r = der.slice(4, 4 + rLen)
const s = der.slice(6 + rLen)
const hex = Utils.toHex
const seq = (body) => [0x30, body.length, ...body]
const int = (bytes) => [0x02, bytes.length, ...bytes]
const n = new BigNumber('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
const highS = new BigNumber(s).neg().add(n).toArray()

const signatures = [
  ['canonical', canonical],
  // r's high bit set and no zero byte: DER's negative integer, which
  // `fromDER` reads as unsigned and `toDER` writes back with the zero byte.
  ['r_without_its_zero_byte', hex(seq([...int(r.slice(1)), ...int(s)]))],
  // s as n - s: DER, not low-S; `toDER` keeps it, ECDSA verifies it.
  ['high_s', hex(seq([...int(r), ...int(highS[0] & 0x80 ? [0, ...highS] : highS)]))],
  // An empty r: `fromDER` reads 0, `toDER` writes `02 01 00`.
  ['empty_r', hex(seq([...int([]), ...int(s)]))],
  // A zero byte before s's first byte, whose high bit is clear.
  ['s_excessively_padded', hex(seq([...int(r), ...int([0, ...s])]))],
  // Two zero bytes before r's high byte.
  ['r_excessively_padded', hex(seq([...int([0, ...r]), ...int(s)]))],
  // The sequence's length in long form, `81 <len>`.
  ['long_form_length', '3081' + canonical.slice(2)],
  // A byte after the sequence.
  ['trailing_byte', canonical + '00'],
  // The sequence's length one short of the bytes.
  ['sequence_length_short', hex([0x30, der[1] - 1, ...der.slice(2)])],
  // s's length one longer than its bytes.
  ['s_length_long', hex([...der.slice(0, 5 + rLen), s.length + 1, ...s])],
  // The DER cut after s's tag, the sequence's length its own: `getLength`
  // reads past the end and the length check after it throws.
  ['s_length_missing', hex([0x30, 3 + rLen, ...der.slice(2, 5 + rLen)])],
  // A set tag where the sequence's goes.
  ['set_tag', '31' + canonical.slice(2)],
  // An integer tag on r other than 02.
  ['r_tag', canonical.slice(0, 4) + '03' + canonical.slice(6)]
]

async function verdict (f) {
  try {
    return { ok: await f() }
  } catch (e) {
    return { error: e.message }
  }
}

const unsigned = certificate(value).toBinary(false)
const cases = []
for (const [id, signature] of signatures) {
  const bytes = Utils.toArray(signature, 'hex')
  cases.push({
    id,
    signature,
    length: bytes.length,
    from_binary: await verdict(async () => {
      const read = Certificate.fromBinary([...unsigned, ...bytes])
      return {
        signature: read.signature,
        verify: await read.verify(),
        // `toBinary(true)` of the certificate read: its signature's bytes.
        written: await verdict(() => hex(read.toBinary(true).slice(unsigned.length)))
      }
    }),
    to_binary: await verdict(() => hex(certificate(value, signature).toBinary(true).slice(unsigned.length))),
    verify: await verdict(() => certificate(value, signature).verify()),
    // `Signature.fromDER` alone, for the reader of this file.
    from_der: await verdict(() => Signature.fromDER(bytes).toDER('hex'))
  })
}

process.stdout.write(JSON.stringify({
  description: "The reference's certificate signature DER at toBinary, fromBinary and verify (#305), recorded by tests/support/certificate_signature_der_305.mjs",
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  field_value: value,
  unsigned_prefix: hex(unsigned),
  cases
}, null, 2) + '\n')
