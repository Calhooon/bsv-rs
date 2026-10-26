// The #249 witnesses: a certificate's field order in the reference.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/certificate_field_order_249.mjs \
//     "$W/sdk.mjs" tests/vectors/auth_certificate_field_order_249.json
//
// It prints the order `localeCompare` gives the six names, signs the
// six-field certificate under the reference's `sign` (`Certificate.ts:458-462`,
// the order `:282`) and prints its bytes, signs the same certificate over
// the names in UTF-8 byte order with the reference's own `createSignature`
// (the preimage an issuer sorting by bytes writes) and prints those bytes,
// prints the reference's refusal of a repeated field name
// (`fromBinary`), prints a corpus of names in `localeCompare` order (every
// printable ASCII and Latin-1 character alone, then strings drawn from a
// fixed seed: the order `src/auth/certificates/collation.rs` must give),
// then runs the reference's `verify` (`Certificate.ts:428-431`)
// on every witness the vector file carries and prints the verdicts the file
// records.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, vectorPath] = process.argv.slice(2)
const { Certificate, ProtoWallet, PrivateKey, Utils } = await import(pathToFileURL(sdkPath).href)

const NAMES = ['Name', 'a_b', 'age', 'a0', 'éa', 'f']
const b64 = (s) => Utils.toBase64(Utils.toArray(s, 'utf8'))
const fields = Object.fromEntries(NAMES.map((n) => [n, b64(`v-${n}`)]))

const certifier = new PrivateKey(21)
const subject = new PrivateKey(23)
const type = Utils.toBase64(new Array(32).fill(6))
const serial = Utils.toBase64(new Array(32).fill(7))
const make = () =>
  new Certificate(
    type,
    serial,
    subject.toPublicKey().toString(),
    certifier.toPublicKey().toString(),
    '00'.repeat(32) + '.0',
    { ...fields }
  )

console.log('node', process.version, 'icu', process.versions.icu)
console.log('localeCompare', [...NAMES].sort((a, b) => a.localeCompare(b)).join(', '))
const bytewise = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
console.log('bytes', [...NAMES].sort(bytewise).join(', '))

// The reference's own signing: its order.
const signed = make()
await signed.sign(new ProtoWallet(certifier))
console.log('reference_signed_mixed_names', Utils.toHex(signed.toBinary(true)))

// The same certificate, the names written in byte order and signed with the
// reference's createSignature under the certificate's protocol and key ID.
const head = make().toBinary(false)
const fieldStart = 32 + 32 + 33 + 33 + 32 + 1
const w = new Utils.Writer()
w.write(head.slice(0, fieldStart))
const sorted = [...NAMES].sort(bytewise)
w.writeVarIntNum(sorted.length)
for (const n of sorted) {
  const name = Utils.toArray(n, 'utf8')
  const value = Utils.toArray(fields[n], 'utf8')
  w.writeVarIntNum(name.length)
  w.write(name)
  w.writeVarIntNum(value.length)
  w.write(value)
}
const preimage = w.toArray()
const { signature } = await new ProtoWallet(certifier).createSignature({
  data: preimage,
  protocolID: [2, 'certificate signature'],
  keyID: `${type} ${serial}`
})
console.log('byte_order_signed_mixed_names', Utils.toHex([...preimage, ...signature]))

// A repeated field name: the reference's reader refuses it.
const dup = new Utils.Writer()
dup.write(head.slice(0, fieldStart))
dup.writeVarIntNum(2)
for (const v of ['djE=', 'djI=']) {
  dup.writeVarIntNum(1)
  dup.write(Utils.toArray('x', 'utf8'))
  dup.writeVarIntNum(v.length)
  dup.write(Utils.toArray(v, 'utf8'))
}
console.log('repeated_field_name', Utils.toHex(dup.toArray()))
try {
  Certificate.fromBinary(dup.toArray())
  console.log('repeated_field_name fromBinary accepted')
} catch (e) {
  console.log('repeated_field_name fromBinary', e.message)
}

// The corpus: every printable character of U+0020..U+007E and U+00A0..U+00FF
// alone, the expansions and the contraction beside their spellings, and
// 1,200 strings of 1 to 8 characters from a fixed seed, half of their
// characters from a set the two orders disagree on.
const printable = []
for (let c = 0x20; c <= 0xff; c++) if (c < 0x7f || c >= 0xa0) printable.push(String.fromCharCode(c))
const tricky = [...'aAeEbB_0-éÉlL·sßæÆ \t']
let seed = 249
const rnd = () => {
  seed = (Math.imul(seed, 1103515245) + 12345) >>> 0
  return seed / 0x100000000
}
const corpus = new Set([...printable, 'ss', 'sr', 'st', 'ae', 'ad', 'af', 'l·', 'L·', 'l', 'lz', 'k'])
while (corpus.size < printable.length + 11 + 1200) {
  let s = ''
  const n = 1 + Math.floor(rnd() * 8)
  for (let i = 0; i < n; i++) {
    s += rnd() < 0.5 ? tricky[Math.floor(rnd() * tricky.length)] : printable[Math.floor(rnd() * printable.length)]
  }
  corpus.add(s)
}
const ordered = [...corpus].sort((a, b) => a.localeCompare(b))
for (let i = 0; i + 1 < ordered.length; i++) {
  if (ordered[i].localeCompare(ordered[i + 1]) === 0) throw new Error(`a tie in the corpus: ${ordered[i]}`)
}
console.log('collation_corpus', JSON.stringify(ordered))

if (vectorPath) {
  const v = JSON.parse(fs.readFileSync(vectorPath, 'utf8'))
  for (const wt of v.witnesses) {
    if (wt.reference_verify === undefined) continue
    const c = Certificate.fromBinary(Utils.toArray(wt.hex, 'hex'))
    console.log('verify', wt.name, await c.verify())
  }
}
