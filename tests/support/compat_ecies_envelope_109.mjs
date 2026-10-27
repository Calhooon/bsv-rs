// The #109 witnesses: Electrum ECIES envelopes and verdicts in the reference.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/compat_ecies_envelope_109.mjs record "$W/sdk.mjs" > "$W/reference.json"
//   ECIES_109_REFERENCE="$W/reference.json" ECIES_109_CRATE_OUT="$W/crate.json" \
//     cargo test --features full --test compat_ecies_envelope_109 -- --ignored
//   $NODE tests/support/compat_ecies_envelope_109.mjs verify "$W/sdk.mjs" "$W/reference.json" \
//     "$W/crate.json" > tests/vectors/compat_ecies_envelope_109.json
//
// `record` seals each plaintext with `ECIES.electrumEncrypt` from the fixed
// sender to the fixed recipient, with the key and without (`noKey`), and opens
// each envelope with `ECIES.electrumDecrypt` with the expected sender and
// without; it builds the refusals (another expected sender, a ciphertext out
// of framing, a key alone, a flipped MAC byte, a key off the curve) and an
// envelope embedding the sender's uncompressed key, its MAC made with the
// reference's own `ECIES.ivkEkM`. `verify` opens the envelopes this crate
// sealed (`crate.json`, the ignored Rust test's output) the same four ways and
// records the verdicts beside the reference's.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [mode, sdkPath, referencePath, cratePath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { ECIES, PrivateKey, Hash, Utils } = sdk

const keyHex = byte => byte.toString(16).padStart(2, '0').repeat(32)
const keys = { recipient: keyHex(1), sender: keyHex(2), other: keyHex(3) }
const recipient = PrivateKey.fromHex(keys.recipient)
const sender = PrivateKey.fromHex(keys.sender)
const other = PrivateKey.fromHex(keys.other)
const expectations = { sender: sender.toPublicKey(), other: other.toPublicKey(), none: undefined }

// The issue's input, a 32-byte plaintext; every other plaintext is a pattern
const ISSUE = Utils.toArray('r68gn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+fn5+9z8I=', 'base64')
const LENGTHS = [1, 15, 16, 17, 31, 32, 33, 47, 48, 64, 96]
const plaintext = n => n === 32 ? ISSUE : Array.from({ length: n }, (_, i) => (i * 31 + n) & 0xff)

const open = (envelopeHex, expected) => {
  try {
    const opened = ECIES.electrumDecrypt(Utils.toArray(envelopeHex, 'hex'), recipient, expectations[expected])
    return { plaintext_hex: Utils.toHex(opened) }
  } catch (e) {
    return { error: e.message }
  }
}

const openings = envelopeHex => ({
  with_sender: open(envelopeHex, 'sender'),
  without_sender: open(envelopeHex, 'none')
})

const seal = (pt, noKey) =>
  Utils.toHex(ECIES.electrumEncrypt(pt, recipient.toPublicKey(), sender, noKey))

function record () {
  const cases = LENGTHS.map(n => {
    const pt = plaintext(n)
    const withKey = seal(pt, false)
    const noKey = seal(pt, true)
    return {
      name: n === 32 ? 'plaintext-32-the-issue-input' : `plaintext-${n}`,
      plaintext_hex: Utils.toHex(pt),
      with_key: { envelope_hex: withKey, opened: openings(withKey) },
      no_key: { envelope_hex: noKey, opened: openings(noKey) }
    }
  })

  const BIE1 = Utils.toArray('BIE1', 'utf8')
  const pt = ISSUE
  const withKey = Utils.toArray(seal(pt, false), 'hex')
  const noKey = Utils.toArray(seal(pt, true), 'hex')
  const ciphertext = noKey.slice(4, noKey.length - 32)
  const uncompressedKey = sender.toPublicKey().encode(false)
  const { kM } = ECIES.ivkEkM(recipient, sender.toPublicKey())
  const unsigned = [...BIE1, ...uncompressedKey, ...ciphertext]
  const uncompressed = [...unsigned, ...Hash.sha256hmac(kM, unsigned)]
  const flipped = noKey.slice()
  flipped[flipped.length - 1] ^= 1
  const offCurve = [...BIE1, 0x02, ...new Array(32).fill(0xff), ...new Array(16).fill(0), ...new Array(32).fill(0)]

  const refusal = (name, bytes, expected) => {
    const envelope_hex = Utils.toHex(bytes)
    return { name, envelope_hex, expected, verdict: open(envelope_hex, expected) }
  }
  const refusals = [
    refusal('embedded-key-beside-another-expected-sender', withKey, 'other'),
    refusal('no-key-envelope-without-a-sender', noKey, 'none'),
    refusal('ciphertext-of-17-bytes', [...BIE1, ...new Array(17).fill(0), ...new Array(32).fill(0)], 'sender'),
    refusal('a-key-and-no-ciphertext', [...BIE1, ...sender.toPublicKey().encode(true), ...new Array(32).fill(0)], 'sender'),
    refusal('a-flipped-mac-byte', flipped, 'sender'),
    refusal('a-compressed-key-off-the-curve', offCurve, 'sender'),
    refusal('a-compressed-key-off-the-curve-without-a-sender', offCurve, 'none'),
    refusal('uncompressed-key-with-the-sender', uncompressed, 'sender'),
    refusal('uncompressed-key-without-a-sender', uncompressed, 'none'),
    refusal('uncompressed-key-beside-another-expected-sender', uncompressed, 'other')
  ]
  return { keys, cases, refusals }
}

function verify () {
  const reference = JSON.parse(fs.readFileSync(referencePath, 'utf8'))
  const crate = JSON.parse(fs.readFileSync(cratePath, 'utf8'))
  for (const c of reference.cases) {
    const sealed = crate.cases[c.name]
    for (const kind of ['with_key', 'no_key']) {
      c[kind].crate_envelope_hex = sealed[kind]
      c[kind].crate_opened = openings(sealed[kind])
    }
  }
  return {
    description: 'Electrum ECIES envelopes (bsv-rs#109): the reference\'s envelopes and verdicts for fixed keys, with this crate\'s envelopes opened by the reference',
    reference: '@bsv/sdk at ts-stack@edf6e03 (packages/sdk/src/compat/ECIES.ts:545-656), bundled with bun, run under Node v22.18.0, by tests/support/compat_ecies_envelope_109.mjs',
    ...reference
  }
}

const out = mode === 'record' ? record() : mode === 'verify' ? verify() : null
if (out === null) throw new Error('mode is record or verify')
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
