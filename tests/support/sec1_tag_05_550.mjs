// #550: a SEC 1 tag `05` key (the compact form k256 reads) at the sites that
// read a key through `PublicKey::from_bytes`, each the reference's outcome at
// `ts-stack@edf6e03` (Node 22). `Point.fromDER` (Point.ts:303-325) reads the
// prefixes 02, 03, 04, 06, 07 and refuses every other as `Unknown point format`.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/sec1_tag_05_550.mjs "$W/sdk.mjs" tests/vectors/token_envelope_544.json \
//     > tests/vectors/sec1_tag_05_550.json
//
// The kvstore cases change the reference's own token of #544's vector (its
// kvstore `reference` case) in one byte. Every other input is built here by
// the reference's writer, then its key's tag byte set to 05. The randomness is
// a SHA-256 counter stream installed before the SDK loads, so two runs print
// the same file. Each case is `{ name, site, input, accepted, words }`, the
// input hex, `words` the reference's thrown message (null when accepted).
import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

let counter = 0
const stream = (n) => {
  const out = []
  while (out.length < n) out.push(...createHash('sha256').update(`bsv-rs#550 ${counter++}`).digest())
  return out.slice(0, n)
}
Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: { getRandomValues (a) { a.set(stream(a.length)); return a } }
})

const sdk = await import(pathToFileURL(process.argv[2]).href)
const envelope544 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const {
  PublicKey, PrivateKey, PushDrop, LockingScript, SignedMessage, EncryptedMessage,
  Certificate, ECIES, WalletWireProcessor, WalletWireTransceiver, ProtoWallet,
  decodeAndVerifyKVStoreToken, Utils
} = sdk
const { toHex, toArray } = Utils

const gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const tag05 = (bytes, at) => { const b = Array.from(bytes); b[at] = 0x05; return b }
const cases = []
const run = async (name, site, input, f) => {
  try {
    await f()
    cases.push({ name, site, input, accepted: true, words: null })
  } catch (e) {
    cases.push({ name, site, input, accepted: false, words: e.message })
  }
}

// The parser: the hex text and the bytes.
await run('from_hex', 'PublicKey.fromString', '05' + gx, () => PublicKey.fromString('05' + gx))
await run('from_bytes', 'PublicKey.fromDER', '05' + gx, () => PublicKey.fromDER(toArray('05' + gx, 'hex')))

// PushDrop.decode, both lock positions (PushDrop.ts:63-95).
const before = '2105' + gx + 'ac' + '03616263' + '75'
await run('pushdrop_lock_before', 'PushDrop.decode before', before,
  () => PushDrop.decode(LockingScript.fromHex(before), 'before'))
const after = '03616263' + '75' + '2105' + gx + 'ac'
await run('pushdrop_lock_after', 'PushDrop.decode after', after,
  () => PushDrop.decode(LockingScript.fromHex(after), 'after'))

// decodeAndVerifyKVStoreToken (kvStoreTokenValidation.ts:85-119) on #544's
// reference token: the locking key's tag, then the controller field's tag.
const token = envelope544.kvstore.cases.find(c => c.name === 'reference').locking_script
const controller = envelope544.kvstore.context.controller
const lockKey = token.slice(0, 2 + 2) === '2103' || token.slice(0, 4) === '2102' ? token : null
if (lockKey === null) throw new Error('the #544 token does not open with a compressed key push')
const lockKey05 = '2105' + token.slice(4)
await run('kvstore_lock_key', 'decodeAndVerifyKVStoreToken', lockKey05,
  () => decodeAndVerifyKVStoreToken(LockingScript.fromHex(lockKey05)))
const at = token.indexOf('21' + controller)
if (at < 0 || token.indexOf('21' + controller, at + 1) >= 0) throw new Error('the controller push is not unique')
const controller05 = token.slice(0, at) + '2105' + token.slice(at + 4)
await run('kvstore_controller', 'decodeAndVerifyKVStoreToken', controller05,
  () => decodeAndVerifyKVStoreToken(LockingScript.fromHex(controller05)))

// SignedMessage.verify (SignedMessage.ts:62-106): the signer's key at byte 4,
// a named recipient's at byte 37.
const message = toArray('hello #550', 'utf8')
const signer = new PrivateKey(7)
const recipient = new PrivateKey(9)
const signedAnyone = tag05(SignedMessage.sign(message, signer), 4)
await run('signed_sender', 'SignedMessage.verify', toHex(signedAnyone),
  () => SignedMessage.verify(message, signedAnyone))
const signedFor = tag05(SignedMessage.sign(message, signer, recipient.toPublicKey()), 37)
await run('signed_recipient', 'SignedMessage.verify', toHex(signedFor),
  () => SignedMessage.verify(message, signedFor, recipient))

// EncryptedMessage.decrypt (EncryptedMessage.ts:72-103): the sender's key at
// byte 4, the recipient's at byte 37.
const encrypted = EncryptedMessage.encrypt(message, signer, recipient.toPublicKey())
const encSender = tag05(encrypted, 4)
await run('encrypted_sender', 'EncryptedMessage.decrypt', toHex(encSender),
  () => EncryptedMessage.decrypt(encSender, recipient))
const encRecipient = tag05(encrypted, 37)
await run('encrypted_recipient', 'EncryptedMessage.decrypt', toHex(encRecipient),
  () => EncryptedMessage.decrypt(encRecipient, recipient))

// Certificate.fromBinary (Certificate.ts:335-350): the subject at byte 64,
// the certifier at byte 97, a signed certificate's bytes.
const certificate = new Certificate(
  Utils.toBase64(new Array(32).fill(1)), Utils.toBase64(new Array(32).fill(2)),
  recipient.toPublicKey().toString(), signer.toPublicKey().toString(),
  '00'.repeat(31) + '03.0', { name: Utils.toBase64(toArray('value', 'utf8')) })
await certificate.sign(new ProtoWallet(signer))
const certificateBytes = certificate.toBinary(true)
for (const [name, offset] of [['certificate_subject', 64], ['certificate_certifier', 97]]) {
  const bytes = tag05(certificateBytes, offset)
  await run(name, 'Certificate.fromBinary', toHex(bytes), () => Certificate.fromBinary(bytes))
}

// ECIES.bitcoreDecrypt (ECIES.ts:703-716): the sender's key at byte 0.
const bitcore = tag05(ECIES.bitcoreEncrypt(message, recipient.toPublicKey(), signer, new Array(16).fill(3)), 0)
await run('ecies_bitcore_sender', 'ECIES.bitcoreDecrypt', toHex(bitcore),
  () => ECIES.bitcoreDecrypt(bitcore, recipient))

// WalletWireProcessor's #decodeCounterparty (WalletWireProcessor.ts:2450-2462):
// a getPublicKey request framed by the reference's transceiver, its
// counterparty's tag set to 05, answered by a processor over a ProtoWallet.
// `input` is the request frame, `words` the error frame's message (the frame
// carries code 1 and an empty stack after it, written by the processor).
let frame
const capture = new WalletWireTransceiver({
  transmitToWallet: async (m) => { frame = Array.from(m); throw new Error('captured') }
})
const counterparty = signer.toPublicKey().toString()
await capture.getPublicKey({ protocolID: [2, 'tests five'], keyID: '1', counterparty }).catch(() => {})
const where = toHex(frame).indexOf(counterparty)
if (where < 0 || where % 2 !== 0) throw new Error('the counterparty is not in the frame')
const request = tag05(frame, where / 2)
const answer = Array.from(await new WalletWireProcessor(new ProtoWallet(recipient)).transmitToWallet(request))
const reader = new Utils.Reader(answer)
const code = reader.readUInt8()
const wireWords = code === 0 ? null : Utils.toUTF8(reader.read(reader.readVarIntNum()))
cases.push({
  name: 'wire_counterparty',
  site: 'WalletWireProcessor getPublicKey',
  input: toHex(request),
  accepted: code === 0,
  words: wireWords,
  code,
  answer: toHex(answer)
})

console.log(JSON.stringify({
  description: '#550: a SEC 1 tag 05 key at the sites that read a key, each the reference\'s outcome (ts-stack@edf6e03, Node v22.18.0). Written by tests/support/sec1_tag_05_550.mjs; never by hand.',
  reference: 'ts-stack@edf6e03',
  node: process.version,
  cases
}, null, 2))
