// #545: the reference's PushDrop `lock` pushes the wallet's getPublicKey
// answer as the wallet returned it, `toArray(publicKey, 'hex')` under the
// opcode `publicKey.length / 2` (`ts-stack@edf6e03`
// `packages/sdk/src/script/templates/PushDrop.ts:158-175`), never re-encoded.
// Recorded with the reference's own template: a ProtoWallet on the scalar 9
// whose getPublicKey answer is rewritten into each key form, `lock` without
// its signature (`includeSignature` false: the fields are the caller's), at
// both lock positions.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk545.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_key_bytes_545.mjs \
//     "$W/sdk545.mjs" > tests/vectors/pushdrop_key_bytes_545.json
//
// The forms: the wallet's compressed answer; uncompressed (`04` + x + y);
// hybrid (`06`/`07` + x + y, the prefix's low bit y's, as the reference's
// `Point.fromDER` and #498's parser read it); odd-length (the compressed text
// without its leading `0`, which `toArray` reads back with one). The reduced
// forms (a coordinate at or above p) name no key a wallet derives. For the
// odd-length text the reference's opcode is 32.5, written as `0x20` by the
// Uint8Array before 33 bytes: `key_push_offset` names that byte, the one
// this crate writes as `0x21`.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { ProtoWallet, PrivateKey, PushDrop, PublicKey, Utils } = await import(pathToFileURL(sdkPath).href)

const PROTOCOL = [2, 'pushdrop key bytes']
const KEY_ID = '1'
const FIELDS = [[0x68, 0x69], [5], []]

const inner = new ProtoWallet(new PrivateKey(9))
const { publicKey: compressed } = await inner.getPublicKey({
  protocolID: PROTOCOL, keyID: KEY_ID, counterparty: 'self'
})
const uncompressed = PublicKey.fromString(compressed).encode(false, 'hex')
const hybrid = (parseInt(uncompressed.slice(-1), 16) & 1 ? '07' : '06') + uncompressed.slice(2)
if (!compressed.startsWith('0')) throw new Error('the compressed text has no leading 0')
const forms = [
  ['compressed', compressed],
  ['uncompressed', uncompressed],
  ['hybrid', hybrid],
  ['odd_length', compressed.slice(1)]
]

const cases = []
for (const [form, answer] of forms) {
  for (const position of ['before', 'after']) {
    const wallet = { getPublicKey: async () => ({ publicKey: answer }) }
    const fields = FIELDS.map((field) => [...field])
    const script = await new PushDrop(wallet).lock(
      fields, PROTOCOL, KEY_ID, 'self', false, false, position
    )
    const bytes = script.toBinary()
    const keyBytes = Utils.toArray(answer, 'hex')
    cases.push({
      form,
      lock_position: position,
      wallet_answer: answer,
      answer_bytes: Utils.toHex(keyBytes),
      key_push_offset: position === 'before' ? 0 : bytes.length - keyBytes.length - 2,
      locking_script: Utils.toHex(bytes)
    })
  }
}

process.stdout.write(JSON.stringify({
  issue: 545,
  reference: 'ts-stack@edf6e03 packages/sdk/src/script/templates/PushDrop.ts:158-175',
  runtime: `node ${process.version}`,
  fields: FIELDS.map((field) => Utils.toHex(field)),
  cases
}, null, 2) + '\n')
