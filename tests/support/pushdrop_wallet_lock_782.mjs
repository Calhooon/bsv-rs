// #782: the reference's wallet-aware `PushDrop.lock`,
// `new PushDrop(wallet, originator).lock(fields, protocolID, keyID,
// counterparty, forSelf, includeSignature, lockPosition)` (`ts-stack@edf6e03`
// `packages/sdk/src/script/templates/PushDrop.ts:130-202`): the wallet's
// getPublicKey answer pushed as returned, then, when `includeSignature`, its
// createSignature over the fields concatenated pushed as the last field.
// Recorded with the reference's own template over a ProtoWallet on the
// scalar 9, wrapped to record each call's arguments and originator; RFC 6979
// makes the signature, and so the whole script, deterministic.
//
// Run against ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk782.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/pushdrop_wallet_lock_782.mjs \
//     "$W/sdk782.mjs" > tests/vectors/pushdrop_wallet_lock_782.json
//
// The cases: counterparty `self`, `anyone` and a compressed key's hex (the
// scalar 7's); `forSelf` false and true; `includeSignature` true and false;
// both lock positions; the field shapes below (the empty list signed is the
// signature alone and one OP_DROP, unsigned the key and OP_CHECKSIG alone);
// an originator and none; one shape with the wallet's key answer rewritten
// uncompressed (#545's form). Each case carries the arguments, the wallet's
// key text, the signature, the calls seen and the locking script. The
// `key_texts` (#782's fold) are the three key texts that are no key, below.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { ProtoWallet, PrivateKey, PushDrop, PublicKey, Utils } = await import(pathToFileURL(sdkPath).href)

const PROTOCOL = [2, 'pushdrop wallet lock']
const KEY_ID = '1'
const OTHER = new PrivateKey(7).toPublicKey().toString()
const ORIGINATOR = 'pushdrop.example.com'

const SHAPES = [
  ['three_fields', [[0x68, 0x69], [5], []]],
  ['no_fields', []],
  ['one_negate', [[0x81]]],
  ['a_76_byte_field', [Array.from({ length: 76 }, (_, i) => i)]],
  ['a_256_byte_field_and_another', [Array.from({ length: 256 }, (_, i) => i % 256), [0xaa, 0xbb]]],
  ['four_fields', [[1], [16], [17], [0]]]
]

const inner = new ProtoWallet(new PrivateKey(9))

function recording (keyForm) {
  const calls = []
  const state = { key: null, signature: null }
  const wallet = {
    getPublicKey: async (args, originator) => {
      calls.push({ method: 'getPublicKey', args: JSON.parse(JSON.stringify(args)), originator: originator ?? null })
      const answer = await inner.getPublicKey(args, originator)
      if (keyForm === 'uncompressed') {
        answer.publicKey = PublicKey.fromString(answer.publicKey).encode(false, 'hex')
      } else if (keyForm.startsWith('text:')) {
        answer.publicKey = keyForm.slice('text:'.length)
      }
      state.key = answer.publicKey
      return answer
    },
    createSignature: async (args, originator) => {
      calls.push({
        method: 'createSignature',
        args: { ...JSON.parse(JSON.stringify({ ...args, data: undefined })), data: Utils.toHex(args.data) },
        originator: originator ?? null
      })
      const answer = await inner.createSignature(args, originator)
      state.signature = Utils.toHex(answer.signature)
      return answer
    }
  }
  return { wallet, calls, state }
}

const cases = []
async function record (name, shape, counterparty, forSelf, includeSignature, position, originator, keyForm) {
  const { wallet, calls, state } = recording(keyForm)
  const fields = shape.map((field) => [...field])
  const script = await new PushDrop(wallet, originator ?? undefined).lock(
    fields, PROTOCOL, KEY_ID, counterparty, forSelf, includeSignature, position
  )
  cases.push({
    name,
    originator: originator ?? null,
    fields: shape.map((field) => Utils.toHex(field)),
    protocol_id: PROTOCOL,
    key_id: KEY_ID,
    counterparty,
    for_self: forSelf,
    include_signature: includeSignature,
    lock_position: position,
    key_form: keyForm,
    wallet_answer: state.key,
    signature: state.signature,
    calls,
    locking_script: script.toHex()
  })
}

// The full grid on the three-field shape.
for (const counterparty of ['self', 'anyone', OTHER]) {
  for (const forSelf of [false, true]) {
    for (const includeSignature of [true, false]) {
      for (const position of ['before', 'after']) {
        const who = counterparty === OTHER ? 'other' : counterparty
        await record(
          `grid_${who}_forself_${forSelf}_signed_${includeSignature}_${position}`,
          SHAPES[0][1], counterparty, forSelf, includeSignature, position, null, 'as_derived'
        )
      }
    }
  }
}
// Every field shape, signed and unsigned, at both positions.
for (const [shapeName, shape] of SHAPES.slice(1)) {
  for (const includeSignature of [true, false]) {
    for (const position of ['before', 'after']) {
      await record(
        `shape_${shapeName}_signed_${includeSignature}_${position}`,
        shape, 'self', true, includeSignature, position, null, 'as_derived'
      )
    }
  }
}
// An originator on both calls.
await record('originator_signed', SHAPES[0][1], 'self', true, true, 'before', ORIGINATOR, 'as_derived')
await record('originator_unsigned', SHAPES[0][1], 'anyone', false, false, 'after', ORIGINATOR, 'as_derived')
// The wallet's answer uncompressed (#545's form), pushed as returned.
for (const position of ['before', 'after']) {
  await record(`uncompressed_answer_signed_${position}`, SHAPES[0][1], 'self', true, true, position, null, 'uncompressed')
}

// #782's fold: a key text that is no key. The reference decodes the text
// (`toArray(publicKey, 'hex')`, `PushDrop.ts:166-172`; `assertValidHex`,
// `primitives/hex.ts:6-17`, through `hexToUint8Array`, `utils.ts:126-128`)
// before it asks the signature (`:173-185`): each outcome, the calls seen
// and the script or the words thrown.
const keyTexts = []
for (const [name, text] of [['not_hex', 'zz'], ['empty', ''], ['odd_not_hex', 'zzz']]) {
  const { wallet, calls } = recording(`text:${text}`)
  let outcome
  try {
    const script = await new PushDrop(wallet, undefined).lock(
      [[0x68, 0x69]], PROTOCOL, KEY_ID, 'self', true, true, 'before'
    )
    outcome = { resolved: script.toHex() }
  } catch (error) {
    outcome = { rejected: String(error && error.message) }
  }
  keyTexts.push({ name, wallet_answer: text, calls: calls.map((call) => call.method), ...outcome })
}

process.stdout.write(JSON.stringify({
  issue: 782,
  reference: 'ts-stack@edf6e03 packages/sdk/src/script/templates/PushDrop.ts:130-202',
  runtime: `node ${process.version}`,
  wallet: 'ProtoWallet(new PrivateKey(9))',
  other_counterparty: OTHER,
  cases,
  key_texts: keyTexts
}, null, 2) + '\n')
