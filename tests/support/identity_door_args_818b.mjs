// #818b (#905): the reference's identity doors hand their arguments to the
// wallet, whose door refuses a bad one before it asks anything
// (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:569`, `:614`;
// `packages/sdk/src/wallet/WalletClient.ts:509-511`, `:524`;
// `packages/sdk/src/wallet/validationHelpers.ts:1535-1587`). Recorded under
// Node v22.18.0, three parts:
//   validators  `validateDiscoverByIdentityKeyArgs` and
//               `validateDiscoverByAttributesArgs` called directly: the
//               error's name, code and message, or the validated key
//   doors       the reference's `IdentityClient` over `new WalletClient(double)`,
//               the double counting every call and answering empty lists:
//               `resolveByIdentityKey({ identityKey }, false)` and `(.., true)`,
//               `resolveByAttributes({ attributes }, false)` and `(.., true)`:
//               the error, or the
//               arguments the double received, and the call counts
//   subject     `Wallet.ts:1012`'s expression, `filterCertificatesByIdentityKey`
//               over one certificate of subject G, asked with the key the
//               validator returns for a padded and an upper-case text
// Every key text is under a member named `subject`; every attribute map is a
// list of `[name, value]` pairs in insertion order, built as an own data
// property each (so `__proto__` is a property, not the prototype).
//
// The bundle:
//   W=/Volumes/Lanes/out/bsv-rs/fix-818b/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   cat > "$W/tsconfig.json" <<'EOF'
//   { "compilerOptions": { "baseUrl": ".", "paths": {
//     "@bsv/sdk": ["packages/sdk/mod.ts"],
//     "@bsv/sdk/primitives/utils": ["packages/sdk/src/primitives/utils.ts"],
//     "@bsv/sdk/wallet/validationHelpers": ["packages/sdk/src/wallet/validationHelpers.ts"]
//   } } }
//   EOF
//   cat > "$W/entry818b.ts" <<'EOF'
//   export * from './packages/sdk/mod.js'
//   export { validateDiscoverByIdentityKeyArgs, validateDiscoverByAttributesArgs } from './packages/sdk/src/wallet/validationHelpers.js'
//   export { filterCertificatesByIdentityKey } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOF
//   (cd "$W" && bun build entry818b.ts --target node --format esm --external mongodb --external @bsv/overlay --outfile "$W/ref818b.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_door_args_818b.mjs \
//     "$W/ref818b.mjs" > tests/vectors/identity_door_args_818b.json
// No network, no port.
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  IdentityClient, WalletClient, PrivateKey, validateDiscoverByIdentityKeyArgs,
  validateDiscoverByAttributesArgs, filterCertificatesByIdentityKey
} = sdk

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const hex64 = (n) => n.toString(16).padStart(64, '0')
const G = new PrivateKey(1).toPublicKey().toString()
// G's negation: the other compressed tag over G's x.
const G2 = '03' + G.slice(2)
// The smallest x of no point: x^3 + 7 not a square mod p (Euler's criterion).
const pow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n } return r }
let noPoint = 1n
while (pow((noPoint ** 3n + 7n) % P, (P - 1n) / 2n, P) === 1n) noPoint++

const keys = [
  ['key_64_digits', G.slice(0, 64)],
  ['key_65_digits', G.slice(0, 65)],
  ['key_66_digits', G],
  ['key_66_digits_03', G2],
  ['key_68_digits', G + '00'],
  ['key_not_hex', 'zz'],
  ['key_not_hex_66', 'g' + G.slice(1)],
  ['key_empty', ''],
  ['key_tag_04', '04' + G.slice(2)],
  ['key_x_p_minus_1', '02' + hex64(P - 1n)],
  ['key_x_p', '02' + hex64(P)],
  ['key_x_p_plus_1', '02' + hex64(P + 1n)],
  ['key_x_no_point', '02' + hex64(noPoint)],
  ['key_upper_case', G.toUpperCase()],
  ['key_padded_spaces', '  ' + G + '  '],
  ['key_feff', '﻿' + G],
  ['key_0085', '\u0085' + G]
]

const many = (n) => Array.from({ length: n }, (_, i) => [`f${i}`, 'v'])
const attributeMaps = [
  ['attributes_0', []],
  ['attributes_1', [['email', 'bob']]],
  ['attributes_32', many(32)],
  ['attributes_33', many(33)],
  ['attributes_100001', many(100001)],
  ['name_0_bytes', [['', 'v']]],
  ['name_1_byte', [['a', 'v']]],
  ['name_50_bytes', [['a'.repeat(50), 'v']]],
  ['name_51_bytes', [['a'.repeat(51), 'v']]],
  ['name_50_bytes_two_byte', [['é'.repeat(25), 'v']]],
  ['name_51_bytes_two_byte', [['a'.repeat(49) + 'é', 'v']]],
  ['name_52_bytes_two_byte', [['é'.repeat(26), 'v']]],
  ['value_0_bytes', [['email', '']]],
  ['value_1_byte', [['email', 'b']]],
  ['value_500_bytes', [['email', 'b'.repeat(500)]]],
  ['value_501_bytes', [['email', 'b'.repeat(501)]]],
  ['value_500_bytes_two_byte', [['email', 'é'.repeat(250)]]],
  ['value_501_bytes_two_byte', [['email', 'b'.repeat(499) + 'é']]],
  ['unsafe_proto', [['email', 'b'], ['__proto__', 'x']]],
  ['unsafe_constructor', [['constructor', 'x']]],
  ['unsafe_prototype', [['prototype', 'x']]],
  ['unsafe_beside_33', [...many(33), ['constructor', 'x']]],
  ['two_faults_index_value_then_name', [['a'.repeat(51), 'v'], ['7', '']]],
  ['two_faults_index_value_long_then_value', [['x', ''], ['3', 'y'.repeat(501)]]],
  ['two_faults_in_insertion_order', [['a'.repeat(51), 'v'], ['email', '']]]
]

const objectOf = (pairs) => {
  const o = {}
  for (const [k, v] of pairs) {
    Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true })
  }
  return o
}
const outcome = (fn) => {
  try {
    return { accepted: fn() }
  } catch (e) {
    return { refused: { name: e.name, code: e.code ?? null, message: e.message } }
  }
}
const outcomeAsync = async (fn) => {
  try {
    return { accepted: await fn() }
  } catch (e) {
    return { refused: { name: e.name, code: e.code ?? null, message: e.message } }
  }
}

// The wallet double: every call counted, empty answers.
const double = () => {
  const calls = {}
  const received = {}
  const count = (name, args) => { calls[name] = (calls[name] ?? 0) + 1; received[name] = args }
  const wallet = {
    calls,
    received,
    // The key received recorded under `subject` (the scanners' key-name rule)
    discoverByIdentityKey: async (args) => { count('discoverByIdentityKey', { subject: args.identityKey, members: Object.keys(args) }); return { totalCertificates: 0, certificates: [] } },
    discoverByAttributes: async (args) => {
      count('discoverByAttributes', Object.keys(args.attributes).length > 64 ? { attributesCount: Object.keys(args.attributes).length } : { attributes: Object.entries(args.attributes) })
      return { totalCertificates: 0, certificates: [] }
    },
    listOutputs: async (args) => { count('listOutputs', { basket: args.basket }); return { totalOutputs: 0, outputs: [] } }
  }
  for (const name of ['getPublicKey', 'createHmac', 'decrypt', 'verifySignature', 'createSignature', 'encrypt']) {
    wallet[name] = async () => { count(name, null); throw new Error(`bsv-rs#818b recorder: ${name} not expected`) }
  }
  return wallet
}
const door = async (call) => {
  const wallet = double()
  const client = new IdentityClient(new WalletClient(wallet))
  const result = await outcomeAsync(() => call(client))
  return { ...result, calls: wallet.calls, received: wallet.received }
}

const cases = []
for (const [name, subject] of keys) {
  const validator = outcome(() => validateDiscoverByIdentityKeyArgs({ identityKey: subject }).identityKey)
  const without = await door((c) => c.resolveByIdentityKey({ identityKey: subject }, false))
  const withContacts = await door((c) => c.resolveByIdentityKey({ identityKey: subject }, true))
  cases.push({ name, subject, validator, resolve: without, resolve_with_contacts: withContacts })
}
for (const [name, pairs] of attributeMaps) {
  const validator = outcome(() => { validateDiscoverByAttributesArgs({ attributes: objectOf(pairs) }); return true })
  const resolve = await door((c) => c.resolveByAttributes({ attributes: objectOf(pairs) }, false))
  const withContacts = await door((c) => c.resolveByAttributes({ attributes: objectOf(pairs) }, true))
  // A map of more than 64 pairs is recorded by its count and its shape alone.
  const recorded = pairs.length > 64
    ? { count: pairs.length, pattern: 'f<i>=v', extra: pairs.slice(-1)[0][0].startsWith('f') ? null : pairs.slice(-1)[0] }
    : pairs
  cases.push({ name, attributes: recorded, validator, resolve, resolve_with_contacts: withContacts })
}
// `limit` at its edges on both validators (the doors take no limit).
for (const limit of [0, 1, 10000, 10001]) {
  cases.push({
    name: `limit_${limit}`,
    limit,
    subject: G,
    validator: outcome(() => validateDiscoverByIdentityKeyArgs({ identityKey: G, limit }).limit),
    validator_attributes: outcome(() => validateDiscoverByAttributesArgs({ attributes: { email: 'bob' }, limit }).limit)
  })
}
// `Wallet.ts:1012`: the asked subject compared through the validated key.
const subjects = []
for (const [name, subject] of [['subject_padded_spaces', '  ' + G + '  '], ['subject_upper_case', G.toUpperCase()]]) {
  const validated = validateDiscoverByIdentityKeyArgs({ identityKey: subject }).identityKey
  const kept = filterCertificatesByIdentityKey([{ subject: G }], validated).length
  subjects.push({ name, subject, certificate_subject: G, validated, kept })
}

process.stdout.write(JSON.stringify({
  source: 'ts-stack@edf6e03 packages/sdk/src/wallet/validationHelpers.ts:1535-1587, IdentityClient.ts:559-655, WalletClient.ts:505-531; wallet-toolbox/src/utility/identityUtils.ts:247-255 (Wallet.ts:1012); Node ' + process.version,
  generator: G,
  no_point_x: hex64(noPoint),
  cases,
  subjects
}, null, 1) + '\n')
