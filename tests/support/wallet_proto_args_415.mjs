// Record the actual ProtoWallet, never a reimplementation of its validators.
// Build outside the checkout, from the pinned clone's commit:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wallet_proto_args_415.mjs "$W/sdk.mjs" \
//     > tests/vectors/wallet_proto_args_415.json
// A { length, byte } byte-array descriptor expands to Uint8Array at invocation;
// it keeps the 256 MiB bound witnesses small on disk. `unrepresentable` rows
// document checks already enforced by Rust's argument types.
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const { ProtoWallet, PrivateKey } = await import(pathToFileURL(process.argv[2]).href)
// #427 records both pinned ProtoWallets using #420's deterministic observations:
//   node wallet_proto_args_415.mjs "$W/ts-stack.mjs" --specific-linkage "$W/ts-sdk.mjs"
if (process.argv[3] === '--specific-linkage') {
  const { recordRemaining } = await import('./wallet_proto_args_420.mjs')
  const current = await recordRemaining({ ProtoWallet, PrivateKey }, 'ts-stack@edf6e03')
  const older = await import(pathToFileURL(process.argv[4]).href)
  const olderReference = await recordRemaining(older, 'ts-sdk@9e3ede6b')
  process.stdout.write(JSON.stringify({ ...current, olderReference }, null, 2) + '\n')
  process.exit(0)
}
// The five remaining methods and encoded-key intake use the same pinned build.
// Add --remaining to record #420 without changing #415's 202-case corpus.
if (process.argv[3] === '--remaining') {
  const { recordRemaining } = await import('./wallet_proto_args_420.mjs')
  await recordRemaining({ ProtoWallet, PrivateKey })
  process.exit(0)
}
const wallet = new ProtoWallet(new PrivateKey(42))
const common = { protocolID: [2, 'wallet tests'], keyID: 'key', counterparty: 'self', data: [1, 2, 3] }
const { signature } = await wallet.createSignature(common)
const { hmac } = await wallet.createHmac(common)
const methods = ['createSignature', 'verifySignature', 'createHmac', 'verifyHmac']
const cases = []

async function record(name, method, patch = {}, unrepresentable) {
  const args = { ...common, ...(method === 'verifySignature' ? { signature } : {}),
    ...(method === 'verifyHmac' ? { hmac } : {}), ...patch }
  for (const key of Object.keys(args)) if (args[key] === undefined) delete args[key]
  const actual = { ...args }
  for (const key of ['data', 'signature', 'hmac', 'hashToDirectlySign', 'hashToDirectlyVerify']) {
    const value = actual[key]
    if (value && !Array.isArray(value) && typeof value.length === 'number') {
      actual[key] = new Uint8Array(value.length).fill(value.byte)
    }
  }
  let expected
  try { expected = { result: await wallet[method](actual) } }
  catch (error) { expected = { error: error.message, code: error.code ?? null } }
  cases.push({ name, method, args, ...(unrepresentable ? { unrepresentable } : {}), expected })
}

for (const method of methods) {
  await record('valid', method)
  await record('empty_data', method, { data: [] })
  await record('protocol_minimum', method, { protocolID: [2, 'short'] })
  await record('protocol_maximum', method, { protocolID: [2, 'a'.repeat(400)] })
  await record('protocol_short', method, { protocolID: [2, 'four'] })
  await record('protocol_long', method, { protocolID: [2, 'a'.repeat(401)] })
  await record('protocol_utf8_long', method, { protocolID: [2, 'é'.repeat(201)] })
  await record('protocol_raw_long_before_normalization', method, { protocolID: [2, ' '.repeat(396) + 'short'] })
  await record('key_empty', method, { keyID: '' })
  await record('key_long', method, { keyID: 'k'.repeat(801) })
  await record('key_utf8_long', method, { keyID: 'é'.repeat(401) })
  await record('reason_short', method, { privilegedReason: 'four' })
  await record('reason_long', method, { privilegedReason: 'r'.repeat(51) })
  await record('reason_utf8_long', method, { privilegedReason: 'é'.repeat(26) })
  await record('reason_missing', method, { privileged: true })
  await record('reason_minimum', method, { privileged: true, privilegedReason: 'short' })
  await record('reason_maximum', method, { privileged: true, privilegedReason: 'é'.repeat(25), seekPermission: false })
  await record('key_maximum', method, { keyID: 'é'.repeat(400) })
  await record('data_long', method, { data: { length: 268435457, byte: 0 } })
  await record('order_protocol_key_privilege_data', method, {
    protocolID: [2, 'four'], keyID: '', privileged: true, data: undefined
  })
  await record('order_key_privilege_data', method, { keyID: '', privileged: true, data: undefined })
  await record('order_privilege_data', method, { privileged: true, data: undefined })
  await record('order_reason_before_missing', method, { privileged: true, privilegedReason: '' })
  await record('protocol_not_tuple', method, { protocolID: null }, 'Protocol is a struct')
  await record('security_not_integer', method, { protocolID: [1.5, 'wallet tests'] }, 'SecurityLevel is an enum')
  await record('security_missing', method, { protocolID: [undefined, 'wallet tests'] }, 'SecurityLevel is an enum')
  await record('security_low', method, { protocolID: [-1, 'wallet tests'] }, 'SecurityLevel is an enum')
  await record('security_high', method, { protocolID: [3, 'wallet tests'] }, 'SecurityLevel is an enum')
  await record('protocol_name_not_string', method, { protocolID: [2, null] }, 'protocol_name is a String')
  await record('key_not_string', method, { keyID: null }, 'key_id is a String')
  await record('counterparty_not_hex', method, { counterparty: 'z1' }, 'Counterparty carries a parsed PublicKey')
  await record('counterparty_not_string', method, { counterparty: null }, 'Counterparty is an enum')
  await record('counterparty_odd_hex', method, { counterparty: 'a' }, 'Counterparty carries a parsed PublicKey')
  await record('counterparty_short_hex', method, { counterparty: 'aa' }, 'Counterparty carries a parsed PublicKey')
  await record('counterparty_long_hex', method, { counterparty: 'aa'.repeat(34) }, 'Counterparty carries a parsed PublicKey')
  await record('counterparty_off_curve', method, { counterparty: '02' + 'ff'.repeat(32) }, 'Counterparty carries a parsed PublicKey')
  await record('privileged_not_boolean', method, { privileged: 1 }, 'privileged is Option<bool>')
  await record('reason_not_string', method, { privilegedReason: 1 }, 'privileged_reason is Option<String>')
  await record('permission_not_boolean', method, { seekPermission: 1 }, 'seek_permission is Option<bool>')
  await record('data_not_bytes', method, { data: null }, 'data is Vec<u8> when present')
  await record('data_out_of_range', method, { data: [256] }, 'data elements are u8')
}

for (const method of ['createSignature', 'verifySignature']) {
  const hash = method === 'createSignature' ? 'hashToDirectlySign' : 'hashToDirectlyVerify'
  await record('data_and_hash_absent', method, { data: undefined })
  await record('data_and_hash_present', method, { [hash]: Array(32).fill(0) })
  await record('direct_hash', method, { data: undefined, [hash]: Array(32).fill(0) })
  await record('hash_wrong_length', method, { data: undefined, [hash]: [0] }, 'hash is Option<[u8; 32]>')
}

const der = (r, s) => [0x30, r.length + s.length + 4, 2, r.length, ...r, 2, s.length, ...s]
const order = Array.from(Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex'))
for (const [name, bytes] of Object.entries({
  empty: [], short: [0x30], wrong_tag: Array.from(Buffer.from('not a signature')),
  length_mismatch: [0x30, 5, 2, 1, 1, 2, 1, 1], wrong_integer_tag: [0x30, 6, 3, 1, 1, 2, 1, 1],
  zero_r: der([0], [1]), zero_s: der([1], [0]), negative_r: der([128], [1]),
  padded_r: der([0, 1], [1]), truncated_s: [0x30, 6, 2, 1, 1, 2, 2, 1],
  order_r: der([0, ...order], [1]), order_s: der([1], [0, ...order]),
  trailing: [0x30, 7, 2, 1, 1, 2, 1, 1, 0], oversized: Array(73).fill(0)
})) await record(`signature_${name}`, 'verifySignature', { signature: bytes })
await record('minimal_canonical_der', 'verifySignature', { signature: der([1], [1]) })
const lastScalar = [...order]
lastScalar[lastScalar.length - 1]--
await record('maximum_canonical_der_high_s', 'verifySignature', { signature: der([0, ...lastScalar], [0, ...lastScalar]) })
await record('canonical_before_derivation', 'verifySignature', { protocolID: [2, 'invalid!name'], signature: [] })
await record('order_exclusive_before_signature', 'verifySignature', { data: undefined, signature: Array(73).fill(0) })
await record('for_self', 'verifySignature', { forSelf: true })
await record('for_self_not_boolean', 'verifySignature', { forSelf: 1 }, 'for_self is Option<bool>')
await record('signature_not_bytes', 'verifySignature', { signature: null }, 'signature is Vec<u8>')
await record('signature_out_of_range', 'verifySignature', { signature: [256] }, 'signature elements are u8')
await record('hmac_wrong_length', 'verifyHmac', { hmac: [0] }, 'hmac is [u8; 32]')

// Record the record/descriptor checks as well. These cannot be Rust structs;
// a description is stored instead of an unserializable or enormous JS object.
async function recordObject(name, actual) {
  let expected
  try { expected = { result: await wallet.verifySignature(actual) } }
  catch (error) { expected = { error: error.message, code: error.code ?? null } }
  cases.push({ name, method: 'verifySignature', args: { description: name },
    unrepresentable: 'Rust arguments are typed structs with owned data fields', expected })
}
await recordObject('args_null', null)
await recordObject('args_array', [])
await recordObject('args_custom_prototype', Object.create({}))
const tooMany = Object.fromEntries(Array.from({ length: 100001 }, (_, i) => [`k${i}`, 0]))
await recordObject('args_too_many_properties', tooMany)
await recordObject('args_unsafe_key', { ...common, signature, constructor: 1 })
await recordObject('args_symbol_key', { ...common, signature, [Symbol('extra')]: 1 })
await recordObject('args_accessor', Object.defineProperty({ ...common, signature }, 'data', { get: () => [1, 2, 3] }))

process.stdout.write(JSON.stringify({
  source: 'ts-stack@edf6e03: packages/sdk/src/wallet/ProtoWallet.ts and validationHelpers.ts',
  node: process.version, key: 42, cases
}, null, 2) + '\n')
