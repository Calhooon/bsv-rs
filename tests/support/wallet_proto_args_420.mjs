// Extension of wallet_proto_args_415.mjs; invoke that recorder with --remaining.
// Actual ProtoWallet calls at ts-stack@edf6e03 under Node 22, no copied validators.
import { createHash } from 'node:crypto'

export async function recordRemaining({ ProtoWallet, PrivateKey }, linkageSource) {
  // Fix only entropy and time; every result still comes from the actual wallet.
  let counter = 0
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
    getRandomValues(bytes) {
      for (let offset = 0; offset < bytes.length; offset += 32) {
        const block = createHash('sha256').update(`bsv-rs#420 ${counter++}`).digest()
        bytes.set(block.subarray(0, Math.min(32, bytes.length - offset)), offset)
      }
      return bytes
    }
  } })
  const ActualDate = Date
  globalThis.Date = class extends ActualDate {
    constructor(...args) { super(...(args.length ? args : ['2026-10-28T09:10:00.000Z'])) }
    static now() { return new ActualDate('2026-10-28T09:10:00.000Z').getTime() }
  }
  const wallet = new ProtoWallet(new PrivateKey(42))
  const verifier = new ProtoWallet(new PrivateKey(88))
  const key = new PrivateKey(69).toPublicKey()
  const compressed = key.toString()
  const uncompressed = key.encode(false, 'hex')
  const common = { protocolID: [2, 'wallet tests'], keyID: 'key', counterparty: 'self' }
  const plaintext = [1, 2, 3]
  const { ciphertext } = await wallet.encrypt({ ...common, plaintext })
  const { signature } = await wallet.createSignature({ ...common, data: plaintext })
  const { hmac } = await wallet.createHmac({ ...common, data: plaintext })
  const methods = ['getPublicKey', 'encrypt', 'decrypt',
    'revealCounterpartyKeyLinkage', 'revealSpecificKeyLinkage']
  const cases = []

  function defaults(method) {
    switch (method) {
      case 'encrypt': return { ...common, plaintext }
      case 'decrypt': return { ...common, ciphertext }
      case 'revealCounterpartyKeyLinkage': return { counterparty: compressed, verifier: verifier.keyDeriver.identityKey }
      case 'revealSpecificKeyLinkage': return { ...common, verifier: verifier.keyDeriver.identityKey }
      case 'createSignature': return { ...common, data: plaintext }
      case 'verifySignature': return { ...common, data: plaintext, signature }
      case 'createHmac': return { ...common, data: plaintext }
      case 'verifyHmac': return { ...common, data: plaintext, hmac }
      default: return { ...common }
    }
  }

  async function observe(method, args, result) {
    if (method === 'encrypt') {
      const decoded = await wallet.decrypt({ ...args, ciphertext: result.ciphertext })
      return { ...decoded, ciphertextLength: result.ciphertext.length }
    }
    if (!method.startsWith('reveal')) return result
    const specific = method === 'revealSpecificKeyLinkage'
    const protocolID = specific
      ? [2, `specific linkage revelation ${args.protocolID[0]} ${args.protocolID[1]}`]
      : [2, 'counterparty linkage revelation']
    const keyID = specific ? args.keyID : result.revelationTime
    const receiver = args.verifier === compressed ? new ProtoWallet(new PrivateKey(69)) : verifier
    const encryptionKey = receiver.keyDeriver.deriveSymmetricKey(protocolID, keyID, result.prover)
    return {
      prover: result.prover, verifier: result.verifier, counterparty: result.counterparty,
      ...(specific ? { protocolID: result.protocolID, keyID: result.keyID, proofType: result.proofType } : {}),
      linkage: encryptionKey.decrypt(result.encryptedLinkage),
      proofLength: encryptionKey.decrypt(result.encryptedLinkageProof).length
    }
  }

  async function record(name, method, patch = {}, unrepresentable) {
    const args = { ...defaults(method), ...patch }
    for (const key of Object.keys(args)) if (args[key] === undefined) delete args[key]
    const actual = { ...args }
    for (const field of ['plaintext', 'ciphertext']) {
      const value = actual[field]
      if (value && !Array.isArray(value) && typeof value.length === 'number') {
        actual[field] = new Uint8Array(value.length).fill(value.byte)
      }
    }
    let expected
    try {
      const result = await wallet[method](actual)
      expected = { result }
    } catch (error) { expected = { error: error.message, code: error.code ?? null } }
    if (expected.result !== undefined) expected.observed = await observe(method, actual, expected.result)
    cases.push({ name, method, args, ...(unrepresentable ? { unrepresentable } : {}), expected })
  }

  // #427: retain the result's actual strings as well as the decrypted linkage.
  // A separate selection leaves #420's original 257-case corpus unchanged.
  if (linkageSource) {
    for (const [name, counterparty] of [['self', 'self'], ['anyone', 'anyone'], ['other', compressed]]) {
      await record(name, 'revealSpecificKeyLinkage', { counterparty })
    }
    return {
      source: `${linkageSource}: ProtoWallet.ts revealSpecificKeyLinkage`,
      node: process.version, key: 42, verifierKey: 88, cases
    }
  }

  for (const method of methods) {
    await record('valid', method)
    await record('reason_short', method, { privilegedReason: 'four' })
    await record('reason_long', method, { privilegedReason: 'r'.repeat(51) })
    await record('reason_utf8_long', method, { privilegedReason: 'é'.repeat(26) })
    await record('reason_missing', method, { privileged: true })
    await record('reason_minimum', method, { privileged: true, privilegedReason: 'short' })
    await record('reason_maximum', method, { privileged: true, privilegedReason: 'é'.repeat(25) })
    await record('order_reason_before_missing', method, { privileged: true, privilegedReason: '' })
    await record('privileged_not_boolean', method, { privileged: 1 }, 'privileged is Option<bool>')
    await record('reason_not_string', method, { privilegedReason: 1 }, 'privileged_reason is Option<String>')
    if (!method.startsWith('reveal')) {
      await record('permission_not_boolean', method, { seekPermission: 1 }, 'seek_permission is Option<bool>')
      await record('permission_false', method, { seekPermission: false })
    } else {
      await record('permission_ignored', method, { seekPermission: 1 }, 'linkage args have no seek_permission field; reference ignores it')
    }
    const counterpartyKeys = method === 'revealCounterpartyKeyLinkage'
      ? ['counterparty', 'verifier'] : method === 'revealSpecificKeyLinkage' ? ['counterparty', 'verifier'] : ['counterparty']
    for (const field of counterpartyKeys) {
      const reason = field === 'verifier' || method === 'revealCounterpartyKeyLinkage'
        ? 'PublicKey is an already parsed point; no encoded-key argument' : undefined
      for (const [name, value] of Object.entries({
        odd_hex: 'a', not_hex: 'zz', short_hex: 'aa', long_hex: 'aa'.repeat(34),
        off_curve: '02' + 'ff'.repeat(32), wrong_prefix: '04' + '01'.repeat(32), uncompressed
      })) await record(`${field}_${name}`, method, { [field]: value }, reason)
      await record(`${field}_not_string`, method, { [field]: null }, 'key argument is a typed enum or PublicKey')
      await record(`${field}_compressed`, method, { [field]: compressed })
    }
    if (method === 'revealCounterpartyKeyLinkage') continue
    for (const [name, patch] of Object.entries({
      protocol_minimum: { protocolID: [2, 'short'] }, protocol_maximum: { protocolID: [2, 'a'.repeat(400)] },
      protocol_short: { protocolID: [2, 'four'] }, protocol_long: { protocolID: [2, 'a'.repeat(401)] },
      protocol_utf8_long: { protocolID: [2, 'é'.repeat(201)] },
      protocol_raw_long: { protocolID: [2, ' '.repeat(396) + 'short'] },
      key_empty: { keyID: '' }, key_long: { keyID: 'k'.repeat(801) },
      key_utf8_long: { keyID: 'é'.repeat(401) }, key_maximum: { keyID: 'é'.repeat(400) },
      order_protocol_key_privilege: { protocolID: [2, 'four'], keyID: '', privileged: true },
      order_key_privilege: { keyID: '', privileged: true }
    })) await record(name, method, patch)
    for (const [name, patch, reason] of [
      ['protocol_not_tuple', { protocolID: null }, 'Protocol is a struct'],
      ['security_not_integer', { protocolID: [1.5, 'wallet tests'] }, 'SecurityLevel is an enum'],
      ['security_low', { protocolID: [-1, 'wallet tests'] }, 'SecurityLevel is an enum'],
      ['security_high', { protocolID: [3, 'wallet tests'] }, 'SecurityLevel is an enum'],
      ['protocol_name_not_string', { protocolID: [2, null] }, 'protocol_name is a String'],
      ['key_not_string', { keyID: null }, method === 'getPublicKey' ? 'key_id is Option<String>' : 'key_id is a String']
    ]) await record(name, method, patch, reason)
  }
  for (const [name, patch, reason] of [
    ['identity_only', { identityKey: true, protocolID: undefined, keyID: undefined, counterparty: undefined }],
    ['identity_with_short_protocol', { identityKey: true, protocolID: [2, 'four'] }],
    ['identity_with_long_protocol', { identityKey: true, protocolID: [2, 'a'.repeat(401)] }],
    ['identity_with_empty_key', { identityKey: true, keyID: '' }],
    ['identity_with_long_key', { identityKey: true, keyID: 'k'.repeat(801) }],
    ['identity_with_short_reason', { identityKey: true, privilegedReason: 'four' }],
    ['identity_with_missing_reason', { identityKey: true, privileged: true }],
    ['identity_with_uncompressed_counterparty', { identityKey: true, counterparty: uncompressed }],
    ['missing_protocol', { protocolID: undefined }], ['missing_key', { keyID: undefined }],
    ['missing_protocol_and_key', { protocolID: undefined, keyID: undefined, privileged: true }],
    ['identity_false', { identityKey: false }, 'identity_key false also represents absence; bool cannot distinguish them'],
    ['identity_not_boolean', { identityKey: 1 }, 'identity_key is bool'],
    ['for_self_not_boolean', { forSelf: 1 }, 'for_self is Option<bool>'],
    ['for_self_true', { forSelf: true }]
  ]) await record(name, 'getPublicKey', patch, reason)
  for (const method of ['encrypt', 'decrypt']) {
    const field = method === 'encrypt' ? 'plaintext' : 'ciphertext'
    await record(`${field}_empty`, method, { [field]: [] })
    await record(`${field}_long`, method, { [field]: { length: 268435457, byte: 0 } })
    await record('order_privilege_bytes', method, { privileged: true, [field]: { length: 268435457, byte: 0 } })
    await record(`${field}_not_bytes`, method, { [field]: null }, `${field} is Vec<u8>`)
    await record(`${field}_out_of_range`, method, { [field]: [256] }, `${field} elements are u8`)
  }
  for (const method of ['createSignature', 'verifySignature', 'createHmac', 'verifyHmac']) {
    await record('counterparty_uncompressed', method, { counterparty: uncompressed })
  }
  for (const method of methods) {
    for (const [name, actual] of [
      ['args_null', null], ['args_array', []], ['args_custom_prototype', Object.create({})],
      ['args_too_many_properties', Object.fromEntries(Array.from({ length: 100001 }, (_, i) => [`k${i}`, 0]))],
      ['args_unsafe_key', { ...defaults(method), constructor: 1 }],
      ['args_symbol_key', { ...defaults(method), [Symbol('extra')]: 1 }],
      ['args_accessor', Object.defineProperty(defaults(method), 'keyID', { get: () => 'key' })]
    ]) {
      let expected
      try { expected = { result: await wallet[method](actual) } }
      catch (error) { expected = { error: error.message, code: error.code ?? null } }
      cases.push({ name, method, args: { description: name },
        unrepresentable: 'Rust arguments are owned typed structs, not JS objects', expected })
    }
  }
  process.stdout.write(JSON.stringify({
    source: 'ts-stack@edf6e03: ProtoWallet.ts, validationHelpers.ts:1717-1762 and key checks:182-230,522-535',
    node: process.version, key: 42, verifierKey: 88, cases
  }, null, 2) + '\n')
}
