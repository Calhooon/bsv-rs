// #609: the seven key calls' argument validators, each recorded at its own
// exported reference site (`ts-stack@edf6e03`, `packages/sdk/src/wallet/validationHelpers.ts`):
//   getPublicKey     validateGetPublicKeyArgs     :1717-1732
//   encrypt          validateWalletEncryptArgs    :1752-1756
//   decrypt          validateWalletDecryptArgs    :1758-1762
//   createHmac       validateCreateHmacArgs       :1764-1768
//   verifyHmac       validateVerifyHmacArgs       :1770-1775
//   createSignature  validateCreateSignatureArgs  :1789-1793
//   verifySignature  validateVerifySignatureArgs  :1795-1804
// over the shared rules (`validateProtocol` :198-205, `validatePrivilege`
// :207-222, `validateEncryptionArgs` :224-230, `validateByteArray` :146-177,
// `validateExclusiveDataAndHash` :1777-1787). Each case records `{ ok: true }`
// or `{ ok: false, message }` (the thrown error's message). Only inputs this
// crate's typed args can hold are recorded: a counterparty, a boolean, a
// security level and a 32-byte hash or HMAC are the types' own (the key text
// is #579's `validate_public_key`, read at `Counterparty::from_hex`).
// A { length, byte } byte-array descriptor expands to a Uint8Array.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-609-key-args-validators/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build src/wallet/validationHelpers.ts --target node --format esm --outfile "$W/vh.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/key_args_validators_609.mjs "$W/vh.mjs" \
//     > tests/vectors/key_args_validators_609.json
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const vh = await import(pathToFileURL(process.argv[2]).href)

const VALIDATORS = {
  getPublicKey: vh.validateGetPublicKeyArgs,
  encrypt: vh.validateWalletEncryptArgs,
  decrypt: vh.validateWalletDecryptArgs,
  createHmac: vh.validateCreateHmacArgs,
  verifyHmac: vh.validateVerifyHmacArgs,
  createSignature: vh.validateCreateSignatureArgs,
  verifySignature: vh.validateVerifySignatureArgs
}

const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
// r = 1, s = 1: the shortest canonical DER signature.
const DER = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
const HASH = Array(32).fill(7)
const OVER = { length: 268435457, byte: 0 }
const base = { protocolID: [2, 'wallet tests'], keyID: 'key', counterparty: 'self' }
const BODY = {
  getPublicKey: {},
  encrypt: { plaintext: [1, 2, 3] },
  decrypt: { ciphertext: [1, 2, 3] },
  createHmac: { data: [1, 2, 3] },
  verifyHmac: { data: [1, 2, 3], hmac: HASH },
  createSignature: { data: [1, 2, 3] },
  verifySignature: { data: [1, 2, 3], signature: DER }
}

// The rules every one of the seven reads, in the reference's order.
const SHARED = [
  ['valid', {}],
  ['counterparty_anyone', { counterparty: 'anyone' }],
  ['counterparty_key', { counterparty: G }],
  ['counterparty_absent', { counterparty: undefined }],
  ['protocol_level_0', { protocolID: [0, 'wallet tests'] }],
  ['protocol_name_short', { protocolID: [2, 'four'] }],
  ['protocol_name_minimum', { protocolID: [2, 'fives'] }],
  ['protocol_name_long', { protocolID: [2, 'p'.repeat(401)] }],
  ['protocol_name_maximum', { protocolID: [2, 'p'.repeat(400)] }],
  ['protocol_name_utf8_long', { protocolID: [2, 'é'.repeat(201)] }],
  ['key_id_empty', { keyID: '' }],
  ['key_id_long', { keyID: 'k'.repeat(801) }],
  ['key_id_maximum', { keyID: 'k'.repeat(800) }],
  ['privileged_without_reason', { privileged: true }],
  ['privileged_with_reason', { privileged: true, privilegedReason: 'short' }],
  ['privileged_false_without_reason', { privileged: false }],
  ['reason_short', { privileged: true, privilegedReason: 'four' }],
  ['reason_long', { privileged: true, privilegedReason: 'r'.repeat(51) }],
  ['reason_maximum', { privileged: true, privilegedReason: 'r'.repeat(50) }],
  ['reason_utf8_long', { privilegedReason: 'é'.repeat(26) }],
  ['reason_short_unprivileged', { privilegedReason: 'four' }],
  ['reason_empty_unprivileged', { privilegedReason: '' }],
  ['reason_unprivileged', { privileged: false, privilegedReason: 'a reason' }],
  ['seek_permission_false', { seekPermission: false }],
  ['order_protocol_before_key_id', { protocolID: [2, 'four'], keyID: '' }],
  ['order_key_id_before_privilege', { keyID: '', privileged: true }]
]

const SPECIFIC = {
  getPublicKey: [
    ['identity_alone', { protocolID: undefined, keyID: undefined, counterparty: undefined, identityKey: true }],
    ['identity_with_fields', { identityKey: true }],
    ['identity_protocol_short', { identityKey: true, protocolID: [2, 'four'] }],
    ['identity_key_id_empty', { identityKey: true, protocolID: undefined, keyID: '' }],
    ['identity_privileged_without_reason', { identityKey: true, privileged: true }],
    ['identity_reason_short', { identityKey: true, privilegedReason: 'four' }],
    ['protocol_absent', { protocolID: undefined }],
    ['key_id_absent', { keyID: undefined }],
    ['protocol_absent_before_privilege', { protocolID: undefined, privileged: true }],
    ['for_self', { forSelf: true }]
  ],
  encrypt: [
    ['plaintext_empty', { plaintext: [] }],
    ['plaintext_over_bound', { plaintext: OVER }],
    ['privilege_before_plaintext', { plaintext: OVER, privileged: true }]
  ],
  decrypt: [
    ['ciphertext_empty', { ciphertext: [] }],
    ['ciphertext_over_bound', { ciphertext: OVER }],
    ['privilege_before_ciphertext', { ciphertext: OVER, privileged: true }]
  ],
  createHmac: [
    ['data_empty', { data: [] }],
    ['data_over_bound', { data: OVER }],
    ['privilege_before_data', { data: OVER, privileged: true }]
  ],
  verifyHmac: [
    ['data_empty', { data: [] }],
    ['data_over_bound', { data: OVER }],
    ['privilege_before_data', { data: OVER, privileged: true }]
  ],
  createSignature: [
    ['hash_alone', { data: undefined, hashToDirectlySign: HASH }],
    ['data_and_hash', { hashToDirectlySign: HASH }],
    ['neither_data_nor_hash', { data: undefined }],
    ['data_empty', { data: [] }],
    ['data_over_bound', { data: OVER }],
    ['privilege_before_exclusivity', { data: undefined, privileged: true }]
  ],
  verifySignature: [
    ['hash_alone', { data: undefined, hashToDirectlyVerify: HASH }],
    ['data_and_hash', { hashToDirectlyVerify: HASH }],
    ['neither_data_nor_hash', { data: undefined }],
    ['data_over_bound', { data: OVER }],
    ['exclusivity_before_signature', { data: undefined, signature: [] }],
    ['signature_empty', { signature: [] }],
    ['signature_over_72', { signature: Array(73).fill(0x30) }],
    ['signature_not_der', { signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x81] }],
    ['signature_s_zero', { signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00] }],
    ['signature_trailing_byte', { signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00] }],
    ['privilege_before_signature', { signature: [], privileged: true }],
    ['for_self', { forSelf: true }]
  ]
}

const expand = v => (v && typeof v === 'object' && !Array.isArray(v) && 'length' in v)
  ? new Uint8Array(v.length).fill(v.byte)
  : v

function prune (args) {
  return Object.fromEntries(Object.entries(args).filter(([, v]) => v !== undefined))
}

const cases = []
for (const [call, validate] of Object.entries(VALIDATORS)) {
  for (const [name, patch] of [...SHARED, ...SPECIFIC[call]]) {
    const args = prune({ ...base, ...BODY[call], ...patch })
    const live = Object.fromEntries(Object.entries(args).map(([k, v]) => [k, expand(v)]))
    let expected
    try {
      validate(live)
      expected = { ok: true }
    } catch (error) {
      expected = { ok: false, message: error.message, code: error.code }
    }
    cases.push({ call, name, args, expected })
  }
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03',
  source: 'packages/sdk/src/wallet/validationHelpers.ts',
  node: process.version,
  cases
}, null, 2) + '\n')
