// #756: the reference overlay's identity lookup service refuses a whole
// question whose limit, offset, key, certifier, type or attributes it does not
// admit (`ts-stack@edf6e03`
// `packages/overlays/topics/src/identity/IdentityLookupService.ts:74-125`,
// the words in `packages/overlays/topics/src/shared/queryValidation.ts`):
// `limit` 1 to 100, `offset` 0 to 100000, `identityKey` and each
// `certifiers` entry 1 to 66 UTF-8 bytes then `02`/`03` and 64 hex digits
// then a point `PublicKey.fromString` reads, each `certificateTypes` entry 1
// to 44 bytes then base64 of 32 bytes, `attributes` 1 to 32 fields, each
// name a safe MongoDB segment of at most 50 bytes and each value at most 500
// bytes, judged in that order. Each case is the question
// `IdentityClient::query` sends for an `IdentityQuery` (`identityKey`,
// `attributes`, `certificateTypes: [type]`, `certifiers: [certifier]`,
// `limit`, `offset`; the certifier always present, the default SocialCert
// key when the query names none), handed to `lookup` over a stub storage
// manager: recorded is the thrown message verbatim, or the storage method
// the question reached. Each case names the question's `identityKey` text
// `subject` (gitleaks' generic rule reads a hex text under a `...Key` member
// as a credential; these are public points and their malformed forms).
//
// The bundle is tests/support/identity_attributes_751.mjs's (`ref751.mjs`);
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_query_bounds_756.mjs \
//     "$W/ref751.mjs" > tests/vectors/identity_query_bounds_756.json
import { pathToFileURL } from 'url'

const { IdentityLookupService } = await import(pathToFileURL(process.argv[2]).href)

const stub = {}
for (const method of ['findByCertificateSerialNumber', 'findByAttribute', 'findByCertificateType',
  'findByIdentityKey', 'findByCertifier']) {
  stub[method] = async () => ({ reached: method })
}
const service = new IdentityLookupService(stub)

const DEFAULT_CERTIFIER = '02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17'
const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const P_PLUS_1 = '02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30'
const TYPE = Buffer.alloc(32, 1).toString('base64')

const judge = async (fields) => {
  const query = {}
  if (fields.subject !== undefined) query.identityKey = fields.subject
  if (fields.attributes !== undefined) query.attributes = Object.fromEntries(fields.attributes)
  if (fields.certificateType !== undefined) query.certificateTypes = [fields.certificateType]
  query.certifiers = [fields.certifier ?? DEFAULT_CERTIFIER]
  if (fields.limit !== undefined) query.limit = fields.limit
  if (fields.offset !== undefined) query.offset = fields.offset
  try {
    const answer = await service.lookup({ service: 'ls_identity', query })
    return { reached: answer.reached }
  } catch (error) {
    return { refused: error.message }
  }
}

// The least x for which `02 || x` is no point (`PublicKey.fromString` throws)
let noPoint
for (let x = 1n; noPoint === undefined; x++) {
  const key = '02' + x.toString(16).padStart(64, '0')
  if ((await judge({ subject: key })).refused !== undefined) noPoint = key
}

const cases = []
const add = async (name, fields) => cases.push({ name, ...fields, outcome: await judge(fields) })

await add('limit_0', { subject: G, limit: 0 })
await add('limit_1', { subject: G, limit: 1 })
await add('limit_100', { subject: G, limit: 100 })
await add('limit_101', { subject: G, limit: 101 })
await add('offset_0', { subject: G, offset: 0 })
await add('offset_100000', { subject: G, offset: 100000 })
await add('offset_100001', { subject: G, offset: 100001 })
const keys = {
  empty: '', bytes_67: '02' + 'a'.repeat(65), prefix_04: '04' + G.slice(2), upper_case: G.toUpperCase(),
  upper_x: '02' + G.slice(2).toUpperCase(), p_plus_1: P_PLUS_1, no_point: noPoint, not_hex: '02' + 'g'.repeat(64),
  short: G.slice(0, 65), padded: ' ' + G.slice(0, 65), multibyte: '02' + 'é'.repeat(32)
}
for (const [name, key] of Object.entries(keys)) await add(`key_${name}`, { subject: key })
for (const [name, key] of Object.entries(keys)) await add(`certifier_${name}`, { certifier: key })
await add('certifier_g', { certifier: G })
const types = {
  valid: TYPE, bytes_31: Buffer.alloc(31, 1).toString('base64'), bytes_33: Buffer.alloc(33, 1).toString('base64'),
  chars_45: TYPE + 'A', not_base64: '!'.repeat(44), unpadded: TYPE.slice(0, 43), padded: ' ' + TYPE.slice(0, 43),
  empty: ''
}
for (const [name, type] of Object.entries(types)) await add(`type_${name}`, { subject: G, certificateType: type })
const fieldsOf = (n) => Array.from({ length: n }, (_, i) => [`f${i}`, 'v'])
await add('attributes_empty', { attributes: [] })
await add('attributes_32', { attributes: fieldsOf(32) })
await add('attributes_33', { attributes: fieldsOf(33) })
const names = {
  dot: 'a.b', dollar: '$a', nul: 'a\u0000b', bytes_50: 'n'.repeat(50), bytes_51: 'n'.repeat(51),
  two_byte_25: 'é'.repeat(25), two_byte_26: 'é'.repeat(26), empty: '', proto: '__proto__',
  constructor: 'constructor', prototype: 'prototype', any: 'any'
}
for (const [name, field] of Object.entries(names)) await add(`name_${name}`, { attributes: [[field, 'v']] })
await add('value_500', { attributes: [['email', 'v'.repeat(500)]] })
await add('value_501', { attributes: [['email', 'v'.repeat(501)]] })
await add('value_two_byte_250', { attributes: [['email', 'é'.repeat(250)]] })
await add('value_two_byte_251', { attributes: [['email', 'é'.repeat(251)]] })
await add('value_empty', { attributes: [['email', '']] })
await add('two_faults_limit_then_key', { subject: '', limit: 0 })
await add('two_faults_offset_then_key', { subject: '', offset: 100001 })
await add('two_faults_key_then_certifier', { subject: '', certifier: '' })
await add('two_faults_certifier_then_type', { certifier: '04' + G.slice(2), certificateType: '' })
await add('two_faults_type_then_attributes', { certificateType: '!', attributes: [] })
await add('two_faults_count_then_name', { attributes: [...fieldsOf(32), ['a.b', 'v']] })
await add('two_faults_value_then_name', { attributes: [['email', 'v'.repeat(501)], ['a.b', 'v']] })
await add('two_faults_name_then_value', { attributes: [['a.b', 'v'.repeat(501)]] })
await add('two_faults_index_value_then_name', { attributes: [['a.b', 'v'], ['7', 'v'.repeat(501)]] })
await add('type_beside_attributes', { subject: G, certificateType: TYPE, attributes: [['email', 'bob']] })
// #818: the other compressed tag (`queryValidation.ts:174`, `(?:02|03)`): no
// case above carried an `03` key, so a check admitting `02` alone passed.
await add('key_prefix_03', { subject: '03' + G.slice(2) })
await add('certifier_prefix_03', { certifier: '03' + G.slice(2) })

process.stdout.write(JSON.stringify({
  description: '#756: the reference overlay\'s ls_identity lookup over the question IdentityClient::query sends ' +
    '(a stub storage manager): the thrown message verbatim, or the storage method reached',
  reference: 'ts-stack@edf6e03 packages/overlays/topics/src/identity/IdentityLookupService.ts:74-152; ' +
    'packages/overlays/topics/src/shared/queryValidation.ts',
  node: process.version,
  recorder: 'tests/support/identity_query_bounds_756.mjs',
  default_certifier: DEFAULT_CERTIFIER,
  cases
}, null, 2) + '\n')
