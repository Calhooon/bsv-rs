// Record #369 from the actual ts-stack@edf6e03 transport under Node 22.18.0.
// Bundle packages/sdk/mod.ts from `git archive edf6e03 packages/sdk` outside
// the checkout, as documented in transport_unsigned_response_354.mjs, then:
//   node tests/support/transport_header_collation_369.mjs "$W/sdk.mjs" \
//     > tests/vectors/transport_header_collation_369.json
// The injected fetch returns an in-memory Response; no network is used.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node, '22.18.0')
const { SimplifiedFetchTransport, PrivateKey, Utils } = await import(pathToFileURL(process.argv[2]).href)
const alphabet = '-0123456789abcdefghijklmnopqrstuvwxyz'
const suffixes = ['', ...alphabet, ...[...alphabet].flatMap(a => [...alphabet].map(b => a + b))]
const names = suffixes.map(suffix => 'x-bsv-' + suffix)
const byBytes = names.slice().sort()
const byLocale = names.slice().sort((a, b) => a.localeCompare(b))
const hash = values => createHash('sha256').update(values.join('\n') + '\n').digest('hex')
assert.deepEqual(byLocale, byBytes)
const rawNames = ['X-BSV-Z', 'x-bsv-a', 'x-bsv-A', 'X-BSV-A', 'x-bsv-0', 'x-bsv-a-a', 'x-bsv-aa']
const rawByteOrder = rawNames.slice().sort()
const rawLocaleOrder = rawNames.slice().sort((a, b) => a.localeCompare(b))
assert.notDeepEqual(rawByteOrder, rawLocaleOrder)
const identity = new PrivateKey(42).toPublicKey().toString()
const required = [
  ['x-bsv-auth-version', '0.1'],
  ['x-bsv-auth-identity-key', identity],
  ['x-bsv-auth-signature', '3006020101020101'],
  ['x-bsv-auth-request-id', Utils.toBase64(new Array(32).fill(7))]
]
const cases = [
  { name: 'brc104_alphabet', subset: 'brc104', names: [...alphabet].map(c => 'X-BSV-' + c.toUpperCase()) },
  { name: 'brc104_case_prefixes_and_exclusions', subset: 'brc104', names: [
    'X-BSV-Z', 'x-BsV-A', 'X-BSV-10', 'x-bsv-2', 'x-bsv-a-a', 'x-bsv-aa',
    'x-bsv-a0', 'Authorization', 'Content-Type', 'x-other', 'x-bsv-auth', 'x-bsv-authextra'
  ] },
  { name: 'http_token_punctuation', subset: 'http_token', names:
    [..."!#$%&'*+-.^_`|~09az"].map(c => 'x-bsv-a' + c) }
]

function general () {
  const writer = new Utils.Writer()
  writer.write(new Array(32).fill(7))
  for (const field of ['POST', '/headers']) {
    const bytes = Utils.toArray(field, 'utf8')
    writer.writeVarIntNum(bytes.length)
    writer.write(bytes)
  }
  writer.writeVarIntNum(-1)
  writer.writeVarIntNum(0)
  writer.writeVarIntNum(-1)
  return { version: '0.1', messageType: 'general', identityKey: identity,
    payload: writer.toArray(), signature: [48, 0] }
}

const recorded = []
for (const item of cases) {
  const headers = [...required, ...item.names.map((name, i) => [name, `value-${i}`])]
  const body = Utils.toArray('headers', 'utf8')
  let delivered
  const transport = new SimplifiedFetchTransport('https://collation-369.invalid', async (url, init) => {
    assert.equal(url, 'https://collation-369.invalid/headers')
    assert.equal(init.method, 'POST')
    return new Response(Buffer.from(body), { status: 200, headers })
  })
  await transport.onData(async message => { delivered = message })
  await transport.send(general())
  assert.ok(delivered)
  const reader = new Utils.Reader(delivered.payload)
  reader.read(32)
  assert.equal(reader.readVarIntNum(), 200)
  const count = reader.readVarIntNum()
  const included = Array.from({ length: count }, () =>
    [Utils.toUTF8(reader.read(reader.readVarIntNum())), Utils.toUTF8(reader.read(reader.readVarIntNum()))])
  assert.deepEqual(included.map(([name]) => name), included.map(([name]) => name).sort((a, b) => a.localeCompare(b)))
  if (item.subset === 'http_token') {
    assert.notDeepEqual(included.map(([name]) => name), included.map(([name]) => name).sort())
  }
  recorded.push({ name: item.name, subset: item.subset, status: 200, headers,
    body_hex: Utils.toHex(body), included_headers: included, payload_hex: Utils.toHex(delivered.payload) })
}

const invalidNames = ['x-bsv-é', 'x-bsv-Ā'].map(name => {
  assert.throws(() => new Headers([[name, 'value']]), TypeError)
  return name
})
console.log(JSON.stringify({
  description: 'Signed response header order from the actual reference transport (#369); generated, never hand-edited',
  reference: 'ts-stack@edf6e03 packages/sdk', node: process.version, icu: process.versions.icu,
  locale: new Intl.Collator().resolvedOptions(),
  measurement: { alphabet, suffix_lengths: [0, 1, 2], count: names.length,
    byte_order_sha256: hash(byBytes), locale_order_sha256: hash(byLocale),
    differing_positions: byBytes.filter((name, i) => name !== byLocale[i]).length,
    raw_case_names: rawNames, raw_byte_order: rawByteOrder, raw_locale_order: rawLocaleOrder,
    rejected_non_ascii_names: invalidNames },
  cases: recorded
}, null, 2))
