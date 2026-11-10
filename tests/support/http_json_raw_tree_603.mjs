// #603: record the pinned reference's HTTPWalletJSON on the raw-tree cases of
// tests/wallet_http_json_raw_tree_603.rs, never handwritten outcomes. The method
// is http_json_result_values_408.mjs's (its lines 1-5):
// Build the unmodified SDK: git archive edf6e03 packages/sdk | tar -x -C "$W"
// (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// Node 22: node tests/support/http_json_raw_tree_603.mjs "$W/sdk.mjs" tests/vectors/http_json_raw_tree_603.json
// The fetch is injected: no URL is contacted and no listener is started.
// A large body stores an expansion recipe: `array` (the item `length` times, a
// JSON array) or `index_object` (`{"0":item,..,"N-1":item}`); its marker occurs
// once, so JS's single replacement and Rust's replace-all expand
// the same bodyText.
import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { HTTPWalletJSON } = sdk

// The accepted seeds the #408 recording holds (its args and its body).
const recorded = JSON.parse(readFileSync(new URL('../vectors/http_json_result_values_408.json', import.meta.url)))
const seed = name => recorded.cases.find(c => c.name === name)
const encrypt = seed('encrypt_valid').args
const signable = seed('createAction_valid')
const signableResult = JSON.parse(signable.bodyText)
if (!signableResult.signableTransaction) throw new Error('createAction_valid carries no signable transaction')
signableResult.signableTransaction.reference = 'AR=='

const marker = '"@@EXPANSION@@"'
const cases = [
  { name: 'c1_dense_byte_array_past_the_node_limit', call: 'getHeight', args: {},
    bodyText: `{"height":1,"extra":${marker}}`, expansion: { marker, kind: 'array', length: 1000001, item: 0 } },
  { name: 'c2_integral_value_above_255', call: 'getHeight', args: {},
    bodyText: `{"height":1,"extra":${marker}}`, expansion: { marker, kind: 'array', length: 1000001, item: 300 } },
  { name: 'c3_non_byte_array_one_property_past', call: 'getHeight', args: {},
    bodyText: `{"height":1,"extra":${marker}}`, expansion: { marker, kind: 'array', length: 999998, item: 'x' } },
  { name: 'c3_non_byte_array_at_the_property_bound', call: 'getHeight', args: {},
    bodyText: `{"height":1,"extra":${marker}}`, expansion: { marker, kind: 'array', length: 999997, item: 'x' } },
  { name: 'c4_index_keyed_object_outside_the_byte_names', call: 'getHeight', args: {},
    bodyText: `{"height":1,"extra":${marker}}`, expansion: { marker, kind: 'index_object', length: 999999, item: 0 } },
  { name: 'c5_escaped_quote', call: 'getVersion', args: {}, bodyText: '{"version":"ab\\"cdefg"}' },
  { name: 'c6_historical_byte_object_raw_path', call: 'encrypt', args: encrypt,
    bodyText: '{"ciphertext":{"0":1,"1":2},"pad":1e400}' },
  { name: 'c7_byte_field_name_unsafe_key', call: 'getHeight', args: {},
    bodyText: '{"height":1,"data":{"__proto__":1}}' },
  { name: 'c8_nested_arrays_raw_path', call: 'getHeight', args: {},
    bodyText: '{"height":1000.0,"pad":[[1],2],"x":1e400}' },
  { name: 'c10_trailing_bits_reference_raw_path', call: 'createAction', args: signable.args,
    bodyText: JSON.stringify(signableResult).replace(/}$/, ',"pad":1e400}') },
  { name: 'c11_negative_zero_byte_raw_path', call: 'encrypt', args: encrypt,
    bodyText: '{"ciphertext":[-0,1.0],"pad":1e400}' },
]

function expand(c) {
  const e = c.expansion
  if (!e) return c.bodyText
  const item = JSON.stringify(e.item)
  const text = e.kind === 'array'
    ? '[' + Array(e.length).fill(item).join(',') + ']'
    : '{' + Array.from({ length: e.length }, (_, i) => `"${i}":${item}`).join(',') + '}'
  return c.bodyText.replace(e.marker, text)
}

// The value the call returns, as the Rust test reads it back.
const pick = {
  getHeight: r => r.height,
  getVersion: r => r.version,
  encrypt: r => Array.from(r.ciphertext),
  createAction: r => r.signableTransaction.reference,
}
for (const c of cases) {
  const text = expand(c)
  const fetch = async () => new Response(text, { status: 200, headers: { 'Content-Type': 'application/json' } })
  const wallet = new HTTPWalletJSON('fixtures.invalid', 'http://127.0.0.1:49151', fetch)
  try {
    const result = await wallet[c.call](structuredClone(c.args))
    c.reference = { accepted: true, value: pick[c.call](result) }
  } catch (error) { c.reference = { error: error.message } }
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, cases }, null, 2) + '\n')
for (const c of cases) console.log(c.name, JSON.stringify(c.reference))
