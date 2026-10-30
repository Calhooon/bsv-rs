// #408: record the pinned reference's HTTPWalletJSON, never handwritten outcomes.
// Build the unmodified SDK: git archive edf6e03 packages/sdk | tar -x -C "$W"
// (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// Node 22: node tests/support/http_json_result_values_408.mjs "$W/sdk.mjs" <output.json>
// The fetch is injected: no URL is contacted and no listener is started.
// Large certificate witnesses store an expansion recipe. Each marker occurs
// once, so JS's first-match replacement and Rust's all-match replacement expand
// the same bodyText, keeping a 16 MiB boundary out of the fixture.
import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { extend432 } from './http_json_pending_432.mjs'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
if (['--wire-487', '--wire-495'].includes(process.argv[2])) {
  const issue = process.argv[2] === '--wire-495' ? '495' : '487'
  const { recordWire487 } = await import('./wire_result_validation_487.mjs')
  const sdk = await import(pathToFileURL(process.argv[3]).href)
  const recording = await recordWire487(sdk, issue === '495')
  writeFileSync(process.argv[4], JSON.stringify(recording, null, 2) + '\n')
  if (process.argv[5]) {
    const path = process.argv[5]
    const source = readFileSync(path, 'utf8').split(`// BEGIN RECORDED #${issue}`)[0]
    const rows = new Set(Array.from(source.matchAll(/row!\([^,]+, (\d+)\)/g), m => Number(m[1])))
    if (issue === '495') rows.add(0)
    const embedded = { source: recording.source, node: recording.node, rows: recording.rows.filter(c => rows.has(c.row)) }
    writeFileSync(path, source + `// BEGIN RECORDED #${issue}\nconst RECORDING: &str = r####"` + JSON.stringify(embedded) + '"####;\n')
  }
  process.exit(0)
}
const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { HTTPWalletJSON } = sdk
const shapes = JSON.parse(readFileSync(new URL('../vectors/wallet_http_json_shapes_105.json', import.meta.url)))
const bytes = JSON.parse(readFileSync(new URL('../vectors/http_json_success_bytes_365.json', import.meta.url)))
const seeds = new Map()
for (const c of shapes.cases) if (!seeds.has(c.call)) seeds.set(c.call, c)
for (const c of bytes.cases) if (!seeds.has(c.call)) seeds.set(c.call, { ...c, result: JSON.parse(c.bodyText) })
const certificate = structuredClone(seeds.get('acquireCertificate').result)
const identity = structuredClone(seeds.get('discoverByIdentityKey').result.certificates[0])
seeds.set('discoverByAttributes', { args: { attributes: { name: 'Fixture' } }, result: { totalCertificates: 1, certificates: [identity] } })
seeds.set('listCertificates', shapes.cases.find(c => c.name === 'listCertificates-one-entry'))
seeds.set('listActions', { args: { labels: [] }, result: { totalActions: 1, actions: [{
  txid: '33'.repeat(32), satoshis: 1, status: 'completed', isOutgoing: false,
  description: 'a history entry', version: 1, lockTime: 0
}] } })
seeds.set('abortAction', { args: { reference: 'UlJSUlJSUlI=' }, result: { aborted: true } })
seeds.set('relinquishOutput', { args: { basket: 'a basket', output: '33'.repeat(32) + '.0' }, result: { relinquished: true } })
for (const [call, result] of Object.entries({
  isAuthenticated: { authenticated: true }, waitForAuthentication: { authenticated: true },
  getHeight: { height: 1 }, getNetwork: { network: 'mainnet' }, getVersion: { version: '1.0.0.0' },
  getHeaderForHeight: { header: '00'.repeat(80) }
})) seeds.set(call, { args: call === 'getHeaderForHeight' ? { height: 1 } : {}, result })

const cases = []
function add(group, call, form, result, args = seeds.get(call).args, expansion) {
  cases.push({ name: `${call}_${form}`, group, call, args: structuredClone(args),
    bodyText: JSON.stringify(result), ...(expansion ? { expansion } : {}) })
}
function changed(call, path, value) {
  const result = structuredClone(seeds.get(call).result)
  const names = path.split('.')
  let holder = result
  for (const name of names.slice(0, -1)) holder = holder[name]
  if (value === undefined) delete holder[names.at(-1)]
  else holder[names.at(-1)] = value
  return result
}
const wrongShapes = [null, 3, 'wrong', false, []]
for (const [call, seed] of seeds) {
  add('containers', call, 'valid', seed.result)
  for (const [i, shape] of wrongShapes.entries()) add('containers', call, `root_${i}`, shape)
}
for (const length of [0, 1, 31, 32, 33]) add('hmac', 'createHmac', `length_${length}`, { hmac: Array(length).fill(7) })
add('hmac', 'createHmac', 'historical_31', { hmac: Object.fromEntries(Array.from({ length: 31 }, (_, i) => [i, i])) })

const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
function integer(n) {
  let text = n.toString(16)
  if (text.length % 2) text = '0' + text
  let value = Array.from(Buffer.from(text, 'hex'))
  if (value[0] & 0x80) value.unshift(0)
  return [2, value.length, ...value]
}
function der(r, s) { const value = [...integer(r), ...integer(s)]; return [48, value.length, ...value] }
const good = der(1n, 1n)
const signatureForms = {
  minimal: good, largest: der(order - 1n, order - 1n), high_s: der(1n, order - 1n),
  empty: [], too_long: Array(73).fill(1), zero_r: der(0n, 1n), zero_s: der(1n, 0n),
  r_at_order: der(order, 1n), s_at_order: der(1n, order),
  padded: [48, 7, 2, 2, 0, 1, 2, 1, 1], negative: [48, 6, 2, 1, 128, 2, 1, 1],
  bad_tag: [49, ...good.slice(1)], bad_length: [48, 7, ...good.slice(2)],
  trailing: [...good, 0], truncated: good.slice(0, -1),
  integer_tag: [48, 6, 3, 1, 1, 2, 1, 1], zero_length: [48, 5, 2, 0, 2, 1, 1],
  long_integer: [48, 39, 2, 34, ...Array(34).fill(1), 2, 1, 1]
}
for (const [form, signature] of Object.entries(signatureForms)) add('signature', 'createSignature', form, { signature })
add('signature', 'createSignature', 'historical', { signature: Object.fromEntries(good.map((v, i) => [i, v])) })

const byteFields = [['encrypt', 'ciphertext'], ['decrypt', 'plaintext'], ['createHmac', 'hmac'],
  ['createSignature', 'signature'], ['createAction', 'signableTransaction.tx'], ['signAction', 'tx'],
  ['listOutputs', 'BEEF'], ...['revealCounterpartyKeyLinkage', 'revealSpecificKeyLinkage']
    .flatMap(call => [[call, 'encryptedLinkage'], [call, 'encryptedLinkageProof']])]
for (const [call, path] of byteFields) add('containers', call, `${path}_null`, changed(call, path, null))
for (const [i, shape] of [null, 3, 'wrong', false, {}, [], [0], [0, 'name', 2]].entries()) {
  add('containers', 'revealSpecificKeyLinkage', `protocol_tuple_${i}`, changed('revealSpecificKeyLinkage', 'protocolID', shape))
}
const completed = shapes.cases.find(c => c.name === 'createAction-completed')
add('containers', 'createAction', 'tx_null', { ...completed.result, tx: null }, completed.args)
add('containers', 'createAction', 'exclusive_signable', {
  ...completed.result, signableTransaction: seeds.get('createAction').result.signableTransaction
}, completed.args)
for (const shape of wrongShapes) add('containers', 'createAction', `signable_${JSON.stringify(shape)}`, changed('createAction', 'signableTransaction', shape))
add('containers', 'signAction', 'signable_null', { ...seeds.get('signAction').result, signableTransaction: null })
for (const call of ['createAction', 'signAction']) {
  for (const field of ['noSendChange', 'sendWithResults']) add('containers', call, `${field}_null`, changed(call, field, null))
}
add('containers', 'createAction', 'sendWith_item_null', changed('createAction', 'sendWithResults', [null]))
for (const [call, field] of [['listActions', 'actions'], ['listOutputs', 'outputs'], ['listCertificates', 'certificates'],
  ['discoverByIdentityKey', 'certificates'], ['discoverByAttributes', 'certificates']]) {
  for (const [i, value] of [undefined, null, 3, 'wrong', {}].entries()) add('containers', call, `${field}_shape_${i}`, changed(call, field, value))
  add('containers', call, `${field}_null_entry`, changed(call, field, [null]))
}
for (const path of ['actions.0.labels', 'actions.0.inputs', 'actions.0.outputs']) add('containers', 'listActions', `${path}_null`, changed('listActions', path, null))
for (const path of ['inputs', 'outputs']) add('containers', 'listActions', `${path}_entry_null`, changed('listActions', `actions.0.${path}`, [null]))
const actionOutput = { satoshis: 1, spendable: true, outputIndex: 0, outputDescription: '', basket: '' }
add('containers', 'listActions', 'output_tags_null', changed('listActions', 'actions.0.outputs', [{ ...actionOutput, tags: null }]))
for (const path of ['tags', 'labels']) add('containers', 'listOutputs', `${path}_null`, changed('listOutputs', `outputs.0.${path}`, null))
for (const path of ['certifierInfo', 'publiclyRevealedKeyring', 'decryptedFields']) {
  for (const call of ['discoverByIdentityKey', 'discoverByAttributes']) add('containers', call, `${path}_null`, changed(call, `certificates.0.${path}`, null))
}
add('containers', 'listCertificates', 'keyring_null', changed('listCertificates', 'certificates.0.keyring', null))
for (const path of ['keyringForVerifier', 'certificate']) add('containers', 'proveCertificate', `${path}_null`, changed('proveCertificate', path, null))
for (const length of [100000, 100001]) {
  add('containers', 'listActions', `labels_count_${length}`,
    changed('listActions', 'actions.0.labels', 'EXPAND_408_ARRAY'), undefined,
    { marker: '"EXPAND_408_ARRAY"', length, array: true, item: 'x' })
}

const certificateForms = {
  valid: {}, bad_signature: { signature: '0102' }, padded_signature: { signature: Buffer.from(signatureForms.padded).toString('hex') },
  zero_signature: { signature: Buffer.from(signatureForms.zero_s).toString('hex') },
  empty_signature: { signature: '' }, odd_signature: { signature: 'a' },
  wrong_type: { type: 'AQ==' }, wrong_serial: { serialNumber: 'AQ==' },
  unpadded_type: { type: certificate.type.replace(/=+$/, '') },
  off_curve: { subject: '02' + 'ff'.repeat(32) }, bad_certifier: { certifier: '04' + '00'.repeat(64) },
  null_fields: { fields: null }, non_string_field: { fields: { name: 1 } },
  empty_field_name: { fields: { '': '' } }, long_field_name: { fields: { ['x'.repeat(51)]: '' } },
  long_utf8_field_name: { fields: { ['é'.repeat(26)]: '' } },
  padded_outpoint: { revocationOutpoint: '33'.repeat(32) + '.01' },
  oversized_outpoint: { revocationOutpoint: '33'.repeat(32) + '.4294967296' },
  extra_outpoint: { revocationOutpoint: '33'.repeat(32) + '.1.2' },
  txid_only: { revocationOutpoint: '33'.repeat(32) },
  maximum_outpoint: { revocationOutpoint: '33'.repeat(32) + '.4294967295' },
  high_s: { signature: Buffer.from(signatureForms.high_s).toString('hex') }
}
for (const call of ['acquireCertificate', 'listCertificates', 'discoverByIdentityKey', 'discoverByAttributes', 'proveCertificate']) {
  for (const [form, changes] of Object.entries(certificateForms)) {
    // Skip the txid-only proveCertificate result: the reference rejects it
    // against the requested certificate. The acquire/prove partial certificate
    // binding row in src/wallet/substrates/CLAUDE.md is still Pending.
    if (call === 'proveCertificate' && form === 'txid_only') continue
    const cert = { ...certificate, ...changes }
    const result = structuredClone(seeds.get(call).result)
    if (call === 'acquireCertificate') Object.assign(result, cert)
    else if (call === 'proveCertificate') result.certificate = cert
    else Object.assign(result.certificates[0], cert)
    // No request-binding error should mask a structurally valid alternate certificate.
    const bindAlternate = call === 'proveCertificate' && ['maximum_outpoint', 'high_s'].includes(form)
    const args = bindAlternate ? { ...seeds.get(call).args, certificate: cert } : seeds.get(call).args
    add('certificate', call, `certificate_${form}`, result, args)
  }
}
const marker = 'EXPAND_408_CERTIFICATE_VALUE'
add('certificate', 'acquireCertificate', 'duplicate_signature_last_wins', certificate)
cases.at(-1).bodyText = JSON.stringify(certificate).replace('"signature":', '"signature":"invalid","signature":')
for (const extra of [-1, 0, 1]) {
  const result = { ...certificate, fields: { name: marker } }
  // 182 bytes: type/serial, two keys, outpoint/index, field count/name,
  // five-byte value length and eight-byte DER signature.
  add('certificate', 'acquireCertificate', `encoded_limit_${extra}`, result, undefined,
    { marker, length: 16 * 1024 * 1024 - 182 + extra })
}

extend432(cases, seeds, sdk)

for (const c of cases) {
  const expansion = c.expansion?.array
    ? JSON.stringify(Array(c.expansion.length).fill(c.expansion.item))
    : 'x'.repeat(c.expansion?.length ?? 0)
  const text = c.expansion ? c.bodyText.replace(c.expansion.marker, expansion) : c.bodyText
  const fetch = async () => new Response(text, { status: c.status ?? 200, headers: { 'Content-Type': 'application/json', ...c.headers } })
  const wallet = new HTTPWalletJSON('fixtures.invalid', 'http://127.0.0.1:49151', fetch)
  try {
    if (c.mode === 'snapshot') sdk.snapshotWalletResultRequest(c.call, structuredClone(c.args))
    else if (c.mode === 'result') sdk.validateWalletResult(c.call, JSON.parse(text), structuredClone(c.args))
    else await wallet[c.call](structuredClone(c.args))
    c.reference = { accepted: true }
  } catch (error) { c.reference = { error: error.message } }
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, cases }, null, 2) + '\n')
const groups = Object.groupBy(cases, c => c.group)
for (const [group, values] of Object.entries(groups)) console.log(group, values.length, 'accepted', values.filter(c => c.reference.accepted).length)
