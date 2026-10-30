// Node 22.18.0; argument: unmodified ts-stack@edf6e03 SDK bundle from git archive.
// Fake fetch only. Emits the vector; never edits expected values by hand.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node, '22.18.0')
let entropy = 0
Object.defineProperty(globalThis, 'crypto', { value: { getRandomValues (array) {
  for (let offset = 0; offset < array.length; offset += 32) {
    const bytes = createHash('sha256').update(`auth-fetch-423:${entropy++}`).digest()
    array.set(bytes.subarray(0, Math.min(32, array.length - offset)), offset)
  }
  return array
} } })
const sdk = await import(pathToFileURL(process.argv[2]).href)
const { AuthFetch, Peer, ProtoWallet, PrivateKey, Certificate, MasterCertificate, VerifiableCertificate, SimplifiedFetchTransport, Utils, parseKnownTxidsHeader } = sdk
const origin = 'https://auth-fetch-423.invalid'
const key = n => new PrivateKey(n)
const identity = n => key(n).toPublicKey().toString()
const policy = { certifiers: [identity(42)], types: { [Utils.toBase64(Array(32).fill(1))]: ['name'] } }
const nativeTimeout = globalThis.setTimeout
let current
globalThis.setTimeout = (callback, ms, ...args) => {
  current?.waits.push(ms)
  return nativeTimeout(callback, ms >= 10000 ? 200 : ms === 500 ? 5 : ms, ...args)
}
for (const level of ['warn', 'info', 'error']) console[level] = (...args) => current?.logs.push(String(args[0]))
const inflight = new Set()
const originalSend = SimplifiedFetchTransport.prototype.send
SimplifiedFetchTransport.prototype.send = async function (message) {
  current.messages.push(JSON.parse(JSON.stringify(message)))
  const work = originalSend.call(this, message)
  inflight.add(work)
  try { return await work } finally { inflight.delete(work) }
}
const originalOnData = SimplifiedFetchTransport.prototype.onData
SimplifiedFetchTransport.prototype.onData = async function (callback) {
  return originalOnData.call(this, async message => {
    if (current.name === 'certificate_handler' && message.messageType === 'certificateRequest') {
      try { await callback(message) } catch (error) { current.intake_error = error.message }
      // The #416 witness: invoke the actual handler after recording full-intake refusal.
      return current.client.peers[origin].peer.processCertificateRequest(message)
    }
    return callback(message)
  })
}

class Wallet extends ProtoWallet {
  async getPublicKey (args, originator) {
    const result = await super.getPublicKey(args, originator)
    current?.public_key_calls.push({ args, result })
    return result
  }
  async createAction (args) { current.actions.push(args); return { tx: [1, 2, 3] } }
  async listCertificates (args) { current.list_calls.push(args); return { totalCertificates: 1, certificates: [current.held.certificate] } }
  async proveCertificate (args) {
    current.prove_calls.push(args)
    return { keyringForVerifier: current.held.keyring }
  }
}

async function certificate (subject, verifier) {
  const certifier = new ProtoWallet(key(42))
  const { certificateFields, masterKeyring } = await MasterCertificate.createCertificateFields(certifier, identity(subject), { name: 'Alice' })
  const c = new Certificate(Utils.toBase64(Array(32).fill(1)), Utils.toBase64(Array(32).fill(2)), identity(subject), identity(42), '0'.repeat(64) + '.0', certificateFields)
  await c.sign(certifier)
  const ring = await MasterCertificate.createKeyringForVerifier(new ProtoWallet(key(subject)), c.certifier, identity(verifier), c.fields, ['name'], masterKeyring, c.serialNumber)
  return { certificate: JSON.parse(JSON.stringify(c)), keyring: ring,
    shown: new VerifiableCertificate(c.type, c.serialNumber, c.subject, c.certifier, c.revocationOutpoint, c.fields, ring, c.signature) }
}

const sign = async (data, keyID) => (await new ProtoWallet(key(42)).createSignature({ data, keyID, protocolID: [2, 'auth message signature'], counterparty: identity(41) })).signature
function responseFrame (requestId, status, headers, body) {
  const w = new Utils.Writer()
  w.write(Utils.toArray(requestId, 'base64')); w.writeVarIntNum(status)
  const included = Object.entries(headers).filter(([key]) => key === 'authorization' || key.startsWith('x-bsv-') && !key.startsWith('x-bsv-auth'))
    .map(([key, value]) => [key, key === 'content-type' ? value.split(';')[0].trim() : value]).sort(([a], [b]) => a.localeCompare(b))
  w.writeVarIntNum(included.length)
  for (const [key, value] of included) { w.writeVarIntNum(Buffer.byteLength(key)); w.write([...Buffer.from(key)]); w.writeVarIntNum(Buffer.byteLength(value)); w.write([...Buffer.from(value)]) }
  w.writeVarIntNum(body.length || -1); w.write(body)
  return w.toArray()
}

async function record (name, options = {}) {
  process.stderr.write(`recording ${name}\n`)
  entropy = 0
  current = { name, options, public_key_calls: [], waits: [], logs: [], requests: [], messages: [], responses: [], actions: [], list_calls: [], prove_calls: [] }
  const row = current
  row.held = await certificate(41, 42)
  const offered = await certificate(42, 41)
  const serverNonce = Utils.toBase64(Array(48).fill(11))
  let clientNonce
  let calls = 0
  let applicationCalls = 0
  const fetch = async (url, config) => {
    row.requests.push({ url, method: config.method, headers: config.headers, body_hex: config.body == null ? null : Buffer.from(config.body).toString('hex'), redirect: config.redirect })
    if (url.endsWith('/.well-known/auth')) {
      const request = JSON.parse(config.body)
      if (request.messageType === 'initialRequest') {
        if (name.startsWith('fallback')) return new Response('{}', { status: 404 })
        clientNonce = request.initialNonce
        const data = [...Utils.toArray(clientNonce, 'base64'), ...Utils.toArray(serverNonce, 'base64')]
        const response = { version: '0.1', messageType: 'initialResponse', identityKey: identity(42), initialNonce: serverNonce, yourNonce: clientNonce,
          signature: await sign(data, `${clientNonce} ${serverNonce}`) }
        if (name === 'certificate_handshake') response.requestedCertificates = policy
        if (name === 'receive_certificates') response.certificates = [offered.shown]
        row.responses.push({ handshake: response })
        return new Response(JSON.stringify(response))
      }
      assert.equal(request.messageType, name === 'receive_certificates' ? 'certificateRequest' : 'certificateResponse')
      if (request.messageType === 'certificateRequest') {
        const nonce = Utils.toBase64(Array(32).fill(19))
        const certificates = [offered.shown]
        const response = { version: '0.1', messageType: 'certificateResponse', identityKey: identity(42), nonce, initialNonce: serverNonce, yourNonce: clientNonce, certificates,
          signature: await sign([...Buffer.from(JSON.stringify(certificates))], `${nonce} ${clientNonce}`) }
        row.responses.push({ certificate_response: response })
        return new Response(JSON.stringify(response))
      }
      const nonce = Utils.toBase64(Array(32).fill(18))
      const response = { version: '0.1', messageType: 'certificateResponse', identityKey: identity(42), nonce, initialNonce: serverNonce, yourNonce: clientNonce, certificates: [], signature: await sign([...Buffer.from('[]')], `${nonce} ${clientNonce}`) }
      row.responses.push({ certificate_ack: response })
      return new Response(JSON.stringify(response))
    }
    applicationCalls++
    if (name === 'timeout') return new Promise(() => {})
    if (name.startsWith('fallback')) {
      const headers = name.endsWith('_claim') ? { 'x-bsv-pretend': 'yes' } : {}
      return new Response('fallback', { status: name.endsWith('_status') ? 503 : 200, headers })
    }
    if (name === 'payment_network' && applicationCalls > 1) {
      row.responses.push({ fault_status: 503, body_hex: Buffer.from('temporary').toString('hex') })
      return new Response('temporary', { status: 503 })
    }
    const certRequest = ['certificate_http', 'certificate_handler'].includes(name) && applicationCalls === 1
    const paid = name === 'payment' || name === 'payment_exhausted' || name === 'payment_always' || name === 'payment_network' || name.startsWith('payment_bad_')
    const status = paid && (applicationCalls === 1 || name !== 'payment') ? 402 : 200
    const body = [...Buffer.from(status === 402 ? 'pay' : 'answer')]
    const requestId = name === 'mismatch' ? Utils.toBase64(Array(32).fill(44)) : config.headers['x-bsv-auth-request-id']
    const nonce = Utils.toBase64(Array(32).fill(20 + calls++))
    const headers = { 'content-type': 'text/plain; charset=utf-8', 'x-bsv-answer': 'yes' }
    if (status === 402) Object.assign(headers, { 'x-bsv-payment-version': '1.0', 'x-bsv-payment-satoshis-required': '7', 'x-bsv-payment-derivation-prefix': Utils.toBase64([4, 5, 6]), 'x-bsv-payment-known-txids': 'AB'.repeat(32) + ',invalid,' + 'ab'.repeat(32) })
    if (name === 'payment_bad_version') headers['x-bsv-payment-version'] = '2.0'
    if (name === 'payment_bad_amount') headers['x-bsv-payment-satoshis-required'] = '01'
    if (name === 'payment_bad_prefix') delete headers['x-bsv-payment-derivation-prefix']
    const frame = responseFrame(requestId, status, headers, body)
    const signed = certRequest ? [...Buffer.from(JSON.stringify(policy))] : frame
    Object.assign(headers, { 'x-bsv-auth-version': '0.1', 'x-bsv-auth-identity-key': identity(42), 'x-bsv-auth-request-id': requestId,
      'x-bsv-auth-nonce': nonce, 'x-bsv-auth-your-nonce': clientNonce, 'x-bsv-auth-signature': Utils.toHex(await sign(signed, `${nonce} ${clientNonce}`)) })
    if (certRequest) Object.assign(headers, { 'x-bsv-auth-message-type': 'certificateRequest', 'x-bsv-auth-requested-certificates': JSON.stringify(policy) })
    row.responses.push({ status, headers, body_hex: Buffer.from(body).toString('hex'), frame_hex: Buffer.from(frame).toString('hex') })
    return new Response(new Uint8Array(body), { status, headers })
  }
  const client = new AuthFetch(new Wallet(key(41)), name === 'receive_certificates' ? policy : undefined, undefined, undefined, {}, fetch)
  row.client = client
  try {
    if (name.startsWith('fallback_direct')) {
      const response = await client.handleFetchAndValidate(origin + '/resource?q=1', options, {})
      row.result = { status: response.status, headers: Object.fromEntries(response.headers), body_hex: Buffer.from(await response.arrayBuffer()).toString('hex') }
    } else if (name === 'receive_certificates') {
      const certs = await client.sendCertificateRequest(origin + '/ignored', policy)
      row.result_certificates = certs
      row.consumed_certificates = client.consumeReceivedCertificates()
      row.consumed_again = client.consumeReceivedCertificates()
    } else {
      const config = { ...options }
      if (Array.isArray(config.body)) config.body = new Uint8Array(config.body)
      const response = await client.fetch(origin + '/resource?q=1', config)
      row.result = { status: response.status, headers: Object.fromEntries(response.headers), body_hex: Buffer.from(await response.arrayBuffer()).toString('hex') }
    }
  } catch (error) { row.error = error.message }
  if (name === 'certificate_handler') {
    const response = await client.fetch(origin + '/resource?q=1', options)
    row.explicit_retry = { status: response.status, body_hex: Buffer.from(await response.arrayBuffer()).toString('hex') }
  }
  await new Promise(resolve => nativeTimeout(resolve, 0))
  if (name !== 'timeout') await Promise.allSettled([...inflight])
  delete row.client
  process.stderr.write(`${name}: ${row.error ?? 'OK'}\n`)
  return row
}

const cases = []
for (const [name, options] of [
  ['plain', { method: 'POST', headers: { 'X-Bsv-Z': 'last', Authorization: 'test-token', 'Content-Type': 'application/json; charset=utf-8', 'X-Bsv-A': 'first' } }],
  ['mismatch', {}], ['timeout', {}], ['certificate_http', {}], ['certificate_handler', {}], ['certificate_handshake', {}], ['receive_certificates', {}],
  ['body_bytes', { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: [0, 128, 255] }],
  ['body_missing_type', { method: 'POST', body: [1] }], ['body_invalid_utf8', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: [255] }],
  ['payment_network', { retryCounter: 2 }], ['payment_always', {}], ['payment', { labels: ['app:test'] }], ['payment_exhausted', { retryCounter: 1, labels: ['app:test'] }],
  ['counter_zero', { retryCounter: 0 }], ['unsupported_header', { headers: { Accept: 'text/plain' } }],
  ['forbidden_header', { headers: { 'X-Bsv-Auth-test': 'no' } }],
  ['payment_bad_version', {}], ['payment_bad_amount', {}], ['payment_bad_prefix', {}],
  ['fallback', {}], ['fallback_direct', {}], ['fallback_direct_claim', {}], ['fallback_direct_status', {}]
]) { if (!process.env.ONLY || process.env.ONLY === name) cases.push(await record(name, options)) }
current = undefined
const knownInputs = [null, '', 'nope', '\ufeff' + '01'.repeat(32) + '\ufeff', '\u0085' + '01'.repeat(32), 'AB'.repeat(32) + ',invalid, ' + 'ab'.repeat(32) + ', ' + '01'.repeat(32), Array.from({ length: 257 }, (_, i) => i.toString(16).padStart(64, '0')).join(',')]
const known_txids = knownInputs.map(input => ({ input, output: parseKnownTxidsHeader(input) ?? null }))
const parser = new AuthFetch(new ProtoWallet(key(41)), undefined, undefined, undefined, { maxResponseBytes: 8 })
const id = Array(32).fill(7)
const frame = (status, headers, body, length = body.length || -1) => {
  const writer = new Utils.Writer()
  writer.write(id); writer.writeVarIntNum(status); writer.writeVarIntNum(headers.length)
  for (const [k, v] of headers) {
    const key = [...Buffer.from(k)]; const value = [...Buffer.from(v)]
    writer.writeVarIntNum(key.length); writer.write(key); writer.writeVarIntNum(value.length); writer.write(value)
  }
  writer.writeVarIntNum(length); writer.write(body)
  return writer.toArray()
}
const baseline = frame(200, [], [1])
const labels = ['BAUG', 'BAU', 'B', '!', 'BAUG===', '_w==', '\ufeff BAUG \n', 'Bh=='].map(prefix => {
  const row = { prefix, suffix: 'BAUG', caller: ['App'] }
  try { row.result = parser.buildPaymentActionLabels({ labels: row.caller }, prefix, row.suffix) } catch (error) { row.error = error.message }
  return row
})
const parser_inputs = [
  ['accepted', baseline], ['absent_body', frame(204, [], [])], ['zero_body', frame(200, [], [], 0)],
  ['status_below', frame(199, [], [])], ['status_above', frame(600, [], [])],
  ['trailing', [...baseline, 0]], ['body_over', frame(200, [], Array(9).fill(1))],
  ['empty_header', frame(200, [['', 'x']], [])], ['bad_header_name', frame(200, [['a b', 'x']], [])],
  ['bad_header_value', frame(200, [['x', 'a\nb']], [])],
  ['header_non_latin1', frame(200, [['x', '\u0100']], [])],
  ['duplicate_headers', frame(200, [['X-BSV-Test', 'first'], ['x-bsv-test', 'last']], [])],
  ['null_body_status', frame(204, [], [1])],
  ['noncanonical', [...id, 253, 200, 0, 0]],
  ['precision', [...id, 255, ...Array(8).fill(255)]],
  ['header_count', [...id, 200, 253, 1, 2]],
  ['header_name_length', [...id, 200, 1, 253, 1, 4]],
  ['header_value_length', [...id, 200, 1, 1, 120, 253, 1, 128]]
]
for (let n = 0; n < baseline.length; n++) parser_inputs.push([`truncated_${n}`, baseline.slice(0, n)])
const parsing = []
for (const [name, bytes] of parser_inputs) {
  const row = { name, payload_hex: Buffer.from(bytes).toString('hex') }
  try {
    const response = parser.parseAuthenticatedResponse(origin, Utils.toBase64(id), identity(42), bytes)
    row.result = response == null ? null : { status: response.status, headers: Object.fromEntries(response.headers), body_hex: Buffer.from(await response.arrayBuffer()).toString('hex') }
  } catch (error) { row.error = error.message }
  parsing.push(row)
}
process.stdout.write(JSON.stringify({ source: 'ts-stack@edf6e03 AuthFetch.ts (all 1300 lines)', node: process.version, origin, identities: { client: identity(41), server: identity(42) }, policy,
  note: 'Only timers >=10000ms and the 500ms grace are accelerated. certificate_handler records the #416 intake error before invoking the reference handler; its retry is explicit, because AuthFetch does not automatically replay after certificates.', cases, known_txids, parsing, labels }, null, 2) + '\n')
