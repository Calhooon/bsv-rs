// Record the pinned transports, built from git archives outside the checkout:
//   bun build "$OUT/ts-stack/packages/sdk/mod.ts" --target node --format esm --outfile "$OUT/ts-stack.mjs"
//   bun build "$OUT/ts-sdk/mod.ts" --target node --format esm --outfile "$OUT/ts-sdk.mjs"
//   node tests/support/auth_transport_bounds_416.mjs "$OUT/ts-stack.mjs" "$OUT/ts-sdk.mjs"
// Node 22.18.0; fake fetch only. No socket, default URL, or live server.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node, '22.18.0')
const origin = 'https://transport-416.invalid'
const MiB = 1024 * 1024
const cases = []
const add = (family, name, recipe) => cases.push({ family, name, ...recipe })
for (const size of [262143, 262144, 262145]) {
  add('certificate_header', `certificate_ascii_${size}`, { certificate_bytes: size })
}
for (const size of [262144, 262145]) {
  add('certificate_header', `certificate_latin1_${size}`, { certificate_bytes: size, latin1: true })
}
for (const signature of ['MAA=', '0', '300', '0g', '0x30', '30 00', 'é', '00', ' 00 ', 'ABcd', '', '   ']) {
  add('signature', `signature_${JSON.stringify(signature)}`, { signature })
}
for (const size of [2048, 2049, 2050]) add('signature', `signature_${size}_characters`, { signature_chars: size })
add('signature', 'signature_repeated', { extra_headers: [['x-bsv-auth-signature', '00']] })
add('signature', 'signature_refused_before_oversized_certificates', { signature: 'MAA=', certificate_bytes: 262145 })
for (const type of ['certificateRequest', 'CertificateRequest', 'certificateResponse', 'general', '']) {
  add('message_type', `type_${type}`, { message_type: type })
}
for (const size of [MiB - 1, MiB, MiB + 1]) {
  add('body', `handshake_${size}`, { handshake: true, body_bytes: size })
}
add('body', 'handshake_over_limit_404', { handshake: true, body_bytes: MiB + 1, status: 404 })
for (const size of [MiB + 1, 16 * MiB, 16 * MiB + 1]) {
  add('body', `general_${size}`, { body_bytes: size })
}
add('body', 'handshake_declared_oversized', { handshake: true, content_length: String(MiB + 1) })
add('body', 'handshake_invalid_length', { handshake: true, content_length: 'nope' })
for (const size of [256, 257]) add('options', `handshake_limit_256_body_${size}`, { handshake: true, body_bytes: size, options: { maxHandshakeResponseBytes: 256 } })
for (const size of [8, 9]) add('options', `general_limit_8_body_${size}`, { body_bytes: size, options: { maxResponseBytes: 8 } })
add('options', 'handshake_raised_limit', { handshake: true, body_bytes: MiB + 1, options: { maxHandshakeResponseBytes: MiB + 1 } })
for (const size of [31, 32, 33]) add('request_id', `request_id_${size}_bytes`, { request_id: Buffer.alloc(size, 7).toString('base64') })
for (const request_id of ['', '!', 'Bw', Buffer.alloc(32, 7).toString('base64').slice(0, -1), Buffer.alloc(32, 7).toString('base64').slice(0, -2) + 'd=', '_'.repeat(43) + '=']) {
  add('request_id', `request_id_${JSON.stringify(request_id)}`, { request_id })
}
add('request_id', 'request_id_absent', {})
add('request_id', 'request_id_different_from_request', { request_id: Buffer.alloc(32, 8).toString('base64') })
for (const size of [1024, 1025]) add('signed_headers', `signed_name_${size}`, { signed_key_bytes: size })
for (const size of [32768, 32769]) {
  add('signed_headers', `signed_value_${size}`, { signed_value_bytes: size })
  add('signed_headers', `signed_latin1_value_${size}`, { signed_value_bytes: size, latin1: true })
}
for (const size of [512, 513]) add('signed_headers', `signed_count_${size}`, { signed_count: size })
for (const size of [262144, 262145]) add('signed_headers', `signed_total_${size}`, { signed_total_bytes: size })
add('signed_headers', 'signed_authorization_over', { extra_headers: [['authorization', 'x'.repeat(32769)]] })
add('signed_headers', 'unsigned_headers_excluded', { extra_headers: [['unrelated', 'x'.repeat(32769)], ['x-bsv-auth-extra', 'x'.repeat(32769)]] })
add('signed_headers', 'signed_repeated_value_at', { extra_headers: [['x-bsv-repeat', 'a'.repeat(16383)], ['x-bsv-repeat', 'b'.repeat(16383)]] })
add('signed_headers', 'signed_repeated_value_over', { extra_headers: [['x-bsv-repeat', 'a'.repeat(16384)], ['x-bsv-repeat', 'b'.repeat(16383)]] })

function filled (size, latin1) {
  return latin1 ? 'é'.repeat(Math.floor(size / 2)) + 'x'.repeat(size % 2) : 'x'.repeat(size)
}

function headersFor (item, key) {
  const headers = new Headers({ 'x-bsv-auth-version': '0.1', 'x-bsv-auth-identity-key': key, 'x-bsv-auth-signature': '3006020101020101' })
  if (item.certificate_bytes != null) {
    const prefix = '{"certifiers":[],"types":{},"pad":"'
    const text = prefix + filled(item.certificate_bytes - Buffer.byteLength(prefix + '"}'), item.latin1) + '"}'
    assert.equal(Buffer.byteLength(text), item.certificate_bytes)
    headers.set('x-bsv-auth-requested-certificates', text)
  }
  if (item.signature != null) headers.set('x-bsv-auth-signature', item.signature)
  if (item.signature_chars != null) headers.set('x-bsv-auth-signature', 'a'.repeat(item.signature_chars))
  if (item.message_type != null) headers.set('x-bsv-auth-message-type', item.message_type)
  if (item.request_id != null) headers.set('x-bsv-auth-request-id', item.request_id)
  if (item.content_length != null) headers.set('content-length', item.content_length)
  if (item.signed_key_bytes != null) headers.set('x-bsv-' + 'k'.repeat(item.signed_key_bytes - 6), 'v')
  if (item.signed_value_bytes != null) headers.set('x-bsv-value', filled(item.signed_value_bytes, item.latin1))
  for (let i = 0; i < (item.signed_count ?? 0); i++) headers.set(`x-bsv-${String(i).padStart(3, '0')}`, 'v')
  if (item.signed_total_bytes != null) {
    let remaining = item.signed_total_bytes - 8 * 'x-bsv-total-0'.length
    for (let i = 0; i < 8; i++) {
      const size = Math.min(32768, remaining)
      headers.set(`x-bsv-total-${i}`, 'x'.repeat(size))
      remaining -= size
    }
    assert.equal(remaining, 0)
  }
  for (const [name, value] of item.extra_headers ?? []) headers.append(name, value)
  return headers
}

async function record (path, reference) {
  const { SimplifiedFetchTransport, PrivateKey, Utils } = await import(pathToFileURL(path).href)
  const key = new PrivateKey(42).toPublicKey().toString()
  const handshake = { version: '0.1', messageType: 'initialRequest', identityKey: key }
  const writer = new Utils.Writer()
  writer.write(Array(32).fill(7))
  for (const field of ['POST', '/sendMessage']) {
    const bytes = Utils.toArray(field, 'utf8')
    writer.writeVarIntNum(bytes.length)
    writer.write(bytes)
  }
  for (const value of [-1, 0, -1]) writer.writeVarIntNum(value)
  const general = { ...handshake, messageType: 'general', payload: writer.toArray(), signature: [48, 0] }
  const results = []
  for (const item of cases) {
    let body = item.handshake ? JSON.stringify(handshake) : 'signed'
    if (item.body_bytes != null) body = item.handshake ? body + ' '.repeat(item.body_bytes - Buffer.byteLength(body)) : 'a'.repeat(item.body_bytes)
    let cancelled = false
    let offset = 0
    const bytes = Buffer.from(body)
    const stream = new ReadableStream({
      pull (controller) {
        if (offset === bytes.length) return controller.close()
        const end = Math.min(offset + 65536, bytes.length)
        controller.enqueue(bytes.subarray(offset, end))
        offset = end
      },
      cancel () { cancelled = true }
    })
    const transport = new SimplifiedFetchTransport(origin, async (url) => {
      assert.equal(url, origin + (item.handshake ? '/.well-known/auth' : '/sendMessage'))
      return new Response(stream, { status: item.status ?? 200, statusText: item.status === 404 ? 'Not Found' : 'OK', headers: headersFor(item, key) })
    }, item.options ?? {})
    let delivered = null
    await transport.onData(async message => {
      const payload = Buffer.from(message.payload ?? [])
      delivered = { message_type: message.messageType, signature_hex: Buffer.from(message.signature ?? []).toString('hex'), payload_bytes: payload.length, payload_sha256: createHash('sha256').update(payload).digest('hex') }
    })
    let error = null
    try { await transport.send(item.handshake ? handshake : general) } catch (e) {
      error = { name: e.name, message: Buffer.from(e.message).toString('utf8').replaceAll(origin, '{url}') }
    }
    // Long repeated values are input recipes, not copies of the wire data.
    const { extra_headers, ...recipe } = item
    results.push({ ...recipe, ...(extra_headers ? { extra_headers: extra_headers.map(([name, value]) => ({ name, character: value[0], count: value.length })) } : {}), error, delivered, cancelled })
  }
  const option_errors = []
  if (reference === 'ts-stack@edf6e03') {
    for (const name of ['maxResponseBytes', 'maxHandshakeResponseBytes']) {
      for (const value of [0, Number.MAX_SAFE_INTEGER + 1]) {
        try {
          new SimplifiedFetchTransport(origin, async () => { throw new Error('must not fetch') }, { [name]: value })
          assert.fail('expected option refusal')
        } catch (error) { option_errors.push({ name, value, message: error.message }) }
      }
    }
  }
  return { reference, cases: results, option_errors }
}

console.log(JSON.stringify({ node: process.version, description: '#416 pinned SimplifiedFetchTransport bounds; fake fetch with streaming bodies; recipes measured in UTF-8 bytes; {url} is the configured origin', references: [await record(process.argv[2], 'ts-stack@edf6e03'), await record(process.argv[3], 'ts-sdk@9e3ede6b')] }, null, 2))
