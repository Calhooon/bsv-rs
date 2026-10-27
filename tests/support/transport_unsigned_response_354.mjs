// The #354 witness: the reference's SimplifiedFetchTransport on a general
// answer without valid BSV authentication.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/transport_unsigned_response_354.mjs \
//     "$W/sdk.mjs" > tests/vectors/transport_unsigned_response_354.json
//
// It serves each case from a local `node:http` server on 127.0.0.1 (an
// ephemeral port, closed at exit), sends one general message through the
// reference's transport (POST /sendMessage, a JSON body) and records the
// words it throws (`#validateResponseAuthentication`, `:220-232`;
// `#createUnauthenticatedResponseError`, `:464-494`) with the server's origin
// written `{url}`, or `null` when the answer reached `onData`. A message is
// written as UTF-8 (`Buffer.from`), so a lone surrogate the preview's cut
// leaves (`:533-534`) is recorded as U+FFFD, the bytes the reference's error
// text has on any wire.
import http from 'http'
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { SimplifiedFetchTransport, PrivateKey, Utils } = await import(pathToFileURL(sdkPath).href)

const identity = new PrivateKey(42).toPublicKey().toString()
const signed = {
  'x-bsv-auth-version': '0.1',
  'x-bsv-auth-identity-key': identity,
  'x-bsv-auth-signature': '3006020101020101'
}
const binary = Array.from({ length: 2000 }, (_, i) => i % 256)

// Each case: its name, status, headers, body bytes and, when given, the
// reason phrase the status line carries (`writeHead(status, reason, ..)`;
// otherwise node's canonical one).
const cases = [
  ['no_auth_headers_json', 200, { 'content-type': 'application/json' }, Utils.toArray('{"ok":true}', 'utf8')],
  ['no_auth_headers_empty_body', 200, {}, []],
  ['signature_missing', 200, { 'content-type': 'text/plain', 'x-bsv-auth-version': '0.1', 'x-bsv-auth-identity-key': identity }, Utils.toArray('half', 'utf8')],
  ['identity_key_missing', 200, { 'x-bsv-auth-version': '0.1', 'x-bsv-auth-signature': '3006020101020101' }, []],
  ['version_blank', 200, { 'x-bsv-auth-version': ' ', 'x-bsv-auth-identity-key': identity, 'x-bsv-auth-signature': '3006020101020101' }, []],
  ['unauthorized_text', 401, { 'content-type': 'text/plain' }, Utils.toArray('no', 'utf8')],
  ['unavailable_no_content_type', 503, {}, Utils.toArray('busy', 'utf8')],
  ['binary_truncated', 200, { 'content-type': 'application/octet-stream' }, binary],
  ['binary_short', 200, {}, [0, 1, 2, 255]],
  ['text_truncated', 200, { 'content-type': 'text/plain' }, Utils.toArray('a'.repeat(1500), 'utf8')],
  ['text_split_pair', 200, { 'content-type': 'text/plain' }, Utils.toArray('x'.repeat(511) + '\u{1F600}' + 'y'.repeat(100), 'utf8')],
  ['text_cut_multibyte', 200, { 'content-type': 'text/plain; charset=utf-8' }, Utils.toArray('a' + '\u{1F600}'.repeat(300), 'utf8')],
  ['bom_and_invalid', 200, { 'content-type': 'text/plain' }, [0xef, 0xbb, 0xbf, 0x68, 0x69, 0xc3, 0x28, 0xf0, 0x9f, 0x98]],
  ['all_three_present', 200, { ...signed, 'content-type': 'text/plain' }, Utils.toArray('signed', 'utf8')],
  ['custom_reason_phrase', 200, {}, Utils.toArray('x', 'utf8'), 'Fine By Me'],
  ['blank_reason_phrase', 401, {}, [], ' '],
  ['latin1_reason_phrase', 401, {}, [], 'Caf\u00e9'],
  ['rate_limited_retry_after', 429, { 'retry-after': '7', 'content-type': 'text/plain' }, Utils.toArray('slow down', 'utf8')],
  ['bad_gateway', 502, {}, []],
  ['unavailable_retry_after', 503, { 'retry-after': '3' }, Utils.toArray('busy', 'utf8')],
  ['gateway_timeout', 504, { 'content-type': 'text/html' }, Utils.toArray('<html>timeout</html>', 'utf8')],
  ['signed_unavailable', 503, { ...signed, 'content-type': 'text/plain' }, Utils.toArray('signed', 'utf8')]
]

const served = new Map(cases.map(([name, status, headers, body, reason]) => [`/${name}`, { status, headers, body, reason }]))
const server = http.createServer((req, res) => {
  req.resume()
  req.on('end', () => {
    const answer = served.get(new URL(req.url, 'http://x').pathname)
    if (answer.reason === undefined) res.writeHead(answer.status, answer.headers)
    else res.writeHead(answer.status, answer.reason, answer.headers)
    res.end(Buffer.from(answer.body))
  })
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`

const sender = new PrivateKey(7).toPublicKey().toString()
function generalMessage (path) {
  const writer = new Utils.Writer()
  writer.write(new Array(32).fill(7))
  const method = Utils.toArray('POST', 'utf8')
  writer.writeVarIntNum(method.length)
  writer.write(method)
  const pathBytes = Utils.toArray(path, 'utf8')
  writer.writeVarIntNum(pathBytes.length)
  writer.write(pathBytes)
  writer.writeVarIntNum(-1)
  const header = [Utils.toArray('content-type', 'utf8'), Utils.toArray('application/json', 'utf8')]
  writer.writeVarIntNum(1)
  for (const part of header) {
    writer.writeVarIntNum(part.length)
    writer.write(part)
  }
  const body = Utils.toArray('{}', 'utf8')
  writer.writeVarIntNum(body.length)
  writer.write(body)
  return {
    version: '0.1',
    messageType: 'general',
    identityKey: sender,
    nonce: Utils.toBase64(new Array(32).fill(1)),
    yourNonce: Utils.toBase64(new Array(32).fill(2)),
    payload: writer.toArray(),
    signature: [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]
  }
}

const recorded = []
for (const [name, status, headers, body, reason] of cases) {
  const transport = new SimplifiedFetchTransport(origin)
  let reached = false
  await transport.onData(async () => { reached = true })
  let refusal = null
  try {
    await transport.send(generalMessage(`/${name}`))
  } catch (e) {
    refusal = Buffer.from(e.message, 'utf8').toString('utf8').split(origin).join('{url}')
  }
  recorded.push({
    name,
    status,
    reason: reason ?? null,
    headers,
    body_hex: Utils.toHex(body),
    refusal,
    reached_on_data: reached
  })
}
server.close()

console.log(JSON.stringify({
  description: 'The reference\'s SimplifiedFetchTransport on a general answer without valid BSV authentication (#354), recorded by tests/support/transport_unsigned_response_354.mjs; {url} is the server\'s origin',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  cases: recorded
}, null, 2))
