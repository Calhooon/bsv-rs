// Record #410 from the actual transports, with no listening socket.
// Build each reference from its commit in an external scratch directory:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   bun build "$W/packages/sdk/mod.ts" --target node --format esm --outfile "$W/stack.mjs"
//   git -C ~/bsv/ts-sdk archive 9e3ede6b | tar -x -C "$S"
//   bun build "$S/mod.ts" --target node --format esm --outfile "$S/sdk.mjs"
// Install undici@6.21.2 outside the checkout, matching Node 22.18.0's
// process.versions.undici, then pass its index.js as the third argument.
//   node tests/support/auth_transport_refusal_words_410.mjs \
//     "$W/stack.mjs" "$S/sdk.mjs" "$U/node_modules/undici/index.js"
// Redirects run through Node's native fetch with a MockAgent dispatcher;
// every other response comes from a fake fetch. No URL can reach a network.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'

const [stackPath, sdkPath, undiciPath] = process.argv.slice(2)
assert.equal(process.versions.node, '22.18.0')
assert.equal(process.versions.undici, '6.21.2')
const { MockAgent } = await import(pathToFileURL(undiciPath).href)
const origin = 'https://transport-410.invalid'
const elsewhere = 'https://redirect-410.invalid'
const bodies = [
  'not auth', '', '{', '{"messageType":', '<html>not auth</html>',
  'undefined', 'NaN', '[object Object]', 'x'.repeat(50),
  '{oops}', '{"a" 1}', '{"a":1,}', '[1,]', '[1 2]', '01', '-x',
  '1.', '1e', '1e+', 'true false', 'nul', 'truX',
  '"unterminated', '"a\nb"', '"\\x"', '"\\uZZZZ"',
  '{\n "a": 1,\n bad\n}', '{"😀": 1, bad}',
  '{"a":' + ' '.repeat(40) + 'x}',
  ' '.repeat(50) + 'x',
  '{"a":' + ' '.repeat(40) + 'x' + ' '.repeat(40) + '}',
  '{"a":1', '[1', '"abc\\', '"\\u12',
  '"a\tb"', '[', ']', '"ok" false',
  '{"a":[1,tre,null,"str"],"b":2}',
  '{"a":[1,t3e,null,"str"],"b":2}', 'f"x","y"]:',
  '{"a"::1,true,null,"str"],"b":2}', 'true\r\nx',
  '"\\é"', '"\\Ā"', '"\\😀"', '\uFEFFnot auth',
  '{"a":[1,true,nulz,"3r"],"😀":2}'
]

async function record (sdkPath, reference) {
  const { SimplifiedFetchTransport, PrivateKey, Utils } = await import(pathToFileURL(sdkPath).href)
  const key = new PrivateKey(42).toPublicKey().toString()
  const signed = {
    'x-bsv-auth-version': '0.1', 'x-bsv-auth-identity-key': key,
    'x-bsv-auth-signature': '3006020101020101'
  }
  const handshake = { version: '0.1', messageType: 'initialRequest', identityKey: key }
  const writer = new Utils.Writer()
  writer.write(new Array(32).fill(7))
  for (const field of ['POST', '/sendMessage']) {
    const bytes = Utils.toArray(field, 'utf8')
    writer.writeVarIntNum(bytes.length)
    writer.write(bytes)
  }
  writer.writeVarIntNum(-1)
  writer.writeVarIntNum(0)
  writer.writeVarIntNum(-1)
  const general = { ...handshake, messageType: 'general', payload: writer.toArray(), signature: [48, 0] }
  const cases = [
    { name: 'handshake_404', status: 404, body: 'not found' },
    { name: 'handshake_404_empty', status: 404, body: '' },
    { name: 'handshake_404_signed', status: 404, body: 'not found', headers: signed },
    { name: 'handshake_401', status: 401, body: 'no' },
    { name: 'handshake_429', status: 429, body: 'slow down', headers: { 'retry-after': '7' } },
    { name: 'handshake_503', status: 503, body: '' },
    { name: 'schema_non_auth', status: 200, body: '{"ok":true}' },
    ...bodies.map((body, i) => ({ name: `body_${i}`, status: 200, body })),
    ...['not auth', '{', '{"a":1,}', 'é', ''].map((value, i) => ({
      name: `header_${i}`, general: true, status: 200, body: 'signed',
      headers: { ...signed, 'x-bsv-auth-message-type': 'certificateRequest', 'x-bsv-auth-requested-certificates': value }
    })),
    { name: 'header_on_general', general: true, status: 200, body: 'signed',
      headers: { ...signed, 'x-bsv-auth-requested-certificates': 'not auth' } },
    { name: 'redirect_handshake', status: 307, body: '', redirect: true },
    { name: 'redirect_general', general: true, status: 307, body: '', redirect: true }
  ]
  const recorded = []
  for (const item of cases) {
    const url = origin + (item.general ? '/sendMessage' : '/.well-known/auth')
    const headers = { 'content-type': 'text/plain', ...item.headers }
    const agent = new MockAgent()
    agent.disableNetConnect()
    let redirectOption = null
    const fetchClient = async (input, init) => {
      assert.equal(input, url)
      redirectOption = init.redirect ?? null
      if (!item.redirect) return new Response(item.body, { status: item.status, statusText: {200:'OK',401:'Unauthorized',404:'Not Found',429:'Too Many Requests',503:'Service Unavailable'}[item.status], headers })
      agent.get(origin).intercept({ path: new URL(url).pathname, method: 'POST' })
        .reply(307, '', { headers: { location: elsewhere + new URL(url).pathname } })
      agent.get(elsewhere).intercept({ path: new URL(url).pathname, method: 'POST' })
        .reply(200, JSON.stringify(handshake), { headers: signed })
      return globalThis.fetch(input, { ...init, dispatcher: agent })
    }
    const transport = new SimplifiedFetchTransport(origin, fetchClient)
    let reached = false
    await transport.onData(async () => { reached = true })
    let error = null
    try { await transport.send(item.general ? general : handshake) } catch (e) {
      const chain = []
      for (let cause = e; cause != null; cause = cause.cause) {
        // Match the UTF-8 bytes of the error on a wire, including a context
        // cut through a surrogate pair (one replacement character, #354).
        chain.push({ name: cause.name, message: Buffer.from(cause.message).toString('utf8').split(origin).join('{url}') })
      }
      error = chain
    } finally { await agent.close() }
    recorded.push({ ...item, headers, body_hex: Buffer.from(item.body).toString('hex'), redirect_option: redirectOption, error, reached_on_data: reached })
  }
  return { reference, cases: recorded }
}

console.log(JSON.stringify({
  description: 'Actual SimplifiedFetchTransport refusal words (#410); fake fetch, native Node fetch + MockAgent for redirects; {url} is the configured origin',
  node: process.version, undici: process.versions.undici,
  references: [await record(stackPath, 'ts-stack@edf6e03'), await record(sdkPath, 'ts-sdk@9e3ede6b')]
}, null, 2))
