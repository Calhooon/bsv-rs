// #416 / #426: SimplifiedFetchTransport and the Peer's certificate handler.
// Run with Node 22.18.0 and the git-archive bundles made by the #416 recorder:
// node tests/support/auth_http_certificate_request_416.mjs "$OUT/ts-stack.mjs" "$OUT/ts-sdk.mjs"
// No socket or default URL. The older bundle is recorded for comparison too.
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node, '22.18.0')
const origin = 'https://certificate-request-416.invalid'

async function record (bundle, reference) {
  const { Peer, ProtoWallet, PrivateKey, SimplifiedFetchTransport, Utils } = await import(pathToFileURL(bundle).href)
  const clientKey = new PrivateKey(41)
  const serverKey = new PrivateKey(42)
  const certifier = new PrivateKey(43).toPublicKey().toString()
  const clientIdentity = clientKey.toPublicKey().toString()
  const serverIdentity = serverKey.toPublicKey().toString()
  const types = { [Utils.toBase64(Array(32).fill(7))]: ['name'] }
  const requested = { certifiers: [certifier], types }
  const compact = JSON.stringify(requested)
  const spaced = JSON.stringify(requested, null, 1).replaceAll('\n', ' ')
  const escaped = compact.replace('"types":', '"\\u0074ypes":')
  assert.deepEqual(JSON.parse(spaced), requested)
  assert.deepEqual(JSON.parse(escaped), requested)
  assert.notEqual(escaped, compact)
  const headers = [
    ['property_order', JSON.stringify({ types, certifiers: [certifier] }), 'header'],
    ['extra_property', JSON.stringify({ ...requested, extension: 'kept' }), 'header'],
    ['general_payload_signature', compact, 'payload'],
    // H3/H3b and H5/H5b record the reference verdicts before and after #426.
    ['spaced_header_signature', spaced, 'header'],
    ['spaced_stringified_signature', spaced, 'stringified'],
    ['escaped_header_signature', escaped, 'header'],
    ['escaped_stringified_signature', escaped, 'stringified']
  ]
  const paired = (name, header) => {
    for (const signed of ['header', 'stringified']) headers.push([`${name}_${signed}`, header, signed])
  }
  paired('426_whitespace', `{ "types" : ${JSON.stringify(types)}, "certifiers" : [${JSON.stringify(certifier)}] }`)
  paired('426_reordered_keys', JSON.stringify({ types, certifiers: [certifier] }))
  paired('426_escaped_string', compact.replace('"name"', '"n\\u0061me"'))
  const extension = text => compact.slice(0, -1) + ',"extension":' + text + '}'
  paired('426_controls', extension('"' + Array.from({ length: 32 }, (_, n) => `\\u${n.toString(16).padStart(4, '0')}`).join('') + '\\u0022\\u005c\\u002f\\u003c\\u003e\\u0026\\u00e9\\u2028\\u2029\\ud83d\\ude00"'))
  paired('426_lone_surrogates', extension('"\\uD800x\\uDC00\\uD800\\uD800\\uDC00"'))
  paired('426_numeric_keys', extension('{"z":0,"10":"ten","2":"two","01":"one","4294967295":"max","0":"zero","a":1}'))
  paired('426_duplicate_keys', extension('{"z":1,"a":2,"\\u007a":3}'))
  const numbers = ['-0.0', '100.0', '1E2', '1e-6', '1e-7', '1e20', '1e21', '9007199254740993', '18446744073709551616', '7.2057594037927933e16', '1e-400', '5e-324', '1.7976931348623157e308', '0.1000000000000000055511151231257827021181583404541015625']
  paired('426_numbers', extension('[' + numbers.join(',') + ']'))
  const cases = []
  for (const [name, header, signed] of headers) {
    const signedText = signed === 'payload' ? null
      : signed === 'stringified' ? JSON.stringify(JSON.parse(header)) : header
    const verified = []
    class RecordingWallet extends ProtoWallet {
      async verifySignature (args, originator) {
        if (args.protocolID[1] === 'auth message signature') verified.push(Buffer.from(args.data).toString('utf8'))
        return await super.verifySignature(args, originator)
      }
    }
    const signer = new ProtoWallet(serverKey)
    const sign = async (data, keyID) => (await signer.createSignature({
      data, protocolID: [2, 'auth message signature'], keyID, counterparty: clientIdentity
    })).signature
    const serverNonce = Utils.toBase64(Array(48).fill(11))
    let clientNonce
    let fetches = 0
    let intakeError = null
    let inboundWork
    const transport = new SimplifiedFetchTransport(origin, async (url, options) => {
      fetches++
      if (url === origin + '/.well-known/auth') {
        const initial = JSON.parse(options.body)
        assert.equal(initial.messageType, 'initialRequest')
        clientNonce = initial.initialNonce
        const data = [...Utils.toArray(clientNonce, 'base64'), ...Utils.toArray(serverNonce, 'base64')]
        return new Response(JSON.stringify({
          version: '0.1', messageType: 'initialResponse', identityKey: serverIdentity,
          initialNonce: serverNonce, yourNonce: clientNonce,
          signature: await sign(data, `${clientNonce} ${serverNonce}`)
        }))
      }
      assert.equal(url, origin + '/request')
      const nonce = Utils.toBase64(Array(32).fill(9))
      const requestId = options.headers['x-bsv-auth-request-id']
      const writer = new Utils.Writer()
      writer.write(Utils.toArray(requestId, 'base64'))
      writer.writeVarIntNum(200)
      writer.writeVarIntNum(0)
      writer.writeVarIntNum(2)
      writer.write(Utils.toArray('hi', 'utf8'))
      const data = signed === 'payload' ? writer.toArray() : Utils.toArray(signedText, 'utf8')
      return new Response('hi', { headers: {
        'x-bsv-auth-version': '0.1', 'x-bsv-auth-identity-key': serverIdentity,
        'x-bsv-auth-message-type': 'certificateRequest',
        'x-bsv-auth-requested-certificates': header,
        'x-bsv-auth-nonce': nonce, 'x-bsv-auth-your-nonce': clientNonce,
        'x-bsv-auth-request-id': requestId,
        'x-bsv-auth-signature': Utils.toHex(await sign(data, `${nonce} ${clientNonce}`))
      } })
    })
    // At edf6e03 HTTP omits initialNonce, which the newer Peer's intake requires.
    // Record that refusal separately, then exercise its unchanged request handler
    // (the path Rust implements) without inventing an HTTP initialNonce header.
    const peerTransport = {
      send: message => transport.send(message),
      onData: callback => transport.onData(message => {
        inboundWork = (async () => {
          if (reference === 'ts-stack@edf6e03' && message.messageType === 'certificateRequest') {
            try { await callback(message) } catch (e) { intakeError = e.message }
            assert.equal(intakeError, 'certificateRequest.initialNonce must be canonical base64.')
            return await peer.processCertificateRequest(message)
          }
          return await callback(message)
        })()
        // The older transport does not await its callback. Await it below.
        inboundWork.catch(() => {})
        return inboundWork
      })
    }
    const peer = new Peer(new RecordingWallet(clientKey), peerTransport, undefined, undefined, false)
    await peer.ready
    const requests = []
    let generalDeliveries = 0
    // Keep callback JSON as text so lone UTF-16 surrogates remain observable
    // in readers whose native strings only represent Unicode scalar values.
    peer.listenForCertificatesRequested((identity, value) => requests.push({ identity, value_text: JSON.stringify(value) }))
    peer.listenForGeneralMessages(() => { generalDeliveries++ })
    const writer = new Utils.Writer()
    writer.write(Array(32).fill(7))
    for (const text of ['POST', '/request']) {
      const bytes = Utils.toArray(text, 'utf8')
      writer.writeVarIntNum(bytes.length)
      writer.write(bytes)
    }
    for (const value of [-1, 0, -1]) writer.writeVarIntNum(value)
    let error = null
    try {
      await peer.toPeer(writer.toArray(), serverIdentity)
      await inboundWork
    } catch (e) { error = e.message }
    assert.equal(fetches, 2, `${reference}: ${name}: ${error}`)
    assert.equal(verified.at(-1), JSON.stringify(JSON.parse(header)), `${reference}: ${name}: ${error}`)
    cases.push({ name, header, signed, signed_text: signedText, intake_error: intakeError, verified_text: verified.at(-1), error, requests, general_deliveries: generalDeliveries })
  }
  assert.equal(cases[0].error, null)
  assert.equal(cases[1].error, null)
  assert.equal(cases[0].requests.length, 1)
  assert.equal(cases[1].requests.length, 1)
  assert.equal(cases[2].error, 'Signature is not valid')
  assert.equal(cases[3].error, 'Signature is not valid')
  assert.equal(cases[4].error, null)
  assert.equal(cases[4].requests.length, 1)
  assert.equal(cases[5].error, 'Signature is not valid')
  assert.equal(cases[6].error, null)
  assert.equal(cases[6].requests.length, 1)
  for (const item of cases.slice(7)) {
    assert.equal(item.error, item.signed_text === item.verified_text ? null : 'Signature is not valid', item.name)
    assert.equal(item.requests.length, item.error == null ? 1 : 0, item.name)
  }
  return { reference, cases }
}

console.log(JSON.stringify({ node: process.version,
  scope: 'The newer HTTP transport omits initialNonce required by Peer intake; record its refusal, then call processCertificateRequest directly. The older Peer uses its normal intake.',
  references: [
  await record(process.argv[2], 'ts-stack@edf6e03'),
  await record(process.argv[3], 'ts-sdk@9e3ede6b')
] }, null, 2))
