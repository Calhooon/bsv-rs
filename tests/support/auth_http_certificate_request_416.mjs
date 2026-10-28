// #416 fold: SimplifiedFetchTransport and the Peer's certificate handler.
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
  const headers = [
    ['property_order', JSON.stringify({ types, certifiers: [certifier] }), 'header'],
    ['extra_property', JSON.stringify({ ...requested, extension: 'kept' }), 'header'],
    ['general_payload_signature', JSON.stringify(requested), 'payload'],
    // A measured residual: JSON.stringify removes whitespace in the reference.
    ['spaced_header_signature', JSON.stringify(requested, null, 1).replaceAll('\n', ' '), 'header']
  ]
  const cases = []
  for (const [name, header, signed] of headers) {
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
      const data = signed === 'payload' ? writer.toArray() : Utils.toArray(header, 'utf8')
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
    peer.listenForCertificatesRequested((identity, value) => requests.push({ identity, value }))
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
    cases.push({ name, header, signed, intake_error: intakeError, verified_text: verified.at(-1), error, requests, general_deliveries: generalDeliveries })
  }
  assert.equal(cases[0].error, null)
  assert.equal(cases[1].error, null)
  assert.equal(cases[0].requests.length, 1)
  assert.equal(cases[1].requests.length, 1)
  assert.equal(cases[2].error, 'Signature is not valid')
  assert.equal(cases[3].error, 'Signature is not valid')
  return { reference, cases }
}

console.log(JSON.stringify({ node: process.version,
  scope: 'The newer HTTP transport omits initialNonce required by Peer intake; record its refusal, then call processCertificateRequest directly. The older Peer uses its normal intake.',
  references: [
  await record(process.argv[2], 'ts-stack@edf6e03'),
  await record(process.argv[3], 'ts-sdk@9e3ede6b')
] }, null, 2))
