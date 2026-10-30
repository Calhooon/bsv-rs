// #338 recorder's --bounds-473 mode. Only the unmodified SDK writes wire bytes
// and supplies verdicts. Truncated boundary frames isolate the pre-entry check:
// at the cap they reach the remaining-data check; one past reaches the cap.
export async function recordBounds473(sdk) {
  const { Utils, BigNumber, PrivateKey, WalletWireTransceiver, WalletWireProcessor } = sdk
  const key = PrivateKey.fromString('1'.padStart(64, '0'), 'hex').toPublicKey().toString()
  const zero32 = Array(32).fill(0)
  const writer = () => new Utils.Writer()
  const number = (w, n) => w.writeVarIntBn(new BigNumber(String(n)))
  const nil = w => number(w, (1n << 64n) - 1n)
  const outpoint = w => w.write(zero32).writeVarIntNum(0)
  const action = w => w.write(zero32).writeVarIntNum(0).writeInt8(1).writeInt8(0).writeVarIntNum(0)
  const actionHead = w => { action(w); nil(w); w.writeVarIntNum(1).writeVarIntNum(0) }
  const outputHead = w => { w.writeVarIntNum(0).writeVarIntNum(0); nil(w); w.writeInt8(1).writeVarIntNum(0); nil(w) }
  const walletOutput = w => { outpoint(w); w.writeVarIntNum(0); nil(w); nil(w) }
  const certificate = {
    type: Utils.toBase64(zero32), serialNumber: Utils.toBase64(zero32),
    subject: key, certifier: key, revocationOutpoint: `${'00'.repeat(32)}.0`,
    signature: '3006020101020101', fields: { f: 'AQ==' }
  }
  const args = {
    createAction: { description: 'bound test' },
    signAction: { spends: {}, reference: 'AQ==' },
    listActions: { labels: [] }, listOutputs: { basket: 'bound test' },
    proveCertificate: { certificate, fieldsToReveal: ['f'], verifier: key }, getHeight: {}
  }
  const rows = []
  async function response(name, call, w, reader, offset = 0, callArgs = args[call]) {
    const payload = w.toArray()
    let sent = false
    const client = new WalletWireTransceiver({ async transmitToWallet() { sent = true; return [0, ...payload] } })
    let value = null
    let message = null
    let code = 0
    try { value = await client[call](callArgs, 'fixtures.invalid') } catch (error) {
      message = error.message
      code = error.code ?? null // A local decoder Error is not a coded wallet frame.
    }
    if (!sent) throw new Error(`${name}: argument validation prevented the recorded response: ${message}`)
    rows.push({ name, call, reader, args: callArgs, payload_hex: Utils.toHex(payload.slice(offset)),
      response_hex: Utils.toHex([0, ...payload]), code, message, value })
  }
  const collections = [
    ['create_no_send_change', 'createAction', 'client_create', 100000, w => w.writeInt8(0).writeInt8(0)],
    ['create_send_with_results', 'createAction', 'client_create', 1001, w => { w.writeInt8(0).writeInt8(0); nil(w) }],
    ['sign_send_with_results', 'signAction', 'client_sign', 1001, w => w.writeInt8(0).writeInt8(0)],
    ['action_labels', 'listActions', 'wallet_action', 100000, w => { w.writeVarIntNum(1); action(w) }, 1],
    ['action_inputs', 'listActions', 'wallet_action', 100000, w => { w.writeVarIntNum(1); actionHead(w) }, 1],
    ['action_outputs', 'listActions', 'wallet_action', 100000, w => { w.writeVarIntNum(1); actionHead(w); nil(w) }, 1],
    ['action_output_tags', 'listActions', 'action_output', 100000, w => {
      w.writeVarIntNum(1); actionHead(w); nil(w); w.writeVarIntNum(1); outputHead(w)
    }, 1 + 32 + 1 + 1 + 1 + 1 + 9 + 1 + 1 + 9 + 1],
    ['output_tags', 'listOutputs', 'wallet_output', 100000, w => { w.writeVarIntNum(1); nil(w); walletOutput(w) }, 10],
    ['output_labels', 'listOutputs', 'wallet_output', 100000, w => { w.writeVarIntNum(1); nil(w); walletOutput(w); nil(w) }, 10],
    ['prove_keyring', 'proveCertificate', 'client_prove', 100000, () => {}]
  ]
  for (const [name, call, reader, maximum, prefix, offset = 0] of collections) {
    for (const [edge, count] of [['at', maximum], ['past', maximum + 1], ['short', 1]]) {
      const w = writer(); prefix(w); number(w, count)
      await response(`${name}_${edge}`, call, w, reader, offset)
    }
  }
  // The two existing request readers have full-wallet processor stubs in Rust.
  // Record the real reference processor, then retain the reader's exact slice.
  for (const [name, call, reader, prefix] of [
    ['spends', 2, 'spends', () => {}],
    ['insertion_tags', 5, 'basket', w => { w.writeVarIntNum(0).writeVarIntNum(1).writeVarIntNum(0).writeUInt8(2).writeVarIntNum(0); nil(w) }]
  ]) {
    for (const [edge, count] of [['at', 100000], ['past', 100001], ['short', 1]]) {
      const w = writer(); prefix(w); number(w, count)
      const payload = w.toArray()
      const request = [call, 0, ...payload]
      const processor = new WalletWireProcessor({})
      const result = await processor.transmitToWallet(request)
      const r = new Utils.Reader(result)
      const code = r.readUInt8()
      const message = code === 0 ? null : Utils.toUTF8(r.read(r.readVarIntNum()))
      // BasketInsertion's codec slice starts at its basket, after tx/count/index/protocol.
      rows.push({ name: `${name}_${edge}`, call, reader,
        payload_hex: Utils.toHex(reader === 'basket' ? payload.slice(4) : payload),
        request_hex: Utils.toHex(request), response_hex: Utils.toHex(result), code, message })
    }
  }
  for (const [name, call, reader, prefix, offset] of [
    ['input_satoshis', 'listActions', 'action_input', w => {
      w.writeVarIntNum(1); actionHead(w); w.writeVarIntNum(1); outpoint(w)
    }, 1 + 32 + 1 + 1 + 1 + 1 + 9 + 1 + 1 + 1],
    ['action_output_satoshis', 'listActions', 'action_output', w => {
      w.writeVarIntNum(1); actionHead(w); nil(w); w.writeVarIntNum(1).writeVarIntNum(0)
    }, 1 + 32 + 1 + 1 + 1 + 1 + 9 + 1 + 1 + 9 + 1],
    ['output_satoshis', 'listOutputs', 'wallet_output', w => { w.writeVarIntNum(1); nil(w); outpoint(w) }, 10]
  ]) {
    for (const [edge, n] of [['range_at', 2100000000000000n], ['range_past', 2100000000000001n],
      ['precision_at', (1n << 53n) - 1n], ['precision_past', 1n << 53n], ['sentinel', (1n << 64n) - 1n]]) {
      const w = writer(); prefix(w); number(w, n)
      if (reader === 'action_input') {
        nil(w); nil(w); w.writeVarIntNum(0).writeVarIntNum(0); nil(w)
      } else if (reader === 'action_output') {
        nil(w); w.writeInt8(1).writeVarIntNum(0).writeVarIntNum(0); nil(w); nil(w)
      } else { nil(w); nil(w); nil(w); nil(w) }
      await response(`${name}_${edge}`, call, w, reader, offset)
    }
  }
  for (const [edge, n] of [['lower_at', 1n], ['lower_past', 0n], ['range_at', 4294967295n],
    ['range_past', 4294967296n], ['precision_at', (1n << 53n) - 1n],
    ['precision_past', 1n << 53n], ['sentinel', (1n << 64n) - 1n]]) {
    const w = writer(); number(w, n)
    await response(`height_${edge}`, 'getHeight', w, 'client_height')
  }
  const trailing = writer().writeVarIntNum(0).writeUInt8(0)
  await response('height_trailing', 'getHeight', trailing, 'client_height')
  for (const call of ['listActions', 'listOutputs']) {
    for (const [label, count, total, limit] of [
      ['page_10', 10, 10], ['page_11', 11, 11],
      ['limit_at', 2, 2, 2], ['limit_past', 3, 3, 2],
      ['over_total', 1, 0], ['partial_total', 1, 100], ['empty_total', 0, 4294967295]
    ]) {
      const w = writer().writeVarIntNum(total)
      if (call === 'listOutputs') nil(w)
      for (let i = 0; i < count; i++) {
        if (call === 'listActions') { actionHead(w); nil(w); nil(w) }
        else { w.write(zero32).writeVarIntNum(i).writeVarIntNum(0); nil(w); nil(w); nil(w); nil(w) }
      }
      const callArgs = limit === undefined ? args[call] : { ...args[call], limit }
      await response(`${call}_${label}`, call, w, call === 'listActions' ? 'client_actions' : 'client_outputs', 0, callArgs)
    }
  }
  return { reference: 'ts-stack@edf6e03 (unmodified)', node: process.version,
    recorder: 'wire_originator_338.mjs --bounds-473 (processor requests and transceiver results)', rows }
}
