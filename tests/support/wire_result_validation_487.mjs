// #408's result cases, encoded by the pinned SDK's Writer/Certificate writer.
// No transport or listener: the actual reference transceiver supplies each
// request frame and the verdict on the recorded response. The processor cannot
// emit a violating result because it validates before writing; these codecs
// follow its result-writing sites using the same SDK writer primitives.
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

export async function recordWire487(sdk) {
  const { Utils, Certificate, WalletWireTransceiver } = sdk
  const source = JSON.parse(readFileSync(new URL('../vectors/http_json_result_values_408.json', import.meta.url)))
  const calls = new Set(['createAction', 'signAction', 'listOutputs', 'createSignature',
    'revealCounterpartyKeyLinkage', 'revealSpecificKeyLinkage', 'acquireCertificate',
    'listCertificates', 'proveCertificate'])
  const status = { unproven: 0, sending: 1, failed: 2 }
  const candidates = source.cases.filter(c => calls.has(c.call) && !c.expansion && (!c.mode || c.group === 'row_35') && !c.headers && !c.status)
  // A result with >1M graph entries but every individual collection within
  // the wire's 100,000-entry limit. The stored frame is a repetition recipe.
  candidates.push({ name: 'row_3_listOutputs_graph', group: 'row_3', call: 'listOutputs',
    args: { basket: 'fixtures' }, bodyText: JSON.stringify({ totalOutputs: 6,
      outputs: Array.from({ length: 6 }, (_, i) => ({ outpoint: `${'33'.repeat(32)}.${i}`,
        satoshis: 1, spendable: true, tags: Array(100000).fill('a'), labels: Array(100000).fill('a') })) }) })
  const acquired = source.cases.find(c => c.name === 'acquireCertificate_valid')
  for (const signature of [undefined, Utils.toHex(JSON.parse(source.cases.find(c => c.name === 'createSignature_r_at_order').bodyText).signature)]) {
    const value = JSON.parse(acquired.bodyText)
    value.signature = signature
    candidates.push({ ...acquired, name: 'row_74_acquireCertificate_' + signature, group: 'row_74', bodyText: JSON.stringify(value) })
  }
  const proof = source.cases.find(c => c.name === 'proveCertificate_valid')
  const unsafeArgs = structuredClone(proof.args)
  unsafeArgs.certificate.fields = JSON.parse('{"constructor":"AQ=="}')
  candidates.push({ ...proof, name: 'row_88_proveCertificate_unsafe_request', group: 'row_88', args: unsafeArgs, mode: 'snapshot' })
  for (const call of ['listOutputs', 'listCertificates']) {
    const seed = source.cases.find(c => c.call === call && c.name === call + '_valid')
    const field = call === 'listOutputs' ? 'outputs' : 'certificates'
    candidates.push({ ...seed, name: `row_49_${call}_request_limit`, group: 'row_49', mode: 'result',
      args: { ...seed.args, limit: 10001 }, bodyText: JSON.stringify({ [field]: [], [call === 'listOutputs' ? 'totalOutputs' : 'totalCertificates']: 0 }) })
  }
  const rows = [], excluded = []
  const bytes = (value, encoding) => {
    if (encoding) {
      if (typeof value !== 'string') throw new Error('not a string')
      if (encoding === 'hex' && (value.length % 2 || !/^[0-9a-f]*$/i.test(value))) throw new Error('not hex')
      return Utils.toArray(value, encoding)
    }
    if (!Array.isArray(value) || value.some(v => !Number.isInteger(v) || v < 0 || v > 255)) throw new Error('not bytes')
    return value
  }
  const string = (w, value) => { const b = bytes(value, 'utf8'); w.writeVarIntNum(b.length).write(b) }
  const blob = (w, value, encoding) => { const b = bytes(value, encoding); w.writeVarIntNum(b.length).write(b) }
  const optional = (w, value, write) => value == null ? w.writeVarIntNum(-1) : write(w, value)
  const array = (w, value, write) => {
    if (!Array.isArray(value)) throw new Error('not an array')
    w.writeVarIntNum(value.length)
    value.forEach(v => write(w, v))
  }
  const outpoint = (w, value) => {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}\.(0|[1-9][0-9]*)$/i.test(value)) throw new Error('not a wire outpoint')
    const [id, index] = value.split('.')
    if (Number(index) > 0xffffffff) throw new Error('outpoint exceeds uint32')
    w.write(bytes(id, 'hex')).writeVarIntNum(Number(index))
  }
  const record = (w, value) => {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not a record')
    w.writeVarIntNum(Object.keys(value).length)
    for (const [key, data] of Object.entries(value)) { string(w, key); blob(w, data, 'base64') }
  }
  const cert = value => new Certificate(value.type, value.serialNumber, value.subject,
    value.certifier, value.revocationOutpoint, value.fields, value.signature).toBinary()
  const send = (w, value) => {
    const id = bytes(value.txid, 'hex')
    if (id.length !== 32 || status[value.status] === undefined) throw new Error('not a wire send result')
    w.write(id).writeInt8(status[value.status])
  }
  function frame(call, value) {
    if (value == null || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object')
    const w = new Utils.Writer().writeUInt8(0)
    if (call === 'createAction' || call === 'signAction') {
      for (const name of ['txid', 'tx']) {
        w.writeInt8(value[name] == null ? 0 : 1)
        if (value[name] != null) {
          if (name === 'txid') { const id = bytes(value.txid, 'hex'); if (id.length !== 32) throw new Error('not a txid'); w.write(id) }
          else blob(w, value.tx)
        }
      }
      if (call === 'createAction') optional(w, value.noSendChange, (w, v) => array(w, v, outpoint))
      optional(w, value.sendWithResults, (w, v) => array(w, v, send))
      if (call === 'createAction') {
        w.writeInt8(value.signableTransaction == null ? 0 : 1)
        if (value.signableTransaction != null) {
          blob(w, value.signableTransaction.tx)
          blob(w, value.signableTransaction.reference, 'base64')
        }
      }
    } else if (call === 'listOutputs') {
      if (!Number.isInteger(value.totalOutputs) || value.totalOutputs < 0 || value.totalOutputs > 0xffffffff) throw new Error('not a wire total')
      if (!Array.isArray(value.outputs)) throw new Error('not outputs')
      w.writeVarIntNum(value.totalOutputs)
      optional(w, value.BEEF, blob)
      for (const output of value.outputs) {
        outpoint(w, output.outpoint)
        if (!Number.isInteger(output.satoshis) || output.satoshis < 0) throw new Error('not unsigned satoshis')
        w.writeVarIntNum(output.satoshis)
        optional(w, output.lockingScript, (w, v) => blob(w, v, 'hex'))
        optional(w, output.customInstructions, string)
        for (const name of ['tags', 'labels']) optional(w, output[name], (w, v) => array(w, v, string))
      }
    } else if (call === 'createSignature') w.write(bytes(value.signature))
    else if (call.startsWith('reveal')) {
      for (const name of ['prover', 'verifier', 'counterparty']) {
        const key = bytes(value[name], 'hex'); if (key.length !== 33) throw new Error('not a key'); w.write(key)
      }
      if (call === 'revealCounterpartyKeyLinkage') string(w, value.revelationTime)
      else {
        if (!Array.isArray(value.protocolID) || value.protocolID.length !== 2 || !Number.isInteger(value.protocolID[0])) throw new Error('not protocol')
        w.writeUInt8(value.protocolID[0]); string(w, value.protocolID[1]); string(w, value.keyID)
      }
      blob(w, value.encryptedLinkage); blob(w, value.encryptedLinkageProof)
      if (call === 'revealSpecificKeyLinkage') {
        if (!Number.isInteger(value.proofType) || value.proofType < 0 || value.proofType > 255) throw new Error('not proofType')
        w.writeUInt8(value.proofType)
      }
    } else if (call === 'acquireCertificate') w.write(cert(value))
    else if (call === 'listCertificates') {
      if (!Number.isInteger(value.totalCertificates) || value.totalCertificates < 0 || value.totalCertificates > 0xffffffff) throw new Error('not a wire total')
      if (!Array.isArray(value.certificates)) throw new Error('not certificates')
      w.writeVarIntNum(value.totalCertificates)
      for (const entry of value.certificates) {
        const certificate = cert(entry); w.writeVarIntNum(certificate.length).write(certificate)
        w.writeUInt8(entry.keyring == null ? 0 : 1)
        if (entry.keyring != null) record(w, entry.keyring)
        blob(w, entry.verifier ?? '', 'hex')
      }
    } else record(w, value.keyringForVerifier)
    return w.toArray()
  }
  const hash = bytes => createHash('sha256').update(Uint8Array.from(bytes)).digest('hex')
  function compress(response) {
    const text = Utils.toHex(response), chunk = '0161'.repeat(100000)
    if (!text.includes(chunk)) return { response_hex: text }
    const parts = text.split(chunk), response_parts = []
    for (let i = 0; i < parts.length; i++) {
      response_parts.push({ hex: parts[i], repeat: 1 })
      if (i + 1 < parts.length) response_parts.push({ hex: '0161', repeat: 100000 })
    }
    return { response_parts }
  }
  for (const c of candidates) {
    let response
    try { response = frame(c.call, JSON.parse(c.bodyText)) }
    catch (e) { excluded.push({ name: c.name, reason: 'unrepresentable: ' + e.message }); continue }
    let request, value, error
    const client = new WalletWireTransceiver({ async transmitToWallet(frame) { request = Utils.toHex(frame); return response } })
    try {
      if (c.mode === 'snapshot') sdk.snapshotWalletResultRequest(c.call, structuredClone(c.args))
      else if (c.mode === 'result') sdk.validateWalletResult(c.call, JSON.parse(c.bodyText), sdk.snapshotWalletResultRequest(c.call, structuredClone(c.args)))
      else value = await client[c.call](structuredClone(c.args), 'fixtures.invalid')
    } catch (e) { error = { message: e.message, code: e.code ?? null } }
    if (!request && !['row_35', 'row_49', 'row_88'].includes(c.group)) { excluded.push({ name: c.name, reason: 'request: ' + error?.message }); continue }
    const row = c.group.startsWith('row_') ? Number(c.group.slice(4))
      : c.group === 'signature' ? 14 : c.name === 'createAction_exclusive_signable' ? 31 : c.group === 'certificates' ? 74 : 0
    rows.push({ name: c.name, row, call: c.call, args: c.args,
      request_hex: request ?? null, frame_sha256: hash(response), ...compress(response), reference: error ?? { accepted: true } })
  }
  // A complete WriterUint8Array frame one byte above the raw response cap.
  // Keep its repeated payload as a recipe, never a 512 MiB hex file.
  const cap = 256 * 1024 * 1024
  const w = new Utils.WriterUint8Array().writeUInt8(0).write(new Uint8Array(cap))
  let error
  const oversized = w.toUint8Array()
  const client = new WalletWireTransceiver({ async transmitToWalletUint8Array() { return oversized } })
  try { await client.createSignature(source.cases.find(c => c.call === 'createSignature').args, 'fixtures.invalid') }
  catch (e) { error = { message: e.message, code: e.code ?? null } }
  rows.push({ name: 'row_4_createSignature_frame_cap', row: 4, call: 'createSignature',
    args: source.cases.find(c => c.call === 'createSignature').args, request_hex: null,
    response_parts: [{ hex: '00', repeat: cap + 1 }], frame_sha256: hash(oversized), reference: error })
  // Certificate.fromBinary's whole-frame cap, including the 164-byte prefix.
  // Every field is within 1 MiB; the total is 16 MiB + 1 certificate bytes.
  const template = JSON.parse(acquired.bodyText)
  const cw = new Utils.WriterUint8Array().writeUInt8(0)
  for (const name of ['type', 'serialNumber']) cw.write(bytes(template[name], 'base64'))
  for (const name of ['subject', 'certifier']) cw.write(bytes(template[name], 'hex'))
  outpoint(cw, template.revocationOutpoint)
  cw.writeVarIntNum(16)
  const parts = [{ hex: Utils.toHex(cw.toUint8Array()), repeat: 1 }]
  for (let i = 0; i < 16; i++) {
    const length = 1048576 - (i === 15 ? 315 : 0)
    const h = new Utils.WriterUint8Array()
    string(h, `f${String(i).padStart(2, '0')}`)
    h.writeVarIntNum(length)
    parts.push({ hex: Utils.toHex(h.toUint8Array()), repeat: 1 }, { hex: '78', repeat: length })
    cw.write(h.toUint8Array()).write(new Uint8Array(length).fill(0x78))
  }
  const signature = bytes(template.signature, 'hex')
  cw.write(signature)
  parts.push({ hex: Utils.toHex(signature), repeat: 1 })
  const certificateFrame = cw.toUint8Array()
  if (certificateFrame.length !== 16 * 1024 * 1024 + 2) throw new Error('incorrect certificate edge')
  let certificateError
  const certificateClient = new WalletWireTransceiver({ async transmitToWalletUint8Array() { return certificateFrame } })
  try { await certificateClient.acquireCertificate(acquired.args, 'fixtures.invalid') }
  catch (e) { certificateError = { message: e.message, code: e.code ?? null } }
  rows.push({ name: 'row_75_acquireCertificate_entire_frame', row: 75, call: 'acquireCertificate',
    args: acquired.args, request_hex: null, response_parts: parts, frame_sha256: hash(certificateFrame), reference: certificateError })
  return { source: 'ts-stack@edf6e03' , node: process.version,
    recorder: 'http_json_result_values_408.mjs --wire-487', rows, excluded }
}
