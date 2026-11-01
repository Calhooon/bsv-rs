// Invoked by wire_linkage_calls_406.mjs with an optional third output path.
// Use an unmodified ts-stack@edf6e03 SDK bundle under Node 22; all responses,
// refusal words and codes below are observed from the reference, not supplied.
const cases = () => {
  const host = ['A'.repeat(63), 'B'.repeat(63), 'C'.repeat(63), 'D'.repeat(52)].join('.')
  return [
    ['length-251', host + ':655350'],
    ['length-255', host + ':6553500000'],
    ['length-256', host + ':65535000000'],
    ['length-250-with-port', host + ':65535'],
    ['padded-host-with-port', ' \uFEFFExample.COM:0080\t'],
    ['invalid-host', 'bad_host.example'],
    ['blank', '   '],
    ['multibyte-length-251', 'é'.repeat(125) + 'a'],
    ['empty', '']
  ]
}

async function processorCase({ WalletWireProcessor, Utils }, name, originator, rawRequest) {
  const observed = []
  const processor = new WalletWireProcessor({
    async getVersion(_args, originator) {
      observed.push(originator)
      return { version: 'v-1.0.0' }
    }
  })
  const bytes = Utils.toArray(originator, 'utf8')
  const request = rawRequest ?? (name === 'length-251-truncated' ? [28, 251] : [28, bytes.length, ...bytes])
  const response = await processor.transmitToWallet(request)
  const reader = new Utils.Reader(response)
  const code = reader.readUInt8()
  const message = code === 0 ? null : Utils.toUTF8(reader.read(reader.readVarIntNum()))
  return { name, originator, request_hex: Utils.toHex(request),
    response_hex: Utils.toHex(response), code, message, observed }
}

async function transceiverCase({ WalletWireTransceiver, WalletWireProcessor, Utils }, name, originator) {
  const frames = []
  const observed = []
  const processor = new WalletWireProcessor({
    async getVersion(_args, originator) {
      observed.push(originator)
      return { version: 'v-1.0.0' }
    }
  })
  const client = new WalletWireTransceiver({
    async transmitToWallet(frame) {
      frames.push(Utils.toHex(frame))
      return await processor.transmitToWallet(frame)
    }
  })
  let thrown = null
  try {
    await client.getVersion({}, originator)
  } catch (error) {
    thrown = { name: error.name, code: error.code ?? null, message: error.message }
  }
  return { name, originator, frames, observed, thrown }
}

if (process.argv[2] === '--bounds-473') {
  const { pathToFileURL } = await import('node:url')
  const { writeFileSync } = await import('node:fs')
  const { recordBounds473 } = await import('./wire_bounds_473.mjs')
  const sdk = await import(pathToFileURL(process.argv[3]).href)
  writeFileSync(process.argv[4], JSON.stringify(await recordBounds473(sdk), null, 2) + '\n')
}

if (process.argv[2] === '--send-with-status-590') {
  const { pathToFileURL } = await import('node:url')
  const { writeFileSync } = await import('node:fs')
  const { recordSendWithStatus590 } = await import('./wire_send_with_status_590.mjs')
  const sdk = await import(pathToFileURL(process.argv[3]).href)
  writeFileSync(process.argv[4], JSON.stringify(await recordSendWithStatus590(sdk), null, 2) + '\n')
}

export async function recordOriginators(sdk) {
  const processor = []
  const transceiver = []
  for (const [name, originator] of cases()) {
    // A 256-byte length cannot be represented in the processor's u8 header.
    if (name !== 'length-256') processor.push(await processorCase(sdk, name, originator))
    transceiver.push(await transceiverCase(sdk, name, originator))
  }
  processor.push(await processorCase(sdk, 'length-251-truncated', ''))
  // #458: bytes that cannot come from encoding an originator string, and a
  // short read within the accepted length bound. Let the processor supply
  // the error code and words, including the runtime's fatal UTF-8 message.
  processor.push(await processorCase(sdk, 'invalid-utf8', '', [28, 1, 0xff]))
  processor.push(await processorCase(sdk, 'length-250-truncated', 'a', [28, 250, 0x61]))
  // #471: record the strict decoder's output before the processor validates
  // it, as well as the wallet's normalized originator (or refusal words).
  for (const [name, originator] of [
    ['bom-only', '\uFEFF'],
    ['bom-before-host', '\uFEFFa.b'],
    ['two-boms-before-host', '\uFEFF\uFEFFa.b'],
    ['bom-after-host', 'a.b\uFEFF']
  ]) {
    processor.push({
      ...await processorCase(sdk, name, originator),
      decoded_originator: sdk.Utils.toUTF8Strict(sdk.Utils.toArray(originator, 'utf8'))
    })
  }
  // #458 fold: use the SDK writer for exact u64 lengths and observe both
  // readVarIntNumStrict modes, followed by the actual byte read. The signed
  // -1 probe deliberately calls read(-1); optional wire fields skip that read.
  const lengths = [
    ['2pow53-minus-1', (1n << 53n) - 1n],
    ['2pow53', 1n << 53n],
    ['2pow53-plus-1', (1n << 53n) + 1n],
    ['u64-max-minus-1', (1n << 64n) - 2n],
    ['u64-max', (1n << 64n) - 1n],
    ['2pow32-plus-3', (1n << 32n) + 3n]
  ]
  const length_reads = []
  const response_lengths = []
  // #458 second fold: unsigned page totals are strict numbers before their u32 bounds.
  const page_totals = []
  for (const [name, length] of lengths) {
    const writer = new sdk.Utils.Writer()
    writer.writeVarIntBn(new sdk.BigNumber(length.toString()))
    writer.write([0x61, 0x62, 0x63])
    const bytes = writer.toArray()
    processor.push(await processorCase(sdk, `protocol-length-${name}`, '', [13, 0, 0, ...bytes]))
    for (const signed of [false, true]) {
      const reader = new sdk.Utils.ReaderUint8Array(bytes)
      let value = null
      let stage = 'varint'
      let message = null
      try {
        value = reader.readVarIntNumStrict(signed)
        stage = 'bytes'
        reader.read(value)
      } catch (error) {
        message = error.message
      }
      length_reads.push({ name, length: length.toString(), signed,
        input_hex: sdk.Utils.toHex(bytes), value, stage, message, position: reader.pos })
    }
    const key = (n) => sdk.PrivateKey.fromString(String(n).padStart(64, '0'), 'hex').toPublicKey().encode(true)
    const certificate = [...Array(64).fill(0), ...key(1), ...key(2), ...Array(32).fill(0), 0, 0]
    const certificateWriter = new sdk.Utils.Writer()
    certificateWriter.writeUInt8(0).writeVarIntNum(1).writeVarIntNum(certificate.length)
    certificateWriter.write(certificate).writeUInt8(0).write(bytes)
    for (const [site, response] of [
      ['error-message', [1, ...bytes]],
      ['error-stack', [1, 0, ...bytes]],
      ['certificate-verifier', certificateWriter.toArray()]
    ]) {
      const client = new sdk.WalletWireTransceiver({ async transmitToWallet() { return response } })
      let message = null
      try {
        if (site === 'certificate-verifier') await client.listCertificates({ certifiers: [], types: [] }, 'fixtures.invalid')
        else await client.getVersion({}, 'fixtures.invalid')
      } catch (error) { message = error.message }
      response_lengths.push({ name, site, response_hex: sdk.Utils.toHex(response), message })
    }
    const totalWriter = new sdk.Utils.Writer()
    totalWriter.writeUInt8(0).writeVarIntBn(new sdk.BigNumber(length.toString()))
    const totalResponse = totalWriter.toArray()
    for (const [site, args] of [
      ['listActions', { labels: [] }],
      ['listOutputs', { basket: 'fixtures' }]
    ]) {
      const client = new sdk.WalletWireTransceiver({ async transmitToWallet() { return totalResponse } })
      let message = null
      try { await client[site](args, 'fixtures.invalid') } catch (error) { message = error.message }
      page_totals.push({ name, site, total: length.toString(), response_hex: sdk.Utils.toHex(totalResponse), message })
    }
  }
  return {
    reference: `ts-stack@edf6e03, unmodified packages/sdk, Node ${process.version}`,
    recorder: 'tests/support/wire_linkage_calls_406.mjs with wire_originator_338.mjs',
    reference_lines: 'WalletWireProcessor.ts:286-294,2379-2396,2444-2445; WalletWireTransceiver.ts:95-100,142-148,380-385,651-656,1533-1542; validationHelpers.ts:996-1037; utils.ts:224-228; ReaderUint8Array.ts:38-59; readVarIntNumStrict.ts:15-36',
    processor, transceiver, length_reads, response_lengths, page_totals
  }
}
