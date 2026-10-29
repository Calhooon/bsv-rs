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

async function processorCase({ WalletWireProcessor, Utils }, name, originator) {
  const observed = []
  const processor = new WalletWireProcessor({
    async getVersion(_args, originator) {
      observed.push(originator)
      return { version: 'v-1.0.0' }
    }
  })
  const bytes = Utils.toArray(originator, 'utf8')
  const request = name === 'length-251-truncated' ? [28, 251] : [28, bytes.length, ...bytes]
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

export async function recordOriginators(sdk) {
  const processor = []
  const transceiver = []
  for (const [name, originator] of cases()) {
    // A 256-byte length cannot be represented in the processor's u8 header.
    if (name !== 'length-256') processor.push(await processorCase(sdk, name, originator))
    transceiver.push(await transceiverCase(sdk, name, originator))
  }
  processor.push(await processorCase(sdk, 'length-251-truncated', ''))
  return {
    reference: `ts-stack@edf6e03, unmodified packages/sdk, Node ${process.version}`,
    recorder: 'tests/support/wire_linkage_calls_406.mjs with wire_originator_338.mjs',
    reference_lines: 'WalletWireProcessor.ts:286-294,2379-2396; WalletWireTransceiver.ts:95-100; validationHelpers.ts:996-1037',
    processor, transceiver
  }
}
