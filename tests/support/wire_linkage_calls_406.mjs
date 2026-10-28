// The #406 recordings: revealCounterpartyKeyLinkage (call 9) and
// revealSpecificKeyLinkage (call 10) through the reference's
// WalletWireTransceiver and WalletWireProcessor, both ways in one exchange.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wire_linkage_calls_406.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_wire/linkage_calls_406.json
//
// For each case the reference's transceiver is called with the case's args
// over a transport that captures the request frame and hands it to the
// reference's processor, whose wallet answers fixed values bound to the
// request (the verifier and the counterparty asked for; the prover for
// `self`, the anyone key for `anyone`). The recording keeps the args, the
// request frame and the response frame as hex, the args the wallet saw and
// the result the transceiver returned (bytes as arrays, keys as hex). The
// refusals serve a valid case's response frame changed by one rule to the
// transceiver alone and keep the words it threw.
//
// With no output path it prints the recording instead: the same script run
// against `@bsv/sdk` at ts-sdk@9e3ede6b prints the same frames and results
// (its transceiver checks nothing after the read; the refusals differ there).
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { WalletWireTransceiver, WalletWireProcessor, PrivateKey, Utils } = sdk

const key = (n) => PrivateKey.fromString(n.toString(16).padStart(64, '0'), 'hex').toPublicKey().toString()
const PROVER = key(7)
const COUNTERPARTY = key(3)
const VERIFIER = key(5)
const OTHER = key(11)
const ANYONE = key(1)
const LINKAGE = Array.from({ length: 32 }, (_, i) => (i * 7 + 1) & 0xff)
const PROOF = [0, 1, 127, 128, 254, 255]
const TIME = '2026-10-28T06:00:00.000Z'
const ORIGINATOR = 'fixtures.invalid'

const observed = []
const wallet = {
  async revealCounterpartyKeyLinkage (args, originator) {
    observed.push({ method: 'revealCounterpartyKeyLinkage', args: { ...args }, originator })
    return {
      prover: PROVER,
      verifier: args.verifier,
      counterparty: args.counterparty,
      revelationTime: TIME,
      encryptedLinkage: LINKAGE,
      encryptedLinkageProof: PROOF
    }
  },
  async revealSpecificKeyLinkage (args, originator) {
    observed.push({ method: 'revealSpecificKeyLinkage', args: { ...args }, originator })
    const counterparty =
      args.counterparty === 'self' ? PROVER : args.counterparty === 'anyone' ? ANYONE : args.counterparty
    return {
      prover: PROVER,
      verifier: args.verifier,
      counterparty,
      protocolID: args.protocolID,
      keyID: args.keyID,
      encryptedLinkage: LINKAGE,
      encryptedLinkageProof: PROOF,
      proofType: 1
    }
  }
}
const processor = new WalletWireProcessor(wallet)

const hex = (bytes) => Utils.toHex(Array.from(bytes))
const plain = (value) => JSON.parse(JSON.stringify(value, (_, v) => (v === undefined ? null : v)))

const cases = [
  ['counterparty-minimal', 'revealCounterpartyKeyLinkage', { counterparty: COUNTERPARTY, verifier: VERIFIER }],
  ['counterparty-privileged', 'revealCounterpartyKeyLinkage', {
    counterparty: COUNTERPARTY, verifier: VERIFIER, privileged: true, privilegedReason: 'fixture linkage reason'
  }],
  ['counterparty-unprivileged', 'revealCounterpartyKeyLinkage', {
    counterparty: COUNTERPARTY, verifier: VERIFIER, privileged: false
  }],
  ['specific-key', 'revealSpecificKeyLinkage', {
    counterparty: COUNTERPARTY, verifier: VERIFIER, protocolID: [2, 'fixture linkage'], keyID: 'key-1'
  }],
  ['specific-self', 'revealSpecificKeyLinkage', {
    counterparty: 'self', verifier: VERIFIER, protocolID: [0, 'fixture linkage'], keyID: 'key-2'
  }],
  ['specific-anyone-privileged', 'revealSpecificKeyLinkage', {
    counterparty: 'anyone', verifier: VERIFIER, protocolID: [1, 'fixture linkage'], keyID: 'key-3',
    privileged: true, privilegedReason: 'fixture linkage reason'
  }]
]

const recorded = []
for (const [name, call, args] of cases) {
  let request
  const transceiver = new WalletWireTransceiver({
    async transmitToWallet (message) {
      request = Array.from(message)
      return Array.from(await processor.transmitToWallet(request))
    }
  })
  observed.length = 0
  let response
  const capture = new WalletWireTransceiver({
    async transmitToWallet (message) {
      response = Array.from(await processor.transmitToWallet(Array.from(message)))
      return response
    }
  })
  const result = await capture[call]({ ...args }, ORIGINATOR)
  const wallet = plain(observed[0])
  // The same call once more over the request capture: one frame, one answer.
  await transceiver[call]({ ...args }, ORIGINATOR)
  recorded.push({
    name,
    call,
    args: plain(args),
    request_hex: hex(request),
    response_hex: hex(response),
    wallet_observed: wallet,
    result: plain(result)
  })
}

// One rule broken in a valid response frame, served to the transceiver alone.
const refusal = async (name, base, change) => {
  const entry = recorded.find((c) => c.name === base)
  const bytes = change(Utils.toArray(entry.response_hex, 'hex'))
  const transceiver = new WalletWireTransceiver({ async transmitToWallet () { return bytes } })
  let thrown = null
  try {
    await transceiver[entry.call]({ ...entry.args }, ORIGINATOR)
  } catch (e) {
    thrown = { name: e.name, code: e.code ?? null, message: e.message }
  }
  return { name, base, response_hex: hex(bytes), thrown }
}
const at = (offset, replacement) => (bytes) => [
  ...bytes.slice(0, offset), ...replacement, ...bytes.slice(offset + replacement.length)
]
const otherKey = Utils.toArray(OTHER, 'hex')
const refusals = [
  await refusal('counterparty-trailing-byte', 'counterparty-minimal', (b) => [...b, 0]),
  await refusal('counterparty-other-verifier', 'counterparty-minimal', at(1 + 33, otherKey)),
  await refusal('counterparty-other-counterparty', 'counterparty-minimal', at(1 + 66, otherKey)),
  await refusal('counterparty-prover-not-a-point', 'counterparty-minimal', at(1, [0x05])),
  await refusal('specific-trailing-byte', 'specific-key', (b) => [...b, 0]),
  await refusal('specific-security-level-3', 'specific-key', at(1 + 99, [3])),
  await refusal('specific-other-verifier', 'specific-key', at(1 + 33, otherKey)),
  await refusal('specific-self-not-the-prover', 'specific-self', at(1 + 66, otherKey))
]

const out = {
  description: 'revealCounterpartyKeyLinkage (9) and revealSpecificKeyLinkage (10) on the wallet wire (#406): each case\'s request frame as the reference\'s WalletWireTransceiver writes it and its response frame as the reference\'s WalletWireProcessor writes it for a wallet answering fixed values bound to the request; the refusals a valid response with one rule broken, served to the transceiver alone',
  reference: `@bsv/sdk at ts-stack@edf6e03 (packages/sdk, bundled with bun build), run under Node ${process.version} by tests/support/wire_linkage_calls_406.mjs`,
  reference_lines: 'WalletWireTransceiver.ts:790-849 (revealCounterpartyKeyLinkage), :851-924 (revealSpecificKeyLinkage), :1351-1376 (#encodeKeyRelatedParams), :1448-1462 (#encodePrivilegedParams), :1936-1938, :2004-2016; WalletWireProcessor.ts:1734-1788, :1790-1849',
  originator: ORIGINATOR,
  cases: recorded,
  refusals
}
const text = JSON.stringify(out, null, 2) + '\n'
if (outPath) writeFileSync(outPath, text)
else process.stdout.write(text)
