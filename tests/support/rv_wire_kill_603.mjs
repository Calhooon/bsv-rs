// #603, kill lane rv-wire: the reference's verdicts behind the four survivors of
// `src/wallet/substrates/result_values/wire.rs` (the complete run of 2026-11-04).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   source ~/.nvm/nvm.sh && nvm use 22
//   node tests/support/rv_wire_kill_603.mjs "$W/sdk.mjs" tests/vectors/rv_wire_kill_603.json
//
// Rows 1 to 3: `validateWalletResult('revealCounterpartyKeyLinkage', ...)`
// (`WalletResultValidation.ts:2165-2173,2226-2227`) on two distinct byte
// arrays whose total is the cap (`MAX_WALLET_WIRE_FRAME_BYTES`, 268435456,
// `WalletWire.ts:9`), one past it, and a small control: the strict `>` of
// `:632-637`. Only the lengths are stored. Row 4: the reference's
// `WalletWireTransceiver.listOutputs` (`WalletWireTransceiver.ts:650-665`) on
// the frame #487's writer builds for `listOutputs_valid`
// (`wire_result_validation_487.mjs`, its listOutputs branch copied below
// verbatim) with `lockingScript` present and `51`, the script the BEEF commits
// at that outpoint (`:2109-2130`). No transport, no listener.
import { readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { Utils, validateWalletResult, WalletWireTransceiver } = sdk

const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const G2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
const revelationTime = '2026-11-09T00:00:00.000Z'
const verdict = fn => {
  try { fn(); return { accepted: true } } catch (e) { return { accepted: false, message: e.message } }
}
const rows = []
for (const [name, linkage, proof] of [
  ['total_at_cap', 268435455, 1],
  ['total_past_cap', 268435456, 1],
  ['small_control', 1, 1]
]) {
  const reference = verdict(() => validateWalletResult('revealCounterpartyKeyLinkage', {
    prover: G, verifier: G2, counterparty: G, revelationTime,
    encryptedLinkage: new Uint8Array(linkage), encryptedLinkageProof: new Uint8Array(proof)
  }))
  rows.push({ name, call: 'revealCounterpartyKeyLinkage', prover: G, verifier: G2, counterparty: G,
    revelation_time: revelationTime, encrypted_linkage_length: linkage,
    encrypted_linkage_proof_length: proof, reference })
}

// The seed #487 records as `listOutputs_valid`, its script made present.
const source = JSON.parse(readFileSync(new URL('../vectors/http_json_result_values_408.json', import.meta.url)))
const seed = source.cases.find(c => c.name === 'listOutputs_valid')
const value = JSON.parse(seed.bodyText)
value.outputs[0].lockingScript = '51'

// #487's listOutputs writer (`wire_result_validation_487.mjs`), verbatim.
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
const w = new Utils.Writer().writeUInt8(0)
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
const response = w.toArray()

let request
const client = new WalletWireTransceiver({ async transmitToWallet (frame) { request = Utils.toHex(frame); return response } })
let reference
try {
  const result = await client.listOutputs(structuredClone(seed.args), 'fixtures.invalid')
  reference = { accepted: true, locking_script: result.outputs[0].lockingScript }
} catch (e) { reference = { accepted: false, message: e.message } }
rows.push({ name: 'list_outputs_matching_script', call: 'listOutputs', args: seed.args,
  request_hex: request, response_hex: Utils.toHex(response), reference })

writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, rows }, null, 2) + '\n')
