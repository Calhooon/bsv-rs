// #338 recorder's --send-with-status-590 mode: the sendWithResults entry's
// status byte (BRC-100 wallet/0100.md:1724-1726; WalletWireProcessor.ts:151-156,
// :617-626, :767-777 and WalletWireTransceiver.ts:1216-1238 at edf6e03).
// Only the unmodified SDK writes wire bytes and supplies verdicts. Run with the
// bundle of tests/support/wire_linkage_calls_406.mjs's header:
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wire_originator_338.mjs \
//     --send-with-status-590 "$W/sdk.mjs" tests/vectors/wallet_wire/send_with_status_590.json
//
// `reference` rows: the reference's transceiver calls createAction and
// signAction over a transport that hands the request frame to the reference's
// processor, whose wallet answers three entries, one per status name; the
// response frame is the reference's writer's bytes and `value` its reader's.
// `crate_base` rows: this crate's WireWriter bytes for the same entries before
// #590 (0/1/2), pasted here as data from a one-off run of the writer at
// e8f324eb (signAction's with the txid flag 1 and 44 x 32), served to the
// reference's transceiver alone; `value` or `message`
// is the reference's verdict on them. `unknown` rows: a status byte outside
// 1 to 3 served to the reference's transceiver, its refusal words.
const TXIDS = { unproven: '11'.repeat(32), sending: '22'.repeat(32), failed: '33'.repeat(32) }
// signAction's result must name its signed transaction (WalletResultValidation.ts:1309-1311).
const SIGNED = '44'.repeat(32)
const ALL = Object.entries(TXIDS).map(([status, txid]) => ({ txid, status }))
// The one-off's output, line for line (`create <set> <hex>` and `sign <set> <hex>`).
const CRATE_BASE = [
  ['create_all', 'createAction',
    '000000ffffffffffffffffff0311111111111111111111111111111111111111111111111111111111111111110022222222222222222222222222222222222222222222222222222222222222220133333333333333333333333333333333333333333333333333333333333333330200'],
  ['sign_all', 'signAction',
    '000144444444444444444444444444444444444444444444444444444444444444440003111111111111111111111111111111111111111111111111111111111111111100222222222222222222222222222222222222222222222222222222222222222201333333333333333333333333333333333333333333333333333333333333333302'],
  ['create_unproven', 'createAction',
    '000000ffffffffffffffffff0111111111111111111111111111111111111111111111111111111111111111110000'],
  ['sign_unproven', 'signAction',
    '000144444444444444444444444444444444444444444444444444444444444444440001111111111111111111111111111111111111111111111111111111111111111100'],
  ['create_sending', 'createAction',
    '000000ffffffffffffffffff0122222222222222222222222222222222222222222222222222222222222222220100'],
  ['sign_sending', 'signAction',
    '000144444444444444444444444444444444444444444444444444444444444444440001222222222222222222222222222222222222222222222222222222222222222201'],
  ['create_failed', 'createAction',
    '000000ffffffffffffffffff0133333333333333333333333333333333333333333333333333333333333333330200'],
  ['sign_failed', 'signAction',
    '000144444444444444444444444444444444444444444444444444444444444444440001333333333333333333333333333333333333333333333333333333333333333302'],
]

export async function recordSendWithStatus590(sdk) {
  const { Utils, WalletWireTransceiver, WalletWireProcessor } = sdk
  // sendWith names the three entries' txids: a createAction of no inputs or
  // outputs creates no transaction, and an entry outside sendWith (or the
  // signed txid) is refused (WalletResultValidation.ts:1285-1288,1335-1353).
  const sendWith = Object.values(TXIDS)
  const args = {
    createAction: { description: 'status test', options: { sendWith } },
    signAction: { spends: {}, reference: 'AQ==', options: { sendWith, returnTXIDOnly: true } }
  }
  const answers = {
    createAction: { sendWithResults: ALL },
    signAction: { txid: SIGNED, sendWithResults: ALL }
  }
  const reference = []
  for (const call of ['createAction', 'signAction']) {
    const observed = []
    const processor = new WalletWireProcessor({
      async [call] (callArgs) {
        observed.push(callArgs)
        return answers[call]
      }
    })
    const frames = []
    const client = new WalletWireTransceiver({
      async transmitToWallet (frame) {
        const response = await processor.transmitToWallet(frame)
        frames.push({ request_hex: Utils.toHex(frame), response_hex: Utils.toHex(response) })
        return response
      }
    })
    let value = null
    let message = null
    try { value = await client[call](args[call], 'fixtures.invalid') } catch (error) { message = error.message }
    if (frames.length !== 1 || observed.length !== 1) throw new Error(`${call}: the exchange did not reach the wallet: ${message}`)
    reference.push({ name: call, call, args: args[call], answered: answers[call], ...frames[0], value, message })
  }
  const crate = []
  for (const [name, call, response_hex] of CRATE_BASE) {
    let sent = false
    const client = new WalletWireTransceiver({
      async transmitToWallet () { sent = true; return Utils.toArray(response_hex, 'hex') }
    })
    let value = null
    let message = null
    try { value = await client[call](args[call], 'fixtures.invalid') } catch (error) { message = error.message }
    if (!sent) throw new Error(`${name}: argument validation prevented the recorded response: ${message}`)
    crate.push({ name, call, args: args[call], response_hex, value, message })
  }
  // A status byte outside 1 to 3, one entry of the unproven txid in a
  // createAction answer: the reader's refusal words (`readInt8`, signed).
  const unknown = []
  for (const code of [0, 4, 127, 128, 255]) {
    const response = Utils.toArray(`000000${'ff'.repeat(9)}01${TXIDS.unproven}${code.toString(16).padStart(2, '0')}00`, 'hex')
    const client = new WalletWireTransceiver({ async transmitToWallet () { return response } })
    let value = null
    let message = null
    try { value = await client.createAction(args.createAction, 'fixtures.invalid') } catch (error) { message = error.message }
    unknown.push({ name: `create_code_${code}`, call: 'createAction', response_hex: Utils.toHex(response), value, message })
  }
  return { reference: 'ts-stack@edf6e03 (unmodified)', node: process.version,
    recorder: 'wire_originator_338.mjs --send-with-status-590', crate_base_writer: 'bsv-rs@e8f324eb WireWriter',
    txids: TXIDS, signed_txid: SIGNED, reference_rows: reference, crate_base_rows: crate, unknown_rows: unknown }
}
