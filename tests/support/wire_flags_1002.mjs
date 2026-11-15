// #1002: every flag byte and optional scalar of the wallet wire, recorded
// from the unmodified reference (WalletWireTransceiver.ts and
// WalletWireProcessor.ts at ts-stack@edf6e03). Run against @bsv/sdk bundled
// with bun (no node_modules), under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wire_flags_1002.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_wire/flags_1002.json
// With no output path it prints the recording. Two runs are byte-identical.
//
// Only the reference writes wire bytes and supplies verdicts, save the rows
// marked as built here (a frame the reference never writes, served to its
// reader for its words) and `crate_base_rows` (this crate's bytes before
// #1002, pasted as data from a one-off run of its writer at d892e206).
//
// `request_rows`: the reference's transceiver is called with the row's args
//   over a transport that keeps the request frame and hands it to the
//   reference's processor, whose wallet records the args it was given
//   (`observed`, the processor's reading of the frame).
// `request_flag_rows`: within a group of request rows that differ in one
//   argument, the offset and the byte that moved, found by comparing the
//   group's frames (observed, never supplied).
// `crate_base_rows`: this crate's listActions frames before #1002 served to
//   the reference's processor: what its wallet observed, or its error frame.
// `processor_refusal_rows`: a recorded request frame with one flag byte set
//   out of range (built here), served to the reference's processor: its
//   error frame.
// `response_rows`: the reference's processor writes the result its wallet
//   answers; the frame, and the value the reference's transceiver read.
// `response_flag_rows`: within a group of response rows that differ in one
//   answered member, the offset and the byte that moved.
// `transceiver_refusal_rows`: a recorded response frame with one flag byte
//   set out of range, or a length changed (built here), served to the
//   reference's transceiver: its words.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { WalletWireTransceiver, WalletWireProcessor, PrivateKey, Utils, Transaction, MerklePath, LockingScript, UnlockingScript } = sdk

const hex = (bytes) => Utils.toHex(Array.from(bytes))
const unhex = (text) => Utils.toArray(text, 'hex')
const key = (n) => PrivateKey.fromString(n.toString(16).padStart(64, '0'), 'hex').toPublicKey().toString()
const plain = (value) => JSON.parse(JSON.stringify(value, (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v)))
const TXID = '11'.repeat(32)
const TXID2 = '22'.repeat(32)
const TYPE = Utils.toBase64(Array(32).fill(1))
const SERIAL = Utils.toBase64(Array(32).fill(2))
const SUBJECT = key(9)
const CERTIFIER = key(7)
const VERIFIER = key(5)
// The two members named `...IdentityKey` carry the generator point, the public
// key of 1 and a public constant of the curve (the secrets scan reads a
// member of that name by its value).
const IDENTITY = key(1)
// internalizeAction's tx is validated as an Atomic BEEF: a two-output
// transaction spending a parent proven by a lone leaf, built by the SDK.
const [ATOMIC, ATOMIC_TXID, PARENT_BEEF, PARENT_TXID] = (() => {
  const lock = LockingScript.fromHex('51')
  const unlock = () => UnlockingScript.fromHex('51')
  const parent = new Transaction(1, [{ sourceTXID: '33'.repeat(32), sourceOutputIndex: 0, unlockingScript: unlock(), sequence: 0xffffffff }],
    [{ lockingScript: lock, satoshis: 1000 }], 0)
  parent.merklePath = new MerklePath(800000, [[{ offset: 0, hash: parent.id('hex'), txid: true }]])
  const tx = new Transaction(1, [{ sourceTransaction: parent, sourceOutputIndex: 0, unlockingScript: unlock(), sequence: 0xffffffff }],
    [{ lockingScript: lock, satoshis: 400 }, { lockingScript: lock, satoshis: 500 }], 0)
  return [tx.toAtomicBEEF(), tx.id('hex'), parent.toBEEF(), parent.id('hex')]
})()
if (ATOMIC.length >= 253) throw new Error('the Atomic BEEF no longer fits a one-byte length')

// One exchange through both reference ends. The wallet answers `answer`
// (or an empty object) and records what it was given.
async function exchange (call, args, answer) {
  const observed = []
  const processor = new WalletWireProcessor({
    async [call] (callArgs) { observed.push(plain(callArgs)); return answer ?? {} }
  })
  const frames = []
  const client = new WalletWireTransceiver({
    async transmitToWallet (frame) {
      const response = await processor.transmitToWallet(frame)
      frames.push({ request_hex: hex(frame), response_hex: hex(response) })
      return response
    }
  })
  let value = null
  let message = null
  try { value = plain(await client[call](args)) } catch (error) { message = error.message }
  if (frames.length !== 1) throw new Error(`${call}: no frame was written: ${message}`)
  return { ...frames[0], observed: observed[0] ?? null, value, message }
}

// The one offset at which two frames of equal length differ.
function movedByte (name, a, b) {
  if (a.length !== b.length) throw new Error(`${name}: the frames differ in length`)
  const at = []
  for (let i = 0; i < a.length; i += 2) if (a.slice(i, i + 2) !== b.slice(i, i + 2)) at.push(i / 2)
  if (at.length !== 1) throw new Error(`${name}: ${at.length} bytes moved`)
  return at[0]
}

const DER = [0x30, 6, 2, 1, 1, 2, 1, 1]
const CERT = { type: TYPE, serialNumber: SERIAL, subject: SUBJECT, certifier: CERTIFIER, revocationOutpoint: `${TXID}.1`, fields: { name: 'YQ==' }, signature: '3006020101020101' }

// ---------------------------------------------------------------- requests
const PROTOCOL = [1, 'flag tests']
const requestGroups = [
  { group: 'listActions labelQueryMode', call: 'listActions', field: 'labelQueryMode', base: { labels: ['alpha'] },
    states: [['absent', {}], ['any', { labelQueryMode: 'any' }], ['all', { labelQueryMode: 'all' }]] },
  { group: 'listActions includeLabels', call: 'listActions', field: 'includeLabels', base: { labels: ['alpha'] },
    states: [['absent', {}], ['false', { includeLabels: false }], ['true', { includeLabels: true }]] },
  { group: 'listActions seekPermission', call: 'listActions', field: 'seekPermission', base: { labels: ['alpha'] },
    states: [['absent', {}], ['false', { seekPermission: false }], ['true', { seekPermission: true }]] },
  { group: 'listOutputs tagQueryMode', call: 'listOutputs', field: 'tagQueryMode', base: { basket: 'flags', tags: ['alpha'] },
    states: [['absent', {}], ['all', { tagQueryMode: 'all' }], ['any', { tagQueryMode: 'any' }]] },
  { group: 'listOutputs include', call: 'listOutputs', field: 'include', base: { basket: 'flags', tags: ['alpha'] },
    states: [['absent', {}], ['locking scripts', { include: 'locking scripts' }], ['entire transactions', { include: 'entire transactions' }]] },
  { group: 'listOutputs includeTags', call: 'listOutputs', field: 'includeTags', base: { basket: 'flags', tags: ['alpha'] },
    states: [['absent', {}], ['false', { includeTags: false }], ['true', { includeTags: true }]] },
  { group: 'createAction trustSelf', call: 'createAction', field: 'options.trustSelf', base: { description: 'flag tests' },
    states: [['absent', { options: {} }], ['known', { options: { trustSelf: 'known' } }]] },
  { group: 'createAction signAndProcess', call: 'createAction', field: 'options.signAndProcess', base: { description: 'flag tests' },
    states: [['absent', { options: {} }], ['false', { options: { signAndProcess: false } }], ['true', { options: { signAndProcess: true } }]] },
  { group: 'getPublicKey forSelf', call: 'getPublicKey', field: 'forSelf', base: { protocolID: PROTOCOL, keyID: '1' },
    states: [['absent', {}], ['false', { forSelf: false }], ['true', { forSelf: true }]] },
  { group: 'getPublicKey privileged', call: 'getPublicKey', field: 'privileged', base: { protocolID: PROTOCOL, keyID: '1', privilegedReason: 'a reason' },
    states: [['absent', {}], ['false', { privileged: false }], ['true', { privileged: true }]] }
]
// Single rows: a presence flag or a selector whose states change the frame's length.
const requestSingles = [
  ['createAction_options_absent', 'createAction', { description: 'flag tests' }],
  ['createAction_options_all', 'createAction', { description: 'flag tests', lockTime: 0, version: 1, labels: [],
    options: { signAndProcess: true, acceptDelayedBroadcast: false, trustSelf: 'known', knownTxids: [TXID], returnTXIDOnly: true, noSend: false, noSendChange: [], sendWith: [], randomizeOutputs: false } }],
  ['signAction_options_absent', 'signAction', { spends: { 0: { unlockingScript: '51' } }, reference: 'AQ==' }],
  ['signAction_options_all', 'signAction', { spends: { 0: { unlockingScript: '51', sequenceNumber: 7 } }, reference: 'AQ==',
    options: { acceptDelayedBroadcast: true, returnTXIDOnly: false, noSend: true, sendWith: [TXID] } }],
  ['listActions_limit_offset', 'listActions', { labels: [], limit: 10, offset: 3 }],
  ['listOutputs_limit_offset', 'listOutputs', { basket: 'flags', limit: 10, offset: 3 }],
  ['internalizeAction_both_protocols', 'internalizeAction', { tx: ATOMIC, description: 'flag tests', seekPermission: false,
    outputs: [
      { outputIndex: 0, protocol: 'wallet payment', paymentRemittance: { senderIdentityKey: IDENTITY, derivationPrefix: 'AQ==', derivationSuffix: 'Ag==' } },
      { outputIndex: 1, protocol: 'basket insertion', insertionRemittance: { basket: 'flags' } }] }],
  ['getPublicKey_identityKey', 'getPublicKey', { identityKey: true }],
  ['getPublicKey_identityKey_privileged', 'getPublicKey', { identityKey: true, privileged: true, privilegedReason: 'a reason', seekPermission: false }],
  ['createSignature_data', 'createSignature', { protocolID: PROTOCOL, keyID: '1', data: [1, 2, 3] }],
  ['createSignature_hash', 'createSignature', { protocolID: PROTOCOL, keyID: '1', hashToDirectlySign: Array(32).fill(4) }],
  ['encrypt_counterparty_self', 'encrypt', { protocolID: PROTOCOL, keyID: '1', counterparty: 'self', plaintext: [1] }],
  ['encrypt_counterparty_anyone', 'encrypt', { protocolID: PROTOCOL, keyID: '1', counterparty: 'anyone', plaintext: [1], seekPermission: true }],
  ['acquireCertificate_direct_certifier', 'acquireCertificate', { type: TYPE, certifier: CERTIFIER, acquisitionProtocol: 'direct', fields: { name: 'YQ==' },
    serialNumber: SERIAL, revocationOutpoint: `${TXID}.1`, signature: '3006020101020101', keyringRevealer: 'certifier', keyringForSubject: { name: 'YQ==' } }],
  ['acquireCertificate_issuance', 'acquireCertificate', { type: TYPE, certifier: CERTIFIER, acquisitionProtocol: 'issuance', fields: { name: 'YQ==' },
    certifierUrl: 'https://certifier.invalid', privileged: false }],
  ['listCertificates_limit_offset_privileged', 'listCertificates', { certifiers: [CERTIFIER], types: [TYPE], limit: 10, offset: 3, privileged: true, privilegedReason: 'a reason' }],
  ['listCertificates_absent', 'listCertificates', { certifiers: [], types: [] }],
  ['discoverByIdentityKey_limit_offset', 'discoverByIdentityKey', { identityKey: IDENTITY, limit: 10, offset: 3, seekPermission: false }],
  ['discoverByAttributes_absent', 'discoverByAttributes', { attributes: { name: 'a' } }],
  ['encrypt_counterparty_key', 'encrypt', { protocolID: PROTOCOL, keyID: '1', counterparty: VERIFIER, plaintext: [1], seekPermission: false }],
  ['decrypt_seekPermission_false', 'decrypt', { protocolID: PROTOCOL, keyID: '1', ciphertext: [1, 2], seekPermission: false }],
  ['createHmac_absent', 'createHmac', { protocolID: PROTOCOL, keyID: '1', data: [1] }],
  ['verifyHmac_seekPermission_true', 'verifyHmac', { protocolID: PROTOCOL, keyID: '1', data: [1], hmac: Array(32).fill(5), seekPermission: true }],
  ['verifySignature_data_forSelf_true', 'verifySignature', { protocolID: PROTOCOL, keyID: '1', data: [1, 2, 3], signature: DER, forSelf: true }],
  ['verifySignature_hash_forSelf_false', 'verifySignature', { protocolID: PROTOCOL, keyID: '1', hashToDirectlyVerify: Array(32).fill(4), signature: DER, forSelf: false, seekPermission: false }],
  ['revealCounterpartyKeyLinkage_absent', 'revealCounterpartyKeyLinkage', { counterparty: SUBJECT, verifier: VERIFIER }],
  ['revealCounterpartyKeyLinkage_privileged', 'revealCounterpartyKeyLinkage', { counterparty: SUBJECT, verifier: VERIFIER, privileged: true, privilegedReason: 'a reason' }],
  ['revealSpecificKeyLinkage_absent', 'revealSpecificKeyLinkage', { counterparty: SUBJECT, verifier: VERIFIER, protocolID: PROTOCOL, keyID: '1' }],
  ['proveCertificate_absent', 'proveCertificate', { certificate: CERT, fieldsToReveal: ['name'], verifier: VERIFIER }],
  ['proveCertificate_privileged', 'proveCertificate', { certificate: CERT, fieldsToReveal: ['name'], verifier: VERIFIER, privileged: true, privilegedReason: 'a reason' }],
  // an input BEEF, an input in each of its two forms, an output with and without its optional members
  ['createAction_input_unlocking_length', 'createAction', { description: 'flag tests', inputBEEF: PARENT_BEEF,
    inputs: [{ outpoint: `${PARENT_TXID}.0`, unlockingScriptLength: 1, inputDescription: 'flag tests' }],
    outputs: [{ lockingScript: '51', satoshis: 400, outputDescription: 'flag tests' }] }],
  ['createAction_input_unlocking_script', 'createAction', { description: 'flag tests', inputBEEF: PARENT_BEEF,
    inputs: [{ outpoint: `${PARENT_TXID}.0`, unlockingScript: '51', inputDescription: 'flag tests', sequenceNumber: 5 }],
    outputs: [{ lockingScript: '51', satoshis: 400, outputDescription: 'flag tests', basket: 'flags', customInstructions: 'keep', tags: ['alpha'] }] }]
]

const request_rows = []
const request_flag_rows = []
for (const { group, call, field, base, states } of requestGroups) {
  const rows = []
  for (const [state, extra] of states) {
    const args = { ...base, ...extra }
    const recorded = await exchange(call, args)
    rows.push({ name: `${group}: ${state}`, group, state, call, args, request_hex: recorded.request_hex, observed: recorded.observed })
  }
  const offset = movedByte(group, rows[0].request_hex, rows[1].request_hex)
  for (const row of rows) {
    if (row !== rows[0] && movedByte(row.name, rows[0].request_hex, row.request_hex) !== offset) throw new Error(`${row.name}: another byte moved`)
    request_flag_rows.push({ group, state: row.state, call, field, offset, byte_hex: row.request_hex.slice(offset * 2, offset * 2 + 2) })
  }
  request_rows.push(...rows)
}
for (const [name, call, args] of requestSingles) {
  const recorded = await exchange(call, args)
  request_rows.push({ name, group: null, state: null, call, args, request_hex: recorded.request_hex, observed: recorded.observed })
}

// This crate's listActions frames before #1002, line for line from the
// one-off (`<state> <hex>`): the args of `listActions labelQueryMode`.
const CRATE_BASE = [
  ['absent', '04000105616c706861ffffffffffffffffffffffffffffffffffffffffffffffffffff'],
  ['any', '04000105616c70686100ffffffffffffffffffffffffffffffffffffffffffffffffff'],
  ['all', '04000105616c70686101ffffffffffffffffffffffffffffffffffffffffffffffffff']
]
const crate_base_rows = []
for (const [state, request_hex] of CRATE_BASE) {
  const observed = []
  const processor = new WalletWireProcessor({
    async listActions (args) { observed.push(plain(args)); return { totalActions: 0, actions: [] } }
  })
  const response = await processor.transmitToWallet(unhex(request_hex))
  crate_base_rows.push({ name: `listActions labelQueryMode: ${state}`, state, call: 'listActions', request_hex, response_hex: hex(response), observed: observed[0] ?? null })
}

// A request frame with one flag byte out of range, to the reference's processor.
const flagOffset = (group) => request_flag_rows.find((row) => row.group === group).offset
const frameOf = (name) => request_rows.find((row) => row.name === name).request_hex
const withByte = (frame, offset, byte) => frame.slice(0, offset * 2) + byte.toString(16).padStart(2, '0') + frame.slice(offset * 2 + 2)
const processorPlants = [
  ['listActions labelQueryMode', 'listActions labelQueryMode: absent', [0, 3, 0x80]],
  ['listActions includeLabels', 'listActions includeLabels: absent', [2, 0x80]],
  ['listActions seekPermission', 'listActions seekPermission: absent', [2]],
  ['listOutputs tagQueryMode', 'listOutputs tagQueryMode: absent', [0, 3]],
  ['listOutputs include', 'listOutputs include: absent', [0, 3]],
  ['createAction trustSelf', 'createAction trustSelf: absent', [0, 2]],
  ['createAction signAndProcess', 'createAction signAndProcess: absent', [2]],
  ['getPublicKey forSelf', 'getPublicKey forSelf: absent', [2]],
  ['getPublicKey privileged', 'getPublicKey privileged: absent', [2]]
]
const processor_refusal_rows = []
async function refusedByProcessor (name, call, request_hex) {
  const called = []
  const processor = new WalletWireProcessor(new Proxy({}, {
    get (_t, method) { return typeof method !== 'string' || method === 'then' ? undefined : async () => { called.push(method); return {} } }
  }))
  const response = await processor.transmitToWallet(unhex(request_hex))
  processor_refusal_rows.push({ name, call, request_hex, response_hex: hex(response), wallet_called: called.length > 0 })
}
for (const [group, source, bytes] of processorPlants) {
  const row = request_rows.find((r) => r.name === source)
  for (const byte of bytes) {
    await refusedByProcessor(`${group} = ${byte}`, row.call, withByte(row.request_hex, flagOffset(group), byte))
  }
}
// The leading bytes of a frame: getPublicKey's identityKey flag at offset 2
// (after the call code and the originator's length), createAction's and
// signAction's options flag as the frame's last byte, and the privileged
// reason's length the byte after the privileged flag.
await refusedByProcessor('getPublicKey identityKey = 2', 'getPublicKey', withByte(frameOf('getPublicKey_identityKey'), 2, 2))
await refusedByProcessor('getPublicKey identityKey = 255', 'getPublicKey', withByte(frameOf('getPublicKey_identityKey'), 2, 255))
{
  const frame = frameOf('createAction_options_absent')
  await refusedByProcessor('createAction optionsPresent = 2', 'createAction', withByte(frame, frame.length / 2 - 1, 2))
  await refusedByProcessor('createAction optionsPresent = 255', 'createAction', withByte(frame, frame.length / 2 - 1, 255))
  const sign = frameOf('signAction_options_absent')
  await refusedByProcessor('signAction optionsPresent = 2', 'signAction', withByte(sign, sign.length / 2 - 1, 2))
  const reason = flagOffset('getPublicKey privileged') + 1
  await refusedByProcessor('getPublicKey privilegedReason length = -2', 'getPublicKey', withByte(frameOf('getPublicKey privileged: absent'), reason, 0xfe))
  const data = frameOf('createSignature_data')
  // the data type flag follows the key-related parameters: the byte before the data's length (3) and bytes
  await refusedByProcessor('createSignature data type = 3', 'createSignature', withByte(data, data.length / 2 - 6, 3))
  const internalize = frameOf('internalizeAction_both_protocols')
  // tx length, tx, output count, output index, then the protocol flag
  await refusedByProcessor('internalizeAction protocol = 3', 'internalizeAction', withByte(internalize, 2 + 1 + ATOMIC.length + 1 + 1, 3))
  // seekPermission closes a request
  const keyed = frameOf('getPublicKey forSelf: absent')
  await refusedByProcessor('getPublicKey seekPermission = 2', 'getPublicKey', withByte(keyed, keyed.length / 2 - 1, 2))
  const encrypt = frameOf('encrypt_counterparty_self')
  await refusedByProcessor('encrypt seekPermission = 2', 'encrypt', withByte(encrypt, encrypt.length / 2 - 1, 2))
  // verifySignature's forSelf follows the same key-related parameters as
  // getPublicKey's, one byte earlier (no identityKey flag ahead of them)
  const verify = frameOf('verifySignature_data_forSelf_true')
  await refusedByProcessor('verifySignature forSelf = 2', 'verifySignature', withByte(verify, flagOffset('getPublicKey forSelf') - 1, 2))
}

// --------------------------------------------------------------- responses
const ACTION = { txid: TXID, satoshis: 1000, status: 'completed', isOutgoing: true, description: 'flag tests', version: 1, lockTime: 0 }
const OUTPUT = { outputIndex: 0, satoshis: 1000, spendable: true, outputDescription: 'flag tests', basket: 'flags', tags: [] }
const INPUT = { sourceOutpoint: `${TXID2}.0`, sourceSatoshis: 5, inputDescription: 'flag tests', sequenceNumber: 0 }
const listActionsArgs = { labels: [] }
const listOutputsArgs = { basket: 'flags' }
const page = (action) => ({ totalActions: 1, actions: [action] })
const outputs = (output) => ({ totalOutputs: 1, outputs: [output] })
const OUT = { outpoint: `${TXID}.0`, satoshis: 1000, spendable: true }
const responseGroups = [
  { group: 'listActions status', call: 'listActions', args: listActionsArgs, field: 'actions[0].status',
    states: ['completed', 'unprocessed', 'sending', 'unproven', 'unsigned', 'nosend', 'nonfinal', 'failed'].map((s) => [s, page({ ...ACTION, status: s })]) },
  { group: 'listActions isOutgoing', call: 'listActions', args: listActionsArgs, field: 'actions[0].isOutgoing',
    states: [['false', page({ ...ACTION, isOutgoing: false })], ['true', page({ ...ACTION, isOutgoing: true })]] },
  { group: 'listActions output spendable', call: 'listActions', args: listActionsArgs, field: 'actions[0].outputs[0].spendable',
    states: [['false', page({ ...ACTION, outputs: [{ ...OUTPUT, spendable: false }] })], ['true', page({ ...ACTION, outputs: [OUTPUT] })]] },
  { group: 'isAuthenticated', call: 'isAuthenticated', args: {}, field: 'authenticated',
    states: [['false', { authenticated: false }], ['true', { authenticated: true }]] },
  { group: 'getNetwork', call: 'getNetwork', args: {}, field: 'network',
    states: [['mainnet', { network: 'mainnet' }], ['testnet', { network: 'testnet' }]] }
]
const responseSingles = [
  ['createAction_txid', 'createAction', { description: 'flag tests', options: { returnTXIDOnly: true } }, { txid: TXID }],
  ['createAction_signable', 'createAction', { description: 'flag tests', options: { signAndProcess: false } }, { signableTransaction: { tx: ATOMIC, reference: 'AQ==' } }],
  ['createAction_txid_tx', 'createAction', { description: 'flag tests' }, { txid: ATOMIC_TXID, tx: ATOMIC }],
  ['signAction_txid', 'signAction', { spends: {}, reference: 'AQ==', options: { returnTXIDOnly: true } }, { txid: TXID }],
  ['listActions_labels_absent', 'listActions', listActionsArgs, page(ACTION)],
  ['listActions_labels_empty', 'listActions', listActionsArgs, page({ ...ACTION, labels: [] })],
  ['listActions_labels_one', 'listActions', listActionsArgs, page({ ...ACTION, labels: ['alpha'] })],
  ['listActions_inputs_outputs_empty', 'listActions', listActionsArgs, page({ ...ACTION, inputs: [], outputs: [] })],
  ['listActions_input_scripts_absent', 'listActions', listActionsArgs, page({ ...ACTION, inputs: [INPUT] })],
  ['listActions_output_optionals_absent', 'listActions', listActionsArgs,
    page({ ...ACTION, outputs: [{ outputIndex: 0, satoshis: 1000, spendable: true, outputDescription: 'flag tests', basket: 'flags' }] })],
  ['listActions_output_empty_strings', 'listActions', listActionsArgs,
    page({ ...ACTION, outputs: [{ outputIndex: 0, satoshis: 1000, spendable: true, outputDescription: 'flag tests', basket: '', tags: [], lockingScript: '', customInstructions: '' }] })],
  ['listOutputs_optionals_absent', 'listOutputs', listOutputsArgs, outputs(OUT)],
  ['listOutputs_empty_strings', 'listOutputs', listOutputsArgs, outputs({ ...OUT, lockingScript: '', customInstructions: '' })],
  ['listOutputs_tags_labels_empty', 'listOutputs', { ...listOutputsArgs, includeTags: true, includeLabels: true }, outputs({ ...OUT, tags: [], labels: [] })],
  ['listOutputs_tags_labels_one', 'listOutputs', { ...listOutputsArgs, includeTags: true, includeLabels: true }, outputs({ ...OUT, tags: ['alpha'], labels: ['omega'] })],
  ['listCertificates_keyring_absent', 'listCertificates', { certifiers: [CERTIFIER], types: [TYPE] }, { totalCertificates: 1, certificates: [CERT] }],
  ['listCertificates_keyring_verifier', 'listCertificates', { certifiers: [CERTIFIER], types: [TYPE] },
    { totalCertificates: 1, certificates: [{ ...CERT, keyring: { name: 'YQ==' }, verifier: VERIFIER }] }]
]
const response_rows = []
const response_flag_rows = []
for (const { group, call, args, field, states } of responseGroups) {
  const rows = []
  for (const [state, answer] of states) {
    const recorded = await exchange(call, args, answer)
    rows.push({ name: `${group}: ${state}`, group, state, call, args, answered: plain(answer), response_hex: recorded.response_hex, value: recorded.value, message: recorded.message })
  }
  const offset = movedByte(group, rows[0].response_hex, rows[1].response_hex)
  for (const row of rows) {
    if (row !== rows[0] && movedByte(row.name, rows[0].response_hex, row.response_hex) !== offset) throw new Error(`${row.name}: another byte moved`)
    response_flag_rows.push({ group, state: row.state, call, field, offset, byte_hex: row.response_hex.slice(offset * 2, offset * 2 + 2) })
  }
  response_rows.push(...rows)
}
for (const [name, call, args, answer] of responseSingles) {
  const recorded = await exchange(call, args, answer)
  response_rows.push({ name, group: null, state: null, call, args, answered: plain(answer), response_hex: recorded.response_hex, value: recorded.value, message: recorded.message })
}

// A response frame served to the reference's transceiver alone.
const transceiver_refusal_rows = []
async function readByTransceiver (name, call, args, response_hex) {
  let sent = false
  const client = new WalletWireTransceiver({ async transmitToWallet () { sent = true; return unhex(response_hex) } })
  let value = null
  let message = null
  try { value = plain(await client[call](args)) } catch (error) { message = error.message }
  if (!sent) throw new Error(`${name}: argument validation prevented the response: ${message}`)
  transceiver_refusal_rows.push({ name, call, args, response_hex, value, message })
}
const responseOffset = (group) => response_flag_rows.find((row) => row.group === group).offset
const responseOf = (name) => response_rows.find((row) => row.name === name)
for (const [group, source, bytes] of [
  ['listActions status', 'listActions status: completed', [0, 9, 0xff]],
  ['listActions isOutgoing', 'listActions isOutgoing: true', [2, 0xff]],
  ['listActions output spendable', 'listActions output spendable: true', [2, 0xff]],
  ['isAuthenticated', 'isAuthenticated: true', [2, 0xff]],
  ['getNetwork', 'getNetwork: mainnet', [2, 0xff]]
]) {
  const row = responseOf(source)
  for (const byte of bytes) {
    await readByTransceiver(`${group} = ${byte}`, row.call, row.args, withByte(row.response_hex, responseOffset(group), byte))
  }
}
{
  // createAction's result opens `00` (the error byte), the txid flag, the txid
  // when present, then the tx flag; the signable flag closes a result that
  // carries no signable transaction.
  const txid = responseOf('createAction_txid')
  await readByTransceiver('createAction txid present = 2', 'createAction', txid.args, withByte(txid.response_hex, 1, 2))
  await readByTransceiver('createAction txid present = 255', 'createAction', txid.args, withByte(txid.response_hex, 1, 0xff))
  await readByTransceiver('createAction tx present = 2', 'createAction', txid.args, withByte(txid.response_hex, 34, 2))
  await readByTransceiver('createAction tx present = 255', 'createAction', txid.args, withByte(txid.response_hex, 34, 0xff))
  const last = txid.response_hex.length / 2 - 1
  await readByTransceiver('createAction signableTransaction present = 2', 'createAction', txid.args, withByte(txid.response_hex, last, 2))
  await readByTransceiver('createAction signableTransaction present = 255', 'createAction', txid.args, withByte(txid.response_hex, last, 0xff))
  const sign = responseOf('signAction_txid')
  await readByTransceiver('signAction txid present = 2', 'signAction', sign.args, withByte(sign.response_hex, 1, 2))
  await readByTransceiver('signAction txid present = 255', 'signAction', sign.args, withByte(sign.response_hex, 1, 0xff))
  await readByTransceiver('signAction tx present = 2', 'signAction', sign.args, withByte(sign.response_hex, 34, 2))
  await readByTransceiver('signAction tx present = 255', 'signAction', sign.args, withByte(sign.response_hex, 34, 0xff))
  const auth = responseOf('isAuthenticated: true')
  await readByTransceiver('isAuthenticated empty', 'isAuthenticated', {}, '00')
  await readByTransceiver('isAuthenticated two bytes', 'isAuthenticated', {}, auth.response_hex + '00')
  const network = responseOf('getNetwork: mainnet')
  await readByTransceiver('getNetwork empty', 'getNetwork', {}, '00')
  await readByTransceiver('getNetwork two bytes', 'getNetwork', {}, network.response_hex + '00')
  const keyring = responseOf('listCertificates_keyring_absent')
  // the keyring flag follows the certificate behind its length; the verifier's length closes the entry
  const flagAt = keyring.response_hex.length / 2 - 2
  await readByTransceiver('listCertificates keyring present = 2', 'listCertificates', keyring.args, withByte(keyring.response_hex, flagAt, 2))
  await readByTransceiver('listCertificates keyring present = 255', 'listCertificates', keyring.args, withByte(keyring.response_hex, flagAt, 0xff))
  // the verifier's length: 0 absent or 33
  await readByTransceiver('listCertificates verifier length = 32', 'listCertificates', keyring.args, withByte(keyring.response_hex, flagAt + 1, 32))
}

const recording = {
  reference: 'ts-stack@edf6e03 (unmodified)',
  node: process.version,
  recorder: 'tests/support/wire_flags_1002.mjs',
  crate_base_writer: 'bsv-rs@d892e206 WalletWireTransceiver::list_actions',
  request_rows,
  request_flag_rows,
  crate_base_rows,
  processor_refusal_rows,
  response_rows,
  response_flag_rows,
  transceiver_refusal_rows
}
const text = JSON.stringify(recording, null, 2) + '\n'
if (outPath === undefined) process.stdout.write(text)
else writeFileSync(outPath, text)
