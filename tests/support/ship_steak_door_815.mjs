// #815's fold recorder: a host's answer to `/submit` at the door it comes
// through, as the reference reads it (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`): the unmodified SDK's
// `TopicBroadcaster` over its own `HTTPSOverlayBroadcastFacilitator` on a
// stub `fetch` answering each case's status and body (`readSHIPJSON`,
// `:271-320`; `send`, `:331-388`; the empty check and `validateSTEAK`,
// `:486-496`, `:240-269`, `:222-238`). One interested host, sent one topic.
//
// Per case: `send`, what the facilitator's `send` returned (`ok`, the JSON
// it handed back) or threw (`error`); `broadcast`, the broadcast's code
// (`null` on success); `words`, the message of the host's refusal when the
// broadcaster refused the host. The broadcaster keeps a host's error to
// itself (`:494-496`), so the words are read as they are built: `Error` is
// wrapped for the length of the broadcast and each message starting `SHIP `
// or `Steak ` or `Failed to facilitate` noted. Nothing is dialled.
//
// A body is a recipe both sides build (`body_of` here, `body_of` in
// `tests/overlay_ship_steak_door_815.rs`): `text`, `hex`, `padded` (the
// text then spaces to `total` bytes), `indexes` (`count` indexes 0.. in
// `list`), `topics` (`count` topics), `nested` (`depth` arrays in an index).
// The stub declares each body's true length, as a server does, save
// `undeclared` cases (a chunked answer).
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node \
//     tests/support/ship_steak_door_815.mjs "$W/sdk.mjs" \
//     tests/vectors/ship_steak_door_815.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const sdk = await import(bundle)
const {
  TopicBroadcaster, HTTPSOverlayBroadcastFacilitator, OverlayAdminTokenTemplate,
  ProtoWallet, PrivateKey, Transaction, Beef, MerklePath, Script
} = sdk

const TOPIC = 'tm_ship_steak'
const HOST = 'https://steak.ship-steak-door-815.invalid'
const MIB = 1024 * 1024

// One SHIP advertisement of TOPIC by the reference's own template under a
// fixed test key (no secret), proven by a block of its own.
const template = new OverlayAdminTokenTemplate(new ProtoWallet(new PrivateKey(7)))
const lockingScript = await template.lock('SHIP', HOST, TOPIC)
const ad = new Transaction(
  1,
  [{ sourceTXID: '11'.repeat(32), sourceOutputIndex: 0, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff }],
  [{ satoshis: 1, lockingScript }],
  0
)
const adBeef = new Beef()
adBeef.mergeBump(new MerklePath(900, [[{ offset: 0, hash: ad.id('hex'), txid: true }]]))
adBeef.mergeRawTx(ad.toBinary())
const answer = { type: 'output-list', outputs: [{ beef: adBeef.toBinary(), outputIndex: 0 }] }
const subject = Transaction.fromBEEF(adBeef.toBinary())

const T = JSON.stringify(TOPIC)
const one = instructions => ({ kind: 'text', text: `{${T}:${instructions}}` })
const admit = '{"outputsToAdmit":[0],"coinsToRetain":[]}'
const outputs = list => one(`{"outputsToAdmit":${list},"coinsToRetain":[]}`)

function bodyOf (body) {
  const enc = new TextEncoder()
  switch (body.kind) {
    case 'text': return enc.encode(body.text)
    case 'hex': return Uint8Array.from(Buffer.from(body.hex, 'hex'))
    case 'padded': {
      const bytes = new Uint8Array(body.total).fill(0x20)
      bytes.set(enc.encode(body.text))
      return bytes
    }
    case 'indexes': {
      const list = `[${Array.from({ length: body.count }, (_, i) => i).join(',')}]`
      const lists = { outputsToAdmit: '[]', coinsToRetain: '[]' }
      lists[body.list] = list
      return enc.encode(`{${T}:{${Object.entries(lists).map(([k, v]) => `"${k}":${v}`).join(',')}}}`)
    }
    case 'topics':
      return enc.encode(`{${Array.from({ length: body.count }, (_, i) => `"tm_n${'x'.repeat(i)}":${admit}`).join(',')}}`)
    case 'nested':
      return enc.encode(`{${T}:{"outputsToAdmit":[${'['.repeat(body.depth)}${']'.repeat(body.depth)}],"coinsToRetain":[]}}`)
    default: throw new Error(`unknown body kind ${body.kind}`)
  }
}

const CASES = [
  // Taken.
  ['control_admit', one(admit)],
  ['control_three_lists', one('{"outputsToAdmit":[0],"coinsToRetain":[1],"coinsRemoved":[2]}')],
  ['control_removed_empty', one('{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[]}')],
  ['control_idle', one('{"outputsToAdmit":[],"coinsToRetain":[]}')],
  ['control_lists_reordered', one('{"coinsToRetain":[],"outputsToAdmit":[0]}')],
  ['control_whitespace', { kind: 'text', text: ` \n{ ${T} : ${admit} }\n ` }],
  ['control_content_type_html', one(admit), { contentType: 'text/html' }],
  ['control_no_content_type', one(admit), { contentType: null }],
  ['control_status_201', one(admit), { status: 201 }],
  // The body is no STEAK.
  ['body_empty', { kind: 'text', text: '' }],
  ['body_open_brace', { kind: 'text', text: '{' }],
  ['body_html', { kind: 'text', text: '<html></html>' }],
  ['body_trailing_text', { kind: 'text', text: `{${T}:${admit}} x` }],
  ['body_bom', { kind: 'hex', hex: 'efbbbf' + Buffer.from(`{${T}:${admit}}`).toString('hex') }],
  ['body_not_utf8', { kind: 'hex', hex: Buffer.from(`{${T}:${admit}}`).toString('hex') + 'ff' }],
  ['body_empty_object', { kind: 'text', text: '{}' }],
  ['body_null', { kind: 'text', text: 'null' }],
  ['body_true', { kind: 'text', text: 'true' }],
  ['body_number', { kind: 'text', text: '5' }],
  ['body_empty_string', { kind: 'text', text: '""' }],
  ['body_string', { kind: 'text', text: '"abc"' }],
  ['body_empty_array', { kind: 'text', text: '[]' }],
  ['body_array_of_number', { kind: 'text', text: '[1]' }],
  ['body_array_of_steak', { kind: 'text', text: `[{${T}:${admit}}]` }],
  // Status.
  ['status_500_with_steak', one(admit), { status: 500 }],
  ['status_404', { kind: 'text', text: 'not found' }, { status: 404 }],
  // Size (`MAX_SHIP_RESPONSE_BYTES`, 1 MiB).
  ['size_one_mib', { kind: 'padded', text: `{${T}:${admit}}`, total: MIB }],
  ['size_one_mib_and_one', { kind: 'padded', text: `{${T}:${admit}}`, total: MIB + 1 }],
  ['size_one_mib_and_one_undeclared', { kind: 'padded', text: `{${T}:${admit}}`, total: MIB + 1 }, { undeclared: true }],
  // Topics.
  ['topic_unsent_alone', { kind: 'text', text: `{"tm_other":${admit}}` }],
  ['topic_unsent_beside_sent', { kind: 'text', text: `{${T}:${admit},"tm_other":${admit}}` }],
  ['topic_proto', { kind: 'text', text: `{"__proto__":${admit}}` }],
  ['topic_lone_surrogate', { kind: 'text', text: `{"\\ud800":${admit}}` }],
  ['topics_65', { kind: 'topics', count: 65 }],
  ['topic_twice_bad_then_good', { kind: 'text', text: `{${T}:null,${T}:${admit}}` }],
  ['topic_twice_good_then_bad', { kind: 'text', text: `{${T}:${admit},${T}:null}` }],
  // The instructions are no record.
  ['instructions_null', one('null')],
  ['instructions_array', one('[]')],
  ['instructions_string', one('"x"')],
  ['instructions_number', one('1')],
  ['instructions_empty_object', one('{}')],
  // An instruction field other than the three.
  ['field_extra', one('{"outputsToAdmit":[0],"coinsToRetain":[],"extra":1}')],
  ['field_extra_alone', one('{"extra":1}')],
  ['field_ancillary_txids', one('{"outputsToAdmit":[0],"coinsToRetain":[],"ancillaryTxids":[]}')],
  ['field_proto', one('{"outputsToAdmit":[0],"coinsToRetain":[],"__proto__":[]}')],
  ['field_case', one('{"outputsToAdmit":[0],"coinsToRetain":[],"CoinsRemoved":[]}')],
  ['field_twice_bad_then_good', one('{"outputsToAdmit":[0,0],"outputsToAdmit":[0],"coinsToRetain":[]}')],
  // A list missing or no array.
  ['outputs_missing', one('{"coinsToRetain":[]}')],
  ['retain_missing', one('{"outputsToAdmit":[0]}')],
  ['outputs_null', one('{"outputsToAdmit":null,"coinsToRetain":[]}')],
  ['retain_null', one('{"outputsToAdmit":[0],"coinsToRetain":null}')],
  ['removed_null', one('{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":null}')],
  ['outputs_object', outputs('{"0":0}')],
  ['outputs_string', outputs('"0"')],
  ['outputs_number', outputs('0')],
  // An index.
  ['index_u32_max', outputs('[4294967295]')],
  ['index_past_u32', outputs('[4294967296]')],
  ['index_past_safe', outputs('[9007199254740993]')],
  ['index_negative', outputs('[-1]')],
  ['index_fraction', outputs('[0.5]')],
  ['index_integral_fraction', outputs('[1.0]')],
  ['index_exponent', outputs('[1e2]')],
  ['index_negative_zero', outputs('[-0]')],
  ['index_past_double', outputs('[1e400]')],
  ['index_string', outputs('["0"]')],
  ['index_null', outputs('[null]')],
  ['index_true', outputs('[true]')],
  ['index_array', outputs('[[0]]')],
  ['index_nested_200', { kind: 'nested', depth: 200 }],
  ['index_repeated', outputs('[0,0]')],
  ['index_repeated_as_fraction', outputs('[1,1.0]')],
  ['index_zero_and_negative_zero', outputs('[0,-0]')],
  ['retain_repeated', one('{"outputsToAdmit":[0],"coinsToRetain":[3,3]}')],
  ['removed_repeated', one('{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[1,2,1]}')],
  ['same_index_in_two_lists', one('{"outputsToAdmit":[0],"coinsToRetain":[0],"coinsRemoved":[0]}')],
  // A list's length (`MAX_SHIP_INSTRUCTION_INDEXES`, 4096).
  ['outputs_4096', { kind: 'indexes', list: 'outputsToAdmit', count: 4096 }],
  ['outputs_4097', { kind: 'indexes', list: 'outputsToAdmit', count: 4097 }],
  ['retain_4097', { kind: 'indexes', list: 'coinsToRetain', count: 4097 }],
  ['removed_4097', { kind: 'indexes', list: 'coinsRemoved', count: 4097 }]
]

const OrigError = globalThis.Error
async function run (body, options = {}) {
  const bytes = bodyOf(body)
  const status = options.status ?? 200
  const headers = {}
  if (options.contentType !== null) headers['content-type'] = options.contentType ?? 'application/json'
  if (options.undeclared !== true) headers['content-length'] = String(bytes.byteLength)
  const fetchStub = async () => new Response(bytes, { status, headers })
  const real = new HTTPSOverlayBroadcastFacilitator(fetchStub, false)
  let send
  const facilitator = {
    send: async (url, tagged) => {
      try {
        const value = await real.send(url, tagged)
        send = { ok: JSON.stringify(value) ?? null }
        return value
      } catch (error) {
        send = { error: String(error?.message ?? error) }
        throw error
      }
    }
  }
  const broadcaster = new TopicBroadcaster([TOPIC], {
    resolver: { query: async () => answer },
    facilitator
  })
  const noted = []
  globalThis.Error = new Proxy(OrigError, {
    construct (target, args, newTarget) {
      if (typeof args[0] === 'string' && /^(SHIP |Steak |Failed to facilitate)/.test(args[0])) noted.push(args[0])
      return Reflect.construct(target, args, newTarget === globalThis.Error ? target : newTarget)
    }
  })
  let result
  try {
    result = await broadcaster.broadcast(subject)
  } finally {
    globalThis.Error = OrigError
  }
  if (send?.ok != null && send.ok.length > 256) send = { ok_bytes: send.ok.length }
  return {
    send,
    broadcast: result.status === 'success' ? null : result.code,
    words: noted.length === 0 ? null : noted[noted.length - 1]
  }
}

const cases = []
for (const [name, body, options] of CASES) {
  cases.push({ name, body, ...(options ?? {}), reference: await run(body, options) })
}

writeFileSync(out, JSON.stringify({
  description: "A host's answer to /submit at the door it comes through (#815's fold): the reference's TopicBroadcaster over its own HTTPSOverlayBroadcastFacilitator on a stub fetch, one interested host sent one topic. ts-stack@edf6e03 SHIPBroadcaster.ts:222-320,331-388,486-496 under Node " + process.version + '. Recorder: tests/support/ship_steak_door_815.mjs.',
  topic: TOPIC,
  host: HOST,
  cases
}, null, 2) + '\n')
console.log(`${cases.length} cases`)
