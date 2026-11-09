// #804 recorder: the hosts the reference's SHIP discovery admits
// (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`,
// `#fetchInterestedHosts` at `:725-789`, `shipEndpoint` at `:103-127`, the
// constructor's specific-host snapshot at `:195-219`). Each case builds the
// unmodified SDK's `TopicBroadcaster` afresh (its interested-hosts cache,
// `:700-718`) with `resolver: { query: async () => answer }` and a
// facilitator whose `send(host)` records the host and acknowledges every
// topic it is sent; `broadcast(tx)` is called once and the hosts sent to
// are the hosts the discovery admitted. A discovery refusal rejects
// `broadcast` (it is outside its `try`); its words are recorded. The
// advertisements are written by the reference's own
// `OverlayAdminTokenTemplate` under a `ProtoWallet` of a fixed test key;
// padding outputs are zero bytes of a stated length (the reference counts a
// BEEF's length before it parses it, `:765-769`). Nothing is dialled. Build
// the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node --max-old-space-size=8192 \
//     tests/support/ship_discovery_admission_804.mjs "$W/sdk.mjs" \
//     tests/vectors/ship_discovery_admission_804.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const sdk = await import(bundle)
const { TopicBroadcaster, OverlayAdminTokenTemplate, ProtoWallet, PrivateKey, Transaction, Beef, MerklePath, Script } = sdk

const TOPIC = 'tm_ship_discovery'
const MIB = 1024 * 1024
// A fixed test key, no secret: the advertiser's identity.
const wallet = new ProtoWallet(new PrivateKey(7))
const template = new OverlayAdminTokenTemplate(wallet)

const host = name => `https://${name}.ship-discovery-804.invalid`

// A transaction of one made-up input (`seed` its source index, so two
// advertisements of one domain differ) whose output 0 is the SHIP
// advertisement of `domain` at `satoshis`, proven by a block of its own (a
// lone leaf at offset 0).
async function advertisement (domain, satoshis = 1, seed = 0) {
  const lockingScript = await template.lock('SHIP', domain, TOPIC)
  const tx = new Transaction(
    1,
    [{ sourceTXID: '11'.repeat(32), sourceOutputIndex: seed, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff }],
    [{ satoshis, lockingScript }],
    0
  )
  const txid = tx.id('hex')
  const beef = new Beef()
  beef.mergeBump(new MerklePath(900, [[{ offset: 0, hash: txid, txid: true }]]))
  beef.mergeRawTx(tx.toBinary())
  return { txid, beef: beef.toBinary(), domain, satoshis }
}

// An output of the answer: an advertisement (with its hint, if any) or
// `bytes` zero bytes standing for a BEEF of that length.
const ad = (a, hint) => ({ kind: 'advertisement', ...a, hint })
const padding = bytes => ({ kind: 'padding', bytes })

function wire (output) {
  if (output.kind === 'padding') return { beef: new Array(output.bytes).fill(0), outputIndex: 0 }
  const item = { beef: output.beef, outputIndex: 0 }
  if (output.hint !== undefined) item.txid = output.hint
  return item
}

function record (output) {
  if (output.kind === 'padding') return { padding: output.bytes }
  return {
    beef: Buffer.from(output.beef).toString('hex'),
    txid: output.txid,
    domain: output.domain,
    satoshis: output.satoshis,
    hint: output.hint ?? null,
    output_index: 0
  }
}

// The transaction broadcast: a proven one, so `toBEEF` needs no source.
const subject = Transaction.fromBEEF((await advertisement(host('subject'))).beef)

async function run (answer, specific) {
  const sent = []
  const facilitator = {
    send: async (url, tagged) => {
      sent.push(url)
      return Object.fromEntries(tagged.topics.map(t => [t, { outputsToAdmit: [0], coinsToRetain: [] }]))
    }
  }
  let broadcaster
  try {
    broadcaster = new TopicBroadcaster([TOPIC], {
      resolver: { query: async () => answer },
      facilitator,
      requireAcknowledgmentFromAnyHostForTopics: 'any',
      ...(specific === undefined ? {} : { requireAcknowledgmentFromSpecificHostsForTopics: specific })
    })
  } catch (error) {
    return { constructor_refusal: String(error?.message ?? error) }
  }
  try {
    const result = await broadcaster.broadcast(subject)
    return {
      hosts: [...sent].sort(),
      status: result.status,
      code: result.code ?? null,
      description: result.description ?? null
    }
  } catch (error) {
    return { refusal: String(error?.message ?? error) }
  }
}

const cases = []
// `compact`: the outputs' count alone is recorded (the 256 and 257 cases,
// whose verdict is the count's; the reader here builds its own outputs).
async function admission (name, outputs, compact = false) {
  const answer = { type: 'output-list', outputs: outputs.map(wire) }
  const recorded = compact ? { output_count: outputs.length } : { outputs: outputs.map(record) }
  cases.push({ name, ...recorded, ...(await run(answer)) })
}

{
  const zero = await advertisement(host('zero'), 0)
  await admission('zero_satoshis', [ad(zero)])
  const two = await advertisement(host('two'), 2)
  await admission('two_satoshis', [ad(two)])
  const one = await advertisement(host('one'), 1)
  await admission('one_satoshi', [ad(one)])
  await admission('hint_disagreeing', [ad(one, 'ab'.repeat(32))])
  await admission('hint_agreeing_upper_case', [ad(one, one.txid.toUpperCase())])
  await admission('hint_63_digits', [ad(one, one.txid.slice(0, 63))])
  await admission('hint_not_hex', [ad(one, 'zz' + one.txid.slice(2))])
  await admission('origin_upper_case_default_port', [ad(await advertisement('https://Host.ship-discovery-804.invalid:443/'))])
  await admission('https_bsvauth', [ad(await advertisement('https+bsvauth://bsvauth.ship-discovery-804.invalid/'))])
  await admission('wss', [ad(await advertisement('wss://wss.ship-discovery-804.invalid'))])
  await admission('https_with_query', [ad(await advertisement('https://query.ship-discovery-804.invalid/?x=1'))])
  const many = []
  for (let i = 0; i < 33; i++) many.push(ad(await advertisement(host(`many-${String(i).padStart(2, '0')}`))))
  await admission('hosts_33', many)
  const plain = []
  for (let i = 0; i < 256; i++) plain.push(ad(await advertisement(host('plain'), 1, i)))
  await admission('outputs_256', plain, true)
  await admission('outputs_257', [...plain, ad(await advertisement(host('plain'), 1, 256))], true)
  const before = await advertisement(host('before'))
  const after = await advertisement(host('after'))
  await admission('total_budget', [
    ad(before), padding(16 * MIB), padding(16 * MIB), padding(16 * MIB), padding(16 * MIB), ad(after)
  ])
  await admission('over_16_mib_uncounted', [
    padding(16 * MIB + 1), padding(16 * MIB), padding(16 * MIB), padding(16 * MIB), ad(after)
  ])
  cases.push({ name: 'not_output_list', answer: { type: 'freeform', result: {} }, ...(await run({ type: 'freeform', result: {} })) })
}

// The constructor's specific-host keys (`:195-219`).
const specific = []
{
  const a = await advertisement(host('host'))
  const answer = { type: 'output-list', outputs: [wire(ad(a))] }
  for (const [name, keys] of [
    ['key_with_trailing_slash', ['https://host.ship-discovery-804.invalid/']],
    ['key_upper_case_default_port', ['https://HOST.ship-discovery-804.invalid:443']],
    ['key_of_another_host', ['https://other.ship-discovery-804.invalid']],
    ['keys_33', Array.from({ length: 33 }, (_, i) => host(`key-${i}`))],
    ['keys_of_one_origin', ['https://host.ship-discovery-804.invalid/', 'https://HOST.ship-discovery-804.invalid:443']],
    ['key_with_path', ['https://host.ship-discovery-804.invalid/submit']],
    ['key_http', ['http://host.ship-discovery-804.invalid']],
    ['key_no_url', ['host.ship-discovery-804.invalid']]
  ]) {
    const requirement = Object.fromEntries(keys.map(k => [k, 'all']))
    specific.push({ name, keys, advertisement: record(ad(a)), ...(await run(answer, requirement)) })
  }
}

writeFileSync(
  out,
  JSON.stringify(
    {
      description:
        "#804: the hosts the reference's SHIP discovery admits and the specific-host keys its constructor takes, recorded by tests/support/ship_discovery_admission_804.mjs under ts-stack@edf6e03 (SHIPBroadcaster.ts:103-127,195-219,725-789). A padding output is that many zero bytes there; a reader here serves a parseable BEEF of the same length.",
      reference: 'ts-stack@edf6e03',
      node: process.version,
      topic: TOPIC,
      cases,
      specific
    },
    null,
    2
  ) + '\n'
)
