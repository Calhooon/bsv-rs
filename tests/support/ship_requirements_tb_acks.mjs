// Lane fix-tb-acks recorder: the reference's acknowledgment requirements
// (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
// the construction check of each requirement's topic list
// (`snapshotAcknowledgmentRequirement`, `:182-193`, called at `:430-444`
// and per specific host at `:212-216`), and the broadcast's verdict when an
// interested host fails, answers no topic or acknowledges some topics, under
// each requirement (the map seeded at `:511-512`, the checks at `:538-546`,
// the codes at `:572`, `:596`, `:615`). Each case builds the unmodified
// SDK's `TopicBroadcaster` afresh with `resolver: { query: async () =>
// answer }` (two hosts, each advertising both topics: four SHIP
// advertisements by the reference's own `OverlayAdminTokenTemplate` under a
// `ProtoWallet` of a fixed test key) and a facilitator whose `send(host)`
// answers by the host's scripted behaviour. Nothing is dialled. Build the
// bundle at the pin and run under Node 22 (as #804's recorder):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node \
//     tests/support/ship_requirements_tb_acks.mjs "$W/sdk.mjs" \
//     tests/vectors/ship_requirements_tb_acks.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const sdk = await import(bundle)
const { TopicBroadcaster, OverlayAdminTokenTemplate, ProtoWallet, PrivateKey, Transaction, Beef, MerklePath, Script } = sdk

const TOPICS = ['tm_alpha', 'tm_beta']
// A fixed test key, no secret: the advertiser's identity.
const wallet = new ProtoWallet(new PrivateKey(7))
const template = new OverlayAdminTokenTemplate(wallet)

const host = name => `https://${name}.ship-requirements-tb-acks.invalid`
const A = host('a')
const B = host('b')
const C = host('c')

// The SHIP advertisement of `domain` for `topic`, its own made-up input
// (`seed`) and a block of its own (a lone leaf at offset 0).
async function advertisement (domain, topic, seed) {
  const lockingScript = await template.lock('SHIP', domain, topic)
  const tx = new Transaction(
    1,
    [{ sourceTXID: '11'.repeat(32), sourceOutputIndex: seed, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff }],
    [{ satoshis: 1, lockingScript }],
    0
  )
  const txid = tx.id('hex')
  const beef = new Beef()
  beef.mergeBump(new MerklePath(900, [[{ offset: 0, hash: txid, txid: true }]]))
  beef.mergeRawTx(tx.toBinary())
  return { txid, beef: beef.toBinary(), domain, topic }
}

const ads = [
  await advertisement(A, 'tm_alpha', 0),
  await advertisement(A, 'tm_beta', 1),
  await advertisement(B, 'tm_alpha', 2),
  await advertisement(B, 'tm_beta', 3)
]
const answer = { type: 'output-list', outputs: ads.map(a => ({ beef: a.beef, outputIndex: 0 })) }

// The transaction broadcast: a proven one, so `toBEEF` needs no source.
const subject = Transaction.fromBEEF(ads[0].beef)

// A host's answer by behaviour, to the topics it is sent.
const admit = { outputsToAdmit: [0], coinsToRetain: [] }
const idle = { outputsToAdmit: [], coinsToRetain: [] }
const BEHAVIOURS = {
  ack: topics => Object.fromEntries(topics.map(t => [t, admit])),
  fail: () => { throw new Error('host refused') },
  empty: () => ({}),
  idle: topics => Object.fromEntries(topics.map(t => [t, idle])),
  alpha_only: topics => Object.fromEntries(topics.map(t => [t, t === 'tm_alpha' ? admit : idle])),
  beta_only: topics => Object.fromEntries(topics.map(t => [t, t === 'tm_beta' ? admit : idle]))
}

// A requirement in the reference's config form; `undefined` the default.
function config (requirement) {
  const c = {}
  if (requirement.all !== undefined) c.requireAcknowledgmentFromAllHostsForTopics = requirement.all
  if (requirement.any !== undefined) c.requireAcknowledgmentFromAnyHostForTopics = requirement.any
  if (requirement.specific !== undefined) c.requireAcknowledgmentFromSpecificHostsForTopics = requirement.specific
  return c
}

async function run (requirement, behaviours) {
  const facilitator = {
    send: async (url, tagged) => BEHAVIOURS[behaviours[url]]([...tagged.topics])
  }
  let broadcaster
  try {
    broadcaster = new TopicBroadcaster(TOPICS, {
      resolver: { query: async () => answer },
      facilitator,
      ...config(requirement)
    })
  } catch (error) {
    return { constructor_refusal: String(error?.message ?? error) }
  }
  if (behaviours == null) return { constructed: true }
  try {
    const result = await broadcaster.broadcast(subject)
    return {
      status: result.status,
      code: result.code ?? null,
      description: result.description ?? null,
      message: result.message ?? null
    }
  } catch (error) {
    return { refusal: String(error?.message ?? error) }
  }
}

// The construction check (`:182-193`, `:430-444`, `:212-216`).
const many = Array.from({ length: 65 }, (_, i) => `tm_t${String.fromCharCode(97 + (i % 26))}${'x'.repeat(Math.floor(i / 26))}`)
const construction = []
for (const [name, requirement] of [
  ['all_hosts_outside', { all: ['tm_other'] }],
  ['all_hosts_one_outside', { all: ['tm_alpha', 'tm_other'] }],
  ['any_host_outside', { any: ['tm_other'] }],
  ['specific_host_outside', { specific: { [A]: ['tm_other'] } }],
  ['specific_host_outside_key_normalized', { specific: { [`${A}/`]: ['tm_other'] } }],
  ['all_and_any_outside', { all: ['tm_other'], any: ['tm_gamma'] }],
  ['any_and_specific_outside', { any: ['tm_other'], specific: { [A]: ['tm_other'] } }],
  ['all_hosts_not_canonical', { all: ['tm_Alpha'] }],
  ['any_host_duplicate', { any: ['tm_alpha', 'tm_alpha'] }],
  ['specific_host_not_canonical', { specific: { [A]: ['ls_alpha'] } }],
  ['all_hosts_65', { all: many }],
  ['all_hosts_inside', { all: ['tm_alpha'] }],
  ['any_host_both', { any: ['tm_beta', 'tm_alpha'] }],
  ['all_hosts_empty', { all: [] }],
  ['any_host_empty', { any: [] }],
  ['specific_host_empty', { specific: { [A]: [] } }],
  ['all_hosts_all', { all: 'all' }],
  ['all_hosts_any', { all: 'any' }],
  ['any_host_any', { any: 'any' }],
  ['specific_host_all_of_uninterested', { specific: { [C]: 'all' } }]
]) {
  construction.push({ name, requirement, ...(await run(requirement)) })
}

// The broadcasts: two interested hosts, each by its behaviour, under each
// requirement.
const SCENARIOS = [
  ['ack', 'ack'],
  ['ack', 'fail'],
  ['ack', 'empty'],
  ['ack', 'idle'],
  ['ack', 'alpha_only'],
  ['alpha_only', 'beta_only'],
  ['idle', 'idle'],
  ['fail', 'fail']
]
const REQUIREMENTS = [
  ['default', {}],
  ['all_hosts_all', { all: 'all' }],
  ['all_hosts_any', { all: 'any' }],
  ['all_hosts_alpha', { all: ['tm_alpha'] }],
  ['all_hosts_empty', { all: [] }],
  ['any_host_any', { any: 'any' }],
  ['any_host_both', { any: ['tm_alpha', 'tm_beta'] }],
  ['any_host_beta', { any: ['tm_beta'] }],
  ['any_host_empty', { any: [] }],
  ['specific_b_all', { any: [], specific: { [B]: 'all' } }],
  ['specific_b_any', { any: [], specific: { [B]: 'any' } }],
  ['specific_b_beta', { any: [], specific: { [B]: ['tm_beta'] } }],
  ['specific_b_empty', { any: [], specific: { [B]: [] } }],
  ['specific_c_empty', { any: [], specific: { [C]: [] } }],
  ['all_any_and_specific', { all: ['tm_alpha'], any: ['tm_beta'], specific: { [B]: ['tm_beta'] } }]
]
const broadcasts = []
for (const [a, b] of SCENARIOS) {
  for (const [rname, requirement] of REQUIREMENTS) {
    broadcasts.push({
      name: `${a}_${b}__${rname}`,
      behaviours: { a, b },
      requirement,
      ...(await run(requirement, { [A]: a, [B]: b }))
    })
  }
}

// #815: the broadcast topics themselves (`canonicalTopics(topics,
// 'Broadcast topics')`, `:420`, `:156-179`: an array of 1 to 64 unique
// names each matching `/^(?=.{1,50}$)tm_[a-z]+(?:_[a-z]+)*$/`), read ahead
// of the requirements; each case built afresh with its own topics.
async function construct (topics, requirement) {
  try {
    // eslint-disable-next-line no-new
    new TopicBroadcaster(topics, {
      resolver: { query: async () => answer },
      facilitator: { send: async () => ({}) },
      ...config(requirement)
    })
    return { constructed: true }
  } catch (error) {
    return { constructor_refusal: String(error?.message ?? error) }
  }
}
const broadcastTopics = []
for (const [name, topics, requirement] of [
  ['valid', TOPICS, {}],
  ['not_canonical_upper_case', ['tm_Foo'], {}],
  ['not_canonical_prefix', ['invalid_topic'], {}],
  ['not_canonical_digit', ['tm_a1'], {}],
  ['not_canonical_trailing_underscore', ['tm_a_'], {}],
  ['not_canonical_double_underscore', ['tm_a__b'], {}],
  ['not_canonical_bare_prefix', ['tm_'], {}],
  ['not_canonical_after_a_canonical_one', ['tm_alpha', 'tm_Beta'], {}],
  ['empty', [], {}],
  ['fifty_characters', [`tm_${'a'.repeat(47)}`], {}],
  ['fifty_one_characters', [`tm_${'a'.repeat(48)}`], {}],
  ['sixty_four', many.slice(0, 64), {}],
  ['sixty_five', many, {}],
  ['repeated', ['tm_alpha', 'tm_beta', 'tm_alpha'], {}],
  ['not_canonical_named_by_a_requirement_too', ['tm_Foo'], { all: ['tm_Foo'] }],
  ['sixty_four_required_by_all_hosts', many.slice(0, 64), { all: many.slice(0, 64) }],
  ['sixty_five_required_of_sixty_four', many.slice(0, 64), { all: many }]
]) {
  broadcastTopics.push({ name, topics, requirement, ...(await construct(topics, requirement)) })
}

writeFileSync(
  out,
  JSON.stringify(
    {
      description:
        "Lane fix-tb-acks: the reference's acknowledgment requirements, recorded by tests/support/ship_requirements_tb_acks.mjs under ts-stack@edf6e03 (SHIPBroadcaster.ts:182-193,212-216,430-444,511-512,538-546,555-684): the construction check of each requirement's topic list, and the broadcast's status, code, description and message with two interested hosts by their behaviour under each requirement. A requirement is in the reference's config form (absent: the default; 'all', 'any' or a topic list); a specific host's key is the host's URL. #815: broadcast_topics, the construction check of the broadcast topics themselves (canonicalTopics(topics, 'Broadcast topics'), :156-179,420), each case with its own topics and requirement.",
      reference: 'ts-stack@edf6e03',
      node: process.version,
      topics: TOPICS,
      hosts: { a: A, b: B, c: C },
      advertisements: ads.map(a => ({ domain: a.domain, topic: a.topic, txid: a.txid, beef: Buffer.from(a.beef).toString('hex') })),
      construction,
      broadcasts,
      broadcast_topics: broadcastTopics
    },
    null,
    2
  ) + '\n'
)
