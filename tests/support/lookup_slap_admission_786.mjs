// #786 recorder: the hosts the reference's SLAP discovery admits from an
// advertisement by its value and its txid hint (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/LookupResolver.ts:2194-2216`,
// `extractHostsFromAnswer`: a hint that, lower-cased, is not the BEEF
// subject's txid skips the output at `:2201`; an output of other than 1
// satoshi skips it at `:2203`). Each case drives the unmodified SDK's
// `LookupResolver.query` through a scripted facilitator: the tracker (an
// `.invalid` name) answers the case's one output, and the facilitator
// records every URL it is asked; nothing is dialled. The hosts asked after
// the tracker are the hosts the discovery admitted. The advertisements are
// written by the reference's own `OverlayAdminTokenTemplate` under a
// `ProtoWallet` of a fixed test key. Build the bundle at the pin and run
// under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/lookup_slap_admission_786.mjs \
//     "$W/sdk.mjs" tests/vectors/lookup_slap_admission_786.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const sdk = await import(bundle)
const { LookupResolver, OverlayAdminTokenTemplate, ProtoWallet, PrivateKey, Transaction, Beef, MerklePath, Script } = sdk

const SERVICE = 'ls_slap_admission'
// A fixed test key, no secret: the advertiser's identity.
const wallet = new ProtoWallet(new PrivateKey(7))
const template = new OverlayAdminTokenTemplate(wallet)

// A transaction of one made-up input whose output 0 is the advertisement at
// `satoshis`, proven by a block of its own (a lone leaf at offset 0).
async function advertisement (host, satoshis) {
  const lockingScript = await template.lock('SLAP', host, SERVICE)
  const tx = new Transaction(
    1,
    [{ sourceTXID: '11'.repeat(32), sourceOutputIndex: 0, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff }],
    [{ satoshis, lockingScript }],
    0
  )
  const txid = tx.id('hex')
  const beef = new Beef()
  beef.mergeBump(new MerklePath(900, [[{ offset: 0, hash: txid, txid: true }]]))
  beef.mergeRawTx(tx.toBinary())
  return { txid, beef: beef.toBinary() }
}

const OTHER = 'ab'.repeat(32)
const CASES = [
  { name: 'zero_satoshis', satoshis: 0, hint: () => undefined },
  { name: 'one_satoshi', satoshis: 1, hint: () => undefined },
  { name: 'two_satoshis', satoshis: 2, hint: () => undefined },
  { name: 'hint_absent', satoshis: 1, hint: () => undefined },
  { name: 'hint_agreeing', satoshis: 1, hint: txid => txid },
  { name: 'hint_agreeing_upper_case', satoshis: 1, hint: txid => txid.toUpperCase() },
  { name: 'hint_disagreeing', satoshis: 1, hint: () => OTHER }
]

const cases = []
for (const c of CASES) {
  const tracker = `https://tracker-${c.name.replace(/_/g, '-')}.slap-admission-786.invalid`
  const host = `https://host-${c.name.replace(/_/g, '-')}.slap-admission-786.invalid`
  const { txid, beef } = await advertisement(host, c.satoshis)
  const hint = c.hint(txid)
  const output = { beef, outputIndex: 0 }
  if (hint !== undefined) output.txid = hint
  const asked = []
  const facilitator = {
    lookup: async (url, question) => {
      asked.push(url)
      if (url === tracker) return { type: 'output-list', outputs: [output] }
      return { type: 'output-list', outputs: [] }
    }
  }
  const resolver = new LookupResolver({ facilitator, slapTrackers: [tracker] })
  let refusal = null
  try {
    await resolver.query({ service: SERVICE, query: {} })
  } catch (error) {
    refusal = String(error?.message ?? error)
  }
  if (asked[0] !== tracker) throw new Error(`${c.name}: the tracker was not asked first: ${asked}`)
  cases.push({
    name: c.name,
    satoshis: c.satoshis,
    txid,
    hint: hint ?? null,
    beef: Buffer.from(beef).toString('hex'),
    output_index: 0,
    advertised: host,
    hosts: asked.slice(1),
    refusal
  })
}

writeFileSync(
  out,
  JSON.stringify(
    {
      description:
        "#786: the hosts the reference's SLAP discovery admits from one advertisement by its value and its txid hint, recorded by tests/support/lookup_slap_admission_786.mjs under ts-stack@edf6e03 (LookupResolver.ts:2194-2216).",
      reference: 'ts-stack@edf6e03',
      node: process.version,
      service: SERVICE,
      cases
    },
    null,
    2
  ) + '\n'
)
