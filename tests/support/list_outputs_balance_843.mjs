// #843: record the reference's own answer to a BRC-112 balance query's
// listOutputs result, for every JSON spelling a peer can send of each member
// the balance reader judges (`totalOutputs`, `outputs`, `BEEF`), never
// handwritten outcomes.
// Build the unmodified SDK at the reference's head:
//   git -C ~/bsv/ts-stack archive 11faa7d16 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// Node 22: node tests/support/list_outputs_balance_843.mjs "$W/sdk.mjs" tests/vectors/list_outputs_balance_843.json
// The fetch is injected: no URL is contacted and no listener is started.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const [sdkPath, outPath] = process.argv.slice(2)
const { HTTPWalletJSON } = await import(pathToFileURL(sdkPath).href)

const output = `{"outpoint":"${'ab'.repeat(32)}.0","satoshis":1,"spendable":true}`
// Each spelling is the member's JSON text as a peer sends it; `null` in this
// table (not the text "null") is the member left out.
const totals = [
  ['zero', '0'], ['minus_zero', '-0'], ['zero_point_zero', '0.0'],
  ['minus_zero_point_zero', '-0.0'], ['zero_exponent', '0e5'], ['minus_zero_exponent', '-0E-3'],
  ['exponent', '1e2'], ['exponent_upper', '1E2'], ['exponent_plus', '1e+2'],
  ['exponent_fraction', '1.5e1'], ['exponent_negative_integral', '100e-2'],
  ['hundred_point_zero', '100.0'], ['hundred_point_zeros', '100.000'],
  ['negative', '-1'], ['negative_exponent', '-1e2'], ['fraction', '1.5'],
  ['small_fraction', '0.5'], ['negative_fraction', '-0.5'], ['tiny', '1e-7'],
  ['u32_max', '4294967295'], ['two_32', '4294967296'], ['two_32_point_zero', '4294967296.0'],
  ['two_53_less_one', '9007199254740991'], ['two_53', '9007199254740992'],
  ['two_53_plus_one', '9007199254740993'], ['two_53_plus_two', '9007199254740994'],
  ['u64_less_2047', '18446744073709549568'], ['u64_max', '18446744073709551615'],
  ['two_64', '18446744073709551616'], ['two_64_exponent', '1.8446744073709552e19'],
  ['two_65', '36893488147419103232'], ['big_exponent', '1e30'], ['past_double', '1e400'],
  ['string_digits', '"5"'], ['string_empty', '""'], ['null', 'null'], ['true', 'true'],
  ['false', 'false'], ['array', '[]'], ['array_digit', '[5]'], ['object', '{}'], ['absent', null]
]
const outputsSpellings = [
  ['empty', '[]'], ['one_output', `[${output}]`], ['absent', null], ['null', 'null'],
  ['object', '{}'], ['string', '""'], ['number', '0'], ['true', 'true'], ['array_null', '[null]']
]
const beefSpellings = [
  ['absent', null], ['null', 'null'], ['bytes', '[1]'], ['empty_array', '[]'],
  ['object', '{}'], ['byte_object', '{"0":1}'], ['string', '""'], ['base64_string', '"AQ=="'],
  ['number', '0'], ['true', 'true'], ['false', 'false']
]

function body(total, outputs, beef) {
  const members = []
  if (total !== null) members.push(`"totalOutputs":${total}`)
  if (outputs !== null) members.push(`"outputs":${outputs}`)
  if (beef !== null) members.push(`"BEEF":${beef}`)
  return `{${members.join(',')}}`
}

const cases = []
for (const basket of ['balance default', 'p color balance aa']) {
  for (const limit of [null, 10]) {
    const args = limit === null ? { basket } : { basket, limit }
    const add = (member, form, bodyText) =>
      cases.push({ name: `${member}_${form}`, member, args, bodyText })
    for (const [form, total] of totals) add('totalOutputs', form, body(total, '[]', null))
    for (const [form, outputs] of outputsSpellings) add('outputs', form, body('5', outputs, null))
    for (const [form, beef] of beefSpellings) add('BEEF', form, body('5', '[]', beef))
  }
}

for (const c of cases) {
  const fetch = async () => new Response(c.bodyText, { status: 200, headers: { 'Content-Type': 'application/json' } })
  const wallet = new HTTPWalletJSON('fixtures.invalid', 'http://127.0.0.1:49151', fetch)
  try {
    const result = await wallet.listOutputs(structuredClone(c.args))
    // The total the reference holds, its exact value (a double) in decimal.
    c.reference = { accepted: BigInt(result.totalOutputs).toString() }
  } catch (error) { c.reference = { error: error.message } }
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@11faa7d16', node: process.version, cases }, null, 2) + '\n')
console.log(cases.length, 'cases', cases.filter(c => c.reference.accepted !== undefined).length, 'accepted')
