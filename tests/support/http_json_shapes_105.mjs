// The #105 witnesses: the HTTP JSON bodies of the certificate, key-linkage,
// action, key-related and listOutputs calls, as the reference's
// HTTPWalletJSON sends and reads them.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/http_json_shapes_105.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_http_json_shapes_105.json [--write] [--patch FILE]...
//
// Each `--patch` file is a list of `[case, JSON pointer, value]` written by
// the Rust test under `BSV_SHAPES_105_RECORD=<dir>` (this crate's
// transactions, `witnesses.json`, and bodies, `bodies.json`); they are applied
// to the vector before anything is computed, so the vector has one writer and
// keeps its order. Recording a new case: the transactions' patch, the script
// with `--write`, the bodies' patch, the script with `--write` again.
//
// For every case of the vector file it runs the reference's client
// (`substrates/HTTPWalletJSON.ts`) over a fetch that records the body and
// answers with the case's result: `reference_request_body` is the body the
// reference sends for the case's args (`stringifyBRC100`, `:303`) and
// `reference_result` what it returns after `validateWalletResult` (`:341`).
// Then the other direction: it hands the reference the bodies this crate
// writes (`crate_request_body`, `crate_result_body`, recorded by
// `tests/wallet_http_json_shapes_105.rs`): the crate's request parsed as the
// reference's args, which the reference validates and sends again
// (`reference_resends_crate_request`), and the crate's result body served to
// the reference's client (`reference_reads_crate_result`, or the reference's
// error in `reference_refuses_crate_result`). For a discovery case it also
// serves the case's result with each member BRC-100 requires of the entry
// removed in turn (`DISCOVERY_MEMBERS`) and records the reference's refusal
// in `reference_refuses_without`. Without `--write` it compares what it
// computed with the file and exits 1 on a difference.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, vectorPath, ...flags] = process.argv.slice(2)
const flag = flags.includes('--write') ? '--write' : undefined
const patches = flags.filter((f, i) => flags[i - 1] === '--patch')
const { HTTPWalletJSON } = await import(pathToFileURL(sdkPath).href)

// The discovery entry's members BRC-100 requires (`wallet/0100.md:1401-1411`
// at `5119a9b`; `Wallet.interfaces.ts:870-882`), as paths into the entry.
const DISCOVERY_MEMBERS = [
  'certifierInfo',
  'certifierInfo.iconUrl',
  'certifierInfo.description',
  'publiclyRevealedKeyring',
  'decryptedFields'
]

function without (result, member) {
  const copy = JSON.parse(JSON.stringify(result))
  const keys = member.split('.')
  const last = keys.pop()
  let target = copy.certificates[0]
  for (const key of keys) target = target[key]
  delete target[last]
  return copy
}

function applyPatch (vector, [name, pointer, value]) {
  const c = vector.cases.find(c => c.name === name)
  if (c === undefined) throw new Error(`patch: no case ${name}`)
  const keys = pointer.split('/').slice(1)
  const last = keys.pop()
  let target = c
  for (const key of keys) target = target[key]
  target[last] = value
}

async function run (call, args, responseBody) {
  let sent
  const fetch = async (url, init) => {
    sent = init.body
    return new Response(responseBody, {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    })
  }
  const wallet = new HTTPWalletJSON('fixtures.invalid', 'http://127.0.0.1:3321', fetch)
  try {
    const result = await wallet[call](args)
    return { sent, result }
  } catch (e) {
    return { sent, error: String(e.message ?? e) }
  }
}

const vector = JSON.parse(fs.readFileSync(vectorPath, 'utf8'))
for (const file of patches) {
  for (const patch of JSON.parse(fs.readFileSync(file, 'utf8'))) applyPatch(vector, patch)
}
vector.node = process.version
let differs = false
for (const c of vector.cases) {
  const computed = {}
  const reference = await run(c.call, c.args, JSON.stringify(c.result))
  if (reference.error !== undefined) throw new Error(`${c.name}: ${reference.error}`)
  computed.reference_request_body = reference.sent
  computed.reference_result = JSON.parse(JSON.stringify(reference.result))
  if (c.crate_request_body !== undefined) {
    const resent = await run(c.call, JSON.parse(c.crate_request_body), JSON.stringify(c.result))
    computed.reference_resends_crate_request = resent.error ?? resent.sent
  }
  if (c.crate_result_body !== undefined) {
    const read = await run(c.call, c.args, c.crate_result_body)
    if (read.error !== undefined) {
      computed.reference_refuses_crate_result = read.error
    } else {
      computed.reference_reads_crate_result = JSON.parse(JSON.stringify(read.result))
    }
  }
  if (c.call.startsWith('discoverBy')) {
    computed.reference_refuses_without = {}
    for (const member of DISCOVERY_MEMBERS) {
      const read = await run(c.call, c.args, JSON.stringify(without(c.result, member)))
      computed.reference_refuses_without[member] = read.error ?? null
    }
  }
  for (const [key, value] of Object.entries(computed)) {
    if (JSON.stringify(c[key]) !== JSON.stringify(value)) {
      console.log(`${c.name} ${key}:\n  file     ${JSON.stringify(c[key])}\n  computed ${JSON.stringify(value)}`)
      differs = true
    }
  }
  for (const key of ['reference_reads_crate_result', 'reference_refuses_crate_result']) {
    if (!(key in computed)) delete c[key]
  }
  Object.assign(c, computed)
}
console.log('node', process.version)
if (flag === '--write') {
  fs.writeFileSync(vectorPath, JSON.stringify(vector, null, 2) + '\n')
  console.log('written', vectorPath)
} else if (differs) {
  process.exit(1)
} else {
  console.log('every case agrees with', vectorPath)
}
