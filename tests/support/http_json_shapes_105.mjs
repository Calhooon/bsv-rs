// The #105 witnesses: the HTTP JSON bodies of the four certificate calls and
// the two key-linkage calls, as the reference's HTTPWalletJSON sends and reads
// them.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/http_json_shapes_105.mjs \
//     "$W/sdk.mjs" tests/vectors/wallet_http_json_shapes_105.json [--write]
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
// error in `reference_refuses_crate_result`). Without `--write` it compares
// what it computed with the file and exits 1 on a difference.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, vectorPath, flag] = process.argv.slice(2)
const { HTTPWalletJSON } = await import(pathToFileURL(sdkPath).href)

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
