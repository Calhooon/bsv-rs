// #603: record the pinned reference's HTTPWalletJSON response bound and its
// request snapshot bounds, never handwritten outcomes.
// Build the unmodified SDK: git archive edf6e03 packages/sdk | tar -x -C "$W"
// (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// Node 22: node tests/support/http_json_boundary_603.mjs "$W/sdk.mjs" <output.json>
// The fetch is injected: no URL is contacted and no listener is started.
// A large body is a recipe: `prefix` then `padByte` up to `length` bytes, sent
// in `chunkBytes` chunks from one reused buffer, so no fixture holds 256 MiB.
import { writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'

if (process.versions.node.split('.')[0] !== '22') throw new Error('Use Node 22')
const [sdkPath, outPath] = process.argv.slice(2)
const sdk = await import(pathToFileURL(sdkPath).href)
const { HTTPWalletJSON } = sdk

const MAX = 256 * 1024 * 1024
const CHUNK = 1024 * 1024
const prefix = '{"height":1}'
const body = (length, declared) => ({ prefix, padByte: 0x20, length, chunkBytes: CHUNK, declared })

const cases = [
  { name: 'content_length_list', mode: 'http', call: 'getHeight', args: {},
    body: { prefix, padByte: 0x20, length: prefix.length, chunkBytes: CHUNK, declared: '12, 12' } },
  { name: 'exact_cap_declared', mode: 'http', call: 'getHeight', args: {}, body: body(MAX, String(MAX)) },
  { name: 'exact_cap_chunked', mode: 'http', call: 'getHeight', args: {}, body: body(MAX, null) },
  { name: 'one_past_cap_chunked', mode: 'http', call: 'getHeight', args: {}, body: body(MAX + 1, null) },
  { name: 'unsafe_key_in_outputs', mode: 'snapshot', call: 'createAction',
    requestText: '{"outputs":[{"constructor":1}]}' },
  { name: 'labels_at_bound', mode: 'snapshot', call: 'listActions',
    requestArray: { field: 'labels', item: 0, length: 1_000_000 } },
  { name: 'labels_past_bound', mode: 'snapshot', call: 'listActions',
    requestArray: { field: 'labels', item: 0, length: 1_000_001 } }
]

function stream(recipe) {
  const pad = new Uint8Array(recipe.chunkBytes).fill(recipe.padByte)
  const head = new TextEncoder().encode(recipe.prefix)
  let sent = 0
  return new ReadableStream({
    pull(controller) {
      if (sent >= recipe.length) return controller.close()
      const size = Math.min(recipe.chunkBytes, recipe.length - sent)
      let chunk
      if (sent === 0) {
        chunk = new Uint8Array(size)
        chunk.fill(recipe.padByte)
        chunk.set(head.subarray(0, size))
      } else {
        chunk = size === pad.length ? pad : pad.subarray(0, size)
      }
      sent += size
      controller.enqueue(chunk)
    }
  })
}

for (const c of cases) {
  try {
    if (c.mode === 'http') {
      const headers = { 'Content-Type': 'application/json' }
      if (c.body.declared != null) headers['Content-Length'] = c.body.declared
      const fetch = async () => new Response(stream(c.body), { status: 200, headers })
      const wallet = new HTTPWalletJSON('fixtures.invalid', 'http://127.0.0.1:49151', fetch)
      const answer = await wallet[c.call](structuredClone(c.args))
      c.reference = { accepted: true, height: answer.height }
    } else {
      const request = c.requestText != null
        ? JSON.parse(c.requestText)
        : { [c.requestArray.field]: Array(c.requestArray.length).fill(c.requestArray.item) }
      sdk.snapshotWalletResultRequest(c.call, request)
      c.reference = { accepted: true }
    }
  } catch (error) { c.reference = { error: error.message } }
  console.log(c.name, JSON.stringify(c.reference))
}
writeFileSync(outPath, JSON.stringify({ source: 'ts-stack@edf6e03', node: process.version, cases }, null, 2) + '\n')
