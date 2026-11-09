// #796: the reference's LookupResolver merge on lookup outputs whose `txid`
// hint disagrees with their BEEF's subject (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/LookupResolver.ts:1101-1115` (mergeAnswer)
// and `:2223-2240` (resolveTxIdForOutput)), driven through the reference's
// own `LookupResolver.query` with a scripted facilitator answering each
// `.invalid` host from the shape (never dialled) and `hostOverrides` naming
// the hosts in the shape's order, a fresh in-memory reputation store per
// shape. The input (the BEEFs, their txids and the shapes) is printed by
// `tests/lookup_hint_merge_796.rs`'s ignored emitter, this crate's writer.
//
// The bundle:
//   W=/Volumes/Lanes/out/bsv-rs/fix-796/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf "export * from './packages/sdk/mod.js'\n" > "$W/entry796.ts"
//   (cd "$W" && bun build entry796.ts --target node --format esm --outfile "$W/ref796.mjs")
//   cargo test --features overlay --test lookup_hint_merge_796 emit -- --ignored --nocapture
//     (the JSON object it prints saved as input796.json)
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/lookup_hint_merge_796.mjs \
//     "$W/ref796.mjs" input796.json > tests/vectors/lookup_hint_merge_796.json
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const { LookupResolver, Utils } = sdk
const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const SERVICE = 'ls_hint_merge_796'

const hintText = (hint) => {
  if (hint === null || hint === undefined) return undefined
  if (hint === 'A_upper') return input.txids.A.toUpperCase()
  return input.txids[hint]
}
const txOf = (beef) => {
  const hex = Utils.toHex(beef)
  return Object.keys(input.beefs).find((k) => input.beefs[k] === hex)
}
const hintName = (txid) => {
  if (txid === undefined) return null
  if (txid === input.txids.A.toUpperCase()) return 'A_upper'
  return Object.keys(input.txids).find((k) => input.txids[k] === txid) ?? txid
}

const shapes = []
for (const shape of input.shapes) {
  const answers = new Map()
  const hosts = shape.hosts.map((h) => {
    const url = `https://${h.role}-${shape.name}-796.invalid`.replaceAll('_', '-')
    answers.set(url, {
      type: 'output-list',
      outputs: h.outputs.map((o) => {
        const out = { beef: Utils.toArray(input.beefs[o.tx], 'hex'), outputIndex: o.outputIndex }
        if (o.context !== null) out.context = o.context
        const t = hintText(o.hint)
        if (t !== undefined) out.txid = t
        return out
      })
    })
    return url
  })
  const store = new Map()
  const resolver = new LookupResolver({
    facilitator: { lookup: async (url) => answers.get(url) },
    hostOverrides: { [SERVICE]: hosts },
    reputationStorage: { get: (k) => store.get(k), set: (k, v) => store.set(k, v) }
  })
  let reference
  try {
    const answer = await resolver.query({ service: SERVICE, query: {} })
    reference = {
      type: answer.type,
      outputs: answer.outputs.map((o) => ({
        tx: txOf(o.beef),
        outputIndex: o.outputIndex,
        hint: hintName(o.txid),
        context: o.context ?? null
      }))
    }
  } catch (e) {
    reference = { error: String(e?.message ?? e) }
  }
  shapes.push({ ...shape, reference })
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk LookupResolver.query',
  node: process.version,
  beefs: input.beefs,
  txids: input.txids,
  shapes
}, null, 2) + '\n')
