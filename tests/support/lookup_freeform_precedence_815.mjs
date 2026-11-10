// #815: the reference's LookupResolver.query when some hosts answer
// freeform (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/LookupResolver.ts`: a freeform answer is
// counted by `recordFreeformAnswer`, `:1085-1087`, from
// `recordLookupHostAnswer`, `:1493-1514`; the session's `snapshot`,
// `:1123-1135`, is always an output list; `queryDetailed`, `:1390-1451`,
// returns `{ type: 'output-list', outputs: progress.outputs }`; `query`,
// `:1369-1375`, returns that answer), driven through the reference's own
// `LookupResolver.queryDetailed` with a scripted facilitator answering each
// `.invalid` host from the shape (never dialled) and `hostOverrides` naming
// the hosts in the shape's order, a fresh in-memory reputation store per
// shape. The input (the BEEFs, their txids and the shapes) is printed by
// `tests/lookup_freeform_precedence_815.rs`'s ignored emitter, this crate's
// writer.
//
// The bundle:
//   W=/Volumes/Lanes/out/bsv-rs/fix-815-freeform/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   printf "export * from './packages/sdk/mod.js'\n" > "$W/entry815.ts"
//   (cd "$W" && bun build entry815.ts --target node --format esm --outfile "$W/ref815.mjs")
//   cargo test --features overlay --test lookup_freeform_precedence_815 emit -- --ignored --nocapture
//     (the JSON object it prints saved as input815.json)
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/lookup_freeform_precedence_815.mjs \
//     "$W/ref815.mjs" input815.json > tests/vectors/lookup_freeform_precedence_815.json
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const { LookupResolver, Utils } = sdk
const input = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const SERVICE = 'ls_freeform_815'

const txOf = (beef) => {
  const hex = Utils.toHex(beef)
  return Object.keys(input.beefs).find((k) => input.beefs[k] === hex)
}
const hintName = (txid) => {
  if (txid === undefined) return null
  return Object.keys(input.txids).find((k) => input.txids[k] === txid) ?? txid
}

const shapes = []
for (const shape of input.shapes) {
  const answers = new Map()
  const hosts = shape.hosts.map((h) => {
    const url = `https://${h.role}-${shape.name}-815.invalid`.replaceAll('_', '-')
    if (h.freeform !== undefined) {
      answers.set(url, { type: 'freeform', result: h.freeform })
    } else {
      answers.set(url, {
        type: 'output-list',
        outputs: h.outputs.map((o) => {
          const out = { beef: Utils.toArray(input.beefs[o.tx], 'hex'), outputIndex: o.outputIndex }
          if (o.context !== null) out.context = o.context
          if (o.hint !== null) out.txid = input.txids[o.hint]
          return out
        })
      })
    }
    return url
  })
  const fresh = () => {
    const store = new Map()
    return new LookupResolver({
      facilitator: { lookup: async (url) => answers.get(url) },
      hostOverrides: { [SERVICE]: hosts },
      reputationStorage: { get: (k) => store.get(k), set: (k, v) => store.set(k, v) }
    })
  }
  const resolver = fresh()
  let reference
  try {
    const { answer, progress } = await resolver.queryDetailed({ service: SERVICE, query: {} })
    const plain = await fresh().query({ service: SERVICE, query: {} })
    reference = {
      type: answer.type,
      query_type: plain.type,
      outputs: answer.outputs.map((o) => ({
        tx: txOf(o.beef),
        outputIndex: o.outputIndex,
        hint: hintName(o.txid),
        context: o.context ?? null
      })),
      hostCount: progress.hostCount,
      successfulHosts: progress.successfulHosts,
      emptyHosts: progress.emptyHosts,
      freeformHosts: progress.freeformHosts,
      failedHosts: progress.failedHosts,
      // Each host's successes and failures in the resolver's reputation
      // tracker, in shape order (the tracker is the resolver's own, a
      // TypeScript `private` field, read at run time; ranking a host gives
      // it an entry, so the counts, not the entry, tell a record).
      reputation: Object.fromEntries(shape.hosts.map((h, i) => {
        const entry = resolver.hostReputation.snapshot(hosts[i])
        return [h.role, [entry?.totalSuccesses ?? 0, entry?.totalFailures ?? 0]]
      }))
    }
  } catch (e) {
    reference = { error: String(e?.message ?? e) }
  }
  shapes.push({ ...shape, reference })
}

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03 packages/sdk LookupResolver.queryDetailed and query',
  node: process.version,
  beefs: input.beefs,
  txids: input.txids,
  shapes
}, null, 2) + '\n')
