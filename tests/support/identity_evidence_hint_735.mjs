// #735: the lookup output's `txid` hint, read by the reference's HTTPS
// facilitator from a JSON answer (`ts-stack@edf6e03`
// `packages/sdk/src/overlay-tools/LookupResolver.ts:327-357`, the member
// kept at `:356`) and from a binary aggregated answer (`:876-940`, each
// output's `txid` its outpoint's), then compared with the evidence's
// subject by `loadEvidenceTransaction`
// (`packages/sdk/src/transaction/TransactionEvidence.ts:110-128`, the
// hint at `:123-124`), which the toolbox's verifier reaches with the whole
// lookup output (`packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634`).
//
// The BEEF is #730's `proven_parent_absent_grandparent` shape, read from
// `tests/vectors/identity_evidence_730.json` (its subject's output 0 the
// reference's own revelation token, read by `parseResults` there). Each
// case serves `{ type: 'output-list', outputs: [{ beef, outputIndex: 0,
// txid? }] }` through the reference's facilitator on a stub fetch, then
// records the hint the facilitator kept, `parseEvidence`'s txid or its
// error, and `parseResults`' outcome (read or skipped) under a tracker
// admitting every root. The binary case is an aggregated answer of one
// outpoint naming the subject.
//
// The bundle (the recipe of tests/support/identity_certificate_record_553.mjs):
//   W=/Volumes/Lanes/out/bsv-rs/fix-735/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk packages/wallet/wallet-toolbox/src | tar -x -C "$W"
//   (the tsconfig.json of tests/support/identity_certificate_record_553.mjs)
//   cat > "$W/entry735.ts" <<'EOT'
//   export * from './packages/sdk/mod.js'
//   export { parseEvidence } from './packages/sdk/src/transaction/TransactionEvidence.js'
//   export { parseResults, IdentityEvidenceVerifier } from './packages/wallet/wallet-toolbox/src/utility/identityUtils.js'
//   EOT
//   (cd "$W" && bun build entry735.ts --target node --format esm --outfile "$W/ref735.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/identity_evidence_hint_735.mjs \
//     "$W/ref735.mjs" tests/vectors/identity_evidence_730.json \
//     > tests/vectors/identity_evidence_hint_735.json
import { readFileSync } from 'fs'
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const {
  parseResults, parseEvidence, defaultTransactionEvidenceLimits: limits,
  HTTPSOverlayLookupFacilitator, Beef, Utils
} = sdk
const v730 = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const shape = v730.shapes.find((s) => s.name === 'proven_parent_absent_grandparent')
const beefHex = shape.beef
const beef = Utils.toArray(beefHex, 'hex')
const subject = shape.selected_txid
const grandparent = v730.grandparent_txid
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }
const question = { service: 'ls_identity', query: { identityKey: '02'.padEnd(66, '0') } }

const served = (body, type) => async () =>
  new Response(body, { status: 200, headers: { 'content-type': type } })
const lookup = async (body, type) =>
  new HTTPSOverlayLookupFacilitator(served(body, type)).lookup('https://ls_identity.invalid', question)

const judge = async (answer) => {
  const output = answer.outputs[0]
  let selected
  try {
    selected = parseEvidence(output, limits).txid
  } catch (e) {
    selected = `refused: ${e.code}`
  }
  const read = await parseResults(answer, tracker)
  return {
    kept_hint: output.txid ?? null,
    selected_txid: selected,
    outcome: read.length === 1 ? 'read' : 'skipped'
  }
}

const cases = []
const hints = [
  ['no_hint', undefined],
  ['hint_the_subject', subject],
  ['hint_the_subject_upper_case', subject.toUpperCase()],
  ['hint_the_grandparent', grandparent],
  ['hint_another_txid', '33'.repeat(32)]
]
for (const [name, txid] of hints) {
  const item = { beef, outputIndex: 0 }
  if (txid !== undefined) item.txid = txid
  const answer = await lookup(JSON.stringify({ type: 'output-list', outputs: [item] }), 'application/json')
  cases.push({ name, wire: 'json', hint: txid ?? null, ...(await judge(answer)) })
}

// The binary aggregated answer: one outpoint (the subject's txid, output 0,
// no context), then the BEEF (`:876-900`).
const w = new Utils.Writer()
w.writeVarIntNum(1)
w.write(Utils.toArray(subject, 'hex'))
w.writeVarIntNum(0)
w.writeVarIntNum(0)
w.write(beef)
const binary = await lookup(new Uint8Array(w.toArray()), 'application/octet-stream')
cases.push({
  name: 'binary_outpoint_names_the_subject',
  wire: 'binary',
  hint: subject,
  atomic_beef: Utils.toHex(binary.outputs[0].beef),
  atomic_txid: Beef.fromBinary(binary.outputs[0].beef).atomicTxid ?? null,
  ...(await judge(binary))
})

process.stdout.write(JSON.stringify({
  description: "#735: the lookup output's txid hint, kept by the reference's HTTPS facilitator from a JSON answer and set from a binary aggregated answer's outpoint, then compared with the evidence's subject (lower-cased) by loadEvidenceTransaction: a disagreeing hint refuses the evidence as invalid-evidence and parseResults skips the output; the port reads it and counts the contradiction (the owner's word of 2026-11-04 13:5xZ)",
  reference: 'ts-stack@edf6e03 packages/sdk/src/overlay-tools/LookupResolver.ts:327-357,876-940; packages/sdk/src/transaction/TransactionEvidence.ts:110-128; packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634',
  node: process.version,
  recorder: 'tests/support/identity_evidence_hint_735.mjs',
  beef_from: 'tests/vectors/identity_evidence_730.json shapes[proven_parent_absent_grandparent].beef',
  beef: beefHex,
  subject_txid: subject,
  grandparent_txid: grandparent,
  cases
}, null, 2) + '\n')
