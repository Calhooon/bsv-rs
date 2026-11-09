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
// The fold's binary cases (`extractAtomicOutputs`, `:905-936`): one BEEF of
// two transactions, the shape above merged (`Beef.mergeBeef`) with #737's
// `second_name_11` BEEF (a proven transaction whose output 0 is a second
// token of the subject, read from `tests/vectors/identity_resolve_737.json`),
// served as an aggregated answer of two outpoints, each transaction's
// output 0: every output's `beef` the reference's `toBinaryAtomic` of its
// own outpoint's txid and its `txid` that outpoint's, recorded with
// `parseEvidence`'s subject per output and `parseResults`' count; the same
// BEEF under one outpoint named twice (one atomic BEEF, cached); an
// outpoint naming a txid the BEEF does not hold, and an answer of no
// outpoint and no BEEF, each with the facilitator's error.
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
//     tests/vectors/identity_resolve_737.json \
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

// The fold: a binary aggregated answer over a BEEF of two transactions.
const v737 = JSON.parse(readFileSync(process.argv[4], 'utf8'))
const second = v737.shapes
  .find((s) => s.name === 'refused_first_then_token').outputs
  .find((o) => o.builder === 'second_name_11')
const secondBeef = Beef.fromBinary(Utils.toArray(second.beef, 'hex'))
const secondTxid = secondBeef.txs.at(-1).txid
const both = Beef.fromBinary(beef)
both.mergeBeef(secondBeef)
const bothBytes = both.toBinary()
const aggregated = (outpoints, beefBytes) => {
  const w = new Utils.Writer()
  w.writeVarIntNum(outpoints.length)
  for (const [txid, index] of outpoints) {
    w.write(Utils.toArray(txid, 'hex'))
    w.writeVarIntNum(index)
    w.writeVarIntNum(0)
  }
  w.write(beefBytes)
  return new Uint8Array(w.toArray())
}
const binaryCase = async (name, outpoints, beefBytes) => {
  const entry = {
    name,
    wire: 'binary',
    outpoints: outpoints.map(([txid, outputIndex]) => ({ txid, outputIndex }))
  }
  let answer
  try {
    answer = await lookup(aggregated(outpoints, beefBytes), 'application/octet-stream')
  } catch (e) {
    return { ...entry, error: e.message }
  }
  entry.outputs = answer.outputs.map((output) => {
    let selected
    try {
      selected = parseEvidence(output, limits).txid
    } catch (e) {
      selected = `refused: ${e.code}`
    }
    return {
      kept_hint: output.txid ?? null,
      output_index: output.outputIndex,
      atomic_beef: Utils.toHex(output.beef),
      atomic_txid: Beef.fromBinary(output.beef).atomicTxid ?? null,
      selected_txid: selected
    }
  })
  entry.read = (await parseResults(answer, tracker)).length
  return entry
}
const binary_cases = [
  await binaryCase('binary_two_transactions', [[subject, 0], [secondTxid, 0]], bothBytes),
  await binaryCase('binary_two_transactions_reversed', [[secondTxid, 0], [subject, 0]], bothBytes),
  await binaryCase('binary_one_outpoint_twice', [[subject, 0], [subject, 0]], bothBytes),
  await binaryCase('binary_outpoint_names_an_absent_txid', [[subject, 0], ['33'.repeat(32), 0]], bothBytes),
  await binaryCase('binary_no_outpoint_no_beef', [], [])
]

process.stdout.write(JSON.stringify({
  description: "#735: the lookup output's txid hint, kept by the reference's HTTPS facilitator from a JSON answer and set from a binary aggregated answer's outpoint, then compared with the evidence's subject (lower-cased) by loadEvidenceTransaction: a disagreeing hint refuses the evidence as invalid-evidence and parseResults skips the output; the port reads it and counts the contradiction (the owner's word of 2026-11-04 13:5xZ)",
  reference: 'ts-stack@edf6e03 packages/sdk/src/overlay-tools/LookupResolver.ts:327-357,876-940; packages/sdk/src/transaction/TransactionEvidence.ts:110-128; packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634',
  node: process.version,
  recorder: 'tests/support/identity_evidence_hint_735.mjs',
  beef_from: 'tests/vectors/identity_evidence_730.json shapes[proven_parent_absent_grandparent].beef',
  beef: beefHex,
  subject_txid: subject,
  grandparent_txid: grandparent,
  cases,
  binary_description: "the fold (#735, the reads): a binary aggregated answer's outputs each carry the reference's toBinaryAtomic of their own outpoint's txid, one atomic BEEF per distinct txid (extractAtomicOutputs, LookupResolver.ts:905-936), so the evidence check selects each outpoint's own subject and its hint agrees",
  second_beef_from: 'tests/vectors/identity_resolve_737.json shapes[refused_first_then_token].outputs[second_name_11].beef',
  second_txid: secondTxid,
  two_transactions_beef: Utils.toHex(bothBytes),
  binary_cases
}, null, 2) + '\n')
