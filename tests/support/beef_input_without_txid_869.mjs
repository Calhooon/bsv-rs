// #869's fourth fold recorder: what the reference's `findAtomicTransaction`
// hands back for a transaction whose input names no txid
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts`: `mergeTransaction`,
// `:875-901`, first runs `materializeSourceTXIDs` over the caller's graph,
// `:883` and `Transaction.ts:254-271`, writing each linked source's id into
// the input's `sourceTXID`; `#addInputProof`, `:649-679`, then descends every
// linked source, attaching the BEEF's BUMP to each it proves, `:658-662`).
// Four states of an input that names no txid: (a) a linked source a BUMP of
// the BEEF proves; (b) a linked unproven source whose own input links an
// unproven source, two deep, and (b2) the same with the deepest proven; (c) no
// linked source; (d) a linked source whose id the BEEF does not hold (the
// entry removed after the merge). Only the unmodified SDK supplies the
// answers. Build the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_input_without_txid_869.mjs \
//     "$W/sdk.mjs" tests/vectors/beef_input_without_txid_869.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Transaction, Beef, LockingScript, UnlockingScript, MerklePath } = await import(bundle)

const u = () => UnlockingScript.fromHex('')
const one = () => LockingScript.fromHex('51')
function root (fill, sats) {
  const t = new Transaction()
  t.addInput({ sourceTXID: fill.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  t.addOutput({ satoshis: sats, lockingScript: one() })
  return t
}
function spend (src, sats) {
  const t = new Transaction()
  t.addInput({ sourceTransaction: src, sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  t.addOutput({ satoshis: sats, lockingScript: one() })
  return t
}
function describe (t, depth) {
  if (t == null) return null
  return {
    id: t.id('hex'),
    path: t.merklePath != null,
    inputs: t.inputs.map(i => ({
      sourceTXID: i.sourceTXID ?? null,
      source: depth > 0 ? describe(i.sourceTransaction, depth - 1) : i.sourceTransaction != null
    }))
  }
}
const bump = (txid) => new MerklePath(100, [[{ offset: 0, hash: txid, txid: true }]])
const states = []
function run (state, build) {
  const r = { state }
  const { beef, c, after } = build()
  try { r.childId = c.id('hex') } catch (e) { r.childId = null; r.childIdError = e.message }
  try { beef.mergeTransaction(c); r.mergeError = null } catch (e) { r.mergeError = e.message }
  if (after != null) after(beef)
  r.held = beef.txs.map(t => t.txid)
  r.atomic = r.childId == null ? null : describe(beef.findAtomicTransaction(r.childId), 3)
  states.push(r)
}
run('a', () => {
  const s = root('11', 1000)
  const beef = new Beef()
  beef.mergeBump(bump(s.id('hex')))
  return { beef, c: spend(s, 5) }
})
run('b', () => ({ beef: new Beef(), c: spend(spend(root('22', 1000), 900), 5) }))
run('b2', () => {
  const s0 = root('22', 1000)
  const beef = new Beef()
  beef.mergeBump(bump(s0.id('hex')))
  return { beef, c: spend(spend(s0, 900), 5) }
})
run('c', () => {
  const c = new Transaction()
  c.inputs.push({ sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  c.addOutput({ satoshis: 5, lockingScript: one() })
  return { beef: new Beef(), c }
})
run('d', () => {
  const s = root('33', 1000)
  const sid = s.id('hex')
  return { beef: new Beef(), c: spend(s, 5), after: (b) => b.removeExistingTxid(sid) }
})
const doc = {
  recorded_by: 'tests/support/beef_input_without_txid_869.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk, Node ' + process.version,
  states
}
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')
