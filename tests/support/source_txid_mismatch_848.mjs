// #848's recorder: what the reference answers for an input whose `sourceTXID`
// differs from its linked source's id, at its three sites
// (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`):
//   sign      `:964-984`   refused over a complete or anchored source (one
//                          with an input or a merkle path), a no-input
//                          descriptor exempt;
//   verify    `:1423-1432` refused whatever the source holds, unless
//                          'scripts only' (`:1433-1436`, the named txid used);
//   preimage  `:2157-2169` refused for any linked source.
// The cells: matching; a mismatch over a complete source; over a proven
// source; over an anchored source without inputs; over a no-input descriptor;
// a `fromEF` transaction; the text in upper case, matching; the named txid
// another input's source's id; and three orders of two refusals on one input
// (a mismatch beside a missing source output, beside a missing unlocking
// script, and behind an earlier input's failing script). For each: `sign`
// (the template's calls counted), `verify` with a tracker, `verify('scripts
// only')` and `preimage(0)`, each on a fresh build, the verdict or the thrown
// words. The survey's doors (`fee`, `getFee`, `toEF`) on the complete-source
// mismatch are recorded beside them. Only the unmodified SDK supplies the
// answers. Build the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/source_txid_mismatch_848.mjs \
//     "$W/sdk.mjs" tests/vectors/source_txid_mismatch_848.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const {
  Transaction, LockingScript, UnlockingScript, MerklePath,
  P2PKH, PushDrop, RPuzzle, OverlayAdminTokenTemplate, ProtoWallet, PrivateKey, BigNumber
} = await import(bundle)

const u = () => UnlockingScript.fromHex('')
const one = () => LockingScript.fromHex('51')
const OTHER = 'ab'.repeat(32)
const tracker = { isValidRootForHeight: async () => true, currentHeight: async () => 1000 }
const bump = (txid) => new MerklePath(100, [[{ offset: 0, hash: txid, txid: true }]])

// A proven root: one input naming `fill` repeated, `outs` outputs, a path.
function root (fill, sats, outs = 1) {
  const t = new Transaction()
  t.addInput({ sourceTXID: fill.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  for (let i = 0; i < outs; i++) t.addOutput({ satoshis: sats, lockingScript: one() })
  t.merklePath = bump(t.id('hex'))
  return t
}
// A complete unproven source: spends `src`'s output 0.
function middle (src, sats) {
  const t = new Transaction()
  t.addInput({ sourceTransaction: src, sourceTXID: src.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  t.addOutput({ satoshis: sats, lockingScript: one() })
  return t
}
// A descriptor as `fromEF` builds it (`:392-397`): no inputs, the one output.
function descriptor (sats) {
  const t = new Transaction(undefined, [], [], undefined)
  t.outputs[0] = { satoshis: sats, lockingScript: one() }
  return t
}
// The child: one input per `[source, namedTxid, vout, unlocking]`.
function child (ins) {
  const t = new Transaction()
  for (const [src, named, vout, unlocking] of ins) {
    const input = { sourceTransaction: src, sourceOutputIndex: vout ?? 0, sequence: 0xffffffff }
    if (named !== undefined) input.sourceTXID = named
    if (unlocking !== null) input.unlockingScript = unlocking ?? u()
    t.addInput(input)
  }
  t.addOutput({ satoshis: 5, lockingScript: one() })
  return t
}

const cells = {
  matching: () => { const s = middle(root('11', 1000), 900); return child([[s, s.id('hex')]]) },
  mismatch_complete: () => child([[middle(root('11', 1000), 900), OTHER]]),
  mismatch_proven: () => child([[root('11', 1000), OTHER]]),
  mismatch_anchored_no_inputs: () => {
    const d = descriptor(900)
    d.merklePath = bump(d.id('hex'))
    return child([[d, OTHER]])
  },
  mismatch_descriptor: () => child([[descriptor(900), OTHER]]),
  from_ef: () => {
    const s = middle(root('11', 1000), 900)
    return Transaction.fromEF(child([[s, s.id('hex')]]).toEF())
  },
  upper_matching: () => { const s = middle(root('11', 1000), 900); return child([[s, s.id('hex').toUpperCase()]]) },
  upper_matching_proven: () => { const s = root('11', 1000); return child([[s, s.id('hex').toUpperCase()]]) },
  named_other_inputs_source: () => {
    const a = root('11', 1000)
    const b = root('22', 1000, 2)
    return child([[a, b.id('hex'), 0], [b, b.id('hex'), 1]])
  },
  mismatch_and_output_missing: () => child([[root('11', 1000), OTHER, 5]]),
  mismatch_and_no_unlocking_script: () => child([[root('11', 1000), OTHER, 0, null]]),
  failing_script_before_mismatch: () => {
    const a = root('11', 1000)
    return child([[a, a.id('hex'), 0, UnlockingScript.fromHex('00')], [root('22', 1000), OTHER]])
  }
}

async function attempt (f) {
  try { return { ok: await f() } } catch (e) { return { error: e.message } }
}
function shape (t) {
  return {
    hex: (() => { try { return t.toHex() } catch (e) { return null } })(),
    ef: (() => { try { return Buffer.from(t.toEF()).toString('hex') } catch (e) { return null } })(),
    inputs: t.inputs.map(i => ({
      sourceTXID: i.sourceTXID ?? null,
      sourceOutputIndex: i.sourceOutputIndex,
      source: i.sourceTransaction == null
        ? null
        : {
            id: (() => { try { return i.sourceTransaction.id('hex') } catch (e) { return null } })(),
            inputs: i.sourceTransaction.inputs.length,
            path: i.sourceTransaction.merklePath != null
          }
    }))
  }
}

const recorded = []
for (const [cell, build] of Object.entries(cells)) {
  const r = { cell, built: shape(build()) }
  {
    const t = build()
    let calls = 0
    for (const input of t.inputs) {
      input.unlockingScript = undefined
      input.unlockingScriptTemplate = { sign: async () => { calls++; return u() }, estimateLength: async () => 0 }
    }
    r.sign = await attempt(async () => { await t.sign(); return true })
    r.sign.template_calls = calls
  }
  r.verify_tracker = await attempt(() => build().verify(tracker))
  r.verify_scripts_only = await attempt(() => build().verify('scripts only'))
  r.preimage = await attempt(() => Buffer.from(build().preimage(0)).toString('hex'))
  recorded.push(r)
}

const survey = {}
{
  const build = cells.mismatch_complete
  survey.cell = 'mismatch_complete'
  survey.getFee = await attempt(() => build().getFee())
  survey.fee = await attempt(async () => { const t = build(); await t.fee(1); return t.getFee() })
  survey.toEF = await attempt(() => Buffer.from(build().toEF()).toString('hex'))
}

// The reference's fourth comparison (#848's fold): its stock templates'
// `resolveSourceDetails` (`script/templates/SignatureUtils.ts:94-106`),
// called by `P2PKH.ts:90`, `PushDrop.ts:232`, `RPuzzle.ts:102` and
// `OverlayAdminTokenTemplate.ts:328`, compares the input's `sourceTXID` with
// its linked source's id, a no-input descriptor included. Per template:
// `descriptor`, the input `add_input_from` builds here (a source with no
// input, its output 0 empty, the claimed output at 1, linked under the named
// txid); `complete`, a complete source under another txid; `from_ef`, a
// `fromEF` transaction spending output 0; and for the two templates that
// take the amount and the script (`P2PKH`, `PushDrop`), `named_alone`, the
// reference's own way to sign a claimed outpoint: the named txid, no source,
// the amount and script handed to the template. `sign` is run, its verdict or words recorded, and
// input 0's unlocking script on a success.
const KEY_HEX = '07'.padStart(64, '0')
const key = PrivateKey.fromHex(KEY_HEX)
const wallet = new ProtoWallet(key)
const PROTOCOL = [2, 'source txid test']
const SATS = 900
const lock = () => new P2PKH().lock(key.toPublicKey().toHash())
function claimed () {
  const t = new Transaction(undefined, [], [], undefined)
  t.outputs[0] = { satoshis: 0, lockingScript: new LockingScript() }
  t.outputs[1] = { satoshis: SATS, lockingScript: lock() }
  return t
}
function completeSource () {
  const t = new Transaction()
  const r = root('11', 1000)
  t.addInput({ sourceTransaction: r, sourceTXID: r.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
  t.addOutput({ satoshis: 0, lockingScript: new LockingScript() })
  t.addOutput({ satoshis: SATS, lockingScript: lock() })
  return t
}
function spend (input) {
  const t = new Transaction()
  t.addInput({ sourceOutputIndex: 1, sequence: 0xffffffff, unlockingScript: u(), ...input })
  t.addOutput({ satoshis: 5, lockingScript: one() })
  return t
}
const templates = {
  P2PKH: (amount) => amount
    ? new P2PKH().unlock(key, 'all', false, SATS, lock())
    : new P2PKH().unlock(key, 'all', false),
  PushDrop: (amount) => amount
    ? new PushDrop(wallet).unlock(PROTOCOL, '1', 'self', 'all', false, SATS, lock())
    : new PushDrop(wallet).unlock(PROTOCOL, '1', 'self', 'all', false),
  RPuzzle: () => new RPuzzle('raw').unlock(new BigNumber(12345), key, 'all', false),
  OverlayAdminTokenTemplate: () => new OverlayAdminTokenTemplate(wallet).unlock('SHIP')
}
const templateCells = {
  descriptor: () => spend({ sourceTransaction: claimed(), sourceTXID: OTHER }),
  complete: () => spend({ sourceTransaction: completeSource(), sourceTXID: OTHER }),
  from_ef: () => {
    const s = new Transaction()
    const r = root('11', 1000)
    s.addInput({ sourceTransaction: r, sourceTXID: r.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
    s.addOutput({ satoshis: SATS, lockingScript: lock() })
    const t = spend({ sourceTransaction: s, sourceTXID: s.id('hex') })
    t.inputs[0].sourceOutputIndex = 0
    return Transaction.fromEF(t.toEF())
  },
  named_alone: () => spend({ sourceTXID: OTHER })
}
const templateRecords = []
for (const [template, make] of Object.entries(templates)) {
  for (const [cell, build] of Object.entries(templateCells)) {
    const takesAmount = template === 'P2PKH' || template === 'PushDrop'
    if (cell === 'named_alone' && !takesAmount) continue
    const t = build()
    const r = { template, cell, built: shape(t) }
    t.inputs[0].unlockingScript = undefined
    t.inputs[0].unlockingScriptTemplate = make(cell === 'named_alone')
    r.sign = await attempt(async () => { await t.sign(); return t.inputs[0].unlockingScript.toHex() })
    templateRecords.push(r)
  }
}

// Two refusals of `verify` (#848's fold, the rule read's rows 1 and 2): an
// input that links no source (`Transaction.ts:1396-1400`), whether or not its
// named txid is another input's source, and an amount that is absent or past
// 21e14 (`requireSatoshiAmount`, `:1414-1418` for a source's, `:1464-1474`
// for an output's, the outputs read before the inputs by
// `#validateUnminedTransactionStructure`, `:1367`), with the totals past
// 21e14 (`addSatoshiAmount`).
const MAX = 21e14
const verifyCells = {
  unlinked_named_reachable: () => {
    const b = root('22', 1000, 2)
    const t = child([[b, b.id('hex'), 1]])
    t.inputs.unshift({ sourceTXID: b.id('hex'), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
    return t
  },
  unlinked_unreachable: () => {
    const t = child([])
    t.inputs.push({ sourceTXID: OTHER, sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: u() })
    return t
  },
  absent_source_amount: () => {
    const s = middle(root('11', 1000), 900)
    s.outputs[0].satoshis = undefined
    return child([[s, s.id('hex')]])
  },
  source_amount_past_max: () => {
    const s = middle(root('11', MAX), 900)
    s.outputs[0].satoshis = MAX + 1
    return child([[s, s.id('hex')]])
  },
  input_total_past_max: () => {
    const s = middle(root('11', MAX), MAX)
    const r = middle(root('22', MAX), 1)
    return child([[s, s.id('hex')], [r, r.id('hex')]])
  },
  absent_output_amount: () => {
    const s = middle(root('11', 1000), 900)
    const t = child([[s, s.id('hex')]])
    t.outputs[0].satoshis = undefined
    return t
  },
  output_amount_past_max: () => {
    const s = middle(root('11', 1000), 900)
    const t = child([[s, s.id('hex')]])
    t.outputs[0].satoshis = MAX + 1
    return t
  },
  output_total_past_max: () => {
    const s = middle(root('11', 1000), 900)
    const t = child([[s, s.id('hex')]])
    t.outputs[0].satoshis = MAX
    t.addOutput({ satoshis: 1, lockingScript: one() })
    return t
  },
  absent_output_amount_and_mismatch: () => {
    const t = child([[middle(root('11', 1000), 900), OTHER]])
    t.outputs[0].satoshis = undefined
    return t
  },
  absent_source_amount_and_mismatch: () => {
    const s = middle(root('11', 1000), 900)
    s.outputs[0].satoshis = undefined
    return child([[s, OTHER]])
  }
}
const verifyRecords = []
for (const [cell, build] of Object.entries(verifyCells)) {
  verifyRecords.push({ cell, built: shape(build()), verify_tracker: await attempt(() => build().verify(tracker)) })
}

const doc = {
  recorded_by: 'tests/support/source_txid_mismatch_848.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk, Node ' + process.version,
  other_txid: OTHER,
  cells: recorded,
  survey,
  templates: {
    key_hex: KEY_HEX,
    protocol: PROTOCOL,
    satoshis: SATS,
    cells: templateRecords
  },
  verify_fold: verifyRecords
}
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')
