// #843d7's recorder: what the reference's EF writer answers for an amount at
// the edge of a JavaScript number (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/Transaction.ts`: `#writeEF` `:1127-1164`,
// the linked source output's amount at `:1150`, an output's at `:1158`, the
// unlinked input's `TypeError` at `:1132-1136`, the missing unlocking
// script at `:1143-1145`; `toEF` `:1171-1173`, `toHexEF` `:1215-1217`;
// `primitives/WriterUint8Array.ts:184-185` `writeUInt64LE`;
// `primitives/BigNumber.ts:460-463` the assertion).
//
// The transaction is block 170's (f4184fc5..., #840's and #844's) with a
// third output (1 satoshi, `OP_1`), its input linked to a source of one
// output (50 BTC, the block 9 coinbase's script). One amount at a time is
// set to an edge: 2^53 - 1, 2^53, 2^63, 2^64 (as a JavaScript number; this
// crate's test takes `u64::MAX`, the nearest a `u64` holds), at output 0, 1,
// 2 and at the linked source output. Three two-fault cells record the order
// of the refusals. No negative amount. Only the unmodified SDK answers.
// Build the bundle at the pin and run under Node v22.18.0 (two runs are
// byte-identical):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/transaction_amount_doors_843d7.mjs "$W/sdk.mjs" tests/vectors/transaction_amount_doors_843d7.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Transaction, LockingScript, UnlockingScript, Utils } = await import(bundle)

const TX_HEX =
  '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
const SOURCE_SCRIPT =
  '410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'
const SOURCE_SATOSHIS = 5000000000
const THIRD_SCRIPT = '51'
const THIRD_SATOSHIS = 1
const SECOND_INPUT_TXID = '11'.repeat(32)
const SECOND_INPUT_UNLOCKING = '51'
const SECOND_SOURCE_SCRIPT = '51'
const SECOND_SOURCE_SATOSHIS = 7

const EDGES = [
  ['two_to_the_53_minus_1', 2 ** 53 - 1, '9007199254740991'],
  ['two_to_the_53', 2 ** 53, '9007199254740992'],
  ['two_to_the_63', 2 ** 63, '9223372036854775808'],
  ['two_to_the_64', 2 ** 64, '18446744073709551616']
]
const POSITIONS = ['output_0', 'output_1', 'output_2', 'source_output']

const answer = (f) => {
  try {
    return { ok: true, hex: f() }
  } catch (e) {
    return { ok: false, error_name: String(e && e.name), error: String(e && e.message) }
  }
}

const source = (satoshis, script) =>
  new Transaction(1, [], [{ satoshis, lockingScript: LockingScript.fromHex(script) }], 0)

// Block 170's transaction, a third output, its input linked.
const base = () => {
  const tx = Transaction.fromHex(TX_HEX)
  tx.outputs.push({ satoshis: THIRD_SATOSHIS, lockingScript: LockingScript.fromHex(THIRD_SCRIPT) })
  tx.inputs[0].sourceTransaction = source(SOURCE_SATOSHIS, SOURCE_SCRIPT)
  return tx
}

const place = (tx, position, value) => {
  if (position === 'source_output') tx.inputs[0].sourceTransaction.outputs[0].satoshis = value
  else tx.outputs[Number(position.slice('output_'.length))].satoshis = value
}

// Each door on a transaction of its own, so neither reads the other's cache.
const doors = (build) => ({
  to_ef: answer(() => Utils.toHex(build().toEF())),
  to_hex_ef: answer(() => build().toHexEF())
})

const control = doors(base)
if (!control.to_ef.ok || control.to_ef.hex !== control.to_hex_ef.hex) throw new Error('the control does not write')
if (Transaction.fromHexEF(control.to_ef.hex).toHexEF() !== control.to_ef.hex) throw new Error('the control does not read back')

const cells = []
for (const [edge, value, decimal] of EDGES) {
  for (const position of POSITIONS) {
    cells.push({
      edge,
      satoshis: decimal,
      position,
      ...doors(() => {
        const tx = base()
        place(tx, position, value)
        return tx
      })
    })
  }
}

// A second input: `11`x32:0, `OP_1` as its unlocking script, the final
// sequence; linked (to a source of one output, 7 satoshis, `OP_1`) or not,
// with its unlocking script or without.
const withSecondInput = ({ linked, unlocking }) => {
  const tx = base()
  tx.inputs.push({
    sourceTXID: SECOND_INPUT_TXID,
    sourceOutputIndex: 0,
    unlockingScript: unlocking ? UnlockingScript.fromHex(SECOND_INPUT_UNLOCKING) : undefined,
    sequence: 0xffffffff,
    sourceTransaction: linked ? source(SECOND_SOURCE_SATOSHIS, SECOND_SOURCE_SCRIPT) : undefined
  })
  return tx
}

const twoInputControl = doors(() => withSecondInput({ linked: true, unlocking: true }))
if (!twoInputControl.to_ef.ok) throw new Error('the two-input control does not write')

const two_fault_cells = [
  {
    name: 'source_amount_at_input_0_then_input_1_unlinked',
    second_input: { linked: false, unlocking: true },
    position: 'source_output',
    ...doors(() => {
      const tx = withSecondInput({ linked: false, unlocking: true })
      place(tx, 'source_output', 2 ** 53)
      return tx
    })
  },
  {
    name: 'output_amount_with_input_1_unlinked',
    second_input: { linked: false, unlocking: true },
    position: 'output_0',
    ...doors(() => {
      const tx = withSecondInput({ linked: false, unlocking: true })
      place(tx, 'output_0', 2 ** 53)
      return tx
    })
  },
  {
    name: 'output_amount_with_input_1_lacking_its_unlocking_script',
    second_input: { linked: true, unlocking: false },
    position: 'output_0',
    ...doors(() => {
      const tx = withSecondInput({ linked: true, unlocking: false })
      place(tx, 'output_0', 2 ** 53)
      return tx
    })
  }
]

// #843d7's fold (the rule read of PR #913): an input that names NO txid
// (`sourceTXID` undefined, this crate's `with_source_transaction` and
// `add_input_from_tx`). `#writeEF` then writes the outpoint from
// `i.sourceTransaction.hash()` (`Transaction.ts:1137-1138`), the plain writer
// of the source (`:1059-1089`), ahead of the unlocking script's check
// (`:1143-1145`), so an amount of 2^53 or more in ANY output of that source,
// or of a source it reaches the same way, throws there. Input 0 of the base
// is unnamed; its source carries two outputs: output 0 (spent, 50 BTC, the
// block 9 coinbase's script) and output 1 (1 satoshi, `OP_1`). The
// grandparent: the source's own input names no txid either (`OP_1` its
// unlocking script, the final sequence) and links a grandparent of one
// output (7 satoshis, `OP_1`), where the edge is set.
const OTHER_SCRIPT = '51'
const OTHER_SATOSHIS = 1
const GRANDPARENT_SCRIPT = '51'
const GRANDPARENT_SATOSHIS = 7
const NO_TXID_POSITIONS = ['source_spent_output', 'source_other_output', 'grandparent_output']

const unnamedSource = (withGrandparent) => {
  const s = new Transaction(
    1,
    [],
    [
      { satoshis: SOURCE_SATOSHIS, lockingScript: LockingScript.fromHex(SOURCE_SCRIPT) },
      { satoshis: OTHER_SATOSHIS, lockingScript: LockingScript.fromHex(OTHER_SCRIPT) }
    ],
    0
  )
  if (withGrandparent) {
    s.inputs.push({
      sourceTXID: undefined,
      sourceOutputIndex: 0,
      unlockingScript: UnlockingScript.fromHex('51'),
      sequence: 0xffffffff,
      sourceTransaction: source(GRANDPARENT_SATOSHIS, GRANDPARENT_SCRIPT)
    })
  }
  return s
}

// The base with input 0 naming no txid, its source `unnamedSource`.
const unnamedBase = ({ grandparent = false, vout = 0 } = {}) => {
  const tx = base()
  tx.inputs[0].sourceTXID = undefined
  tx.inputs[0].sourceOutputIndex = vout
  tx.inputs[0].sourceTransaction = unnamedSource(grandparent)
  return tx
}

const placeUnnamed = (tx, position, value) => {
  const s = tx.inputs[0].sourceTransaction
  if (position === 'source_spent_output') s.outputs[0].satoshis = value
  else if (position === 'source_other_output') s.outputs[1].satoshis = value
  else s.inputs[0].sourceTransaction.outputs[0].satoshis = value
}

const noTxidControl = doors(() => unnamedBase({ grandparent: true }))
if (!noTxidControl.to_ef.ok) throw new Error('the no-txid control does not write')
if (Transaction.fromHexEF(noTxidControl.to_ef.hex).toHexEF() !== noTxidControl.to_ef.hex) throw new Error('the no-txid control does not read back')

const noTxidCells = []
for (const [edge, value, decimal] of EDGES) {
  for (const position of NO_TXID_POSITIONS) {
    noTxidCells.push({
      edge,
      satoshis: decimal,
      position,
      ...doors(() => {
        const tx = unnamedBase({ grandparent: true })
        placeUnnamed(tx, position, value)
        return tx
      })
    })
  }
}

// Input 1 naming no txid, its source `unnamedSource` without a grandparent.
const withUnnamedSecondInput = (tx) => {
  tx.inputs.push({
    sourceTXID: undefined,
    sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex(SECOND_INPUT_UNLOCKING),
    sequence: 0xffffffff,
    sourceTransaction: unnamedSource(false)
  })
  return tx
}

const NO_TXID_TWO_FAULTS = [
  ['source_other_output_with_input_0_lacking_its_unlocking_script', () => {
    const tx = unnamedBase()
    tx.inputs[0].unlockingScript = undefined
    placeUnnamed(tx, 'source_other_output', 2 ** 53)
    return tx
  }],
  ['source_spent_output_with_input_0_lacking_its_unlocking_script', () => {
    const tx = unnamedBase()
    tx.inputs[0].unlockingScript = undefined
    placeUnnamed(tx, 'source_spent_output', 2 ** 53)
    return tx
  }],
  ['source_other_output_with_input_0_spending_past_the_source', () => {
    const tx = unnamedBase({ vout: 2 })
    placeUnnamed(tx, 'source_other_output', 2 ** 53)
    return tx
  }],
  ['source_other_output_then_input_1_unlinked', () => {
    const tx = unnamedBase()
    placeUnnamed(tx, 'source_other_output', 2 ** 53)
    tx.inputs.push({
      sourceTXID: SECOND_INPUT_TXID,
      sourceOutputIndex: 0,
      unlockingScript: UnlockingScript.fromHex(SECOND_INPUT_UNLOCKING),
      sequence: 0xffffffff,
      sourceTransaction: undefined
    })
    return tx
  }],
  ['input_0_lacking_its_unlocking_script_then_input_1_unnamed_with_source_other_output', () => {
    const tx = withUnnamedSecondInput(base())
    tx.inputs[0].unlockingScript = undefined
    tx.inputs[1].sourceTransaction.outputs[1].satoshis = 2 ** 53
    return tx
  }],
  ['input_1_unnamed_with_source_other_output_then_output_0', () => {
    const tx = withUnnamedSecondInput(base())
    tx.inputs[1].sourceTransaction.outputs[1].satoshis = 2 ** 53
    tx.outputs[0].satoshis = 2 ** 53
    return tx
  }]
]

const no_txid = {
  source_other_output: { satoshis: OTHER_SATOSHIS, locking_script: OTHER_SCRIPT },
  grandparent_output: { satoshis: GRANDPARENT_SATOSHIS, locking_script: GRANDPARENT_SCRIPT },
  control: noTxidControl,
  cells: noTxidCells,
  two_fault_cells: NO_TXID_TWO_FAULTS.map(([name, build]) => ({ name, ...doors(build) }))
}

// The strength read's F1 (PR #913): three orders the cells above leave
// open, each with input 0 naming its txid. S1: input 0's spent source amount
// at 2^53 and its unlocking script absent (`:1143` before `:1150`). S2: input
// 1 linked with its source amount at 2^53, input 0 unlinked (`:1132` at
// input 0 before input 1's amount). S3: input 0's source carrying a second,
// unspent output at 2^53 (the outpoint named, no hash: written).
const strength_cells = [
  ['s1_source_amount_with_input_0_lacking_its_unlocking_script', () => {
    const tx = base()
    tx.inputs[0].unlockingScript = undefined
    place(tx, 'source_output', 2 ** 53)
    return tx
  }],
  ['s2_input_0_unlinked_then_input_1_source_amount', () => {
    const tx = withSecondInput({ linked: true, unlocking: true })
    tx.inputs[0].sourceTransaction = undefined
    tx.inputs[1].sourceTransaction.outputs[0].satoshis = 2 ** 53
    return tx
  }],
  ['s3_named_input_whose_source_carries_an_unspent_output', () => {
    const tx = base()
    tx.inputs[0].sourceTransaction.outputs.push({
      satoshis: 2 ** 53,
      lockingScript: LockingScript.fromHex(OTHER_SCRIPT)
    })
    return tx
  }]
].map(([name, build]) => ({ name, ...doors(build) }))

// The scoped re-read of the fold (PR #913): two cells no plant reached and
// the residual it named. Each input naming a txid here names `33`x32 (the
// vector's `walk.named_txid`), linked to the source given, `OP_1` its
// unlocking script unless absent, the final sequence.
// M1: input 0 names no txid; its source's own input NAMES a txid and links a
// grandparent of one output (2^53, `OP_1`): `#writeEF` hashes the source,
// whose plain writer writes the named outpoint from its text and never
// hashes the grandparent (`:1069-1071`): written.
// M2: input 0 names its txid and is clean; input 1 names no txid, its source
// (`unnamedSource`) carrying 2^53 in output 1, which input 1 does not spend:
// refused in the writer's words (`:1137-1138`).
// The residual (item 2), two cells: input 0 names no txid, its source's own
// input lacks its unlocking script, and an amount of 2^53 sits (a) in the
// source's output 1, the source's input naming a txid (the plain writer
// reaches the unlocking script's check, `:1072-1074`, before the output,
// `:1083`), (b) in the output of a grandparent the source's input reaches
// naming no txid (the grandparent's hash is written, `:1067`, before that
// check).
const WALK_NAMED_TXID = '33'.repeat(32)
const namedInput = (sourceTransaction, unlocking = true) => ({
  sourceTXID: WALK_NAMED_TXID,
  sourceOutputIndex: 0,
  unlockingScript: unlocking ? UnlockingScript.fromHex('51') : undefined,
  sequence: 0xffffffff,
  sourceTransaction
})
const walk = {
  named_txid: WALK_NAMED_TXID,
  cells: [
    ['m1_unnamed_source_whose_input_names_a_txid_over_a_grandparent_at_two_to_the_53', () => {
      const tx = unnamedBase()
      tx.inputs[0].sourceTransaction.inputs.push(namedInput(source(2 ** 53, GRANDPARENT_SCRIPT)))
      return tx
    }],
    ['m2_input_1_unnamed_with_source_other_output_alone', () => {
      const tx = withUnnamedSecondInput(base())
      tx.inputs[1].sourceTransaction.outputs[1].satoshis = 2 ** 53
      return tx
    }],
    ['source_input_named_lacking_its_unlocking_script_with_source_other_output', () => {
      const tx = unnamedBase()
      tx.inputs[0].sourceTransaction.inputs.push(namedInput(source(GRANDPARENT_SATOSHIS, GRANDPARENT_SCRIPT), false))
      placeUnnamed(tx, 'source_other_output', 2 ** 53)
      return tx
    }],
    ['source_input_unnamed_lacking_its_unlocking_script_over_a_grandparent_at_two_to_the_53', () => {
      const tx = unnamedBase({ grandparent: true })
      tx.inputs[0].sourceTransaction.inputs[0].unlockingScript = undefined
      placeUnnamed(tx, 'grandparent_output', 2 ** 53)
      return tx
    }]
  ].map(([name, build]) => ({ name, ...doors(build) }))
}

// The walk's two rules as a property (#843d7's third fold): the test
// enumerates every case of a small space and holds this crate's `to_ef` to
// an oracle written from the reference's lines; this recording ties that
// oracle to the reference on a fixed sample of the space. A case: a
// transaction of four inputs, `unnamed_input` (0 to 3) naming no txid and
// every other naming `walk.named_txid` (output 0, linked to a source of one
// output, 7 satoshis, `OP_1`); the unnamed input spends output 0 of level 1
// of a chain of `depth` levels (1 to 4). Each level holds two outputs (7 and
// 1 satoshis, `OP_1`) and, above the last, one input linking the next level,
// naming `walk.named_txid` (`n` in `links`) or no txid (`u`). `at` puts 2^53
// at one output of one level, or nowhere. Every input: `OP_1` its unlocking
// script, output 0, the final sequence. One output of 1 satoshi, `OP_1`.
const walkInput = (named, sourceTransaction) => ({
  sourceTXID: named ? WALK_NAMED_TXID : undefined,
  sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex('51'),
  sequence: 0xffffffff,
  sourceTransaction
})
const walkCase = ({ unnamed_input, depth, links, at }) => () => {
  let below
  for (let level = depth; level >= 1; level--) {
    const outputs = [
      { satoshis: 7, lockingScript: LockingScript.fromHex('51') },
      { satoshis: 1, lockingScript: LockingScript.fromHex('51') }
    ]
    if (at !== null && at.level === level) outputs[at.output].satoshis = 2 ** 53
    const inputs = level < depth ? [walkInput(links[level - 1] === 'n', below)] : []
    below = new Transaction(1, inputs, outputs, 0)
  }
  const inputs = []
  for (let i = 0; i < 4; i++) {
    inputs.push(i === unnamed_input ? walkInput(false, below) : walkInput(true, source(7, '51')))
  }
  return new Transaction(1, inputs, [{ satoshis: 1, lockingScript: LockingScript.fromHex('51') }], 0)
}
const walkCaseName = ({ unnamed_input, depth, links, at }) =>
  `u${unnamed_input}_d${depth}_links_${links === '' ? 'none' : links}_at_${at === null ? 'none' : `l${at.level}o${at.output}`}`
// The sample: for each depth and each unnamed input, (a) every link unnamed
// and 2^53 at the deepest level's output 1 and (b) every link unnamed but the
// last, named, and 2^53 at the deepest level's output 0 (at depth 1, no
// 2^53); then six mixed cases. The second re-read's two deeper cells are
// among them: `u0_d3_links_un_at_l3o0` (a grandparent whose input names a
// txid over a level at 2^53) and `u2_d1_links_none_at_l1o1` (an unnamed
// input 2 whose source carries 2^53).
const walkSample = []
for (let depth = 1; depth <= 4; depth++) {
  for (let unnamed_input = 0; unnamed_input < 4; unnamed_input++) {
    walkSample.push({ unnamed_input, depth, links: 'u'.repeat(depth - 1), at: { level: depth, output: 1 } })
    walkSample.push(
      depth === 1
        ? { unnamed_input, depth, links: '', at: null }
        : { unnamed_input, depth, links: 'u'.repeat(depth - 2) + 'n', at: { level: depth, output: 0 } }
    )
  }
}
walkSample.push(
  { unnamed_input: 0, depth: 4, links: 'nuu', at: { level: 4, output: 1 } },
  { unnamed_input: 1, depth: 4, links: 'unu', at: { level: 2, output: 0 } },
  { unnamed_input: 2, depth: 4, links: 'uun', at: { level: 3, output: 1 } },
  { unnamed_input: 3, depth: 3, links: 'nu', at: { level: 1, output: 1 } },
  { unnamed_input: 3, depth: 4, links: 'unn', at: { level: 4, output: 1 } },
  { unnamed_input: 1, depth: 2, links: 'n', at: null }
)
walk.space = {
  inputs: 4,
  max_depth: 4,
  sample: walkSample.map((c) => ({ name: walkCaseName(c), ...c, ...doors(walkCase(c)) }))
}

const vector = {
  description:
    "The reference's toEF and toHexEF on block 170's transaction with a third output and a linked source, one amount at the edge of a JavaScript number (#843d7); recorded by tests/support/transaction_amount_doors_843d7.mjs",
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  transaction: {
    hex: TX_HEX,
    third_output: { satoshis: THIRD_SATOSHIS, locking_script: THIRD_SCRIPT },
    source_output: { satoshis: SOURCE_SATOSHIS, locking_script: SOURCE_SCRIPT },
    second_input: {
      txid: SECOND_INPUT_TXID,
      vout: 0,
      unlocking_script: SECOND_INPUT_UNLOCKING,
      sequence: 0xffffffff,
      source_output: { satoshis: SECOND_SOURCE_SATOSHIS, locking_script: SECOND_SOURCE_SCRIPT }
    }
  },
  control,
  two_input_control: twoInputControl,
  cells,
  two_fault_satoshis: '9007199254740992',
  two_fault_cells,
  no_txid,
  strength_cells,
  walk
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
console.log(`${cells.length} cells, ${two_fault_cells.length} two-fault cells, ${noTxidCells.length} no-txid cells, ${no_txid.two_fault_cells.length} no-txid two-fault cells, ${walk.cells.length} walk cells, ${walk.space.sample.length} walk space cells -> ${out}`)
