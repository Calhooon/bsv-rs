// #844's recorder: what the reference's readers answer for a wire number at
// its edge (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`:
// `fromEF` `:370-421`, `parseScriptOffsets` `:438-464`, `fromReader`
// `:466-515`, `fromBinary` `:523-538`, `fromHex` `:548-553`, `fromHexEF`
// `:562-564`; `BeefTx.ts:16-48` the raw-transaction scan, `:288-311` the
// entry reader; `Beef.ts` `fromBinary` `:1286`, `fromBinaryStrict` `:1296`,
// `verifyValid` `:1054`, `isValid` `:1002`, `mergeRawTx` `:835`, `mergeBeef`
// `:971`; `MerklePath.ts:108-160` the BUMP reader; `primitives/utils.ts`
// and `ReaderUint8Array.ts` the readers, `readVarIntNumStrict.ts` the
// canonical varint, `BigNumber.ts:628` `toNumber`).
//
// The transaction is block 170's (f4184fc5..., 275 bytes), #840's; one field
// at a time is set to an edge. Only the unmodified SDK answers. Build the
// bundle at the pin and run under Node v22.18.0:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/transaction_numbers_844.mjs "$W/sdk.mjs" tests/vectors/transaction_numbers_844.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, BeefTx, Hash, Transaction, LockingScript, MerklePath, Script, Utils } = await import(bundle)

const TX_HEX =
  '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
const SOURCE_SCRIPT =
  '410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'
const SOURCE_SATOSHIS = 5000000000

const hex = (bytes) => Utils.toHex(Array.from(bytes))
const bytesOf = (h) => Utils.toArray(h, 'hex')
const le = (n, width) => {
  let h = ''
  for (let i = 0n; i < BigInt(width); i++) h += ((n >> (8n * i)) & 0xffn).toString(16).padStart(2, '0')
  return h
}
const answer = (f) => {
  try {
    return f()
  } catch (e) {
    return { ok: false, error: String(e && e.message) }
  }
}
const txAnswer = (t) => ({ ok: true, id: t.id('hex'), to_hex: t.toHex() })

// Block 170's transaction cut into its fields (hex offsets in characters).
const F = {
  version: [0, 8],
  input_count: [8, 10],
  input_vout: [74, 82],
  input_script_len: [82, 84],
  input_sequence: [228, 236],
  output_count: [236, 238],
  output_value: [238, 254],
  lock_time: [TX_HEX.length - 8, TX_HEX.length]
}
if (TX_HEX.slice(...F.input_script_len) !== '48') throw new Error('the script length is not where it is named')
if (TX_HEX.slice(...F.input_sequence) !== 'ffffffff') throw new Error('the sequence is not where it is named')
if (TX_HEX.slice(...F.output_value) !== '00ca9a3b00000000') throw new Error('the value is not where it is named')
const withField = (h, field, value) => h.slice(0, F[field][0]) + value + h.slice(F[field][1])

// The amount edges, the 32-bit edges, the varint forms.
const AMOUNTS = {
  two_to_the_53_minus_1: (1n << 53n) - 1n,
  two_to_the_53: 1n << 53n,
  two_to_the_63: 1n << 63n,
  two_to_the_64_minus_1: (1n << 64n) - 1n
}
const U32 = { zero: 0n, two_to_the_31_minus_1: 0x7fffffffn, two_to_the_31: 0x80000000n, max: 0xffffffffn }
// A count or length of value `v` in a longer form, and the nine-byte form at
// 2^53 and at 2^64 - 1.
const varints = (v) => ({
  fd_form: 'fd' + le(v, 2),
  fe_form: 'fe' + le(v, 4),
  ff_form_below_2_32: 'ff' + le(v, 8),
  ff_form_two_to_the_53: 'ff' + le(1n << 53n, 8),
  ff_form_two_to_the_64_minus_1: 'ff' + le((1n << 64n) - 1n, 8)
})

const readers = {
  fromBinary: (h) => txAnswer(Transaction.fromBinary(bytesOf(h))),
  fromHex: (h) => txAnswer(Transaction.fromHex(h)),
  fromReader: (h) => {
    const r = new Utils.Reader(bytesOf(h))
    const t = Transaction.fromReader(r)
    return { ...txAnswer(t), remaining: r.bin.length - r.pos }
  },
  parseScriptOffsets: (h) => {
    const o = Transaction.parseScriptOffsets(bytesOf(h))
    return { ok: true, inputs: o.inputs.map((i) => [i.offset, i.length]), outputs: o.outputs.map((i) => [i.offset, i.length]) }
  }
}
const efReaders = {
  fromEF: (h) => txAnswer(Transaction.fromEF(bytesOf(h))),
  fromHexEF: (h) => txAnswer(Transaction.fromHexEF(h))
}

const cells = []
const add = (reader, field, edge, input, f) => cells.push({ reader, field, edge, input, answer: answer(() => f(input)) })

for (const [reader, f] of Object.entries(readers)) {
  for (const [edge, v] of Object.entries(AMOUNTS)) add(reader, 'output_value', edge, withField(TX_HEX, 'output_value', le(v, 8)), f)
  for (const field of ['version', 'input_vout', 'input_sequence', 'lock_time']) {
    for (const [edge, v] of Object.entries(U32)) add(reader, field, edge, withField(TX_HEX, field, le(v, 4)), f)
  }
  for (const [field, v] of [['input_count', 1n], ['input_script_len', 0x48n], ['output_count', 2n]]) {
    for (const [edge, form] of Object.entries(varints(v))) add(reader, field, edge, withField(TX_HEX, field, form), f)
  }
}

// The EF form: the source amount and the output amount at the edges.
const tx = Transaction.fromHex(TX_HEX)
const source = new Transaction(1, [], [], 0)
source.outputs = [{ satoshis: SOURCE_SATOSHIS, lockingScript: LockingScript.fromHex(SOURCE_SCRIPT) }]
tx.inputs[0].sourceTransaction = source
const EF_HEX = tx.toHexEF()
const SOURCE_AMOUNT = le(BigInt(SOURCE_SATOSHIS), 8)
if (EF_HEX.split(SOURCE_AMOUNT).length !== 2) throw new Error('the source amount is not unique in the EF')
const EF_OUTPUT = SOURCE_SCRIPT + '0200ca9a3b00000000'
if (EF_HEX.split(EF_OUTPUT).length !== 2) throw new Error('the output amount is not unique in the EF')
for (const [reader, f] of Object.entries(efReaders)) {
  for (const [edge, v] of Object.entries(AMOUNTS)) {
    add(reader, 'source_value', edge, EF_HEX.replace(SOURCE_AMOUNT, le(v, 8)), f)
    add(reader, 'output_value', edge, EF_HEX.replace(EF_OUTPUT, SOURCE_SCRIPT + '02' + le(v, 8)), f)
  }
}

// The BEEF doors, on a BEEF holding block 170's transaction with its output 0
// at an edge, proven by a one-leaf BUMP of its own txid at 170.
const beefCells = []
for (const edge of ['two_to_the_53_minus_1', 'two_to_the_53']) {
  const raw = withField(TX_HEX, 'output_value', le(AMOUNTS[edge], 8))
  const txid = txidOf(raw)
  const beefBytes = beefOf(raw)
  const atomic = answer(() => ({ ok: true, hex: hex(Beef.fromBinary(beefBytes).toBinaryAtomic(txid)) }))
  const doors = {
    'Beef.fromBinary': () => ({ ok: true, txs: Beef.fromBinary(beefBytes).txs.length }),
    'Beef.fromBinaryStrict': () => ({ ok: true, txs: Beef.fromBinaryStrict(beefBytes).txs.length }),
    'Beef.verifyValid': () => {
      const r = Beef.fromBinaryStrict(beefBytes).verifyValid(false)
      return { ok: true, valid: r.valid }
    },
    'Beef.isValid': () => ({ ok: true, valid: Beef.fromBinaryStrict(beefBytes).isValid(false) }),
    'BeefTx.tx': () => txAnswer(Beef.fromBinaryStrict(beefBytes).findTxid(txid).tx),
    'Transaction.fromBEEF': () => txAnswer(Transaction.fromBEEF(beefBytes)),
    'Transaction.fromAtomicBEEF': () => txAnswer(Transaction.fromAtomicBEEF(bytesOf(atomic.hex))),
    'Beef.mergeRawTx': () => {
      const b = new Beef()
      b.mergeRawTx(bytesOf(raw))
      return { ok: true, to_hex: hex(b.toBinary()) }
    },
    'Beef.mergeBeef': () => {
      const b = new Beef()
      b.mergeBeef(beefBytes)
      return { ok: true, to_hex: hex(b.toBinary()) }
    }
  }
  const answers = {}
  for (const [door, f] of Object.entries(doors)) answers[door] = answer(f)
  beefCells.push({ edge, raw, txid, beef: hex(beefBytes), atomic, answers })
}
function txidOf(raw) {
  return hex(Hash.hash256(bytesOf(raw)).reverse())
}
function beefOf(raw) {
  const b = new Beef()
  b.mergeBump(MerklePath.fromCoinbaseTxidAndHeight(txidOf(raw), 170))
  b.mergeRawTx(bytesOf(raw), 0)
  return b.toBinary()
}

// The BUMP numbers: a block height at 2^32 and at 2^53, a leaf offset at 2^53.
const bumpCells = []
const coinbase = 'ab'.repeat(32)
const bumpHex = (heightVarint, treeHeight, offsetVarint) =>
  heightVarint + treeHeight + '01' + offsetVarint + '02' + coinbase
for (const [edge, h] of Object.entries({
  height_two_to_the_32_minus_1: 'fe' + le(0xffffffffn, 4),
  height_two_to_the_32: 'ff' + le(1n << 32n, 8),
  height_two_to_the_53: 'ff' + le(1n << 53n, 8)
})) {
  const input = bumpHex(h, '01', '00')
  bumpCells.push({ edge, input, answer: answer(() => ({ ok: true, height: MerklePath.fromHex(input).blockHeight })) })
}
// A 54-level path (the reference's most) whose txid sits at a level-0
// offset at an edge: its sibling beside it, one node per level above.
const varint = (n) =>
  n < 0xfdn ? le(n, 1) : n <= 0xffffn ? 'fd' + le(n, 2) : n <= 0xffffffffn ? 'fe' + le(n, 4) : 'ff' + le(n, 8)
const deepBump = (offset) => {
  let h = 'aa' + '36' + '02'
  const pair = [offset, offset ^ 1n].sort((a, b) => (a < b ? -1 : 1))
  for (const o of pair) h += varint(o) + (o === offset ? '02' : '00') + (o === offset ? coinbase : 'cd'.repeat(32))
  for (let level = 1n; level < 54n; level++) h += '01' + varint((offset >> level) ^ 1n) + '00' + 'ef'.repeat(32)
  return h
}
for (const [edge, o] of Object.entries({
  offset_two_to_the_53_minus_1: (1n << 53n) - 1n,
  offset_two_to_the_53: 1n << 53n
})) {
  const input = deepBump(o)
  bumpCells.push({
    edge,
    input,
    answer: answer(() => {
      const p = MerklePath.fromHex(input)
      return { ok: true, height: p.blockHeight, root: p.computeRoot(coinbase) }
    })
  })
}

// A script chunk's push length at its own edge (a 32-bit read).
const scriptCells = []
for (const [edge, s] of Object.entries({
  pushdata4_max_truncated: '4effffffff',
  pushdata4_two_to_the_31_truncated: '4e00000080'
})) {
  scriptCells.push({
    edge,
    input: s,
    answer: answer(() => {
      const sc = Script.fromHex(s)
      return { ok: true, chunks: sc.chunks.length, to_hex: sc.toHex() }
    })
  })
}

// The writers (#844's fold): a transaction built by hand (its `outputs` set
// after the read, as this crate's public `satoshis` field is set) whose output
// at `position` holds an amount, at each of the reference's writer doors and
// its merge door: `Transaction.toBinary`, `toBEEF(true)`, `toAtomicBEEF(true)`
// (`Transaction.ts`), `Beef.mergeTransaction` (`Beef.ts:875-901`), an entry
// pushed into `txs` by hand (`new BeefTx(tx)`, unhashed) and written by
// `Beef.toBinary`, `toHex`, `toBinaryAtomic` and `BeefTx.toWriter`, merged by
// `mergeBeef`, and an entry of a BEEF read from bytes edited in place through
// `findTxid(..).tx`, then written by `toBinary`. Block 170's transaction with
// a third output (a copy of its last) appended, so the amount sits in the
// first, a middle and the last output. The txid is the edited bytes' hash,
// computed from the hex, as the reference's own hash throws for them.
const writerCells = []
{
  const lastOutput = TX_HEX.slice(TX_HEX.length - 8 - (16 + 2 + 0x43 * 2), TX_HEX.length - 8)
  if (!lastOutput.startsWith('00286bee00000000')) throw new Error('the last output is not where it is named')
  const three = withField(TX_HEX, 'output_count', '03').slice(0, TX_HEX.length - 8) + lastOutput + TX_HEX.slice(TX_HEX.length - 8)
  const valueAt = (h, position) => {
    let at = F.output_value[0]
    for (let i = 0; i < position; i++) at += 16 + 2 + parseInt(h.slice(at + 16, at + 18), 16) * 2
    return at
  }
  const withValue = (h, position, v) => {
    const at = valueAt(h, position)
    return h.slice(0, at) + le(v, 8) + h.slice(at + 16)
  }
  const built = (position, v) => {
    const t = Transaction.fromHex(three)
    t.outputs[position].satoshis = Number(v)
    return t
  }
  const pushed = (t) => {
    const b = new Beef()
    b.txs.push(new BeefTx(t))
    return b
  }
  for (const [edge, v] of [['two_to_the_53_minus_1', AMOUNTS.two_to_the_53_minus_1], ['two_to_the_53', AMOUNTS.two_to_the_53]]) {
    for (const position of [0, 1, 2]) {
      const raw = withValue(three, position, v)
      const txid = txidOf(raw)
      const doors = {
        'Transaction.toBinary': () => ({ ok: true, hex: hex(built(position, v).toBinary()) }),
        'Transaction.toBEEF': () => ({ ok: true, hex: hex(built(position, v).toBEEF(true)) }),
        'Transaction.toAtomicBEEF': () => ({ ok: true, hex: hex(built(position, v).toAtomicBEEF(true)) }),
        'Beef.mergeTransaction': () => {
          const b = new Beef()
          b.mergeTransaction(built(position, v))
          return { ok: true, txs: b.txs.length }
        },
        'Beef.toBinary (pushed)': () => ({ ok: true, hex: hex(pushed(built(position, v)).toBinary()) }),
        'Beef.toHex (pushed)': () => ({ ok: true, hex: pushed(built(position, v)).toHex() }),
        'Beef.toBinaryAtomic (pushed)': () => ({ ok: true, hex: hex(pushed(built(position, v)).toBinaryAtomic(txid)) }),
        'BeefTx.toWriter (pushed)': () => {
          const w = new Utils.Writer()
          new BeefTx(built(position, v)).toWriter(w, 4022206466)
          return { ok: true, hex: hex(w.toArray()) }
        },
        'Beef.mergeBeef (pushed)': () => {
          const b = new Beef()
          b.mergeBeef(pushed(built(position, v)))
          return { ok: true, txs: b.txs.length }
        },
        'Beef.toBinary (edited in place)': () => {
          const b = Beef.fromBinary(beefOf(three))
          b.findTxid(txidOf(three)).tx.outputs[position].satoshis = Number(v)
          return { ok: true, hex: hex(b.toBinary()) }
        }
      }
      const answers = {}
      for (const [door, f] of Object.entries(doors)) answers[door] = answer(f)
      writerCells.push({ edge, position, outputs: 3, raw, txid, answers })
    }
  }
}

writeFileSync(
  out,
  JSON.stringify(
    {
      issue: 844,
      reference: 'ts-stack@edf6e03 packages/sdk (@bsv/sdk), Node v22.18.0',
      recorder: 'tests/support/transaction_numbers_844.mjs',
      tx_hex: TX_HEX,
      ef_hex: EF_HEX,
      cells,
      beef_cells: beefCells,
      bump_cells: bumpCells,
      script_cells: scriptCells,
      writer_cells: writerCells
    },
    null,
    2
  ) + '\n'
)
