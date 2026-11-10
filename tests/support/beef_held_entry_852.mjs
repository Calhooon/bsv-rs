// #852's recorder: what the reference's BEEF answers for a raw entry whose
// bytes are not exactly one transaction (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/`: `BeefTx.ts:24-54` the prefix scan,
// `:110-113` the txid, `:118-126` the lazy `tx` getter, `:200-203` the scan
// skipped under a BUMP index; `Beef.ts:835-846` `mergeRawTx`, `:1054-1088`
// `verifyValid`, `:1286-1309` `fromBinary` and `fromBinaryStrict`;
// `Transaction.ts:282-319` `fromBEEF`, `fromAtomicBEEF`).
//
// Each shape is held in each state the reference can build, and every door
// is asked: `mergeRawTx` (returns, or throws with its words), `inputTxids`,
// `verifyValid`, `isValid(false)`, `isValid(true)`, and the end-to-end
// answers: the BEEF written (`toBinary`, or `toBinaryAtomic` for the
// atomic subject) then read by `Beef.fromBinaryStrict` (and, when it reads,
// that BEEF's `verifyValid`) and by `Transaction.fromBEEF`
// (`fromAtomicBEEF` for the atomic subject). Only the unmodified SDK
// answers. Build the bundle at the pin and run under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/beef_held_entry_852.mjs "$W/sdk.mjs" tests/vectors/beef_held_entry_852.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, Transaction, MerklePath, Utils, Hash } = await import(bundle)

// Block 170's transaction (f4184fc5..., 275 bytes) and the coinbase of
// block 9 (0437cd7f..., the one transaction of its block) that it spends.
const TX_HEX =
  '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
const PARENT_HEX =
  '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0134ffffffff0100f2052a0100000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
const PARENT_HEIGHT = 9
// The height of the BUMP an entry that carries its own index is proven by.
const ENTRY_HEIGHT = 1000

// The shapes, by name; the Rust table builds the same bytes.
const cut = (n) => TX_HEX.slice(0, 2 * n)
const SHAPES = {
  exact: TX_HEX,
  plus_one_byte: TX_HEX + '00',
  plus_four_bytes: TX_HEX + '01020304',
  plus_itself: TX_HEX + TX_HEX,
  cut_in_inputs: cut(20),
  cut_at_output_count: cut(118),
  cut_in_output: cut(150),
  cut_in_lock_time: cut(273),
  no_transaction_3_bytes: '010000',
  no_transaction_40_bytes: '01000000' + 'fd0100' + '00'.repeat(33),
  no_bytes: '',
  zero_inputs_plus_byte: '01000000' + '00' + '01' + '0000000000000000' + '00' + '00000000' + '00'
}
const STATES = [
  'parent_absent',
  'parent_present_proven',
  'entry_proven',
  'atomic_subject',
  'parent_of_child',
  'merged'
]

const bytesOf = (h) => Utils.toArray(h, 'hex')
const txidOf = (h) => Utils.toHex(Hash.hash256(bytesOf(h)).reverse())
const reverseHex = (h) => Utils.toHex(bytesOf(h).reverse())

// A child that spends output 0 of `parentTxid`: one input with an empty
// unlocking script, one output of 1,000 satoshis to OP_TRUE.
const childHex = (parentTxid) =>
  '01000000' + '01' + reverseHex(parentTxid) + '00000000' + '00' + 'ffffffff' +
  '01' + 'e803000000000000' + '01' + '51' + '00000000'

const answer = (f) => {
  try {
    return { ok: true, value: f() }
  } catch (e) {
    return { ok: false, error: String(e && e.message) }
  }
}

const withParent = (beef) => {
  beef.mergeBump(MerklePath.fromCoinbaseTxidAndHeight(txidOf(PARENT_HEX), PARENT_HEIGHT))
  beef.mergeRawTx(bytesOf(PARENT_HEX), 0)
}

// Builds the state; returns { beef, merge, child } or throws through `merge`.
const build = (shapeHex, state) => {
  const entryTxid = txidOf(shapeHex)
  const beef = new Beef()
  if (state === 'entry_proven') {
    beef.mergeBump(MerklePath.fromCoinbaseTxidAndHeight(entryTxid, ENTRY_HEIGHT))
  } else if (state !== 'parent_absent') {
    withParent(beef)
  }
  const bumpIndex = state === 'entry_proven' ? 0 : undefined
  const merge = answer(() => {
    const btx = beef.mergeRawTx(bytesOf(shapeHex), bumpIndex)
    return { input_txids: btx.inputTxids }
  })
  if (!merge.ok) return { merge }
  let child
  if (state === 'parent_of_child') {
    child = childHex(entryTxid)
    beef.mergeRawTx(bytesOf(child))
  }
  if (state === 'atomic_subject') beef.atomicTxid = entryTxid
  if (state === 'merged') {
    // The reference's mergeBeef writes the BEEF and reads it back strictly
    // (`Beef.ts:975`): it answers, or throws in its words.
    const merged = new Beef()
    const mergeBeef = answer(() => {
      merged.mergeBeef(beef)
      return null
    })
    return mergeBeef.ok ? { beef: merged, merge, mergeBeef } : { merge, mergeBeef }
  }
  return { beef, merge, child }
}

const cells = []
for (const [shape, shapeHex] of Object.entries(SHAPES)) {
  for (const state of STATES) {
    const entryTxid = txidOf(shapeHex)
    const cell = { shape, state, raw: shapeHex, entry_txid: entryTxid }
    const built = build(shapeHex, state)
    cell.merge_raw_tx = built.merge
    if (built.mergeBeef != null) cell.merge_beef = built.mergeBeef
    if (built.beef != null) {
      const beef = built.beef
      if (built.child != null) cell.child_txid = txidOf(built.child)
      const held = beef.findTxid(entryTxid)
      cell.input_txids = held == null ? null : held.inputTxids
      cell.verify_valid = answer(() => beef.verifyValid(false).valid)
      cell.is_valid_false = answer(() => beef.isValid(false))
      cell.is_valid_true = answer(() => beef.isValid(true))
      const atomic = state === 'atomic_subject'
      const written = answer(() =>
        Utils.toHex(atomic ? beef.toBinaryAtomic(entryTxid) : beef.toBinary())
      )
      cell.written = written.ok ? { ok: true } : written
      if (written.ok) {
        const bin = bytesOf(written.value)
        cell.from_binary_strict = answer(() => {
          const read = Beef.fromBinaryStrict(bin)
          return { verify_valid: read.verifyValid(false).valid }
        })
        cell.transaction_from_beef = answer(() => {
          const tx = atomic ? Transaction.fromAtomicBEEF(bin) : Transaction.fromBEEF(bin, entryTxid)
          return { id: tx.id('hex') }
        })
      }
    }
    // The stated divergence (#852): bytes that are not exactly one
    // transaction, which the reference's verifyValid alone answers valid
    // (its own end-to-end read refuses them; this crate refuses at the
    // verdict).
    cell.stated_divergence = shape !== 'exact' && cell.verify_valid?.ok === true &&
      cell.verify_valid.value === true
    cells.push(cell)
  }
}

const vector = {
  description:
    'What the reference answers for a BEEF raw entry whose bytes are not exactly one transaction (#852, the stable line of #840): mergeRawTx, inputTxids, verifyValid, isValid and the end-to-end read of the BEEF it writes, per shape and state.',
  reference: 'ts-stack@edf6e03 packages/sdk',
  recorder: 'tests/support/beef_held_entry_852.mjs',
  node: process.version,
  parent_raw: PARENT_HEX,
  parent_height: PARENT_HEIGHT,
  entry_height: ENTRY_HEIGHT,
  cells
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
