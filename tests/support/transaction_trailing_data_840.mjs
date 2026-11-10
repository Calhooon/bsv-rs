// #840's recorder: what the reference's transaction readers answer for a
// transaction followed by other bytes (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/Transaction.ts`: `fromBinary` and
// `fromBinaryView` `:523-538`, `fromHex` `:548-553`, `fromEF` `:370-421`,
// `fromHexEF` `:562-564`, `parseScriptOffsets` `:438-464`, `fromReader`
// `:466-468`, `fromBEEF` `:282-300`).
//
// The transaction is block 170's (f4184fc5..., 275 bytes), the one #840's
// probe used; its EF form carries the spent coinbase output (block 9's,
// 50 BSV to its P2PK script). Only the unmodified SDK answers. Build the
// bundle at the pin and run under Node 22.18.0:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/transaction_trailing_data_840.mjs "$W/sdk.mjs" tests/vectors/transaction_trailing_data_840.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, Transaction, LockingScript, Utils } = await import(bundle)

const TX_HEX =
  '0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000'
// Block 9's coinbase output, the coin block 170's transaction spends.
const SOURCE_SCRIPT =
  '410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac'
const SOURCE_SATOSHIS = 5000000000

const hex = (bytes) => Utils.toHex(Array.from(bytes))
const bytesOf = (h) => Utils.toArray(h, 'hex')

const tx = Transaction.fromHex(TX_HEX)
const source = new Transaction(1, [], [], 0)
source.outputs = [{ satoshis: SOURCE_SATOSHIS, lockingScript: LockingScript.fromHex(SOURCE_SCRIPT) }]
tx.inputs[0].sourceTransaction = source
const EF_HEX = tx.toHexEF()
const beef = new Beef()
beef.mergeRawTx(bytesOf(TX_HEX))
const BEEF_HEX = hex(beef.toBinary())

// The suffixes every byte form is read with.
const SUFFIXES = {
  clean: '',
  plus_one_byte: '00',
  plus_four_bytes: '01020304'
}

const answer = (f) => {
  try {
    return f()
  } catch (e) {
    return { ok: false, error: String(e && e.message) }
  }
}
const txAnswer = (t) => ({
  ok: true,
  id: t.id('hex'),
  to_binary_len: t.toBinary().length,
  to_hex: t.toHex()
})

const cells = []
const add = (reader, name, input, f) => cells.push({ reader, name, input, answer: answer(f) })

for (const [name, suffix] of Object.entries({ ...SUFFIXES, plus_itself: TX_HEX })) {
  const input = TX_HEX + suffix
  add('fromBinary', name, input, () => txAnswer(Transaction.fromBinary(bytesOf(input))))
  add('fromHex', name, input, () => txAnswer(Transaction.fromHex(input)))
}
add('fromHex', 'hex_plus_two_digits', TX_HEX + '00', () => txAnswer(Transaction.fromHex(TX_HEX + '00')))
add('fromHex', 'hex_plus_one_digit', TX_HEX + '0', () => txAnswer(Transaction.fromHex(TX_HEX + '0')))

for (const [name, suffix] of Object.entries({ ...SUFFIXES, plus_itself: EF_HEX })) {
  const input = EF_HEX + suffix
  add('fromEF', name, input, () => txAnswer(Transaction.fromEF(bytesOf(input))))
  add('fromHexEF', name, input, () => txAnswer(Transaction.fromHexEF(input)))
}
add('fromHexEF', 'hex_plus_one_digit', EF_HEX + '0', () => txAnswer(Transaction.fromHexEF(EF_HEX + '0')))

for (const [name, suffix] of Object.entries(SUFFIXES)) {
  const input = BEEF_HEX + suffix
  add('fromBEEF', name, input, () => txAnswer(Transaction.fromBEEF(bytesOf(input))))
}

const offsets = (input) => {
  const o = Transaction.parseScriptOffsets(bytesOf(input))
  return { ok: true, inputs: o.inputs.map((i) => [i.offset, i.length]), outputs: o.outputs.map((i) => [i.offset, i.length]) }
}
for (const [name, suffix] of Object.entries(SUFFIXES)) {
  add('parseScriptOffsets', name, TX_HEX + suffix, () => offsets(TX_HEX + suffix))
}
const NO_LOCK_TIME = TX_HEX.slice(0, TX_HEX.length - 8)
add('parseScriptOffsets', 'no_lock_time', NO_LOCK_TIME, () => offsets(NO_LOCK_TIME))

// The reader form: one transaction from the front, the rest left unread.
for (const [name, suffix] of Object.entries({ ...SUFFIXES, plus_itself: TX_HEX })) {
  const input = TX_HEX + suffix
  add('fromReader', name, input, () => {
    const r = new Utils.Reader(bytesOf(input))
    const t = Transaction.fromReader(r)
    return { ...txAnswer(t), remaining: r.bin.length - r.pos }
  })
}

// The 53-bit cells (the cold read's item 7, older than #840; #844 conforms):
// the reference reads an amount through `readUInt64LEBn().toNumber()`
// (`Transaction.ts:388,409,497`), which throws past 2^53 - 1 (`BigNumber.ts:628`).
// Block 170's transaction with its first output's amount replaced, and its
// EF form with the source amount replaced.
const le64 = (n) => {
  let h = ''
  for (let i = 0n; i < 8n; i++) h += ((n >> (8n * i)) & 0xffn).toString(16).padStart(2, '0')
  return h
}
const FIRST_AMOUNT = 'ffffffff0200ca9a3b00000000'
const SOURCE_AMOUNT = le64(BigInt(SOURCE_SATOSHIS))
const cells_53 = []
const add53 = (reader, name, input, f) => cells_53.push({ reader, name, input, answer: answer(f) })
const AMOUNTS = {
  two_to_the_53_minus_1: (1n << 53n) - 1n,
  two_to_the_53: 1n << 53n,
  two_to_the_64_minus_1: (1n << 64n) - 1n
}
for (const [name, amount] of Object.entries(AMOUNTS)) {
  const input = TX_HEX.replace(FIRST_AMOUNT, 'ffffffff02' + le64(amount))
  add53('fromBinary', 'output_' + name, input, () => txAnswer(Transaction.fromBinary(bytesOf(input))))
  add53('fromHex', 'output_' + name, input, () => txAnswer(Transaction.fromHex(input)))
  add53('fromReader', 'output_' + name, input, () => {
    const r = new Utils.Reader(bytesOf(input))
    const t = Transaction.fromReader(r)
    return { ...txAnswer(t), remaining: r.bin.length - r.pos }
  })
}
{
  if (EF_HEX.split(SOURCE_AMOUNT).length !== 2) throw new Error('the source amount is not unique in the EF')
  const input = EF_HEX.replace(SOURCE_AMOUNT, le64(1n << 53n))
  add53('fromEF', 'source_two_to_the_53', input, () => txAnswer(Transaction.fromEF(bytesOf(input))))
}
// The writer, for #844: a transaction built with such a number written.
const writer_53 = {}
for (const [name, amount] of Object.entries({ two_to_the_53: 2 ** 53, two_to_the_64: 2 ** 64 })) {
  writer_53[name] = answer(() => {
    const t = new Transaction(1, [], [{ satoshis: amount, lockingScript: LockingScript.fromHex('51') }], 0)
    return { ok: true, to_hex: t.toHex() }
  })
}

writeFileSync(
  out,
  JSON.stringify(
    {
      issue: 840,
      reference: 'ts-stack@edf6e03 packages/sdk (@bsv/sdk), Node 22.18.0',
      recorder: 'tests/support/transaction_trailing_data_840.mjs',
      tx_hex: TX_HEX,
      ef_hex: EF_HEX,
      beef_hex: BEEF_HEX,
      cells_53,
      writer_53,
      cells
    },
    null,
    2
  ) + '\n'
)
