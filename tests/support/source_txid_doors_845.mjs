// #845's recorder: what the reference answers for an input's `sourceTXID`
// that is, or is not, 64 hex digits, at the door where it enters and at the
// plain writer (`ts-stack@edf6e03` `packages/sdk/src/transaction/Transaction.ts`:
// `requireTXID` `:95-100`, `addInput` `:701-716`, the writer `:1058-1072`,
// `id` through it). One transaction per cell: version 1, the one input at
// output 0 with the unlocking script `51` and sequence 0xffffffff, one output
// of 1 satoshi locked `51`, lock time 0. `linked` adds a source transaction
// of no input and one output (1000 satoshis, `51`) beside the text.
//
// Only the unmodified SDK answers. Build the bundle at the pin and run under
// Node v22.18.0:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/source_txid_doors_845.mjs "$W/sdk.mjs" tests/vectors/source_txid_doors_845.json
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Transaction, LockingScript, UnlockingScript } = await import(bundle)

const A = 'aa'.repeat(32)
const forms = [
  ['lower_64', A],
  ['upper_64', 'AA'.repeat(32)],
  ['mixed_64', 'aA'.repeat(32)],
  ['null_64', '00'.repeat(32)],
  ['short_4', 'abcd'],
  ['odd_63', 'a'.repeat(63)],
  ['odd_65', 'a'.repeat(65)],
  ['long_66', 'aa'.repeat(33)],
  ['not_hex_64', 'zz'.repeat(32)],
  ['not_hex_2', 'zz'],
  ['one_bad_digit_64', 'g' + 'a'.repeat(63)],
  ['empty', ''],
  ['space_padded_64', ' ' + 'a'.repeat(62) + ' '],
  ['space_padded_66', ' ' + A + ' '],
  ['prefixed_0x_64', '0x' + 'a'.repeat(62)],
  ['plus_sign_64', '+' + 'a'.repeat(63)],
  ['two_byte_character', 'é' + 'a'.repeat(62)],
  ['absent', null]
]

const answer = (f) => {
  try {
    return { ok: f() }
  } catch (e) {
    return { error: String(e && e.message) }
  }
}
const source = () => {
  const t = new Transaction()
  t.addOutput({ satoshis: 1000, lockingScript: LockingScript.fromHex('51') })
  return t
}
const input = (text, linked) => ({
  sourceTXID: text === null ? undefined : text,
  sourceTransaction: linked ? source() : undefined,
  sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex('51'),
  sequence: 0xffffffff
})
const output = () => ({ satoshis: 1, lockingScript: LockingScript.fromHex('51') })
// The input handed to the constructor, which checks nothing: the hand-built
// door, judged by the writer.
const handBuilt = (text, linked) => new Transaction(1, [input(text, linked)], [output()], 0)
// The 32 outpoint txid bytes as written: after the version and the count.
const outpoint = (hex) => hex.slice(10, 74)

const cases = []
for (const [name, text] of forms) {
  for (const linked of [false, true]) {
    cases.push({
      name: name + (linked ? '_linked' : ''),
      text,
      linked,
      add_input: answer(() => {
        const t = new Transaction()
        const i = input(text, linked)
        t.addInput(i)
        t.addOutput(output())
        return { held: i.sourceTXID ?? null, outpoint: outpoint(t.toHex()), id: t.id('hex') }
      }),
      hand_built: answer(() => {
        const t = handBuilt(text, linked)
        return { outpoint: outpoint(t.toHex()), id: t.id('hex') }
      })
    })
  }
}

writeFileSync(
  out,
  JSON.stringify(
    {
      description:
        "#845: the reference's answers for an input's sourceTXID at addInput and at the plain writer (ts-stack@edf6e03, Node " +
        process.version +
        '); tests/support/source_txid_doors_845.mjs',
      source_id: source().id('hex'),
      cases
    },
    null,
    2
  ) + '\n'
)
