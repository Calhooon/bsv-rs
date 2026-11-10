// #603 recorder: the result validator's BEEF reader (`src/wallet/substrates/
// result_values/beef.rs`) on the shapes that kill its survivors, read by the
// reference's `parseWalletResultBEEF` and `parseWalletResultAtomicBEEF`
// (`ts-stack@edf6e03` `packages/sdk/src/wallet/WalletResultBEEF.ts`). The
// file is not in the package index at the pin, so it is bundled alone:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build src/wallet/WalletResultBEEF.ts --target node --format esm --outfile "$W/wrb.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/wallet_result_beef_603.mjs \
//     "$W/wrb.mjs" tests/vectors/wallet_result_beef_603.json
//
// The bytes are built here by hand (each shape is a framing edge no writer
// produces); the Rust test reads the hex and asserts the verdicts and txids.
import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { parseWalletResultBEEF, parseWalletResultAtomicBEEF } = await import(bundle)

const sha256d = hex =>
  createHash('sha256').update(createHash('sha256').update(Buffer.from(hex, 'hex')).digest()).digest()
const txidOf = hex => Buffer.from(sha256d(hex)).reverse().toString('hex')
const internal = txid => Buffer.from(txid, 'hex').reverse().toString('hex')

const V2 = '0200beef'
const A = 'a1'.repeat(32)
const B = 'b2'.repeat(32)
const C = 'c3'.repeat(32)
const D = 'd4'.repeat(32)
// Version 1, no input, one output of 1 sat with an L-byte script of 51s, lock time 0.
const T = L =>
  '01000000' + '00' + '01' + '0100000000000000' + L.toString(16).padStart(2, '0') + '51'.repeat(L) + '00000000'
const TP = T(1)
const P = txidOf(TP)
// Spends P:0 with an empty unlocking script; one output of 1 sat, script 51.
const TX = '01000000' + '01' + internal(P) + '00000000' + '00' + 'ffffffff' + '01' + '0100000000000000' + '0151' + '00000000'
const X = txidOf(TX)

// A one-BUMP V2 BEEF, no transactions, the BUMP's block height varint given.
const loneLeaf = height => V2 + '01' + height + '01' + '01' + '00' + '00' + A + '00'
// Tree height 2: level 0 A at 0 and B at 1, level 1 the given leaves.
const twoLevels = level1 => V2 + '01' + '00' + '02' + '02' + '0000' + A + '0100' + B + level1 + '00'

const cases = [
  { name: 'height_2_53', kills: ['53:10 > ==', '53:10 > >='], hex: loneLeaf('ff0000000000002000') },
  { name: 'height_2_53_minus_1', kills: ['53:10 > >='], hex: loneLeaf('ffffffffffffff1f00') },
  { name: 'outputs_remaining_multiple_of_9', kills: ['88:36 / %'], hex: V2 + '00' + '01' + '00' + T(5) },
  { name: 'level_count_half_remaining', kills: ['119:19 > ==', '119:19 > >='], hex: twoLevels('01' + '0101') },
  {
    name: 'offset_at_level_max',
    kills: ['126:23 > ==', '126:23 > >='],
    hex: twoLevels('02' + '0100' + C + 'feffffff7f00' + D)
  },
  {
    name: 'offset_past_level_max',
    kills: ['126:46 >> <<', '126:56 || &&'],
    hex: twoLevels('02' + '0100' + C + 'fe0000008000' + D)
  },
  {
    name: 'atomic_closed_expected_parent',
    kills: ['247:9 None', '252:16 !', '271:21 == !='],
    hex: '01010101' + internal(X) + V2 + '00' + '02' + '00' + TP + '00' + TX,
    parent: P,
    subject: X
  }
]

const verdict = f => {
  try {
    return { ok: true, value: f() }
  } catch (e) {
    return { ok: false, error: String(e.message) }
  }
}

const recorded = cases.map(c => {
  const bytes = Buffer.from(c.hex, 'hex')
  const plain = verdict(() => parseWalletResultBEEF(bytes))
  const entry = { ...c, parse: plain.ok ? 'ok' : plain.error }
  if (plain.ok) entry.txids = [...plain.value.transactions.keys()]
  if (c.subject !== undefined) {
    const strict = verdict(() => parseWalletResultAtomicBEEF(bytes).txid)
    const partial = verdict(() => parseWalletResultAtomicBEEF(bytes, true).txid)
    entry.atomic_strict = strict.ok ? strict.value : strict.error
    entry.atomic_partial = partial.ok ? partial.value : partial.error
  }
  return entry
})

writeFileSync(
  out,
  JSON.stringify(
    {
      reference: 'ts-stack@edf6e03 packages/sdk/src/wallet/WalletResultBEEF.ts',
      runtime: process.version,
      recorder: 'tests/support/wallet_result_beef_603.mjs',
      cases: recorded
    },
    null,
    2
  ) + '\n'
)
