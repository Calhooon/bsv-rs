// #734 recorder: an offset-0 proof under 100 blocks deep, read by the
// reference's `MerklePath.verify` as a coinbase's (`ts-stack@edf6e03`
// `packages/sdk/src/transaction/MerklePath.ts:476-500`: the root computed,
// `indexOf` the txid's level-0 offset, at offset 0 alone `currentHeight`
// asked and `blockHeight + 100 > height` answering false before the root is
// asked), so `Transaction.verify` throws `Invalid merkle path for
// transaction <txid>` (`Transaction.ts:1298-1316`) for every proven
// transaction it reaches, the subject included, while `Beef.verify`
// (`Beef.ts:1020-1035`) has no depth rule. Only the unmodified SDK writes
// the bytes and supplies the answers. Build the bundle at the pin and run
// under Node 22:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/coinbase_depth_734.mjs \
//     "$W/sdk.mjs" tests/vectors/coinbase_depth_734.json
//
// The vector carries every input (the transactions' and the BUMPs' bytes,
// each cell's tracker height and roots), so the Rust test rebuilds each
// transaction and BUMP with this crate's writer and compares the bytes.
import { writeFileSync } from 'node:fs'

const [, , bundle, out] = process.argv
const { Beef, MerklePath, Transaction, Script } = await import(bundle)

const H = 800000
const SIBLING = 'bb'.repeat(32)
// The parent's output `OP_EQUAL`, the child's unlocking `OP_1 OP_1`: one
// true element, clean under the version-1 default's CLEANSTACK.
const parent = new Transaction(
  1,
  [{ sourceTXID: 'aa'.repeat(32), sourceOutputIndex: 0, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff }],
  [{ satoshis: 1000, lockingScript: Script.fromHex('87') }],
  0
)
const P = parent.id('hex')

const PATHS = {
  // The parent alone in its block: the lone leaf at offset 0.
  lone: (h) => new MerklePath(h, [[{ offset: 0, hash: P, txid: true }]]),
  // The parent at offset 0 beside a sibling.
  left: (h) => new MerklePath(h, [[{ offset: 0, hash: P, txid: true }, { offset: 1, hash: SIBLING }]]),
  // The control: the parent at offset 1, no height asked.
  right: (h) => new MerklePath(h, [[{ offset: 0, hash: SIBLING }, { offset: 1, hash: P, txid: true }]])
}

function tracker (height, roots) {
  const calls = []
  return {
    calls,
    async currentHeight () {
      calls.push(['currentHeight'])
      return height
    },
    async isValidRootForHeight (root, h) {
      calls.push(['isValidRootForHeight', root, h])
      return roots[h] === root
    }
  }
}

function build (pathName, h) {
  const p = Transaction.fromHex(parent.toHex())
  p.merklePath = PATHS[pathName](h)
  const child = new Transaction(
    1,
    [{ sourceTransaction: p, sourceOutputIndex: 0, unlockingScript: Script.fromHex('5151'), sequence: 0xffffffff }],
    [{ satoshis: 900, lockingScript: Script.fromHex('51') }],
    0
  )
  return { p, child }
}

async function answer (f) {
  try {
    return { ok: await f() }
  } catch (e) {
    return { err: e.message }
  }
}

const DOORS = {
  merklePath: ({ p }, t) => p.merklePath.verify(P, t),
  child: ({ child }, t) => child.verify(t),
  parent: ({ p }, t) => p.verify(t),
  beef: ({ child }, t) => Beef.fromBinary(child.toBEEF()).verify(t)
}

const cells = []
const bumps = {}
async function cell (pathName, h, tip, rootKnown) {
  const txs = build(pathName, h)
  const root = txs.p.merklePath.computeRoot(P)
  bumps[`${pathName}_${h}`] = txs.p.merklePath.toHex()
  for (const [door, f] of Object.entries(DOORS)) {
    const t = tracker(tip, rootKnown ? { [h]: root } : {})
    const r = await answer(() => f(txs, t))
    cells.push({
      path: pathName,
      block_height: h,
      tip,
      root_known: rootKnown,
      door,
      child_hex: txs.child.toHex(),
      beef_hex: door === 'beef' ? txs.child.toHexBEEF() : undefined,
      ...r,
      calls: t.calls
    })
  }
}

for (const pathName of Object.keys(PATHS)) {
  for (const d of [0, 99, 100, 101]) await cell(pathName, H, H + d, true)
}
// A root the tracker refuses at depth.
await cell('lone', H, H + 100, false)
// The height bound: a proof at the top of the u32 range, no overflow.
await cell('lone', 4294967295, 4294967295, true)
// The tip below the proof (#734's fold, the strength read): a tracker whose
// `currentHeight` is a placeholder (0, 1) or one block short of the proof;
// `blockHeight + 100 > height` answers false at each, before the root is
// asked. The tip at the proof's own height is the `+0` cell above. Appended
// after the cells above, so their bytes do not move.
for (const pathName of ['lone', 'left']) {
  for (const tip of [0, 1, H - 1]) await cell(pathName, H, tip, true)
}

const vector = {
  description:
    '#734: an offset-0 proof under 100 blocks deep (MerklePath.ts:476-500 at ts-stack@edf6e03); each cell the verdict or thrown words and the tracker calls in order',
  recorded_with: `node ${process.version}, @bsv/sdk at ts-stack@edf6e03`,
  parent: { txid: P, raw: parent.toHex() },
  sibling: SIBLING,
  bumps,
  cells
}
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n')
