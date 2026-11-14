// #817's test pins: what the reference answers at two doors of a BEEF.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules),
// as the #621 and #817 recorders are run:
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_pins_817.mjs \
//     "$W/sdk.mjs" > tests/vectors/beef_pins_817.json
//
// `raw_after_read`: a source read from bytes (`Beef.fromString` of its own
// `toHex`, its cache held), then given a raw transaction through `mergeRawTx`
// (`Beef.ts:835-839`: `#markMutated(true)`, the cache ended and the sort
// asked), merged into an empty target by `mergeBeef` (`:971-990`): the
// target's entries and the SHA-256 of its `toBinary`, and of the source's
// after the merge.
//
// `raw_index`: `mergeRawTx(rawTx, bumpIndex)` with an index the BEEF's BUMPs
// do not bear out (`:835-847`; `#tryToValidateBumpIndex` returns at a given
// index, `:1329-1332`): the entry returned, the entries held, the SHA-256 of
// `toBinary`, what `Beef.fromString` and `Beef.fromBinaryStrict` read back
// from those bytes, and `verifyValid(true)` and `isValid(true)`.
//
// The vector carries every input (the transactions' and the BUMPs' bytes and
// each case's steps) and no BEEF: the Rust tests rebuild each BEEF with this
// crate's writer and compare the SHA-256 of the bytes written.
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const [sdkPath] = process.argv.slice(2)
const { Beef, MerklePath, Transaction, Script } = await import(pathToFileURL(sdkPath).href)

const ONE = () => Script.fromHex('51')
const spend = (txid, vout) => ({
  sourceTXID: txid,
  sourceOutputIndex: vout,
  unlockingScript: ONE(),
  sequence: 0xffffffff
})
// The #621 recorder's T, U, X and Y, built the same way (the same txids).
const t = new Transaction(1, [spend('aa'.repeat(32), 0)], [{ satoshis: 1000, lockingScript: ONE() }], 0)
const u = new Transaction(1, [spend('bb'.repeat(32), 0)], [{ satoshis: 2000, lockingScript: ONE() }], 0)
const x = new Transaction(1, [spend('dd'.repeat(32), 0)], [{ satoshis: 3000, lockingScript: ONE() }], 0)
const y = new Transaction(1, [spend('cc'.repeat(32), 0)], [{ satoshis: 4000, lockingScript: ONE() }], 0)
const TXS = { t, u, x, y }
const NAMES = Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [tx.id('hex'), name]))

const BUMPS = {
  t_800000: () => new MerklePath(800000, [[{ offset: 0, hash: t.id('hex'), txid: true }]]),
  x_800002: () => new MerklePath(800002, [[{ offset: 0, hash: x.id('hex'), txid: true }]])
}

const sha256 = bytes => createHash('sha256').update(Uint8Array.from(bytes)).digest('hex')
const entries = beef =>
  beef.txs.map(e => ({ tx: NAMES[e.txid], bump_index: e.bumpIndex ?? null, txid_only: e.isTxidOnly }))

// A step: `bump:<name>` (`mergeBump`), `raw:<name>` (`mergeRawTx` with no
// index), `raw:<name>:<n>` (`mergeRawTx` with the index n), `txid:<name>`
// (`mergeTxidOnly`), `reread:` (the BEEF replaced by `Beef.fromString` of its
// own `toHex`). The last value a `mergeRawTx` returned is kept.
const apply = (beef, steps) => {
  let returned = null
  for (const step of steps) {
    if (step === 'reread:') {
      beef = Beef.fromString(beef.toHex(), 'hex')
      continue
    }
    const [kind, name, index] = step.split(':')
    if (kind === 'bump') beef.mergeBump(BUMPS[name]())
    else if (kind === 'raw') {
      returned = index === undefined
        ? beef.mergeRawTx(TXS[name].toBinary())
        : beef.mergeRawTx(TXS[name].toBinary(), Number(index))
    } else if (kind === 'txid') beef.mergeTxidOnly(TXS[name].id('hex'))
    else throw new Error(`no step ${step}`)
  }
  return { beef, returned }
}

function read (f) {
  try {
    return { accepted: true, entries: entries(f()) }
  } catch (e) {
    return { accepted: false, refusal: e.message, class: e.constructor.name }
  }
}

// ---- raw_after_read ----
// X proven and T a txid alone, read from bytes in that order; then Y raw.
// The order read, with Y appended, is X, T, Y.
const AFTER_READ = [
  {
    name: 'read_source_then_raw_merged_is_sorted',
    source: ['bump:x_800002', 'bump:t_800000', 'raw:x', 'txid:t', 'reread:', 'raw:y']
  }
]
const rawAfterRead = AFTER_READ.map(cs => {
  const { beef: source } = apply(new Beef(), cs.source)
  const heldBefore = entries(source)
  const target = new Beef()
  // The source is not serialized between its last step and the merge.
  target.mergeBeef(source)
  return {
    name: cs.name,
    source: cs.source,
    source_held_before_the_merge: heldBefore,
    entries: entries(target),
    bumps: target.bumps.length,
    beef_sha256: sha256(target.toBinary()),
    source_beef_sha256: sha256(source.toBinary())
  }
})

// ---- raw_index ----
const INDEX = [
  // One BUMP held (index 0); the index given is 5.
  { name: 'index_past_the_list', steps: ['bump:t_800000', 'raw:t:5'] },
  // One BUMP held; the index given is the count.
  { name: 'index_at_the_count', steps: ['bump:t_800000', 'raw:t:1'] },
  // No BUMP held; the index given is 0.
  { name: 'index_with_no_bump_held', steps: ['raw:t:0'] },
  // The BUMP at the index holds T; the transaction is U.
  { name: 'index_naming_a_bump_without_the_txid', steps: ['bump:t_800000', 'raw:u:0'] },
  // Two BUMPs; the one at the index given (0) holds X, the other (1) holds T.
  { name: 'index_naming_the_other_of_two_bumps', steps: ['bump:x_800002', 'bump:t_800000', 'raw:t:0'] },
  // The control: the index given is the BUMP holding the txid.
  { name: 'index_naming_the_bump_holding_the_txid', steps: ['bump:x_800002', 'bump:t_800000', 'raw:t:1'] }
]
const rawIndex = INDEX.map(cs => {
  const { beef, returned } = apply(new Beef(), cs.steps)
  const bytes = beef.toBinary()
  return {
    name: cs.name,
    steps: cs.steps,
    returned: { tx: NAMES[returned.txid], bump_index: returned.bumpIndex ?? null },
    entries: entries(beef),
    bumps: beef.bumps.length,
    beef_sha256: sha256(bytes),
    beef_length: bytes.length,
    read_back: read(() => Beef.fromString(beef.toHex(), 'hex')),
    read_back_strict: read(() => Beef.fromBinaryStrict(bytes)),
    verify_valid: beef.verifyValid(true).valid,
    is_valid: beef.isValid(true)
  }
})

const out = {
  description:
    'bsv-rs#817 test pins. raw_after_read: a source read from bytes then given a raw transaction through mergeRawTx, merged into an empty target by mergeBeef: the target\'s entries and the SHA-256 of its toBinary and of the source\'s after the merge. raw_index: mergeRawTx(rawTx, bumpIndex) with an index the BUMPs do not bear out: the entry returned, the entries held, the SHA-256 and length of toBinary, what fromString and fromBinaryStrict read back, verifyValid(true).valid and isValid(true). No BEEF is carried: each is rebuilt from the steps. Written by tests/support/beef_pins_817.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/Beef.ts (:835-847, :971-990, :1329-1340)',
  node: process.version,
  txs: Object.fromEntries(Object.entries(TXS).map(([name, tx]) => [name, { txid: tx.id('hex'), raw: tx.toHex() }])),
  bumps: Object.fromEntries(Object.entries(BUMPS).map(([name, mp]) => [name, mp().toHex()])),
  raw_after_read: rawAfterRead,
  raw_index: rawIndex
}
console.log(JSON.stringify(out, null, 2))
