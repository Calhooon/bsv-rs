// The #817 transaction fold's witnesses: the reference's `hashPair` on a hash
// text of odd length (group `hash_pair`), and what its
// `findTransactionForSigning` answers (group `signing`).
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/transaction_fold_817.mjs \
//     "$W/sdk.mjs" > tests/vectors/transaction_fold_817.json
//
// `hash_pair`: a path is held as a caller holds one through the public
// fields (an object of the class whose `blockHeight` and `path` are set
// directly), as `merkle_path_writer_refusals_817.mjs` holds it.
// `compute_root` is `computeRoot()` on the held path (`MerklePath.ts:375-411`,
// pairing through `hashPair`, `:30-32`: the two texts concatenated, one
// leading `0` when the total length is odd, `utils.ts:125-128`), `checked`
// is `new MerklePath(h, path)` and `unchecked` the same with
// `legalOffsetsOnly` false: accepted (the root for `compute_root`) or the
// words thrown and the error class.
//
// `signing`: a parent and a child spending it, merged into a BEEF, written
// and read back (so every entry is held raw, its inputs unlinked; the
// child's unlocking script empty until it is signed);
// `findTransactionForSigning(child)` (`Beef.ts:615-631`), whether the object
// returned is the entry's, whether the entry's input is linked after it, and
// the BEEF's hex before and after the returned object's input is signed
// (P2PKH, SIGHASH_ALL | FORKID, the scalar 7).
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { MerklePath, Hash, Utils, Beef, Transaction, PrivateKey, P2PKH, Script } =
  await import(pathToFileURL(sdkPath).href)

const H = i => Utils.toHex(Hash.sha256([i & 0xff, (i >> 8) & 0xff]))

function words (f) {
  try {
    const r = f()
    return { accepted: true, result: typeof r === 'string' ? r : null }
  } catch (e) {
    return { accepted: false, refusal: e.message, class: e.constructor.name }
  }
}

const copy = path => path.map(level => level.map(leaf => ({ ...leaf })))

function held (blockHeight, path) {
  const mp = Object.create(MerklePath.prototype)
  mp.blockHeight = blockHeight
  mp.path = copy(path)
  return mp
}

const two = (txid, sibling) => [[{ offset: 0, hash: txid, txid: true }, { offset: 1, hash: sibling }]]
// Three levels: the txid at 0, its sibling at 1, the node at level 1 offset 1
// computed from level 0's offsets 2 (leaf0) and 3 (leaf1), level 2's offset 1
// carried.
const three = (leaf0, leaf1) => [
  [{ offset: 0, hash: H(0), txid: true }, { offset: 1, hash: H(1) }, { offset: 2, hash: leaf0 }, { offset: 3, hash: leaf1 }],
  [],
  [{ offset: 1, hash: H(4) }]
]

const cells = [
  ['sibling_of_63_digits', two(H(0), H(1).slice(1))],
  ['txid_of_63_digits', two(H(0).slice(1), H(1))],
  ['both_of_63_digits', two(H(0).slice(1), H(1).slice(1))],
  ['sibling_of_1_digit', two(H(0), 'a')],
  ['sibling_of_65_digits', two(H(0), H(1) + 'a')],
  ['txid_of_63_digits_beside_a_duplicate', [[{ offset: 0, hash: H(0).slice(1), txid: true }, { offset: 1, duplicate: true }]]],
  ['computed_node_leaf0_of_63_digits', three(H(2).slice(1), H(3))],
  ['computed_node_leaf1_of_63_digits', three(H(2), H(3).slice(1))],
  ['sibling_of_62_digits', two(H(0), H(1).slice(2))],
  ['sibling_of_64_digits', two(H(0), H(1))],
  ['sibling_of_66_digits', two(H(0), H(1) + 'ab')],
  ['empty_sibling', two(H(0), '')],
  ['computed_node_of_64_digits', three(H(2), H(3))]
]

const BLOCK_HEIGHT = 800000
const out = {
  description:
    'bsv-rs#817 transaction fold. hash_pair: each cell a MerklePath held through the public fields at block height 800000; compute_root computeRoot() on the held path, checked new MerklePath(h, path), unchecked the same with legalOffsetsOnly false: accepted (with the root) or the words thrown and the error class. signing: findTransactionForSigning on a BEEF read from bytes, the identity of the object returned, the entry\'s input link, the BEEF hex before and after the returned object is signed. Written by tests/support/transaction_fold_817.mjs.',
  reference: 'ts-stack@edf6e03 packages/sdk/src/transaction/MerklePath.ts, Beef.ts',
  node: process.version,
  block_height: BLOCK_HEIGHT,
  hash_pair: [],
  signing: null
}
for (const [name, path] of cells) {
  out.hash_pair.push({
    name,
    path,
    compute_root: words(() => held(BLOCK_HEIGHT, path).computeRoot()),
    checked: words(() => { new MerklePath(BLOCK_HEIGHT, copy(path)) }),
    unchecked: words(() => { new MerklePath(BLOCK_HEIGHT, copy(path), false) })
  })
}

// ---- signing ----
const key = new PrivateKey(7)
const lock = new P2PKH().lock(key.toPublicKey().toAddress())
const parent = new Transaction()
parent.addInput({ sourceTXID: H(9), sourceOutputIndex: 0, unlockingScript: Script.fromHex('51'), sequence: 0xffffffff })
parent.addOutput({ lockingScript: lock, satoshis: 1000 })
const child = new Transaction()
child.addInput({ sourceTransaction: parent, sourceOutputIndex: 0, unlockingScript: new Script(), sequence: 0xffffffff })
child.addOutput({ lockingScript: lock, satoshis: 900 })
const built = new Beef()
built.mergeTransaction(child)
const before = built.toHex()

const beef = Beef.fromString(before, 'hex')
const childTxid = child.id('hex')
const entry = beef.findTxid(childTxid)
const linkedBefore = entry.tx.inputs[0].sourceTransaction != null
const returned = beef.findTransactionForSigning(childTxid)
const sameObject = returned === beef.findTxid(childTxid).tx
const entryLinked = beef.findTxid(childTxid).tx.inputs[0].sourceTransaction != null
const unsignedAfterFind = beef.toHex()
returned.inputs[0].unlockingScriptTemplate = new P2PKH().unlock(key, 'all', false)
await returned.sign()
const after = beef.toHex()
out.signing = {
  key_scalar: 7,
  parent_txid: parent.id('hex'),
  child_txid: childTxid,
  signed_child_txid: returned.id('hex'),
  before,
  entry_input_linked_before: linkedBefore,
  returned_is_the_entry: sameObject,
  entry_input_linked_after: entryLinked,
  hex_after_find: unsignedAfterFind,
  hex_after_signing_the_returned: after,
  signed_child: returned.toHex()
}
console.log(JSON.stringify(out, null, 2))
