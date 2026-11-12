// The order witnesses: the reference's answers on this crate's transaction
// doors' bytes.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   BEEF_TX_ORDER_PRINT=1 cargo test --features full --test beef_tx_order \
//     the_reference_writes -- --nocapture \
//     | grep -E '^[a-z_]+ [0-9a-f]+ [0-9a-f]+$' > "$W/witnesses.txt"
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_tx_order.mjs \
//     "$W/sdk.mjs" "$W/witnesses.txt" > tests/vectors/beef_tx_order.json
//
// Each witness is this crate's writer's V1 bytes with its subject's txid
// (`tests/beef_tx_order.rs`, `the_reference_writes_the_same_bytes_on_every_
// witness`), one `<name> <hex> <subject txid>` per line. For each, the
// reference's own transaction door (`Transaction.fromBEEF(bytes, txid)` —
// it links the sources on read — then `toBEEF(true)`, which writes what
// its post-order walk collects, the subject last, under the V1 word), the
// txid its reader takes from those bytes with no txid, its validity verdict
// on this crate's bytes, and its Beef-level sorted door
// (`Beef.fromBinary(bytes).sortTxs().toBinary()`, the dependency order every
// version before 0.8.8 wrote at this crate's transaction doors), are
// printed as the fields of `tests/vectors/beef_tx_order.json`.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, witnessPath] = process.argv.slice(2)
const { Transaction, Beef, Utils } = await import(pathToFileURL(sdkPath).href)

const hex = bytes => Utils.toHex(bytes)
console.error('node', process.version) // stderr: the vector takes stdout whole
const witnesses = []
for (const line of fs.readFileSync(witnessPath, 'utf8').split('\n')) {
  if (line.trim() === '') continue
  const [name, hexBytes, subject] = line.trim().split(' ')
  const bytes = Utils.toArray(hexBytes, 'hex')
  const named = Transaction.fromBEEF(bytes, subject)
  const theirs = hex(named.toBEEF(true))
  witnesses.push({
    name,
    origin: 'this crate\'s to_beef_v1, tests/beef_tx_order.rs',
    hex: hexBytes,
    subject_txid: subject,
    reference_tx_door_hex: theirs,
    reference_no_txid_txid: Transaction.fromBEEF(Utils.toArray(theirs, 'hex')).id('hex'),
    reference_valid: Beef.fromBinary(bytes).verifyValid().valid,
    reference_beef_sorted_hex: hex((() => { const b = Beef.fromBinary(bytes); b.sortTxs(); return b.toBinary() })())
  })
}
console.log(JSON.stringify({
  description: 'A transaction\'s BEEF ends with that transaction: the reference\'s transaction door (its post-order walk, subject last, V1 word) beside its Beef-level dependency sort, on the shapes of the finding (a proven branch beside a missing source) and honest chains and diamonds.',
  reference: '@bsv/sdk at ts-stack@edf6e03 (bundled with bun)',
  reference_lines: 'Transaction.ts:1787-1839 (writeSerializedBEEF); Beef.ts:360-373 (#getSerializedBytes); Beef.ts:1352-1406 (sortTxs)',
  brc: 'BRC-62',
  witnesses
}, null, 2))
