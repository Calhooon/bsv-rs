// The #240 witnesses: a BEEF's order on the wire in the reference.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   BEEF_ORDER_240_PRINT=1 cargo test --features full --test beef_order_held the_three -- --nocapture \
//     | grep -E '^[a-z0-9_]+ [0-9a-f]+$' > "$W/witnesses.txt"
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/beef_order_240.mjs \
//     "$W/sdk.mjs" "$W/witnesses.txt"
//
// Each witness is this crate's writer's bytes (`tests/beef_order_held.rs`,
// `witnesses()`), one `<name> <hex>` per line. For each, the reference's
// `Beef.fromBinary(bytes).verifyValid()` (`Beef.ts:1054-1088`: the atomic
// rule, then `sortTxs` at `:1065` ahead of its checks) is printed as the
// `reference_valid` field of `tests/vectors/beef_order_240.json`.
import fs from 'fs'
import { pathToFileURL } from 'url'

const [sdkPath, witnessPath] = process.argv.slice(2)
const { Beef, Utils } = await import(pathToFileURL(sdkPath).href)

console.log('node', process.version)
for (const line of fs.readFileSync(witnessPath, 'utf8').split('\n')) {
  if (line.trim() === '') continue
  const [name, hex] = line.trim().split(' ')
  let verdict
  try {
    verdict = Beef.fromBinary(Utils.toArray(hex, 'hex')).verifyValid().valid
  } catch (e) {
    verdict = `threw: ${e.message}`
  }
  console.log(name, verdict)
}
