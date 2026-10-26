// The #282 witnesses: the reference's createAction argument gate on an input's
// unlocking script and its length.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/create_action_unlocking_script_282.mjs "$W/sdk.mjs"
//
// It runs the reference's `Validation.validateCreateActionArgs`
// (`validationHelpers.ts:749-758`, each input through
// `validateCreateActionInput` at `:587-614`) on one-input arguments and
// prints, for each case, the verdict and the thrown message.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Validation } = await import(pathToFileURL(sdkPath).href)

const input = extra => ({
  outpoint: `${'11'.repeat(32)}.0`,
  inputDescription: 'spend the coin',
  ...extra
})
const cases = [
  ['empty_unlocking_script', { unlockingScript: '' }],
  ['empty_unlocking_script_with_length_zero', { unlockingScript: '', unlockingScriptLength: 0 }],
  ['zero_unlocking_script_length', { unlockingScriptLength: 0 }],
  ['one_byte_unlocking_script', { unlockingScript: '51' }],
  ['unlocking_script_length_one', { unlockingScriptLength: 1 }]
]
console.log('node', process.version)
for (const [name, extra] of cases) {
  const args = {
    description: 'pay the invoice',
    inputs: [input(extra)],
    outputs: []
  }
  try {
    Validation.validateCreateActionArgs(args)
    console.log(JSON.stringify({ name, input: extra, accepted: true }))
  } catch (e) {
    console.log(
      JSON.stringify({ name, input: extra, accepted: false, error: e.name, code: e.code, message: e.message })
    )
  }
}
