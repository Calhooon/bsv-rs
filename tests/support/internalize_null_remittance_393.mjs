// Measure the actual edf6e03 SDK under Node 22, without network calls.
// git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
// (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
// node tests/support/internalize_null_remittance_393.mjs "$W/sdk.mjs" \
//   tests/vectors/internalize_null_remittance_393.json [--write]
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { pathToFileURL } from 'node:url'

assert.equal(process.versions.node.split('.')[0], '22', 'use Node 22')
const [bundle, vector, mode] = process.argv.slice(2)
const { Validation } = await import(pathToFileURL(bundle))
const payment = {
  derivationPrefix: 'cHJlZml4', derivationSuffix: 'c3VmZml4',
  senderIdentityKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
}
const insertion = { basket: 'fixtures', tags: [] }
const cases = []
function record(name, protocol, remittances) {
  // JSON parsing supplies precisely the presence semantics being measured.
  const output = JSON.parse(JSON.stringify({ outputIndex: 0, protocol, ...remittances }))
  let expected
  try {
    Validation.validateInternalizeOutput(output)
    expected = { accepted: true }
  } catch (error) {
    expected = { accepted: false, code: error.code, message: error.message }
  }
  cases.push({ name, output, expected })
}
for (const [protocol, own, other, remittance] of [
  ['wallet payment', 'paymentRemittance', 'insertionRemittance', payment],
  ['basket insertion', 'insertionRemittance', 'paymentRemittance', insertion]
]) {
  const name = protocol.replace(' ', '_')
  record(`${name}_other_null`, protocol, { [own]: remittance, [other]: null })
  record(`${name}_own_null`, protocol, { [own]: null })
  record(`${name}_other_undefined`, protocol, { [own]: remittance, [other]: undefined })
  record(`${name}_own_undefined`, protocol, { [own]: undefined })
  record(`${name}_both_null`, protocol, { [own]: null, [other]: null })
  record(`${name}_other_null_alone`, protocol, { [other]: null })
}
const measured = {
  reference: 'ts-stack@edf6e03 packages/sdk/src/wallet/validationHelpers.ts:914-984',
  node: process.version, cases
}
if (mode === '--write') fs.writeFileSync(vector, JSON.stringify(measured, null, 2) + '\n')
else assert.deepEqual(JSON.parse(fs.readFileSync(vector, 'utf8')), measured)
for (const { name, expected } of cases) console.log(`${name}: ${JSON.stringify(expected)}`)
