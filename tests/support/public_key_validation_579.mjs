// #579: the reference's two public-key validators on one list of key texts
// (`ts-stack@edf6e03`; the keeper's word of 2026-11-01 01:1xZ, shape (2)).
//   wallet  `validatePublicKey` (`packages/sdk/src/wallet/validationHelpers.ts:185-191`,
//           through `isValidCompressedPublicKey`, `Secp256k1Validation.ts:15-22`),
//           reached through the exported `validateDiscoverByIdentityKeyArgs`
//           (`:1535-1546`), whose `identityKey` it judges first under that name
//   auth    `assertAuthIdentityKey` (`packages/sdk/src/auth/AuthMessageValidation.ts:81-90`)
// Each case records `{ ok, returned }` (the text the validator returns, the wallet's
// trimmed and lower-cased; the auth's the text as given) or `{ ok: false,
// message }` (the thrown error's message). The texts are #498's lenient forms,
// the case and trim differences between the two rules, and the reference's own
// test inputs (`wallet/__tests/WalletNarrowValidation.test.ts:43-56`,
// `wallet/__tests/validationHelpers.test.ts:1257-1260,1449-1454`).
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-579/ref
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build src/wallet/validationHelpers.ts --target node --format esm --outfile "$W/vh.mjs" \
//     && bun build src/auth/AuthMessageValidation.ts --target node --format esm --outfile "$W/amv.mjs")
//   node tests/support/public_key_validation_579.mjs "$W/vh.mjs" "$W/amv.mjs" > tests/vectors/public_key_validation_579.json
import { pathToFileURL } from 'url'

const [walletBundle, authBundle] = process.argv.slice(2)
const { validateDiscoverByIdentityKeyArgs } = await import(pathToFileURL(walletBundle).href)
const { assertAuthIdentityKey } = await import(pathToFileURL(authBundle).href)

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const hex64 = n => n.toString(16).padStart(64, '0')
const GX = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const GY = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'

const cases = [
  ['compressed', `02${GX}`],
  ['compressed_other_parity', `03${GX}`],
  ['upper_case', `02${GX.toUpperCase()}`],
  ['surrounding_space', ` 02${GX} `],
  ['odd_length_498', `2${GX}`],
  ['uncompressed_498', `04${GX}${GY}`],
  ['hybrid_498', `06${GX}${GY}`],
  ['x_above_p_498', `02${hex64(P + 1n)}`],
  ['x_at_p', `02${hex64(P)}`],
  ['empty', ''],
  ['uncompressed_zero', `04${'00'.repeat(64)}`],
  ['x_zero', `02${'00'.repeat(32)}`],
  ['non_hex', `02${'gg'.repeat(32)}`],
  ['short', '0234'],
  ['prefix_04_compressed_length', `04${'00'.repeat(32)}`]
]

function outcome (judge) {
  try {
    return { ok: true, returned: judge() }
  } catch (error) {
    return { ok: false, message: error.message }
  }
}

const vectors = cases.map(([name, text]) => ({
  name,
  text,
  wallet: outcome(() => validateDiscoverByIdentityKeyArgs({ identityKey: text }).identityKey),
  auth: outcome(() => {
    assertAuthIdentityKey(text)
    return text
  })
}))

process.stdout.write(JSON.stringify({
  reference: 'ts-stack@edf6e03',
  node: process.version,
  wallet_parameter: 'identityKey',
  cases: vectors
}, null, 2) + '\n')
