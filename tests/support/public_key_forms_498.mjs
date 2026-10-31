// The #498 witnesses: the public-key strings `PublicKey.fromString` reads.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   NODE=~/.nvm/versions/node/v22.18.0/bin/node
//   $NODE tests/support/public_key_forms_498.mjs "$W/sdk.mjs" > tests/vectors/public_key_forms_498.json
//
// Each case is a key string and the reference's verdict: accepted, with what
// its `toString()` and `encode(false, 'hex')` write back, or refused, with its
// words. `point` is the accepted point's coordinates reduced modulo p, worked
// out here from the reference's own uncompressed encoding: `Point.validate`
// judges those (Point.ts:495-510), while `encode` writes a coordinate at or
// above p unreduced and takes the compressed prefix from the unreduced y.
import { pathToFileURL } from 'url'

const sdk = await import(pathToFileURL(process.argv[2]).href)
const { PublicKey } = sdk

const P = (1n << 256n) - (1n << 32n) - 977n
const hex = n => n.toString(16).padStart(64, '0')
const pow = (base, exponent) => {
  let result = 1n
  base %= P
  while (exponent > 0n) {
    if (exponent & 1n) result = result * base % P
    base = base * base % P
    exponent >>= 1n
  }
  return result
}
const gx = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const gy = '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
const negGy = hex(P - BigInt('0x' + gy))
// x = p + 1 reads as x = 1 (Point.fromX's biMod); its even root from the reference.
const xAbove = hex(P + 1n)
const rootOne = PublicKey.fromString('02' + xAbove).encode(false, 'hex').slice(66)
const rootOneOdd = hex(P - BigInt('0x' + rootOne))
// The point with y = 1: x the cube root of 1 - 7 (p = 7 mod 9, so a^((p+2)/9)).
const xOfYOne = hex(pow(P - 6n, (P + 2n) / 9n))
// An x whose x^3 + 7 has no root, above p: refused after the reduction.
let offCurve = 1n
while (pow((offCurve ** 3n + 7n) % P, (P - 1n) / 2n) === 1n) offCurve++

const definitions = [
  // The strict forms, accepted by every reader.
  ['compressed_even', '02' + gx],
  ['compressed_odd', '03' + gx],
  ['uncompressed', '04' + gx + gy],
  ['compressed_upper_case', ('02' + gx).toUpperCase()],
  // An odd-length string padded with a leading 0 (utils.ts:127-128).
  ['odd_length_compressed_even', '2' + gx],
  ['odd_length_compressed_odd', '3' + gx],
  ['odd_length_uncompressed', '4' + gx + gy],
  ['odd_length_hybrid_even', '6' + gx + gy],
  ['odd_length_hybrid_odd', '7' + gx + negGy],
  // A hybrid key whose prefix names y's parity (Point.ts:305-319).
  ['hybrid_even', '06' + gx + gy],
  ['hybrid_odd', '07' + gx + negGy],
  // An x at or above p, reduced (Point.ts:366-367 for 02/03, validate for 04/06/07).
  ['x_above_p_compressed_even', '02' + xAbove],
  ['x_above_p_compressed_odd', '03' + xAbove],
  ['x_above_p_odd_length', '2' + xAbove],
  ['x_above_p_uncompressed', '04' + xAbove + rootOne],
  ['x_above_p_hybrid_even', '06' + xAbove + rootOne],
  ['x_above_p_hybrid_odd', '07' + xAbove + rootOneOdd],
  // A y at or above p: validate reduces it too; the hybrid parity is the raw byte's.
  ['y_above_p_uncompressed', '04' + xOfYOne + hex(P + 1n)],
  ['y_above_p_hybrid_even', '06' + xOfYOne + hex(P + 1n)],
  ['y_above_p_hybrid_odd', '07' + xOfYOne + hex(P + 1n)],
  // The refusals.
  ['hybrid_even_prefix_odd_y', '06' + gx + negGy],
  ['hybrid_odd_prefix_even_y', '07' + gx + gy],
  ['odd_length_hybrid_wrong_parity', '7' + gx + gy],
  ['x_equal_p_compressed', '02' + hex(P)],
  ['x_above_p_off_curve', '02' + hex(P + offCurve)],
  ['uncompressed_off_curve', '04' + gx + hex(BigInt('0x' + gy) + 1n)],
  ['compressed_prefix_05', '05' + gx],
  ['compact_prefix_05_odd_length', '5' + gx],
  ['infinity', '00'],
  ['empty', ''],
  ['prefix_alone', '02'],
  ['odd_length_one_digit', '2'],
  ['odd_length_short', '2' + gx.slice(1)],
  ['compressed_too_long', '02' + gx + '00'],
  ['non_hex', 'zz'],
  ['non_hex_odd_length', 'not-hex'],
  ['non_hex_odd_length_tail', '2' + gx.slice(0, 63) + 'g'],
  ['leading_space', ' 02' + gx],
  ['hex_prefix', '0x02' + gx]
]

const point = uncompressed => {
  const x = BigInt('0x' + uncompressed.slice(2, 66)) % P
  const y = BigInt('0x' + uncompressed.slice(66)) % P
  return { compressed: ((y & 1n) ? '03' : '02') + hex(x), uncompressed: '04' + hex(x) + hex(y) }
}

const cases = definitions.map(([name, input]) => {
  try {
    const key = PublicKey.fromString(input)
    const uncompressed = key.encode(false, 'hex')
    return {
      name,
      input,
      accepted: true,
      reference_compressed: key.toString(),
      reference_uncompressed: uncompressed,
      point: point(uncompressed),
      error: null
    }
  } catch (error) {
    return { name, input, accepted: false, reference_compressed: null, reference_uncompressed: null, point: null, error: error.message }
  }
})

process.stdout.write(JSON.stringify({
  issue: 498,
  reference: 'ts-stack@edf6e03 packages/sdk PublicKey.fromString',
  node: process.version,
  cases
}, null, 2) + '\n')
