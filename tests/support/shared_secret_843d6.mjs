// The #843d6 witness: the reference's ECDH bytes, which the crate-owned
// `SharedSecret` must leave unmoved.
//
// Run against @bsv/sdk at ts-stack@edf6e03 bundled with bun (no node_modules):
//   git -C ~/bsv/ts-stack archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/shared_secret_843d6.mjs \
//     "$W/sdk.mjs" > tests/vectors/shared_secret_843d6.json
//
// For each pair of small fixed scalars (a, b) it records
// `PrivateKey(a).deriveSharedSecret(B).encode(true)` (`PrivateKey.ts:397-402`),
// `PublicKey(B).deriveSharedSecret(a)` (`PublicKey.ts:113-118`, B the point of
// b, the same point), `new KeyDeriver(a).revealCounterpartySecret(B)`
// (`KeyDeriver.ts:407-422`, `number[]`), and BRC-42's `deriveChild` from both
// sides for two invoice numbers (`PrivateKey.ts:460`: the HMAC keyed with the
// 33 bytes): the private child's scalar and the public child's compressed key.
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { PrivateKey, KeyDeriver, Utils } = await import(pathToFileURL(sdkPath).href)

const pairs = [[2, 3], [5, 7], [9, 11], [1234567, 89], [65537, 4294967291]]
const invoices = ['2-3241645161d8-test', '1-brc42 invoice 843d6']

const cases = pairs.map(([a, b]) => {
  const priv = new PrivateKey(a)
  const otherPriv = new PrivateKey(b)
  const other = otherPriv.toPublicKey()
  const fromPrivate = Utils.toHex(priv.deriveSharedSecret(other).encode(true))
  const fromPublic = Utils.toHex(priv.toPublicKey().deriveSharedSecret(otherPriv).encode(true))
  const revealed = Utils.toHex(new KeyDeriver(priv).revealCounterpartySecret(other))
  const children = invoices.map((invoice) => ({
    invoice,
    private_child: priv.deriveChild(other, invoice).toHex(),
    public_child: other.deriveChild(priv, invoice).toString()
  }))
  return {
    a,
    b,
    public_b: other.toString(),
    point_from_private: fromPrivate,
    point_from_public: fromPublic,
    point_revealed: revealed,
    children
  }
})

console.log(JSON.stringify({
  description: 'The reference\'s ECDH bytes (#843d6): deriveSharedSecret from both doors encoded compressed, revealCounterpartySecret, and deriveChild from both sides; recorded by tests/support/shared_secret_843d6.mjs',
  reference: 'ts-stack@edf6e03 packages/sdk',
  node: process.version,
  cases
}, null, 2))
