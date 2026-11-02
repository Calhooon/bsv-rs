// #634, the adversarial door read: where this crate's clamped IF depth gives
// an answer other than the reference's beyond the chunk count. The reference,
// `ts-stack@edf6e03` `packages/sdk`, lets the depth go negative
// (`Script.ts:616`), so after a stray `OP_ENDIF` an `OP_RETURN` is an opcode
// and what follows it is read as chunks; this crate folds it into the
// `OP_RETURN`'s data. Recorded here, per shape, as the reference answers:
//   - `Script.fromHex(h).toASM()` and `Script.fromASM` of that text back to hex;
//   - `PushDrop.decode(LockingScript.fromHex(h)).fields` (`PushDrop.ts:63-121`)
//     at its default position, as hex, or the words it throws;
//   - `decodeAndVerifyRegistryToken('basket', ...)`
//     (`registryTokenValidation.ts:57-64`, through `decodeCanonicalPushDrop`,
//     `PushDropValidation.ts:54-79`): the words it throws.
// The bytes are this crate's writer's (the Rust test rebuilds and compares).
//
// Recorded under Node v22.18.0:
//   W=<scratch>
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_if_depth_consequences_634.mjs "$W/sdk.mjs" \
//     > tests/vectors/script_if_depth_consequences_634.json
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Script, LockingScript, PushDrop, decodeAndVerifyRegistryToken, Utils } = await import(
  pathToFileURL(sdkPath).href
)

const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const push = text => text.length.toString(16).padStart(2, '0') + Utils.toHex(Utils.toArray(text, 'utf8'))

const shapes = [
  { id: 'endif-return-op1', hex: '686a51' },
  { id: 'endif-return-push', hex: '686a0568656c6c6f' },
  { id: 'p2pkh-then-endif-return-op1', hex: `76a914${'11'.repeat(20)}88ac686a51` },
  { id: 'pushdrop-field-endif-return-field-2drop', hex: `21${G}ac0461626364686a0568656c6c6f6d` }
]

const out = []
for (const { id, hex } of shapes) {
  const asm = Script.fromHex(hex).toASM()
  let pushdrop
  try {
    pushdrop = { fields: PushDrop.decode(LockingScript.fromHex(hex)).fields.map(f => Utils.toHex(f)) }
  } catch (e) {
    pushdrop = { error: e.message }
  }
  out.push({ id, hex, ts: { asm, asm_back_to_hex: Script.fromASM(asm).toHex(), pushdrop } })
}

const registryHex = `21${G}ac${push('a')}${push('b')}${push('c')}${push('d')}686a${push('sigsigsig')}6d6d6d75`
let registry
try {
  registry = { fields: await decodeAndVerifyRegistryToken('basket', LockingScript.fromHex(registryHex)) }
} catch (e) {
  registry = { error: e.message }
}

console.log(
  JSON.stringify(
    {
      source: 'tests/support/script_if_depth_consequences_634.mjs',
      runtime: `node ${process.version}`,
      reference: 'bsv-blockchain/ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk (bun bundle)',
      shapes: out,
      registry_basket: { hex: registryHex, ts: registry }
    },
    null,
    2
  )
)
