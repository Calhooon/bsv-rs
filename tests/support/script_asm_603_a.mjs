// #603 shard A: the reference's `Script.fromASM` (`ts-stack@edf6e03`
// `packages/sdk/src/script/Script.ts:73-123`: the tokens split on one space,
// `#parseASMToken` per token, an inline PUSHDATA consuming the next two tokens
// `:102-108`, an unknown token a hex push sized by `#pushdataOpCodeNum`
// `:85-90`) and the type predicates (`:430-441`, `LockingScript.ts`,
// `UnlockingScript.ts`), and `setChunkOpCode` (`:297-301`: `this.chunks[i] =
// { op }` on a JavaScript array, appended at the length, a hole left beyond
// it), recorded for `tests/script_script_603_a.rs`.
// Each `asm` case is a list of parts joined with one space: a string is a
// token as written, `{ "bytes": n }` a hex token of n bytes, byte i being
// (7i + 1) mod 256 (the #603 RPuzzle recorder's value). Each records the
// reference's script (`toHex`) as `length` (bytes), `head` (the first six
// bytes, hex), `sha256` (hex) and, up to 600 bytes, `hex`; or `error`.
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-603-script-a/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   node tests/support/script_asm_603_a.mjs "$W/sdk.mjs" > tests/vectors/script_asm_603_a.json
import { pathToFileURL } from 'url'
import { createHash } from 'crypto'

const [bundle] = process.argv.slice(2)
const { Script, LockingScript, UnlockingScript } = await import(pathToFileURL(bundle).href)

const toHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
const token = part =>
  typeof part === 'string' ? part : toHex(Array.from({ length: part.bytes }, (_, i) => (7 * i + 1) % 256))

const cases = [
  // the inline PUSHDATA forms, `:102-108`
  ['pushdata1_at_0', ['OP_PUSHDATA1', '01', 'ff']],
  ['pushdata1_at_1', ['OP_1', 'OP_PUSHDATA1', '01', 'ff']],
  ['pushdata1_at_3', ['OP_1', 'OP_1', 'OP_1', 'OP_PUSHDATA1', '01', 'ff']],
  ['pushdata1_then_op', ['OP_PUSHDATA1', '01', 'ff', 'OP_1']],
  ['pushdata2_at_0', ['OP_PUSHDATA2', '0100', 'ab']],
  ['pushdata4_at_0', ['OP_PUSHDATA4', '01000000', 'ab']],
  // the short inline forms: fewer than two tokens after the opcode
  ['pushdata1_alone', ['OP_PUSHDATA1']],
  ['pushdata1_one_token', ['OP_PUSHDATA1', '01']],
  ['pushdata1_alone_at_1', ['OP_1', 'OP_PUSHDATA1']],
  ['pushdata1_one_token_at_1', ['OP_1', 'OP_PUSHDATA1', '01']],
  // a hex token's push opcode at each bound of `#pushdataOpCodeNum`, `:85-90`
  ...[75, 76, 77, 100, 255, 256, 257, 65535, 65536].map(n => [`hex_${n}`, [{ bytes: n }]]),
  ['hex_76_after_op', ['OP_1', { bytes: 76 }]],
  // the literal tokens, `:94-95`, and the empty token a split on one space gives
  ['zero_and_negative_one', ['0', '-1']],
  ['empty_text', ['']],
  ['double_space', ['OP_1', '', 'OP_2']]
]

const asm = cases.map(([name, parts]) => {
  const text = parts.map(token).join(' ')
  try {
    const bytes = Script.fromASM(text).toBinary()
    const out = {
      name,
      parts,
      length: bytes.length,
      head: toHex(bytes.slice(0, 6)),
      sha256: createHash('sha256').update(Uint8Array.from(bytes)).digest('hex')
    }
    if (bytes.length <= 600) out.hex = toHex(bytes)
    return out
  } catch (e) {
    return { name, parts, error: e.message }
  }
})

const answer = f => {
  try {
    return { returns: f() }
  } catch (e) {
    return { error: e.message }
  }
}
const predicates = {
  script: {
    isLockingScript: answer(() => new Script().isLockingScript()),
    isUnlockingScript: answer(() => new Script().isUnlockingScript())
  },
  lockingScript: {
    isLockingScript: answer(() => new LockingScript().isLockingScript()),
    isUnlockingScript: answer(() => new LockingScript().isUnlockingScript())
  },
  unlockingScript: {
    isLockingScript: answer(() => new UnlockingScript().isLockingScript()),
    isUnlockingScript: answer(() => new UnlockingScript().isUnlockingScript())
  }
}

// `setChunkOpCode(i, OP_0)` on `OP_1 OP_1` (`5151`) at an index it has, at
// its length and beyond it: the script written back (`toHex`) and its chunk
// count, or the error `toHex` throws.
const setChunkOpCode = [1, 2, 3].map(index => {
  const script = Script.fromASM('OP_1 OP_1')
  script.setChunkOpCode(index, 0)
  const out = { script: '5151', index, op: 0, chunks: script.chunks.length }
  try {
    out.hex = script.toHex()
  } catch (e) {
    out.error = e.message
  }
  return out
})

console.log(
  JSON.stringify(
    {
      reference: 'ts-stack@edf6e03 packages/sdk/src/script/Script.ts',
      node: process.version,
      asm,
      predicates,
      setChunkOpCode
    },
    null,
    2
  )
)
