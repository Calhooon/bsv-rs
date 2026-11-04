// #723: the ASM names of `0x00` and `0x4f`. The reference's `toASM`
// (`ts-stack@edf6e03` `packages/sdk/src/script/Script.ts:222-229`) writes a
// chunk without data through `#_chunkToString` (`:668-677`) as `OP[op]`, the
// reverse map built from `namedOP` by `OP[opcode] ??= name` (`OP.ts`, its
// tail), so the name listed earlier wins: `OP_0` before `OP_FALSE` for `0x00`
// (`OP.ts:6-7`, "the top one will be used in standard ASM output") and
// `OP_1NEGATE` for `0x4f` (`OP.ts:11`). Its `fromASM` (`Script.ts:73-123`)
// reads the literal tokens `0` and `-1` before any name (`#parseASMToken`, `:91-92`),
// then any opcode name (`OP_0`, `OP_FALSE`, `OP_1NEGATE`).
// Each shape is recorded as the reference answers it:
//   - `bytes` shapes: `Script.fromHex(hex).toASM()` and `fromASM` of that
//     text back to hex;
//   - `text` shapes: `Script.fromASM(text).toHex()` (`null` with the words
//     when it throws) and `toASM` of the script read.
// `go` is NOT a run (no Go toolchain on the recording host): go-sdk@2ca481c's
// `NewFromASM` (`script/script.go:46-63`) looks each token up in
// `OpCodeStrings` (`OP_0`, `OP_FALSE`, `OP_1NEGATE` among them,
// `script/opcodes.go:277,279,358`) and otherwise reads it as hex through
// `AppendPushDataHex` (`:79-86`, `hex.DecodeString`), so `0` (odd length)
// and `-1` (not hex) are `ErrInvalidOpCode`; its `ToASM` (`:190-215`) writes
// `OpCodeValues` (`opcodes.go:546,625`): `OP_FALSE` for `0x00`, `OP_1NEGATE`
// for `0x4f`. The transcription below is that reader on each text.
//
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-723/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_asm_names_723.mjs "$W/sdk.mjs" \
//     > tests/vectors/script_asm_names_723.json
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Script } = await import(pathToFileURL(sdkPath).href)

const BYTES = [
  ['op0', '00', 'OP_0 alone'],
  ['op1negate', '4f', 'OP_1NEGATE alone'],
  ['op0-op1negate', '004f', 'both, side by side'],
  ['op0-push', '0003aabbcc', 'OP_0 then a push, a CHECKMULTISIG unlocking shape'],
  ['op1negate-arith', '4f8b0087', 'OP_1NEGATE OP_1ADD OP_0 OP_EQUAL'],
  ['dup-op0-drop', '760075', 'OP_0 inside a longer script'],
  ['push-zero-byte', '0100', 'a push of one zero byte: its data hex, not a name'],
  ['push-81', '0181', 'a push of 0x81: its data hex, not a name'],
]

const TEXTS = [
  ['zero', '0', 'the old writer\'s text for 0x00'],
  ['negative-one', '-1', 'the old writer\'s text for 0x4f'],
  ['op0-name', 'OP_0', 'the reference\'s name for 0x00'],
  ['op-false-name', 'OP_FALSE', 'the alias of 0x00'],
  ['op1negate-name', 'OP_1NEGATE', 'the reference\'s name for 0x4f'],
  ['zero-negative-one', '0 -1', 'both old texts'],
  ['op0-op1negate-names', 'OP_0 OP_1NEGATE', 'both names'],
  ['dup-zero-drop', 'OP_DUP 0 OP_DROP', 'the old text inside a longer script'],
  ['dup-op0-drop', 'OP_DUP OP_0 OP_DROP', 'the name inside a longer script'],
  ['hex-00', '00', 'two hex digits: a push of one zero byte'],
]

const tryRun = f => {
  try {
    return f()
  } catch (e) {
    return { error: String(e.message) }
  }
}

// go-sdk@2ca481c `NewFromASM` (`script/script.go:46-63`), transcribed for
// the tokens these texts carry: a name of `OpCodeStrings`, else hex.
const GO_NAMES = { OP_0: '00', OP_FALSE: '00', OP_1NEGATE: '4f', OP_DUP: '76', OP_DROP: '75' }
function goRead (text) {
  let out = ''
  for (const tok of text.split(' ')) {
    if (GO_NAMES[tok] !== undefined) {
      out += GO_NAMES[tok]
    } else if (/^([0-9a-fA-F]{2})*$/.test(tok) && tok.length > 0 && tok.length / 2 <= 75) {
      out += (tok.length / 2).toString(16).padStart(2, '0') + tok.toLowerCase()
    } else {
      return { error: 'ErrInvalidOpCode' }
    }
  }
  return out
}

const bytes = BYTES.map(([id, hex, note]) => {
  const asm = Script.fromHex(hex).toASM()
  const back = tryRun(() => Script.fromASM(asm).toHex())
  return { id, note, hex, ts: { asm, asm_back_hex: typeof back === 'string' ? back : null } }
})

const texts = TEXTS.map(([id, text, note]) => {
  const read = tryRun(() => Script.fromASM(text))
  const ok = !('error' in read)
  const go = goRead(text)
  return {
    id,
    note,
    text,
    ts: {
      hex: ok ? read.toHex() : null,
      error: ok ? null : read.error,
      asm: ok ? read.toASM() : null,
    },
    go_transcribed: typeof go === 'string' ? { hex: go, error: null } : { hex: null, error: go.error },
  }
})

process.stdout.write(
  JSON.stringify(
    {
      source: 'tests/support/script_asm_names_723.mjs',
      runtime: `node ${process.version}`,
      reference: 'bsv-blockchain/ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk (bun bundle)',
      go: 'bsv-blockchain/go-sdk@2ca481c5931b987a0c8f48bb341c70b7477b6b07 script/script.go:46-63,190-215, transcribed, not run',
      bytes,
      texts,
    },
    null,
    1
  ) + '\n'
)
