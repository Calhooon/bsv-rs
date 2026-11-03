// #661: a script built by hand from chunks whose opcode and data disagree.
// `Script::from_chunks` with `ScriptChunk::new` holds any `{ op, data }`, as the
// reference's `new Script(chunks)` does (`ts-stack@edf6e03`
// `packages/sdk/src/script/Script.ts`, `ScriptChunk.ts`: `{ op, data? }`, no
// check). Each shape is recorded as the reference answers it:
//   - `to_hex`: `toHex()` through `#serializeChunksToBytes` (`:474-490`) and
//     `#writeChunkData` (`:539-562`): the opcode byte, then the data only for
//     an opcode below `OP_PUSHDATA1` (the data bare) or a PUSHDATA opcode (its
//     length then the data), and after an `OP_RETURN` with data the data and
//     nothing more;
//   - `asm`: `toASM()` (`:222-229`) through `#_chunkToString` (`:668-677`): a
//     chunk with data writes its data's hex alone, whatever its opcode; a chunk
//     without writes `OP[op]`, the opcode's name;
//   - `asm_back_hex`: `Script.fromASM(asm).toHex()` (`:73-123`), the script the
//     reference reads back from its own text (`null` with the words when it
//     throws);
//   - `hex_back_asm`: `Script.fromHex(to_hex).toASM()`, the text of the bytes
//     the serializer wrote.
// `go` is NOT a run (no Go toolchain on the recording host): go-sdk@2ca481c
// writes a chunk list through `NewScriptFromScriptOps`
// (`script/script_chunk.go:119-163`): a push opcode (`OpDATA1` to
// `OpPUSHDATA4`) re-encoded as `AppendPushData(data)`'s minimal push, any
// other opcode alone, the data after an `OP_RETURN` appended and the walk
// ended; its `ToASM` (`script/script.go:190-213`) reads those bytes. The
// transcription below is that writer, line for line, on each shape.
//
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-661/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_chunk_asm_661.mjs "$W/sdk.mjs" \
//     > tests/vectors/script_chunk_asm_661.json
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Script, Utils } = await import(pathToFileURL(sdkPath).href)

// Each chunk: [op, data hex or null]; null is `data` absent (`None` here).
const SHAPES = [
  ['op1-empty-data', [[0x51, '']], 'the issue: Some(vec![]) on OP_1'],
  ['op0-empty-data', [[0x00, '']], 'the issue: Some(vec![]) on OP_0'],
  ['push1-empty-data', [[0x01, '']], 'the issue: Some(vec![]) on the direct push 0x01'],
  ['pushdata1-empty-data', [[0x4c, '']], 'the issue: Some(vec![]) on OP_PUSHDATA1'],
  ['dup-op1empty-dup', [[0x76, null], [0x51, ''], [0x76, null]], 'an empty-data OP_1 between two opcodes: a double space'],
  ['op-return-data-then-op1', [[0x6a, '51'], [0x51, null]], 'the issue: an OP_RETURN with data followed by a chunk'],
  ['op-return-push-then-dup', [[0x6a, '0568656c6c6f'], [0x76, null]], 'an OP_RETURN carrying a push, then OP_DUP'],
  ['op-return-empty-data-then-op1', [[0x6a, ''], [0x51, null]], 'an OP_RETURN with empty data followed by a chunk'],
  ['op-return-empty-data', [[0x6a, '']], 'an OP_RETURN with empty data alone'],
  ['dup-with-data', [[0x76, '0102']], 'the issue: data on a non-push opcode, OP_DUP with [1, 2]'],
  ['checksig-with-data', [[0xac, 'ab']], 'data on OP_CHECKSIG'],
  ['op1negate-with-data', [[0x4f, '81']], 'data on OP_1NEGATE'],
  ['push1-two-bytes', [[0x01, '0102']], 'a direct push whose data is longer than its opcode says'],
  ['push3-one-byte', [[0x03, 'aa']], 'a direct push whose data is shorter than its opcode says'],
  ['pushdata1-small', [[0x4c, 'aa']], 'OP_PUSHDATA1 carrying one byte (non-minimal)'],
  ['pushdata2-small', [[0x4d, 'aabb']], 'OP_PUSHDATA2 carrying two bytes (non-minimal)'],
  ['push1-no-data', [[0x01, null]], 'a direct push opcode with no data'],
  ['push4b-no-data', [[0x4b, null]], 'the direct push 0x4b with no data'],
  ['pushdata1-no-data', [[0x4c, null]], 'OP_PUSHDATA1 with no data'],
  ['pushdata4-no-data', [[0x4e, null]], 'OP_PUSHDATA4 with no data'],
  ['op0-no-data', [[0x00, null]], 'OP_0 as the parser holds it'],
  ['op1negate-no-data', [[0x4f, null]], 'OP_1NEGATE as the parser holds it'],
  ['undefined-op-ba', [[0xba, null]], 'an undefined opcode, 0xba'],
  ['undefined-op-ff', [[0xff, null]], 'an undefined opcode, 0xff'],
]

const hex = a => (a == null ? null : Utils.toHex(a))
const tryRun = f => {
  try {
    return f()
  } catch (e) {
    return { error: String(e.message) }
  }
}

// go-sdk@2ca481c `script/script_chunk.go:119-163` (`NewScriptFromScriptOps`)
// with `PushDataPrefix` (`:196-228`) inlined, transcribed.
function goWrite (chunks) {
  const out = []
  for (const [op, d] of chunks) {
    const data = d == null ? [] : Utils.toArray(d, 'hex')
    if (op >= 0x01 && op <= 0x4e) {
      const l = data.length
      if (l <= 75) out.push(l)
      else if (l <= 0xff) out.push(0x4c, l)
      else if (l <= 0xffff) out.push(0x4d, l & 0xff, l >> 8)
      else out.push(0x4e, l & 0xff, (l >> 8) & 0xff, (l >> 16) & 0xff, l >>> 24)
      out.push(...data)
    } else {
      out.push(op)
    }
    if (op === 0x6a && data.length > 0) {
      out.push(...data)
      break
    }
  }
  return Utils.toHex(out)
}

const shapes = SHAPES.map(([id, spec, note]) => {
  const chunks = spec.map(([op, d]) => (d == null ? { op } : { op, data: Utils.toArray(d, 'hex') }))
  const script = new Script(chunks)
  const toHex = script.toHex()
  const asm = script.toASM()
  const back = tryRun(() => Script.fromASM(asm).toHex())
  const hexBack = tryRun(() => Script.fromHex(toHex).toASM())
  return {
    id,
    note,
    chunks: spec.map(([op, data]) => ({ op, data })),
    ts: {
      to_hex: toHex,
      asm,
      asm_back_hex: typeof back === 'string' ? back : null,
      asm_back_error: typeof back === 'string' ? null : back.error,
      hex_back_asm: typeof hexBack === 'string' ? hexBack : null,
    },
    go_transcribed: { to_hex: goWrite(spec) },
  }
})

process.stdout.write(
  JSON.stringify(
    {
      source: 'tests/support/script_chunk_asm_661.mjs',
      runtime: `node ${process.version}`,
      reference: 'bsv-blockchain/ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk (bun bundle)',
      go: 'bsv-blockchain/go-sdk@2ca481c5931b987a0c8f48bb341c70b7477b6b07 script/script_chunk.go:119-163, transcribed, not run',
      shapes,
    },
    null,
    1
  ) + '\n'
)
