// #634: a stray `OP_ENDIF` before `OP_RETURN`. The chunk readers decide where
// a top-level `OP_RETURN` ends the parse (the rest one data chunk) by an IF
// depth they count as they read; they differ on a stray `OP_ENDIF`:
//   - the reference, `ts-stack@edf6e03` `packages/sdk/src/script/Script.ts`
//     `#parseChunks` `:599-632`: `inConditionalBlock--` with no floor (`:616`),
//     and `OP_RETURN` ends the parse only at `=== 0` (`:608`), so after a stray
//     `OP_ENDIF` the depth is -1 and an `OP_RETURN` is read as an opcode;
//   - go-sdk@2ca481c `script/script_chunk.go` `DecodeScript` `:245-332`
//     (`Script.Chunks()`, `script.go:395-397`): `conditionalBlock--` with no
//     floor (`:255-257`), and `OP_RETURN` is read as an opcode only at `> 0`
//     (`:258-260`), so at -1 it ends the parse. go-sdk's other readers are not
//     recorded here: `ReadOp`/`ParseOps` (`script_chunk.go:25-115`, under
//     `ToASM`, `script.go:190-213`) count no depth and fold nothing; the
//     interpreter's legacy parser (`interpreter/opcodeparser.go:284-385`)
//     clamps at 0 as this crate does (`updateConditionalDepth`, `:389-401`);
//     its engine's node-exact parser (`:218-266`) folds nothing;
//   - this crate, `Script::parse_chunks` (`src/script/script.rs`): the depth
//     clamped at 0 (`(in_conditional_block - 1).max(0)`), `OP_RETURN` ends the
//     parse at `== 0`.
// The node reads no chunks: `CScript::GetOp2` (bitcoin-sv v1.2.3 `6504a3a`
// `src/script/script.h:165-198`) reads one opcode and its push, with no depth,
// and the interpreter's `OP_RETURN` (`interpreter.cpp:856-871`) and
// `OP_ENDIF` (`:835-840`, `SCRIPT_ERR_UNBALANCED_CONDITIONAL` on an empty
// conditional stack) judge at run time.
//
// Each shape is written from its ASM by the reference's `Script.fromASM` (the
// Rust test rebuilds the same bytes with this crate's `Script::from_asm`), read
// back by `Script.fromHex`, and recorded as the reference holds it: its chunks
// (`op`, `data` hex or null), `toASM()`, and the reference's `Spend` verdict in
// its default mode (no `verifyFlags`) at transaction versions 1 and 2, the
// shape as the locking script under the unlocking script `OP_1`.
// `go_transcribed` is NOT a run (no Go toolchain on the recording host): it is
// `goDecodeScript` below, a line-for-line transcription of the depth rule and
// the push reading of `DecodeScript` at the pin, applied to the same bytes.
//
// Recorded under Node v22.18.0:
//   W=/Volumes/Lanes/out/bsv-rs/fix-634/ref
//   git -C <ts-stack clone> archive edf6e03 packages/sdk conformance | tar -x -C "$W"
//   (cd "$W/packages/sdk" && bun build mod.ts --target node --format esm --outfile "$W/sdk.mjs")
//   ~/.nvm/versions/node/v22.18.0/bin/node tests/support/script_if_depth_634.mjs "$W/sdk.mjs" \
//     > tests/vectors/script_if_depth_634.json
import { pathToFileURL } from 'url'

const [sdkPath] = process.argv.slice(2)
const { Script, LockingScript, UnlockingScript, Spend, Utils } = await import(pathToFileURL(sdkPath).href)

const SHAPES = [
  ['endif-return-op1', 'OP_ENDIF OP_RETURN OP_1', 'the issue: a stray OP_ENDIF before OP_RETURN (686a51)'],
  ['endif-return-push', 'OP_ENDIF OP_RETURN 68656c6c6f', 'the issue\'s form OP_ENDIF OP_RETURN <push>'],
  ['return-push', 'OP_RETURN 68656c6c6f', 'the issue\'s form of a bare OP_RETURN <push>'],
  ['if-endif-return-op1', 'OP_1 OP_IF OP_ENDIF OP_RETURN OP_1', 'a balanced OP_IF OP_ENDIF before OP_RETURN'],
  ['if-endif-endif-return-push', 'OP_IF OP_ENDIF OP_ENDIF OP_RETURN 68656c6c6f', 'the issue\'s form OP_IF OP_ENDIF OP_ENDIF OP_RETURN <push>, as written (no condition pushed)'],
  ['op1-if-endif-endif-return-op1', 'OP_1 OP_IF OP_ENDIF OP_ENDIF OP_RETURN OP_1', 'a balanced OP_IF OP_ENDIF, then a stray OP_ENDIF, before OP_RETURN'],
  ['endif-endif-return-op1', 'OP_ENDIF OP_ENDIF OP_RETURN OP_1', 'two stray OP_ENDIFs before OP_RETURN'],
  ['return-endif-op1', 'OP_RETURN OP_ENDIF OP_1', 'a stray OP_ENDIF after an OP_RETURN at depth 0'],
  ['if-return-op1-endif', 'OP_1 OP_IF OP_RETURN OP_1 OP_ENDIF', 'OP_RETURN inside an open, executed OP_IF'],
  ['false-if-return-endif', 'OP_0 OP_IF OP_RETURN OP_ENDIF', 'OP_RETURN inside an open, unexecuted OP_IF'],
  ['nested-balanced-return-op1', 'OP_1 OP_IF OP_1 OP_IF OP_ENDIF OP_ENDIF OP_RETURN OP_1', 'nested, balanced, before OP_RETURN'],
  ['nested-balanced-endif-return-op1', 'OP_1 OP_IF OP_1 OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_RETURN OP_1', 'nested, balanced, then a stray OP_ENDIF, before OP_RETURN'],
  ['endif-if-return-op1-endif', 'OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF', 'a stray OP_ENDIF, then an OP_IF around OP_RETURN: the depth -1 + 1 = 0 in TS and Go, 1 here'],
  ['balanced-endif-if-return-op1-endif', 'OP_1 OP_IF OP_ENDIF OP_ENDIF OP_1 OP_IF OP_RETURN OP_1 OP_ENDIF', 'balanced, a stray OP_ENDIF, then an OP_IF around OP_RETURN'],
  ['false-if-verif-endif-return-op1', 'OP_0 OP_IF OP_VERIF OP_ENDIF OP_RETURN OP_1', 'OP_VERIF in an unexecuted branch: every reader counts it as a depth, the node before Chronicle does not'],
]

const hex = a => (a == null ? null : Utils.toHex(a))
const chunks = s => s.chunks.map(c => ({ op: c.op, data: hex(c.data) }))

// go-sdk@2ca481c `script/script_chunk.go:245-332`, transcribed: the depth and
// the OP_RETURN rule (`:247-262`), the pushes (`:263-318`), `ErrDataTooSmall`
// returned with the chunks read so far.
function goDecodeScript (b) {
  const ops = []
  let conditionalBlock = 0
  while (b.length > 0) {
    const op = { op: b[0], data: null }
    switch (op.op) {
      case 0x63: case 0x64: case 0x65: case 0x66: // OpIF, OpNOTIF, OpVERIF, OpVERNOTIF
        conditionalBlock++
        b = b.slice(1)
        break
      case 0x68: // OpENDIF
        conditionalBlock--
        b = b.slice(1)
        break
      case 0x6a: // OpRETURN
        if (conditionalBlock > 0) {
          b = b.slice(1)
        } else {
          op.data = b.slice(1)
          b = []
        }
        break
      case 0x4c: case 0x4d: case 0x4e:
        return { chunks: ops, error: 'pushdata shapes are not recorded here' }
      default:
        if (op.op >= 0x01 && op.op <= 0x4e) {
          const l = op.op
          if (b.length < 1 + l) return { chunks: ops, error: 'ErrDataTooSmall' }
          op.data = b.slice(1, 1 + l)
          b = b.slice(1 + l)
        } else {
          b = b.slice(1)
        }
    }
    ops.push({ op: op.op, data: hex(op.data) })
  }
  return { chunks: ops }
}

function spendVerdict (lockHex, version) {
  try {
    const ok = new Spend({
      sourceTXID: '00'.repeat(32),
      sourceOutputIndex: 0,
      sourceSatoshis: 1000,
      lockingScript: LockingScript.fromHex(lockHex),
      transactionVersion: version,
      otherInputs: [],
      outputs: [],
      inputIndex: 0,
      unlockingScript: UnlockingScript.fromHex('51'),
      inputSequence: 0xffffffff,
      lockTime: 0
    }).validate()
    return { valid: ok }
  } catch (e) {
    // The message alone: the reference appends its TXID, PC and stack dump.
    return { error: String(e.message ?? e).split('\n')[0] }
  }
}

const shapes = SHAPES.map(([id, asm, note]) => {
  const written = Script.fromASM(asm).toHex()
  const read = Script.fromHex(written)
  return {
    id,
    note,
    asm_in: asm,
    hex: written,
    ts: { chunks: chunks(read), asm: read.toASM(), to_hex: read.toHex() },
    ts_spend: { v1: spendVerdict(written, 1), v2: spendVerdict(written, 2) },
    go_transcribed: goDecodeScript(Array.from(Utils.toArray(written, 'hex')))
  }
})

process.stdout.write(JSON.stringify({
  source: 'tests/support/script_if_depth_634.mjs',
  runtime: `node ${process.version}`,
  reference: 'bsv-blockchain/ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9 packages/sdk (bun bundle), Node v22.18.0',
  go: 'bsv-blockchain/go-sdk@2ca481c5931b987a0c8f48bb341c70b7477b6b07 script/script_chunk.go:245-332, transcribed, not run',
  unlocking_hex: '51',
  shapes
}, null, 2) + '\n')
