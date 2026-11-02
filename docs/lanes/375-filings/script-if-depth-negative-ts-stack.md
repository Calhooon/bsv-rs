PENDING: queue row 26, from bsv-rs#634; not in the keeper's order until the three reads on the door land and the keeper reads it. Unfiled.

# Script.fromBinary lets the IF depth go negative on a stray OP_ENDIF, so OP_RETURN after it does not end the data

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on a stray `OP_ENDIF` before `OP_RETURN` (#634).

`Script`'s chunk parser counts an IF depth so that an `OP_RETURN` outside every conditional ends the parse, the rest of the script becoming that chunk's data. A stray `OP_ENDIF` (one with no open `OP_IF`) decrements the depth below zero, and the top-level test is equality with zero:

```ts
if (op === OP.OP_RETURN && inConditionalBlock === 0) {
  chunks.push({ op, data: Script.#copyRange(bytes, pos, length) })
  break
}

if (op === OP.OP_IF || op === OP.OP_NOTIF || op === OP.OP_VERIF || op === OP.OP_VERNOTIF) {
  inConditionalBlock++
} else if (op === OP.OP_ENDIF) {
  inConditionalBlock--
}
```

After a stray `OP_ENDIF` the depth is -1, so a following `OP_RETURN` is read as an opcode and the bytes after it are parsed as further chunks. An `OP_RETURN` reached after an `OP_ENDIF` with nothing open is outside every conditional, and the SDKs disagree on its chunk list.

The node is not affected: bitcoin-sv reads one opcode at a time with no depth (`CScript::GetOp2`) and refuses an `OP_ENDIF` with no open conditional at run time (`SCRIPT_ERR_UNBALANCED_CONDITIONAL`), before any `OP_RETURN` after it. The reference's `Spend` refuses these scripts too (`OP_ENDIF requires a preceeding OP_IF.`). The difference is in what `Script.fromBinary`, `fromHex`, `chunks` and `toASM` present for such a script: tooling that classifies scripts by their chunks (data carriers, templates) or prints them reads a different script from the one other SDKs read.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0):

1. `Script.fromHex('686a51')` (`OP_ENDIF OP_RETURN OP_1`) has three chunks, `[{op: 0x68}, {op: 0x6a}, {op: 0x51}]`, and `toASM()` is `OP_ENDIF OP_RETURN OP_1`.
2. `Script.fromHex('6a6851')` (`OP_RETURN OP_ENDIF OP_1`, the `OP_RETURN` at depth 0) has one chunk, `{op: 0x6a, data: [0x68, 0x51]}`, as expected.
3. `Script.fromHex('5163686a51')` (`OP_1 OP_IF OP_ENDIF OP_RETURN OP_1`, balanced) has four chunks, the `OP_RETURN` carrying `[0x51]`, as expected.
4. `Script.fromHex('68686a51')` (two stray `OP_ENDIF`s) has four chunks; `Script.fromHex('68636a5168')` (`OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF`) has three, the `OP_RETURN` carrying `[0x51, 0x68]`, because the depth is -1 + 1 = 0 there although an `OP_IF` is open.

Expected: an `OP_RETURN` after a stray `OP_ENDIF`, with no conditional open, ends the parse as one at depth 0 does: `686a51` is two chunks, `[{op: 0x68}, {op: 0x6a, data: [0x51]}]`; and an `OP_RETURN` inside an `OP_IF` opened after a stray `OP_ENDIF` is read as an opcode: `68636a5168` is five chunks.

Actual: at edf6e03 the depth goes negative (`Script.ts:616`) and only `=== 0` ends the parse (`:608`), so steps 1 and 4 read otherwise.

bsv-rs floors the depth at 0 (`Script::parse_chunks`): `686a51` is two chunks and `68636a5168` five. go-sdk at 2ca481c has four readers: `Script.Chunks()` (`DecodeScript`) lets the depth go negative too but reads `OP_RETURN` as an opcode only at `> 0`, so `686a51` is two chunks there and `68636a5168` three; its interpreter's legacy parser floors the depth at 0, as bsv-rs does; its `ToASM` reader and its engine's parser count no depth and fold nothing, as the node reads. Across the fifteen recorded shapes the verdict of every SDK's interpreter is the same whichever chunking it is given, so no spend changes; only the chunk list and the ASM differ.

Witness:

- `tests/script_if_depth_634.rs` in bsv-rs (`a_stray_endif_before_op_return_parses_as_two_chunks_the_if_depth_clamped_at_0_634`, `the_readers_differ_only_after_a_stray_endif_634`, `the_verdict_does_not_depend_on_the_chunking_634`; the keeper links them at the landing commit)
- `tests/vectors/script_if_depth_634.json` (fifteen shapes: the reference's chunks, `toASM` and `Spend` verdicts at versions 1 and 2, go-sdk's `Script.Chunks()` transcribed), recorded from the reference by `tests/support/script_if_depth_634.mjs`

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:599-632](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L599-L632) (`#parseChunks`; the top-level test at `:608`, the decrement at `:616`), reached from `fromBinary` (`:157-160`) through `#ensureParsed` (`:206-215`)
- [go-sdk@2ca481c59 script/script_chunk.go:245-332](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/script/script_chunk.go#L245-L332) (`DecodeScript`: the decrement at `:255-257`, `> 0` at `:258-260`) and [script/interpreter/opcodeparser.go:389-401](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/script/interpreter/opcodeparser.go#L389-L401) (`updateConditionalDepth`, floored at 0)
- [bitcoin-sv@6504a3a src/script/script.h:165-198](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/script.h#L165-L198) (`GetOp2`, no depth) and [src/script/interpreter.cpp:835-840](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L835-L840) (`OP_ENDIF` with nothing open refused), `:856-871` (`OP_RETURN` after Genesis)

BRC reading: no BRC defines a chunk list; the node's interpreter is the authority on the opcodes and refuses these scripts. The ask is that the SDKs read one chunk list for them.

Requested maintainer action: floor the depth at 0 in `#parseChunks` (`inConditionalBlock = Math.max(inConditionalBlock - 1, 0)`), so an `OP_RETURN` after a stray `OP_ENDIF` with nothing open ends the data, and add `686a51` (two chunks) and `68636a5168` (five chunks) as regressions. If the negative depth is intended, please say so in the code, so that other SDKs can follow it.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder, and its outputs are the recorded vector; go-sdk's `DecodeScript` was transcribed in the recorder and run once in a scratch copy of 2ca481c (go1.27.0) on the fifteen shapes by the cold read of bsv-rs#652, its chunks the transcription's on every one. The linked Rust tests are the reproducible witness. This draft contains no private-key literal.
