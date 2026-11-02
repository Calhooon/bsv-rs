PENDING: queue row 28, from bsv-rs#634's fold (the keeper's word of 2026-11-02 22:1xZ); in go-sdk's turn after rows 26 and 27, pending the keeper's read and the owner's cadence. Unfiled.

# DecodeScript reads a negative IF depth as the top level, so OP_RETURN after a stray OP_ENDIF swallows the rest of the script

Repository: bsv-blockchain/go-sdk

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on a stray `OP_ENDIF` before `OP_RETURN` (#634).

`DecodeScript` (behind `Script.Chunks()`) counts an IF depth so that an `OP_RETURN` outside every conditional takes the rest of the script as its data. Its comment says it matches ts-stack's `Script.#parseChunks`. It does not on a stray `OP_ENDIF` (one with no `OP_IF` open): the depth goes below zero, and the `OP_RETURN` branch reads the opcode alone only at `> 0`:

```go
case OpENDIF:
	conditionalBlock--
	b = b[1:]
case OpRETURN:
	if slices.Contains(options, DecodeOptionsParseOpReturn) || conditionalBlock > 0 {
		b = b[1:]
	} else {
		op.Data = b[1:]
		b = nil
	}
```

So at depth -1 the `OP_RETURN` takes the rest as data. The reference folds only at `=== 0` and reads the rest as chunks there. go-sdk's own interpreter parser does a third thing: it floors the depth at 0 (`updateConditionalDepth`). That gives the same chunks as `DecodeScript` on `686a51`, but not after a stray `OP_ENDIF` followed by an `OP_IF`.

Steps to reproduce (go-sdk at 2ca481c, `script.NewFromHex(h).Chunks()`):

1. `686a51` (`OP_ENDIF OP_RETURN OP_1`): `DecodeScript` gives two chunks, `[{Op: 0x68}, {Op: 0x6a, Data: [0x51]}]`. ts-stack at edf6e03 gives three, `OP_ENDIF OP_RETURN OP_1`, its depth -1 at the `OP_RETURN` (`Script.ts:608`, `:616`).
2. The same split on five more shapes with the `OP_RETURN` at a negative depth: `686a0568656c6c6f` (2 against 3 chunks), `68686a51` (3 against 4), `6368686a0568656c6c6f` (4 against 5), `516368686a51` (5 against 6), `516351636868686a51` (8 against 9).
3. `68636a5168` (`OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF`): the depth is -1 + 1 = 0 at the `OP_RETURN`, and `DecodeScript` and the reference agree (three chunks). The interpreter's floored parser reads depth 1 there and does not fold.

Across fifteen recorded shapes, `DecodeScript` gives the reference's chunks on nine and differs on the six of steps 1 and 2.

The node is not affected. bitcoin-sv reads one opcode at a time and keeps no depth (`CScript::GetOp2`). It refuses an `OP_ENDIF` with nothing open (`SCRIPT_ERR_UNBALANCED_CONDITIONAL`) before it reaches any of these `OP_RETURN`s, so no verdict depends on the chunks. The difference shows up in what reads the chunks: the chunk list, data-carrier and template classification, PushDrop field decoding, and a scriptCode cleaned chunk by chunk.

Expected: as in the reference, an `OP_RETURN` takes the rest of the script as data only at depth 0. `686a51` is three chunks, and so are the other five shapes of step 2 by the reference's counts. `DecodeScript` and the interpreter's parser read one chunk list.

Actual: at 2ca481c `DecodeScript` folds at any depth that is not `> 0` (`script_chunk.go:255-260`). The interpreter's parser floors the depth at 0 (`opcodeparser.go:389-401`). go-sdk's `ToASM` (`ReadOp`) and its engine's node-exact parser keep no depth and fold nothing. That is four readers with three readings.

bsv-rs followed the floor until #634 and now reads as the reference does (`Script::parse_chunks`, ported from `Script.ts:599-631`): three chunks on `686a51` and the reference's chunks on all fifteen shapes. It parts from `DecodeScript` on the six above.

Witness:

- `tests/script_if_depth_634.rs` in bsv-rs (`the_chunks_are_the_references_and_part_from_go_sdk_after_a_stray_endif_634`, `a_stray_endif_before_op_return_parses_as_three_chunks_the_if_depth_negative_634`, `the_verdict_does_not_depend_on_the_chunking_634`; the keeper links them at the landing commit)
- `tests/vectors/script_if_depth_634.json` (fifteen shapes: the reference's chunks and verdicts recorded under Node 22.18.0, `DecodeScript`'s chunks transcribed in `tests/support/script_if_depth_634.mjs`)

Pinned reference reading:

- [go-sdk@2ca481c59 script/script_chunk.go:245-332](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/script/script_chunk.go#L245-L332) (`DecodeScript`: the decrement at `:255-257`, `> 0` at `:258-260`)
- [go-sdk@2ca481c59 script/interpreter/opcodeparser.go:389-401](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c5931b987a0c8f48bb341c70b7477b6b07/script/interpreter/opcodeparser.go#L389-L401) (`updateConditionalDepth`, floored at 0)
- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:599-631](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L599-L631) (`#parseChunks`: `=== 0` at `:608`, the decrement at `:616`)
- [bitcoin-sv@6504a3a src/script/script.h:165-198](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/script.h#L165-L198) (`GetOp2`, no depth) and [src/script/interpreter.cpp:835-840](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L835-L840) (`OP_ENDIF` with nothing open refused)

BRC reading: no BRC defines a chunk list. The node's interpreter is the authority on the opcodes and refuses these scripts. The ask is that go-sdk's readers read the TypeScript reference's single chunk list, as `DecodeScript`'s own comment says it does.

Requested maintainer action: in `DecodeScript`, fold only at `conditionalBlock == 0` (read the `OP_RETURN` as an opcode at any other depth, negative included), as `#parseChunks` does. Add `686a51` (three chunks) and `68686a51` (four) as regressions. If the interpreter parser's floor is meant to stay, please say which reading `Chunks()` promises.

Evidence status: `DecodeScript` was transcribed in the linked recorder. The cold read of bsv-rs#652 ran it once in a scratch copy of 2ca481c (go1.27.0) on the fifteen shapes, and its chunks matched the transcription on every one; it was not run again for this draft (no Go toolchain on the drafting host). The reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0). The linked Rust tests are the reproducible witness. This draft contains no private-key literal.
