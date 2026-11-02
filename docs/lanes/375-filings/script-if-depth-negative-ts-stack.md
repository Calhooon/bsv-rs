PENDING: queue row 26, from bsv-rs#634, narrowed by the keeper's word of 2026-11-02 22:1xZ to the one reading the reference itself would call wrong. Unfiled; the keeper files it the day the draft is read.

# Script.fromBinary folds OP_RETURN inside an open OP_IF as top level after a stray OP_ENDIF

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on a stray `OP_ENDIF` before `OP_RETURN` (#634).

`Script`'s chunk parser counts an IF depth so that only an `OP_RETURN` outside every conditional takes the rest of the script as its data. An `OP_RETURN` inside an `OP_IF` is read as an opcode, and the chunks after it are read too. The depth goes below zero on a stray `OP_ENDIF` (one with no `OP_IF` open), and the top-level test is equality with zero:

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

A stray `OP_ENDIF` followed by an `OP_IF` brings the count back to 0, although an `OP_IF` is open. An `OP_RETURN` inside that `OP_IF` is then folded as if it were top level. This goes against the parser's own rule.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0):

1. `Script.fromHex('51636a5168')` (`OP_1 OP_IF OP_RETURN OP_1 OP_ENDIF`, the `OP_RETURN` inside an open `OP_IF`) has five chunks, the `OP_RETURN` an opcode. This is the parser's rule, as expected.
2. `Script.fromHex('68636a5168')` (`OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF`, the same `OP_IF` around the `OP_RETURN` after a stray `OP_ENDIF`) has three chunks, `[{op: 0x68}, {op: 0x63}, {op: 0x6a, data: [0x51, 0x68]}]`. The depth is -1 + 1 = 0 at the `OP_RETURN`, so the `OP_IF`'s contents and its `OP_ENDIF` become data.
3. `Script.fromHex('5163686851636a5168')` (a balanced `OP_IF OP_ENDIF`, a stray `OP_ENDIF`, then `OP_1 OP_IF OP_RETURN OP_1 OP_ENDIF`) folds the same way: seven chunks, the `OP_RETURN` carrying `[0x51, 0x68]`.
4. `toASM` of step 2 is `OP_ENDIF OP_IF 5168`, and `Script.fromASM` of that text is `6863025168`, a different script.

Expected: an `OP_RETURN` inside an open `OP_IF` is read as an opcode whatever came before it. `68636a5168` is five chunks, `OP_ENDIF OP_IF OP_RETURN OP_1 OP_ENDIF`, as `51636a5168` is.

Actual: at edf6e03 the depth after a stray `OP_ENDIF` is negative (`Script.ts:616`), and an `OP_IF` returns it to the `=== 0` the fold tests (`:608`). Steps 2 and 3 read as above.

The stray `OP_ENDIF` before an `OP_RETURN` with nothing open (`686a51`, three chunks) is not in question. That reading is the reference's, and bsv-rs now follows it (#634). Only a fold inside an open `OP_IF` is asked here. A floor at 0 would fix step 2 but change `686a51`, and the SDKs read that as the reference does. A fix that keeps both could count the open `OP_IF`s alone (a stray `OP_ENDIF` closing nothing), or keep the count and fold only when no conditional opened after the last stray `OP_ENDIF` is still open.

The node is not affected. bitcoin-sv reads one opcode at a time and keeps no depth (`CScript::GetOp2`). It refuses an `OP_ENDIF` with nothing open at run time (`SCRIPT_ERR_UNBALANCED_CONDITIONAL`), and the reference's `Spend` refuses these scripts too (`OP_ENDIF requires a preceeding OP_IF.`). The difference is in what `fromBinary`, `fromHex`, `chunks` and `toASM` present for such a script, and in what reads the chunks (PushDrop field decoding, a scriptCode cleaned chunk by chunk).

A related observation, not asked here: `toASM` writes a folded `OP_RETURN` as its data's hex alone (`#_chunkToString`, `Script.ts:668-677`), and `fromASM` reads that hex back as a push (`:108-117`). The ASM round trip therefore fails on every folded `OP_RETURN` carrying data, not only after a stray `OP_ENDIF`: `6a0568656c6c6f` reads back as `060568656c6c6f`, and `006a0568656c6c6f` as `00060568656c6c6f`. In the fifteen recorded shapes it fails on six. bsv-rs writes such a chunk as `OP_RETURN` and the rest's ASM (`OP_RETURN 0x<hex>` when that would not read back).

go-sdk at 2ca481c reads `68636a5168` as the reference does (`DecodeScript`, three chunks). Its interpreter's parser floors the depth at 0 and reads five. bsv-rs follows the reference on all fifteen shapes, step 2 included, and states this row.

Witness:

- `tests/script_if_depth_634.rs` in bsv-rs (`the_chunks_are_the_references_and_part_from_go_sdk_after_a_stray_endif_634`, `the_asm_round_trips_on_every_shape_both_readings_of_op_return_included_634`, `the_verdict_does_not_depend_on_the_chunking_634`; the keeper links them at the landing commit)
- `tests/vectors/script_if_depth_634.json` (fifteen shapes: the reference's chunks, `toASM` and `Spend` verdicts at versions 1 and 2), recorded from the reference by `tests/support/script_if_depth_634.mjs`

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:599-631](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L599-L631) (`#parseChunks`; the top-level test at `:608`, the decrement at `:616`), reached from `fromBinary` (`:157-160`) through `#ensureParsed` (`:206-215`)
- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:668-677](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L668-L677) (`#_chunkToString`) and [:73-117](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L73-L117) (`fromASM`, `#parseASMToken`)
- [bitcoin-sv@6504a3a src/script/script.h:165-198](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/script.h#L165-L198) (`GetOp2`, no depth) and [src/script/interpreter.cpp:835-840](https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/script/interpreter.cpp#L835-L840) (`OP_ENDIF` with nothing open refused)

BRC reading: no BRC defines a chunk list. The node's interpreter is the authority on the opcodes and refuses these scripts. The ask is that the parser's fold follow its own top-level rule.

Requested maintainer action: in `#parseChunks`, read an `OP_RETURN` inside an open `OP_IF` as an opcode even after a stray `OP_ENDIF`, so `68636a5168` is five chunks, and keep `686a51` at three. Add both as regressions. If the fold in step 2 is intended, please say so in the code, so that other SDKs can follow it.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder, and its outputs are the recorded vector. The `fromASM` round trips of step 4 and the observation were run from the same bundle while drafting. The linked Rust tests are the reproducible witness. This draft contains no private-key literal.
