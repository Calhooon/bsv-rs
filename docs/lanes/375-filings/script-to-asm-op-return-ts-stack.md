keeper's word first

# Script.toASM drops the OP_RETURN opcode of every script that ends in an OP_RETURN, so fromASM reads back a different script

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence rows "A bare `OP_RETURN` (no byte after it)" (#603 shard B) and "A stray `OP_ENDIF` before `OP_RETURN`" (#634, its ASM clause). Drafted by the filings-1109 lane on 2026-11-09. Queue row 26 (the IF-depth fold) is a different ask and leaves this round trip out by the keeper's word of 2026-11-02 22:1xZ; this draft asks it alone.

A user who prints a data output (`OP_FALSE OP_RETURN <data>`, or `OP_RETURN <data>`) with `toASM` gets text without the word `OP_RETURN`, and `Script.fromASM` of that text is a different script: the data becomes a push and the output is no longer a data carrier. A bare `OP_RETURN` prints as the empty string, which `fromASM` reads back as `OP_0`.

The parser folds every byte after a top-level `OP_RETURN` into that chunk's `data` (`Script.ts:608-610`, a bare one as `data: []`), and `#_chunkToString` prints a chunk with `data` as the data's hex alone, never its opcode:

```ts
if (chunk.data === undefined) {
  const val = OP[op] as string
  str = `${str} ${val}`
} else {
  str = `${str} ${toHex(chunk.data)}`
}
```

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0):

1. `Script.fromHex('6a0568656c6c6f').toASM()` is `0568656c6c6f`; `Script.fromASM('0568656c6c6f').toHex()` is `060568656c6c6f`.
2. `Script.fromHex('006a0568656c6c6f').toASM()` is `OP_0 0568656c6c6f`, read back as `00060568656c6c6f`.
3. `Script.fromHex('6a').toASM()` is `''`, read back as `00`; `Script.fromHex('006a').toASM()` is `OP_0 ` (a trailing space), read back as `0000`.
4. `Script.fromHex('68636a5168').toASM()` reads back as `6863025168`.

Expected: the ASM names the opcode and then the rest, as the node's `ScriptToAsmStr` prints `OP_RETURN` by its name (bitcoin-sv v1.2.2 `src/core_write.cpp:100-176`, `GetOpName(opcode)` at `:173` for every non-push opcode, its `GetOp2` reading `OP_RETURN` as one opcode and the bytes after it as further instructions, `src/script/script.h:163-198`), so that `fromASM(toASM(s))` is `s`: for example `OP_RETURN 68656c6c6f` for step 1, and `OP_RETURN` for a bare one (the reference's own `fromASM('OP_RETURN')` is `6a`).

Actual: the opcode is never printed for a folded `OP_RETURN`, so the round trip fails on every script whose top-level `OP_RETURN` is followed by data, and on a bare one.

bsv-rs's `to_asm` writes a folded `OP_RETURN` as `OP_RETURN` and the rest's ASM (or `OP_RETURN 0x<hex>` where the rest would not read back), and round-trips the fifteen recorded shapes and random rests. go-sdk at 2ca481c gives a bare `OP_RETURN` an empty `Data` too (`script/script_chunk.go:258-270`); its `ToASM` was not compared for this draft.

Witness:

- [tests/script_if_depth_634.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/script_if_depth_634.rs) (`the_asm_round_trips_on_every_shape_both_readings_of_op_return_included_634`, `the_asm_round_trips_on_random_rests_after_op_return_634`)
- [tests/vectors/script_if_depth_634.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/script_if_depth_634.json) (recorded from the reference under Node v22.18.0: shape `6a0568656c6c6f`, `ts.asm` `0568656c6c6f`; shape `68636a5168`)
- [tests/script_script_603_b.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/script_script_603_b.rs) (`a_bare_op_return_is_an_opcode_without_data_bytes_00107`)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:668-677](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L668-L677) (`#_chunkToString`), [:222-229](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L222-L229) (`toASM`), [:608-610](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L608-L610) (the fold)

Existing related filing(s): ts-stack #1479 (`fromASM('')` read as one empty push; the keeper's, 2026-11-04): the reading side of step 3's empty text, not the printing asked here. Queue row 26 (unfiled): the fold of an `OP_RETURN` inside an open `OP_IF` after a stray `OP_ENDIF`, a parser question. Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: print an `OP_RETURN` chunk as `OP_RETURN` followed by the ASM (or the hex) of its data, so `fromASM(toASM(s))` returns `s` for every script, and add steps 1 to 3 as regressions.

Evidence status: the reference was run by the #634 and #603 shard B recorders (Node 22.18.0) and its outputs are the recorded vectors; the node's printer is source-read at v1.2.2. This draft contains no private-key literal.
