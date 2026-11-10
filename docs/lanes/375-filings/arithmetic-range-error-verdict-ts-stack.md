keeper's word first

# Spend lets a RangeError escape validate() and Transaction.verify() on an arithmetic result past V8's string limit, instead of returning a verdict

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "`Transaction::verify` takes the caller's memory budget as the reference's third parameter" (#331, #374; "a result past the figure ... throws `RangeError: Invalid string length` uncaught out of the reference's `verify`, neither of its classes"; "Theirs: ts-stack, filing pending"). Supersedes the short batch-1 draft `arithmetic-range-error-verdict.md`. Drafted by the filings-older-1110 lane on 2026-11-10.

A service that runs `Transaction.verify` (or `Spend.validate`) on transactions it did not write, such as an overlay topic manager at its submit door, gets an uncaught `RangeError` instead of `false` or a script error when a script's arithmetic result passes 536,870,888 bits: `OP_1 <536870888> OP_LSHIFTNUM` throws in about 6 ms. The caller cannot tell it from an engine fault, and code that catches only the SDK's two error classes lets it through.

```ts
const value = this.#readScriptNumber(this.#popStack()).toBigInt()
...
const resultBytes = new BigNumber(value << bits).toScriptNum()
```

`new BigNumber` sets its magnitude through `#_setValueFromSigned` and `#_finishInitialization`, which takes `toString(2)` of every magnitude (`BigNumber.ts:450`, `:771-781`); past V8's longest string (`0x1fffffe8` characters) that throws `RangeError: Invalid string length`. An operand read is wrapped (`#readScriptNumber`, `Spend.ts:525-535`, rethrows it as a script error, a verdict), but a result is not: `OP_ADD`, `OP_SUB`, `OP_1ADD`, `OP_1SUB` (`add`/`sub` through `#_setValueFromSigned`, `BigNumber.ts:912-924`) and `OP_LSHIFTNUM` (`Spend.ts:1066`) throw out of `validate`. A shift past 2^30 bits throws `RangeError: Maximum BigInt size exceeded` at `value << bits`, the same way.

Steps to reproduce (ts-stack at edf6e03 under Node 22.18.0, `Spend` with no flags, version 2):

1. Locking script `5104e8ffff1fb6` (`OP_1`, the push of 536,870,888, `OP_LSHIFTNUM`), any push-only unlocking script.
2. `validate()` throws `RangeError: Invalid string length` (about 6 ms; the result has 536,870,889 bits).
3. `1` shifted by 2^30 throws `RangeError: Maximum BigInt size exceeded`; an at-limit operand (67,108,861 bytes of `ff` and a `00` sign byte) under `OP_1ADD` or `OP_DUP OP_ADD` throws `Invalid string length` in 3.5 to 4.5 s.

Expected: the step fails as a script evaluation error (a verdict, as the operand read already does), or a resource limit the caller can tell apart, never a raw engine exception out of `verify`.

Actual: an uncaught `RangeError`.

bsv-rs answers each case as a verdict in the reference's words (`Invalid string length`, `Maximum BigInt size exceeded`) at the push (#331, #374, the keeper's word of 2026-10-27 21:5xZ). The node never holds such a number (its script number length after Chronicle is 32,000,000 bytes, `SCRIPT_ERR_SCRIPTNUM_OVERFLOW`), so no consensus verdict is at stake; the ask is the error's class.

Witness:

- [tests/script_reference_read_limit_331.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/script_reference_read_limit_331.rs) (`a_left_shift_past_536_870_888_bits_is_invalid_before_it_allocates`, `a_left_shift_past_2_pow_30_bits_is_invalid_with_the_bigint_words`, `an_increment_past_536_870_888_bits_is_invalid_at_its_push`, `a_sum_or_difference_past_536_870_888_bits_is_invalid_at_its_push`)
- The reference's run is recorded in bsv-rs's CHANGELOG (the #331/#374 entry, "the re-review ran it": the at-limit `OP_DUP OP_ADD` in 4.5 s, its `OP_1ADD` in 3.5 s, `1 <536,870,888> OP_LSHIFTNUM` in 6 ms, each uncaught)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:1052-1070](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L1052-L1070) (the shift) and [:525-536](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L525-L536) (the read's rethrow, the result has none)
- [ts-stack@edf6e03da packages/sdk/src/primitives/BigNumber.ts:771-781](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/BigNumber.ts#L771-L781) (`#_setValueFromSigned`) and [:450](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/primitives/BigNumber.ts#L450) (`toString(2)`)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:1685-1700](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L1685-L1700) (`verify`, the caller's door)

Existing related filing(s): ts-stack #1525 (E-Jacko's, open) proposes an optional executed-operation budget for `Spend`; it is a local CPU bound, not this error's class. No issue found for the RangeError (`--search "RangeError verify"`, `"Invalid string length"`, `"BigInt size"`, 2026-11-10). Keep these numbers; confirm their scope before opening a duplicate.

Requested maintainer action: catch the engine's `RangeError` at an arithmetic result's construction (as `#readScriptNumber` does at the read) and report it as a script evaluation error, or as the existing resource-limit class, rather than letting it escape `verify`.

Evidence status: the reference was run under Node 22.18.0 at edf6e03 by the #331/#374 review (recorded in the CHANGELOG, not re-run here); the lines read at the pin. This draft contains no private-key literal.
