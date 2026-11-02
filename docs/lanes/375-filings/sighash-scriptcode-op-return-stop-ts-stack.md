# Spend's CHECKSIG scriptCode drops every byte after a top-level OP_RETURN, so an unlocking-script check signs a different digest than the node

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on the scriptCode's `OP_RETURN` stop (#654).

`Spend` builds the scriptCode of `OP_CHECKSIG` and `OP_CHECKMULTISIG` from the executing script's chunks after the last `OP_CODESEPARATOR`, appends the locking script's chunks when the check runs inside the unlocking script, and writes the result with `new Script(chunks)`:

```ts
let scriptCodeChunks = scriptForChecksig.chunks.slice(
  this.lastCodeSeparator === null ? 0 : this.lastCodeSeparator + 1
)
if (this.context === 'UnlockingScript') {
  scriptCodeChunks = scriptCodeChunks.concat(this.lockingScript.chunks)
}
subscript = new Script(scriptCodeChunks)
```

The parser folds every byte after a top-level `OP_RETURN` into that one chunk's `data` (a bare `OP_RETURN` gets `data: []`, `Script.ts:608-610`), and the serializer stops after an `OP_RETURN` chunk that has `data`:

```ts
if (chunk.op === OP.OP_RETURN) {
  bytes.set(chunk.data, offset)
  break
}
```

So whenever the unlocking script carries a top-level `OP_RETURN` after the check, the locking script appended behind it is never written, and the digest is taken over the unlocking script's tail alone. bitcoin-sv v1.2.3 builds the scriptCode from the bytes: `CScript scriptCode {pbegincodehash, pend}`, then `scriptCode += *checksigData` (the locking script) under Chronicle, then `CleanupScriptCode`, whose `FindAndDelete` walks `GetOp` instructions straight through an `OP_RETURN`. The two scriptCodes differ, so a spend the node accepts is refused by `Spend`, and a spend `Spend` accepts is refused by the node.

The same fold also hides a non-FORKID signature's push placed after an `OP_RETURN` from `findAndDelete` (the folded chunk never equals the push), where the node's walk deletes it.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0; `Spend` with no flags, one input spending the synthetic outpoint `5a…5a:0` of 10,000 satoshis, one output of 9,000 satoshis to `51`, lock time 0, sequence `ffffffff`, version 2; the signatures RFC 6979 by the recorder's fixed test key):

1. Locking script `6951` (`OP_VERIFY OP_1`). Unlocking script `<sig> <P> OP_CODESEPARATOR OP_CHECKSIG OP_RETURN 01 00` with `sig` an `ALL|FORKID` signature over the node's scriptCode `ac6a01006951`:
   `483045022100ea4ef806566a0b5a7adfee5adc2a4fea99ea5c95e6ba4145c59615b3aac6a57e022032ceba7244a07c92c652c83f652966ca6ac501456eccb44aaaf4a133bc6a712a4121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaabac6a0100`.
   `validate()` throws `OP_VERIFY requires the top stack value to be truthy.`; the node accepts it (BIP143 digest `6fd93a20…92f18370`).
2. The same shape signed over `ac6a0100` (the scriptCode `Spend` builds):
   `4730440220208870a4c1c96b935b2f5557c3d921c771fc8ca29400fe1bc65723ea5eaee60a02202f6356aa54ddfb0e07a647501933db9d21482ab7182998e8b2c8a67cdea5a6314121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaabac6a0100`.
   `validate()` returns `true`; the node refuses it (`SCRIPT_ERR_VERIFY`).
3. A bare `OP_RETURN` ending the unlocking script, signed over `ac6a6951`:
   `47304402203c0bc136d68b7a186c7dc50d9e351012212d400c998e08e0923d5d183378ee940220307fea513042fbdd31c76f99d0cff4fe2620de885c9f33a153caa10c6b1ee1a34121034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaabac6a`.
   `validate()` throws `OP_VERIFY requires the top stack value to be truthy.` (the empty `data` stops the serializer too); the node accepts it.
4. A non-FORKID (`0x01`) signature in the locking script behind its own `OP_RETURN`: locking script `21 <P> OP_CHECKSIG OP_RETURN <sig>`, unlocking script `<sig>`, the signature over `<P> OP_CHECKSIG OP_RETURN` (its push deleted, as `findAndDelete` is meant to do for a non-FORKID signature):
   locking `21034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aaac6a473044022057e07861658f697b7fefbaf17e3f85a0bfb0e123964ad37a178c12789ef3c047022052191cc2b70414da3d0b8540ed5c8d01d0e128f757c0c8c8c81b5f9c7a2c7eb401`.
   `validate()` throws `The top stack element must be truthy after script evaluation.`: the push stays in the scriptCode.

Expected: the scriptCode is the executing script's bytes from the last executed `OP_CODESEPARATOR` to its end, the locking script's bytes appended inside the unlocking script, and a non-FORKID signature's push deleted by a walk of the bytes, as the node builds it. Steps 1 and 3 are valid, step 2 is invalid; step 4 verifies its signature.

Actual: the scriptCode stops at the `OP_RETURN`, so steps 1 and 3 are refused and step 2 accepted; step 4's push is kept.

bsv-rs builds the scriptCode from the bytes since #654 (`src/script/spend/script_code.rs`), with `FindAndDelete` ported from the node, and its verdicts on all twenty cases of the linked vector, under the node's block and standard words, equal those of the node's rules as the Lean specification evaluates them (`bsv-script-lean@387dab35`, `eval/bsvs`). go-sdk was not run for this draft.

Witness:

- [tests/sighash_scriptcode_654.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/sighash_scriptcode_654.rs) (`an_unlocking_checksig_signs_the_locking_script_past_a_top_level_op_return_654`, `a_bare_op_return_ending_the_unlocking_script_keeps_the_locking_script_654`, `the_vector_holds_the_cases_this_crate_writes_and_their_verdicts_654`)
- [tests/vectors/sighash_scriptcode_654.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/sighash_scriptcode_654.json) (each case's scripts, its three scriptCodes and their digests, this SDK's default verdict as `ts_default`, the specification's verdict under each word), recorded by [tests/support/sighash_scriptcode_654.mjs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/support/sighash_scriptcode_654.mjs)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:1676-1702](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L1676-L1702) (the CHECKSIG scriptCode; the CHECKMULTISIG site builds it the same way)
- [ts-stack@edf6e03da packages/sdk/src/script/Script.ts:450-484](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L450-L484) (the serializer's stop) and [:608-610](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Script.ts#L608-L610) (the fold)
- bitcoin-sv v1.2.3 (`6504a3af`) `src/script/interpreter.cpp:1470-1484`, `:1566-1579` (the scriptCode), `:255-263` (`CleanupScriptCode`), `src/script/script.h:201-224` (`FindAndDelete`)

Requested maintainer action: build the scriptCode from the script's bytes rather than through `toBinary` (or serialize the chunks with no `OP_RETURN` stop for this purpose), delete a non-FORKID signature's push by a walk of the bytes, and add the four cases above as regressions. If the stop is a deliberate choice for the default mode, please say so in the code, since the node signs the other bytes.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder, and its outputs are the recorded vector; the node's verdicts are the Lean specification's evaluator at its pin (its self-test green), not a running node. This draft contains no private-key literal.
