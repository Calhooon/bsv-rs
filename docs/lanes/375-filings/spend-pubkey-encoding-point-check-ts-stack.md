keeper's word first

# Spend refuses an off-curve public key at the encoding check, where the node passes it to the signature check and lets `OP_CHECKSIG OP_NOT` succeed

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row on the interpreter's key reading (#660). Drafted by the filings-1109 lane on 2026-11-09.

A script that checks a signature against a key of the right length and prefix that is not a point (`<key> OP_CHECKSIG OP_NOT` with an empty signature, a common "this key did not sign" pattern) is valid at the node and refused by `Spend` with `The public key is in an unknown format.`. Under explicit flags carrying `STRICTENC` the same helper runs, so the reference refuses a spend that the node's block word accepts.

`#checkPublicKeyEncoding` checks the length and the prefix, then also parses the point:

```ts
try {
  PublicKey.fromDER(buf as number[]) // This can throw for stricter DER rules
} catch {
  this.#scriptEvaluationError('The public key is in an unknown format.')
  return false
}
```

The node's `CheckPubKeyEncoding` under `SCRIPT_VERIFY_STRICTENC` calls `IsCompressedOrUncompressedPubKey`, which reads the length and the prefix alone (`02`/`03` and 33 bytes, `04` and 65 bytes). A key that passes it and is not on the curve reaches `CheckSig`, which returns false; with an empty signature `NULLFAIL` does not apply, `OP_CHECKSIG` pushes false, and `OP_NOT` makes the script succeed.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0, `Spend` with no flags, versions 1 and 2):

1. Locking script `21020000000000000000000000000000000000000000000000000000000000000005ac91` (`<02 || x=5> OP_CHECKSIG OP_NOT`), unlocking script `00`.
   `validate()` throws `Script evaluation error: The public key is in an unknown format.`; the node's rules (block and standard words, post-Genesis and post-Chronicle) accept it.
2. Locking script `410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9ac91` (`<04 || G.x || G.y+1> OP_CHECKSIG OP_NOT`), unlocking script `00`. The same throw; the node accepts it.
3. The control: `0279be66...16f81798` (the generator) in the same shape is valid in both.
4. Under explicit flags `STRICTENC` (or `SIGHASH_FORKID`, `Spend.ts:388-392`) the same `#checkPublicKeyEncoding` runs at `OP_CHECKSIG` and `OP_CHECKMULTISIG` (`:1669`, `:1810`); read from the code, not run.

Expected: the encoding check reads the length and the prefix as the node's does, and a key that is not a point fails the signature check, so steps 1 and 2 are valid.

Actual: the encoding check parses the point and throws.

bsv-rs reads the key at the encoding check by length and prefix alone in every mode since #660 (`src/script/spend/key_point.rs`), and its verdicts on the linked vector's 280 cells equal those of the node's rules as the Lean specification evaluates them (`bsv-script-lean@387dab35`). go-sdk was not run for this draft.

Witness:

- [tests/pubkey_encoding_660.rs](https://github.com/Calhooon/bsv-rs/blob/beta/tests/pubkey_encoding_660.rs) (`an_off_curve_or_over_range_key_fails_the_signature_check_not_the_encoding_check_660`, `the_vector_carries_this_crates_cells_and_the_lean_agrees_with_the_node_660`)
- [tests/vectors/pubkey_encoding_660.json](https://github.com/Calhooon/bsv-rs/blob/beta/tests/vectors/pubkey_encoding_660.json) (cells `02||5`, `03||5`, `02||p`, `04||G.x||G.y+1` under shape `checksig-not-empty`: `referenceError` in the default mode, `lean` `valid` under the four node words)

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:687-718](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L687-L718) (the point parse at `:711-716`), [:388-392](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L388-L392) (`#shouldEnforceStrictEncoding`), [:606-607](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L606-L607) (an empty signature passes its encoding check)

Node reading: bitcoin-sv v1.2.2 `src/script/interpreter.cpp:132-152` (`IsCompressedOrUncompressedPubKey`), `:312-318` (`CheckPubKeyEncoding`), the CHECKSIG site at `:1465-1495` (`CheckSig`, then `NULLFAIL` only for a non-empty signature).

Requested maintainer action: drop the `PublicKey.fromDER` parse from `#checkPublicKeyEncoding` (leave the point to the signature check, which already returns false for a key that is not a point), and add steps 1 and 2 as regressions.

Evidence status: the reference's default mode was run by the #660 recorder (Node 22.18.0) and its outputs are the recorded vector; the explicit-flags path is read from the code; the node's verdicts are the Lean specification's evaluator at its pin, not a running node. This draft contains no private-key literal.
