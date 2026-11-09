PENDING: queue row 29, from bsv-rs#418. Unfiled; the keeper files it the day the draft is read.

# Spend's explicit flags read a transaction version at or above 2^31 as malleable, where the node reads it as negative

Repository: bsv-blockchain/ts-stack

Prepared for filing by Calhooon (owner). Draft only; no issue was created. Census pointer: bsv-rs#375; bsv-rs CLAUDE.md's divergence row "TS's explicit `verifyFlags` gates NULLDUMMY, MINIMALDATA, LOW_S, SIGPUSHONLY and CLEANSTACK" (#418).

`Transaction` reads the version with `readUInt32LE` (`Transaction.ts:471`), so the bytes `00000080` are the number 2147483648 and `ffffffff` is 4294967295. `Transaction.verify` passes that number to `Spend` (`transactionVersion: tx.version`, `:1446`). Under explicit flags, `Spend` decides the malleability rules with the same comparison as the node, on that unsigned number:

```ts
#enforceNonMalleability(): boolean {
  return !(this.#hasFlag('CHRONICLE') && this.transactionVersion > 1)
}
```

The node reads the version as `int32_t` (`CTransaction::nVersion`, bitcoin-sv v1.2.2 `src/primitives/transaction.h:273`) and compares it signed:

```cpp
inline constexpr bool IsMalleableTxnVersion(const int32_t version)
{
    // Post-Chronicle, malleability is permitted if txn version > 1
    return (version > 1);
}

inline constexpr bool EnforceNonMalleability(const uint32_t flags, const int32_t txnVersion)
{
    // Enforce strict validation unless Chronicle allows malleability for this txn version
    return !(IsChronicle(flags) && IsMalleableTxnVersion(txnVersion));
}
```

So for a version at or above 2^31 the node enforces MINIMALDATA, LOW_S, NULLDUMMY, SIGPUSHONLY and CLEANSTACK under a Chronicle word (the version is negative, not malleable), and `Spend` with the same flags relaxes them. go-sdk at 2ca481c reads the version as `uint32` and converts it before the comparison (`script/interpreter/thread.go:513-518`, `txVersion = int32(t.tx.Version)`, `t.malleableTxVersion = txVersion > 1`), which is the node's reading.

Steps to reproduce (ts-stack at edf6e03, a bun bundle of `packages/sdk` under Node 22.18.0), each `new Spend({...}).validate()` with `verifyFlags` set to the node's post-Chronicle standard word (`P2SH, STRICTENC, DERSIG, LOW_S, NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, NULLFAIL, SIGHASH_FORKID, GENESIS, UTXO_AFTER_GENESIS, CHRONICLE, UTXO_AFTER_CHRONICLE`):

1. Unlocking `4c0102` (a non-minimal push of `02`), locking `5287`: at `transactionVersion: 1`, `This data is not minimally-encoded.`; at 2147483648 and 4294967295, `true`.
2. Unlocking `5151`, locking `51`: at 1 the clean-stack refusal; at 2147483648 and 4294967295, `true`.
3. Unlocking `51`, locking `0000ae` (a non-empty CHECKMULTISIG dummy): at 1 `OP_CHECKMULTISIG requires the extra stack item (dummy) to be empty.`; at 2147483648 and 4294967295, `true`.
4. A high-S `ALL|FORKID` signature over the version's own digest: at 1 `The signature format is invalid.`; at 2147483648 and 4294967295, `true`.

Expected: under explicit Chronicle flags, a version whose four bytes read as a negative `int32_t` is not malleable, as at the node and in go-sdk, so steps 1 to 4 are refused at 2147483648 and 4294967295 as at 1.

Actual: they are accepted (`transactionVersion > 1` on the unsigned number).

The default mode (no flags) is not in question. Its `#isRelaxed()` (`Spend.ts:319-321`) has no node counterpart; bsv-rs follows it there and now relaxes these versions too (bsv-rs#418). Only the explicit-flags path claims the node's rule, and only there does the reading part from consensus. `OP_VER` and `OP_VERIF` write the four low bytes, the same for either sign, and CSV already reads the version unsigned as the node does (`>>> 0 < 2`, `Spend.ts:925`; `static_cast<uint32_t>`, `interpreter.cpp:2212`).

Witness:

- `tests/script_transaction_version_sign_418.rs` in bsv-rs (`a_version_at_or_above_2_31_is_strict_under_a_word_as_the_node_reads_int32_418`; the keeper links it at the landing commit)
- `tests/vectors/script_transaction_version_sign_418.json` (versions 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF in both modes, six rules each, and the unsigned read), recorded from the reference by `tests/support/script_transaction_version_sign_418.mjs`

Pinned reference reading:

- [ts-stack@edf6e03da packages/sdk/src/script/Spend.ts:319-373](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/script/Spend.ts#L319-L373) (`#isRelaxed`, `#enforceNonMalleability`, the five rules)
- [ts-stack@edf6e03da packages/sdk/src/transaction/Transaction.ts:471](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L471) (`readUInt32LE`) and [:1446](https://github.com/bsv-blockchain/ts-stack/blob/edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9/packages/sdk/src/transaction/Transaction.ts#L1446)
- [bitcoin-sv@879fc8b src/script/interpreter.cpp:34-44](https://github.com/bitcoin-sv/bitcoin-sv/blob/879fc8b/src/script/interpreter.cpp#L34-L44) and [src/primitives/transaction.h:273](https://github.com/bitcoin-sv/bitcoin-sv/blob/879fc8b/src/primitives/transaction.h#L273)
- [go-sdk@2ca481c script/interpreter/thread.go:513-518](https://github.com/bsv-blockchain/go-sdk/blob/2ca481c/script/interpreter/thread.go#L513-L518)

BRC reading: no BRC states the version's sign. The node's interpreter is the authority on the flags' rules, and the explicit-flags path names the node's flags.

Requested maintainer action: under explicit flags, compare the version as the node does, `(this.transactionVersion | 0) > 1` in `#enforceNonMalleability`, and add the four steps above at 2147483648 as regressions. If the unsigned reading under flags is intended, please say so in the code, so that other SDKs can follow it.

Evidence status: the reference was run (a bun bundle of ts-stack@edf6e03 `packages/sdk`, Node 22.18.0) by the linked recorder, and its outputs are the recorded vector. The node and go-sdk sites were read, not run. The linked Rust tests are the reproducible witness. This draft contains no private-key literal.
