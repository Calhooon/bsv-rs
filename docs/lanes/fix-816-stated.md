# Lane fix-816-stated: the default mode's push-only rule, stated

Started from `origin/beta` at `c96f3c7e`. No behaviour change: the rule is
stated as this crate's own, both sides are pinned, and the choice is laid out
for the owner (bucket #816, BLOCKS-CUT in `bucket-script.md` of 2026-11-09).

## The finding

Without a flag word, `Spend` requires a push-only unlocking script at every
transaction version (`src/script/spend/mod.rs`, `REQUIRE_PUSH_ONLY_UNLOCKING`;
the check at the head of `Spend::validate`). The reference and the node:

- `ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts:319-321`:
  `#isRelaxed(): boolean { return this.isRelaxedOverride || this.transactionVersion > 1 }`;
  `:365-369`: `#shouldEnforceSigPushOnly()` is
  `this.#hasFlag('SIGPUSHONLY') && this.#enforceNonMalleability()` under
  explicit flags and `!this.#isRelaxed()` without; `:2059-2063`: the check,
  `'Unlocking scripts can only contain push operations, and no other opcodes.'`
- bitcoin-sv v1.2.2 `src/script/interpreter.cpp:2321-2334`: under
  `SIGPUSHONLY`, push-only when `(IsGenesis(flags) && !IsChronicle(flags)) ||
  (IsChronicle(flags) && !IsMalleableTxnVersion(checker.Version()))`, else
  `SCRIPT_ERR_SIG_PUSHONLY`. This crate's words follow it
  (`ScriptFlags::requires_push_only`).

So `<sig> OP_DUP OP_DROP` (or `OP_1 OP_DROP <sig>`) at version 2 is refused
here in the default mode by `Spend`, by `Transaction::verify` and by the
streaming reader, and run by the reference's default and by the node under
Chronicle. At version 1 all three refuse it, in the same words.

## The witness

`tests/script_push_only_default_816.rs` (7 tests, every name ending `_816`)
against `tests/vectors/script_push_only_default_816.json` (24 cases:
`default`, `SIGPUSHONLY`, `SIGPUSHONLY,CHRONICLE` and `CHRONICLE` explicit
flags, by versions 1 and 2, by three unlocking scripts over `OP_DROP OP_1`),
recorded by `tests/support/script_push_only_default_816.mjs` (the #397
recorder's bundle: `git archive edf6e03 packages/sdk`, `bun build`, Node
v22.18.0; two runs byte-identical). Green on the tree. RED, watched: a scratch
copy with the default's check skipped at version above 1
(`&& !(self.flags.is_none() && self.transaction_version > 1)`), its own target
directory, 3 of 7 failed:

```
the_default_mode_refuses_a_non_push_only_unlocking_script_at_every_version_816:
  assertion `left == right` failed: v2 op1-drop-then-push
  left: Ok(true)
 right: Err("Unlocking scripts can only contain push operations, and no other opcodes.")
transaction_verify_refuses_the_divergent_cells_816:
  assertion `left == right` failed: op1-drop-then-push
  left: Ok(true)
 right: Err(TransactionError("Script validation failed for input 0: Unlocking scripts can only contain push operations, and no other opcodes."))
the_stream_refuses_the_divergent_cells_816:
  op1-drop-then-push: Valid { subject: None, roots: [(800000, [...])] }
```

## The options for the owner

**A correction from the reads of PR #822 (2026-11-10), the options below left as they were put to the owner:** both options name the
overlay engine's submit door as a caller of the default mode through `Transaction::verify`. It is not one: the door builds a `Spend`
per input behind its own static push-only refusal at every version
(`~/bsv/bsv-overlay-cloudflare/crates/overlay-engine/src/script_door.rs:557,649,857`, read at `9a0f3c29`), so neither option moves
its verdicts, and above version 1 the door is now stricter than the default mode. The other callers named stand.

(a) **Keep the rule.** A consumer gains a default mode in which no unlocking
script that is not push-only ever runs, at any version: no executable code in
a scriptSig reaches the interpreter without the caller's explicit
`set_require_push_only(false)`. The cost: the default mode is stricter than
both the reference's default and the network after Chronicle at version 2, so
the overlay engine's submit door (`Transaction::verify`, default mode) and
every stream reader without chain parameters refuse a version-2 transaction
the network accepts after Chronicle and the reference's `Transaction.verify`
accepts. The row stays in the divergence list.

(b) **Relax it at version above 1, as the reference's default does.** What
moves: the verdict of the divergent cells (a version-2 spend whose unlocking
script is not push-only, valid by its scripts) at `Spend` without a word,
`Transaction::verify`, `verify_stream` and the asynchronous and two-pass
readers without chain parameters; nothing at version 1 and nothing under a
word (the words already read as the node). Who is reached: every caller of
the default mode: the overlay engine's submit door, the watchtower and monitor
workers, the toolbox and any downstream that verifies without chain
parameters. The change is one line at the check (or the switch derived from
the version, as `require_minimal` is); the pins of this lane that flip are
exactly those asserted as divergent (`the_default_mode_..._816`'s version-2
cells, `transaction_verify_..._816`, `the_stream_..._816`), and the row
closes.

## Gate

Recorded in the lane's REPORT.
