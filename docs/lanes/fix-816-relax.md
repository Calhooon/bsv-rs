# Lane fix-816-relax: the default mode's push-only rule relaxed above version 1

Opened from `origin/lane/fix-816-stated` (PR #822's head, `e19fec98` on beta
`4e57b23f`); the tip matched it at the start, no reset.

## The ruling

The owner, 2026-11-09 23:5xZ, on the question `docs/lanes/fix-816-stated.md`
put (keep the default mode's push-only rule at every version, or relax it
above version 1 as the reference's default does): "yeah relax it". Option (b)
of that record.

## The reference's condition, ported as written

`ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts`:

```
:319-321  #isRelaxed(): boolean { return this.isRelaxedOverride || this.transactionVersion > 1 }
:365-369  #shouldEnforceSigPushOnly(): explicit flags ? SIGPUSHONLY && #enforceNonMalleability() : !this.#isRelaxed()
:2059-2063 if (#shouldEnforceSigPushOnly() && !unlockingScript.isPushOnly()) 'Unlocking scripts can only contain push operations, and no other opcodes.'
```

`transactionVersion` is the number `readUInt32LE` reads, so the comparison is
unsigned. `isRelaxedOverride` (the constructor's `isRelaxed` option) has no
counterpart in `SpendParams`; `set_require_push_only(false)` is the override
here. The node (bitcoin-sv v1.2.2 `interpreter.cpp:2321-2334`) relaxes the
same rule under Chronicle at a malleable version (above 1); this crate's
words already read it (`ScriptFlags::requires_push_only`), unchanged.

PR #812's helper (`relaxed_by_default`, #418) was not on beta when the lane
ran (`git log origin/beta --oneline | grep -c '#418'` was 0), so the lane wrote
the comparison inline with the same reading, `transaction_version as u32 <= 1`.
#812 landed before this PR (`f8200846`); at the captain's rebase the line
became `!relaxed_by_default(transaction_version)`, the conflict's resolution,
the file's 800 lines kept.

## The sites

- `src/script/spend/mod.rs`, `Spend::new`: `require_push_only:
  REQUIRE_PUSH_ONLY_UNLOCKING && !relaxed_by_default(transaction_version)` (was
  the constant alone; the lane's inline `transaction_version as u32 <= 1` until
  the rebase). `Spend::with_transaction` builds through `Spend::new`; the
  check itself (`Spend::validate`, the head) is unchanged.
- `Transaction::verify` and the streaming readers build each spend with
  `Spend`, so they move with it; no line of theirs changed.
- The overlay engine's submit door does not move: it builds a `Spend` per
  input itself and refuses a non-push-only unlocking script at every version
  in its own static checks before any `Spend` runs (`bsv-overlay-cloudflare`
  `crates/overlay-engine/src/script_door.rs:557,649,857`, read at
  `9a0f3c29`), so that door is now stricter than the default mode above
  version 1.
- Under a word: `set_flags` (`word.rs`) re-derives the rule from
  `ScriptFlags::gates`, unchanged.
- Docs: the crate docs of `spend/mod.rs`, the constant's comment,
  `set_require_push_only`'s rustdoc (`word.rs`), `ScriptFlags`' table note
  (`flags.rs`), the root `CLAUDE.md` contract line (the #816 divergence row
  removed; the #654 row's reach updated), `src/script/CLAUDE.md`'s two places.

## RED

Base `e19fec98` with the new `tests/script_push_only_default_816.rs` and its
vector overlaid, `git archive` scratch copy, own target directory: 3 of 7 RED.

```
the_default_mode_judges_push_only_as_the_reference_default_816:
  assertion `left == right` failed: v2 op1-drop-then-push
  left: Err("Unlocking scripts can only contain push operations, and no other opcodes.")
 right: Ok(true)
transaction_verify_judges_push_only_as_the_reference_default_816:
  assertion `left == right` failed: v2 op1-drop-then-push
  left: Err(TransactionError("Script validation failed for input 0: Unlocking scripts can only contain push operations, and no other opcodes."))
 right: Ok(true)
the_stream_judges_push_only_as_the_reference_default_816: (panicked at :315)
```

The tip's `mod.rs` with the version read signed (`transaction_version <= 1`)
in the same scratch copy: 3 of 7 RED, `v2147483648 op1-drop-then-push`.

## The cells added

`version_edges` (9 cases, the default mode at versions 0, 2147483648 and
4294967295 by the three unlocking scripts), recorded at the pin under Node
v22.18.0 by the lane's recorder; two runs byte-identical; the existing 24
cases byte-identical. The reference refuses both non-push-only scripts at 0 and
runs them at 2^31 and 2^32 - 1.

## Other pins moved

- `src/script/spend/flag_tests.rs`, `push_only_is_derived_from_the_word_and_the_version`:
  the default at version 2 now valid, at version 1 refused.
- `tests/vectors/sighash_scriptcode_654.json`: the `default` column's nine
  version-2 cells (U1, U2 ×3, U3, M2 ×2, P1 ×2) were the push-only refusal;
  they are now the `default_no_push_only` column's verdicts, written by the
  file's ignored recorder (`record_sighash_scriptcode_654_cases`) and spliced
  into the vector with every other field checked equal (the TypeScript and Lean
  columns do not depend on this crate). Seven of the nine differ from the
  reference's default (U1, U2 ×3, U3, M2 ×2; P1's two agree; with L1, which
  did not move, eight of the ten version-2 cells differ): #654's stated scriptCode divergence, reached in the
  default mode at version 2 now where only the switch reached it before.

## Conformance

`BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance` (no diff from `edf6e03`
under `conformance/`):

| | run | passed | unsupported | skipped | known failures |
|---|---:|---:|---:|---:|---:|
| before (`e19fec98`) | 4,120 | 4,109 | 959 | 37 | 11 |
| after | 4,121 | 4,110 | 958 | 37 | 11 |

One vector moved, `node.tx-valid.shared.0168` (version 2, unlocking script
`51 b2`, `OP_1 OP_NOP3`, flags `P2SH, CHECKSEQUENCEVERIFY, UTXO_AFTER_GENESIS`,
expected valid): it left the unsupported class "bsv-rs always enforces
SIGPUSHONLY (push-only unlocking scripts)" (319 to 318; the class renamed "the
default mode enforces SIGPUSHONLY at version <= 1 (a word would express the
fixture)") and joined the run and passed. Found by diffing the census's
`BSV_CONFORMANCE_DEBUG` lines on the base and the tip. `conformance_beef`
unchanged.

## The sibling

`bsv-script-lean@5dc337e1` `harness/run --impl bsv-rs --corpus seed`, a
scratch copy with `bsv-rs` a path dependency (base copy, then this tree):
GREEN both, `bsv-rs/manifest.json` and `bsv-rs/seed.jsonl` byte-identical
(10,000 entries, agree 10,000 block and 10,000 mempool, 0 witnesses). The
harness runs every seed entry under a word (`not_applicable_entries: 0`); its
no-word path (`engine.rs:344`) sets `set_require_push_only` explicitly, so
the default mode's derived switch is never read by it.

## Gate

Recorded in the lane's REPORT.
