# Lane fix-844-amount: the readers' 2^53 refusal (#844) and `from_json`'s txid (#845, the reader half)

Base: `origin/beta` at `842e5cc4` (no reset needed), the lane's opening; PR #856 sits on
`eba1fc72` (beta's tip when it was opened), and the RED counts of section 7 are the same
there (the cold read's run, 2026-11-09). Reference: `ts-stack@edf6e03`
`packages/sdk`, bundled with `bun build` and run under Node v22.18.0
(`tests/support/transaction_numbers_844.mjs`, two runs byte-identical). Go:
`go-sdk@2ca481c`, by reading. Node: bitcoin-sv `v1.2.2`, by reading.

## 1. The survey: every wire number the reference holds in a JavaScript number

"Run" means the cell is recorded in `tests/vectors/transaction_numbers_844.json`
(or `transaction_trailing_data_840.json`) and asserted by
`tests/transaction_numbers_844.rs`; "read" means read at the pin and not run.

### The transaction readers (`Transaction.ts`)

| Field | Reference site | Reference read | This crate's twin | Type here | Edges, reference | Edges, here (after #844) | Class | Go (read) |
|---|---|---|---|---|---|---|---|---|
| Output amount | `:409` (EF), `:497` (`fromReader`, so `fromBinary`, `fromHex`) | `readUInt64LEBn().toNumber()` | `transaction.rs:334` (EF), `:433` (`from_reader`, so `from_binary`, `from_hex`, `from_json`'s `hex`) | `u64` | 2^53 - 1 read; 2^53, 2^63, 2^64 - 1 `Number can only safely store up to 53 bits` (run) | the same, `TransactionError` (run) | same verdict and words (was: different verdict) | `uint64` (`output.go:53`), every edge read |
| EF source amount | `:388` | `readUInt64LEBn().toNumber()` | `transaction.rs:288` | `u64` | as above (run) | as above (run) | same verdict and words (was: different verdict) | `uint64`, read |
| Output amount at the offsets reader | `:456` | `br.read(8)`, unread | `transaction.rs:497` | skipped | every edge read, 2^64 - 1 included (run) | every edge read (run) | same (the brief listed this door to refuse; the reference skips it, so it is not touched) | no twin |
| Version | `:471`, `:372` | `readUInt32LE` (unsigned) | `:392`, `:251` (`read_u32_le`) | `u32` | 0, 2^31 - 1, 2^31, 2^32 - 1 read (run) | read, the same id and hex (run) | same | `uint32` |
| Input index (vout) | `:476`, `:380` | `readUInt32LE` | `:409`, `:278` | `u32` | four edges read (run) | read (run) | same | `uint32` |
| Sequence | `:486`, `:387` | `readUInt32LE` | `:415`, `:285` | `u32` | four edges read (run) | read (run) | same | `uint32` |
| Lock time | `:512`, `:418` | `readUInt32LE` | `:445`, `:346` | `u32` | four edges read (run) | read (run) | same | `uint32` |
| Input count, output count, script lengths | `:472,477,494,498`, `:376,384,389,406,410`, `:447,450,454,457` | `readVarIntNumStrict(false)` (`readVarIntNumStrict.ts`) | `:394,411,427,434`, `:262,281,291,328,335`, `:473,478,493,499` (`read_var_int_num`, canonical since 0.6.0) | `usize` | `fd`, `fe`, `ff` forms of a small value `non-canonical varInt`; `ff` at 2^53 and 2^64 - 1 `number too large to retain precision - use readVarIntBn` (run, 60 cells over four readers) | refused: `NonCanonicalVarInt`, or a read past the bytes (run) | same verdict in other words (stated in the root `CLAUDE.md`, the 2^53 row) | lenient varint (`util/varint.go`, the 0.6.0 row) |

### The BEEF, BUMP and script readers

| Field | Reference site | Reference read | This crate's twin | Edges, reference | Edges, here | Class |
|---|---|---|---|---|---|---|
| A raw entry's amount in the scan | `BeefTx.ts:39` | `skipBytes(8)`, unread | `beef_raw_frame.rs:63-70,105` (the scan, since #844 reading the amount through `amount::safe_amount`) | read (run: `mergeRawTx`, `mergeBeef`, `Beef.fromBinary`, `fromBinaryStrict` take 2^53) | refused in the reader's words (run) | different verdict, stated (the BEEF row) |
| An entry's transaction, parsed | `BeefTx.ts:118-126` (the `tx` getter, `fromBinaryView`) | through `fromReader` | `beef/collect.rs` (`Transaction::from_binary` of the bytes the decoder framed); `beef_tx.rs:495-499` (`BeefTx::from_reader`) | refused at `tx`, `Transaction.fromBEEF`, `fromAtomicBEEF` (run) | refused at `Beef::from_binary` (the stream's `ValueOutOfRange` at the value), `from_beef`, `from_atomic_beef`, `BeefTx::from_reader` (run) | same verdict at the transaction doors; at the BEEF reader stated |
| The stream's value | none | none | `beef_stream.rs:1138-1147`, judged by `check_transaction` (`:206-215`, `MAX_MONEY`) | `verifyValid` valid (run) | `ValueOutOfRange` (unchanged by #844) | stated (the 0.4.1 to 0.4.3 rows) |
| BEEF version word, atomic prefix | `Beef.ts:1242,1249` | `readUInt32LE` | the stream's `St::Word`, `St::Version` | 32-bit field, no number edge past it (read) | the same | same |
| BUMP count, entry count | `Beef.ts:1257,1262` | `readVarIntNumStrict(false)` | the stream's varints | a count past 2^53 - 1 refused (read) | refused, the bytes not there (read) | same verdict in other words |
| An entry's format byte, V1 has-BUMP byte | `BeefTx.ts:293,306` | `readUInt8` | the stream | 8-bit, the #86 row | the #86 row | stated already (#86) |
| An entry's BUMP index | `BeefTx.ts:298,306` | `readVarIntNumStrict(false)` | the stream; `beef_tx.rs:454,468` | past 2^53 - 1 refused at the read (read) | read; an index naming no BUMP refused by the stream and `verify_structure`, collected unjudged by `Beef::from_binary` (the #798 row) | same verdict at judgment; the reference refuses earlier (read, not run) |
| BUMP block height | `MerklePath.ts:113` | `readVarIntNumStrict(false)` | the BUMP decoder (`Bump::in_memory`, a `u32` height) | 2^32 - 1 and 2^32 read, 2^53 refused (run) | 2^32 - 1 read, 2^32 `RootNotCarried`, 2^53 refused (run) | 2^32: different verdict, stated already (#167's row); 2^53: other words |
| BUMP tree height | `MerklePath.ts:114` | `readUInt8` | the decoder | 8-bit | 8-bit | same |
| BUMP leaf count, offset | `MerklePath.ts:123,125` | `readVarIntNumStrict(false)` | the decoder (`u64`, an offset within its level) | a 54-level path at offset 2^53 - 1 read, the root (run); at 2^53 refused `number too large to retain precision - use readVarIntBn` (run) | 2^53 - 1 read, the same root (run); 2^53 read (run) | **different verdict, not conformed: two defensible answers** (section 6) |
| BUMP leaf flags | `MerklePath.ts:126` | `readUInt8` | the decoder | the #86 row | the #86 row | stated already |
| A script push length | `Script.ts:577-597` | bytes or'd, `>>> 0` | the script reader | `4effffffff`, `4e00000080` one chunk, written back (run) | one chunk, written back (run) | same |
| `toNumber` elsewhere in a script | `Script.ts:322` (`writeNumber`, a writer) | | | not a reader | | out of scope |

`primitives/utils.ts` and `ReaderUint8Array.ts` hold the readers named above
(`readUInt32LE` `:746-756`, `readUInt64LEBn` `:770-774`, `readVarIntNum`
`:785-801`, `readVarIntNumStrict` `:810-812`); the transaction, BEEF, BUMP and
script readers call only the strict varint and the fixed reads listed.

## 2. What was conformed and what was stated

- Conformed (#844): `src/transaction/amount.rs` (`read_amount`, `safe_amount`), called at `transaction.rs:288,334,433`; the scan at `beef_raw_frame.rs:63-70,105`; the writers' check at `beef_tx_writer.rs:107-126` (a parsed entry written from its fields judged by its amounts; see section 4).
- Conformed (#845): `tx_json.rs:203-225`.
- Grep, after: `grep -rn 'read_u64_le' src/transaction/transaction.rs` gives `:497` alone (the offsets reader's skip); every other `read_u64_le` under `src/` reads a cursor (`beef_stream.rs`, `beef_stream/deferred.rs`), a wallet wire field (`wallet/wire/reader.rs`), the wallet's result BEEF reader (`wallet/substrates/result_values/beef.rs:94`: a raw transaction's output amount, read as a `u64`, where its twin `WalletResultBEEF.ts:56-63,303` at `ts-stack@edf6e03` reads `Number(value)` and throws for none, rounding past 2^53 - 1; both judge the committed amount later against 2.1e15, `WalletResultValidation.ts:1125,2105` and `action_binding.rs:7`; left unchanged, the strength read's correction of this line) or the sighash parser (`primitives/bsv/sighash.rs:217`, stated: no reference twin). No transaction reader of `src/transaction/` is left without the helper; the result BEEF reader keeps its exact `u64`, as its twin refuses no amount.
- Stated (root `CLAUDE.md`): the 2^53 row rewritten (closed for the readers; the writer's cell; the 60 varint word cells); the BEEF row; the BUMP offset row; the JSON row.
- Not touched, reported: the BUMP offset (section 6); `parse_script_offsets` (the reference skips the amount).

## 3. The doors of step 3, the reference's recorded answer beside this crate's

| Door | Reference (2^53 output, run) | Here, before | Here, after |
|---|---|---|---|
| `from_json` with `hex` | no twin (`fromHex`: refused) | `Ok` | refused, `Number can only safely store up to 53 bits` |
| `from_json`, fields, `satoshis` 2^53 | no twin | `Ok` | `Ok` (stated; `from_json(to_json)` then refuses through `hex`) |
| `sighash::parse_transaction` | no twin | reads the `u64` | reads the `u64` (stated: a prefix reader the signers hand their own transaction's bytes; a hand-built transaction with such an output is signed) |
| `Beef.fromBinary` / `Beef::from_binary` | `Ok` | `Ok`, `verify_structure` `ValueOutOfRange` | refused at the value, `ValueOutOfRange`, the stream's offset |
| `Beef.fromBinaryStrict` | `Ok` | (no twin; `from_binary` is strict) | as above |
| `Beef::from_reader`, `BeefTx::from_reader` | (`Beef.fromReader` scans: `Ok`) | `Ok` | refused (`BeefTx::from_reader`: `TransactionError`, the reader's words) |
| `verifyValid`, `isValid` | valid | `ValueOutOfRange` | not reached (the parse refuses) |
| the entry's `tx` getter | refused in the amount's words | `Ok` | not reached |
| `Transaction.fromBEEF` / `from_beef` | refused in the amount's words | `Ok` | refused |
| `Transaction.fromAtomicBEEF` / `from_atomic_beef` | refused in the amount's words | `Ok` | refused |
| `mergeRawTx` / `merge_raw_tx`, `BeefTx::from_raw_tx` | `Ok` | `Ok` | refused, `BeefError` in the reader's words, the BEEF untouched |
| `mergeBeef` / `merge_beef` | `Ok` | `Ok` (source by hand) | refused in the scan's words, the target untouched |
| the streaming reader | (no twin) | `ValueOutOfRange` | `ValueOutOfRange` |

## 4. The scan, the pre-pass and the census

The scan (`beef_raw_frame::one_transaction`) skipped the amount as the
reference's does; with the reader refusing 2^53, the scan and the reader
would part on such an output and the pre-pass of #621 would no longer equal
its round trip. The scan now reads the amount through `safe_amount`, in the
reader's words. Planting the old scan back: the differential RED
(`prepass_621_tests.rs:81`).

`fuzz_beef_parser` then found a second door on its own seeds (its 60-second
run): `BeefTx::own_refusal` took a parsed entry with no cached bytes on
trust ("a serialization built from the fields is one transaction by
construction"), which an amount of 2^53 breaks: a transaction built by hand
and pushed into `txs` without being hashed passed the check, the round trip
refused it `ValueOutOfRange`, and the pre-pass disagreed with its oracle
(`left: BeefError("Number can only safely store up to 53 bits")`, `right:
BeefError("invalid BEEF at byte 123: ValueOutOfRange")`; the oracle had
written the entry and so cached its bytes before the merge's check scanned
them). The check now judges such an entry's amounts. The input is kept as
found, `fuzz/corpus/fuzz_beef_parser/issue-844-hand-pushed-entry-amount-unchecked`.
The lib differential reaches it too (state 16, a hand push of a transaction
never hashed): RED with the old check (`state 16: the pre-pass Ok(()), the
oracle Err(BeefError("invalid BEEF at byte 375: ValueOutOfRange"))`).

Census (`the_pre_pass_is_the_round_trip_on_every_vector_beef_621`):

| | BEEFs read | states | `Ok` | refused | by the reader | `RootNotCarried` |
|---|---|---|---|---|---|---|
| before (`842e5cc4`) | 338 | 14 | 2,215 | 2,517 | 1,726 | 243 |
| the 14 states on the 341 (measured) | 341 | 14 | 2,237 | 2,537 | 1,740 | 245 |
| after | 341 | 17 | 2,263 | 3,534 | 1,740 | 245 |

The three new BEEFs are the vector's readable ones (block 170's transaction at
an output of 2^53 - 1: the BEEF, its atomic form, the `mergeRawTx` bytes; the
2^53 ones refused): 22 `Ok`, 20 refused under the 14 states. The three new
states over 341 BEEFs: 26 `Ok` (BEEFs holding no transaction with an output,
where the `edit_tx` state moves nothing) and 997 refused, all by the writers'
check (none by the reader). The recorded-states test is unchanged
(4, 23, 2, 0). The #817 sweeps: `beef_v1_txid_only_writer_817.rs`'s `SWEPT`
(338, 115) to (341, 115), `beef_writer_refusals_817.rs` 6 x 338 to 6 x 341.

## 5. The `from_json` cells and the `source_txid` doors

| Document | Before | After |
|---|---|---|
| input `txid` `"zz"`, `"abcd"`, `""` | `Ok`, one id for the three | refused, `Invalid txid of input N: expected 64 hex digits` |
| 63 or 65 digits, a `g`, a leading space | `Ok` | refused, naming the index only |
| upper or mixed case | `Ok`, held as given | `Ok`, held in lower case, the same id and bytes |
| a top-level `txid` beside `hex`, disagreeing | unread: the hex's transaction | unchanged (reported; go-sdk's `UnmarshalJSON` the same, `transaction/txjson.go:49-66`) |

The doors that set `source_txid` (`grep -rn 'source_txid' src/ | grep -v '_tests.rs'`):

| Door | Text from outside? | Checked? | Disposition |
|---|---|---|---|
| `TransactionInput::new(String, u32)` (`input.rs:114`) | yes, any caller's text | no | the typed id of #843's break (a public signature; not this lane's) |
| `TransactionInput { source_txid, .. }` struct literal | yes | no | the same |
| `Transaction::add_input_from` (`transaction.rs:1137`) | yes, `&str` | 64 hex digits checked (`:1146-1160`); case kept as given | row for the captain: an upper-case txid held as a second string |
| `Transaction::add_inputs_from_utxos` (`transaction.rs:1215-1243`, `Utxo.txid`) | yes | 64 hex digits checked; case kept | row for the captain, as above |
| `Transaction::from_json` (`tx_json.rs:210`) | yes | checked since #845 | fixed here |
| `from_reader`, `from_ef` (`transaction.rs:271`, `:402`) | bytes, written as hex | by construction | none |
| `overlay/historian.rs:323,466,469` | computed ids, `format!("{k:064x}")` | by construction | none |
| wallet JSON substrate, `create_action` inputs, templates | none set a `TransactionInput::source_txid` (outpoints travel as their own types) | | none |

## 6. Cells stopped short of: two defensible answers

A BUMP leaf offset of 2^53 or more in a path of 54 levels or fewer: the
reference refuses it at the varint (`MerklePath.ts:125`, recorded); BRC-74
carries the offset as a varint to 2^64 - 1, and this crate already holds
BRC-74's 64 levels against the reference's 54 (a stated row). Conforming would
refuse in the BUMP decoder (shared by the stream and the whole reader, outside
the transaction readers); keeping BRC-74's width is the crate's standing
reading. No block holds 2^53 transactions, so no proof a node makes reaches
either cell. Stated as a row; the captain's call.

## 7. RED

On a scratch copy of `842e5cc4` (`git archive`, its own target dir under
`$TMPDIR`), the tip's two test files and the vector overlaid
(`/Volumes/Lanes/out/bsv-rs/fix-844-amount/red-on-base.log`):
`tests/transaction_numbers_844.rs` 11 of 17 RED (the six green: the script
offsets, the sighash parser, the top-level txid, the two BUMP tests, the
script push); `tests/transaction_trailing_data_840.rs` 3 of 15 RED (the three
renamed pins, `assert_refused` at `:86`). The scan's amount check planted out:
the pre-pass differential RED (`red-scan-plant.log`); the writers' check
planted back: RED at state 16 (`red-check-plant.log`).

## 8. The sweep

`$TMPDIR/fix-844-scripts/sweep.py` (not tracked) over `tests/vectors`,
`tests/fixtures`, `tests/transaction/vectors` and the conformance corpus:
3,888 transactions and 599 BEEFs parsed, 37 carrying an amount of 2^53 or
more: 36 in this lane's and #840's vectors (the recorded cells), and one in
the corpus, `node.tx-invalid.shared.0025` (`vectors/sdk/scripts/evaluation.json`,
an output of 2^64 - 1, expected invalid): refused before and after (now at
the parse, as the reference's `fromHex` refuses it), the census unmoved. The
pinned totals hold with `BSV_CONFORMANCE_DIR=~/bsv/ts-stack/conformance`:
scripts 5,116 total, 4,121 run, 4,110 passed, 958 unsupported, 37 skipped,
11 known failures, 0 failures, 0 panics; the four BEEF classes (total/run/passed) 16/15/15 with one skipped,
15/12/12 with three unsupported, 16/12/11 with four unsupported and one
known failure, 8/8/8, unchanged. (`beef.rs:2861`, `beef_tx.rs:712,746` set
`source_txid` in test modules alone.)

## 9. The dependents

| Repository | `Transaction::from_json` calls | Moved texts matched (`Number can only`, `ValueOutOfRange`, `Invalid txid of input`) |
|---|---|---|
| `~/bsv/bsv-wallet-toolbox-rs/src` | 0 | 0 |
| `~/bsv/bsv-wallet-cli/src` | 0 | 0 |
| `~/bsv/bsv-overlay-cloudflare/crates` | 0 (six `from_json` hits are `Response::from_json` and `TxFacts::from_json`: `overlay-cloudflare/src/proof_probe.rs:261`, `low-app-layer/src/owed_actor.rs:630,891,4641`, two in its tests) | 0 |
| `~/bsv/rust-message-box/src` | 0 | 0 |
| `~/bsv/bsv-middleware-rs` | 0 | 0 |

The raw-entry doors (`merge_raw_tx`, `from_raw_tx`, `parse_script_offsets`)
are called at 65 sites in the toolbox, 44 in the overlay crates and 1 in the
middleware (counted, tests included): they now refuse an output of 2^53 or
more, which no node accepts.

## 10. The fold (the three reads of `e2cac3a1`, 2026-11-09)

The reads: cold FIX 0.85 (the required `lint` red on rustfmt of
`fuzz/fuzz_targets/fuzz_beef_parser.rs` alone; "the code itself reads MERGE"),
rule ACCEPT 0.85, strength ACCEPT 0.85. Taken in that order, each by
`git cherry-pick -x`: the cold read's `09ad67a6` (the fuzz target's rustfmt) and
`f4cfbac5` (the BEEF writers' refusal stated), the rule read's `b4201028` (go-sdk's
txid reading and the BEEF doors in the migration line), the strength read's
`9b514be6` (the result BEEF reader's line in this record). `b4201028` and
`f4cfbac5` both rewrote the CHANGELOG's writer and migration bullets: the
cold read's writer bullet and the rule read's migration line were kept, each
true of the code at its commit; the fold then rewrote the writer bullet's BEEF
sentence (below).

What was folded:

- The writers refuse in the writer's words (the cold read's item 3). Recorded
  first: the recorder gains `writer_cells` (additions only, the 156 cells and
  every older key byte for byte; two runs byte-identical under Node v22.18.0):
  block 170's transaction with a third output appended, the amount at 2^53 - 1
  and 2^53 in the first, the middle and the last output, at ten doors. The
  reference throws `The number is larger than 2 ^ 53 (unsafe)` at every one
  (`Transaction.toBinary`, `toBEEF`, `toAtomicBEEF`, `Beef.mergeTransaction`,
  `toBinary`, `toHex`, `toBinaryAtomic`, `BeefTx.toWriter`, `mergeBeef` of a
  source holding the entry, `toBinary` after an edit in place), and writes at
  2^53 - 1. Conformed: `BeefTx::amount_refusal` (`src/transaction/beef_tx_writer.rs`)
  reads every output of an entry holding a transaction and refuses in those
  words (`amount::UNSAFE_WRITE`), first: in `BeefTx::to_writer` ahead of its other
  checks, over every held entry at the head of `Beef`'s check, of `to_binary`
  (before the empty-txid check and the sort) and of `to_binary_atomic` (before
  the subject is looked for), as the reference's `#getSerializedBytes` and
  `#getAtomicSerializedBytes` serialize every held transaction first
  (`Beef.ts:360-362,392-404`). The raw-entry doors keep the reader's words.
  Stated, two cells: `Transaction::to_binary` writes the amount (#843's break),
  and `merge_transaction` holds the entry where the reference's
  `mergeTransaction` throws (no `Result` in its signature; the writers refuse it
  after). Found on the way and changed by the same check: `merge_beef` of a BEEF
  read from bytes then given such an entry through `txs` answered `Ok` on beta
  (`30664040`, before #844: #621's residue, a hand edit of a read BEEF merged as
  read) where the reference's `mergeBeef` throws; at `e2cac3a1` it refused
  already, in the scan's words (the field check in `own_refusal`), and it
  refuses now in the writer's, the check reading every held entry (the scoped
  cold re-read of the fold: `merge_beef` equal to the round trip on
  `e2cac3a1` at every position, the test RED there on the words alone).
- The integration pin (the cold read's residual):
  `a_hand_pushed_entry_with_such_an_output_is_refused_by_every_writer_and_merged_as_the_round_trip_844`,
  the fuzzer's state through public calls (a BEEF read from bytes, then the
  entry pushed unhashed, the amount in each of three outputs): every writer
  refuses it in the writer's words, and `merge_beef` answers what `to_binary`
  then `Beef::from_binary` answers, the target untouched.
- The surviving mutant (the strength read): the recorded cells put the
  amount in a middle and the last output.
- The records: the record's base line (its third) names `eba1fc72` beside `842e5cc4`; the
  BUMP offset row's "Theirs" is ts-stack #1469 (`Bound MerklePath height at
  BRC-74's 64 levels rather than 54`, open, read by `gh issue view`).
- The census: the fifteen recorded control BEEFs join the sweep, so the
  pre-pass census reads 356 BEEFs (341) under 17 states, 6,052 = 2,416 `Ok` and
  3,636 refused, 1,761 by the reader, 248 `RootNotCarried`; the 341 older BEEFs
  measured at the fold's tip with the old vector keep 2,263, 3,534, 1,740, 245,
  so the move is the vector's alone (15 x 17 = 255 = 153 + 102). The two #817
  sweeps: `(356, 121)` and `6 * 356`. The `.cargo/mutants.toml` entry for
  `dependency_order`'s `<` moved from 1132 to 1138 (six lines in
  `to_binary_atomic`).

RED (scratch copies under `$TMPDIR`, their own target dir; the logs in
`/Volumes/Lanes/out/bsv-rs/fix-844-amount-fold/`):

```
e2cac3a1 + the fold's tests and vector: 3 of 19 FAILED, on the words alone
  (the re-read's run: merge_beef equal to the round trip there, both the
  scan's words; the `merge_beef 0  left: Ok(())` line belongs to the
  no-output plant below and to beta 30664040, not to e2cac3a1)
  left: BeefError("Number can only safely store up to 53 bits")
  right: BeefError("The number is larger than 2 ^ 53 (unsafe)")
tip, amount_refusal reading the first output alone: 2 of 19 FAILED
  "two_to_the_53 1 BeefTx.toWriter (pushed): here Ok(..)", positions 1 and 2
tip, amount_refusal reading no output: 3 of 19 FAILED
  merge_beef 0  left: Ok(())
```
