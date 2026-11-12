# Lane fix-874-door-reads-as-node: the documented door reads a transaction as the node's script door reads it (#874)

**Base.** `origin/beta` at `8e78516f`. **Decided** by three independent design reads, 3 of 3
(`design-door-reader-node`, `design-door-reader-api`, `design-door-reader-adversary`): option O2. The
issue's "Decided" section is the specification; this lane built it cell by cell.

## What changed

- `src/transaction/amount.rs`: `AmountRule` (crate-private), the reader's amount rule. `Reference`
  refuses an amount of 2^53 or more in the reference's words, as `read_amount` does; `Node` reads any
  64-bit value and notes one of 2^53 or more, answered as `from_binary`'s refusal
  (`reference_refusal`).
- `src/transaction/transaction.rs`: the one reader. `from_reader` is `read_one(reader,
  AmountRule::Reference)`, unchanged in behaviour; `from_binary_as_node` (crate-private) is the door's:
  `read_one` under `AmountRule::Node`, then the trailing-byte refusal in `from_binary`'s words; any
  refusal after an amount of 2^53 or more is answered as the amount's error, since `from_binary` stops
  there. `from_binary`, `from_hex`, `from_ef`, `from_hex_ef`, `from_reader` and `parse_script_offsets`
  keep the reference's bound (#844 stands).
- `src/transaction/spending.rs`: `SpendingTransaction` holds the refusal beside its midstates;
  `verify_input` returns `InputRefusal::Transaction(that error)` in the default mode before the index
  check and before evaluation, and under a word checks no amount. No new arm, no signature change. The
  module doc, `from_bytes` and `InputRefusal::Transaction` say the door is the node's script check and
  never its transaction check.

## The cells, as built

| Cell | Answer | Test |
|---|---|---|
| `tx-00026`, block and standard words of both eras | `Ok(InputVerified)` | `tx_00026_is_judged_valid_under_every_word_as_the_node_judges_it_874` |
| `tx-00026`, the default mode and its three overrides | `Transaction(Number can only safely store up to 53 bits)` | `tx_00026_is_refused_in_the_default_mode_in_the_readers_words_874` |
| the default mode at an index past the inputs | the amount's refusal, before the index | `the_default_mode_refuses_the_amount_before_the_index_874` |
| the default mode on a lock that fails, under a work limit of 0 | the amount's refusal, before evaluation | `the_default_mode_refuses_the_amount_before_evaluation_874` |
| an amount behind a later refusal (cut, trailing byte) | the amount's error, as `from_binary` | `an_unsafe_amount_behind_a_later_refusal_is_answered_in_the_amount_words_874` |
| nine amount classes at the first, middle and last output, four shapes | 108 cells, six each, what each is asserted | `every_amount_class_at_every_place_is_read_as_the_node_reads_it_874` |
| `from_binary`, `from_hex`, `from_reader` | the reference's bound | `from_binary_and_its_family_keep_the_references_bound_874` |
| a caller's `source_satoshis` of 2^53 or more under CHECKSIG (the issue's "Beside it") | valid in every mode here; the reference's default fails the check (run, recorded) | `tests/verify_input_door_source_amount_874.rs` |

The invariant (`tests/verify_input_door.rs`' agreement and `fuzz_verify_input`): `from_bytes` refuses
exactly what `from_binary` refuses, with its error, save a transaction whose only refusal there is an
amount of 2^53 or more (the bytes with every such amount made 0 read by `from_binary`); in the default
mode the door answers `from_binary`'s error for those, at any index.

## The node's oracle through the door

The sibling's harness at its pin `1c051eae`, in a clone under this lane's out folder, its working tree's
`harness/src/engine.rs` patched to judge each input through `SpendingTransaction::from_bytes` and
`verify_input` (a word the interpreter cannot honor and `V2MinimalOnly` under a word stay on the
`Spend` path, as no door rule expresses them), run by `.github/scripts/sibling_harness.py` against
`tests/sibling/column.json` (HEAD unchanged, so the pin check holds):

| Tree | Summary lines |
|---|---|
| base `8e78516f`, the door adapter | `VERDICTS: 13765 entries, 4 divergences` (tx-00026 under spec and spec-mempool, unexplained and as a rules row), `REASONS: 13764 equal, 1 differ` (tx-00026), RED |
| tip, the door adapter | `VERDICTS: 13765 entries, 0 divergences`, `REASONS: 13765 equal, 0 differ`, GREEN |
| tip, the pinned adapter (the job's own steps) | `VERDICTS: 13765 entries, 0 divergences`, `REASONS: 13765 equal, 0 differ`, GREEN |

tx-00026 moved, and no other entry.

## "Beside it", run

`tests/support/door_source_amount_874.mjs` on `ts-stack@edf6e03` `packages/sdk` bundled with bun under
Node v22.18.0, two runs byte-identical: a P2PKH spend this crate's writer signs at a source amount of
2^53 - 1, 2^53, 2^63 and 2^64 - 1 (2^64 as the reference's number), versions 1 and 2. The reference's
default `Spend`: valid at 2^53 - 1; past it its preimage writer throws (`BigNumber.ts:462`) inside its
signature check, which catches it as a failed check (`Spend.ts:1696-1705`), and the script ends false.
This crate judges the signature over the amount's eight bytes in every mode, as the node and go-sdk do.
Stated, not conformed (the CHANGELOG's parity note, the root `CLAUDE.md`'s row): the amount is the
caller's argument, no coin holds it, and every reader of either SDK refuses it from bytes.

## REDs and plants

- A scratch copy of `8e78516f` with the new file: 5 of 7 RED (the word test naming each of the four
  words refused; the property's door-alone cells `refused by both`; the order and evaluation tests
  at the read).
- Plants on the tip: the door given `AmountRule::Reference`, 5 of 7 RED; the default-mode check moved
  after the index check, 2 of 7 RED and `fuzz_verify_input` crashing at its 256th execution; `from_reader`
  given `AmountRule::node()`, 8 tests of `tests/transaction_numbers_844.rs` RED.
