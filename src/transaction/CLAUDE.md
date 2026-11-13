# BSV Transaction Module
> Transaction construction, signing, serialization, and SPV verification for BSV blockchain

## Overview

This module provides complete Bitcoin transaction functionality:
- Transaction inputs, outputs, construction, and manipulation
- Binary/hex serialization and Extended Format (BRC-30)
- Transaction hash and TXID computation
- Signing with script templates
- Fee calculation with pluggable fee models
- MerklePath (BRC-74 BUMP) for merkle proofs
- BEEF format (BRC-62/95/96) for SPV proofs with iterative ancestry collection (no walk over `source_transaction` recurses: link, sort, serializers, `verify`, `Clone`, `Drop`; 0.3.35, bsv-stack-lean #57)
- The transaction doors write the collected order (0.8.8): `to_beef`, `to_beef_v1` and `to_atomic_beef` write each entry's sources above it and the subject last — BRC-62's own rule for the form ("we must ensure that we end with the tx being evaluated, and its inputs are above, and their inputs are above that") — the first two through one shared helper onto `Beef::hold_order`, which holds a BEEF a transaction door assembles as it stands; the atomic door through the same helper onto the atomic writer's transaction-door form (`to_binary_atomic_subject_last`, 0.8.8's fold: the BRC-95 closure sorted as `Beef::to_binary_atomic` sorts it, then the subject moved last, the bytes `0.8.7`'s). Until 0.8.8 the plain doors sorted the collected ancestry into the dependency order (and on this line, after `0.9.0-beta.7`, the atomic door's closure sorted its copy without the move), so a graph holding a proven branch beside a missing source got its subject written before the proven entry and `from_beef(&bytes, None)` (its target `txid ?? atomic_txid ?? the last entry`) answered an ancestor; every version since the crate's first release (`0.2.0`) read this way. The Beef-level doors keep their documented dependency sort (a BEEF a caller assembles by hand, `merge_beef` then `to_binary`, and `Beef::to_binary_atomic` on one, which sorts its closure), and the atomic word names its subject in the header. Pinned by `tests/beef_tx_order.rs` (the finding's shape, the boundary doors, the property over generated graphs and the honest-tree cell, the atomic bytes pinned on the finding's shape, the atomic order (the sorted closure, the subject moved last) on 605 graphs, the version word, the corpus seed replayed, the census of the property's counts) on `tests/vectors/beef_tx_order.json`, recorded by `tests/support/beef_tx_order.mjs` by a run at the pin; the fuzz target `fuzz_beef_parser` checks the round trip and carries the shape's seed
- The streaming BEEF reader (`beef_stream`, 0.4.0): `verify_stream` over any `Read`, one element held at a time, the verdict `Valid`, `Invalid { offset, kind }` (twenty kinds, none a size or a count) or `SpendRefused`, with `NotJudged { offset, txid, input, cause }` for a word outside scope (#452); `Cursor` and `resume`. A valid BEEF is never refused for its size or its counts
- The stream's two budgets for its scripts (#373): `StreamVerifier::set_work_limit` and `set_memory_limit` (the same on `AsyncStreamVerifier`), per input, `None` the default and uncapped, `Some(n)` the caller's (the memory budget `n` bytes per stack, `Transaction::verify`'s third parameter, #331); work exhaustion is `Verdict::NotJudged` with `WorkBudgetExceeded`; memory exhaustion is `Verdict::SpendRefused { txid, input, why: SpendRefusal::Resource(limit) }`, a decline naming the transaction and the input, never a verdict; local configuration, absent from the `Cursor` and set again after `resume`; the structure-only reader spends none; the reader's own bound per element is the charter's (NL-3), not a cap on a script. The `verify_stream*` functions take neither: a caller with a budget builds the reader. Pinned by `tests/beef_stream_memory_budget_373.rs` and `tests/script_work_budget.rs`
- A raw transaction with no input is invalid bytes (0.4.1, bsv-stack-lean #58): `Kind::NoInputs` at the transaction's offset from the streaming reader, not valid from `Beef::verify_valid`, with or without a BUMP index. The rule is the node's (bsv-script-lean `lean/BsvScript/TxRules.lean`, `checkTransactionCommon_vinEmpty`); a test BEEF's root needs an input and a merkle path
- A raw transaction with an input and no output is invalid bytes too (0.4.3, bsv-stack-lean #59): `Kind::NoOutputs` at the transaction's offset, after the inputs' check (the sibling's `TxRules.lean:85-86`, `checkTransactionCommon_voutEmpty`); `beef_stream::no_transaction` answers both for every path. `Transaction::verify` refuses a transaction it reaches with either, proven or not (`invalid transaction <txid>: NoInputs`): there is no synthetic root
- The whole path on the reader's walk and rules (0.4.2, bsv-stack-lean #61): `Beef::verify_valid` computes each BUMP's root by `beef_stream`'s `bump_root` (linear; 0.4.1 walked once per leaf), and `Beef::verify_structure` answers the roots or the reader's `Kind`. A lone leaf at an offset other than 0 is `MissingSibling`; `from_binary` refuses a byte after the frame (`TrailingBytes`, in the reader's words); an atomic BEEF is held to the reader's atomic rule (`SubjectMissing`, `UnrelatedTransaction`); a txid-only entry is valid when a BUMP of the BEEF proves it (`StubNotProven` otherwise) and `allow_txid_only` decides nothing
- One reader (bsv-rs#86): the whole-BEEF reader is a mode of the streaming reader. `Beef::from_binary`, `from_hex`, `from_reader` and `from_binary_with_limits` (and through them `Transaction::from_beef` and `from_atomic_beef`) run `BeefDecoder::collecting()` (crate-private) and collect its elements into the `Beef` in one pass (`beef/collect.rs`): the BUMPs by `Bump::to_merkle_path`, each level's leaves sorted by offset as the in-memory form always held them; the transactions from the bytes the decoder read (`Transaction::from_binary` on them, so the hash is the bytes'), in the order written; version and subject from the header. The parse refuses what the stream refuses as a frame or a BUMP (a second leaf at an offset its level carries among them, agreeing or not: `DuplicateOffset { level, offset }` at its offset varint, the reference's `Duplicate offset`, its own kind by the owner's word, #86, #167; `merkle_path_root` refuses one held in memory, ahead of the walk), in the stream's words (`BEEF error: invalid BEEF at byte N: Reason`, `Error::BeefError`): the earliest refusal of the reading, an earlier element's content or fold refusal included (a structure-only `BeefIndex` folds each element beside the collection, the leading BUMP's root at a height as the one root the headers carry there). The collect mode yields a transaction whatever its content (`check_transaction`: unproven coinbase, no input, no output, `ValueOutOfRange`, null or repeated outpoint), so such a BEEF parses and `verify_structure` judges it. `verify_structure` is one pass over the entries in the order held, each judged as the decoder and the fold judge an element (`beef/in_memory.rs`: `merkle_path_root`, `content_refused`, `atomic_table`), then the sort, whose result decides where the unproven inputs lead (`missing_inputs`, `with_missing_inputs`, `not_valid`: `InputNamesNoElement`), then the atomic rule. A BUMP above a `u32` height is `RootNotCarried` at the parse (the in-memory height is a `u32`; through 0.8.3 it was cut to its low bits). The differential `tests/beef_two_readers_agree.rs` (every BEEF the tree holds, its prefixes, single-byte changes and reversals: 0 disagreements, no stated difference) and `fuzz_beef_parser`'s assertion pin it
- A BEEF is valid whatever its order on the wire (bsv-rs#240, the keeper's re-reading of 2026-10-26 on the owner's north star: one verdict across the SDKs): every input of an unproven transaction names a transaction of the BEEF or a proven txid, wherever it is written. The whole path sorts before judging, as the reference's `Beef.verifyValid` does (`ts-stack@edf6e03` `Beef.ts:1054-1073`, `sortTxs` at `:1065`). The stream holds an unproven transaction an input of which names a txid the index does not hold yet by its index entry (`BeefIndex`'s `Deferred` of `HeldTx`, by offset: txid, offset and wire length, 56 bytes; per input the outpoint, sequence and offset, 48; with spends checked the version and lock time, each unlocking script, and the outputs, 16 bytes and the script each, which the original digest of a CHRONICLE-bit signature hashes after the parent's scriptCode; never its raw bytes), and the txids it waits on, counted. When the last is in it is ready, and the reader folds the ready ones in one per step, in wire order, ahead of the next element (`Judge::release_next`; under `step_until` its scripts run under the caller's budget and may pause inside it, the cursor naming it before the frame; the asynchronous reader folds every ready one after the element; `BeefIndex::fold` in the same call). At `finish`, ahead of the atomic rule, what is still held is refused: `InputNamesNoElement` at the earliest held transaction's earliest input that names nothing. A refusal after a held child is the later element's, on both paths. No bound (the beef-of-any-size charter: a valid BEEF is never refused for its size or its counts; the keeper's stop on #240): a BEEF in BRC-62's order holds nothing, one written children first at most the entry of every unproven transaction read; `BeefIndex::deferred()` answers the transactions held and the bytes their entries hold. The whole reader's structure-only judge holds the same entry, not a copy of the bytes the `Beef` holds. A cursor taken while one is held is BSC4 (BSC3, then the held entries by offset, each count bounded by the bytes left); one that holds nothing keeps BSC3's bytes. `Stop`, `Verdict` and `AsyncVerifyError` are `#[non_exhaustive]` (0.9.0, #240). BRC-62 (`5119a9b` `0062.md:43`, `:72-74`, `:172-191`) keeps the order on the writer's side: `to_binary` writes parents before children. From bsv-rs#86 to #240 the three readers refused a child written ahead of its parent; 0.8's `verify_valid` sorted. Pinned by `tests/beef_order_held.rs` (the reference's verdicts in `tests/vectors/beef_order_240.json`, `tests/support/beef_order_240.mjs`; the held entry and its signatures, the BSC4 cursor's prefixes and changes, one release per step under the budget), `tests/beef_deep_chain.rs` (100,000 links newest first on a 1 MiB stack), `tests/memory_profiling.rs` (the held bytes per link) and the differential
- The atomic rule on the subject's graph (0.8.1, BRC-95): one walk, `beef_stream::atomic_unreached` (the Lean's `finish`, bsv-stack-lean `lean/BeefOfAnySize.lean` `walk`/`finish`), called by `BeefIndex::finish` (the stream) and `Beef::verify_structure` (the whole path). The subject is a raw transaction of the BEEF, else `SubjectMissing` (a missing subject is named at the prefix's 32 bytes; without a prefix, at the last raw transaction instead, or at the stream's end when there is none: the public line on `Reason::SubjectMissing`, promoted from `Judge::conclude`'s 0.8.1 comment); every other entry, raw or txid-only, is reached from the subject through the inputs of raw entries, else `UnrelatedTransaction`. The entry a refusal names is the earliest, by the trie order (the txid's bytes, each byte's bits reversed, least first), of the entries the walk does not reach, at its offset (the ruled text, 2026-10-22); the last pass takes them by their bytes (a `BTreeSet`), never in the `HashMap`'s order, so no seed decides between them (the seed fold of #645). The whole path's verdict is a `Kind` and names no entry. A one-flag predicate (is the entry spent by some raw entry?) gives the same verdict, the refusal set being empty exactly when every entry is reachable (a txid is a hash: no chain of spends returns), but not the same entry: beside the subject, a raw `X` nothing spends and its parent `Y` that only `X` spends are both unreached, and the flag names `X` even when `Y` is earlier (`an_unreached_parent_earlier_by_the_trie_order_is_the_entry_named`, red on the flag predicate). No flag can stand in for the edges: two BEEFs with the same flags can leave different entries unreached. Position is not judged: the TS writer puts proven entries first, so a raw unproven ancestor can follow its proven descendant (the bsv-dd x402 refund, P0-65), and this crate's `to_binary_atomic` (the same sort, no cut) wrote such an ancestor after the subject until it emitted the closure. The graph follows the inputs of every raw entry, proven or not (the owner's ruling, 2026-10-22); TS ≥ 3 cuts it at each proven transaction (ts-stack `Beef.ts:420-434`) and refuses a raw ancestor behind a proof, a stated divergence (the root `CLAUDE.md`). The BRC-62 clause (an unproven transaction spends earlier transactions) is unchanged. The stream keeps the edges: under a subject each raw transaction's entry holds the txids its inputs name (`TxEntry::prevs`, the Lean's `prevs`), and the walk marks entries in place (`reached`, no table beside the index). They are kept only under a subject (the caller's, or the prefix's: the header precedes the first element; `BeefIndex::hold_to_subject`), and `entries()` counts them. `spec_size()` is the Lean's `Index.size`, which counts one edge per input of every raw transaction read, a repeat's again, with or without a subject (a counter, `inputs`; not a table). `model_work()` adds the Lean's atomic end: one pass over the table and the walk's fuel three times (`entries + 3 * (entries + inputs + 2)`). The bound: per element, plus 32 bytes per input of a raw transaction, only under a subject (an input is 41 bytes or more on the wire: linear in the bytes read). Measured (`memory_profiling`): the deep chain under its subject 351 B per element at each of 1,000, 4,000 and 16,000 links (the depths since the #676 fold, each at the same point of the index table's doubling); before speed loop two (#670) the test read 352, 281, 225 B per element at 1,000, 10,000, 100,000 links (0.8.0: 274, 219, 175), and #670 itself 351, 234, 281 at 1,000, 3,000, 10,000, the fall with the depth the table's slack at that point of its step; the bound is 400; 100 proven transactions of 1,000 inputs, 262 KB peak without a subject, 32 B per input under one; the cursor after one proven transaction of 10,000 inputs is 238 B without a subject, 320,305 B under one. The cursor format is BSC3: after the transactions, the inputs counted and the edges, by txid strictly ascending (a list out of order, or edges of a txid the index does not hold raw, is refused); a BSC2 cursor reads as BSC3 with no edge (the walk reaches less: it only refuses more); a BSC3, BSC4 or BSC5 transaction's flags byte is 0 or 2 (the raw bit), any other refused (`Cursor::from_binary`'s rustdoc; the writer never produces another, the parser is public and takes stored bytes). Pinned by `tests/beef_atomic_graph.rs` and the staged vectors `tests/transaction/vectors/atomic-beef.json` (run by `tests/conformance_beef.rs`, the X/Y pair's named entries and offsets pinned there too)
- The atomic writer emits the BRC-95 closure (0.8.1): `Beef::to_binary_atomic` writes the subject and, through the inputs of raw entries, its ancestry up to each entry carrying a BUMP index (matching or not, since #798, as the reference's `bumpIndex` setter empties `inputTxids`, `BeefTx.ts:90-92,219-221`) and each txid-only entry, the BUMPs those of the included entries a BUMP of the BEEF proves, renumbered, each index mapped through them (#798), the copy keeping the source's `input_txids` for an entry held raw and re-scanning them for one held as a transaction alone (the reference's `BeefTx.fromTx`, `Beef.ts:464-467`, #798's fold; an entry held raw and mutated through `tx_mut` counted as held raw, `BeefTx::held_raw`, the reference's re-synced `_rawTx`, `BeefTx.ts:160-169`, #798's second fold), the closure copied from the entries as held, the source never sorted first (`#getBeefForAtomic`, `Beef.ts:375-390`; sorted first until #798's second fold), the reference's sort of the copy as it leaves the entries (the subject last when every entry links, else among those resting on a missing input, ahead of the proven ones; moved last after the sort until #798's fold); every other entry and BUMP is dropped. What `@bsv/sdk` 3 (`#collectAtomicTransactions`) and go-sdk (`selectAtomicBeef`) write; `to_binary` still writes every entry. Since 0.8.8's fold the closure has two doors: `Beef::to_binary_atomic` on a BEEF a caller assembles by hand keeps the sort, and `to_binary_atomic_subject_last`, the transaction door's form, sorts the same and then moves the subject last (BRC-62's rule; the bytes `0.8.7`'s), so the no-txid read of its bytes takes the subject. Pinned by `tests/beef_atomic_graph.rs` (`the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest`, `every_accepted_vector_round_trips_through_the_atomic_writer`)
- A ring of source links terminates (#160): on the wire a raw entry is named by its bytes' hash, so a ring (A spends B, B spends A) is writable only by its input fields, and its inputs never reach a proven entry: `Beef::from_binary` parses it (it judges the frame), the stream with and without its spend checks (each member held to the end, #240), `verify_structure` and `verify_valid` (the sort's `not_valid`) refuse it `InputNamesNoElement`, before any walk, in every order, with or without a BUMP that proves none of it, V1 and V2; `Transaction::from_atomic_beef` returns the subject with that input unlinked (it does not judge the graph) and it does not verify. In memory, since #171, a ring cannot close through the parsed transactions either: an entry mutated through `BeefTx::tx_mut` is renamed by its new hash, so pointing `T0`'s input at its descendant leaves a chain with `T0` missing (`sort_txs` names it, `verify_structure` refuses `InputNamesNoElement`, the writer emits the mutated bytes). A ring is left only in the public `input_txids` cache written by hand on an entry `tx_mut` never touched: `sort_txs` holds every link not valid, `verify_structure` refuses it, `trim_known_proven` stops, and the writer emits the bytes each entry was read with. `add_input_proof` still memoizes the stub before it descends and `to_binary_atomic`'s closure keeps a seen set. Each reader runs on its own thread under a 5 s bound. Pinned by `tests/beef_cycle.rs` (the renamed chain and the cached ring) and `tests/beef_tx_mut.rs`
- `BeefLimits { max_txs, max_bumps }` are memory hints since 0.4.0; `Beef::from_binary_with_limits` is deprecated and refuses nothing by size or count
- JSON serialization matching Go SDK format for cross-SDK compatibility
- Async Broadcaster trait with Teranode and WhatsOnChain implementations, and ARC's, deprecated since 0.9.0 (#350)
- Async ChainTracker trait with WhatsOnChain and BlockHeadersService implementations

Compatible with the TypeScript and Go SDKs through shared binary formats.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports all public types and sighash constants |
| `input.rs` | `TransactionInput` and `Utxo` for transaction inputs |
| `output.rs` | `TransactionOutput` for transaction outputs |
| `transaction.rs` | `Transaction` with parsing, serialization, signing, SPV verification, BEEF ancestry collection; its four serialized fields private and its three caches `OnceLock`s (#843), the three BEEF doors through one private `ancestry_beef` writing the collected order since 0.8.8 |
| `transaction/fields.rs` | `transaction.rs`'s child module (#843): the inline module `sealed` (#869's sixth fold) declares `Fields`, the four serialized fields and the three caches, every field private to `sealed`, and its whole API: `new` (no cache), `read`, `caches` (shared), `write` (the one exclusive door: empties the caches, then lends the four `&mut`), `into_four`, `replace_source` (the linking door: keeps the caches only where the input's `source_txid` is 64 hex digits), `copy_relinked` (`Clone`'s step) and `copy_named` (`clone_for_beef`), which copy the caches only where the copy writes the same bytes, and `names_32_bytes` (the outpoint rule's test); so no write of a field outside `sealed` compiles (E0616, E0451); the reads `version()`, `lock_time()`, `inputs()`, `outputs()`; the doors `set_version`, `set_lock_time`, `inputs_mut`, `outputs_mut`, `parts_mut` (`TransactionPartsMut`, six `&mut`), each clearing every cache before it lends or sets; `from_parts`/`into_parts` (`TransactionParts`, six named fields, lossless since #869's fold; its `Default` `Transaction::new()`'s parts, version 1, since #869's second fold); `Fields::write`, the one place the caches are emptied; the readers' fill (`read_exact`), the three cache fills behind `to_binary`, `to_hex`, `hash`, the serializer, `clone_for_beef`, `Clone`, `Debug`; `outpoint_txid`/`outpoint_txid_bytes` (#869's second fold), the serializer's one rule for an input's outpoint txid (its `source_txid` when 64 hex digits, else the linked source's hash, else zeros), read by the serializer, its iterative pre-hash, `clone_for_beef`'s repair (every input the rule reads through its source named by the source's id, so a BEEF's stored copy keeps the law) and `replace_source`, the crate's linking door (`beef.rs`' `add_input_proof` and `find_transaction_for_signing`), which keeps the caches when the input's txid parses and empties them otherwise; its units `transaction/link_source_869_tests.rs`; `outpoint_txid_name` (#869's third fold), the txid an input's outpoint names as the BEEF graph keys it (the text when 64 hex digits, else the linked source's id, else the text as given; no scan when no source is linked), read by `input_txids`, `trim_known_proven` and the in-memory judge (`spent_txids`, `content_refused`); the test door `with_cached_bytes_for_test` (tests and `internal-test-doors` alone); the `compile_fail` doc tests (`tx.version = 2`, `tx.lock_time = 7`, `tx.inputs.push(..)`, `tx.outputs.push(..)`, a write through `outputs()`, a read held across `inputs_mut()`, `tx.invalidate_caches()`, a struct literal). `tests/arch_field_writes_843.rs` pins `sealed`'s text (items by signature, its tokens' digest), the module declarations and, lexically, where a cache is filled (#869's sixth fold; the fifth's per-function rules gone, the compiler holding every write) |
| `source_link.rs` | An input's `source_txid` against its linked source's id (#848), beside the outpoint rule it reads (`outpoint_txid`, `outpoint_txid_bytes`; a module of its own for `fields.rs`' 800-line ceiling): `source_named_otherwise`, the linked source of an input whose 64-hex text (either case) is not that source's id, by the source's cached hash, `None` for every other input (nothing linked, the text the source's id, a text that does not parse): the one judgment `sign` and `verify.rs` share, the reference's `Transaction.ts:974-979,1423-1428`; `refuse_at_sign`, `sign`'s pass over every input before any template (a source with an input or a merkle path refused, `Input N sourceTXID does not reference its supplied source transaction.`, a descriptor exempt, `:964-984`) |
| `verify.rs` | The existing SPV graph walk (each input judged through `spending::judge_input` since #855, its errors unchanged) and chain-parameter variants, sharing fee/value/proof/resource behavior and the per-transaction sighash cache; `sources` refuses an input whose linked source is not the transaction its 64-hex `source_txid` names, for every unproven transaction it reaches, after the linked source's output is found and its amount summed, `Verification failed because input N of transaction <txid> does not reference its supplied source transaction.` (the reference's, `Transaction.ts:1423-1432`; no exemption for a descriptor without inputs, so a `from_ef` transaction is refused in these words, `Input N has no source transaction` until #848), and looks a named txid up in lower case (a text in upper case names the same bytes); since #848's fold refuses, in the reference's words, an input that links no source (`... is missing an associated source transaction. ...`, `Transaction.ts:1396-1400`), whatever another input links, and reads every output's amount before any input and each source amount (`output_total`, `source_amount`: absent or past 21e14 refused in `requireSatoshiAmount`'s words, a total past 21e14 in `addSatoshiAmount`'s, through `amount.rs`; an absent amount read as 0 until then); pinned by `tests/transaction_source_txid_mismatch_848.rs` and `tests/transaction_source_txid_fold_848.rs` (#848); singular work-budget methods keep their signatures, plural `verify_with_work_budgets` / `verify_with_chain_params_and_work_budgets` accept `WorkBudget` and charge each transaction's inputs in order (#519); a proven transaction is judged by `MerklePath::verify`, an offset-0 proof under 100 blocks deep refused in `Invalid merkle path for transaction <txid>` as the reference refuses it (`MerklePath.ts:476-500`, #734) |
| `spending.rs` | The one-input door (#855): `SpendingTransaction` (`from_bytes`, exactly one transaction by `Transaction::from_binary`'s reader under the node's amount rule since #874 (`Transaction::from_binary_as_node`: an output amount any 64-bit value, `from_binary`'s refusal of one of 2^53 or more kept beside the transaction and answered by `verify_input` in the default mode alone, before the index check; every other refusal `from_binary`'s error), held as an `Arc<TxSighashCache>` shared by every input, `Send + Sync`; `input_count`; `verify_input(index, locking_script, source_satoshis, &InputRules)`), the one-shot `verify_input` in the node's argument order, `InputRules` (`reference_default`, `reference_default_with(DefaultMode)`, `under(ScriptFlags)` checked when built, `under_with(ScriptFlags, NodeFigures)`; `with_memory_limit`, `with_work_limit`; private fields, commuting setters), `DefaultMode` (the three default-mode overrides; a word takes none, by type), `NodeFigures` (the node operator's stack-memory policy, consensus figure and number-length policy; the default mode takes none, by type), `InputVerified { work_spent }` (always counted: the door hands the core `u64::MAX` when the rules carry no work limit, the verifiers' own rules unchanged), `InputRefusal::{Transaction, InputIndex, Invalid, Declined}`; and `judge_input`, the crate's one construction of a `Spend` for an input outside `src/script/`, called by the door, `verify.rs` and `beef_stream/spends.rs` (`InputRules::for_verifier` leaves their word for `Spend::validate` to check, so their words stay), `sighash_of` (the transaction's midstates, `verify.rs`'s until #855). The door is the node's script check and never its transaction check (its rustdoc). Pinned by `tests/verify_input_door.rs`, `tests/verify_input_door_fold_855.rs`, `tests/verify_input_door_amount_874.rs`, `tests/verify_input_door_source_amount_874.rs`, `tests/arch_one_input_core.rs`, `tests/arch_door_says_what_spend_says_855.rs`, `fuzz_verify_input` |
| `work_budget.rs` | `#[non_exhaustive] WorkBudget` with readable public `per_input: Option<u64>` and `per_transaction: Option<u64>` fields, `new()` and derived `Default` both unbounded, const `with_per_input` / `with_per_transaction` setters; common input accounting and the public transaction-total `charge(self, &mut total, input, work)`, the rule's one implementation for the verifiers and a host that judges inputs itself (#519, #527, #567) |
| `verification_flags.rs` | Checks tip + 1, then calls `ChainParams::word_for_input(Word::Standard, ...)`; the public resolver owns the no-tip latest-era rule and returns `NotJudgedCause`, never a script failure (#452, #520) |
| `verify_refusal.rs` | What `Transaction::verify` answers for an input's script `Err` (#38): a decline (`resource_limit` `Some`) is `Error::ScriptEvaluationDeclined { input_index, limit }`, the reference's `ScriptResourceLimitError` kept apart; a verdict `TransactionError("Script validation failed for input N: …")` |
| `amount.rs` | The one judgment of an amount read from a transaction's bytes (#844): `read_amount` (the readers' four sites save the script offsets, which skip it) and `safe_amount` (the raw-entry scan and the writers' check), an amount above 2^53 - 1 refused in the reference's words, `Number can only safely store up to 53 bits` (`BigNumber.ts:628`); `UNSAFE_WRITE`, the reference's writer's words for the same amount, `The number is larger than 2 ^ 53 (unsafe)` (`BigNumber.ts:462`), the BEEF writers' refusal since #844's fold; `AmountRule` (#874), the reader's amount rule: `Reference` (`from_reader` and every public reader) or `Node` (the door's: any 64-bit value read, one of 2^53 or more noted and answered as `from_binary`'s refusal in the default mode), the parameter of the one reader `Transaction::read_one`; `held_amount` (#843d7), `read_amount`'s judgment for a door that reads no bytes (`from_json`'s field-built output), and `written_amount` (#843d7), the EF writer's: an amount of 2^53 or more refused as `TransactionError` in `UNSAFE_WRITE`'s words at `to_ef`'s two amount lines, as the reference's `#writeEF` throws (`Transaction.ts:1150,1158`), and `unnamed_source_amounts` (#843d7's fold), the same refusal for an input naming no txid over every output of its source and of each source reached through inputs naming no txid, each source once, ahead of that input's other checks, as the reference writes that outpoint from the source's `hash()` (`:1137-1138`); the plain writer (`to_binary`, `to_hex`, `hash`, `id`) comes through neither: the node's serializer, any 64-bit amount its eight bytes, decided 2026-11-12 and stated against the reference's throw (the root list's #844 row; `tests/transaction_amount_doors_843d7.rs`); `add_amount`, a sum of a caller's amounts past 21e14 (`MAX_SATOSHIS`) refused in the reference's `addSatoshiAmount` words (`fee`, `get_fee`; past `u64` from #868 until #871), and `require_satoshi_amount`, a caller's amount absent or past 21e14 refused in its `requireSatoshiAmount` words (#871): the one place for both bounds |
| `tx_json.rs` | JSON serialization/deserialization matching Go SDK's `MarshalJSON`/`UnmarshalJSON`; a field-built input's `txid` member exactly 64 hex digits, held in lower case, else `Invalid txid of input N: expected 64 hex digits` (#845); a field-built output's `satoshis` of 2^53 or more refused in the byte readers' words, `Number can only safely store up to 53 bits`, before its script is read (#843d7; held until then) |
| `merkle_path.rs` | `MerklePath` (BRC-74 BUMP) for merkle proofs; its readers are the BEEF reader's BUMP decoder (#167) |
| `merkle_path_walk.rs` | The cached walk from a level-0 leaf to the root, `RootWalker` (the reference's `computeRootCached`, `MerklePath.ts:335-366`), and `hash_pair`; `pub(super)` for the constructors' root check and `compute_root` (#93 P0); `hash_pair` refuses a text with a non-hex character in the reference's words, `Invalid hex string` (`INVALID_HEX`, `is_reference_hex`, shared with the writer), as its `hashPair` throws (#817); every other text is paired as the reference's `hashPair(right, left)` reads it, the two texts concatenated, one leading `0` when the total length is odd, decoded once and reversed whole (#817's transaction fold: until then a side of odd length was dropped; `tests/merkle_path_hash_pair_817.rs`) |
| `merkle_path_legal.rs` | The constructor's legal offsets per level above 0, kept in the order level 0's leaves name them, and the off-path refusal in the reference's words with that list (`MerklePath.ts:220-235`, #631); `rooted`, the root check's end: a level 0 of duplicates alone refused as `Transaction ID is undefined` (`:241-263`, `:342-343`, #641); `no_levels`, the constructors' refusal of a path with no levels (`:198-200`, #649); `MerklePath::level0`, level 0's leaves or none, the one way every walk reads level 0 (#649) |
| `merkle_path_verify.rs` | `MerklePath::verify`, the reference's (`MerklePath.ts:476-500`): the root, then at level-0 offset 0 alone the tracker's `current_height`, `block_height + 100 > height` (in `u64`) answering `Ok(false)` before the root is asked, else `is_valid_root_for_height`; `Transaction::verify`'s proof check (#734) |
| `merkle_path_603_tests.rs` | #603's witnesses for `MerklePath`'s constructor rules, `combine` and `trim` (test-only, wired in `mod.rs`): the reference's recordings in `tests/vectors/merkle_path_603.json` over BUMPs of the sibling's `corpus/wire/bump.jsonl` and the conformance corpus |
| `beef.rs` | `Beef` (BRC-62/95/96): the type, the public readers (over `beef/collect.rs`), `verify_structure`, sorting (`dependency_order`, crate-private: the sort's order from the entries alone, `sort_txs` reorders by it and `merge_beef` walks a source by it unsorted, #621's second fold; kept here, in the nightly's `beef*.rs` mutation selection), `hold_order` (crate-private, 0.8.8: a BEEF a transaction door assembles holds its entries as they stand, the collected order the transaction doors write), merging, the writers (`to_binary`), logging; the atomic writer moved to `beef_atomic.rs` in 0.8.8's fold for the line ceiling |
| `beef_atomic.rs` | `beef`'s child module by `#[path]`, in the nightly's `beef*.rs` mutation selection: the Atomic BEEF writer, moved from `beef.rs` in 0.8.8's fold for its line ceiling. `Beef::to_binary_atomic` (the Beef-level door, on a BEEF a caller assembles by hand) writes the BRC-95 closure in its documented dependency sort (#798); `to_binary_atomic_subject_last` (crate-private, the transaction door's form, `Transaction::to_atomic_beef` and `legacy_to_beef`'s atomic leg) sorts the same closure and then moves the subject last (BRC-62's rule, 0.8.8's fold), through one shared `atomic_bytes` body: `proves`, `atomic_closure` (the walk, the renumbered BUMPs, the sort and the transaction door's move at its end) |
| `beef/collect.rs` | The whole-BEEF reader: the streaming decoder's collect mode collected into a `Beef`, with the stream's judge beside it (#86); `bumps_as_read`, `merge_beef`'s pre-pass (#621): each BUMP written alone, read by `Bump::read_alone`, its offsets moved to its place in the frame, folded by the same judge and taken to its in-memory form in `collect`'s order, so a refusal is the reader's own (the judge's earlier `RootNotCarried` ahead of a later BUMP's decoder refusal); after the writers' check nothing past the BUMPs is refused, so no state takes a slow path |
| `beef/prepass_621_tests.rs` | #621's differential: the pre-pass against the oracle (`snapshot_round_trip`) on the 338 sweep BEEFs under fourteen states each (since #844's fold 356 under seventeen states, three holding a 2^53 output: 6,052, 2,416 `Ok`, 3,636 refused, 1,761 by the reader, 248 the judge's `RootNotCarried`, the fold's fifteen recorded control BEEFs; 363 under the seventeen since #817's transaction fold brought the two V2 BEEFs of `transaction_fold_817.json`'s `signing` group: 6,171, 2,467 `Ok`, 3,704 refused, 1,789 by the reader, 252 the judge's `RootNotCarried`; 361 under the seventeen since 0.8.8's `beef_tx_order.json` brought its witnesses' five distinct V1 BEEFs: 6,137, 2,443 `Ok`, 3,694 refused, 1,789 by the reader, 252 the judge's `RootNotCarried`; 341 and 5,797 until then, 2,263, 3,534, 1,740, 245; 338 under fourteen until #844's vector, 4,732: 2,215, 2,517, 1,726, 243; 337 and 4,718 before #841's vector: the census pinned, the totals derived from it, the re-derivation in the test's comment), the cold read's state (a parsed entry caching a transaction and more, by `merge_transaction` and a hand push: 676 refused alike, twice the sweep's count; built through `Transaction::with_cached_bytes_for_test`, `cfg(any(test, feature = "internal-test-doors"))` since #869's fold (`cfg(any(test, fuzzing))` until then), since #840's reader refuses the buffer; #621's fold) and #817's 27 recorded states (`tests/support/beef_merge_states_817.rs`, reached through the lib's `#[cfg(test)] extern crate self as bsv_rs`): the same `Ok` or the same `Err`, the merged bytes the snapshot's merged into two targets, the target untouched on `Err` |
| `beef/reference_603_tests.rs` | #603: the surviving mutants' tests, the sibling's `corpus/wire` rows against the reference's answers (`tests/vectors/beef_reference_603.json`); a test module inside the BEEF surface's `--lib` selection, outside the `beef*.rs` mutation glob |
| `beef/index.rs` | The txid index and the edit door: `rebuild_index`, `find_txid`, `find_txid_mut`, `replace_or_append` (an entry stored at the held txid's position, else appended, the reference's `#replaceOrAppendTx`, `Beef.ts:531-540`; every replacing merge door since #764's fold); `index_of` checks a hit against the entry's txid and `refresh_mutated` re-reads each entry mutated through the deprecated `BeefTx::tx_mut` ahead of a whole-BEEF reader (#171). Since #817: `edit_tx` (the eager edit door: a copy edited, the entry repaired and re-keyed at once, `Err` for a txid not held as a transaction or an edited txid another entry holds) and `reindex` (the rebuild after a hand edit of `txs`); `indexed_len`, the entry count the index was built for: `position` (every `&mut` door's lookup) brings the index up first (`sync_index`: a grown count with the indexed prefix still ending where it did, `indexed_prefix_holds`, one lookup, indexes the tail alone; a shrunk count or a moved prefix rebuilds whole) and rebuilds whole on a hit naming another entry; `index_of` (the `&self` lookups) scans only the unindexed tail on a miss after a grown count with the prefix in place, and `txs` whole after a shrink, a moved prefix or a mismatched hit; `push_tx` keeps the count in step; `index_entry` (the pushed tail, `push_tx`) and `rebuild_index` note two entries of one txid (`holds_twins`), so `edit_tx` keeps the old key on such a BEEF and the other entry stays found (#817's second fold); the fold of the rebuild made the response cost what the edit was, its unit pins `beef/index_817_tests.rs`; `edit_tx` compares the edited copy's bytes with the original's before it rewrites (a no-op keeps the txid and the bytes held) and refuses raw bytes that do not parse as one transaction as `BeefError` (a byte after the transaction among them since #840, `index_817_tests.rs`' `an_edit_of_raw_bytes_with_a_trailing_byte_is_refused_840`) |
| `beef_writable.rs` | `beef`'s child module by `#[path]`, in the nightly's `beef*.rs` mutation selection: `Beef::to_binary`, `to_hex` and `to_writer` (moved from `beef.rs`, #817) and the BEEF writers' one read-only check (`check_writable`, `check_writable_in`, #817), in the order the reference meets the states (an empty txid-only txid; a BUMP's non-hex hash; each entry's reference refusal in written order; the version word; the BUMPs' own refusals; each entry's own), `write_checked` (the bytes after the check) and `snapshot_verdict`, `merge_beef`'s verdict: the source's check over `written_order`, then `bumps_as_read` (`beef/collect.rs`), a pre-pass that writes no entry (#621, after #817; the literal round trip, its bytes in that order and `Beef::from_binary` of them, until then, about twice the merge's cost), proven equal to that round trip, kept as the oracle `snapshot_round_trip` and `merge_snapshot_oracle` (`#[doc(hidden)]`) under `cfg(any(test, feature = "internal-test-doors"))` (`cfg(any(test, fuzzing))` until #869's second fold; `tests/arch_test_doors_869.rs`); the two fallible merge doors `merge_raw_tx` and `merge_beef` (moved from `beef.rs` for its line ceiling, #817) |
| `beef_tx_writer.rs` | `beef_tx`'s child module by `#[path]`, in the same selection: `BeefTx::to_writer` and its checks (#817): `reference_refusal` (a txid-only entry outside V2, a non-hex txid: the reference's words), `amount_refusal` (an entry holding a transaction with an output amount of 2^53 or more, any output, in the reference's writer's words, `The number is larger than 2 ^ 53 (unsafe)`, ahead of every other check, at `BeefTx::to_writer` and, over every held entry, at the head of `Beef`'s check, `to_binary` and `to_binary_atomic`, as the reference serializes every held transaction first; #844's fold, the reader's words in `own_refusal` until then), `own_refusal` (a txid not 64 hex digits; an entry whose written bytes are not one transaction: the bytes held, else a parsed transaction's cache, which `Transaction::from_binary` set to the whole buffer it read a prefix of until #840, one transaction since, so the scan holds on its own and no public door reaches it at this tip; a parsed entry unscanned until #621's fold), `empty_txid`, `write_unchecked` (the bytes after the check, each entry's `written_tx_bytes` on every path since #621's fold, no panic left), `RAW_TX_EXPECTED` |
| `beef_raw_frame.rs` | Whether bytes are exactly one transaction (#817): `one_transaction`, the reference's `scanRawTransaction` reads (varints and lengths, linear, no allocation) in its words where it refuses, bytes after the lock time in this crate's, and an output amount of 2^53 or more in the transaction reader's (#844, where the reference's scan skips it: the scan and the reader one judgment); read by `BeefTx::from_raw_tx` and the writers' check of every entry's written bytes (a parsed one's cache too since #621's fold). Its units `raw_frame_817_tests.rs` (outside the `beef*.rs` glob, as `beef/reference_603_tests.rs` is: the scan against `Transaction`'s reader on every cut and changed byte, the recorded words) |
| `beef/merge_entry.rs` | `merge_beef_entry` (crate-private): one source entry of `merge_beef` by the reference's `#mergeBeefTxEntry` (`Beef.ts:950-967`): a txid-only one appended only where nothing is held, a source entry with data merged as its written bytes (`BeefTx::written_tx_bytes`; a parsed one's serialization, no object, link or path: the snapshot's form, #621's second fold) only where nothing or a txid alone is held, an entry held raw or parsed left alone (its index and links kept; replaced until #621's fold); filed under `BeefTx::held_txid`, else its bytes' hash, never `txid()`'s reading of a stale cache (#621); `written_order`, the source's entries in the order the reference's `toBinary` writes them (as read while `Beef`'s crate-private `wire_order` mark holds, the reader's, cleared by every merge door and the sort; else the sort when needed, a `tx_mut` entry read with its refreshed inputs; else held; #621's second fold); `store_raw_entry`, the one body `merge_raw_tx` (after its hash) shares |
| `beef/merge_entry_621_tests.rs` | #621's witnesses: a source entry's held txid kept by `merge_beef` (a sentinel txid, no hash run); an entry edited inside the deprecated `tx_mut` borrow after its id was read filed under its fields' hash (`an_entry_edited_inside_tx_mut_is_filed_under_its_fields_hash_843`) and written from its fields by `Beef::to_writer` and `BeefTx::to_writer`, as by `to_binary` and `merge_beef` (`to_writer_writes_a_tx_mut_entry_from_its_fields_843`); until #843 both pinned a stale cache, the second planted through `Transaction::with_cached_bytes_for_test`, a state #843's doors make unbuildable, so both were restated on the law (RED on `7df16cf6` for the writer) |
| `beef/merge_graph.rs` | `merge_transaction`: the transaction's path merged through `merge_bump`, its index taken, and the inputs' `source_transaction`s merged and walked while an entry ends with no index, a stack as the reference's `#mergeTransactionGraph` (`Beef.ts:849-901`); ancestors stored without links, the transaction given as given (#764) |
| `beef/in_memory.rs` | The stream's rules on the in-memory forms: `Bump::to_merkle_path`, `Bump::in_memory` (each level by offset, the `u32` height bound) and `Bump::read_alone` (one BUMP by the decoder, #167), the walk on a `MerklePath`, `check_transaction` on a `BeefTx`, the atomic table (#86) |
| `beef_tx.rs` | `BeefTx` wrapper, `TxDataFormat`, format constants; `BeefTx::from_reader` reads one entry (no BEEF reader calls it since #86); `tx_mut` (deprecated since #817 for `Beef::edit_tx`) makes the transaction the entry's only reading (#171): the bytes and txid it was read with dropped, the BUMP index kept, `input_txids` refreshed (`refresh`) by the BEEF's next whole-BEEF reader or `Beef::reindex`, which re-key the index; `has_txid` checks an index hit, so a renamed entry is not found by its old txid |
| `beef_stream.rs` | The streaming reader: `BeefDecoder` (and its collect mode, the whole reader's parser), `BeefStream`, `BeefIndex`, `verify_stream`, `Verdict`, `Cursor`, `SpendRefusal` (its `Display` beside the enum, one sentence per arm, the texts pinned in `tests/beef_stream.rs`'s `a_spend_refusal_prints_*`, #213); the specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean |
| `beef_stream/reason.rs` | The refusal's names, `Kind` (twenty-six, `Kind::ALL`; `LeftDuplicateBelow` since #167's re-read) and `Reason`, re-exported from `beef_stream`; both `#[non_exhaustive]` (#86, #167): a `match` outside the crate ends in a wildcard arm |
| `beef_stream/budget.rs` | The readers' `set_work_limit`, adjacent `with_work_budget` / `with_transaction_work_budget`, `work_spent` total and `set_memory_limit` (#373, #378, #519); limits remain local and absent from cursors; BSC5 carries charged work across input pauses; `Verdict::work_spent` exposes the total from a transaction-budget cause |
| `beef_stream/evaluation.rs` | Local `Evaluation { work, memory, chain }`, `with_chain_params` on sync/async readers and `verify_stream_two_pass_with_chain_params`; no caller-made word or era resolver |
| `beef_stream/spends.rs` | In-order/deferred input checks (each input judged through `spending::judge_input` since #855, its refusals unchanged), only referenced source scripts retained, one shared sighash cache; source heights from the verified BUMP index; scope refusals are `SpendRefusal::NotJudged { input, cause }` before script parsing/execution (#452) |
| `beef_stream/deferred.rs` | What the stream holds for a parent not read yet (#240): `HeldTx` (a transaction's index entry, its raw bytes dropped), `TxFields` (one fold for a transaction read in order and one released), `Deferred` (the held entries by offset, the txids each waits on, the ready ones, the bytes held; no bound; `unresolved`, what the end refuses), the index's and the reader's sides of the release (`BeefIndex::held_for_a_parent`, `BeefIndex::release_one`, `Judge::release_next`, one per step; `AsyncStreamVerifier::release_all`, every released one at once), `write_held` and `read_held` (a BSC4 cursor's held entries) |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `credential_debug.rs` | The secret Debug fold (2026-11-10): the redacting `Debug` of `ArcConfig`, `TeranodeConfig`, `WocBroadcastConfig`, `LivePolicyConfig` (`api_key`) and `BlockHeadersServiceConfig` (`auth_token`), every other field as the derive printed it, the credential `Some(<redacted>)` or `None`, never its value or length, the URL through `crate::util::debug_redact::Url` (user info, query, fragment `<redacted>`; the second fold); the broadcasters, tracker and fee model holding one implement no `Debug`; pinned by `tests/secret_debug.rs` |
| `fee_models/` | `SatoshisPerKilobyte`, `LivePolicy`, `LivePolicyConfig`, default constants |
| `broadcaster.rs` | `Broadcaster` trait, response/failure types, helper functions |
| `broadcasters/` | `TeranodeBroadcaster`, `WhatsOnChainBroadcaster`, `ArcBroadcaster` (deprecated, #350) |
| `chain_tracker.rs` | `ChainTracker` trait, `MockChainTracker` (a synthetic mainnet mining tip at its height, `with_mining_tip`; #218), `AlwaysValidChainTracker` |
| `chain_trackers/` | `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, `BlockHeadersServiceConfig` |

## Budgets

`Transaction::verify_with_work_budget(tracker, fee_model, memory_limit, work_limit)`
adds `Option<u64>` beside the memory budget. Live doors use
`verify_with_chain_params_and_work_budget(tracker, fee_model, memory_limit, work_limit, chain)`.
Existing `verify` and `verify_with_chain_params` default to `None`. The reference's
`verify` has no work bound; `None` keeps that behavior byte for byte.

The bound lives in `SpendParams::work_limit` (also `TxSpendParams`), passed anew
for each input by the whole-transaction evaluator and by
`StreamVerifier::set_work_limit` / `with_work_budget` (the async reader too).
The interpreter counter is `Spend::charge_work` in `src/script/spend/limits.rs`, one
unit per reached opcode plus bytes hashed, including double-hash intermediates
and uncached sighash midstates. Charges precede the work; `work_done` is work
already charged, not the next refused charge. Each input gets the entire budget;
a proof or structure-only read executes no script and spends no work.

Exhaustion is `NotJudgedCause::WorkBudgetExceeded { input, budget, work_done }`,
carried by `Error::TransactionNotJudged` or `SpendRefusal::NotJudged` and then
`Verdict::NotJudged`. A spend inside the budget retains its verdict; memory
exhaustion retains `ScriptEvaluationDeclined` / `SpendRefusal::Resource`.
The bound is a service door's policy, never a consensus rule. Each captain names
its value in the door's brief beside the sibling's memory policy rows. A work
counter cannot interrupt one arithmetic opcode, so elapsed time needs an
external bound. Stream budgets are local configuration, absent from cursors and
reapplied after every resume. The `#[non_exhaustive] WorkBudget` has readable
public `per_transaction` and `per_input` fields (both `Option<u64>`); `new()`
and derived `Default` leave both unbounded, and const `with_per_input` and
`with_per_transaction` setters configure them. External destructures use `..`.
The plural whole-transaction methods accept this type. Stream readers keep
`with_work_budget` / `with_transaction_work_budget` and expose
`work_spent()` for the current or most recently evaluated transaction. Each
input's spent work is charged after evaluation, in input order, and the total
resets per transaction. A total strictly above its bound yields
`TransactionWorkBudgetExceeded { input, limit, total }`; the cause and
`Verdict::work_spent()` expose the crossing total. Other verdicts return `None`
from that accessor; successful totals are available on the reader. A per-input
refusal keeps its class even if its charged work also passes the total bound.
A host that runs each input itself calls the public `WorkBudget::charge`
(the verifiers' own method) once per input in order and gets the same cause
(#567).
The total is checked after an input, never inside one: the crossing input runs
under `per_input` alone (unbounded without it), so a door passes both bounds.
BSC5 cursors preserve charged totals; limits are still reapplied. Old unmetered
cursors replay their prefix when a budget is introduced. The toolbox deletes
its door-side sum and passes the transaction limit; the CLI adds the new
not-judged row. See `tests/transaction_work_budget_378.rs` and
`tests/transaction_work_budget_519.rs`.

## Core Types

### TransactionInput

```rust
pub struct TransactionInput {
    pub source_transaction: Option<Box<Transaction>>,  // Full source tx (preferred for BEEF)
    pub source_txid: Option<String>,                   // TXID if source tx unavailable
    pub source_output_index: u32,
    pub unlocking_script: Option<UnlockingScript>,     // Populated after signing
    pub unlocking_script_template: Option<Box<ScriptTemplateUnlock>>,
    pub sequence: u32,                                 // Default: 0xFFFFFFFF
}

impl TransactionInput {
    pub fn new(source_txid: String, source_output_index: u32) -> Self
    pub fn with_source_transaction(tx: Transaction, output_index: u32) -> Self
    pub fn get_source_txid(&self) -> Result<String>      // Falls back to source_transaction
    pub fn get_source_txid_bytes(&self) -> Result<[u8; 32]>  // Internal byte order
    pub fn source_satoshis(&self) -> Option<u64>
    pub fn source_locking_script(&self) -> Option<&LockingScript>
    pub fn set_unlocking_script_template(&mut self, template: ScriptTemplateUnlock)
    pub fn set_unlocking_script(&mut self, script: UnlockingScript)
    pub fn has_source_transaction(&self) -> bool
}
```

Note: `unlocking_script_template` is not cloned when cloning `TransactionInput` (templates contain closures).

### Utxo

```rust
pub struct Utxo {
    pub txid: String,                    // TXID of the source transaction
    pub vout: u32,                       // Output index in source transaction
    pub satoshis: u64,                   // Amount in the output
    pub locking_script: LockingScript,   // Spending conditions
}
```

Used with `Transaction::add_inputs_from_utxos()` for convenient batch input creation without needing full source transactions.

### TransactionOutput

```rust
pub struct TransactionOutput {
    pub satoshis: Option<u64>,           // None for change outputs before fee calc
    pub locking_script: LockingScript,
    pub change: bool,                    // If true, amount computed during fee()
}

impl TransactionOutput {
    pub fn new(satoshis: u64, locking_script: LockingScript) -> Self
    pub fn new_change(locking_script: LockingScript) -> Self
    pub fn get_satoshis(&self) -> u64      // Returns 0 if None
    pub fn has_satoshis(&self) -> bool
    pub fn serialized_size(&self) -> usize // 8 + varint + script_len
}
```

### Transaction

```rust
pub struct Transaction {
    pub metadata: HashMap<String, Value>, // Not serialized
    pub merkle_path: Option<MerklePath>,  // SPV proof (stops BEEF ancestry walk)
    // Private since #843: `fields: Fields` (fields.rs), version (default 1), inputs, outputs,
    // lock_time (default 0) and the caches cached_hash, raw_bytes_cache, hex_cache (OnceLock),
    // its fields visible to fields.rs alone (#869's fold)
}

pub struct TransactionParts { pub version: u32, pub inputs: Vec<TransactionInput>, pub outputs: Vec<TransactionOutput>, pub lock_time: u32, pub metadata: HashMap<String, Value>, pub merkle_path: Option<MerklePath> }
pub struct TransactionPartsMut<'a> { /* the six fields, each `&'a mut` */ }  // #[derive(Debug)]; TransactionParts derives Debug, Clone; its Default is Transaction::new()'s parts (version 1, #869's second fold)

impl Transaction {
    // Constructors
    pub fn new() -> Self
    pub fn with_params(version, inputs, outputs, lock_time) -> Self
    pub fn from_parts(parts: TransactionParts) -> Self   // the six as given
    pub fn into_parts(self) -> TransactionParts           // all six: from_parts(tx.into_parts()) is tx (#869's fold)

    // The four fields (#843): read through &self, written only through &mut doors
    // that clear every cache before they lend or set; `invalidate_caches` removed
    pub fn version(&self) -> u32
    pub fn lock_time(&self) -> u32
    pub fn inputs(&self) -> &[TransactionInput]
    pub fn outputs(&self) -> &[TransactionOutput]
    pub fn set_version(&mut self, version: u32)
    pub fn set_lock_time(&mut self, lock_time: u32)
    pub fn inputs_mut(&mut self) -> &mut Vec<TransactionInput>
    pub fn outputs_mut(&mut self) -> &mut Vec<TransactionOutput>
    pub fn parts_mut(&mut self) -> TransactionPartsMut<'_>

    // Parsing: exactly one transaction, a byte after the lock time refused in the
    // reference's words (#840: `Serialized transaction contains trailing data`,
    // EF `Serialized EF transaction contains trailing data`); the cache the
    // transaction's bytes alone
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_ef(ef: &[u8]) -> Result<Self>           // Extended Format (BRC-30)
    pub fn from_hex_ef(hex: &str) -> Result<Self>
    pub fn from_reader(reader: &mut Reader) -> Result<Self> // one from the front, the rest unread; no cache (#840)
    pub fn from_beef(beef: &[u8], txid: Option<&str>) -> Result<Self>
    pub fn from_atomic_beef(beef: &[u8]) -> Result<Self>
    pub fn from_json(json: &str) -> Result<Self>         // Go SDK-compatible JSON
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets>  // reads the lock time, refuses what follows (#840)

    // Serialization
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_hex(&self) -> String
    pub fn to_ef(&self) -> Result<Vec<u8>>
    pub fn to_hex_ef(&self) -> Result<String>
    pub fn to_beef(&self, allow_partial: bool) -> Result<Vec<u8>>      // BEEF V2
    pub fn to_beef_v1(&self, allow_partial: bool) -> Result<Vec<u8>>   // BEEF V1 (BRC-62), no TXID-only entries
    pub fn to_atomic_beef(&self, allow_partial: bool) -> Result<Vec<u8>>
    pub fn to_json(&self) -> Result<String>              // Go SDK-compatible JSON
    pub fn to_json_pretty(&self) -> Result<String>       // Pretty-printed JSON

    // Hashing
    pub fn hash(&self) -> [u8; 32]        // Double SHA-256 (internal byte order)
    pub fn id(&self) -> String            // TXID (reversed hash as hex)
    pub fn hash_hex(&self) -> String

    // Building
    pub fn add_input(&mut self, input: TransactionInput) -> Result<()>
    pub fn add_output(&mut self, output: TransactionOutput) -> Result<()>
    pub fn add_p2pkh_output(&mut self, address: &str, satoshis: Option<u64>) -> Result<()>
    pub fn add_op_return_output(&mut self, data: &[u8]) -> Result<()>          // OP_FALSE OP_RETURN <data>
    pub fn add_op_return_parts_output(&mut self, parts: &[&[u8]]) -> Result<()> // Multi-part OP_RETURN
    pub fn add_hash_puzzle_output(&mut self, secret: &str, public_key_hash: &str, satoshis: u64) -> Result<()>
    pub fn add_input_from_tx(&mut self, source_tx: Transaction, vout: u32, template: ScriptTemplateUnlock) -> Result<()>
    pub fn add_input_from(&mut self, prev_txid: &str, vout: u32, prev_locking_script: &LockingScript, satoshis: u64, template: ScriptTemplateUnlock) -> Result<()>
    pub fn add_inputs_from_utxos(&mut self, utxos: &[Utxo]) -> Result<()>      // No template set
    pub fn update_metadata(&mut self, key: &str, value: Value)
    pub fn input_count(&self) -> usize
    pub fn output_count(&self) -> usize

    // Inspection
    pub fn is_coinbase(&self) -> bool       // True if single input with null TXID
    pub fn has_data_outputs(&self) -> bool   // True if any output has OP_RETURN
    pub fn total_input_satoshis(&self) -> Result<u64>  // Sum of all input satoshis
    pub fn total_output_satoshis(&self) -> u64         // Sum of all output satoshis

    // Signing & Fees
    pub async fn sign(&mut self) -> Result<()>
    pub async fn fee(&mut self, fee_sats: Option<u64>, change_distribution: ChangeDistribution) -> Result<()>  // refuses as the reference does (#871)
    pub fn get_fee(&self) -> Result<u64>  // every output's amount required; 0 where the reference is negative
    pub fn estimate_size(&self) -> usize

    // SPV Verification
    pub async fn verify(&self, chain_tracker: &dyn ChainTracker, fee_model: Option<&dyn FeeModel>, memory_limit: Option<usize>) -> Result<bool>
    pub async fn verify_with_chain_params(&self, chain_tracker: &dyn ChainTracker, fee_model: Option<&dyn FeeModel>, memory_limit: Option<usize>, chain: &ChainParams) -> Result<bool>
    // memory_limit: the reference's third parameter; None uncapped, as its default (#331), Some(n) n bytes per stack
    // an invalid script: Err(TransactionError("Script validation failed for input N: …"));
    // outside the selected word's scope: Err(TransactionNotJudged { input_index, cause }) (#452)
    // an input stopped at the caller's budget, or by the allocator: Err(ScriptEvaluationDeclined { input_index, limit }) (#38)
}

pub enum ChangeDistribution { Equal, Random }  // the reference's #distributeChange (#868)
pub struct ScriptOffsets { pub inputs: Vec<ScriptOffset>, pub outputs: Vec<ScriptOffset> }
pub struct ScriptOffset { pub index: usize, pub offset: usize, pub length: usize }
```

## JSON Serialization (tx_json.rs)

Cross-SDK compatible JSON format matching Go SDK's `MarshalJSON`/`UnmarshalJSON`:

```rust
// Serialize to JSON
let json = tx.to_json()?;          // Compact JSON
let json = tx.to_json_pretty()?;   // Pretty-printed

// Deserialize from JSON (supports hex-only or field-based)
let tx = Transaction::from_json(&json)?;
```

JSON format:
```json
{
    "txid": "hex...",
    "hex": "full_serialized_tx_hex",
    "inputs": [{ "unlockingScript": "hex", "txid": "hex", "vout": 0, "sequence": 4294967295 }],
    "outputs": [{ "satoshis": 1000, "lockingScript": "hex" }],
    "version": 1,
    "lockTime": 0
}
```

Deserialization priority: if `hex` field is present and non-empty, reconstructs from hex (matching Go SDK). Otherwise builds from individual fields (`inputs`, `outputs`, `version`, `lockTime`).

## Fee Models

```rust
pub trait FeeModel: Send + Sync {
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>;
}

pub struct FixedFee(u64);                              // Always returns same fee
pub struct SatoshisPerKilobyte { pub value: u64 }      // Fee based on tx size (default: 100 sat/KB)
pub struct LivePolicy { /* ... */ }                    // Fetches rate from a policy endpoint of the caller's (ARC's schema)

// Exported constants
pub const DEFAULT_POLICY_URL: &str;     // "https://arc.gorillapool.io/v1/policy", deprecated (#350)
pub const DEFAULT_FALLBACK_RATE: u64;   // Fallback sat/KB rate
pub const DEFAULT_CACHE_TTL_SECS: u64;  // Cache TTL for live policy
```

`LivePolicy` has `with_url()`, `with_config(LivePolicyConfig)`, `refresh()` (async fetch), `cached_rate()`, `effective_rate()`, `set_rate()`. Config: `LivePolicyConfig { policy_url, api_key, cache_ttl, fallback_rate, timeout_ms }`. No default policy URL since 0.9.0 (#350, the owner's word of 2026-10-27: ARC is deprecated, ARCade is the standard): `new()` (ARC's GorillaPool policy, the reference's) and `DEFAULT_POLICY_URL` are deprecated; `LivePolicy::default()` and `LivePolicyConfig::default()` carry an empty URL, which `refresh()` refuses before any request (`No policy URL: ..`), as a trait impl cannot carry `#[deprecated]`. ARCade serves ARC's schema at `/v1/policy`.

## Broadcasting

```rust
#[async_trait(?Send)]
pub trait Broadcaster: Send + Sync {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult;
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>; // Default: sequential
}

pub type BroadcastResult = Result<BroadcastResponse, BroadcastFailure>;
pub enum BroadcastStatus { Success, Error }
// BroadcastResponse: status, txid, message, competing_txs. Constructors: success(), success_with_competing()
// BroadcastFailure: status, code, txid, description, more. Constructors: new(), with_txid(), with_details()
// transport_fault(): the class of NEVER_SENT, MAY_HAVE_BEEN_RECEIVED, RATE_LIMITED (wait from more's retry_after_ms), as a TransportFault (#87)
// Helpers: is_broadcast_success(), is_broadcast_failure()
```

### Broadcaster Implementations (require `http` feature)

| Broadcaster | Format | Default | Config |
|-------------|--------|---------|--------|
| `ArcBroadcaster` (deprecated since 0.9.0, #350) | Raw tx hex (JSON `rawTx`) | none of this crate's: its deprecated `default()` is `arc.taal.com` | `ArcConfig` (deprecated) |
| `TeranodeBroadcaster` | Extended Format (EF binary) | No default URL | `TeranodeConfig` |
| `WhatsOnChainBroadcaster` | Raw tx hex | `mainnet()`, `testnet()`, `stn()` | `WocBroadcastConfig`, `WocBroadcastNetwork` |

Teranode has `new(url, api_key)` and `with_config(config)` constructors, as the deprecated ARC broadcaster does. WoC has `new(network, api_key)`, `mainnet()`, `testnet()`, `stn()`, `with_config(config)`, `with_base_url(url, network, api_key)`. `WocBroadcastNetwork` enum selects `Mainnet`, `Testnet`, or `STN`.

## Chain Tracking

```rust
#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
    async fn mining_tip(&self) -> Result<Option<ChainTip>, ChainTrackerError> { Ok(None) } // default
}

#[non_exhaustive]
pub enum ChainTrackerError { NetworkError(String), TransportFault { fault: TransportFault, status: Option<u16>, detail: String }, InvalidResponse(String), BlockNotFound(u32), Other(String) }

// Test mocks
pub struct MockChainTracker { pub height: u32, pub roots: HashMap<u32, String>, /* private: the tip set */ }
pub struct AlwaysValidChainTracker { pub height: u32 }
// MockChainTracker: new(height), add_root(height, root), always_valid(height) -> AlwaysValidChainTracker,
//   with_mining_tip(Option<ChainTip>); mining_tip (ChainTracker and Headers alike) is a synthetic mainnet
//   tip at `height` (MTP 1_700_000_000, Genesis 620_538, CSV 419_328, no next block time) unless set (#218)
// AlwaysValidChainTracker: new(height) - always returns true for any root
```

### Chain Tracker Implementations (require `http` feature)

| Tracker | Networks | Config |
|---------|----------|--------|
| `WhatsOnChainTracker` | `mainnet()`, `testnet()` | `WocNetwork` enum |
| `BlockHeadersServiceTracker` | Any (via URL) | `BlockHeadersServiceConfig`, `DEFAULT_HEADERS_URL` |

## MerklePath (BUMP - BRC-74)

```rust
pub struct MerklePath {
    pub block_height: u32,
    pub path: Vec<Vec<MerklePathLeaf>>,  // Tree structure, level 0 = txids
}

pub struct MerklePathLeaf {
    pub offset: u64, pub hash: Option<String>, pub txid: bool, pub duplicate: bool,
}
// Leaf constructors: new(offset, hash), new_txid(offset, hash), new_duplicate(offset)

impl MerklePath {
    pub fn new(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>  // Full validation
    pub fn new_unchecked(block_height, path) -> Result<Self>    // As new, but for the legal offsets above level 0 (#641)
    pub fn from_hex/from_binary/from_reader(...)                // Parsing: the BEEF reader's BUMP decoder (#167)
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self  // Single-tx block
    pub fn to_hex(&self) -> Result<String>; to_binary(&self) -> Result<Vec<u8>>; to_writer(&self, &mut Writer) -> Result<()>  // Serialization; refuses what its bytes cannot carry (#817)
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>  // One cached walk (RootWalker)
    pub async fn verify(&self, txid: &str, tracker: &dyn ChainTracker) -> Result<bool>  // The reference's: at level-0 offset 0 the height asked first, under 100 deep false (#734)
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>  // Same height/root required
    pub fn trim(&mut self)  // Remove unnecessary internal nodes
}
```

One decoder (bsv-rs#167): `from_binary`, `from_hex` and `from_reader` read a BUMP by the decoder that reads one in a BEEF (`Bump::read_alone`, then `Bump::in_memory`), so a BUMP means one thing wherever this crate reads it: a leaf flag `00`, `01` or `02` (`BadFlag` otherwise), an offset within its level (`OffsetOutsideTree`) and once there (`DuplicateOffset` at the second leaf's offset varint), a tree height of 1 to 64, every hashed leaf of level 0 climbing to one root by the stream's walk (`MissingSibling`, `MismatchedNode`, `LeftDuplicateBelow`, `NoTxidAtLevelZero`), a block height that fits the `u32` (`RootNotCarried` at the BUMP); a refusal is `MerklePathError("invalid BUMP at byte N: Reason")`, `N` counted from the BUMP's leading byte, the words after "at byte" the stream's (#167). `from_binary` and `from_hex` take the bytes as one BUMP and refuse a byte after the frame (`TrailingBytes` at its offset, #167); `from_reader` reads one frame and leaves the cursor after it, as TS's `fromBinary` (a reader's) leaves it; `MerklePath::read_bump` in `beef/in_memory.rs` is both. `tests/merkle_path_two_readers_agree.rs` (every BUMP the tree holds and its prefixes and single-byte changes: 0 disagreements) and `fuzz_merkle_path` pin it. A duplicate (flag `01`) at an even offset is read as the reference reads it (#167, the re-read of 2026-10-26: one verdict across the SDKs): the walk pairs the working hash with itself where the duplicate is its sibling, at either offset (`ts-stack@edf6e03` `MerklePath.ts:60`), and refuses a computed sibling that rests on a duplicate at an even offset, as its left child or under a child computed in turn, `LeftDuplicateBelow { level, offset }` at the offset varint of the level-0 leaf whose path needs it, where the reference's walk throws `Missing hash for index N at height N` (`:58`, `:628-631`); `new` and `new_unchecked` read it with `RootWalker`, which gives up there too (`Missing hash at height N, offset N`). Through 0.9.0-beta.1 every path refused it (`BadFlag { byte: 1 }`, a pre-pass, `Duplicate at an even offset`). Pinned by `tests/merkle_path_even_offset_duplicate.rs` on the reference's verdicts (`tests/vectors/merkle_path_even_offset_duplicate_167.json`).

The writers (#817): `to_binary`, `to_hex` and `to_writer` return `Result` and refuse, before any byte is written (a caller's `Writer` untouched on `Err`), a path whose bytes would not frame or would read back as another path: a leaf not flagged duplicate whose hash has a non-hex character, looked for over the whole path before every other check (`Invalid hex string`, the reference's words, `MerklePath.ts:289`, `hex.ts:6-17`, as its writer throws at that leaf whatever else the path holds; #817's fold), then in written order more than 255 levels (`Invalid tree height: N, over the 255 levels a BUMP's tree height byte writes`), a leaf not flagged duplicate with no hash (`Missing hash at height H, offset O`) or a hash of other than 64 hex digits (`Invalid hash at height H, offset O: expected 64 hex digits, got N`), a leaf flagged duplicate that carries a hash (`Duplicate leaf at height H, offset O carries a hash, which a BUMP's duplicate flag cannot write`) or the txid flag (`Duplicate leaf at height H, offset O is flagged txid, which a BUMP's duplicate flag cannot write`; the reference writes `03` and reads it back as a plain duplicate; `combine` can produce it, unchanged). Every other state is written as the reference's `toWriter` writes it, valid or not (validity is the readers' and `verify`'s): no level, 65 to 255 levels, an empty level 0, repeated and illegal offsets, mismatched roots, an upper-case hash. The reference writes the five other refused states as bytes no reader reads back as written (the stated rows in the root `CLAUDE.md`). `Beef`'s writers run the same check on each BUMP (`check_writable`, `pub(crate)`) and write it through `write_unchecked` after their own check (the second change of #817; the lenient writer it replaced is removed). `MerklePath::combine_verified` (`pub(crate)`) is `combine`'s merge once its checks hold, infallible: `Beef::merge_bump` computes both roots and calls it (#817). `new`, `new_unchecked` and `compute_root` refuse a hash a walk pairs that has a non-hex character in `Invalid hex string`, as the reference's `hashPair` throws (`:30-32`); a lone leaf's hash, returned unread, and a leaf no walk reads are not refused there. A hex text of odd length is paired as the reference's `hashPair` pairs it, concatenated with the other side and padded with one leading `0` when the total is odd (until the transaction fold of #817 such a side was dropped; `tests/merkle_path_hash_pair_817.rs` on `tests/vectors/transaction_fold_817.json`). Pinned by `tests/merkle_path_writer_refusals_817.rs` on `tests/vectors/merkle_path_writer_refusals_817.json`.

Validation in `new()`: at least one level (a path with no levels refused as `Merkle Path must contain between 1 and 64 levels`, the reference's sentence, `MerklePath.ts:198-200`, with BRC-74's bound where the reference holds 54; #649), level 0 non-empty and carrying a hashed leaf (a level 0 of duplicate flags alone refused after the offset checks as `Transaction ID is undefined`, the reference's constructor's words, `ts-stack@edf6e03` `MerklePath.ts:241-263`, `:342-343`; #641), no duplicate offsets, legal higher-level offsets (an off-path offset refused as `Invalid offset: N, at height: H, with legal offsets: …`, the list in level-0 leaf order, the reference's text, #631), all txids compute same root. A one-level lone hashed leaf is valid only at offset 0; the parse (the decoder's walk) and `compute_root` (`RootWalker`) share this rule, refusing other offsets with `MissingSibling` and the missing sibling's level and offset (the parse refuses a lone leaf at 2 or above earlier, `OffsetOutsideTree`). TS returns the txid at any offset (`ts-stack@edf6e03 MerklePath.ts:345,390-391`); this divergence follows the BEEF reader and the owner's offset-0 ruling.

`new_unchecked` is the reference's constructor with `legalOffsetsOnly` false: every check of `new` but the legal offsets above level 0, every root checked, a level 0 of duplicates alone refused as `new` refuses it (#641; until then both accepted it). It is for a path that may have been trimmed; its `src/` caller is the wallet's BEEF result reader (`wallet/substrates/result_values/beef.rs`). The readers (`from_binary`, `from_hex`, `from_reader`, the stream, `Beef::from_binary`, `verify_structure`) refuse such a level as `NoTxidAtLevelZero` in the stream's words; a path held through the public fields with no check is refused by `compute_root` in the reference's `computeRoot()` words (`No valid leaf found in the Merkle Path`, `:375-381`), with no walk. Pinned by `tests/merkle_path_641.rs` on `tests/vectors/merkle_path_641.json`.

A path with no levels at all (#649): both constructors refuse it (above); the readers refuse a tree height of 0 as `TreeHeightZero` at the height byte, in the stream's words where the reference's `fromHex` throws its constructor's sentence. Held through the public fields, every walk reads level 0 through `MerklePath::level0` (`merkle_path_legal.rs`), never `path[0]`: `compute_root` refuses it as `No valid leaf found in the Merkle Path`, or with a txid `Transaction ID <txid> not found in the Merkle Path` (the reference's `computeRoot` and `indexOf` words; the reference itself throws its runtime's `TypeError` there, `:375-382`, `:327-333`), `combine` refuses through it, `trim` leaves the path as it is, `contains`/`contains_and_mark` answer `false`, `txids` none, `Beef::merge_bump` proves no transaction by it, `Transaction::verify` refuses it. Until #649 each of these panicked. Pinned by `tests/merkle_path_649.rs` on `tests/vectors/merkle_path_649.json`.

## BEEF Format (BRC-62/95/96)

```rust
pub struct Beef {
    pub bumps: Vec<MerklePath>,       // Merkle proofs
    pub txs: Vec<BeefTx>,             // Transactions (sorted by dependency)
    pub version: u32,                 // BEEF_V1 or BEEF_V2
    pub atomic_txid: Option<String>,  // Target txid for Atomic BEEF
    // Internal: txid_index (HashMap for fast lookup), needs_sort flag
}

impl Beef {
    // Construction: new() [V2], with_version(), from_hex(), from_binary(), from_reader() [the streaming decoder, collecting]
    // Serialization: to_hex(), to_binary() [auto-sorts], to_writer(), to_binary_atomic(txid): each -> Result, refusing before any byte what the format cannot carry faithfully (#817)
    // Validation: is_valid(allow_txid_only), verify_valid() -> BeefValidationResult, verify_structure() -> Result<roots, Kind> (0.4.2), sort_txs() -> SortResult
    // Lookup: find_txid(), find_txid_mut(), find_bump(), find_transaction_for_signing(), find_atomic_transaction(), is_atomic()
    // find_transaction_for_signing() answers a linked copy, the entry left as held (#817, stated: the reference returns the held object; edit_tx the way back)
    // Editing: edit_tx(txid, |tx| ..) [a copy edited, the entry re-keyed at once, #817], reindex() [after a hand edit of txs]
    // Merging: merge_bump() [combines same height/root], merge_transaction() [the path as a BUMP, the sources walked, #764], merge_raw_tx() [-> Result: bytes that are not one transaction refused, #817], merge_txid_only(), make_txid_only(), merge_beef() [-> Result since #817: the verdict of the reference's snapshot, the source written and read back strictly, the target untouched on Err; the source's snapshot, as `mergeBeef` reads `fromBinaryStrict(beef.toBinary())`: its entries in the order its serialization writes them (as read for a BEEF read from bytes and untouched, else its sort, else held) and each as its bytes or txid alone, its BUMPs with every level sorted by offset (#621's third fold, `MerklePath.ts:148-149`), the source unchanged (#621's second fold); the target re-keyed first (`refresh_mutated`, `Beef.ts:976`, #621's fourth fold); an entry held raw or parsed left alone, a held txid-only one upgraded, as `mergeBeef` does; a raw source entry stored under the txid it holds, no second hash, #621]
    // Utility: clone_shallow(), to_log_string()
}

pub struct BeefValidationResult { pub valid: bool, pub roots: HashMap<u32, String> }
pub struct SortResult { pub missing_inputs, not_valid, valid, with_missing_inputs, txid_only: Vec<String> }
```

**BeefTx**: Wraps a single tx in BEEF. Constructors: `from_tx(tx, bump_index)`, `from_raw_tx(raw_tx, bump_index) -> Result` (bytes that are not exactly one transaction refused, #817), `from_txid(txid)`. `to_writer(writer, version) -> Result` (a txid-only entry outside V2, a txid not 64 hex digits, refused before any byte, #817). Accessors: `txid()`, `tx()`, `tx_mut()` (deprecated since #817: the transaction then the entry's only reading, #171; edit through `Beef::edit_tx`), `raw_tx()`, `raw_tx_or_compute()`. State: `has_proof()`, `is_txid_only()`, `bump_index()`, `set_bump_index()`. Public fields: `input_txids`, `is_valid`.

**Constants**: `BEEF_V1 = 0xEFBE0001` (BRC-62), `BEEF_V2 = 0xEFBE0002` (BRC-96 with txid-only), `ATOMIC_BEEF = 0x01010101` (BRC-95). `TxDataFormat`: `RawTx=0`, `RawTxAndBumpIndex=1`, `TxidOnly=2`.

## Re-exported Sighash Constants

The module re-exports sighash constants from `primitives::bsv::sighash`:
- `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`
- `SIGHASH_ANYONECANPAY`, `SIGHASH_FORKID`

## Usage Examples

```rust
// Building and Signing
let mut tx = Transaction::new();
tx.add_input(TransactionInput::with_source_transaction(source_tx, 0))?;
tx.add_output(TransactionOutput::new(100_000, locking_script))?;
tx.add_p2pkh_output("1MyChange...", None)?;  // Change output
tx.fee(None, ChangeDistribution::Equal).await?;
tx.sign().await?;

// Convenience input methods (match Go SDK)
tx.add_input_from_tx(source_tx, 0, p2pkh_unlock)?;        // Full source tx + template
tx.add_input_from(txid, 0, &locking_script, 50_000, p2pkh_unlock)?; // By TXID + script
tx.add_inputs_from_utxos(&utxos)?;  // Batch add from UTXOs (templates set separately)

// Inspecting
assert!(!tx.is_coinbase());
assert!(tx.has_data_outputs());  // If any OP_RETURN outputs exist

// JSON serialization (cross-SDK compatible with Go SDK)
let json = tx.to_json()?;
let tx2 = Transaction::from_json(&json)?;
assert_eq!(tx.to_hex(), tx2.to_hex());

// Broadcasting (requires `http` feature)
let result = WhatsOnChainBroadcaster::mainnet().broadcast(&tx).await;    // Raw hex
let result = TeranodeBroadcaster::new(url, None).broadcast(&tx).await;   // EF binary

// Serializing to BEEF (collects ancestors with an explicit stack)
let beef_v1 = tx.to_beef_v1(false)?;  // V1 format (BRC-62)
let beef_v2 = tx.to_beef(false)?;     // V2 format
let atomic = tx.to_atomic_beef(false)?;

// SPV Verification (Transaction-level, by txid over the whole ancestry)
let tracker = WhatsOnChainTracker::mainnet();
let is_valid = tx.verify(&tracker, None, None).await?;              // SPV verify of the ancestry
let is_valid = tx.verify(&tracker, Some(&fee_model), None).await?;  // With fee validation

// SPV Verification (BEEF-level, manual root checking)
let validation = beef.verify_valid(false);
for (height, root) in validation.roots {
    tracker.is_valid_root_for_height(&root, height).await?;
}

// Fee Models
let fee = SatoshisPerKilobyte::new(100).compute_fee(&tx)?;  // Fixed rate
let live = LivePolicy::with_url("https://<host>/v1/policy"); live.refresh().await?;  // Live rate (ARC is deprecated and no default, #350)
```

## Implementation Notes

- **Caching (#843)**: the hash, the bytes and the hex are cached in `OnceLock`s beside the four fields in `Fields`, whose fields only the inline module `sealed` of `transaction/fields.rs` sees (#869's sixth fold; `fields.rs` whole from #869's fold until then), filled through `&self` and emptied only by `Fields::write(&mut self)`, the one exclusive door, which every door goes through before it lends or sets; every mutator of `transaction.rs` (`add_input`, `add_output` and its family, `sign`, `fee`, `distribute_change`, `Drop`) writes through a door, the compiler refusing any other write, so a stale id does not compile: while a door's `&mut` borrow lives no `&self` read can refill a cache, and a linked source is reachable mutably only through its child's `inputs_mut()`, which has cleared the child. `invalidate_caches` is removed (its `&self` signature was the hole: a linked parent edited through the public field kept the child's id stale even after the child's `invalidate_caches()`, probe A). A read never goes through a `_mut` door (each call clears the cached id). Pinned by `tests/transaction_identity_843.rs` (the law as a seeded property over every door, its reach counted with floors, probes A to E, the parts lossless; since #869's second fold the odd source-txid namings and the four links, and a second seeded run judging every copy a BEEF stores), `tests/transaction_identity_attempts_869.rs` (the strength read's attempts as cells), `tests/arch_field_writes_843.rs` (`sealed`'s text, the module declarations and the cache fills, pinned lexically), the fuzz invariant of `fuzz_transaction_parser` and `fuzz_beef_parser`, and `tests/arch_owned_fields_843.rs` (no public field on a type that holds a cache or an index, an enumerated list that only shrinks). `from_binary` and `from_hex` cache the input, which is exactly the transaction since #840 (until then a byte after the lock time was cached and hashed into the txid); `from_reader`, `from_ef` and `with_params` cache nothing. Pinned by `tests/transaction_trailing_data_840.rs` on the reference's recording and by `fuzz_transaction_parser` (a transaction `from_binary` returns serializes to exactly its buffer, `from_hex` agrees with it, a transaction `from_ef` returns writes its buffer back through `to_ef`). Every reader of a transaction refuses an output amount, and `from_ef` a source amount, of 2^53 or more in the reference's words, `Number can only safely store up to 53 bits` (`amount.rs`, #844; a `u64` read until then), and `parse_script_offsets` skips the eight bytes unread, as the reference's does; pinned by `tests/transaction_numbers_844.rs` (156 recorded cells) and `fuzz_transaction_parser` (no accepted transaction holds such an amount)
- **Inputs**: Must have `source_txid` or `source_transaction`; fee calc/signing need full source tx with satoshis/locking_script
- **Convenience inputs**: `add_input_from_tx` sets template; `add_input_from` builds a minimal source tx; `add_inputs_from_utxos` does NOT set templates (caller must set them separately)
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()` as the reference's `#distributeChange` (`Transaction.ts:864-897`, #868): equal, `floor(change / n)` to each change output and the remainder to the last; random, `floor(remaining * log10(1 + 1/d))` for a digit of 1 to 9 to each but the last, the rest to the last (an output may be 0). `fee`'s and `get_fee`'s totals past `u64` refused in the reference's `addSatoshiAmount` words (`amount::add_amount`); `total_output_satoshis` saturates. Pinned by `tests/transaction_fee_random_change_868.rs`
- **Fee refusals (#871)**: `fee` checks as the reference's `fee` and `#calculateChange` do, in their order and words (`Transaction.ts:65-86,770-862`): the fee (`fee_sats`, or `estimate_size` for `None`) past 21e14; per input, no source transaction, a source output that does not exist (`Input N references a source output that does not exist.`), a source amount absent or past 21e14, the input total past 21e14 (`source_total`, shared with `get_fee`); per output not flagged change, an amount absent or past 21e14, the output total; then inputs that cannot pay the outputs and the fee (`Transaction inputs are insufficient for the requested outputs and fee.`), where the change saturated to 0 until #871. The transaction is unchanged on `Err`. `get_fee` (`getFee`, `:899-933`) reads every output, change outputs included, so it refuses an uncomputed change output; it answers 0 where the reference answers a negative fee (stated). `fee(None, ..)` is one satoshi per byte, where the reference's default is its live policy (stated). Pinned by `tests/transaction_fee_refusals_871.rs`
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Debug**: `Transaction` and `TransactionInput` implement `Debug` by hand; a linked `source_transaction` prints as `Some("<txid>")`, never its ancestry (0.3.35, bsv-stack-lean #57 P0-5c)
- **Async traits**: `Broadcaster` uses `?Send` (`Transaction` is not `Sync`: its caches are `OnceLock`s since #843, but every input and output holds a `Script`, whose chunks and caches are `RefCell`s, `src/script/script.rs:22-30`; `Script` is a later PR of its own); `ChainTracker` is standard async
- **HTTP feature**: `TeranodeBroadcaster`, `ArcBroadcaster` (deprecated), `WhatsOnChainBroadcaster`, `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, and `LivePolicy` require the `http` feature flag
- **BEEF ancestry**: `to_beef()` and `to_beef_v1()` walk the `source_transaction` chain depth first with an explicit stack via `collect_ancestors()`, stop at txs with `merkle_path`, and store each ancestor without its own ancestry; the collected order is written as collected, the subject last (0.8.8, BRC-62's rule; the doors sorted it into the dependency order until then)
- **BEEF V1 vs V2**: Use `to_beef_v1()` for a reader that takes V1 only (BRC-62), `to_beef()` for V2 with TXID-only support (BRC-96)
- **BEEF indexing**: Beef maintains an internal `txid_index` HashMap for O(1) transaction lookup by txid
- **The edit door and hand edits (#817)**: `Beef::edit_tx` is the one supported edit of a held transaction: the closure runs on a copy, then the entry is repaired at once (bytes, txid, `input_txids`, the index, the sort mark; the BUMP index kept), so no door after it stores the txid twice; an edit keeping the txid is stored and moves nothing. `BeefTx::tx_mut` is deprecated and keeps the #171 window. The index notices a hand edit of `txs` in constant time where it can (the entry count it was built for, a hit naming another entry), and its response costs what the edit was (the fold of the rebuild): a `&mut` door indexes the entries pushed by hand alone, and rebuilds whole after a shrink, a moved prefix or a hit naming another entry (a hand swap or reorder), so the doors after it read the index alone; a `&self` lookup scans the unindexed tail alone after pushes, `txs` whole after a shrink or a mismatched hit; hand edits that leave a txid the index was never given below the entry count it was built for (a replacement inside the indexed prefix, whatever pushes follow it; a `truncate` or a `retain` with pushes back past it), the count back at the indexed one or past it with the prefix's last position in place, make a lookup of it miss: the stated window, `reindex` its door. A hand replacement that puts a second entry of a txid the index holds at a position below its own is not noted as a twin (`holds_twins` is set only when an entry is indexed), so `edit_tx` of that txid drops its key and the copy is not found, and `merge_raw_tx` of it stores it again, until `reindex`, where the reference's next synchronizing door rebuilds its index and finds the copy (`Beef.ts:342-352,516-524`; stated, the rule read of `65369528`). Two entries of one txid are noted when indexed (`holds_twins`), so `edit_tx` keeps the old key and the other entry stays found (#817's second fold). Two costs are stated (hand pushes with `&self` lookups alone, each miss scanning the pushed tail; a hand `retain` before every door, each rebuilding whole); `reindex` or any `&mut` door after the burst is the way out. No interior mutability: `Beef` and `BeefTx` are `Send` and not `Sync` (as the `RefCell`s of `Script`, which every `Transaction` holds, make them), pinned in `tests/beef_edit_door_817.rs`. The ensemble's five reads withdrew PR #832's lazy repair (a process-wide edit count, a per-BEEF stamp, the reference's BUMP map ported as a precedence and a snapshot; `docs/lanes/fix-817-door-sync.md`, "The design changed"). Pinned by `tests/beef_edit_door_817.rs` and `tests/beef_door_sync_817.rs`
- **The linker's key (#869's third fold)**: `add_input_proof` keys its stubs by the id of what an input links, its own source's when it carries one (never replaced, as the reference's `#resolveInputSource` never replaces a linked source and its walk visits by id, `Beef.ts:649-679`), else the text the BEEF is asked by; an input naming no txid is keyed by its linked source's id and descended like any other, as the reference's walk descends every linked source (#869's fourth fold; skipped until then, so a source the BEEF's BUMP proves came back without that path), and one that links nothing and names nothing is left as it is (the reference refuses it before any BEEF door, `sourceTransaction is undefined`: stated); the reference's `mergeTransaction` also writes each linked source's id into the input's `sourceTXID` (`materializeSourceTXIDs`, `Beef.ts:883`), which `merge_transaction` does not (stated). Pinned by `tests/beef_input_without_txid_869.rs` on `tests/vectors/beef_input_without_txid_869.json`. Keyed by the text until then, so two inputs sharing one that does not parse, each over its own source, were both handed the first one's: `find_atomic_transaction` of the id merged answered another id. Pinned by `tests/beef_shared_txid_text_869.rs`, the identity property's shared-text arms and `fuzz_beef_parser`'s merge-back check. `Transaction::verify` still finds a source by the text (`verify.rs`), so such an input is refused there (`Input N has no source transaction`), kept; a text of 64 hex digits that is not its linked source's id is refused by `sign` and `verify` in the reference's words since #848 (`source_named_otherwise`)
- **BUMP lookup (#732)**: `find_bump` and `add_input_proof`'s index (built once per walk, level 0's hashes to the BUMP) answer the LAST BUMP holding a txid at level 0, as the reference's `Map.set` index does (`ts-stack@edf6e03` `Beef.ts:570-585`); the readers keep every BUMP read (`Beef.ts:1257-1261`, `beef/collect.rs`) and `merge_bump` combines only one of the same height and root, so two proofs of one txid (a reorg, two roots at a height) reach `from_beef` from the wire and the last is attached. Until #732 the earliest. The entry's wire bump index is not consulted. Pinned by `tests/beef_bump_lookup_732.rs`; the reference's txid map answers otherwise after a combine into an earlier BUMP, until a BUMP synchronization drops it, seven recorded cells stated (#817, the root list; PR #832 ported the map and was withdrawn)
- **Written BUMP index and a caller's path (#757)**: an entry merged after two BUMPs holding its txid (`merge_raw_tx`, `merge_txid_only`, `merge_transaction`, through `try_to_validate_bump_index`) takes the LAST one's index, as the reference's `#tryToValidateBumpIndex` reads its index (`Beef.ts:1329-1340`, `:576-585`), so `to_binary` writes that byte and the atomic writers (`atomic_closure`, the reference's `#copySelectedTransactions`, `:448-470`) carry that BUMP, a txid-only entry's too since #757's fold; a txid-only entry whose index names no BUMP holding its txid (none, or another BUMP) is copied with no BUMP and no index, as `#copySelectedTransactions` copies it (`#hasMatchingBump`, `:436-446`; #766: until then the last BUMP carrying the txid, the earliest until #757's fold); a raw entry the same, its index dropped and the walk stopped at it (#798: until then its BUMP kept whatever it held, an out-of-range index an `Err`, the entry descended), the index kept, renumbered, where another included entry's matching BUMP is the one it names (`:453-456`, `:462`, the reference's shape); `make_txid_only` sets the index again, as `makeTxidOnly` does (`:550-565`); an entry merged before a BUMP keeps the BUMP present at its merge (`update_bump_indices`, the reference's `#mergeBumpEntry`, `:774-786`); the earliest until #757. Both sites take any level-0 leaf holding the txid and flag it `txid` (`MerklePath::contains_and_mark`; its flag byte written `02` for `00`), as the reference's `#tryToValidateBumpIndex` and `#tryMarkTxProvenByBump` do (`:1334-1338`, `:813-822`) and go-sdk's `bumpProves`/`MergeBump` and this crate's own `find_bump` read a BUMP (#765; strict, a flagged leaf only, from v0.3.5's `ef98e246` until then, pinned by `tests/beef_sibling_leaf_765.rs`). `add_input_proof` gives a transaction this BEEF proves the BEEF's BUMP in place of a path it carries and does not descend it, and descends one it does not prove with its own path kept, as `#addInputProof` does (`:658-666`); until #757 a carried path was kept and ended the walk. Pinned by `tests/beef_bump_index_757.rs`
- **BEEF writers (#817)**: `Beef::to_binary`, `to_hex`, `to_writer`, `BeefTx::to_writer` and `to_binary_atomic` (its closure checked before the subject's txid) run one read-only check before any byte (`beef_writable.rs`) and refuse only a state they cannot write faithfully, in the order the reference meets them: a txid-only entry whose txid is empty (ahead of everything, where the reference's `txid` getter throws `Internal`), a BUMP's non-hex hash (`Invalid hex string`), each entry's reference refusal in written order (a txid-only entry outside V2, `a valid serialized Transaction is expected`; a V2 one with a non-hex txid, `Invalid hex string`), a version word other than V1 or V2 (the reference reader's `Serialized BEEF must start with ...`), a BUMP `MerklePath`'s writer refuses, then each entry's own (a txid-only txid not 64 hex digits, `Invalid txid-only entry txid: expected 64 hex digits, got N`; a raw entry held unparsed that is not one transaction, `beef_raw_frame.rs`'s words). `to_binary` refuses an empty txid-only txid before its sort (the entries left as held) and every other state after it (the entries sorted), as the reference's `#getSerializedBytes` throws around its sort (`Beef.ts:367-368`; #817's fold, the vector's `sort_on_refusal`). A BUMP index naming no BUMP is written. `merge_beef` returns `Result`, the reference snapshot's verdict (the source's check over `written_order`, then each BUMP read by the reader's decoder at its place in the frame, `bumps_as_read`: a pre-pass proven equal to the literal round trip of its bytes read back by `from_binary`, which it replaced for #621 at beta's cost; the oracle `snapshot_round_trip`, `prepass_621_tests.rs`, `fuzz_beef_parser`), the target untouched on `Err`, and merges as #621 does; merges into one growing BEEF grow faster than linearly by `refresh_mutated`'s whole-target scan (stated, #621: 2,210 ms of 2,374 ms at 200,000 entries in merges of ten, release), gone with the deprecated `tx_mut`; `merge_raw_tx` and `BeefTx::from_raw_tx` refuse bytes that are not exactly one transaction, the BEEF untouched. `merge_bump` combines through `MerklePath::combine_verified` (no error left to drop) and appends a BUMP whose root does not compute (stated). Pinned by `tests/beef_v1_txid_only_writer_817.rs` and `tests/beef_writer_refusals_817.rs` on `tests/vectors/beef_v1_txid_only_writer_817.json`, `fuzz_beef_parser`'s write and merge invariants
- **merge_transaction's graph (#764)**: `merge_transaction(tx)` walks a stack from `tx`, each txid once per call, as the reference's `mergeTransaction` does (`ts-stack@edf6e03` `Beef.ts:875-901`; go-sdk@2ca481c `beef.go:875-912`): a transaction carrying a `merkle_path` has it merged through `merge_bump` and takes the returned index (`#mergeTransactionEntry`, `:849-856`; a BUMP of the same height and root held already is combined, no second one), else the last BUMP flagging its txid; an entry ending with no index has its inputs' sources merged and walked, from the first input on (`:858-863`, `:897`), an entry ending with one stops the walk. A txid held already is replaced in its place (`replace_or_append`, one entry, no entry moved), at `merge_raw_tx` too: removed and appended until #764's fold, so independent entries were written in another order than the reference's. The transaction given is stored as given, each ancestor as a copy without links (linear; a stated divergence, the #764 parity note). `Transaction::to_beef`, `to_beef_v1`, `to_atomic_beef` store an entry alone (`push_transaction`), as `to_beef`'s BUMPs are merged already; `merge_beef` stores each source entry as its bytes (`store_raw_entry`), as the reference's `mergeBeef` reads a byte snapshot (only where the target holds nothing or a txid alone, since #621's fold; as bytes since its second fold, a parsed entry's transaction pushed with its links until then); a caller wanting that one-entry merge uses `merge_raw_tx(tx.to_binary(), None)`. Until #764 the transaction alone was stored, no BUMP, no ancestor. Pinned by `tests/beef_merge_transaction_764.rs`
- **MerklePath root check**: `new` and `new_unchecked` check every level-0 leaf's root with one `RootWalker` (`merkle_path_walk.rs`, #93 P0) (the parse, since #167, by the decoder's walk) that indexes each level by offset and computes each node once, shared across the walks (the reference's `computeRootCached`; linear in the leaves since 0.3.35, bsv-stack-lean #57 P0-5c). A tree height over 64 is refused before any shift
- **MerklePath dedup**: BEEF ancestry collection deduplicates proofs by `"height:root"` key; combines proofs at same height/root
- **Dependency order**: the Beef-level writers sort oldest-first (`to_binary` of a BEEF a caller assembles, `merge_beef`); the plain transaction doors write the collected order since 0.8.8 (the subject last), the atomic door the sorted closure with the subject moved last. Inputs processed in reverse order during collection (like TS SDK)
- **JSON format**: `to_json()`/`from_json()` match Go SDK's `MarshalJSON`/`UnmarshalJSON`; deserialization prefers `hex` field when present
- **Default impls**: `Transaction`, `TransactionInput`, `TransactionOutput`, `Beef`, `MockChainTracker`, `WhatsOnChainBroadcaster`, `WhatsOnChainTracker` implement `Default`
- **Genesis authority (#451)**: supplied `ChainParams.genesis_height` alone decides. Without params, the stream's P2SH check still reads `ChainTip.genesis_height`, deprecated since beta.4, or mainnet's figure when there is no tip. The copy functions until its removal at the next api-break, when params become the only source; no default-path verdict changes.
- **SPV verify**: `verify()` performs queue-based verification over the whole ancestry (no recursion): checks merkle paths against chain tracker, validates fees (optional), runs script interpreter on each input (a decline is `Error::ScriptEvaluationDeclined`, never `TransactionError`, #38), enqueues unverified source transactions. Matches Go SDK's `spv.Verify()` and TS SDK's `Transaction.verify()`
- **Equality**: `Transaction` and `TransactionOutput` implement `PartialEq`/`Eq` based on binary serialization

## BEEF Ancestry Collection Algorithm

The `collect_ancestors()` method implements the same algorithm as TypeScript/Go SDKs:

1. **Cycle detection**: Skip transactions already seen (by txid)
2. **Proven transactions**: If tx has `merkle_path`, add proof (deduplicated by height:root) and do not descend
3. **Unproven transactions**: Process each input's `source_transaction` first, in reverse order, depth first on an explicit stack (the recursive walk's order)
4. **Dependency order**: After processing all ancestors, add current transaction
5. **Partial support**: `allow_partial=true` skips inputs with missing source transactions

## Error Types

| Error Type | Conditions |
|------------|------------|
| `TransactionError` | Missing source, satoshis, uncomputed change, EF marker issues, BEEF parsing, JSON serialization, SPV verification failures (invalid merkle path, fee too low, script validation) |
| `TransactionNotJudged { txid, input_index, cause }` | Unsupported chain facts: pre-Genesis coin/spend, overflowing tip, zero activation; names the unproven transaction and input, a verifier refusal, never a transaction judgment (#452) |
| `FeeModelError` | Input missing unlocking script or template |
| `BeefError` | Invalid version (not V1/V2), missing atomic txid, txid not in BEEF |
| `MerklePathError` | Empty path, tree height over 64, duplicate offset, invalid offset at height, mismatched roots |
| `ChainTrackerError` | `NetworkError`, `TransportFault { fault, status, detail }` (the HTTP trackers' fault, its class typed; `transport_fault()` reads it, `From<ChainTrackerError> for Error` carries it to `Error::TransportFault`), `InvalidResponse`, `BlockNotFound(height)`, `Other` (`#[non_exhaustive]`, #87) |
| `TransportFault` | `NeverSent`, `MayHaveBeenReceived`, `RateLimited { retry_after_ms }` (`#[non_exhaustive]`, `code()` the broadcasters' word; re-exported from `crate::error`, #87) |

## Related Documentation

- `../script/CLAUDE.md` - LockingScript, UnlockingScript, templates
- `../primitives/CLAUDE.md` - Reader, Writer, sha256d, from_hex, to_hex
- `fee_models/CLAUDE.md` - SatoshisPerKilobyte, LivePolicy
- `broadcasters/CLAUDE.md` - TeranodeBroadcaster, WhatsOnChainBroadcaster, ArcBroadcaster (deprecated)
- `chain_trackers/CLAUDE.md` - WhatsOnChainTracker, BlockHeadersServiceTracker

## Live script verification (#440)

Existing callers keep SDK default mode. A live door selects
`StreamVerifier::new(...).with_chain_params(chain)` (also on the retaining and
resumed reader), `verify_stream_two_pass_with_chain_params(..., &chain)`, or
`Transaction::verify_with_chain_params(..., &chain)`. Async readers have the same
builder. Add `.with_work_budget(Some(policy_units))` on each stream door, or use
`verify_with_chain_params_and_work_budget(..., Some(policy_units), &chain)` on
the whole path. Each door names `policy_units` in its brief. Apply it before stepping; reapply it after any resume, including a
decoded cursor, exactly as the local budgets. No flag word is serialized.

The verifier obtains source heights only from header-verified BUMPs; unproven
sources use the spend era. Transaction flags use tip + 1 with checked overflow;
without a tip they use the latest era in the chain parameters. A pre-Genesis
coin, overflowing tip or zero activation height is `Verdict::NotJudged` with
`input` and `NotJudgedCause`; the underlying `SpendRefusal::NotJudged` also
carries both. The whole path uses `Error::TransactionNotJudged { txid,
input_index, cause }`, naming the unproven transaction even in an ancestor.
These refuse the verifier's scope and never claim script failure
(#452). Downstream matches add the `SpendRefusal::NotJudged` arm on beta.4;
the toolbox's #461 skip and pre-Genesis refusal use this typed class, and the
CLI reads its fields, never its text. Supplied `ChainParams` alone decide
Genesis. Without params, the P2SH check honors the deprecated
`ChainTip.genesis_height` until its next-api-break removal (#451), using
mainnet's figure only when no tip is supplied. A proven transaction still stops
at its proof: the stream runs scripts only for unproven transactions; callers
judging mined scripts can
use `input_script_flags(..., mined = true)` with their block height.
Structural, atomic, finality/maturity, value, duplicate and deferred-parent rules
are unchanged. `ChainParams` is authoritative on the live path; the deprecated
`ChainTip::genesis_height` still serves the default path's P2SH check.
