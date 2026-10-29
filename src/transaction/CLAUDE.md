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
- The streaming BEEF reader (`beef_stream`, 0.4.0): `verify_stream` over any `Read`, one element held at a time, the verdict `Valid`, `Invalid { offset, kind }` (twenty kinds, none a size or a count) or `SpendRefused`; `Cursor` and `resume`. A valid BEEF is never refused for its size or its counts
- The stream's two budgets for its scripts (#373): `StreamVerifier::set_work_limit` and `set_memory_limit` (the same on `AsyncStreamVerifier`), per input, `None` the default and uncapped, `Some(n)` the caller's (the memory budget `n` bytes per stack, `Transaction::verify`'s third parameter, #331); one spent is `Verdict::SpendRefused { txid, input, why: SpendRefusal::Resource(limit) }`, a decline naming the transaction and the input, never a verdict; local configuration, absent from the `Cursor` and set again after `resume`; the structure-only reader spends none; the reader's own bound per element is the charter's (NL-3), not a cap on a script. The `verify_stream*` functions take neither: a caller with a budget builds the reader. Pinned by `tests/beef_stream_memory_budget_373.rs` and `tests/script_work_budget.rs`
- A raw transaction with no input is invalid bytes (0.4.1, bsv-stack-lean #58): `Kind::NoInputs` at the transaction's offset from the streaming reader, not valid from `Beef::verify_valid`, with or without a BUMP index. The rule is the node's (bsv-script-lean `lean/BsvScript/TxRules.lean`, `checkTransactionCommon_vinEmpty`); a test BEEF's root needs an input and a merkle path
- A raw transaction with an input and no output is invalid bytes too (0.4.3, bsv-stack-lean #59): `Kind::NoOutputs` at the transaction's offset, after the inputs' check (the sibling's `TxRules.lean:85-86`, `checkTransactionCommon_voutEmpty`); `beef_stream::no_transaction` answers both for every path. `Transaction::verify` refuses a transaction it reaches with either, proven or not (`invalid transaction <txid>: NoInputs`): there is no synthetic root
- The whole path on the reader's walk and rules (0.4.2, bsv-stack-lean #61): `Beef::verify_valid` computes each BUMP's root by `beef_stream`'s `bump_root` (linear; 0.4.1 walked once per leaf), and `Beef::verify_structure` answers the roots or the reader's `Kind`. A lone leaf at an offset other than 0 is `MissingSibling`; `from_binary` refuses a byte after the frame (`TrailingBytes`, in the reader's words); an atomic BEEF is held to the reader's atomic rule (`SubjectMissing`, `UnrelatedTransaction`); a txid-only entry is valid when a BUMP of the BEEF proves it (`StubNotProven` otherwise) and `allow_txid_only` decides nothing
- One reader (bsv-rs#86): the whole-BEEF reader is a mode of the streaming reader. `Beef::from_binary`, `from_hex`, `from_reader` and `from_binary_with_limits` (and through them `Transaction::from_beef` and `from_atomic_beef`) run `BeefDecoder::collecting()` (crate-private) and collect its elements into the `Beef` in one pass (`beef/collect.rs`): the BUMPs by `Bump::to_merkle_path`, each level's leaves sorted by offset as the in-memory form always held them; the transactions from the bytes the decoder read (`Transaction::from_binary` on them, so the hash is the bytes'), in the order written; version and subject from the header. The parse refuses what the stream refuses as a frame or a BUMP (a second leaf at an offset its level carries among them, agreeing or not: `DuplicateOffset { level, offset }` at its offset varint, the reference's `Duplicate offset`, its own kind by the owner's word, #86, #167; `merkle_path_root` refuses one held in memory, ahead of the walk), in the stream's words (`BEEF error: invalid BEEF at byte N: Reason`, `Error::BeefError`): the earliest refusal of the reading, an earlier element's content or fold refusal included (a structure-only `BeefIndex` folds each element beside the collection, the leading BUMP's root at a height as the one root the headers carry there). The collect mode yields a transaction whatever its content (`check_transaction`: unproven coinbase, no input, no output, `ValueOutOfRange`, null or repeated outpoint), so such a BEEF parses and `verify_structure` judges it. `verify_structure` is one pass over the entries in the order held, each judged as the decoder and the fold judge an element (`beef/in_memory.rs`: `merkle_path_root`, `content_refused`, `atomic_table`), then the sort, whose result decides where the unproven inputs lead (`missing_inputs`, `with_missing_inputs`, `not_valid`: `InputNamesNoElement`), then the atomic rule. A BUMP above a `u32` height is `RootNotCarried` at the parse (the in-memory height is a `u32`; through 0.8.3 it was cut to its low bits). The differential `tests/beef_two_readers_agree.rs` (every BEEF the tree holds, its prefixes, single-byte changes and reversals: 0 disagreements, no stated difference) and `fuzz_beef_parser`'s assertion pin it
- A BEEF is valid whatever its order on the wire (bsv-rs#240, the keeper's re-reading of 2026-10-26 on the owner's north star: one verdict across the SDKs): every input of an unproven transaction names a transaction of the BEEF or a proven txid, wherever it is written. The whole path sorts before judging, as the reference's `Beef.verifyValid` does (`ts-stack@edf6e03` `Beef.ts:1054-1073`, `sortTxs` at `:1065`). The stream holds an unproven transaction an input of which names a txid the index does not hold yet by its index entry (`BeefIndex`'s `Deferred` of `HeldTx`, by offset: txid, offset and wire length, 56 bytes; per input the outpoint, sequence and offset, 48; with spends checked the version and lock time, each unlocking script, and the outputs, 16 bytes and the script each, which the original digest of a CHRONICLE-bit signature hashes after the parent's scriptCode; never its raw bytes), and the txids it waits on, counted. When the last is in it is ready, and the reader folds the ready ones in one per step, in wire order, ahead of the next element (`Judge::release_next`; under `step_until` its scripts run under the caller's budget and may pause inside it, the cursor naming it before the frame; the asynchronous reader folds every ready one after the element; `BeefIndex::fold` in the same call). At `finish`, ahead of the atomic rule, what is still held is refused: `InputNamesNoElement` at the earliest held transaction's earliest input that names nothing. A refusal after a held child is the later element's, on both paths. No bound (the beef-of-any-size charter: a valid BEEF is never refused for its size or its counts; the keeper's stop on #240): a BEEF in BRC-62's order holds nothing, one written children first at most the entry of every unproven transaction read; `BeefIndex::deferred()` answers the transactions held and the bytes their entries hold. The whole reader's structure-only judge holds the same entry, not a copy of the bytes the `Beef` holds. A cursor taken while one is held is BSC4 (BSC3, then the held entries by offset, each count bounded by the bytes left); one that holds nothing keeps BSC3's bytes. `Stop`, `Verdict` and `AsyncVerifyError` are `#[non_exhaustive]` (0.9.0, #240). BRC-62 (`5119a9b` `0062.md:43`, `:72-74`, `:172-191`) keeps the order on the writer's side: `to_binary` writes parents before children. From bsv-rs#86 to #240 the three readers refused a child written ahead of its parent; 0.8's `verify_valid` sorted. Pinned by `tests/beef_order_held.rs` (the reference's verdicts in `tests/vectors/beef_order_240.json`, `tests/support/beef_order_240.mjs`; the held entry and its signatures, the BSC4 cursor's prefixes and changes, one release per step under the budget), `tests/beef_deep_chain.rs` (100,000 links newest first on a 1 MiB stack), `tests/memory_profiling.rs` (the held bytes per link) and the differential
- The atomic rule on the subject's graph (0.8.1, BRC-95): one walk, `beef_stream::atomic_unreached` (the Lean's `finish`, bsv-stack-lean `lean/BeefOfAnySize.lean` `walk`/`finish`), called by `BeefIndex::finish` (the stream) and `Beef::verify_structure` (the whole path). The subject is a raw transaction of the BEEF, else `SubjectMissing` (at 4 behind a prefix); every other entry, raw or txid-only, is reached from the subject through the inputs of raw entries, else `UnrelatedTransaction`. The entry a refusal names is the earliest, by the trie order (the txid's bytes, each byte's bits reversed, least first), of the entries the walk does not reach, at its offset (the ruled text, 2026-10-22). The whole path's verdict is a `Kind` and names no entry. A one-flag predicate (is the entry spent by some raw entry?) gives the same verdict, the refusal set being empty exactly when every entry is reachable (a txid is a hash: no chain of spends returns), but not the same entry: beside the subject, a raw `X` nothing spends and its parent `Y` that only `X` spends are both unreached, and the flag names `X` even when `Y` is earlier (`an_unreached_parent_earlier_by_the_trie_order_is_the_entry_named`, red on the flag predicate). No flag can stand in for the edges: two BEEFs with the same flags can leave different entries unreached. Position is not judged: the TS writer puts proven entries first, so a raw unproven ancestor can follow its proven descendant (the bsv-dd x402 refund, P0-65), and this crate's `to_binary_atomic` (the same sort, no cut) wrote such an ancestor after the subject until it emitted the closure. The graph follows the inputs of every raw entry, proven or not (the owner's ruling, 2026-10-22); TS ≥ 3 cuts it at each proven transaction (ts-stack `Beef.ts:420-434`) and refuses a raw ancestor behind a proof, a stated divergence (the root `CLAUDE.md`). The BRC-62 clause (an unproven transaction spends earlier transactions) is unchanged. The stream keeps the edges: under a subject each raw transaction's entry holds the txids its inputs name (`TxEntry::prevs`, the Lean's `prevs`), and the walk marks entries in place (`reached`, no table beside the index). They are kept only under a subject (the caller's, or the prefix's: the header precedes the first element; `BeefIndex::hold_to_subject`), and `entries()` counts them. `spec_size()` is the Lean's `Index.size`, which counts one edge per input of every raw transaction read, a repeat's again, with or without a subject (a counter, `inputs`; not a table). `model_work()` adds the Lean's atomic end: one pass over the table and the walk's fuel three times (`entries + 3 * (entries + inputs + 2)`). The bound: per element, plus 32 bytes per input of a raw transaction, only under a subject (an input is 41 bytes or more on the wire: linear in the bytes read). Measured (`memory_profiling`): the deep chain under its subject 352, 281, 225 B per element at 1,000, 10,000, 100,000 links (0.8.0: 274, 219, 175; the bound is 400); 100 proven transactions of 1,000 inputs, 262 KB peak without a subject, 32 B per input under one; the cursor after one proven transaction of 10,000 inputs is 238 B without a subject, 320,305 B under one. The cursor format is BSC3: after the transactions, the inputs counted and the edges, by txid strictly ascending (a list out of order, or edges of a txid the index does not hold raw, is refused); a BSC2 cursor reads as BSC3 with no edge (the walk reaches less: it only refuses more). Pinned by `tests/beef_atomic_graph.rs` and the staged vectors `tests/transaction/vectors/atomic-beef.json` (run by `tests/conformance_beef.rs`, the X/Y pair's named entries and offsets pinned there too)
- The atomic writer emits the BRC-95 closure (0.8.1): `Beef::to_binary_atomic` writes the subject and, through the inputs of raw entries, its ancestry up to each transaction a BUMP of the BEEF proves (and each txid-only entry), the BUMPs renumbered, the reference's sort, the subject last; every other entry and BUMP is dropped. What `@bsv/sdk` 3 (`#collectAtomicTransactions`) and go-sdk (`selectAtomicBeef`) write; `to_binary` still writes every entry. Pinned by `tests/beef_atomic_graph.rs` (`the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest`, `every_accepted_vector_round_trips_through_the_atomic_writer`)
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
| `transaction.rs` | `Transaction` with parsing, serialization, signing, SPV verification, BEEF ancestry collection |
| `verify.rs` | The existing SPV graph walk and `Transaction::verify_with_chain_params`, sharing fee/value/proof/resource behavior and the per-transaction sighash cache |
| `verification_flags.rs` | Resolves tip + 1 (checked) or the no-tip latest era, then calls the crate's one `script::input_script_flags` function |
| `verify_refusal.rs` | What `Transaction::verify` answers for an input's script `Err` (#38): a decline (`resource_limit` `Some`) is `Error::ScriptEvaluationDeclined { input_index, limit }`, the reference's `ScriptResourceLimitError` kept apart; a verdict `TransactionError("Script validation failed for input N: …")` |
| `tx_json.rs` | JSON serialization/deserialization matching Go SDK's `MarshalJSON`/`UnmarshalJSON` |
| `merkle_path.rs` | `MerklePath` (BRC-74 BUMP) for merkle proofs; its readers are the BEEF reader's BUMP decoder (#167) |
| `beef.rs` | `Beef` (BRC-62/95/96): the type, the public readers (over `beef/collect.rs`), `verify_structure`, sorting, merging, the writers (`to_binary`, the atomic closure), logging |
| `beef/collect.rs` | The whole-BEEF reader: the streaming decoder's collect mode collected into a `Beef`, with the stream's judge beside it (#86) |
| `beef/index.rs` | The txid index: `rebuild_index`, `find_txid`, `find_txid_mut`; `index_of` checks a hit against the entry's txid and `refresh_mutated` re-reads each entry mutated through `BeefTx::tx_mut` ahead of a whole-BEEF reader (#171) |
| `beef/in_memory.rs` | The stream's rules on the in-memory forms: `Bump::to_merkle_path`, `Bump::in_memory` (each level by offset, the `u32` height bound) and `Bump::read_alone` (one BUMP by the decoder, #167), the walk on a `MerklePath`, `check_transaction` on a `BeefTx`, the atomic table (#86) |
| `beef_tx.rs` | `BeefTx` wrapper, `TxDataFormat`, format constants; `BeefTx::from_reader` reads one entry (no BEEF reader calls it since #86); `tx_mut` makes the transaction the entry's only reading (#171): the bytes and txid it was read with dropped, the BUMP index kept, `input_txids` refreshed (`refresh`) by the BEEF's next whole-BEEF reader, which re-keys the index; `has_txid` checks an index hit, so a renamed entry is not found by its old txid |
| `beef_stream.rs` | The streaming reader: `BeefDecoder` (and its collect mode, the whole reader's parser), `BeefStream`, `BeefIndex`, `verify_stream`, `Verdict`, `Cursor`, `SpendRefusal` (its `Display` beside the enum, one sentence per arm, the texts pinned in `tests/beef_stream.rs`'s `a_spend_refusal_prints_*`, #213); the specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean |
| `beef_stream/reason.rs` | The refusal's names, `Kind` (twenty-six, `Kind::ALL`; `LeftDuplicateBelow` since #167's re-read) and `Reason`, re-exported from `beef_stream`; both `#[non_exhaustive]` (#86, #167): a `match` outside the crate ends in a wildcard arm |
| `beef_stream/budget.rs` | The readers' `set_work_limit` and `set_memory_limit` (#373); budgets remain local and absent from cursors |
| `beef_stream/evaluation.rs` | Local `Evaluation { work, memory, chain }`, `with_chain_params` on sync/async readers and `verify_stream_two_pass_with_chain_params`; no caller-made word or era resolver |
| `beef_stream/spends.rs` | In-order/deferred input checks, only referenced source scripts retained, one shared sighash cache; source heights from the verified BUMP index |
| `beef_stream/deferred.rs` | What the stream holds for a parent not read yet (#240): `HeldTx` (a transaction's index entry, its raw bytes dropped), `TxFields` (one fold for a transaction read in order and one released), `Deferred` (the held entries by offset, the txids each waits on, the ready ones, the bytes held; no bound; `unresolved`, what the end refuses), the index's and the reader's sides of the release (`BeefIndex::held_for_a_parent`, `BeefIndex::release_one`, `Judge::release_next`, one per step; `AsyncStreamVerifier::release_all`, every released one at once), `write_held` and `read_held` (a BSC4 cursor's held entries) |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `fee_models/` | `SatoshisPerKilobyte`, `LivePolicy`, `LivePolicyConfig`, default constants |
| `broadcaster.rs` | `Broadcaster` trait, response/failure types, helper functions |
| `broadcasters/` | `TeranodeBroadcaster`, `WhatsOnChainBroadcaster`, `ArcBroadcaster` (deprecated, #350) |
| `chain_tracker.rs` | `ChainTracker` trait, `MockChainTracker` (a synthetic mainnet mining tip at its height, `with_mining_tip`; #218), `AlwaysValidChainTracker` |
| `chain_trackers/` | `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, `BlockHeadersServiceConfig` |

## Core Types

`Transaction::verify` has no work budget; `SpendParams::work_limit` and `StreamVerifier::set_work_limit` bound charged work, while an elapsed-time bound must be external because a work counter cannot interrupt one arithmetic opcode (#378).

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
    pub version: u32,                     // Default: 1
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,                   // Default: 0
    pub metadata: HashMap<String, Value>, // Not serialized
    pub merkle_path: Option<MerklePath>,  // SPV proof (stops BEEF ancestry walk)
    // Internal caches: cached_hash, raw_bytes_cache, hex_cache
}

impl Transaction {
    // Constructors
    pub fn new() -> Self
    pub fn with_params(version, inputs, outputs, lock_time) -> Self

    // Parsing
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_ef(ef: &[u8]) -> Result<Self>           // Extended Format (BRC-30)
    pub fn from_hex_ef(hex: &str) -> Result<Self>
    pub fn from_beef(beef: &[u8], txid: Option<&str>) -> Result<Self>
    pub fn from_atomic_beef(beef: &[u8]) -> Result<Self>
    pub fn from_json(json: &str) -> Result<Self>         // Go SDK-compatible JSON
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets>

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
    pub async fn fee(&mut self, fee_sats: Option<u64>, change_distribution: ChangeDistribution) -> Result<()>
    pub fn get_fee(&self) -> Result<u64>
    pub fn estimate_size(&self) -> usize

    // SPV Verification
    pub async fn verify(&self, chain_tracker: &dyn ChainTracker, fee_model: Option<&dyn FeeModel>, memory_limit: Option<usize>) -> Result<bool>
    pub async fn verify_with_chain_params(&self, chain_tracker: &dyn ChainTracker, fee_model: Option<&dyn FeeModel>, memory_limit: Option<usize>, chain: &ChainParams) -> Result<bool>
    // memory_limit: the reference's third parameter; None uncapped, as its default (#331), Some(n) n bytes per stack
    // an invalid script: Err(TransactionError("Script validation failed for input N: …"));
    // an input stopped at the caller's budget, or by the allocator: Err(ScriptEvaluationDeclined { input_index, limit }) (#38)
}

pub enum ChangeDistribution { Equal, Random }  // Random uses Benford's law
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
    pub fn new_unchecked(block_height, path) -> Result<Self>    // Skips offset validation
    pub fn from_hex/from_binary/from_reader(...)                // Parsing: the BEEF reader's BUMP decoder (#167)
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self  // Single-tx block
    pub fn to_hex/to_binary/to_writer(...)                      // Serialization
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>  // One cached walk (RootWalker)
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>  // Same height/root required
    pub fn trim(&mut self)  // Remove unnecessary internal nodes
}
```

One decoder (bsv-rs#167): `from_binary`, `from_hex` and `from_reader` read a BUMP by the decoder that reads one in a BEEF (`Bump::read_alone`, then `Bump::in_memory`), so a BUMP means one thing wherever this crate reads it: a leaf flag `00`, `01` or `02` (`BadFlag` otherwise), an offset within its level (`OffsetOutsideTree`) and once there (`DuplicateOffset` at the second leaf's offset varint), a tree height of 1 to 64, every hashed leaf of level 0 climbing to one root by the stream's walk (`MissingSibling`, `MismatchedNode`, `LeftDuplicateBelow`, `NoTxidAtLevelZero`), a block height that fits the `u32` (`RootNotCarried` at the BUMP); a refusal is `MerklePathError("invalid BUMP at byte N: Reason")`, `N` counted from the BUMP's leading byte, the words after "at byte" the stream's (#167). `from_binary` and `from_hex` take the bytes as one BUMP and refuse a byte after the frame (`TrailingBytes` at its offset, #167); `from_reader` reads one frame and leaves the cursor after it, as TS's `fromBinary` (a reader's) leaves it; `MerklePath::read_bump` in `beef/in_memory.rs` is both. `tests/merkle_path_two_readers_agree.rs` (every BUMP the tree holds and its prefixes and single-byte changes: 0 disagreements) and `fuzz_merkle_path` pin it. A duplicate (flag `01`) at an even offset is read as the reference reads it (#167, the re-read of 2026-10-26: one verdict across the SDKs): the walk pairs the working hash with itself where the duplicate is its sibling, at either offset (`ts-stack@edf6e03` `MerklePath.ts:60`), and refuses a computed sibling that rests on a duplicate at an even offset, as its left child or under a child computed in turn, `LeftDuplicateBelow { level, offset }` at the offset varint of the level-0 leaf whose path needs it, where the reference's walk throws `Missing hash for index N at height N` (`:58`, `:628-631`); `new` and `new_unchecked` read it with `RootWalker`, which gives up there too (`Missing hash at height N, offset N`). Through 0.9.0-beta.1 every path refused it (`BadFlag { byte: 1 }`, a pre-pass, `Duplicate at an even offset`). Pinned by `tests/merkle_path_even_offset_duplicate.rs` on the reference's verdicts (`tests/vectors/merkle_path_even_offset_duplicate_167.json`).

Validation in `new()`: level 0 non-empty, no duplicate offsets, legal higher-level offsets, all txids compute same root. A one-level lone hashed leaf is valid only at offset 0; the parse (the decoder's walk) and `compute_root` (`RootWalker`) share this rule, refusing other offsets with `MissingSibling` and the missing sibling's level and offset (the parse refuses a lone leaf at 2 or above earlier, `OffsetOutsideTree`). TS returns the txid at any offset (`ts-stack@edf6e03 MerklePath.ts:345,390-391`); this divergence follows the BEEF reader and the owner's offset-0 ruling.

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
    // Serialization: to_hex(), to_binary() [auto-sorts], to_binary_atomic(txid)
    // Validation: is_valid(allow_txid_only), verify_valid() -> BeefValidationResult, verify_structure() -> Result<roots, Kind> (0.4.2), sort_txs() -> SortResult
    // Lookup: find_txid(), find_txid_mut(), find_bump(), find_transaction_for_signing(), find_atomic_transaction(), is_atomic()
    // Merging: merge_bump() [combines same height/root], merge_transaction(), merge_raw_tx(), merge_txid_only(), make_txid_only(), merge_beef()
    // Utility: clone_shallow(), to_log_string()
}

pub struct BeefValidationResult { pub valid: bool, pub roots: HashMap<u32, String> }
pub struct SortResult { pub missing_inputs, not_valid, valid, with_missing_inputs, txid_only: Vec<String> }
```

**BeefTx**: Wraps a single tx in BEEF. Constructors: `from_tx(tx, bump_index)`, `from_raw_tx(raw_tx, bump_index)`, `from_txid(txid)`. Accessors: `txid()`, `tx()`, `tx_mut()` (the transaction then the entry's only reading, #171), `raw_tx()`, `raw_tx_or_compute()`. State: `has_proof()`, `is_txid_only()`, `bump_index()`, `set_bump_index()`. Public fields: `input_txids`, `is_valid`.

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

- **Caching**: Transaction hash/serialization cached in RefCell; invalidates on modification via `add_input()`, `add_output()`, `sign()`, `fee()`
- **Inputs**: Must have `source_txid` or `source_transaction`; fee calc/signing need full source tx with satoshis/locking_script
- **Convenience inputs**: `add_input_from_tx` sets template; `add_input_from` builds a minimal source tx; `add_inputs_from_utxos` does NOT set templates (caller must set them separately)
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()` using Benford's law for Random distribution
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Debug**: `Transaction` and `TransactionInput` implement `Debug` by hand; a linked `source_transaction` prints as `Some("<txid>")`, never its ancestry (0.3.35, bsv-stack-lean #57 P0-5c)
- **Async traits**: `Broadcaster` uses `?Send` (Transaction has RefCell); `ChainTracker` is standard async
- **HTTP feature**: `TeranodeBroadcaster`, `ArcBroadcaster` (deprecated), `WhatsOnChainBroadcaster`, `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, and `LivePolicy` require the `http` feature flag
- **BEEF ancestry**: `to_beef()` and `to_beef_v1()` walk the `source_transaction` chain depth first with an explicit stack via `collect_ancestors()`, stop at txs with `merkle_path`, and store each ancestor without its own ancestry
- **BEEF V1 vs V2**: Use `to_beef_v1()` for a reader that takes V1 only (BRC-62), `to_beef()` for V2 with TXID-only support (BRC-96)
- **BEEF indexing**: Beef maintains an internal `txid_index` HashMap for O(1) transaction lookup by txid
- **MerklePath root check**: `new` and `new_unchecked` check every level-0 leaf's root with one `RootWalker` (the parse, since #167, by the decoder's walk) that indexes each level by offset and computes each node once, shared across the walks (the reference's `computeRootCached`; linear in the leaves since 0.3.35, bsv-stack-lean #57 P0-5c). A tree height over 64 is refused before any shift
- **MerklePath dedup**: BEEF ancestry collection deduplicates proofs by `"height:root"` key; combines proofs at same height/root
- **Dependency order**: BEEF transactions sorted oldest-first; inputs processed in reverse order during collection (like TS SDK)
- **JSON format**: `to_json()`/`from_json()` match Go SDK's `MarshalJSON`/`UnmarshalJSON`; deserialization prefers `hex` field when present
- **Default impls**: `Transaction`, `TransactionInput`, `TransactionOutput`, `Beef`, `MockChainTracker`, `WhatsOnChainBroadcaster`, `WhatsOnChainTracker` implement `Default`
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
builder. Apply it before stepping; reapply it after any resume, including a
decoded cursor, exactly as the local budgets. No flag word is serialized.

The verifier obtains source heights only from header-verified BUMPs; unproven
sources use the spend era. Transaction flags use tip + 1 with checked overflow;
without a tip they use the latest era in the chain parameters. Pre-Genesis is
refused explicitly. A proven transaction still stops at its proof: the stream
runs scripts only for unproven transactions; callers judging mined scripts can
use `input_script_flags(..., mined = true)` with their block height.
Structural, atomic, finality/maturity, value, duplicate and deferred-parent rules
are unchanged. `ChainParams` is authoritative for script activation; the old
`ChainTip::genesis_height` field remains for the existing mining checks.
