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
- A raw transaction with no input is invalid bytes (0.4.1, bsv-stack-lean #58): `Kind::NoInputs` at the transaction's offset from the streaming reader, not valid from `Beef::verify_valid`, with or without a BUMP index. The rule is the node's (bsv-script-lean `lean/BsvScript/TxRules.lean`, `checkTransactionCommon_vinEmpty`); a test BEEF's root needs an input and a merkle path
- A raw transaction with an input and no output is invalid bytes too (0.4.3, bsv-stack-lean #59): `Kind::NoOutputs` at the transaction's offset, after the inputs' check (the sibling's `TxRules.lean:85-86`, `checkTransactionCommon_voutEmpty`); `beef_stream::no_transaction` answers both for every path. `Transaction::verify` refuses a transaction it reaches with either, proven or not (`invalid transaction <txid>: NoInputs`): there is no synthetic root
- The whole path on the reader's walk and rules (0.4.2, bsv-stack-lean #61): `Beef::verify_valid` computes each BUMP's root by `beef_stream`'s `bump_root` (linear; 0.4.1 walked once per leaf), and `Beef::verify_structure` answers the roots or the reader's `Kind`. A lone leaf at an offset other than 0 is `MissingSibling`; `from_binary` refuses a byte after the frame (`TrailingBytes`, in the reader's words); an atomic BEEF is held to the reader's atomic rule (`SubjectMissing`, `UnrelatedTransaction`); a txid-only entry is valid when a BUMP of the BEEF proves it (`StubNotProven` otherwise) and `allow_txid_only` decides nothing
- One reader (bsv-rs#86): the whole-BEEF reader is a mode of the streaming reader. `Beef::from_binary`, `from_hex`, `from_reader` and `from_binary_with_limits` (and through them `Transaction::from_beef` and `from_atomic_beef`) run `BeefDecoder::collecting()` (crate-private) and collect its elements into the `Beef` in one pass (`beef/collect.rs`): the BUMPs by `Bump::to_merkle_path`, each level's leaves sorted by offset as the in-memory form always held them; the transactions from the bytes the decoder read (`Transaction::from_binary` on them, so the hash is the bytes'), in the order written; version and subject from the header. The parse refuses what the stream refuses as a frame or a BUMP (a second leaf at an offset its level carries among them, agreeing or not: `MismatchedNode { level, offset }` at its offset varint, the reference's `Duplicate offset`; `bump_root` refuses one held in memory), in the stream's words (`BEEF error: invalid BEEF at byte N: Reason`, `Error::BeefError`): the earliest refusal of the reading, an earlier element's content or fold refusal included (a structure-only `BeefIndex` folds each element beside the collection, the leading BUMP's root at a height as the one root the headers carry there). The collect mode yields a transaction whatever its content (`check_transaction`: unproven coinbase, no input, no output, `ValueOutOfRange`, null or repeated outpoint), so such a BEEF parses and `verify_structure` judges it. `verify_structure` is one pass over the entries in the order held, each judged as the decoder and the fold judge an element (`beef/in_memory.rs`: `merkle_path_root`, `content_refused`, `atomic_table`), an unproven input judged against the entries held ahead of it (BRC-62's order, the stream's: a transaction written ahead of its parent is `InputNamesNoElement`, before the sort; through 0.9.0 the sort ran ahead of judging, as TS's and Go's `verifyValid` do), then the sort, then the atomic rule. A BUMP above a `u32` height is `RootNotCarried` at the parse (the in-memory height is a `u32`; through 0.9.0 it was cut to its low bits). The differential `tests/beef_two_readers_agree.rs` (every BEEF the tree holds, its prefixes, single-byte changes and reversals: 0 disagreements, no stated difference) and `fuzz_beef_parser`'s assertion pin it
- The atomic rule on the subject's graph (0.8.1, BRC-95): one walk, `beef_stream::atomic_unreached` (the Lean's `finish`, bsv-stack-lean `lean/BeefOfAnySize.lean` `walk`/`finish`), called by `BeefIndex::finish` (the stream) and `Beef::verify_structure` (the whole path). The subject is a raw transaction of the BEEF, else `SubjectMissing` (at 4 behind a prefix); every other entry, raw or txid-only, is reached from the subject through the inputs of raw entries, else `UnrelatedTransaction`. The entry a refusal names is the earliest, by the trie order (the txid's bytes, each byte's bits reversed, least first), of the entries the walk does not reach, at its offset (the ruled text, 2026-10-22). The whole path's verdict is a `Kind` and names no entry. A one-flag predicate (is the entry spent by some raw entry?) gives the same verdict, the refusal set being empty exactly when every entry is reachable (a txid is a hash: no chain of spends returns), but not the same entry: beside the subject, a raw `X` nothing spends and its parent `Y` that only `X` spends are both unreached, and the flag names `X` even when `Y` is earlier (`an_unreached_parent_earlier_by_the_trie_order_is_the_entry_named`, red on the flag predicate). No flag can stand in for the edges: two BEEFs with the same flags can leave different entries unreached. Position is not judged: the TS writer puts proven entries first, so a raw unproven ancestor can follow its proven descendant (the bsv-dd x402 refund, P0-65), and this crate's `to_binary_atomic` (the same sort, no cut) wrote such an ancestor after the subject until it emitted the closure. The graph follows the inputs of every raw entry, proven or not (the owner's ruling, 2026-10-22); TS ≥ 3 cuts it at each proven transaction (ts-stack `Beef.ts:420-434`) and refuses a raw ancestor behind a proof, a stated divergence (the root `CLAUDE.md`). The BRC-62 clause (an unproven transaction spends earlier transactions) is unchanged. The stream keeps the edges: under a subject each raw transaction's entry holds the txids its inputs name (`TxEntry::prevs`, the Lean's `prevs`), and the walk marks entries in place (`reached`, no table beside the index). They are kept only under a subject (the caller's, or the prefix's: the header precedes the first element; `BeefIndex::hold_to_subject`), and `entries()` counts them. `spec_size()` is the Lean's `Index.size`, which counts one edge per input of every raw transaction read, a repeat's again, with or without a subject (a counter, `inputs`; not a table). `model_work()` adds the Lean's atomic end: one pass over the table and the walk's fuel three times (`entries + 3 * (entries + inputs + 2)`). The bound: per element, plus 32 bytes per input of a raw transaction, only under a subject (an input is 41 bytes or more on the wire: linear in the bytes read). Measured (`memory_profiling`): the deep chain under its subject 352, 281, 225 B per element at 1,000, 10,000, 100,000 links (0.8.0: 274, 219, 175; the bound is 400); 100 proven transactions of 1,000 inputs, 262 KB peak without a subject, 32 B per input under one; the cursor after one proven transaction of 10,000 inputs is 238 B without a subject, 320,305 B under one. The cursor format is BSC3: after the transactions, the inputs counted and the edges, by txid strictly ascending (a list out of order, or edges of a txid the index does not hold raw, is refused); a BSC2 cursor reads as BSC3 with no edge (the walk reaches less: it only refuses more). Pinned by `tests/beef_atomic_graph.rs` and the staged vectors `tests/transaction/vectors/atomic-beef.json` (run by `tests/conformance_beef.rs`, the X/Y pair's named entries and offsets pinned there too)
- The atomic writer emits the BRC-95 closure (0.8.1): `Beef::to_binary_atomic` writes the subject and, through the inputs of raw entries, its ancestry up to each transaction a BUMP of the BEEF proves (and each txid-only entry), the BUMPs renumbered, the reference's sort, the subject last; every other entry and BUMP is dropped. What `@bsv/sdk` 3 (`#collectAtomicTransactions`) and go-sdk (`selectAtomicBeef`) write; `to_binary` still writes every entry. Pinned by `tests/beef_atomic_graph.rs` (`the_atomic_writer_emits_the_brc95_closure_and_drops_the_rest`, `every_accepted_vector_round_trips_through_the_atomic_writer`)
- `BeefLimits { max_txs, max_bumps }` are memory hints since 0.4.0; `Beef::from_binary_with_limits` is deprecated and refuses nothing by size or count
- JSON serialization matching Go SDK format for cross-SDK compatibility
- Async Broadcaster trait with ARC, Teranode, and WhatsOnChain implementations
- Async ChainTracker trait with WhatsOnChain and BlockHeadersService implementations

Compatible with the TypeScript and Go SDKs through shared binary formats.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports all public types and sighash constants |
| `input.rs` | `TransactionInput` and `Utxo` for transaction inputs |
| `output.rs` | `TransactionOutput` for transaction outputs |
| `transaction.rs` | `Transaction` with parsing, serialization, signing, SPV verification, BEEF ancestry collection |
| `tx_json.rs` | JSON serialization/deserialization matching Go SDK's `MarshalJSON`/`UnmarshalJSON` |
| `merkle_path.rs` | `MerklePath` (BRC-74 BUMP) for merkle proofs |
| `beef.rs` | `Beef` (BRC-62/95/96): the type, the public readers (over `beef/collect.rs`), `verify_structure`, sorting, merging, the writers (`to_binary`, the atomic closure), logging |
| `beef/collect.rs` | The whole-BEEF reader: the streaming decoder's collect mode collected into a `Beef`, with the stream's judge beside it (#86) |
| `beef/in_memory.rs` | The stream's rules on the in-memory forms: `Bump::to_merkle_path`, the walk on a `MerklePath`, `check_transaction` on a `BeefTx`, the atomic table (#86) |
| `beef_tx.rs` | `BeefTx` wrapper, `TxDataFormat`, format constants; `BeefTx::from_reader` reads one entry (no BEEF reader calls it since #86) |
| `beef_stream.rs` | The streaming reader: `BeefDecoder` (and its collect mode, the whole reader's parser), `BeefStream`, `BeefIndex`, `verify_stream`, `Verdict`, `Cursor`; the specification is the Lean definition `BeefOfAnySize` of bsv-stack-lean |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `fee_models/` | `SatoshisPerKilobyte`, `LivePolicy`, `LivePolicyConfig`, default constants |
| `broadcaster.rs` | `Broadcaster` trait, response/failure types, helper functions |
| `broadcasters/` | `ArcBroadcaster`, `TeranodeBroadcaster`, `WhatsOnChainBroadcaster` |
| `chain_tracker.rs` | `ChainTracker` trait, `MockChainTracker`, `AlwaysValidChainTracker` |
| `chain_trackers/` | `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, `BlockHeadersServiceConfig` |

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
    pub fn to_beef_v1(&self, allow_partial: bool) -> Result<Vec<u8>>   // BEEF V1 for ARC
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
    pub async fn verify(&self, chain_tracker: &dyn ChainTracker, fee_model: Option<&dyn FeeModel>) -> Result<bool>
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
pub struct LivePolicy { /* ... */ }                    // Fetches rate from ARC policy endpoint

// Exported constants
pub const DEFAULT_POLICY_URL: &str;     // "https://arc.gorillapool.io/v1/policy"
pub const DEFAULT_FALLBACK_RATE: u64;   // Fallback sat/KB rate
pub const DEFAULT_CACHE_TTL_SECS: u64;  // Cache TTL for live policy
```

`LivePolicy` has `new()`, `with_url()`, `with_config(LivePolicyConfig)`, `refresh()` (async fetch), `cached_rate()`, `effective_rate()`, `set_rate()`. Config: `LivePolicyConfig { policy_url, api_key, cache_ttl, fallback_rate, timeout_ms }`. Default policy URL: `https://arc.gorillapool.io/v1/policy`.

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
| `ArcBroadcaster` | BEEF V1 (JSON) | `default()` = gorillapool.io | `ArcConfig` |
| `TeranodeBroadcaster` | Extended Format (EF binary) | No default URL | `TeranodeConfig` |
| `WhatsOnChainBroadcaster` | Raw tx hex | `mainnet()`, `testnet()`, `stn()` | `WocBroadcastConfig`, `WocBroadcastNetwork` |

ARC/Teranode have `new(url, api_key)` and `with_config(config)` constructors. WoC has `new(network, api_key)`, `mainnet()`, `testnet()`, `stn()`, `with_config(config)`, `with_base_url(url, network, api_key)`. `WocBroadcastNetwork` enum selects `Mainnet`, `Testnet`, or `STN`.

## Chain Tracking

```rust
#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

#[non_exhaustive]
pub enum ChainTrackerError { NetworkError(String), TransportFault { fault: TransportFault, status: Option<u16>, detail: String }, InvalidResponse(String), BlockNotFound(u32), Other(String) }

// Test mocks
pub struct MockChainTracker { pub height: u32, pub roots: HashMap<u32, String> }
pub struct AlwaysValidChainTracker { pub height: u32 }
// MockChainTracker: new(height), add_root(height, root), always_valid(height) -> AlwaysValidChainTracker
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
    pub fn from_hex/from_binary/from_reader(...)                // Parsing
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self  // Single-tx block
    pub fn to_hex/to_binary/to_writer(...)                      // Serialization
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>  // One cached walk (RootWalker)
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>  // Same height/root required
    pub fn trim(&mut self)  // Remove unnecessary internal nodes
}
```

Validation in `new()`: level 0 non-empty, no duplicate offsets, legal higher-level offsets, all txids compute same root. A one-level lone hashed leaf is valid only at offset 0; parsing and `compute_root` share this rule in `RootWalker`, refusing other offsets with `MissingSibling` and the missing sibling's level and offset. TS returns the txid at any offset (`ts-stack@edf6e03 MerklePath.ts:345,390-391`); this divergence follows the BEEF reader and the owner's offset-0 ruling.

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

**BeefTx**: Wraps a single tx in BEEF. Constructors: `from_tx(tx, bump_index)`, `from_raw_tx(raw_tx, bump_index)`, `from_txid(txid)`. Accessors: `txid()`, `tx()`, `tx_mut()`, `raw_tx()`, `raw_tx_or_compute()`. State: `has_proof()`, `is_txid_only()`, `bump_index()`, `set_bump_index()`. Public fields: `input_txids`, `is_valid`.

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
let result = ArcBroadcaster::default().broadcast(&tx).await;             // BEEF V1
let result = WhatsOnChainBroadcaster::mainnet().broadcast(&tx).await;    // Raw hex
let result = TeranodeBroadcaster::new(url, None).broadcast(&tx).await;   // EF binary

// Serializing to BEEF (collects ancestors with an explicit stack)
let beef_v1 = tx.to_beef_v1(false)?;  // For ARC
let beef_v2 = tx.to_beef(false)?;     // V2 format
let atomic = tx.to_atomic_beef(false)?;

// SPV Verification (Transaction-level, by txid over the whole ancestry)
let tracker = WhatsOnChainTracker::mainnet();
let is_valid = tx.verify(&tracker, None).await?;              // SPV verify of the ancestry
let is_valid = tx.verify(&tracker, Some(&fee_model)).await?;  // With fee validation

// SPV Verification (BEEF-level, manual root checking)
let validation = beef.verify_valid(false);
for (height, root) in validation.roots {
    tracker.is_valid_root_for_height(&root, height).await?;
}

// Fee Models
let fee = SatoshisPerKilobyte::new(100).compute_fee(&tx)?;  // Fixed rate
let live = LivePolicy::default(); live.refresh().await?;     // Live rate
```

## Implementation Notes

- **Caching**: Transaction hash/serialization cached in RefCell; invalidates on modification via `add_input()`, `add_output()`, `sign()`, `fee()`
- **Inputs**: Must have `source_txid` or `source_transaction`; fee calc/signing need full source tx with satoshis/locking_script
- **Convenience inputs**: `add_input_from_tx` sets template; `add_input_from` builds a minimal source tx; `add_inputs_from_utxos` does NOT set templates (caller must set them separately)
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()` using Benford's law for Random distribution
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Debug**: `Transaction` and `TransactionInput` implement `Debug` by hand; a linked `source_transaction` prints as `Some("<txid>")`, never its ancestry (0.3.35, bsv-stack-lean #57 P0-5c)
- **Async traits**: `Broadcaster` uses `?Send` (Transaction has RefCell); `ChainTracker` is standard async
- **HTTP feature**: `ArcBroadcaster`, `TeranodeBroadcaster`, `WhatsOnChainBroadcaster`, `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, and `LivePolicy` require the `http` feature flag
- **BEEF ancestry**: `to_beef()` and `to_beef_v1()` walk the `source_transaction` chain depth first with an explicit stack via `collect_ancestors()`, stop at txs with `merkle_path`, and store each ancestor without its own ancestry
- **BEEF V1 vs V2**: Use `to_beef_v1()` for ARC compatibility (BRC-62), `to_beef()` for V2 with TXID-only support (BRC-96)
- **BEEF indexing**: Beef maintains an internal `txid_index` HashMap for O(1) transaction lookup by txid
- **MerklePath root check**: the parse checks every level-0 leaf's root with one `RootWalker` that indexes each level by offset and computes each node once, shared across the walks (the reference's `computeRootCached`; linear in the leaves since 0.3.35, bsv-stack-lean #57 P0-5c). A tree height over 64 is refused before any shift
- **MerklePath dedup**: BEEF ancestry collection deduplicates proofs by `"height:root"` key; combines proofs at same height/root
- **Dependency order**: BEEF transactions sorted oldest-first; inputs processed in reverse order during collection (like TS SDK)
- **JSON format**: `to_json()`/`from_json()` match Go SDK's `MarshalJSON`/`UnmarshalJSON`; deserialization prefers `hex` field when present
- **Default impls**: `Transaction`, `TransactionInput`, `TransactionOutput`, `Beef`, `MockChainTracker`, `WhatsOnChainBroadcaster`, `WhatsOnChainTracker` implement `Default`
- **SPV verify**: `verify()` performs queue-based verification over the whole ancestry (no recursion): checks merkle paths against chain tracker, validates fees (optional), runs script interpreter on each input, enqueues unverified source transactions. Matches Go SDK's `spv.Verify()` and TS SDK's `Transaction.verify()`
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
- `broadcasters/CLAUDE.md` - ArcBroadcaster, TeranodeBroadcaster, WhatsOnChainBroadcaster
- `chain_trackers/CLAUDE.md` - WhatsOnChainTracker, BlockHeadersServiceTracker
