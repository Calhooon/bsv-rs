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
- BEEF format (BRC-62/95/96) for SPV proofs with recursive ancestry collection
- Async Broadcaster trait with ARC and WhatsOnChain implementations
- Async ChainTracker trait with WhatsOnChain and BlockHeadersService implementations

Compatible with the TypeScript and Go SDKs through shared binary formats.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports all public types |
| `input.rs` | `TransactionInput` for transaction inputs |
| `output.rs` | `TransactionOutput` for transaction outputs |
| `transaction.rs` | `Transaction` with parsing, serialization, signing, BEEF ancestry collection |
| `merkle_path.rs` | `MerklePath` (BRC-74 BUMP) for merkle proofs |
| `beef.rs` | `Beef` (BRC-62/95/96) with validation, sorting, and merging |
| `beef_tx.rs` | `BeefTx` wrapper, `TxDataFormat`, format constants |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `fee_models/` | `SatoshisPerKilobyte`, `LivePolicy`, `LivePolicyConfig` |
| `broadcaster.rs` | `Broadcaster` trait, response/failure types |
| `broadcasters/` | `ArcBroadcaster`, `ArcConfig`, `WhatsOnChainBroadcaster`, `WocBroadcastConfig` |
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
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets>

    // Serialization
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_hex(&self) -> String
    pub fn to_ef(&self) -> Result<Vec<u8>>
    pub fn to_hex_ef(&self) -> Result<String>
    pub fn to_beef(&self, allow_partial: bool) -> Result<Vec<u8>>      // BEEF V2
    pub fn to_beef_v1(&self, allow_partial: bool) -> Result<Vec<u8>>   // BEEF V1 for ARC
    pub fn to_atomic_beef(&self, allow_partial: bool) -> Result<Vec<u8>>

    // Hashing
    pub fn hash(&self) -> [u8; 32]        // Double SHA-256 (internal byte order)
    pub fn id(&self) -> String            // TXID (reversed hash as hex)
    pub fn hash_hex(&self) -> String

    // Building
    pub fn add_input(&mut self, input: TransactionInput) -> Result<()>
    pub fn add_output(&mut self, output: TransactionOutput) -> Result<()>
    pub fn add_p2pkh_output(&mut self, address: &str, satoshis: Option<u64>) -> Result<()>
    pub fn update_metadata(&mut self, key: &str, value: Value)
    pub fn input_count(&self) -> usize
    pub fn output_count(&self) -> usize

    // Signing & Fees
    pub async fn sign(&mut self) -> Result<()>
    pub async fn fee(&mut self, fee_sats: Option<u64>, change_distribution: ChangeDistribution) -> Result<()>
    pub fn get_fee(&self) -> Result<u64>
    pub fn estimate_size(&self) -> usize
}

pub enum ChangeDistribution { Equal, Random }  // Random uses Benford's law
pub struct ScriptOffsets { pub inputs: Vec<ScriptOffset>, pub outputs: Vec<ScriptOffset> }
pub struct ScriptOffset { pub index: usize, pub offset: usize, pub length: usize }
```

## Fee Models

```rust
pub trait FeeModel: Send + Sync {
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>;
}

// Fixed fee - always returns the same amount
pub struct FixedFee(u64);
impl FixedFee {
    pub fn new(satoshis: u64) -> Self
}

// Satoshis per kilobyte - computes based on transaction size
pub struct SatoshisPerKilobyte { pub value: u64 }
impl SatoshisPerKilobyte {
    pub fn new(value: u64) -> Self      // value = satoshis per KB
    pub fn default() -> Self            // 100 sat/KB (standard BSV rate)
}

// Live policy - fetches fee rate from ARC policy endpoint
pub struct LivePolicy { /* ... */ }
impl LivePolicy {
    pub fn new() -> Self                // Uses DEFAULT_POLICY_URL
    pub fn with_url(policy_url: &str) -> Self
    pub fn with_config(config: LivePolicyConfig) -> Self
    pub fn policy_url(&self) -> &str
    pub fn cache_ttl(&self) -> Duration
    pub async fn refresh(&self) -> Result<u64>  // Fetch live rate
    pub fn cached_rate(&self) -> Option<u64>
    pub fn effective_rate(&self) -> u64  // Cached or fallback (100 sat/KB)
    pub fn set_rate(&self, rate: u64)    // Manual override
}

pub struct LivePolicyConfig {
    pub policy_url: String,
    pub api_key: Option<String>,
    pub cache_ttl: Duration,        // Default: 5 minutes
    pub fallback_rate: u64,         // Default: 100 sat/KB
    pub timeout_ms: u64,
}

pub const DEFAULT_POLICY_URL: &str = "https://arc.gorillapool.io/v1/policy";
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;
pub const DEFAULT_FALLBACK_RATE: u64 = 100;
```

## Broadcasting

```rust
#[async_trait(?Send)]
pub trait Broadcaster: Send + Sync {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult;
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>;
}

pub struct BroadcastResponse { pub status: BroadcastStatus, pub txid: String, pub message: String, pub competing_txs: Option<Vec<String>> }
pub struct BroadcastFailure { pub status: BroadcastStatus, pub code: String, pub txid: Option<String>, pub description: String, pub more: Option<Value> }
pub enum BroadcastStatus { Success, Error }
pub type BroadcastResult = Result<BroadcastResponse, BroadcastFailure>;

// Implementations (require http feature): ArcBroadcaster, WhatsOnChainBroadcaster
```

## Chain Tracking

```rust
#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

pub enum ChainTrackerError { NetworkError(String), InvalidResponse(String), BlockNotFound(u32), Other(String) }

// Test mocks: MockChainTracker, AlwaysValidChainTracker
// HTTP implementations: WhatsOnChainTracker, BlockHeadersServiceTracker
```

## MerklePath (BUMP - BRC-74)

```rust
pub struct MerklePath {
    pub block_height: u32,
    pub path: Vec<Vec<MerklePathLeaf>>,  // Tree structure, level 0 = txids
}

pub struct MerklePathLeaf {
    pub offset: u64,            // Position in tree level
    pub hash: Option<String>,   // None if duplicate
    pub txid: bool,             // True if this is a transaction ID
    pub duplicate: bool,        // True if hash duplicated from sibling
}

impl MerklePathLeaf {
    pub fn new(offset: u64, hash: String) -> Self
    pub fn new_txid(offset: u64, hash: String) -> Self
    pub fn new_duplicate(offset: u64) -> Self
}

impl MerklePath {
    // Constructors
    pub fn new(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>  // Full validation
    pub fn new_unchecked(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>  // Skips offset validation
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_reader(reader: &mut Reader) -> Result<Self>
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self  // Single-tx block

    // Serialization
    pub fn to_hex(&self) -> String
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_writer(&self, writer: &mut Writer)

    // Verification
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>  // All txids marked with txid=true

    // Merging
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>  // Same height/root required
    pub fn trim(&mut self)  // Remove unnecessary internal nodes
}
```

Validation in `new()`:
- Level 0 must not be empty
- No duplicate offsets at same level
- All higher-level offsets must be derivable from level 0 txids
- All txids must compute to the same root

## BEEF Format (BRC-62/95/96)

```rust
pub struct Beef {
    pub bumps: Vec<MerklePath>,       // Merkle proofs
    pub txs: Vec<BeefTx>,             // Transactions (sorted by dependency)
    pub version: u32,                 // BEEF_V1 or BEEF_V2
    pub atomic_txid: Option<String>,  // Target txid for Atomic BEEF
}

impl Beef {
    pub fn new() -> Self                 // V2 by default
    pub fn with_version(version: u32) -> Self
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn to_hex(&mut self) -> String
    pub fn to_binary(&mut self) -> Vec<u8>         // Auto-sorts txs
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>>

    // Validation
    pub fn is_valid(&mut self, allow_txid_only: bool) -> bool
    pub fn verify_valid(&mut self, allow_txid_only: bool) -> BeefValidationResult
    pub fn sort_txs(&mut self) -> SortResult

    // Lookup
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx>
    pub fn find_bump(&self, txid: &str) -> Option<&MerklePath>

    // Merging
    pub fn merge_bump(&mut self, bump: MerklePath) -> usize  // Combines same height/root
    pub fn merge_transaction(&mut self, tx: Transaction) -> &BeefTx
    pub fn merge_txid_only(&mut self, txid: String) -> &BeefTx
    pub fn make_txid_only(&mut self, txid: &str) -> Option<&BeefTx>
    pub fn merge_beef(&mut self, other: &Beef)
}

pub struct BeefValidationResult { pub valid: bool, pub roots: HashMap<u32, String> }
pub struct SortResult { pub missing_inputs, not_valid, valid, with_missing_inputs, txid_only: Vec<String> }

pub struct BeefTx { pub input_txids: Vec<String>, pub is_valid: Option<bool> }
impl BeefTx {
    pub fn from_tx(tx: Transaction, bump_index: Option<usize>) -> Self
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self
    pub fn from_txid(txid: String) -> Self
    pub fn has_proof(&self) -> bool      // bump_index.is_some()
    pub fn is_txid_only(&self) -> bool   // Has txid but no tx data
    pub fn txid(&self) -> String
    pub fn tx(&self) -> Option<&Transaction>
}

pub enum TxDataFormat { RawTx = 0, RawTxAndBumpIndex = 1, TxidOnly = 2 }
pub const BEEF_V1: u32 = 0xEFBE0001;  // BRC-62
pub const BEEF_V2: u32 = 0xEFBE0002;  // BRC-96 with txid-only
pub const ATOMIC_BEEF: u32 = 0x01010101;  // BRC-95
```

## Usage Examples

```rust
// Building and Signing
let mut tx = Transaction::new();
tx.add_input(TransactionInput::with_source_transaction(source_tx, 0))?;
tx.add_output(TransactionOutput::new(100_000, locking_script))?;
tx.add_p2pkh_output("1MyChange...", None)?;  // Change output
tx.fee(None, ChangeDistribution::Equal).await?;
tx.sign().await?;

// Broadcasting
let broadcaster = ArcBroadcaster::default();
let result = broadcaster.broadcast(&tx).await;

// Serializing to BEEF (recursively collects ancestors)
let beef_v1 = tx.to_beef_v1(false)?;  // For ARC
let beef_v2 = tx.to_beef(false)?;     // V2 format
let atomic = tx.to_atomic_beef(false)?;

// SPV Verification
let tracker = WhatsOnChainTracker::mainnet();
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
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()` using Benford's law for Random distribution
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Async traits**: `Broadcaster` uses `?Send` (Transaction has RefCell); `ChainTracker` is standard async
- **HTTP feature**: `ArcBroadcaster`, `WhatsOnChainBroadcaster`, `WhatsOnChainTracker`, `BlockHeadersServiceTracker`, and `LivePolicy` require the `http` feature flag
- **BEEF ancestry**: `to_beef()` and `to_beef_v1()` recursively walk `source_transaction` chain via `collect_ancestors()`, stops at txs with `merkle_path`
- **BEEF V1 vs V2**: Use `to_beef_v1()` for ARC compatibility (BRC-62), `to_beef()` for V2 with TXID-only support (BRC-96)
- **MerklePath dedup**: BEEF ancestry collection deduplicates proofs by `"height:root"` key; combines proofs at same height/root
- **Dependency order**: BEEF transactions sorted oldest-first; inputs processed in reverse order during collection (like TS SDK)
- **Default impls**: `Transaction`, `TransactionInput`, `TransactionOutput`, `Beef`, `MockChainTracker` implement `Default`
- **Equality**: `Transaction` and `TransactionOutput` implement `PartialEq`/`Eq` based on binary serialization

## BEEF Ancestry Collection Algorithm

The `collect_ancestors()` method implements the same algorithm as TypeScript/Go SDKs:

1. **Cycle detection**: Skip transactions already seen (by txid)
2. **Proven transactions**: If tx has `merkle_path`, add proof (deduplicated by height:root) and stop recursion
3. **Unproven transactions**: Recursively process each input's `source_transaction` in reverse order
4. **Dependency order**: After processing all ancestors, add current transaction
5. **Partial support**: `allow_partial=true` skips inputs with missing source transactions

## Error Types

| Error Type | Conditions |
|------------|------------|
| `TransactionError` | Missing source, satoshis, uncomputed change, EF marker issues, BEEF parsing |
| `FeeModelError` | Input missing unlocking script or template |
| `BeefError` | Invalid version (not V1/V2), missing atomic txid, txid not in BEEF |
| `MerklePathError` | Empty path, duplicate offset, invalid offset at height, mismatched roots |
| `ChainTrackerError` | `NetworkError`, `InvalidResponse`, `BlockNotFound(height)`, `Other` |

## Related Documentation

- `../script/CLAUDE.md` - LockingScript, UnlockingScript, templates
- `../primitives/CLAUDE.md` - Reader, Writer, sha256d, from_hex, to_hex
- `fee_models/CLAUDE.md` - SatoshisPerKilobyte, LivePolicy
- `broadcasters/CLAUDE.md` - ArcBroadcaster, WhatsOnChainBroadcaster
- `chain_trackers/CLAUDE.md` - WhatsOnChainTracker, BlockHeadersServiceTracker
