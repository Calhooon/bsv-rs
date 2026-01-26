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
- BEEF format (BRC-62/95/96) for SPV proofs
- Async Broadcaster trait with ARC and WhatsOnChain implementations
- Async ChainTracker trait with WhatsOnChain and BlockHeadersService implementations

Compatible with the TypeScript and Go SDKs through shared binary formats.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports |
| `input.rs` | `TransactionInput` for transaction inputs |
| `output.rs` | `TransactionOutput` for transaction outputs |
| `transaction.rs` | `Transaction` with parsing, serialization, signing |
| `merkle_path.rs` | `MerklePath` (BRC-74 BUMP) |
| `beef.rs` | `Beef` (BRC-62/95/96) |
| `beef_tx.rs` | `BeefTx` wrapper, `TxDataFormat`, format constants |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `fee_models/` | `SatoshisPerKilobyte`, `LivePolicy` |
| `broadcaster.rs` | `Broadcaster` trait, response/failure types |
| `broadcasters/` | `ArcBroadcaster`, `WhatsOnChainBroadcaster` |
| `chain_tracker.rs` | `ChainTracker` trait, `MockChainTracker`, `AlwaysValidChainTracker` |
| `chain_trackers/` | `WhatsOnChainTracker`, `BlockHeadersServiceTracker` |

## Core Types

### TransactionInput

```rust
pub struct TransactionInput {
    pub source_transaction: Option<Box<Transaction>>,  // Full source tx (preferred)
    pub source_txid: Option<String>,                   // TXID if source tx unavailable
    pub source_output_index: u32,
    pub unlocking_script: Option<UnlockingScript>,     // Populated after signing
    pub unlocking_script_template: Option<Box<ScriptTemplateUnlock>>,
    pub sequence: u32,                                 // Default: 0xFFFFFFFF
}

impl TransactionInput {
    pub fn new(source_txid: String, source_output_index: u32) -> Self
    pub fn with_source_transaction(tx: Transaction, output_index: u32) -> Self
    pub fn get_source_txid(&self) -> Result<String>
    pub fn get_source_txid_bytes(&self) -> Result<[u8; 32]>
    pub fn source_satoshis(&self) -> Option<u64>
    pub fn source_locking_script(&self) -> Option<&LockingScript>
    pub fn set_unlocking_script_template(&mut self, template: ScriptTemplateUnlock)
    pub fn set_unlocking_script(&mut self, script: UnlockingScript)
    pub fn has_source_transaction(&self) -> bool
}
```

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
    pub fn get_satoshis(&self) -> u64
    pub fn has_satoshis(&self) -> bool
    pub fn serialized_size(&self) -> usize
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
    pub fn to_beef(&self, allow_partial: bool) -> Result<Vec<u8>>
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

pub enum ChangeDistribution { Equal, Random }
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
    pub fn with_url(url: &str) -> Self
    pub fn with_config(config: LivePolicyConfig) -> Self
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

pub struct BroadcastResponse {
    pub status: BroadcastStatus,
    pub txid: String,
    pub message: String,
    pub competing_txs: Option<Vec<String>>,
}

pub struct BroadcastFailure {
    pub status: BroadcastStatus,
    pub code: String,
    pub txid: Option<String>,
    pub description: String,
    pub more: Option<Value>,
}

pub enum BroadcastStatus { Success, Error }
pub type BroadcastResult = Result<BroadcastResponse, BroadcastFailure>;

// Helper functions
pub fn is_broadcast_success(result: &BroadcastResult) -> bool
pub fn is_broadcast_failure(result: &BroadcastResult) -> bool
```

### ARC Broadcaster

```rust
pub struct ArcBroadcaster { /* ... */ }

impl ArcBroadcaster {
    pub fn new(url: &str, api_key: Option<String>) -> Self
    pub fn with_config(config: ArcConfig) -> Self
    pub fn default() -> Self             // Uses https://arc.taal.com
    pub fn url(&self) -> &str
    pub fn api_key(&self) -> Option<&str>
}

pub struct ArcConfig {
    pub url: String,
    pub api_key: Option<String>,
    pub timeout_ms: u64,                 // Default: 30_000
}
```

## Chain Tracking

```rust
#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

pub enum ChainTrackerError {
    NetworkError(String),
    InvalidResponse(String),
    BlockNotFound(u32),
    Other(String),
}

// Mock implementations for testing
pub struct MockChainTracker { pub height: u32, pub roots: HashMap<u32, String> }
impl MockChainTracker {
    pub fn new(height: u32) -> Self
    pub fn add_root(&mut self, height: u32, root: String)
}

pub struct AlwaysValidChainTracker { pub height: u32 }
impl AlwaysValidChainTracker {
    pub fn new(height: u32) -> Self
}
```

### WhatsOnChain Tracker

```rust
pub struct WhatsOnChainTracker { /* ... */ }

impl WhatsOnChainTracker {
    pub fn mainnet() -> Self
    pub fn testnet() -> Self
    pub fn new(network: WocNetwork) -> Self
    pub fn network(&self) -> WocNetwork
}

pub enum WocNetwork { Mainnet, Testnet }
impl WocNetwork {
    pub fn base_url(&self) -> &'static str
}
```

## MerklePath (BUMP - BRC-74)

```rust
pub struct MerklePath {
    pub block_height: u32,
    pub path: Vec<Vec<MerklePathLeaf>>,
}

pub struct MerklePathLeaf {
    pub offset: u64,
    pub hash: Option<String>,
    pub txid: bool,
    pub duplicate: bool,
}

impl MerklePathLeaf {
    pub fn new(offset: u64, hash: String) -> Self
    pub fn new_txid(offset: u64, hash: String) -> Self
    pub fn new_duplicate(offset: u64) -> Self
}

impl MerklePath {
    pub fn new(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>
    pub fn new_unchecked(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_reader(reader: &mut Reader) -> Result<Self>
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self
    pub fn to_hex(&self) -> String
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_writer(&self, writer: &mut Writer)
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>
    pub fn trim(&mut self)
}
```

## BEEF Format (BRC-62/95/96)

```rust
pub struct Beef {
    pub bumps: Vec<MerklePath>,
    pub txs: Vec<BeefTx>,
    pub version: u32,
    pub atomic_txid: Option<String>,
}

impl Beef {
    pub fn new() -> Self                 // V2 by default
    pub fn with_version(version: u32) -> Self
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_reader(reader: &mut Reader) -> Result<Self>
    pub fn to_hex(&mut self) -> String
    pub fn to_binary(&mut self) -> Vec<u8>
    pub fn to_writer(&self, writer: &mut Writer)
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>>
    pub fn is_valid(&mut self, allow_txid_only: bool) -> bool
    pub fn verify_valid(&mut self, allow_txid_only: bool) -> BeefValidationResult
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx>
    pub fn find_bump(&self, txid: &str) -> Option<&MerklePath>
    pub fn find_transaction_for_signing(&self, txid: &str) -> Option<Transaction>
    pub fn find_atomic_transaction(&self, txid: &str) -> Option<Transaction>
    pub fn merge_bump(&mut self, bump: MerklePath) -> usize
    pub fn merge_transaction(&mut self, tx: Transaction) -> &BeefTx
    pub fn merge_raw_tx(&mut self, raw_tx: Vec<u8>, bump_index: Option<usize>) -> &BeefTx
    pub fn merge_txid_only(&mut self, txid: String) -> &BeefTx
    pub fn merge_beef(&mut self, other: &Beef)
    pub fn sort_txs(&mut self) -> SortResult
    pub fn is_atomic(&self) -> bool
    pub fn to_log_string(&mut self) -> String
}

pub struct BeefValidationResult { pub valid: bool, pub roots: HashMap<u32, String> }
pub struct SortResult {
    pub missing_inputs: Vec<String>,
    pub not_valid: Vec<String>,
    pub valid: Vec<String>,
    pub with_missing_inputs: Vec<String>,
    pub txid_only: Vec<String>,
}

pub struct BeefTx {
    pub input_txids: Vec<String>,
    pub is_valid: Option<bool>,
}

impl BeefTx {
    pub fn from_tx(tx: Transaction, bump_index: Option<usize>) -> Self
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self
    pub fn from_txid(txid: String) -> Self
    pub fn bump_index(&self) -> Option<usize>
    pub fn set_bump_index(&mut self, index: Option<usize>)
    pub fn has_proof(&self) -> bool
    pub fn is_txid_only(&self) -> bool
    pub fn txid(&self) -> String
    pub fn tx(&self) -> Option<&Transaction>
    pub fn raw_tx(&self) -> Option<&[u8]>
}

pub enum TxDataFormat { RawTx = 0, RawTxAndBumpIndex = 1, TxidOnly = 2 }
pub const BEEF_V1: u32 = 0x0100BEEF;
pub const BEEF_V2: u32 = 0x0200BEEF;
pub const ATOMIC_BEEF: u32 = 0x01010101;
```

## Usage Examples

### Building and Signing

```rust
let mut tx = Transaction::new();
tx.add_input(TransactionInput::with_source_transaction(source_tx, 0))?;
tx.add_output(TransactionOutput::new(100_000, locking_script))?;
tx.add_p2pkh_output("1MyChange...", None)?;  // Change output
tx.fee(None, ChangeDistribution::Equal).await?;
tx.sign().await?;
let hex = tx.to_hex();
```

### Broadcasting with ARC

```rust
let broadcaster = ArcBroadcaster::new("https://arc.taal.com", Some(api_key));
match broadcaster.broadcast(&tx).await {
    Ok(response) => println!("Success: {}", response.txid),
    Err(failure) => println!("Failed: {}", failure.description),
}
```

### SPV Verification with WhatsOnChain

```rust
let tracker = WhatsOnChainTracker::mainnet();
let mut beef = Beef::from_hex("...")?;
let validation = beef.verify_valid(false);
if validation.valid {
    for (height, root) in validation.roots {
        let valid = tracker.is_valid_root_for_height(&root, height).await?;
    }
}
```

### Fee Computation

```rust
let fee_model = SatoshisPerKilobyte::new(100);  // 100 sat/KB
let fee = fee_model.compute_fee(&tx)?;
```

## Implementation Notes

- **Caching**: Transaction hash/serialization cached; invalidates on modification
- **Inputs**: Must have `source_txid` or `source_transaction`; fee calc/signing need full source tx
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()`
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Async traits**: `Broadcaster` uses `?Send` (Transaction has RefCell); `ChainTracker` is standard async
- **HTTP feature**: `ArcBroadcaster` and `WhatsOnChainTracker` require the `http` feature flag

## Error Types

| Error Type | Conditions |
|------------|------------|
| `TransactionError` | Missing source, satoshis, uncomputed change, EF issues |
| `FeeModelError` | Input missing unlocking script or template |
| `BeefError` | Invalid version, missing atomic txid |
| `MerklePathError` | Empty path, duplicate/invalid offset, mismatched roots |
| `ChainTrackerError` | Network error, invalid response, block not found |

## Related Documentation

- `../script/CLAUDE.md` - LockingScript, UnlockingScript, templates
- `../primitives/CLAUDE.md` - Reader, Writer, sha256d
