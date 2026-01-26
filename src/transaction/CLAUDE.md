# BSV Transaction Module
> Transaction construction, signing, serialization, and SPV verification for BSV blockchain

## Overview

This module provides complete Bitcoin transaction functionality for the BSV SDK:
- Transaction inputs and outputs
- Transaction construction and manipulation
- Binary and hex serialization
- Extended Format (BRC-30) support for SPV
- Transaction hash and TXID computation
- Signing infrastructure with script templates
- Fee calculation and change distribution
- MerklePath (BRC-74 BUMP) for merkle proofs
- BEEF format (BRC-62/95/96) for SPV proofs
- Fee models for computing transaction fees
- Broadcaster trait for transaction broadcasting
- ChainTracker trait for SPV verification

Compatible with the TypeScript and Go SDKs through shared binary formats and test vectors.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `input.rs` | `TransactionInput` struct for transaction inputs |
| `output.rs` | `TransactionOutput` struct for transaction outputs |
| `transaction.rs` | `Transaction` struct with parsing, serialization, and signing |
| `merkle_path.rs` | `MerklePath` for BRC-74 BUMP merkle proofs |
| `beef.rs` | `Beef` for BRC-62/95/96 SPV proofs |
| `beef_tx.rs` | `BeefTx` for transactions within BEEF format |
| `fee_model.rs` | `FeeModel` trait and `FixedFee` implementation |
| `fee_models/` | Fee model implementations (`SatoshisPerKilobyte`) |
| `broadcaster.rs` | `Broadcaster` trait for transaction broadcasting |
| `chain_tracker.rs` | `ChainTracker` trait for SPV verification |

## Key Exports

```rust
// Core transaction types
pub use transaction::{ChangeDistribution, ScriptOffset, ScriptOffsets, Transaction};
pub use input::TransactionInput;
pub use output::TransactionOutput;

// MerklePath and BEEF
pub use merkle_path::{MerklePath, MerklePathLeaf};
pub use beef::{Beef, BeefValidationResult, SortResult};
pub use beef_tx::{BeefTx, TxDataFormat, ATOMIC_BEEF, BEEF_V1, BEEF_V2};

// Fee models
pub use fee_model::{FeeModel, FixedFee};
pub use fee_models::SatoshisPerKilobyte;

// External interfaces
pub use broadcaster::{
    is_broadcast_failure, is_broadcast_success, BroadcastFailure, BroadcastResponse,
    BroadcastResult, BroadcastStatus, Broadcaster,
};
pub use chain_tracker::{
    AlwaysValidChainTracker, ChainTracker, ChainTrackerError, MockChainTracker,
};
```

## Core Types

### TransactionInput

Represents an input to a Bitcoin transaction, referencing a previous UTXO:

```rust
pub struct TransactionInput {
    pub source_transaction: Option<Box<Transaction>>,  // Full source tx (preferred)
    pub source_txid: Option<String>,                   // TXID if source tx unavailable
    pub source_output_index: u32,                      // Output index in source tx
    pub unlocking_script: Option<UnlockingScript>,     // Populated after signing
    pub unlocking_script_template: Option<Box<ScriptTemplateUnlock>>,  // For signing
    pub sequence: u32,                                 // Default: 0xFFFFFFFF (final)
}

impl TransactionInput {
    pub fn new(source_txid: String, source_output_index: u32) -> Self
    pub fn with_source_transaction(tx: Transaction, output_index: u32) -> Self
    pub fn get_source_txid(&self) -> Result<String>
    pub fn source_satoshis(&self) -> Option<u64>
    pub fn source_locking_script(&self) -> Option<&LockingScript>
    pub fn set_unlocking_script_template(&mut self, template: ScriptTemplateUnlock)
    pub fn set_unlocking_script(&mut self, script: UnlockingScript)
}
```

### TransactionOutput

Represents an output in a Bitcoin transaction:

```rust
pub struct TransactionOutput {
    pub satoshis: Option<u64>,           // None for change outputs before fee calc
    pub locking_script: LockingScript,   // Spending conditions
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

The main transaction struct with full parsing and serialization:

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
    pub fn with_params(version: u32, inputs: Vec<TransactionInput>,
                       outputs: Vec<TransactionOutput>, lock_time: u32) -> Self

    // Parsing
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_ef(ef: &[u8]) -> Result<Self>      // Extended Format (BRC-30)
    pub fn from_hex_ef(hex: &str) -> Result<Self>
    pub fn from_beef(beef: &[u8], txid: Option<&str>) -> Result<Self>
    pub fn from_atomic_beef(beef: &[u8]) -> Result<Self>
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets>

    // Serialization
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_hex(&self) -> String
    pub fn to_ef(&self) -> Result<Vec<u8>>         // Extended Format (BRC-30)
    pub fn to_hex_ef(&self) -> Result<String>
    pub fn to_beef(&self, allow_partial: bool) -> Result<Vec<u8>>
    pub fn to_atomic_beef(&self, allow_partial: bool) -> Result<Vec<u8>>

    // Hashing
    pub fn hash(&self) -> [u8; 32]                 // Double SHA-256
    pub fn id(&self) -> String                     // TXID (reversed hash as hex)
    pub fn hash_hex(&self) -> String               // Hash as hex (not reversed)

    // Building
    pub fn add_input(&mut self, input: TransactionInput) -> Result<()>
    pub fn add_output(&mut self, output: TransactionOutput) -> Result<()>
    pub fn add_p2pkh_output(&mut self, address: &str, satoshis: Option<u64>) -> Result<()>
    pub fn update_metadata(&mut self, key: &str, value: Value)

    // Signing
    pub async fn sign(&mut self) -> Result<()>

    // Fees
    pub async fn fee(&mut self, fee_sats: Option<u64>,
                     change_distribution: ChangeDistribution) -> Result<()>
    pub fn get_fee(&self) -> Result<u64>
    pub fn estimate_size(&self) -> usize
}
```

## Fee Models

### FeeModel Trait

```rust
pub trait FeeModel: Send + Sync {
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>;
}
```

### FixedFee

Always returns the same fee amount:

```rust
pub struct FixedFee(u64);

impl FixedFee {
    pub fn new(satoshis: u64) -> Self
}
```

### SatoshisPerKilobyte

The standard fee model that computes fees based on transaction size:

```rust
pub struct SatoshisPerKilobyte {
    pub value: u64,  // satoshis per kilobyte
}

impl SatoshisPerKilobyte {
    pub fn new(value: u64) -> Self
}

impl Default for SatoshisPerKilobyte {
    fn default() -> Self { Self::new(100) }  // 100 sat/KB standard rate
}
```

Example:
```rust
use bsv_sdk::transaction::{FeeModel, SatoshisPerKilobyte};

let fee_model = SatoshisPerKilobyte::new(100); // 100 sat/KB
let fee = fee_model.compute_fee(&tx)?;
```

## Broadcasting

### Broadcaster Trait (Async)

The Broadcaster trait uses async methods, matching the TypeScript and Go SDK interfaces:

```rust
use async_trait::async_trait;

#[async_trait(?Send)]
pub trait Broadcaster: Send + Sync {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult;
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>;
}
```

Note: Uses `#[async_trait(?Send)]` because `Transaction` contains `RefCell` for caching.

### BroadcastResponse / BroadcastFailure

```rust
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
```

Example implementation:
```rust
use bsv_sdk::transaction::{Broadcaster, BroadcastResult, BroadcastResponse, Transaction};
use async_trait::async_trait;

struct MyBroadcaster { endpoint: String }

#[async_trait(?Send)]
impl Broadcaster for MyBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        // Async HTTP POST to endpoint
        Ok(BroadcastResponse::success(tx.id(), "Accepted".to_string()))
    }

    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult> {
        let mut results = Vec::with_capacity(txs.len());
        for tx in &txs {
            results.push(self.broadcast(tx).await);
        }
        results
    }
}
```

## Chain Tracking

### ChainTracker Trait (Async)

Used for SPV verification of merkle proofs. Uses async methods matching the Go SDK context-based interface:

```rust
use async_trait::async_trait;

#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

#[derive(Error)]
pub enum ChainTrackerError {
    NetworkError(String),
    InvalidResponse(String),
    BlockNotFound(u32),
    Other(String),
}
```

### MockChainTracker

For testing SPV verification (implements async ChainTracker trait):

```rust
pub struct MockChainTracker {
    pub height: u32,
    pub roots: HashMap<u32, String>,
}

impl MockChainTracker {
    pub fn new(height: u32) -> Self
    pub fn add_root(&mut self, height: u32, root: String)
    pub fn always_valid(height: u32) -> AlwaysValidChainTracker
}
```

### AlwaysValidChainTracker

Always returns true for any merkle root (testing only):

```rust
pub struct AlwaysValidChainTracker { pub height: u32 }

impl AlwaysValidChainTracker {
    pub fn new(height: u32) -> Self
}
```

Example:
```rust
use bsv_sdk::transaction::{ChainTracker, MockChainTracker};

let mut tracker = MockChainTracker::new(1000);
tracker.add_root(999, "merkle_root_hex".to_string());

let is_valid = tracker.is_valid_root_for_height("merkle_root_hex", 999)?;
```

## MerklePath (BUMP)

BRC-74 merkle proof format:

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

impl MerklePath {
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self
    pub fn to_hex(&self) -> String
    pub fn to_binary(&self) -> Vec<u8>
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String>
    pub fn contains(&self, txid: &str) -> bool
    pub fn txids(&self) -> Vec<String>
    pub fn combine(&mut self, other: &MerklePath) -> Result<()>
}
```

## BEEF Format

BRC-62/95/96 SPV proof format:

```rust
pub struct Beef {
    pub bumps: Vec<MerklePath>,
    pub txs: Vec<BeefTx>,
    pub version: u32,
    pub atomic_txid: Option<String>,
}

impl Beef {
    pub fn new() -> Self
    pub fn with_version(version: u32) -> Self
    pub fn from_hex(hex: &str) -> Result<Self>
    pub fn from_binary(bin: &[u8]) -> Result<Self>
    pub fn to_hex(&mut self) -> String
    pub fn to_binary(&mut self) -> Vec<u8>
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>>
    pub fn is_valid(&mut self, allow_txid_only: bool) -> bool
    pub fn verify_valid(&mut self, allow_txid_only: bool) -> BeefValidationResult
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx>
    pub fn merge_bump(&mut self, bump: MerklePath) -> usize
    pub fn merge_transaction(&mut self, tx: Transaction) -> &BeefTx
    pub fn merge_txid_only(&mut self, txid: String) -> &BeefTx
    pub fn merge_beef(&mut self, other: &Beef)
}
```

## Binary Formats

### Standard Transaction Format

```
[4 bytes]  version (little-endian)
[varint]   input count
[...]      inputs:
             [32 bytes] prev_txid (internal byte order)
             [4 bytes]  prev_output_index (LE)
             [varint]   script_length
             [...]      unlocking_script
             [4 bytes]  sequence (LE)
[varint]   output count
[...]      outputs:
             [8 bytes]  satoshis (LE)
             [varint]   script_length
             [...]      locking_script
[4 bytes]  lock_time (LE)
```

### Extended Format (BRC-30)

Includes source UTXO data for SPV verification:

```
[4 bytes]  version (LE)
[6 bytes]  marker: 0x0000000000EF
[varint]   input count
[...]      inputs:
             [32 bytes] prev_txid (internal byte order)
             [4 bytes]  prev_output_index (LE)
             [varint]   script_length
             [...]      unlocking_script
             [4 bytes]  sequence (LE)
             [8 bytes]  source_satoshis (LE)      // Extra
             [varint]   source_script_length      // Extra
             [...]      source_locking_script     // Extra
[varint]   output count
[...]      outputs:
             [8 bytes]  satoshis (LE)
             [varint]   script_length
             [...]      locking_script
[4 bytes]  lock_time (LE)
```

## Usage Examples

### Parsing Transactions

```rust
use bsv_sdk::transaction::Transaction;

// From hex
let tx = Transaction::from_hex("0100000001...")?;

// From binary
let tx = Transaction::from_binary(&bytes)?;

// From Extended Format
let tx = Transaction::from_ef(&ef_bytes)?;

// From BEEF
let tx = Transaction::from_beef(&beef_bytes, None)?;
```

### Building Transactions

```rust
use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput, ChangeDistribution};
use bsv_sdk::script::LockingScript;

let mut tx = Transaction::new();

// Add input
let input = TransactionInput::new(
    "abc123...".to_string(),  // Source TXID
    0,                        // Output index
);
tx.add_input(input)?;

// Add output
let locking = LockingScript::from_hex("76a914...88ac")?;
tx.add_output(TransactionOutput::new(100_000, locking))?;

// Add P2PKH output directly from address
tx.add_p2pkh_output("1BvBMSEY...", Some(50_000))?;

// Add change output (amount computed during fee())
tx.add_p2pkh_output("1MyChange...", None)?;
```

### Using Fee Models

```rust
use bsv_sdk::transaction::{FeeModel, SatoshisPerKilobyte, FixedFee};

// 100 sat/KB (standard rate)
let fee_model = SatoshisPerKilobyte::new(100);
let fee = fee_model.compute_fee(&tx)?;

// Or use a fixed fee
let fixed = FixedFee::new(500);
let fee = fixed.compute_fee(&tx)?;
```

### Fee Calculation and Signing

```rust
// Compute fees and distribute change
tx.fee(Some(500), ChangeDistribution::Equal).await?;

// Or let it auto-calculate based on size (1 sat/byte)
tx.fee(None, ChangeDistribution::Equal).await?;

// Sign all inputs with templates
tx.sign().await?;

// Get the current fee
let fee = tx.get_fee()?;
```

### Serialization

```rust
// To hex
let hex = tx.to_hex();

// To binary
let bytes = tx.to_binary();

// To Extended Format (requires source transactions)
let ef_bytes = tx.to_ef()?;

// To BEEF
let beef_bytes = tx.to_beef(false)?;

// Get TXID
let txid = tx.id();  // "abc123..."

// Get raw hash
let hash = tx.hash();  // [u8; 32]
```

### Using Script Templates

```rust
use bsv_sdk::script::templates::P2PKH;
use bsv_sdk::script::template::SignOutputs;

let private_key = PrivateKey::from_wif("...")?;

// Create input with template
let mut input = TransactionInput::with_source_transaction(source_tx, 0);
input.set_unlocking_script_template(
    P2PKH::unlock(&private_key, SignOutputs::All, false)
);

tx.add_input(input)?;
tx.add_output(output)?;
tx.fee(None, ChangeDistribution::Equal).await?;
tx.sign().await?;  // Template generates unlocking script
```

### SPV Verification with Chain Tracker

```rust
use bsv_sdk::transaction::{Beef, ChainTracker, MockChainTracker};

// Parse BEEF
let beef = Beef::from_hex("0100beef...")?;

// Create chain tracker with known roots
let mut tracker = MockChainTracker::new(1000);
tracker.add_root(999, "expected_merkle_root".to_string());

// Verify BEEF structure
let validation = beef.verify_valid(false);
if validation.valid {
    // Check each root against chain tracker
    for (height, root) in validation.roots {
        let valid = tracker.is_valid_root_for_height(&root, height)?;
        assert!(valid);
    }
}
```

## Implementation Notes

### Caching

- Transaction serialization and hash are cached
- Caches invalidate on modification (add_input, add_output, sign)
- Parse-from-hex caches both hex and binary forms

### Input Requirements

- Every input must have either `source_txid` or `source_transaction`
- Fee calculation requires `source_transaction` for satoshi values
- Signing requires `source_transaction` for locking scripts

### Change Outputs

- Created with `new_change()` or `add_p2pkh_output(_, None)`
- Amount computed during `fee()` call
- Removed if no change remains after fees

### TXID vs Hash

- `hash()` returns the double SHA-256 in internal byte order
- `id()` returns the hash reversed as a hex string (display format)
- TXIDs in inputs are stored in display format, serialized reversed

### Fee Model Design

- `FeeModel` trait is synchronous (fee computation is CPU-bound, no I/O needed)
- `SatoshisPerKilobyte` uses ceiling division to ensure miners get minimum fees
- Default rate is 100 sat/KB (standard BSV network fee)

### Broadcasting Design

- `Broadcaster` trait is async, matching TypeScript and Go SDKs
- Uses `#[async_trait(?Send)]` because `Transaction` uses `RefCell` for caching
- `broadcast_many` must be implemented by each broadcaster (no default impl due to Send constraints)
- Implementations can use concurrent or batch broadcasting

### Chain Tracker Design

- `ChainTracker` trait is async, matching Go SDK's context-based interface
- `MockChainTracker` and `AlwaysValidChainTracker` implement the async trait for testing
- Real implementations would use async HTTP clients

## Error Handling

Transaction operations return `crate::Error::TransactionError` for:

| Error | Condition |
|-------|-----------|
| Missing source | Input without TXID or source transaction |
| Missing satoshis | Non-change output without amount |
| Uncomputed change | Signing before fee() with change outputs |
| Missing source tx | EF serialization without source transactions |
| Invalid EF marker | EF parsing with wrong marker bytes |

Fee operations return `crate::Error::FeeModelError` for:

| Error | Condition |
|-------|-----------|
| Missing script | Input without unlocking script or template |

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../script/CLAUDE.md` - Script module (LockingScript, UnlockingScript)
- `../script/template.rs` - ScriptTemplateUnlock for signing
- `../primitives/CLAUDE.md` - Primitives (Reader, Writer, sha256d)
