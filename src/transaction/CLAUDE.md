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
- Async Broadcaster trait for transaction broadcasting
- Async ChainTracker trait for SPV verification

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
| `beef_tx.rs` | `BeefTx` transaction wrapper |
| `fee_model.rs` | `FeeModel` trait, `FixedFee` |
| `fee_models/` | `SatoshisPerKilobyte` |
| `broadcaster.rs` | Async `Broadcaster` trait |
| `chain_tracker.rs` | Async `ChainTracker` trait |

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
```

## Fee Models

```rust
pub trait FeeModel: Send + Sync {
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>;
}

pub struct FixedFee(u64);  // Always returns same fee
pub struct SatoshisPerKilobyte { pub value: u64 }  // Default: 100 sat/KB
```

## Broadcasting (Async)

```rust
#[async_trait(?Send)]
pub trait Broadcaster: Send + Sync {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult;
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>;
}

pub struct BroadcastResponse { pub status, pub txid, pub message, pub competing_txs }
pub struct BroadcastFailure { pub status, pub code, pub txid, pub description, pub more }
pub type BroadcastResult = Result<BroadcastResponse, BroadcastFailure>;
```

## Chain Tracking (Async)

```rust
#[async_trait]
pub trait ChainTracker: Send + Sync {
    async fn is_valid_root_for_height(&self, root: &str, height: u32) -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

pub struct MockChainTracker { pub height: u32, pub roots: HashMap<u32, String> }
pub struct AlwaysValidChainTracker { pub height: u32 }  // Testing only
```

## MerklePath (BUMP - BRC-74)

```rust
pub struct MerklePath {
    pub block_height: u32,
    pub path: Vec<Vec<MerklePathLeaf>>,
}

pub struct MerklePathLeaf {
    pub offset: u64, pub hash: Option<String>, pub txid: bool, pub duplicate: bool
}

impl MerklePath {
    pub fn new(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self>
    pub fn from_hex/from_binary/from_reader/from_coinbase_txid(...)
    pub fn to_hex/to_binary/to_writer(...)
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
    pub fn new() -> Self  // V2 by default
    pub fn with_version(version: u32) -> Self
    pub fn from_hex/from_binary/from_reader(...)
    pub fn to_hex/to_binary/to_writer/to_binary_atomic(...)
    pub fn is_valid(&mut self, allow_txid_only: bool) -> bool
    pub fn verify_valid(&mut self, allow_txid_only: bool) -> BeefValidationResult
    pub fn find_txid/find_bump/find_transaction_for_signing/find_atomic_transaction(...)
    pub fn merge_bump/merge_transaction/merge_raw_tx/merge_txid_only/merge_beef(...)
    pub fn sort_txs(&mut self) -> SortResult
}

pub struct BeefTx { pub input_txids: Vec<String>, pub is_valid: Option<bool> }
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

### SPV Verification

```rust
let mut beef = Beef::from_hex("...")?;
let validation = beef.verify_valid(false);
if validation.valid {
    for (height, root) in validation.roots {
        let valid = tracker.is_valid_root_for_height(&root, height).await?;
    }
}
```

## Implementation Notes

- **Caching**: Transaction hash/serialization cached; invalidates on modification
- **Inputs**: Must have `source_txid` or `source_transaction`; fee calc/signing need full source tx
- **Change**: Created via `new_change()` or `add_p2pkh_output(_, None)`; computed in `fee()`
- **TXID**: `hash()` = internal byte order; `id()` = reversed hex (display format)
- **Async traits**: `Broadcaster` uses `?Send` (Transaction has RefCell); `ChainTracker` is standard async

## Error Types

| Error Type | Conditions |
|------------|------------|
| `TransactionError` | Missing source, satoshis, uncomputed change, EF issues |
| `FeeModelError` | Input missing unlocking script or template |
| `BeefError` | Invalid version, missing atomic txid |
| `MerklePathError` | Empty path, duplicate/invalid offset, mismatched roots |

## Related Documentation

- `../script/CLAUDE.md` - LockingScript, UnlockingScript, templates
- `../primitives/CLAUDE.md` - Reader, Writer, sha256d
