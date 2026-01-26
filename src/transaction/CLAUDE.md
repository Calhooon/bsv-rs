# BSV Transaction Module
> Transaction construction, signing, and serialization for BSV blockchain

## Overview

This module provides complete Bitcoin transaction functionality for the BSV SDK:
- Transaction inputs and outputs
- Transaction construction and manipulation
- Binary and hex serialization
- Extended Format (BRC-30) support for SPV
- Transaction hash and TXID computation
- Signing infrastructure with script templates
- Fee calculation and change distribution

Compatible with the TypeScript and Go SDKs through shared binary formats and test vectors.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `input.rs` | `TransactionInput` struct for transaction inputs |
| `output.rs` | `TransactionOutput` struct for transaction outputs |
| `transaction.rs` | `Transaction` struct with parsing, serialization, and signing |

## Key Exports

```rust
pub use input::TransactionInput;
pub use output::TransactionOutput;
pub use transaction::{ChangeDistribution, ScriptOffset, ScriptOffsets, Transaction};
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
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets>

    // Serialization
    pub fn to_binary(&self) -> Vec<u8>
    pub fn to_hex(&self) -> String
    pub fn to_ef(&self) -> Result<Vec<u8>>         // Extended Format (BRC-30)
    pub fn to_hex_ef(&self) -> Result<String>

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

### ChangeDistribution

Controls how change is distributed among change outputs:

```rust
pub enum ChangeDistribution {
    Equal,   // Divide equally among change outputs
    Random,  // Use Benford's law distribution for privacy
}
```

### ScriptOffsets

For efficient script retrieval from binary transaction data:

```rust
pub struct ScriptOffsets {
    pub inputs: Vec<ScriptOffset>,
    pub outputs: Vec<ScriptOffset>,
}

pub struct ScriptOffset {
    pub index: usize,   // Input/output index
    pub offset: usize,  // Byte offset in transaction
    pub length: usize,  // Script length in bytes
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

## Error Handling

Transaction operations return `crate::Error::TransactionError` for:

| Error | Condition |
|-------|-----------|
| Missing source | Input without TXID or source transaction |
| Missing satoshis | Non-change output without amount |
| Uncomputed change | Signing before fee() with change outputs |
| Missing source tx | EF serialization without source transactions |
| Invalid EF marker | EF parsing with wrong marker bytes |

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../script/CLAUDE.md` - Script module (LockingScript, UnlockingScript)
- `../script/template.rs` - ScriptTemplateUnlock for signing
- `../primitives/CLAUDE.md` - Primitives (Reader, Writer, sha256d)
