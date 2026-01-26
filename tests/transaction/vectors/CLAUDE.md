# Transaction Test Vectors
> Standardized test data for transaction, MerklePath, and BEEF validation

## Overview

This module provides test vectors for the transaction subsystem. Vectors include valid and invalid transactions, BUMP/MerklePath data (BRC-74), BEEF format data (BRC-62), and large transaction samples. These vectors are derived from the TypeScript and Go SDKs to ensure cross-SDK compatibility.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declarations, re-exports all vector submodules |
| `tx_valid.rs` | Valid transaction hex strings for serialization/deserialization testing |
| `tx_invalid.rs` | Structurally valid but semantically invalid transactions (includes unit tests) |
| `bump_valid.rs` | Valid BRC-74 MerklePath (BUMP) hex strings |
| `bump_invalid.rs` | Malformed BUMP data with expected error messages |
| `bigtx.rs` | Large transaction vectors for stress testing |
| `beef_cross_sdk.rs` | BEEF (BRC-62/BRC-74) vectors from TypeScript and Go SDKs |

## Key Exports

### Transaction Vectors

**`TX_VALID_VECTORS: &[&str]`** - Array of valid transaction hex strings for roundtrip testing.

**`TX_VALID_1: &str`** - Basic P2PKH spend transaction.

**`TX_VALID_2: &str`** - Complex transaction with multiple inputs.

**`TX_VALID_2_TXID: &str`** - Expected TXID for `TX_VALID_2`.

**`TX_SIMPLE: &str`** - Minimal transaction for basic testing.

**`TX_INVALID_VECTORS: &[(&str, &str)]`** - Array of 10 (hex, description) tuples for invalid transactions. Includes:
- Extra junk in scriptPubKey
- Non-standard pushdata prefix
- Invalid P2SH script hash
- No outputs
- Coinbase of size 1 (below minimum 2 bytes)
- Coinbase of size 101 (above maximum 100 bytes)
- CHECKMULTISIG missing dummy value
- Empty stack for CHECKSIG
- Non-standard DER signature
- CHECKLOCKTIMEVERIFY locked input
- CHECKSEQUENCEVERIFY argument missing

### BUMP/MerklePath Vectors

**`BUMP_VALID_VECTORS: &[&str]`** - Array of valid BUMP hex strings.

**`BUMP_VALID_1: &str`** - First valid BUMP vector.

**`BUMP_VALID_2: &str`** - Second valid BUMP vector.

**`InvalidBumpVector`** - Struct containing:
- `bump: &'static str` - The invalid BUMP hex
- `error: &'static str` - Expected error message substring

**`BUMP_INVALID_VECTORS: &[InvalidBumpVector]`** - Array of 6 invalid BUMP vectors with expected errors:
- Invalid offset at height 1 (offset 12, legal offset 413)
- Duplicate offset 413 at height 1
- Duplicate offset 231 at height 3
- Missing hash for index 923 at height 0
- Missing hash for index 1844 at height 6
- Mismatched merkle roots

### Large Transaction Vectors

**`BIG_TX_TXID: &str`** - Expected TXID for a 1MB transaction (from TypeScript SDK).

**`LARGE_TX_HEX: &str`** - Coinbase transaction with annotated structure.

**`MULTI_IO_TX_HEX: &str`** - Transaction with multiple inputs and outputs.

**`MULTI_IO_TX_TXID: &str`** - Expected TXID for `MULTI_IO_TX_HEX`.

### BEEF Vectors (BRC-62)

**`BRC62_HEX: &str`** - BEEF hex from Go SDK in BRC-62 format.

**`BRC62_EXPECTED_TXID: &str`** - Expected transaction ID from the BRC62 BEEF.

**`BEEF_SET_HEX: &str`** - BEEF V2 hex containing multiple transactions from Go SDK.

**`BEEF_SET_FIND_TXID: &str`** - Expected TXID when finding a specific transaction in BEEF set.

**`BRC74_HEX: &str`** - MerklePath (BUMP) test vector in BRC-74 format.

**`BRC74_ROOT: &str`** - Expected merkle root from BRC74 MerklePath.

**`BRC74_TXID1: &str`**, **`BRC74_TXID2: &str`**, **`BRC74_TXID3: &str`** - Transaction IDs contained in the BRC74 MerklePath.

**`BRC74_BLOCK_HEIGHT: u32`** - Expected block height (813706) from BRC74.

**`SINGLE_TX_BUMP_HEX: &str`** - MerklePath for a single-transaction block (coinbase only).

**`SINGLE_TX_COINBASE_TXID: &str`** - Expected coinbase TXID (equals merkle root for single-tx blocks).

**`EMPTY_BEEF_V1_HEX: &str`** - Empty BEEF version 1 hex string.

**`EMPTY_BEEF_V2_HEX: &str`** - Empty BEEF version 2 hex string.

## Usage

### Testing Transaction Parsing

```rust
use tests::transaction::vectors::{TX_VALID_VECTORS, TX_INVALID_VECTORS};

// Test roundtrip serialization
for hex in TX_VALID_VECTORS {
    let tx = Transaction::from_hex(hex).unwrap();
    assert_eq!(tx.to_hex(), *hex);
}

// Test invalid transactions can still be parsed
for (hex, description) in TX_INVALID_VECTORS {
    let result = Transaction::from_hex(hex);
    // Should parse structurally, but fail semantic validation
}
```

### Testing BUMP/MerklePath

```rust
use tests::transaction::vectors::{BUMP_VALID_VECTORS, BUMP_INVALID_VECTORS};

// Test valid BUMP parsing
for bump_hex in BUMP_VALID_VECTORS {
    let merkle_path = MerklePath::from_hex(bump_hex).unwrap();
    assert!(merkle_path.is_valid());
}

// Test invalid BUMP error handling
for vector in BUMP_INVALID_VECTORS {
    let result = MerklePath::from_hex(vector.bump);
    match result {
        Err(e) => assert!(e.to_string().contains(vector.error)),
        Ok(mp) => assert!(!mp.is_valid()),
    }
}
```

### Testing Large Transactions

```rust
use tests::transaction::vectors::{MULTI_IO_TX_HEX, MULTI_IO_TX_TXID};

let tx = Transaction::from_hex(MULTI_IO_TX_HEX).unwrap();
assert_eq!(tx.txid().to_hex(), MULTI_IO_TX_TXID);
```

### Testing BEEF Parsing

```rust
use tests::transaction::vectors::{BRC62_HEX, BRC62_EXPECTED_TXID, BEEF_SET_HEX};

// Test BEEF parsing
let beef = Beef::from_hex(BRC62_HEX).unwrap();
let tx = beef.get_newest_tx().unwrap();
assert_eq!(tx.txid().to_hex(), BRC62_EXPECTED_TXID);

// Test BEEF with multiple transactions
let beef_set = Beef::from_hex(BEEF_SET_HEX).unwrap();
assert!(beef_set.find_tx_by_id(BEEF_SET_FIND_TXID).is_some());
```

### Testing MerklePath with Block Height

```rust
use tests::transaction::vectors::{BRC74_HEX, BRC74_ROOT, BRC74_BLOCK_HEIGHT};

let merkle_path = MerklePath::from_hex(BRC74_HEX).unwrap();
assert_eq!(merkle_path.block_height(), BRC74_BLOCK_HEIGHT);
assert_eq!(merkle_path.root().to_hex(), BRC74_ROOT);
```

## Invalid Transaction Categories

The `TX_INVALID_VECTORS` cover 10 failure modes:

| Category | Description |
|----------|-------------|
| Script Structure | Extra junk in scriptPubKey, non-standard pushdata prefix |
| P2SH | Invalid script hashes |
| Output Count | Missing outputs (zero outputs) |
| Coinbase | Size violations (must be 2-100 bytes): size 1 and size 101 |
| Signatures | CHECKMULTISIG missing dummy, empty stack for CHECKSIG, non-standard DER |
| Timelocks | CHECKLOCKTIMEVERIFY locked input, CHECKSEQUENCEVERIFY argument missing |

Note: These vectors test serialization/deserialization parsing, not script verification. The `tx_invalid.rs` file includes a unit test (`test_invalid_tx_can_be_parsed`) that verifies all vectors have non-empty hex strings.

## Invalid BUMP Error Types

The `BUMP_INVALID_VECTORS` test 6 error conditions:

| Error Type | Count | Description |
|------------|-------|-------------|
| Invalid offset | 1 | Offset doesn't match legal values for height |
| Duplicate offset | 2 | Same offset appears twice at a height |
| Missing hash | 2 | Required hash missing for merkle tree computation |
| Mismatched roots | 1 | Computed root doesn't match expected |

## BEEF Format (BRC-62)

BEEF (Background Evaluation Extended Format) is a serialization format for transactions that includes SPV proof data. The `beef_cross_sdk.rs` module provides vectors for testing:

| Vector Type | Constant | Description |
|-------------|----------|-------------|
| BRC62 BEEF V1 | `BRC62_HEX` | Single transaction with merkle proof (version 1) |
| BEEF Set V2 | `BEEF_SET_HEX` | Multiple transactions with shared ancestry (version 2) |
| BRC74 MerklePath | `BRC74_HEX` | Standalone merkle path with 3 TXIDs at block height 813706 |
| Single-TX Block | `SINGLE_TX_BUMP_HEX` | Edge case where merkle root equals coinbase TXID |
| Empty BEEF V1 | `EMPTY_BEEF_V1_HEX` | Empty version 1 container (`0100beef0000`) |
| Empty BEEF V2 | `EMPTY_BEEF_V2_HEX` | Empty version 2 container (`0200beef0000`) |

## Cross-SDK Compatibility

All vectors in this module are derived from the TypeScript and Go SDKs to ensure byte-for-byte compatibility across implementations. When adding new vectors, verify they produce identical results in:
- BSV TypeScript SDK
- BSV Go SDK
- This Rust SDK

The BEEF vectors specifically come from the Go SDK implementation to ensure compatibility with the most recent BEEF specification.

## Module Structure

The `mod.rs` file exports all submodules publicly:

```rust
pub mod beef_cross_sdk;
pub mod bigtx;
pub mod bump_invalid;
pub mod bump_valid;
pub mod tx_invalid;
pub mod tx_valid;
```

All constants and types are accessed via their respective submodules (e.g., `vectors::tx_valid::TX_VALID_1`).

## Related

- `src/transaction/CLAUDE.md` - Transaction module implementation
- `tests/transaction/CLAUDE.md` - Transaction test module documentation
- `CLAUDE.md` - Root project documentation
