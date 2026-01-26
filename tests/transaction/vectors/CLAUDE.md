# Transaction Test Vectors
> Standardized test data for transaction and MerklePath validation

## Overview

This module provides test vectors for the transaction subsystem. Vectors include valid and invalid transactions, BUMP/MerklePath data (BRC-74), and large transaction samples. These vectors are derived from the TypeScript SDK to ensure cross-SDK compatibility.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module declarations, re-exports all vector submodules |
| `tx_valid.rs` | Valid transaction hex strings for serialization/deserialization testing |
| `tx_invalid.rs` | Structurally valid but semantically invalid transactions |
| `bump_valid.rs` | Valid BRC-74 MerklePath (BUMP) hex strings |
| `bump_invalid.rs` | Malformed BUMP data with expected error messages |
| `bigtx.rs` | Large transaction vectors for stress testing |

## Key Exports

### Transaction Vectors

**`TX_VALID_VECTORS: &[&str]`** - Array of valid transaction hex strings for roundtrip testing.

**`TX_VALID_1: &str`** - Basic P2PKH spend transaction.

**`TX_VALID_2: &str`** - Complex transaction with multiple inputs.

**`TX_VALID_2_TXID: &str`** - Expected TXID for `TX_VALID_2`.

**`TX_SIMPLE: &str`** - Minimal transaction for basic testing.

**`TX_INVALID_VECTORS: &[(&str, &str)]`** - Array of (hex, description) tuples for invalid transactions. Includes:
- Extra junk in scriptPubKey
- Non-standard pushdata prefix
- Invalid P2SH script hash
- No outputs
- Coinbase size violations (too small or too large)
- CHECKMULTISIG missing dummy value
- Empty stack for CHECKSIG
- Non-standard DER signature
- CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY issues

### BUMP/MerklePath Vectors

**`BUMP_VALID_VECTORS: &[&str]`** - Array of valid BUMP hex strings.

**`BUMP_VALID_1: &str`** - First valid BUMP vector.

**`BUMP_VALID_2: &str`** - Second valid BUMP vector.

**`InvalidBumpVector`** - Struct containing:
- `bump: &'static str` - The invalid BUMP hex
- `error: &'static str` - Expected error message substring

**`BUMP_INVALID_VECTORS: &[InvalidBumpVector]`** - Array of invalid BUMP vectors with expected errors:
- Invalid offset at specific height
- Duplicate offset at height
- Missing hash for index at height
- Mismatched merkle roots

### Large Transaction Vectors

**`BIG_TX_TXID: &str`** - Expected TXID for a 1MB transaction (from TypeScript SDK).

**`LARGE_TX_HEX: &str`** - Coinbase transaction with annotated structure.

**`MULTI_IO_TX_HEX: &str`** - Transaction with multiple inputs and outputs.

**`MULTI_IO_TX_TXID: &str`** - Expected TXID for `MULTI_IO_TX_HEX`.

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

## Invalid Transaction Categories

The `TX_INVALID_VECTORS` cover various failure modes:

| Category | Description |
|----------|-------------|
| Script Structure | Invalid scriptPubKey/scriptSig content |
| P2SH | Invalid script hashes |
| Output Count | Missing outputs |
| Coinbase | Size violations (must be 2-100 bytes) |
| Signatures | Missing dummy values, non-standard DER |
| Timelocks | CLTV/CSV verification failures |

## Invalid BUMP Error Types

The `BUMP_INVALID_VECTORS` test these error conditions:

| Error Type | Description |
|------------|-------------|
| Invalid offset | Offset doesn't match legal values for height |
| Duplicate offset | Same offset appears twice at a height |
| Missing hash | Required hash missing for merkle tree computation |
| Mismatched roots | Computed root doesn't match expected |

## Cross-SDK Compatibility

All vectors in this module are derived from the TypeScript SDK to ensure byte-for-byte compatibility across implementations. When adding new vectors, verify they produce identical results in:
- BSV TypeScript SDK
- BSV Go SDK
- This Rust SDK

## Related

- `src/transaction/CLAUDE.md` - Transaction module implementation
- `tests/transaction/CLAUDE.md` - Transaction test module documentation
- `CLAUDE.md` - Root project documentation
