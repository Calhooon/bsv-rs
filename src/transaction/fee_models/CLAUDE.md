# Fee Models Module
> Fee calculation implementations for BSV transaction construction

## Overview

This module provides concrete implementations of the `FeeModel` trait for computing transaction fees. The primary implementation is `SatoshisPerKilobyte`, which calculates fees based on transaction size using the standard BSV fee rate model.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; exports `SatoshisPerKilobyte` |
| `sats_per_kb.rs` | Size-based fee model computing satoshis per kilobyte |

## Key Exports

```rust
// Re-exported from mod.rs
pub use sats_per_kb::SatoshisPerKilobyte;
```

### SatoshisPerKilobyte

The primary fee model that computes fees based on transaction size in bytes.

```rust
#[derive(Debug, Clone, Copy)]
pub struct SatoshisPerKilobyte {
    /// The number of satoshis paid per kilobyte of transaction size.
    pub value: u64,
}
```

**Key Methods:**

| Method | Description |
|--------|-------------|
| `new(value: u64)` | Constructs a fee model with the specified sat/KB rate |
| `compute_fee(&self, tx: &Transaction)` | Computes the fee for a transaction (from `FeeModel` trait) |

**Private Methods:**

| Method | Description |
|--------|-------------|
| `estimate_size(&self, tx: &Transaction)` | Estimates transaction size in bytes for fee calculation |

**Traits Implemented:**

- `FeeModel` - Core trait for fee computation (requires `Send + Sync`)
- `Default` - Returns `SatoshisPerKilobyte::new(100)` (standard BSV rate)
- `Debug`, `Clone`, `Copy`

## Usage

### Basic Fee Calculation

```rust
use bsv_sdk::transaction::{SatoshisPerKilobyte, FeeModel, Transaction};

// Create fee model with 100 satoshis per kilobyte (standard BSV rate)
let fee_model = SatoshisPerKilobyte::new(100);

// Or use the default (also 100 sat/KB)
let fee_model = SatoshisPerKilobyte::default();

// Compute fee for a transaction
let tx = Transaction::new();
let fee = fee_model.compute_fee(&tx)?;
```

### Custom Fee Rates

```rust
// Higher fee for faster confirmation (1 sat/byte = 1000 sat/KB)
let fast_fee = SatoshisPerKilobyte::new(1000);

// Lower fee for non-urgent transactions
let slow_fee = SatoshisPerKilobyte::new(50);
```

## Implementation Details

### Transaction Size Estimation

The `estimate_size` method calculates transaction size by summing:

1. **Version field**: 4 bytes
2. **Input count**: Varint (1-9 bytes)
3. **Each input**: 40 bytes base (txid + output index + sequence) + unlocking script with varint length
4. **Output count**: Varint (1-9 bytes)
5. **Each output**: 8 bytes (satoshis) + locking script with varint length
6. **Lock time**: 4 bytes

### Varint Encoding

Bitcoin uses variable-length integers for counts and lengths. The module includes a helper function `varint_size()`:

| Value Range | Encoded Size |
|-------------|--------------|
| 0 - 0xFC | 1 byte |
| 0xFD - 0xFFFF | 3 bytes |
| 0x10000 - 0xFFFFFFFF | 5 bytes |
| > 0xFFFFFFFF | 9 bytes |

### Unlocking Script Size

For inputs without a finalized unlocking script, the fee model uses:

1. **`unlocking_script`** - If present, uses actual script size via `to_binary().len()`
2. **`unlocking_script_template`** - If present, calls `estimate_length()` for estimated size
3. **Neither** - Returns `FeeModelError` since fee cannot be computed

### Fee Calculation Formula

The fee is computed using ceiling division to ensure miners receive at least the minimum fee:

```rust
let fee = (size as u64 * self.value).div_ceil(1000);
```

This rounds up any fractional kilobyte to ensure the miner receives the extra satoshi.

## Error Handling

The fee computation returns `Result<u64>` and may fail if:

- An input has neither an unlocking script nor a template for size estimation

```rust
Err(crate::Error::FeeModelError(format!(
    "Input {} must have an unlocking script or template for fee computation",
    i
)))
```

## Tests

The module includes unit tests in `sats_per_kb.rs`:

| Test | Description |
|------|-------------|
| `test_new` | Verifies constructor sets value correctly |
| `test_default` | Verifies default is 100 sat/KB |
| `test_varint_size` | Tests varint size calculation for boundary values |
| `test_empty_transaction_fee` | Tests fee calculation for empty transaction (10 bytes = 10 sats at 1000 sat/KB) |

## Related

- `../fee_model.rs` - Defines the `FeeModel` trait and `FixedFee` implementation
- `../CLAUDE.md` - Parent transaction module documentation
- `/CLAUDE.md` - Root SDK documentation
