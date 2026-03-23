# Fee Models Module
> Fee calculation implementations for BSV transaction construction

## Overview

This module provides concrete implementations of the `FeeModel` trait for computing transaction fees:

- **`SatoshisPerKilobyte`** - Static fee rate based on transaction size
- **`LivePolicy`** - Dynamic fee rate fetched from ARC policy endpoint

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; exports all fee models |
| `sats_per_kb.rs` | Size-based fee model computing satoshis per kilobyte |
| `live_policy.rs` | Live fee rate fetched from ARC policy API |

## Key Exports

```rust
// Re-exported from mod.rs
pub use sats_per_kb::SatoshisPerKilobyte;
pub use live_policy::{LivePolicy, LivePolicyConfig, DEFAULT_POLICY_URL, DEFAULT_CACHE_TTL_SECS, DEFAULT_FALLBACK_RATE};
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
use bsv_rs::transaction::{SatoshisPerKilobyte, FeeModel, Transaction};

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

## LivePolicy

The `LivePolicy` fee model fetches the current fee rate from an ARC policy endpoint and caches it for a configurable duration.

### LivePolicyConfig

```rust
pub struct LivePolicyConfig {
    pub policy_url: String,        // Default: "https://arc.gorillapool.io/v1/policy"
    pub api_key: Option<String>,   // Optional Bearer token
    pub cache_ttl: Duration,       // Default: 5 minutes
    pub fallback_rate: u64,        // Default: 100 sat/KB
    pub timeout_ms: u64,           // Default: 10,000 ms
}
```

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_POLICY_URL` | `"https://arc.gorillapool.io/v1/policy"` | Default ARC policy endpoint |
| `DEFAULT_CACHE_TTL_SECS` | `300` | 5 minute cache TTL |
| `DEFAULT_FALLBACK_RATE` | `100` | Fallback rate in sat/KB |

### LivePolicy

```rust
pub struct LivePolicy {
    config: LivePolicyConfig,
    cached_rate: RwLock<Option<CachedRate>>,
    client: reqwest::Client,  // Only with "http" feature
}

impl LivePolicy {
    pub fn new() -> Self                         // Create with default config
    pub fn with_url(policy_url: &str) -> Self    // Create with custom URL
    pub fn with_config(config: LivePolicyConfig) -> Self
    pub fn policy_url(&self) -> &str
    pub fn cache_ttl(&self) -> Duration
    pub fn cached_rate(&self) -> Option<u64>     // Get cached rate if valid
    pub fn effective_rate(&self) -> u64          // Get cached or fallback rate
    pub fn set_rate(&self, rate: u64)            // Manually set cached rate
    pub async fn refresh(&self) -> Result<u64>   // Fetch rate from API
}

impl FeeModel for LivePolicy {
    fn compute_fee(&self, tx: &Transaction) -> Result<u64>
}
```

### LivePolicy Usage

```rust
use bsv_rs::transaction::{LivePolicy, FeeModel, Transaction};

// Create with default configuration
let fee_model = LivePolicy::default();

// Refresh the cached rate (async)
fee_model.refresh().await?;

// Compute fee using cached or fallback rate
let tx = Transaction::new();
let fee = fee_model.compute_fee(&tx)?;

// Or set a rate manually for offline use
fee_model.set_rate(100);
```

### LivePolicy API

**Endpoint**: `GET {policy_url}`

**Response Format**:
```json
{
  "miningFee": {
    "satoshis": 1,
    "bytes": 1000
  }
}
```

The rate is converted to sat/KB: `(satoshis * 1000) / bytes`

## Related

- `../fee_model.rs` - Defines the `FeeModel` trait and `FixedFee` implementation
- `../CLAUDE.md` - Parent transaction module documentation
- `/CLAUDE.md` - Root SDK documentation
