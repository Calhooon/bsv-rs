# Chain Tracker Implementations
> Concrete implementations of the ChainTracker trait for SPV verification

## Overview

This module provides production-ready implementations of the [`ChainTracker`](../chain_tracker.rs) trait for verifying merkle roots against the BSV blockchain. These implementations connect to blockchain explorer APIs to validate that transaction inclusion proofs are anchored in real blocks.

The primary implementation uses the WhatsOnChain API, which provides free access to BSV blockchain data for both mainnet and testnet.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports `WhatsOnChainTracker` and `WocNetwork` |
| `whatsonchain.rs` | WhatsOnChain API implementation of `ChainTracker` |

## Feature Requirements

These implementations require the `http` feature to be enabled for actual network calls:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["transaction", "http"] }
```

Without the `http` feature, the tracker methods will return `ChainTrackerError::NetworkError` indicating the feature is not enabled.

## Key Exports

### WocNetwork

Network selection enum for WhatsOnChain API endpoints.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WocNetwork {
    #[default]
    Mainnet,  // https://api.whatsonchain.com/v1/bsv/main
    Testnet,  // https://api.whatsonchain.com/v1/bsv/test
}

impl WocNetwork {
    pub fn base_url(&self) -> &'static str
}
```

### WhatsOnChainTracker

Production chain tracker using the WhatsOnChain blockchain explorer API.

```rust
pub struct WhatsOnChainTracker {
    network: WocNetwork,
    client: reqwest::Client,  // Only with "http" feature
}

impl WhatsOnChainTracker {
    pub fn mainnet() -> Self           // Create mainnet tracker
    pub fn testnet() -> Self           // Create testnet tracker
    pub fn new(network: WocNetwork) -> Self  // Create with specific network
    pub fn network(&self) -> WocNetwork     // Get configured network
}

impl Default for WhatsOnChainTracker {
    fn default() -> Self  // Returns mainnet tracker
}
```

### ChainTracker Implementation

The tracker implements the async `ChainTracker` trait:

```rust
#[async_trait]
impl ChainTracker for WhatsOnChainTracker {
    async fn is_valid_root_for_height(&self, root: &str, height: u32)
        -> Result<bool, ChainTrackerError>;

    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}
```

## API Endpoints

The WhatsOnChain tracker uses these API endpoints:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `is_valid_root_for_height` | `GET /block/{height}/header` | Fetch block header, compare merkleroot |
| `current_height` | `GET /chain/info` | Get current blockchain height from `blocks` field |

## Error Handling

The tracker returns `ChainTrackerError` variants:

| Error | Condition |
|-------|-----------|
| `NetworkError` | HTTP request failed, or `http` feature not enabled |
| `BlockNotFound` | HTTP 404 response (block height doesn't exist) |
| `InvalidResponse` | Non-success HTTP status, or JSON parsing failure |

## Usage Examples

### Basic Usage

```rust
use bsv_sdk::transaction::{ChainTracker, WhatsOnChainTracker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create mainnet tracker (default)
    let tracker = WhatsOnChainTracker::mainnet();

    // Get current blockchain height
    let height = tracker.current_height().await?;
    println!("Current height: {}", height);

    // Verify a merkle root at a specific height
    let merkle_root = "abc123def456...";
    let is_valid = tracker
        .is_valid_root_for_height(merkle_root, 700000)
        .await?;

    if is_valid {
        println!("Merkle root is valid for block 700000");
    }

    Ok(())
}
```

### Testnet Usage

```rust
use bsv_sdk::transaction::{WhatsOnChainTracker, WocNetwork};

let tracker = WhatsOnChainTracker::testnet();
// or
let tracker = WhatsOnChainTracker::new(WocNetwork::Testnet);
```

### SPV Verification with BEEF

```rust
use bsv_sdk::transaction::{Beef, ChainTracker, WhatsOnChainTracker};

async fn verify_beef(beef_hex: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let mut beef = Beef::from_hex(beef_hex)?;
    let validation = beef.verify_valid(false);

    if !validation.valid {
        return Ok(false);
    }

    let tracker = WhatsOnChainTracker::mainnet();

    // Verify all merkle roots against the blockchain
    for (height, root) in validation.roots {
        let valid = tracker.is_valid_root_for_height(&root, height).await?;
        if !valid {
            return Ok(false);
        }
    }

    Ok(true)
}
```

## Implementation Details

### Merkle Root Comparison

The `is_valid_root_for_height` method performs case-insensitive comparison of merkle roots:

```rust
Ok(header.merkleroot.to_lowercase() == root.to_lowercase())
```

This ensures compatibility regardless of whether the caller provides uppercase or lowercase hex strings.

### HTTP Client

When the `http` feature is enabled, each tracker instance creates its own `reqwest::Client`. For high-volume applications, consider reusing tracker instances rather than creating new ones for each verification.

### Conditional Compilation

The implementation uses `#[cfg(feature = "http")]` to provide functional implementations only when HTTP support is available. Without the feature, methods return descriptive errors guiding users to enable it.

## Testing

The module includes unit tests for network configuration:

```bash
cargo test chain_trackers
```

Tests verify:
- `WocNetwork` URL generation for mainnet/testnet
- `WocNetwork::default()` returns `Mainnet`
- `WhatsOnChainTracker` construction methods
- Network getter returns correct value

Note: Integration tests against the live API are marked `ignore` to avoid network dependencies in CI.

## Related Documentation

- `../chain_tracker.rs` - The `ChainTracker` trait definition, `ChainTrackerError`, and mock implementations
- `../CLAUDE.md` - Transaction module overview including SPV verification patterns
- `../merkle_path.rs` - `MerklePath` for computing merkle roots from proofs
- `../beef.rs` - BEEF format verification that uses `ChainTracker`

## External References

- [WhatsOnChain API Documentation](https://developers.whatsonchain.com/)
- [BRC-74 BUMP](https://github.com/bitcoin-sv/BRCs/blob/master/transactions/0074.md) - Merkle proof format
- [BRC-62 BEEF](https://github.com/bitcoin-sv/BRCs/blob/master/transactions/0062.md) - Background Evaluation Extended Format
