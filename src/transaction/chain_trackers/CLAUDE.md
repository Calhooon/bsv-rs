# Chain Tracker Implementations
> Concrete implementations of the ChainTracker trait for SPV verification

## Overview

This module provides production-ready implementations of the [`ChainTracker`](../chain_tracker.rs) trait for verifying merkle roots against the BSV blockchain. These implementations connect to blockchain services to validate that transaction inclusion proofs are anchored in real blocks.

Available implementations:
- **`WhatsOnChainTracker`** - WhatsOnChain API (free tier available)
- **`BlockHeadersServiceTracker`** - Block Headers Service API (headers.spv.money)

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports all trackers and constants |
| `whatsonchain.rs` | WhatsOnChain API implementation of `ChainTracker` |
| `block_headers_service.rs` | Block Headers Service implementation of `ChainTracker` |

## Feature Requirements

These implementations require the `http` feature to be enabled for actual network calls:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["transaction", "http"] }
```

Without the `http` feature, the tracker methods will return `ChainTrackerError::NetworkError` indicating the feature is not enabled.

## Key Exports

From `mod.rs`:
- `WhatsOnChainTracker` - WhatsOnChain tracker implementation
- `WocNetwork` - Network enum (Mainnet/Testnet)
- `BlockHeadersServiceTracker` - Block Headers Service tracker implementation
- `BlockHeadersServiceConfig` - Configuration struct for Block Headers Service
- `DEFAULT_HEADERS_URL` - Default URL constant (`"https://headers.spv.money"`)

---

## WhatsOnChainTracker

Production chain tracker using the WhatsOnChain blockchain explorer API.

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

### WhatsOnChainTracker Struct

```rust
pub struct WhatsOnChainTracker {
    network: WocNetwork,
    base_url_override: Option<String>,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl WhatsOnChainTracker {
    pub fn mainnet() -> Self                                      // Create mainnet tracker
    pub fn testnet() -> Self                                      // Create testnet tracker
    pub fn new(network: WocNetwork) -> Self                       // Create with specific network
    pub fn with_base_url(base_url: &str, network: WocNetwork) -> Self  // Create with custom URL (for testing)
    pub fn network(&self) -> WocNetwork                           // Get configured network
    fn base_url(&self) -> &str                                    // (http only) Resolve effective base URL
}

impl Default for WhatsOnChainTracker {
    fn default() -> Self  // Returns mainnet tracker
}

impl Debug for WhatsOnChainTracker {
    // Custom impl: shows network and base_url_override, omits reqwest::Client
}
```

### WhatsOnChain API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `is_valid_root_for_height` | `GET /block/{height}/header` | Fetch block header, compare merkleroot |
| `current_height` | `GET /chain/info` | Get current blockchain height from `blocks` field |

### WhatsOnChain Usage

```rust
use bsv_rs::transaction::{ChainTracker, WhatsOnChainTracker, WocNetwork};

// Create mainnet tracker (default)
let tracker = WhatsOnChainTracker::mainnet();

// Create testnet tracker
let tracker = WhatsOnChainTracker::testnet();

// Or with explicit network
let tracker = WhatsOnChainTracker::new(WocNetwork::Testnet);

// Or with a custom base URL (useful for testing against a mock server)
let tracker = WhatsOnChainTracker::with_base_url("http://localhost:8080", WocNetwork::Mainnet);

// Get current blockchain height
let height = tracker.current_height().await?;

// Verify a merkle root at a specific height
let is_valid = tracker
    .is_valid_root_for_height("abc123def456...", 700000)
    .await?;
```

---

## BlockHeadersServiceTracker

Chain tracker using the Block Headers Service API (headers.spv.money), a fast and reliable headers service designed for SPV verification.

### BlockHeadersServiceConfig

```rust
#[derive(Debug, Clone)]
pub struct BlockHeadersServiceConfig {
    pub base_url: String,           // Default: "https://headers.spv.money"
    pub auth_token: Option<String>, // Optional Bearer token for authentication
    pub timeout_ms: u64,            // Request timeout (default: 30,000 ms)
}

impl Default for BlockHeadersServiceConfig {
    fn default() -> Self  // Returns config with DEFAULT_HEADERS_URL, no auth, 30s timeout
}
```

### BlockHeadersServiceTracker Struct

```rust
pub struct BlockHeadersServiceTracker {
    config: BlockHeadersServiceConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl BlockHeadersServiceTracker {
    pub fn new() -> Self                                      // Create with default URL
    pub fn with_url(base_url: &str) -> Self                   // Create with custom URL
    pub fn with_config(config: BlockHeadersServiceConfig) -> Self  // Create with full config
    pub fn base_url(&self) -> &str                            // Get configured base URL
    pub fn auth_token(&self) -> Option<&str>                  // Get configured auth token
}

impl Default for BlockHeadersServiceTracker {
    fn default() -> Self  // Returns tracker with default URL
}
```

### Block Headers Service API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `is_valid_root_for_height` | `GET /api/v1/chain/header/{height}` | Fetch header, compare merkleroot |
| `current_height` | `GET /api/v1/chain/tip` | Get current blockchain height |

The Block Headers Service API supports multiple field names for compatibility:
- `merkleroot` or `merkleRoot` for the merkle root field
- `height`, `blockHeight`, or `blocks` for the chain height field

### Block Headers Service Usage

```rust
use bsv_rs::transaction::{
    ChainTracker, BlockHeadersServiceTracker, BlockHeadersServiceConfig,
    DEFAULT_HEADERS_URL
};

// Create with default URL
let tracker = BlockHeadersServiceTracker::default();

// Or with custom URL
let tracker = BlockHeadersServiceTracker::with_url("https://custom.headers.com");

// Or with full configuration (including auth token)
let config = BlockHeadersServiceConfig {
    base_url: DEFAULT_HEADERS_URL.to_string(),
    auth_token: Some("my-api-token".to_string()),
    timeout_ms: 60_000,  // 60 second timeout
};
let tracker = BlockHeadersServiceTracker::with_config(config);

// Verify a merkle root
let is_valid = tracker
    .is_valid_root_for_height("abc123...", 700000)
    .await?;

// Get current height
let height = tracker.current_height().await?;
```

---

## ChainTracker Trait Implementation

Both trackers implement the async `ChainTracker` trait:

```rust
#[async_trait]
impl ChainTracker for WhatsOnChainTracker {
    async fn is_valid_root_for_height(&self, root: &str, height: u32)
        -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

#[async_trait]
impl ChainTracker for BlockHeadersServiceTracker {
    async fn is_valid_root_for_height(&self, root: &str, height: u32)
        -> Result<bool, ChainTrackerError>;
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}
```

## Error Handling

Both trackers return `ChainTrackerError` variants:

| Error | Condition |
|-------|-----------|
| `NetworkError` | HTTP request failed, timeout, or `http` feature not enabled |
| `BlockNotFound` | HTTP 404 response (block height doesn't exist) |
| `InvalidResponse` | Non-success HTTP status, JSON parsing failure, or missing required fields |

## SPV Verification with BEEF

```rust
use bsv_rs::transaction::{Beef, ChainTracker, WhatsOnChainTracker};

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

Both trackers perform case-insensitive comparison of merkle roots:

```rust
Ok(header.merkleroot.to_lowercase() == root.to_lowercase())
```

This ensures compatibility regardless of whether the caller provides uppercase or lowercase hex strings.

### Base URL Override (WhatsOnChainTracker)

`WhatsOnChainTracker::with_base_url()` allows overriding the network-derived URL. When set, the override takes precedence over the network's default URL. This is useful for integration testing against mock HTTP servers. The override is stored in `base_url_override: Option<String>` and resolved by the private `base_url()` method.

### HTTP Client

When the `http` feature is enabled, each tracker instance creates its own `reqwest::Client`. For high-volume applications, consider reusing tracker instances rather than creating new ones for each verification.

### Authentication (BlockHeadersServiceTracker only)

The `BlockHeadersServiceTracker` supports optional Bearer token authentication via the `auth_token` config field. When set, requests include an `Authorization: Bearer <token>` header.

### Request Timeout (BlockHeadersServiceTracker only)

The `BlockHeadersServiceTracker` supports configurable request timeouts via `timeout_ms` (default: 30 seconds).

### Conditional Compilation

Both implementations use `#[cfg(feature = "http")]` to provide functional implementations only when HTTP support is available. Without the feature, methods return descriptive errors guiding users to enable it.

## Testing

The module includes unit tests for tracker configuration:

```bash
cargo test chain_trackers
```

Tests verify:
- `WocNetwork` URL generation for mainnet/testnet
- `WocNetwork::default()` returns `Mainnet`
- `WhatsOnChainTracker` construction methods
- `BlockHeadersServiceConfig` default values
- `BlockHeadersServiceTracker` construction with various configurations
- Network/URL getter methods return correct values

Integration tests using `with_base_url` (WoC) or `with_url` (BHS) to point at mock HTTP servers are in `tests/chaintracker_http_tests.rs`.

Note: Integration tests against the live APIs are marked `ignore` to avoid network dependencies in CI.

## Related Documentation

- `../chain_tracker.rs` - The `ChainTracker` trait definition, `ChainTrackerError`, and mock implementations
- `../CLAUDE.md` - Transaction module overview including SPV verification patterns
- `../merkle_path.rs` - `MerklePath` for computing merkle roots from proofs
- `../beef.rs` - BEEF format verification that uses `ChainTracker`

## External References

- [WhatsOnChain API Documentation](https://developers.whatsonchain.com/)
- [Block Headers Service](https://headers.spv.money)
- [BRC-74 BUMP](https://github.com/bitcoin-sv/BRCs/blob/master/transactions/0074.md) - Merkle proof format
- [BRC-62 BEEF](https://github.com/bitcoin-sv/BRCs/blob/master/transactions/0062.md) - Background Evaluation Extended Format
