# BSV Transaction Broadcasters
> Concrete implementations of the Broadcaster trait for broadcasting transactions to the BSV network

## Overview

This module provides production-ready implementations of the [`Broadcaster`](../broadcaster.rs) trait:

- **`ArcBroadcaster`** - TAAL's ARC (Avalanche Relay Client) service, recommended for production
- **`TeranodeBroadcaster`** - Teranode transaction processing using Extended Format (EF/BRC-30) binary
- **`WhatsOnChainBroadcaster`** - WhatsOnChain API, free tier available

These implementations require the `http` feature flag to enable actual network requests.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports all broadcasters |
| `arc.rs` | ARC broadcaster implementation for TAAL's service |
| `teranode.rs` | Teranode broadcaster using Extended Format binary data |
| `whatsonchain.rs` | WhatsOnChain API broadcaster implementation |

## Feature Requirements

The broadcasters require HTTP functionality. Enable via Cargo.toml:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["transaction", "http"] }
```

Without the `http` feature, calling `broadcast()` returns an error with code `NO_HTTP`.

## Key Exports

### ArcConfig

Configuration for the ARC broadcaster:

```rust
pub struct ArcConfig {
    pub url: String,           // ARC API URL (default: "https://arc.taal.com")
    pub api_key: Option<String>, // Optional Bearer token for authentication
    pub timeout_ms: u64,       // Request timeout (default: 30,000 ms)
}
```

### ArcBroadcaster

TAAL's ARC service broadcaster:

```rust
pub struct ArcBroadcaster {
    config: ArcConfig,
    client: reqwest::Client,  // Only with "http" feature
}

impl ArcBroadcaster {
    pub fn new(url: &str, api_key: Option<String>) -> Self
    pub fn with_config(config: ArcConfig) -> Self
    pub fn default() -> Self  // Uses https://arc.taal.com
    pub fn url(&self) -> &str
    pub fn api_key(&self) -> Option<&str>
}

#[async_trait(?Send)]
impl Broadcaster for ArcBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>
}
```

### TeranodeConfig

Configuration for the Teranode broadcaster:

```rust
pub struct TeranodeConfig {
    pub url: String,           // Teranode API URL (no default - must be provided)
    pub api_key: Option<String>, // Optional Bearer token for authentication
    pub timeout_ms: u64,       // Request timeout (default: 30,000 ms)
}
```

### TeranodeBroadcaster

Teranode transaction processing broadcaster. Unlike ARC, Teranode accepts Extended Format (EF/BRC-30)
binary data rather than JSON hex. No default URL — must be provided.

```rust
pub struct TeranodeBroadcaster {
    config: TeranodeConfig,
    client: reqwest::Client,  // Only with "http" feature
}

impl TeranodeBroadcaster {
    pub fn new(url: &str, api_key: Option<String>) -> Self
    pub fn with_config(config: TeranodeConfig) -> Self
    pub fn url(&self) -> &str
    pub fn api_key(&self) -> Option<&str>
    // Note: no Default impl — URL is required
}

#[async_trait(?Send)]
impl Broadcaster for TeranodeBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>
}
```

### WocBroadcastNetwork

Network selection for WhatsOnChain broadcaster:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WocBroadcastNetwork {
    #[default]
    Mainnet,   // https://api.whatsonchain.com/v1/bsv/main/tx/raw
    Testnet,   // https://api.whatsonchain.com/v1/bsv/test/tx/raw
    Stn,       // https://api.whatsonchain.com/v1/bsv/stn/tx/raw
}

impl WocBroadcastNetwork {
    pub fn broadcast_url(&self) -> String  // Full URL for this network
}
```

### WocBroadcastConfig

Configuration for WhatsOnChain broadcaster:

```rust
pub struct WocBroadcastConfig {
    pub network: WocBroadcastNetwork,  // Network to broadcast to
    pub api_key: Option<String>,       // Optional API key for higher rate limits
    pub timeout_ms: u64,               // Request timeout (default: 30,000 ms)
    pub base_url: Option<String>,      // Optional URL override (for testing with mock servers)
}
```

### WhatsOnChainBroadcaster

WhatsOnChain API broadcaster:

```rust
pub struct WhatsOnChainBroadcaster {
    config: WocBroadcastConfig,
    client: reqwest::Client,  // Only with "http" feature
}

impl WhatsOnChainBroadcaster {
    pub fn mainnet() -> Self          // Create mainnet broadcaster
    pub fn testnet() -> Self          // Create testnet broadcaster
    pub fn stn() -> Self              // Create STN broadcaster
    pub fn new(network: WocBroadcastNetwork, api_key: Option<String>) -> Self
    pub fn with_config(config: WocBroadcastConfig) -> Self
    pub fn with_base_url(base_url: &str, network: WocBroadcastNetwork, api_key: Option<String>) -> Self
    pub fn network(&self) -> WocBroadcastNetwork
    pub fn api_key(&self) -> Option<&str>
}

#[async_trait(?Send)]
impl Broadcaster for WhatsOnChainBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>
}
```

## API Details

### ARC API

**Endpoint**: `POST {url}/v1/tx`

**Request**:
```json
{ "rawTx": "<hex-encoded-transaction>" }
```

**Headers**:
- `Content-Type: application/json`
- `Authorization: Bearer {api_key}` (if configured)

**Success Response** (HTTP 2xx):
```json
{
  "txid": "...",
  "txStatus": "SEEN_ON_NETWORK",
  "extraInfo": "..."
}
```

**Error Response** (HTTP 4xx/5xx):
```json
{
  "status": 400,
  "title": "Bad Request",
  "detail": "Transaction validation failed"
}
```

### Teranode API

**Endpoint**: `POST {url}/v1/tx`

**Request**: Raw Extended Format (EF/BRC-30) binary body

**Headers**:
- `Content-Type: application/octet-stream`
- `Authorization: Bearer {api_key}` (if configured)

**Success Response** (HTTP 2xx): Body text (or "Success" if empty)

**Error Response** (HTTP 4xx/5xx): Body text with error description

**Key difference from ARC**: Uses `tx.to_ef()` to serialize the transaction as EF binary instead of
hex-encoded JSON. This is more efficient for large transactions. An `EF_SERIALIZATION_ERROR` is
returned if the transaction cannot be serialized to EF format (e.g., missing source outputs).

### WhatsOnChain API

**Endpoint**: `POST https://api.whatsonchain.com/v1/bsv/{network}/tx/raw` (or `{base_url}/v1/bsv/{network}/tx/raw` if `base_url` is set)

**Request**: Raw transaction hex as body (Content-Type: application/json)

**Headers**:
- `Content-Type: application/json`
- `Authorization: {api_key}` (if configured, no "Bearer" prefix)

**Success Response** (HTTP 2xx): Returns TXID as plain text

**Error Response** (HTTP 4xx/5xx): Returns error description

## Error Codes

| Code | Description |
|------|-------------|
| `NETWORK_ERROR` | HTTP request failed (timeout, connection error) |
| `PARSE_ERROR` | Failed to parse response body |
| `NO_HTTP` | HTTP feature not enabled |
| `EF_SERIALIZATION_ERROR` | Failed to serialize to EF format (Teranode only) |
| `{status}` | HTTP status code from service (e.g., "400", "500") |

## Usage Examples

### Basic Broadcasting (ARC)

```rust
use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster, Transaction};

#[tokio::main]
async fn main() {
    // Create broadcaster with default TAAL endpoint
    let broadcaster = ArcBroadcaster::default();

    let tx = Transaction::from_hex("0100000001...").unwrap();

    match broadcaster.broadcast(&tx).await {
        Ok(response) => {
            println!("Broadcast success!");
            println!("TXID: {}", response.txid);
            println!("Status: {:?}", response.status);
        }
        Err(failure) => {
            println!("Broadcast failed: {}", failure.description);
            println!("Error code: {}", failure.code);
        }
    }
}
```

### Teranode Broadcasting

```rust
use bsv_sdk::transaction::{TeranodeBroadcaster, Broadcaster, Transaction};

// No default URL - must be provided
let broadcaster = TeranodeBroadcaster::new(
    "https://teranode.example.com",
    Some("your-api-key".to_string())
);

match broadcaster.broadcast(&tx).await {
    Ok(response) => println!("Success: {}", response.txid),
    Err(failure) => println!("Failed: {}", failure.description),
}
```

### With API Key Authentication

```rust
use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster};

let broadcaster = ArcBroadcaster::new(
    "https://arc.taal.com",
    Some("your-api-key".to_string())
);
```

### Custom Configuration

```rust
use bsv_sdk::transaction::broadcasters::{ArcBroadcaster, ArcConfig};

let config = ArcConfig {
    url: "https://arc.gorillapool.io".to_string(),
    api_key: Some("my-api-key".to_string()),
    timeout_ms: 60_000,  // 60 second timeout
};

let broadcaster = ArcBroadcaster::with_config(config);
```

### WhatsOnChain Broadcasting

```rust
use bsv_sdk::transaction::{WhatsOnChainBroadcaster, Broadcaster, WocBroadcastNetwork};

// Create mainnet broadcaster
let broadcaster = WhatsOnChainBroadcaster::mainnet();

// Or testnet
let broadcaster = WhatsOnChainBroadcaster::testnet();

// Or with API key
let broadcaster = WhatsOnChainBroadcaster::new(
    WocBroadcastNetwork::Mainnet,
    Some("your-api-key".to_string())
);

// Broadcast
match broadcaster.broadcast(&tx).await {
    Ok(response) => println!("Success: {}", response.txid),
    Err(failure) => println!("Failed: {}", failure.description),
}
```

### WhatsOnChain with Custom Base URL (Testing)

```rust
use bsv_sdk::transaction::{WhatsOnChainBroadcaster, WocBroadcastNetwork};

// Use a mock server for testing
let broadcaster = WhatsOnChainBroadcaster::with_base_url(
    "http://localhost:3000",
    WocBroadcastNetwork::Mainnet,
    None,
);
// Broadcasts to: http://localhost:3000/v1/bsv/main/tx/raw
```

### Broadcasting Multiple Transactions

```rust
use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster, Transaction};

let broadcaster = ArcBroadcaster::default();
let transactions = vec![tx1, tx2, tx3];

let results = broadcaster.broadcast_many(transactions).await;

for (i, result) in results.iter().enumerate() {
    match result {
        Ok(r) => println!("TX {}: Success - {}", i, r.txid),
        Err(f) => println!("TX {}: Failed - {}", i, f.description),
    }
}
```

## Implementation Notes

- **Async Trait**: Uses `#[async_trait(?Send)]` because `Transaction` contains `RefCell` which is not `Send`
- **Sequential Batching**: `broadcast_many()` is a default trait method that broadcasts sequentially; none of the three implementations override it
- **Timeout Handling**: Default 30-second timeout on all broadcasters; increase for slow networks or large transactions
- **TXID Computation**: All broadcasters compute the TXID locally via `tx.id()` before sending
- **Response Parsing**: ARC parses structured JSON; Teranode and WoC use plain text responses
- **EF Format**: Teranode uses `tx.to_ef()` for binary serialization; ARC and WoC use `tx.to_hex()` for hex encoding
- **Auth Header**: ARC and Teranode use `Authorization: Bearer {key}`; WoC uses `Authorization: {key}` (no prefix)

## Testing

The module includes unit tests for configuration and construction:

```bash
cargo test broadcasters
```

Integration tests with actual endpoints require network access and valid API keys.

## Related Documentation

- `../CLAUDE.md` - Transaction module overview
- `../broadcaster.rs` - `Broadcaster` trait definition and types
- [ARC Documentation](https://github.com/bitcoin-sv/arc) - Official ARC service documentation
- [WhatsOnChain API](https://developers.whatsonchain.com/) - WhatsOnChain API documentation
