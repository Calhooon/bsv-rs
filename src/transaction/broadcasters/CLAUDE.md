# BSV Transaction Broadcasters
> Concrete implementations of the Broadcaster trait for broadcasting transactions to the BSV network

## Overview

This module provides production-ready implementations of the [`Broadcaster`](../broadcaster.rs) trait. Currently includes the `ArcBroadcaster` for TAAL's ARC (Avalanche Relay Client) service, which is the recommended broadcaster for BSV applications.

These implementations require the `http` feature flag to enable actual network requests.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports `ArcBroadcaster` and `ArcConfig` |
| `arc.rs` | ARC broadcaster implementation for TAAL's service |

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

## ARC API Details

The broadcaster communicates with ARC's REST API:

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

## Error Codes

| Code | Description |
|------|-------------|
| `NETWORK_ERROR` | HTTP request failed (timeout, connection error) |
| `PARSE_ERROR` | Failed to parse JSON response from ARC |
| `NO_HTTP` | HTTP feature not enabled |
| `{status}` | HTTP status code from ARC (e.g., "400", "500") |

## Usage Examples

### Basic Broadcasting

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
- **Sequential Batching**: `broadcast_many()` broadcasts sequentially; ARC does not have a batch endpoint
- **Timeout Handling**: Default 30-second timeout; increase for slow networks or large transactions
- **TXID Computation**: The broadcaster computes the TXID locally via `tx.id()` before sending to ARC
- **Response Parsing**: Gracefully handles missing fields in ARC response with sensible defaults

## Testing

The module includes unit tests for configuration and construction:

```bash
cargo test broadcasters
```

Integration tests with actual ARC endpoints require network access and valid API keys.

## Related Documentation

- `../CLAUDE.md` - Transaction module overview
- `../broadcaster.rs` - `Broadcaster` trait definition and types
- [ARC Documentation](https://github.com/bitcoin-sv/arc) - Official ARC service documentation
