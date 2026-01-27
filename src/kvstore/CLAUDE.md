# BSV KVStore Module
> Blockchain-backed key-value storage for BSV applications

## Overview

This module provides persistent key-value storage backed by blockchain transactions. It offers two implementations:

- **LocalKVStore**: Private storage using wallet transactions and baskets. Values are encrypted by default using wallet-derived keys.
- **GlobalKVStore**: Public storage using the overlay network. Values are stored as PushDrop tokens discoverable via lookup services.

Both implementations maintain cross-SDK compatibility with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with re-exports | ~75 |
| `types.rs` | Core types (Config, Entry, Token, Query, Options) | ~480 |
| `local.rs` | LocalKVStore implementation | ~450 |
| `global.rs` | GlobalKVStore implementation | ~420 |
| `interpreter.rs` | PushDrop token interpreter | ~290 |

## Key Exports

```rust
// Types
pub use types::{
    KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreLookupResult,
    KVStoreQuery, KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
};

// Stores
pub use local::LocalKVStore;
pub use global::GlobalKVStore;

// Interpreter
pub use interpreter::{KVStoreContext, KVStoreFields, KVStoreInterpreter};
```

## LocalKVStore

Private key-value store using wallet transactions and baskets.

### Features
- **Encrypted storage**: Values encrypted using wallet-derived keys (AES-256-GCM)
- **Wallet basket**: Entries stored in a namespaced basket
- **Tag-based lookup**: Keys stored as tags for efficient retrieval
- **Atomic operations**: Per-key locking prevents concurrent conflicts

### Methods

```rust
impl<W: WalletInterface> LocalKVStore<W> {
    /// Create a new LocalKVStore
    pub fn new(wallet: W, config: KVStoreConfig) -> Self;

    /// Get a value by key (returns None if not found)
    pub async fn get(&self, key: &str, options: Option<KVStoreGetOptions>) -> Result<Option<KVStoreEntry>>;

    /// Set a key-value pair (creates or updates)
    pub async fn set(&self, key: &str, value: &str, options: Option<KVStoreSetOptions>) -> Result<String>;

    /// Remove a key-value pair
    pub async fn remove(&self, key: &str, options: Option<KVStoreRemoveOptions>) -> Result<Vec<String>>;

    /// List all keys
    pub async fn keys(&self) -> Result<Vec<String>>;

    /// List entries matching a query
    pub async fn list(&self, query: Option<KVStoreQuery>) -> Result<Vec<KVStoreEntry>>;

    /// Check if a key exists
    pub async fn has(&self, key: &str) -> Result<bool>;

    /// Get the entry count
    pub async fn count(&self) -> Result<usize>;

    /// Clear all entries
    pub async fn clear(&self) -> Result<()>;
}
```

### Encryption

LocalKVStore encrypts values using the wallet's key derivation:

```rust
// Key derivation for encryption
let protocol = Protocol::new(SecurityLevel::Counterparty, &config.protocol_id);
// keyID = the key being stored
// counterparty = Self_ (encrypt for self)
```

The encryption uses AES-256-GCM with keys derived via BRC-42.

## GlobalKVStore

Public key-value store using the overlay network.

### Features
- **Public discovery**: Entries discoverable via lookup services
- **PushDrop tokens**: Entries stored as on-chain tokens
- **Signature verification**: Entries signed by controller
- **Tag filtering**: Query by tags with "all" or "any" mode

### Methods

```rust
impl<W: WalletInterface> GlobalKVStore<W> {
    /// Create a new GlobalKVStore
    pub fn new(wallet: W, config: KVStoreConfig) -> Self;

    /// Create with custom network preset
    pub fn with_network(wallet: W, config: KVStoreConfig, network: NetworkPreset) -> Self;

    /// Get a value by key
    pub async fn get(&self, key: &str, options: Option<KVStoreGetOptions>) -> Result<Option<KVStoreEntry>>;

    /// Set a key-value pair
    pub async fn set(&self, key: &str, value: &str, options: Option<KVStoreSetOptions>) -> Result<String>;

    /// Remove a key-value pair
    pub async fn remove(&self, key: &str, options: Option<KVStoreRemoveOptions>) -> Result<String>;

    /// Query entries
    pub async fn query(&self, query: KVStoreQuery) -> Result<Vec<KVStoreEntry>>;

    /// Get entries by controller
    pub async fn get_by_controller(&self, controller: &str) -> Result<Vec<KVStoreEntry>>;

    /// Get entries by tags
    pub async fn get_by_tags(&self, tags: &[String], mode: Option<&str>) -> Result<Vec<KVStoreEntry>>;
}
```

## PushDrop Token Format

Global entries use PushDrop tokens with the following field layout:

| Index | Field | Description |
|-------|-------|-------------|
| 0 | Protocol ID | String identifier (e.g., "kvstore") |
| 1 | Key | The key string |
| 2 | Value | The value (plaintext for global, encrypted for local) |
| 3 | Controller | 33-byte compressed public key |
| 4 | Tags | JSON array of tag strings (optional, new format) |
| 5 | Signature | Controller's signature over fields 0-4 |

### Old vs New Format

- **Old format**: 5 fields (no tags), signature at index 4
- **New format**: 6 fields (with tags), signature at index 5

Both formats are supported for backward compatibility.

## Configuration

```rust
pub struct KVStoreConfig {
    /// Protocol ID for key derivation (default: "kvstore")
    pub protocol_id: String,
    /// Service name for overlay lookup (default: "ls_kvstore")
    pub service_name: String,
    /// Token amount in satoshis (default: 1)
    pub token_amount: u64,
    /// Topics for broadcasting (default: ["tm_kvstore"])
    pub topics: Vec<String>,
    /// Originator for wallet operations
    pub originator: Option<String>,
    /// Whether to encrypt values (LocalKVStore only)
    pub encrypt: bool,
}

impl KVStoreConfig {
    pub fn new() -> Self;
    pub fn with_protocol_id(self, id: impl Into<String>) -> Self;
    pub fn with_service_name(self, name: impl Into<String>) -> Self;
    pub fn with_token_amount(self, amount: u64) -> Self;
    pub fn with_topics(self, topics: Vec<String>) -> Self;
    pub fn with_originator(self, originator: impl Into<String>) -> Self;
    pub fn with_encrypt(self, encrypt: bool) -> Self;
}
```

## Query Parameters

```rust
pub struct KVStoreQuery {
    pub key: Option<String>,           // Exact key match
    pub controller: Option<String>,    // Controller pubkey (hex)
    pub protocol_id: Option<String>,   // Protocol ID filter
    pub tags: Option<Vec<String>>,     // Tag filter
    pub tag_query_mode: Option<String>, // "all" (default) or "any"
    pub limit: Option<u32>,            // Max results
    pub skip: Option<u32>,             // Pagination offset
    pub sort_order: Option<String>,    // "asc" or "desc"
}

impl KVStoreQuery {
    pub fn new() -> Self;
    pub fn with_key(self, key: impl Into<String>) -> Self;
    pub fn with_controller(self, controller: impl Into<String>) -> Self;
    pub fn with_tags(self, tags: Vec<String>) -> Self;
    pub fn with_tag_query_mode(self, mode: impl Into<String>) -> Self;
    pub fn with_limit(self, limit: u32) -> Self;
    // ...
}
```

## Interpreter

The `KVStoreInterpreter` extracts entries from PushDrop scripts:

```rust
impl KVStoreInterpreter {
    /// Interpret a transaction output
    pub fn interpret(
        tx: &Transaction,
        output_index: u32,
        ctx: Option<&KVStoreContext>,
    ) -> Option<KVStoreEntry>;

    /// Interpret a locking script directly
    pub fn interpret_script(
        script: &LockingScript,
        ctx: Option<&KVStoreContext>,
    ) -> Option<KVStoreEntry>;

    /// Extract just the value
    pub fn extract_value(script: &LockingScript) -> Option<String>;

    /// Check if script is a KVStore token
    pub fn is_kvstore_token(script: &LockingScript) -> bool;

    /// Extract all raw fields
    pub fn extract_fields(script: &LockingScript) -> Option<KVStoreFields>;
}
```

## Usage Examples

### LocalKVStore Basic Usage

```rust
use bsv_sdk::kvstore::{LocalKVStore, KVStoreConfig};
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::primitives::PrivateKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet and store
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let config = KVStoreConfig::default();
    let store = LocalKVStore::new(wallet, config);

    // Set a value
    let outpoint = store.set("user:name", "Alice", None).await?;
    println!("Stored at: {}", outpoint);

    // Get a value
    if let Some(entry) = store.get("user:name", None).await? {
        println!("Name: {}", entry.value);
    }

    // List all keys
    let keys = store.keys().await?;
    println!("Keys: {:?}", keys);

    // Remove a value
    store.remove("user:name", None).await?;

    Ok(())
}
```

### GlobalKVStore with Tags

```rust
use bsv_sdk::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreSetOptions, KVStoreQuery};
use bsv_sdk::wallet::ProtoWallet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = ProtoWallet::new(None);
    let config = KVStoreConfig::default();
    let store = GlobalKVStore::new(wallet, config);

    // Set with tags
    let opts = KVStoreSetOptions::new()
        .with_tags(vec!["important".to_string(), "user-data".to_string()]);
    store.set("profile:123", r#"{"name": "Bob"}"#, Some(opts)).await?;

    // Query by tags
    let query = KVStoreQuery::new()
        .with_tags(vec!["important".to_string()])
        .with_tag_query_mode("any")
        .with_limit(10);
    let entries = store.query(query).await?;

    for entry in entries {
        println!("{}: {} (tags: {:?})", entry.key, entry.value, entry.tags);
    }

    Ok(())
}
```

### Custom Configuration

```rust
use bsv_sdk::kvstore::KVStoreConfig;

let config = KVStoreConfig::new()
    .with_protocol_id("my-app-storage")
    .with_service_name("ls_myapp")
    .with_topics(vec!["tm_myapp".to_string()])
    .with_token_amount(100)
    .with_originator("myapp.example.com")
    .with_encrypt(false);  // Disable encryption for local store
```

## Error Handling

The module uses specific error types:

```rust
use bsv_sdk::Error;

match store.get("nonexistent", None).await {
    Ok(None) => println!("Key not found"),
    Ok(Some(entry)) => println!("Found: {}", entry.value),
    Err(Error::KvStoreError(msg)) => println!("Store error: {}", msg),
    Err(Error::KvStoreKeyNotFound(key)) => println!("Key not found: {}", key),
    Err(Error::KvStoreCorruptedState(msg)) => println!("Corrupted: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## Feature Flag

Enable the kvstore feature in `Cargo.toml`:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["kvstore"] }
```

The kvstore feature requires the `overlay` feature (which enables `wallet` and `tokio`).

## Cross-SDK Compatibility

This module maintains API compatibility with:
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `LocalKVStore`, `GlobalKVStore`, query types
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `LocalKVStore`, `KVStoreInterface`

### Type Mapping

| TypeScript | Rust |
|------------|------|
| `KVStoreConfig` | `KVStoreConfig` |
| `KVStoreEntry` | `KVStoreEntry` |
| `KVStoreToken` | `KVStoreToken` |
| `KVStoreQuery` | `KVStoreQuery` |
| `LocalKVStore` | `LocalKVStore<W>` |
| `GlobalKVStore` | `GlobalKVStore<W>` |
| `kvStoreInterpreter` | `KVStoreInterpreter` |

## Related Documentation

- `../wallet/CLAUDE.md` - Wallet module (WalletInterface, encryption)
- `../overlay/CLAUDE.md` - Overlay module (LookupResolver, TopicBroadcaster)
- `../script/templates/CLAUDE.md` - PushDrop template
- `../CLAUDE.md` - Root SDK documentation
