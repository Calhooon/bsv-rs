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
| `mod.rs` | Module root with re-exports and documentation | ~120 |
| `types.rs` | Core types (Config, Entry, Token, Query, Options, KvProtocolFields) | ~787 |
| `local.rs` | LocalKVStore implementation with MockWallet tests | ~1379 |
| `global.rs` | GlobalKVStore implementation with SyncHistorian history building | ~760 |
| `interpreter.rs` | PushDrop token interpreter, KVStoreFields, signature verification | ~573 |

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
- **Wallet basket**: Entries stored in a namespaced basket (protocol_id)
- **Tag-based lookup**: Keys stored as tags for efficient retrieval
- **Atomic operations**: Per-key locking prevents concurrent conflicts
- **Validation**: Empty keys, values, and protocol_id are rejected

### Methods

```rust
impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    /// Create a new LocalKVStore (returns error if protocol_id is empty)
    pub fn new(wallet: W, config: KVStoreConfig) -> Result<Self>;

    /// Get a value by key (returns default_value if not found)
    /// Matches Go SDK signature: Get(ctx, key, defaultValue string) (string, error)
    pub async fn get(&self, key: &str, default_value: &str) -> Result<String>;

    /// Get full entry with metadata (returns None if not found)
    pub async fn get_entry(
        &self,
        key: &str,
        options: Option<KVStoreGetOptions>,
    ) -> Result<Option<KVStoreEntry>>;

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
- **PushDrop tokens**: Entries stored as on-chain tokens with field layout
- **Signature verification**: Entries signed by controller, verified on retrieval
- **Tag filtering**: Query by tags with "all" or "any" mode
- **Network presets**: Supports Mainnet and Testnet configurations
- **Cached identity key**: Controller pubkey cached via `Arc<Mutex<Option<String>>>`
- **History building**: Uses `SyncHistorian` to traverse transaction ancestry for entry history
- **Overlay broadcast**: Broadcasts tokens via `TopicBroadcaster`

### Methods

```rust
impl<W: WalletInterface> GlobalKVStore<W> {
    /// Create a new GlobalKVStore (uses default Mainnet network)
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

| Index | Constant | Field | Description |
|-------|----------|-------|-------------|
| 0 | `PROTOCOL_ID` | Protocol ID | String identifier (e.g., "kvstore") |
| 1 | `KEY` | Key | The key string |
| 2 | `VALUE` | Value | The value (plaintext for global, encrypted for local) |
| 3 | `CONTROLLER` | Controller | 33-byte compressed public key |
| 4 | `TAGS` | Tags | JSON array of tag strings (optional, new format) |
| 5 | `SIGNATURE` | Signature | Controller's signature over fields 0-4 |

### Field Constants (KvProtocolFields)

```rust
pub struct KvProtocolFields;

impl KvProtocolFields {
    pub const PROTOCOL_ID: usize = 0;
    pub const KEY: usize = 1;
    pub const VALUE: usize = 2;
    pub const CONTROLLER: usize = 3;
    pub const TAGS: usize = 4;
    pub const SIGNATURE: usize = 5;
    pub const MIN_FIELDS_OLD: usize = 5;  // Old format without tags
    pub const MIN_FIELDS_NEW: usize = 6;  // New format with tags
}
```

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
    /// Whether to encrypt values (LocalKVStore only, default: true)
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
    pub fn with_protocol_id(self, protocol_id: impl Into<String>) -> Self;
    pub fn with_tags(self, tags: Vec<String>) -> Self;
    pub fn with_tag_query_mode(self, mode: impl Into<String>) -> Self;
    pub fn with_limit(self, limit: u32) -> Self;
    pub fn with_skip(self, skip: u32) -> Self;
    pub fn with_sort_order(self, order: impl Into<String>) -> Self;
    pub fn to_json(&self) -> serde_json::Value;
}
```

## Interpreter

The `KVStoreInterpreter` extracts entries from PushDrop scripts. Signature verification
uses a cached `ProtoWallet::anyone()` via `OnceLock` for efficient repeated verification.

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

    /// Verify signature of a KVStore token
    /// Uses ProtoWallet::anyone() with SecurityLevel::App protocol
    /// Returns true if signature is valid, false if invalid/missing
    pub fn verify_signature(fields: &KVStoreFields, protocol_id: &str) -> bool;

    /// Extract just the value
    pub fn extract_value(script: &LockingScript) -> Option<String>;

    /// Check if script is a KVStore token
    pub fn is_kvstore_token(script: &LockingScript) -> bool;

    /// Extract all raw fields
    pub fn extract_fields(script: &LockingScript) -> Option<KVStoreFields>;
}
```

### KVStoreFields

Raw field data extracted from a KVStore token:

```rust
pub struct KVStoreFields {
    pub protocol_id: Vec<u8>,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub controller: Vec<u8>,
    pub tags: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub locking_public_key: PublicKey,
}

impl KVStoreFields {
    pub fn protocol_id_string(&self) -> Option<String>;
    pub fn key_string(&self) -> Option<String>;
    pub fn value_string(&self) -> Option<String>;
    pub fn value_bytes(&self) -> &[u8];
    pub fn controller_hex(&self) -> String;
    pub fn tags_vec(&self) -> Vec<String>;
    pub fn has_tags(&self) -> bool;
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
    let store = LocalKVStore::new(wallet, config)?;  // Note: returns Result

    // Set a value
    let outpoint = store.set("user:name", "Alice", None).await?;
    println!("Stored at: {}", outpoint);

    // Get a value with default
    let name = store.get("user:name", "Unknown").await?;
    println!("Name: {}", name);

    // Get full entry with metadata
    if let Some(entry) = store.get_entry("user:name", None).await? {
        println!("Entry: {} = {}", entry.key, entry.value);
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

// LocalKVStore creation can fail
match LocalKVStore::new(wallet, config) {
    Ok(store) => { /* use store */ }
    Err(Error::KvStoreEmptyContext) => println!("Protocol ID cannot be empty"),
    Err(e) => println!("Failed to create store: {}", e),
}

// Operations validate keys and values
match store.set("", "value", None).await {
    Err(Error::KvStoreInvalidKey) => println!("Key cannot be empty"),
    _ => {}
}

match store.set("key", "", None).await {
    Err(Error::KvStoreInvalidValue) => println!("Value cannot be empty"),
    _ => {}
}

// General error handling
match store.get("key", "default").await {
    Ok(value) => println!("Value: {}", value),
    Err(Error::KvStoreError(msg)) => println!("Store error: {}", msg),
    Err(Error::KvStoreKeyNotFound(key)) => println!("Key not found: {}", key),
    Err(Error::KvStoreCorruptedState(msg)) => println!("Corrupted: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## Internal Design

### Per-Key Locking

Both `LocalKVStore` and `GlobalKVStore` implement per-key atomic locking using `tokio::sync::oneshot` channels
to prevent concurrent modifications to the same key. Operations acquire a lock before mutating and release
it after completion.

### Signature Verification

`GlobalKVStore` verifies token signatures on retrieval. The verification:
1. Concatenates fields 0-4 (protocol_id + key + value + controller + optional tags)
2. Uses `SecurityLevel::App` protocol with key_id `"kvstore-token"`
3. Verifies via `ProtoWallet::anyone()` with `Counterparty::Other(controller_pubkey)`

### History Building

`GlobalKVStore` uses the overlay module's `SyncHistorian` to traverse transaction input ancestry
and extract all previous values for a key/protocol combination, returned in chronological order (oldest first).

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

### Go SDK Method Compatibility

The `LocalKVStore::get()` method signature matches the Go SDK:
```go
// Go SDK
func (l *LocalKVStore) Get(ctx context.Context, key, defaultValue string) (string, error)
```
```rust
// Rust SDK
pub async fn get(&self, key: &str, default_value: &str) -> Result<String>
```

## Related Documentation

- `../wallet/CLAUDE.md` - Wallet module (WalletInterface, encryption)
- `../overlay/CLAUDE.md` - Overlay module (LookupResolver, TopicBroadcaster)
- `../script/templates/CLAUDE.md` - PushDrop template
- `../CLAUDE.md` - Root SDK documentation
