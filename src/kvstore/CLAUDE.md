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
| `mod.rs` | Module root with re-exports and documentation | 123 |
| `types.rs` | Core types (Config, Entry, Token, Query, Options, KvProtocolFields, TTL encoding) | 787 |
| `local.rs` | LocalKVStore with single-attempt mutations; tests in local_tests.rs | 534 |
| `global.rs` | GlobalKVStore implementation with SyncHistorian history building | 619 |
| `bound.rs`, `bound/action.rs`, `bound/checks.rs` | Shared owned create/sign boundary: request and signer binding, result validation, carried options and abort (#341/#342) | 50 / 177 / 204 |
| `global_actions.rs` | #343: exact authenticated namespace, merged token BEEF, reference writer; #340: one replacement script and fresh selection on each shared-rule retry | 239 |
| `local_actions.rs` | #343: replace/remove every listed token; #340: one attempt per removal batch; #479: refuse an empty page under a positive total, a stated reference divergence | 169 |
| `token_spends.rs` | #343: unique outpoint inputs and BEEF merge; source-specific wallet PushDrop signatures after binding | 141 |
| `action_options.rs` | Private broadcast configuration, set by additive store builders; the reference's per-store createAction options (#342) | 20 |
| `local_tests.rs` | Local store unit tests, separated from production code; writer-built wallet transactions | 730 |
| `interpreter.rs` | PushDrop token interpreter, KVStoreFields; #344 separates the five/six-field forms, validates tags in reference order, and authenticates the reference writer's JSON protocol/key-ID form; the older raw-protocol form retained | 629 |
| `local_lookup.rs` | Local output limit/total checks, exact BEEF and canonical token authentication (#454) | 301 |
| `local_token.rs` | Signed local value envelopes, matching PushDrop.lock (#454) | 46 |
| `local_list.rs` | Existing convenience listing, separated to keep functions below the size limit | 78 |

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
- **TTL support**: Optional time-to-live with client-side expiration
- **Batch operations**: `batch_get`, `batch_set`, `batch_remove` for multi-key operations

### Methods

```rust
impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    /// Create a new LocalKVStore (returns error if protocol_id is empty)
    pub fn new(wallet: W, config: KVStoreConfig) -> Result<Self>;

    /// Set acceptDelayedBroadcast (default: false)
    pub fn with_accept_delayed_broadcast(self, accept: bool) -> Self;

    /// Get a value by key (returns default_value if not found or TTL-expired)
    /// Matches Go SDK signature: Get(ctx, key, defaultValue string) (string, error)
    pub async fn get(&self, key: &str, default_value: &str) -> Result<String>;

    /// Get full entry with metadata (returns None if not found or TTL-expired)
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

    /// Get multiple values by key (None for missing keys)
    pub async fn batch_get(&self, keys: &[&str]) -> Result<Vec<Option<String>>>;

    /// Set multiple key-value pairs sequentially
    pub async fn batch_set(&self, entries: &[(&str, &str)]) -> Result<()>;

    /// Remove multiple key-value pairs sequentially
    pub async fn batch_remove(&self, keys: &[&str]) -> Result<()>;

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
- **Batch operations**: `batch_get`, `batch_set`, `batch_remove` for multi-key operations

### Methods

```rust
impl<W: WalletInterface> GlobalKVStore<W> {
    /// Create a new GlobalKVStore (uses default Mainnet network)
    pub fn new(wallet: W, config: KVStoreConfig) -> Self;

    /// Create with custom network preset
    pub fn with_network(wallet: W, config: KVStoreConfig, network: NetworkPreset) -> Self;

    /// Set acceptDelayedBroadcast (default: false)
    pub fn with_accept_delayed_broadcast(self, accept: bool) -> Self;

    /// Set noSend, the reference's overlayBroadcast setting (default: false)
    pub fn with_no_send(self, no_send: bool) -> Self;

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

    /// Get multiple values by key (None for missing keys)
    pub async fn batch_get(&self, keys: &[&str]) -> Result<Vec<Option<KVStoreEntry>>>;

    /// Set multiple key-value pairs sequentially
    pub async fn batch_set(&self, entries: &[(&str, &str)]) -> Result<()>;

    /// Remove multiple key-value pairs sequentially
    pub async fn batch_remove(&self, keys: &[&str]) -> Result<()>;
}
```

## PushDrop Token Format

Global entries use PushDrop tokens with the following field layout:

| Index | Constant | Field | Description |
|-------|----------|-------|-------------|
| 0 | `PROTOCOL_ID` | Protocol ID | Reference: JSON wallet protocol (e.g., `[1,"kvstore"]`); older crate tokens: raw name |
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

Both formats are supported. With five fields, field 4 is only the signature;
with six, field 4 is a JSON array of tags and field 5 the signature (#344).
A present tag array has at most 32 strings, each 1 to 256 UTF-8 bytes and
unique. Array/count is checked first, then each element's type/length before
its uniqueness (`kvStoreTokenValidation.ts:58-74,88-118`, ts-stack@edf6e03).
The refusal words are `KVStore tags must be a bounded array`,
`KVStore tag has an invalid length`, and `KVStore tags must be unique`.
The store and interpreter skip refused tokens. No tags means an absent
field, distinct from a present, signed `[]`; both read successfully.
`tests/kvstore_untagged_token_344.rs` and the interpreter unit
`malformed_reference_token_tags_use_the_reference_words_and_order` replay
`kvstore_tags_344.json`, recorded by the extended #326 reference writer.

Since #454 the local store writes the reference's two-field layout: value
and its signature, in a canonical PushDrop under `Protocol(Counterparty, name)`
with key ID equal to the key and counterparty self. Wallet metadata carries
`[key]` for lookup. The convenience `list` still uses the public token
interpreter and does not list these local tokens, a pre-existing behavior.
Payload tags belong to the public five/six-field token, not wallet metadata.

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
    /// Originator for wallet operations; `None` passes no originator to the
    /// wallet (`"kvstore"` until #329), as the reference's `originator?`
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

Broadcast settings are private store configuration, exposed through
`LocalKVStore::with_accept_delayed_broadcast`,
`GlobalKVStore::with_accept_delayed_broadcast` and `GlobalKVStore::with_no_send`.
Each takes a `bool` and returns `Self`; both options default to `false`.
`KVStoreConfig` keeps its existing public shape, including exhaustive literals.
Migration: none; additive.

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

## TTL (Time-to-Live) Support

LocalKVStore supports optional TTL on entries via `KVStoreSetOptions::with_ttl()`. TTL is enforced client-side; on-chain data remains immutable.

### How It Works

1. When `ttl` is set, the value is wrapped in a JSON envelope: `{"v":"<value>","e":<unix_ts>}`
2. On `get()` / `get_entry()`, the envelope is decoded and the expiration timestamp is checked
3. Expired entries return the default value (for `get()`) or `None` (for `get_entry()`)

### Internal Functions

```rust
// Encode a value with expiration timestamp
pub(crate) fn encode_value_with_ttl(value: &str, ttl: Duration) -> String;

// Decode a potentially TTL-wrapped value, returns (value, is_expired)
pub(crate) fn decode_value_with_ttl(stored: &str) -> (String, bool);
```

### Usage

```rust
use std::time::Duration;
use bsv_rs::kvstore::{LocalKVStore, KVStoreConfig, KVStoreSetOptions};

let opts = KVStoreSetOptions::new()
    .with_ttl(Duration::from_secs(3600)); // Expires in 1 hour
store.set("session", "token_abc", Some(opts)).await?;

// After 1 hour, get() returns default_value
let val = store.get("session", "expired").await?;
```

## Operation Options

```rust
pub struct KVStoreSetOptions {
    pub protocol_id: Option<String>,     // Override protocol ID
    pub description: Option<String>,     // Operation description
    pub token_amount: Option<u64>,       // Token amount override
    pub tags: Option<Vec<String>>,       // Tags to attach
    pub ttl: Option<std::time::Duration>, // Time-to-live (client-side expiration)
}

pub struct KVStoreGetOptions {
    pub history: bool,                   // Include full history chain
    pub include_token: bool,             // Include token data in result
    pub service_name: Option<String>,    // Override service name
}

pub struct KVStoreRemoveOptions {
    pub protocol_id: Option<String>,     // Override protocol ID
    pub description: Option<String>,     // Operation description
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
use bsv_rs::kvstore::{LocalKVStore, KVStoreConfig};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::primitives::PrivateKey;

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

### Batch Operations

```rust
use bsv_rs::kvstore::{LocalKVStore, KVStoreConfig};

// Batch set multiple values
let entries = vec![("key1", "value1"), ("key2", "value2"), ("key3", "value3")];
store.batch_set(&entries).await?;

// Batch get (returns Vec<Option<String>>)
let values = store.batch_get(&["key1", "key2", "missing"]).await?;
// values[0] = Some("value1"), values[2] = None

// Batch remove
store.batch_remove(&["key1", "key2"]).await?;
```

### TTL (Time-to-Live)

```rust
use std::time::Duration;
use bsv_rs::kvstore::KVStoreSetOptions;

// Set with 5-minute TTL
let opts = KVStoreSetOptions::new()
    .with_ttl(Duration::from_secs(300));
store.set("session:token", "abc123", Some(opts)).await?;

// Value is available immediately
let val = store.get("session:token", "").await?;
assert_eq!(val, "abc123");

// After 5 minutes, get() returns the default value
// let val = store.get("session:token", "expired").await?;
// assert_eq!(val, "expired");
```

### GlobalKVStore with Tags

```rust
use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreSetOptions, KVStoreQuery};
use bsv_rs::wallet::ProtoWallet;

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
use bsv_rs::kvstore::KVStoreConfig;

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
use bsv_rs::Error;

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

### Bound actions (#326, #341, #342)

Both stores call `bound::complete_with_signers` through `token_spends::complete_token_action` for set and removal. It owns the
request before createAction, validates the signable reference and atomic BEEF,
binds version, lock time, requested input outpoints/sequences/scripts, requested
outputs and values, then maps token signers onto those input indexes. Wallet
funding inputs receive no token signer. The signed transaction must preserve
the template and authorized scripts and agree with any returned txid. The
validated signed result supplies the stores' result; failures after accepting
a reference abort best-effort. Rust ownership replaces the reference's dynamic
property snapshots and shared-JavaScript-intrinsics checks.

`action_options` keeps broadcast settings private on each store and sends the
reference's false defaults for `acceptDelayedBroadcast` (set through
`with_accept_delayed_broadcast`) and global `noSend` (the reference's
`overlayBroadcast`, set through `with_no_send`), with
`randomizeOutputs: false` except on local removal. The boundary forces
`signAndProcess: false` and `returnTXIDOnly: false`; `bound_sign_options` carries
the same create options into signAction, including `sendWith` if present.
The reference text is re-encoded as canonical base64 (#326).

Since #343 the stores sign each token's source script and satoshis through its
wallet protocol, binding signers by outpoint even when the wallet reorders
inputs. Global set and remove collect every authenticated token for the exact
key/controller/JSON protocol namespace and merge their BEEFs. The global
writer uses that protocol and key for its locking key and field signature.
Raw-protocol tokens remain readable but are outside that mutation namespace.
Local set/remove authenticate every listed output against its exact BEEF and wallet key;
the same-value shortcut requires one output. Since #454 mutation listings request
10,000 outputs, set rejects incomplete totals and remove follows the reported total.
Reads reject multiple outputs, including a second output hidden beyond the returned page. The untagged-token reader is
fixed by #344. Pinned by `tests/kvstore_tokens_343.rs` (eleven tests),
`tests/kvstore_signaction_326.rs`,
`tests/kvstore_bound_action_341_342.rs`, `tests/kvstore_options_342.rs` and the
unused-signer unit test; the reference's calls and refusals are recorded by
`tests/support/signaction_reference_326.mjs --bound-actions` under Node 22.

### Wallet double-spend retry (#340)

`overlay::wallet_retry::with_wallet_double_spend_retry` is the single internal
rule used by revocation and the global store: five attempts at most for
structured wallet double-spend evidence, each retry after acknowledgment of
the competing transactions. Global set and remove repeat lookup and input
selection inside the key lock, aborting the failed reference before obtaining
another. `GlobalKVStore::with_broadcaster` supplies an injectable broadcaster
for synchronization and completed broadcasts; its default uses the configured
topics and network.

The local store does not retry, as the reference's does not. Local set makes
one bound action; local removal makes one bound action per batch and stops on
failure. Neither has a broadcaster. Both retain the per-key lock and the bound
action's abort on failure.

The helper's TypeScript home is `overlay-tools/withDoubleSpendRetry.ts`, not
`wallet/completeBoundAction.ts`. At `edf6e03`, global set/remove wrap their
lookup and bound action; local set/remove call the boundary without retry.
Go's `kvstore/local_kv_store.go` at `2ca481c` also does not retry a double spend.
`tests/kvstore_double_spend_retry_340.rs` has eleven cases using the #326
recording wallet: four local single-attempt cases fail on the retrying
`dd0a4a59` tree, and the global retry and non-retry controls remain pinned.
The #340 Node 22 recording retains its eight cases and adds three #470 count/key
witnesses. Local bound-action failures now return `KvStoreLocalError` with the
reference wrapper: set uses the authenticated count, remove the reported total.
The wrapper tests and abort checks are in `kvstore_local_error_470.rs`. Migration:
no published public item moved; the removed local `with_broadcaster` was
unreleased, the global builder remains additive, and config literals are
unchanged.

### Per-Key Locking

Both `LocalKVStore` and `GlobalKVStore` implement per-key atomic locking using `tokio::sync::oneshot` channels
to prevent concurrent modifications to the same key. Operations acquire a lock before mutating and release
it after completion.

### Local lookup and wallet signing (#454, #470)

`LocalKVStore.ts:173-370,455,574-590` at edf6e03 is the local lookup rule:
10,000 outputs for mutations, read ambiguity by both length and total, every
listed output authenticated against the exact BEEF transaction and index,
metadata, canonical two-field envelope, the wallet's `[2, context]` key and
signature over the value. Duplicate outpoints fail. An optional listed script
may be absent; the authenticated script comes from BEEF. Lookup failures are
wrapped for get/set, direct for remove. Bound-action failures carry the count/key
wrapper in `LocalKVStore.ts:427-431,547-551`, distinct from lookup failures.

All wallet PushDrop unlockers call `wallet::pushdrop::sign`, which sends
`data: SHA256(preimage)` (`PushDrop.ts:234-258`); the wallet hashes once more.
`kvstore_two_token_454.rs` compares four recorded local/global actions: input
text, merged BEEF, every unlocking script and each signature request.
`kvstore_local_454.rs` pins pagination and authentication. Go at `2ca481c`,
`kvstore/local_kv_store.go:66-171,228,436,518`, keeps last-output decoding,
10/100 limits and different error wrappers; TypeScript decides this behavior.
Migration: additive `Error::KvStoreLocalError`; callers matching bare wallet
errors must handle the wrapped text. Public store/config paths are unchanged.

### Empty removal page (#479)

By the keeper's word (00:1xZ), removal ends on the first empty page under a
positive total, where `ts-stack@edf6e03` `LocalKVStore.ts:574-590` loops. It uses
the local store's `Error::KvStoreLocalError` with its own words:
`Wallet returned an inconsistent KVStore output list: totalOutputs is 7, but
page at offset 0 is empty for key alpha`. The total and key vary; the offset is
the requested page's zero (omitted on every request), not a consumed count.
Earlier spends remain spent, but the operation returns an error, not partial
success. The Node 22 witness is `{ totalOutputs: 7, outputs: [] }`.
Local set (`:173-203,329-339,455`) reads once and cannot loop this way; global
lookup (`GlobalKVStore.ts:583-604`) reads no total and makes one query. Both stay
unchanged, as do consistent-wallet requests and #454 vectors. The four tests in
`tests/kvstore_local_empty_page_479.rs` pin first-empty and post-spend refusals
(one-second timeouts on the base), two-page removal and zero-total success.
Migration: handle the new refusal in the existing variant; no API additions.

### Signature Verification

`GlobalKVStore` verifies token signatures on retrieval. The verification:
1. Concatenates fields 0-4 (protocol_id + key + value + controller + optional tags)
2. For the reference writer's JSON protocol, uses that wallet protocol and
   the token's key as key ID, checking the derived locking key first (#344).
   The older raw protocol form written by this crate retains
   `SecurityLevel::App` with key ID `"kvstore-token"`.
3. Verifies via `ProtoWallet::anyone()` with `Counterparty::Other(controller_pubkey)`.
   All present fields preceding the signature are signed, including `[]`.

The reference form is also authenticated by `interpret_script` for history.
A string context names an App protocol, matching the reference's `[1, name]`;
the default `kvstore` configuration reads the reference's `[1,"kvstore"]`.
The raw-protocol form keeps the historical extraction-only history behavior.
The reference's other canonical PushDrop/protocol/value/controller checks and its
controller context are not fully implemented here; see #344's parity note.

### History Building

`GlobalKVStore` uses the overlay module's `SyncHistorian` to traverse transaction input ancestry
and extract all previous values for a key/protocol combination, returned in chronological order (oldest first).

### TTL Encoding

TTL values are stored as JSON envelopes wrapping the original value: `{"v":"<value>","e":<expiry_unix_ts>}`.
On read, `decode_value_with_ttl()` transparently checks expiration. Plain (non-TTL) values pass through unchanged.
Expiration is client-side only; on-chain data remains immutable.

## Feature Flag

Enable the kvstore feature in `Cargo.toml`:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["kvstore"] }
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
