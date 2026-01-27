//! # KVStore Module
//!
//! Blockchain-backed key-value storage for BSV applications.
//!
//! This module provides two implementations of persistent key-value storage:
//!
//! - **[`LocalKVStore`]**: Private storage using wallet transactions and baskets.
//!   Values are encrypted by default and only accessible by the wallet owner.
//!
//! - **[`GlobalKVStore`]**: Public storage using the overlay network.
//!   Values are stored as PushDrop tokens and discoverable via lookup services.
//!
//! ## Features
//!
//! - **Persistent storage**: Values are stored on-chain in transaction outputs
//! - **Encryption**: LocalKVStore encrypts values using wallet-derived keys
//! - **Tagging**: Entries can be tagged for filtering and discovery
//! - **Atomic operations**: Concurrent access is serialized per key
//! - **Cross-SDK compatible**: API matches TypeScript and Go SDK implementations
//!
//! ## Quick Start
//!
//! ### LocalKVStore (Private)
//!
//! ```rust,ignore
//! use bsv_sdk::kvstore::{LocalKVStore, KVStoreConfig};
//! use bsv_sdk::wallet::ProtoWallet;
//!
//! // Create a local store with default configuration
//! let wallet = ProtoWallet::new(None);
//! let config = KVStoreConfig::default();
//! let store = LocalKVStore::new(wallet, config);
//!
//! // Set a value
//! store.set("my_key", "my_value", None).await?;
//!
//! // Get a value
//! if let Some(entry) = store.get("my_key", None).await? {
//!     println!("Value: {}", entry.value);
//! }
//!
//! // List all keys
//! let keys = store.keys().await?;
//!
//! // Remove a value
//! store.remove("my_key", None).await?;
//! ```
//!
//! ### GlobalKVStore (Public)
//!
//! ```rust,ignore
//! use bsv_sdk::kvstore::{GlobalKVStore, KVStoreConfig, KVStoreQuery};
//! use bsv_sdk::wallet::ProtoWallet;
//!
//! // Create a global store
//! let wallet = ProtoWallet::new(None);
//! let config = KVStoreConfig::default();
//! let store = GlobalKVStore::new(wallet, config);
//!
//! // Set a public value
//! store.set("public_key", "public_value", None).await?;
//!
//! // Query entries
//! let query = KVStoreQuery::new()
//!     .with_tags(vec!["important".to_string()])
//!     .with_limit(10);
//! let entries = store.query(query).await?;
//!
//! // Get entries by controller
//! let my_entries = store.get_by_controller("02abc...").await?;
//! ```
//!
//! ## PushDrop Token Format
//!
//! Global entries use PushDrop tokens with the following field layout:
//!
//! | Index | Field | Description |
//! |-------|-------|-------------|
//! | 0 | Protocol ID | String identifier (e.g., "kvstore") |
//! | 1 | Key | The key string |
//! | 2 | Value | The value (encrypted for LocalKVStore) |
//! | 3 | Controller | 33-byte compressed public key |
//! | 4 | Tags | JSON array of tag strings (optional) |
//! | 5 | Signature | Controller's signature over fields 0-4 |
//!
//! ## Configuration
//!
//! The [`KVStoreConfig`] struct controls store behavior:
//!
//! - `protocol_id`: Namespace for entries (default: "kvstore")
//! - `service_name`: Overlay lookup service (default: "ls_kvstore")
//! - `token_amount`: Satoshis per token (default: 1)
//! - `topics`: Broadcast topics (default: ["tm_kvstore"])
//! - `encrypt`: Enable encryption for LocalKVStore (default: true)
//!
//! ## Error Handling
//!
//! KVStore operations return [`crate::Result<T>`] with specific error types:
//!
//! - [`Error::KvStoreError`](crate::Error::KvStoreError): General kvstore errors
//! - [`Error::KvStoreKeyNotFound`](crate::Error::KvStoreKeyNotFound): Key doesn't exist
//! - [`Error::KvStoreCorruptedState`](crate::Error::KvStoreCorruptedState): Invalid state

pub mod global;
pub mod interpreter;
pub mod local;
pub mod types;

// Re-export main types
pub use types::{
    KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreLookupResult, KVStoreQuery,
    KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
};

// Re-export store implementations
pub use global::GlobalKVStore;
pub use local::LocalKVStore;

// Re-export interpreter types
pub use interpreter::{KVStoreContext, KVStoreFields, KVStoreInterpreter};
