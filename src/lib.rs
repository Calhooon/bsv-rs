//! # bsv-rs
//!
//! A Rust SDK for BSV: cryptographic primitives, the Bitcoin Script
//! interpreter, transactions with BEEF/SPV, BRC-42 wallets, BRC-103 mutual
//! authentication, and the overlay network (SHIP/SLAP/STEAK), with storage,
//! registry, key-value and identity clients on top. It is a reference-parity
//! port of the TypeScript `@bsv/sdk` (cross-checked against the Go SDK),
//! pinned by shared test vectors and the `ts-stack` conformance corpus, and it
//! builds for `wasm32-unknown-unknown` (Cloudflare Workers, browsers).
//!
//! The README (`README.md`) is the guide: every code block in it is a file
//! under `examples/` that CI compiles. Each module carries its own docs.
//!
//! ## Feature flags
//!
//! `default = ["primitives", "script"]`. Opt in per module: `transaction`,
//! `wallet`, `messages`, `compat`, `totp`, `auth`, `overlay`, `storage`,
//! `registry`, `kvstore`, `identity`, `socketio`; `full` turns every module
//! on. Transports and platforms: `http` (reqwest: ARC, WhatsOnChain, the
//! HTTP wallet substrate, overlay hosts), `websocket` (a tokio-tungstenite
//! auth transport, opt-in), `wasm` (the JS RNG, runtime-agnostic timers,
//! `js_sys::Date` for wall-clock reads).
//!
//! ## Quick start
//!
//! ```rust
//! use bsv_rs::primitives::{sha256, PrivateKey};
//!
//! let private_key = PrivateKey::random();
//! let public_key = private_key.public_key();
//! let digest = sha256(b"Hello, BSV!");
//! let signature = private_key.sign(&digest).unwrap();
//! assert!(public_key.verify(&digest, &signature));
//! ```

// Error types (shared across modules)
pub mod error;
pub use error::{Error, Result};

// Internal utilities (wasm32-safe time helpers, etc.). Not part of the
// public API — see `src/util/mod.rs`.
pub(crate) mod util;

// Feature-gated modules
#[cfg(feature = "primitives")]
pub mod primitives;

#[cfg(feature = "script")]
pub mod script;

#[cfg(feature = "transaction")]
pub mod transaction;

#[cfg(feature = "wallet")]
pub mod wallet;

#[cfg(feature = "messages")]
pub mod messages;

#[cfg(feature = "compat")]
pub mod compat;

#[cfg(feature = "totp")]
pub mod totp;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "overlay")]
pub mod overlay;

#[cfg(feature = "storage")]
pub mod storage;

#[cfg(feature = "registry")]
pub mod registry;

#[cfg(feature = "kvstore")]
pub mod kvstore;

#[cfg(feature = "identity")]
pub mod identity;

// Convenience re-exports from primitives (most common items)
#[cfg(feature = "primitives")]
pub use primitives::{
    from_hex, hash160, sha256, sha256d, to_hex, BigNumber, PrivateKey, PublicKey, Signature,
    SymmetricKey,
};

// Convenience re-exports from script
#[cfg(feature = "script")]
pub use script::{Address, LockingScript, Script, ScriptChunk, UnlockingScript};

// Convenience re-exports from transaction
#[cfg(feature = "transaction")]
pub use transaction::{ChangeDistribution, Transaction, TransactionInput, TransactionOutput};

// Convenience re-exports from wallet
#[cfg(feature = "wallet")]
pub use wallet::{
    CacheConfig, CachedKeyDeriver, Counterparty, KeyDeriver, KeyDeriverApi, ProtoWallet, Protocol,
    SecurityLevel,
};

// Convenience re-exports from messages
#[cfg(feature = "messages")]
pub use messages::{decrypt, encrypt, sign, verify};

// Convenience re-exports from compat
#[cfg(feature = "compat")]
pub use compat::{Language, Mnemonic, WordCount};

// Convenience re-exports from totp
#[cfg(feature = "totp")]
pub use totp::{Algorithm as TotpAlgorithm, Totp, TotpOptions, TotpValidateOptions};

// Convenience re-exports from auth
#[cfg(feature = "socketio")]
pub use auth::{
    install_app_event_listener, run_dispatch, AppEvent, SocketIoFrameSource, SocketIoSink,
    SocketIoTransport,
};
#[cfg(feature = "auth")]
pub use auth::{
    AuthMessage, Certificate, MasterCertificate, MessageType, Peer, PeerOptions, PeerSession,
    RequestedCertificateSet, SessionManager, SimplifiedFetchTransport, Transport,
    VerifiableCertificate,
};
#[cfg(feature = "websocket")]
pub use auth::{WebSocketTransport, WebSocketTransportOptions};

// Convenience re-exports from overlay
#[cfg(feature = "overlay")]
pub use overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, NetworkPreset, Steak, TaggedBEEF,
    TopicBroadcaster,
};
// Note: overlay::Protocol is separate from wallet::Protocol

// Convenience re-exports from storage
#[cfg(feature = "storage")]
pub use storage::{
    get_hash_from_url, get_url_for_file, is_valid_url, DownloadResult, StorageDownloader,
    StorageUploader, UploadFileResult, UploadableFile,
};

// Convenience re-exports from registry
#[cfg(feature = "registry")]
pub use registry::{
    BasketDefinitionData, BasketQuery, BroadcastFailure, BroadcastSuccess,
    CertificateDefinitionData, CertificateFieldDescriptor, CertificateQuery, DefinitionData,
    DefinitionType, ProtocolDefinitionData, ProtocolQuery, RegisterDefinitionResult,
    RegistryClient, RegistryClientConfig, RegistryRecord, RevokeDefinitionResult, TokenData,
};

// Convenience re-exports from kvstore
#[cfg(feature = "kvstore")]
pub use kvstore::{
    GlobalKVStore, KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreQuery,
    KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken, LocalKVStore,
};

// Convenience re-exports from identity
#[cfg(feature = "identity")]
pub use identity::{
    Contact, ContactsManager, ContactsManagerConfig, DisplayableIdentity, IdentityClient,
    IdentityClientConfig, IdentityQuery, KnownCertificateType,
};
