//! # BSV SDK
//!
//! A comprehensive Rust SDK for building BSV (Bitcoin SV) applications.
//! Feature-complete and production-ready.
//!
//! ## Modules
//!
//! - **primitives**: Cryptographic primitives (hash, EC, encoding, AES-256-GCM)
//! - **script**: Bitcoin Script parsing, execution, and templates (P2PKH, RPuzzle, PushDrop)
//! - **transaction**: Transaction construction, signing, BEEF/MerklePath SPV proofs
//! - **wallet**: BRC-42 key derivation, ProtoWallet, WalletClient
//!
//! ## Feature Flags
//!
//! - `primitives` (default): Core cryptographic primitives
//! - `script` (default): Script parsing, execution, and templates
//! - `transaction`: Transaction building, signing, BEEF format, fee models
//! - `wallet`: BRC-42 key derivation, ProtoWallet, WalletClient
//! - `full`: All features
//! - `http`: HTTP client for ARC broadcaster, WhatsOnChain, WalletClient
//! - `wasm`: WebAssembly support
//!
//! ## Quick Start
//!
//! ```rust
//! use bsv_sdk::primitives::{PrivateKey, sha256};
//!
//! // Generate a key pair
//! let private_key = PrivateKey::random();
//! let public_key = private_key.public_key();
//!
//! // Hash some data
//! let hash = sha256(b"Hello, BSV!");
//!
//! // Sign a message
//! let signature = private_key.sign(&hash).unwrap();
//! assert!(public_key.verify(&hash, &signature));
//! ```

// Error types (shared across modules)
pub mod error;
pub use error::{Error, Result};

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
pub use script::{LockingScript, Script, ScriptChunk, UnlockingScript};

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
#[cfg(feature = "auth")]
pub use auth::{
    AuthMessage, Certificate, MasterCertificate, MessageType, Peer, PeerOptions, PeerSession,
    RequestedCertificateSet, SessionManager, SimplifiedFetchTransport, Transport,
    VerifiableCertificate,
};

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
