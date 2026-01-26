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
