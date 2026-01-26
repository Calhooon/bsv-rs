//! # BSV SDK
//!
//! A comprehensive Rust SDK for building BSV (Bitcoin SV) applications.
//!
//! ## Modules
//!
//! - **primitives**: Cryptographic primitives (hash, EC, encoding)
//! - **script**: Bitcoin Script parsing and execution
//! - **transaction**: Transaction construction and signing (coming soon)
//! - **wallet**: HD wallets and key management (coming soon)
//!
//! ## Feature Flags
//!
//! - `primitives` (default): Core cryptographic primitives
//! - `script` (default): Script parsing and interpreter
//! - `transaction`: Transaction building and signing
//! - `wallet`: HD wallet support
//! - `full`: All features
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
