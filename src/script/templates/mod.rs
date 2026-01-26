//! Script templates for common transaction types.
//!
//! This module provides high-level APIs for creating and spending common
//! Bitcoin script patterns. Templates handle the details of script construction
//! and signing, making it easy to work with standard transaction types.
//!
//! # Available Templates
//!
//! - [`P2PKH`] - Pay-to-Public-Key-Hash (most common)
//! - [`RPuzzle`] - R-Puzzle (knowledge-based locking using ECDSA K-value)
//!
//! # Example: P2PKH
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::P2PKH;
//! use bsv_sdk::script::template::{ScriptTemplate, SignOutputs, SigningContext};
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let pubkey_hash = private_key.public_key().hash160();
//!
//! // Create locking script
//! let template = P2PKH::new();
//! let locking = template.lock(&pubkey_hash)?;
//!
//! // Or from an address
//! let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
//!
//! // Create unlock and sign
//! let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);
//! let unlocking = unlock.sign(&context)?;
//! ```
//!
//! # Example: R-Puzzle
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::{RPuzzle, RPuzzleType};
//! use bsv_sdk::script::template::{ScriptTemplate, SignOutputs};
//! use bsv_sdk::primitives::ec::PrivateKey;
//! use bsv_sdk::primitives::BigNumber;
//!
//! // Generate a random K value
//! let k = BigNumber::from_bytes_be(&random_bytes);
//! let r_value = RPuzzle::compute_r_from_k(&k)?;
//!
//! // Create locking script (raw R value)
//! let template = RPuzzle::new(RPuzzleType::Raw);
//! let locking = template.lock(&r_value)?;
//!
//! // Or use hashed R value (smaller script)
//! let template = RPuzzle::new(RPuzzleType::Hash160);
//! let r_hash = bsv_sdk::primitives::hash160(&r_value);
//! let locking = template.lock(&r_hash)?;
//!
//! // Unlock using the K value
//! let private_key = PrivateKey::random();
//! let unlock = RPuzzle::unlock(&k, &private_key, SignOutputs::All, false);
//! let unlocking = unlock.sign(&context)?;
//! ```

pub mod p2pkh;
pub mod rpuzzle;

// Re-export main types
pub use p2pkh::P2PKH;
pub use rpuzzle::{RPuzzle, RPuzzleType};
