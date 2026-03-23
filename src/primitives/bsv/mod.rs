//! BSV-specific cryptographic operations.
//!
//! This module provides transaction signature operations, Schnorr proofs,
//! and Shamir Secret Sharing for the BSV blockchain.
//!
//! # Modules
//!
//! - [`sighash`] - Sighash computation (BIP-143 style)
//! - [`tx_signature`] - Transaction signatures with sighash scope
//! - [`schnorr`] - Schnorr zero-knowledge proofs for ECDH
//! - [`polynomial`] - Polynomial operations for Shamir Secret Sharing
//! - [`shamir`] - Shamir Secret Sharing for private key backup
//!
//! # Example: Sighash Computation
//!
//! ```rust,ignore
//! use bsv_rs::primitives::bsv::sighash::{compute_sighash, parse_transaction, SighashParams};
//! use bsv_rs::primitives::bsv::sighash::{SIGHASH_ALL, SIGHASH_FORKID};
//!
//! // Parse a raw transaction
//! let raw_tx = hex::decode("0100000001...").unwrap();
//! let tx = parse_transaction(&raw_tx).unwrap();
//!
//! // Compute sighash for input 0
//! let subscript = hex::decode("76a914...88ac").unwrap();
//! let sighash = compute_sighash(&SighashParams {
//!     version: tx.version,
//!     inputs: &tx.inputs,
//!     outputs: &tx.outputs,
//!     locktime: tx.locktime,
//!     input_index: 0,
//!     subscript: &subscript,
//!     satoshis: 100000,
//!     scope: SIGHASH_ALL | SIGHASH_FORKID,
//! });
//! ```
//!
//! # Example: Shamir Secret Sharing
//!
//! ```rust
//! use bsv_rs::primitives::bsv::shamir::{split_private_key, KeyShares};
//! use bsv_rs::primitives::ec::PrivateKey;
//!
//! // Generate a random private key
//! let key = PrivateKey::random();
//!
//! // Split into 5 shares with threshold of 3
//! let shares = split_private_key(&key, 3, 5).unwrap();
//!
//! // Export to backup format for storage
//! let backup = shares.to_backup_format();
//!
//! // Later, recover from any 3 shares
//! let subset = KeyShares::from_backup_format(&backup[0..3]).unwrap();
//! let recovered = subset.recover_private_key().unwrap();
//!
//! assert_eq!(key.to_bytes(), recovered.to_bytes());
//! ```

pub mod polynomial;
pub mod schnorr;
pub mod shamir;
pub mod sighash;
pub mod tx_signature;

// Re-export commonly used items
pub use polynomial::{PointInFiniteField, Polynomial};
pub use schnorr::{Schnorr, SchnorrProof};
pub use shamir::{split_private_key, KeyShares};
pub use sighash::{
    build_sighash_preimage, compute_sighash, compute_sighash_for_signing, compute_sighash_from_raw,
    parse_transaction, RawTransaction, SighashParams, TxInput, TxOutput, SIGHASH_ALL,
    SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
pub use tx_signature::TransactionSignature;
