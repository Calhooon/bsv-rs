//! BSV-specific cryptographic operations.
//!
//! This module provides transaction signature operations for the BSV blockchain.
//!
//! # Modules
//!
//! - [`sighash`] - Sighash computation (BIP-143 style)
//! - [`tx_signature`] - Transaction signatures with sighash scope
//! - [`key_derivation`] - Key derivation utilities (placeholder)
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_primitives::bsv::sighash::{compute_sighash, parse_transaction, SighashParams};
//! use bsv_primitives::bsv::sighash::{SIGHASH_ALL, SIGHASH_FORKID};
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

pub mod key_derivation;
pub mod sighash;
pub mod tx_signature;

// Re-export commonly used items
pub use sighash::{
    build_sighash_preimage, compute_sighash, compute_sighash_for_signing, compute_sighash_from_raw,
    parse_transaction, RawTransaction, SighashParams, TxInput, TxOutput, SIGHASH_ALL,
    SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
pub use tx_signature::TransactionSignature;
