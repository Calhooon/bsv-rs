//! # BSV SDK Compatibility Module
//!
//! This module provides compatibility implementations for various Bitcoin standards
//! that are commonly used but not part of the core BSV protocol.
//!
//! ## Submodules
//!
//! - **base58**: Base58 encoding/decoding (Bitcoin alphabet)
//! - **bip32**: BIP-32 Hierarchical Deterministic (HD) key derivation
//! - **bip39**: BIP-39 mnemonic phrase generation and seed derivation
//! - **bsm**: Bitcoin Signed Message signing and verification
//! - **ecies**: ECIES encryption (Electrum and Bitcore variants)

pub mod base58;
pub mod bip32;
pub mod bip39;
pub mod bsm;
pub mod ecies;

// Re-exports for convenience
pub use bip32::{ExtendedKey, Network, HARDENED_KEY_START};
pub use bip39::{Language, Mnemonic, WordCount};
