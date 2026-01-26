//! # BSV SDK Compatibility Module
//!
//! This module provides compatibility implementations for various Bitcoin standards
//! that are commonly used but not part of the core BSV protocol.
//!
//! ## Submodules
//!
//! - **bip39**: BIP-39 mnemonic phrase generation and seed derivation

pub mod bip39;

// Re-exports for convenience
pub use bip39::{Language, Mnemonic, WordCount};
