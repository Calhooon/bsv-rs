//! # BIP-39 Mnemonic Phrases
//!
//! Implementation of BIP-39 mnemonic code for generating deterministic keys.
//!
//! BIP-39 describes the implementation of a mnemonic code or mnemonic sentence -
//! a group of easy-to-remember words - for the generation of deterministic wallets.
//!
//! ## Features
//!
//! - Generate random mnemonic phrases (12, 15, 18, 21, or 24 words)
//! - Create mnemonics from entropy bytes
//! - Parse and validate existing mnemonic phrases
//! - Convert mnemonics to 512-bit seeds with optional passphrase
//! - Extract entropy from valid mnemonics
//!
//! ## Example
//!
//! ```rust
//! use bsv_sdk::compat::bip39::{Mnemonic, WordCount};
//!
//! // Generate a new 12-word mnemonic
//! let mnemonic = Mnemonic::new(WordCount::Words12).unwrap();
//! println!("Mnemonic: {}", mnemonic.phrase());
//!
//! // Convert to seed with passphrase
//! let seed = mnemonic.to_seed("my passphrase");
//! assert_eq!(seed.len(), 64);
//!
//! // Parse an existing mnemonic
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let mnemonic = Mnemonic::from_phrase(phrase).unwrap();
//! assert!(mnemonic.is_valid());
//! ```
//!
//! ## Specification
//!
//! See <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>

mod mnemonic;
pub mod wordlists;

pub use mnemonic::{Language, Mnemonic, WordCount};
pub use wordlists::verify_english_wordlist;
