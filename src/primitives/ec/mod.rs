//! Elliptic curve cryptography for secp256k1.
//!
//! This module provides ECDSA signing and verification, key derivation (BRC-42),
//! and all the elliptic curve operations needed for Bitcoin SV.
//!
//! # Overview
//!
//! - [`PrivateKey`] - A secp256k1 private key for signing and key derivation
//! - [`PublicKey`] - A secp256k1 public key for verification and addresses
//! - [`Signature`] - An ECDSA signature with DER and compact encoding
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::primitives::ec::{PrivateKey, PublicKey, Signature};
//! use bsv_sdk::primitives::hash::sha256;
//!
//! // Generate a random key pair
//! let private_key = PrivateKey::random();
//! let public_key = private_key.public_key();
//!
//! // Sign a message
//! let message = b"Hello, BSV!";
//! let msg_hash = sha256(message);
//! let signature = private_key.sign(&msg_hash).unwrap();
//!
//! // Verify the signature
//! assert!(public_key.verify(&msg_hash, &signature));
//!
//! // The signature is always low-S (BIP 62 compliant)
//! assert!(signature.is_low_s());
//! ```
//!
//! # BRC-42 Key Derivation
//!
//! ```rust
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! // Alice and Bob each have key pairs
//! let alice_priv = PrivateKey::random();
//! let bob_priv = PrivateKey::random();
//!
//! // Derive child keys using an invoice number
//! let invoice = "payment-12345";
//!
//! // Alice derives her child private key using Bob's public key
//! let alice_child = alice_priv.derive_child(&bob_priv.public_key(), invoice).unwrap();
//!
//! // Bob derives the corresponding child public key using Alice's public key
//! let bob_derived_pub = alice_priv.public_key().derive_child(&bob_priv, invoice).unwrap();
//!
//! // They arrive at the same public key
//! assert_eq!(alice_child.public_key().to_compressed(), bob_derived_pub.to_compressed());
//! ```
//!
//! # WIF Encoding
//!
//! ```rust
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! // Parse a WIF private key
//! let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
//! let key = PrivateKey::from_wif(wif).unwrap();
//!
//! // Export back to WIF
//! assert_eq!(key.to_wif(), wif);
//! ```

pub mod ecdsa;
pub mod private_key;
pub mod public_key;
pub mod signature;

pub use ecdsa::{recover_public_key, sign, verify};
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;
