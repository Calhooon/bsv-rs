//! # BSV Primitives
//!
//! A Rust library providing cryptographic primitives for the BSV blockchain.
//!
//! This crate provides:
//! - **Hash functions**: SHA-1, SHA-256, SHA-512, RIPEMD-160, and Bitcoin-specific
//!   composite hashes (hash256, hash160)
//! - **HMAC**: HMAC-SHA256 and HMAC-SHA512
//! - **Key derivation**: PBKDF2-SHA512
//! - **Symmetric encryption**: AES-256-GCM with BSV SDK compatibility
//! - **Elliptic curve cryptography**: secp256k1, secp256r1 (Phase 5)
//! - **BSV-specific**: Transaction signatures, BRC-42 key derivation (Phase 6)
//!
//! ## Example
//!
//! ```rust
//! use bsv_primitives::hash;
//!
//! // Single hash
//! let digest = hash::sha256(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // Bitcoin double-SHA256 (hash256)
//! let double_hash = hash::sha256d(b"hello world");
//!
//! // Bitcoin hash160 (RIPEMD160(SHA256(x)))
//! let h160 = hash::hash160(b"hello world");
//! assert_eq!(h160.len(), 20);
//! ```
//!
//! ## Symmetric Encryption
//!
//! ```rust
//! use bsv_primitives::symmetric::SymmetricKey;
//!
//! // Create a random symmetric key
//! let key = SymmetricKey::random();
//!
//! // Encrypt some data
//! let plaintext = b"Hello, BSV!";
//! let ciphertext = key.encrypt(plaintext).expect("encryption failed");
//!
//! // Decrypt the data
//! let decrypted = key.decrypt(&ciphertext).expect("decryption failed");
//! assert_eq!(plaintext, &decrypted[..]);
//! ```

pub mod bignum;
pub mod error;
pub mod hash;
pub mod symmetric;

// Placeholder modules for future phases
pub mod encoding;

pub mod bsv;
pub mod ec;

// Re-export commonly used items
pub use bignum::BigNumber;
pub use error::Error;
pub use hash::{
    hash160, pbkdf2_sha512, ripemd160, sha1, sha256, sha256_hmac, sha256d, sha512, sha512_hmac,
};
pub use symmetric::SymmetricKey;
pub use encoding::{
    from_base58, from_base58_check, from_base64, from_hex, from_utf8_bytes, to_base58,
    to_base58_check, to_base64, to_hex, to_utf8_bytes, Reader, Writer,
};
