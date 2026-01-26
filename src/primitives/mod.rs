//! # BSV Primitives
//!
//! Low-level cryptographic building blocks for BSV applications.
//!
//! This module provides:
//! - Hash functions (SHA-1, SHA-256, SHA-512, RIPEMD-160, hash256, hash160)
//! - HMAC and PBKDF2
//! - Symmetric encryption (AES-256-GCM)
//! - Encoding (hex, base58, base64)
//! - BigNumber for arbitrary-precision arithmetic
//! - secp256k1 elliptic curve operations
//! - P-256 elliptic curve operations
//! - BSV-specific: transaction signatures, BRC-42 key derivation, Shamir sharing

pub mod bignum;
pub mod bsv;
pub mod ec;
pub mod encoding;
pub mod hash;
pub mod p256;
pub mod symmetric;

// Re-exports for convenience
pub use bignum::BigNumber;
pub use ec::{PrivateKey, PublicKey, Signature};
pub use encoding::{
    from_base58, from_base58_check, from_base64, from_hex, from_utf8_bytes, to_base58,
    to_base58_check, to_base64, to_hex, to_utf8_bytes, Reader, Writer,
};
pub use hash::{
    hash160, pbkdf2_sha512, ripemd160, sha1, sha256, sha256_hmac, sha256d, sha512, sha512_hmac,
};
pub use symmetric::SymmetricKey;
