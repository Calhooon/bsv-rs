//! # BSV Primitives
//!
//! Low-level cryptographic building blocks for BSV applications.
//!
//! This module provides:
//! - Hash functions (SHA-1, SHA-256, SHA-512, RIPEMD-160, hash256, hash160)
//! - HMAC, PBKDF2 and HKDF (RFC 5869)
//! - Symmetric encryption (AES-256-GCM)
//! - Encoding (hex, base58, base64)
//! - BigNumber for arbitrary-precision arithmetic
//! - secp256k1 elliptic curve operations
//! - P-256 elliptic curve operations
//! - BSV-specific: transaction signatures, BRC-42 key derivation, Shamir sharing

pub mod bignum;
pub mod bsv;
pub mod drbg;
pub mod ec;
pub mod encoding;
pub mod hash;
pub mod p256;
pub mod symmetric;
pub mod u256;

/// A 32-byte digest in internal wire order. Display hex reverses these bytes.
/// ```
/// let hash: bsv_rs::primitives::Hash32 = [0; 32];
/// assert_eq!(hash.len(), 32);
/// ```
pub type Hash32 = [u8; 32];

pub use u256::U256;

// Re-exports for convenience
pub use bignum::BigNumber;
pub use drbg::HmacDrbg;
pub use ec::{PrivateKey, PublicKey, Signature};
pub use encoding::{
    bounded_capacity, from_base58, from_base58_check, from_base64, from_hex, from_utf8_bytes,
    from_var_int, to_base58, to_base58_check, to_base64, to_hex, to_utf8_bytes, to_var_int,
    var_int_len, Reader, Writer, MAX_COMPACT_SIZE,
};
pub use hash::{
    hash160, hkdf_sha256, hkdf_sha256_expand, hkdf_sha256_extract, hkdf_sha512, hkdf_sha512_expand,
    hkdf_sha512_extract, pbkdf2_sha512, ripemd160, sha1, sha1_hmac, sha256, sha256_hmac, sha256d,
    sha512, sha512_hmac, HKDF_SHA256_MAX_OKM, HKDF_SHA512_MAX_OKM,
};
pub use symmetric::SymmetricKey;
