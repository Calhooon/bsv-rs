//! Cryptographic hash functions and related utilities.
//!
//! This module provides:
//! - Single hash functions: SHA-1, SHA-256, SHA-512, RIPEMD-160
//! - Bitcoin-specific composite hashes: hash256 (double SHA-256), hash160 (RIPEMD-160(SHA-256(x)))
//! - Incremental hashers: [`Sha256`] and [`Sha256d`], fed in chunks of any size
//! - HMAC: HMAC-SHA256, HMAC-SHA512
//! - Key derivation functions: PBKDF2 over HMAC-SHA512, and HKDF over HMAC-SHA256 or HMAC-SHA512 (RFC 5869)
//!
//! # Examples
//!
//! ## Basic hashing
//!
//! ```rust
//! use bsv_rs::primitives::hash;
//!
//! // SHA-256
//! let digest = hash::sha256(b"abc");
//! assert_eq!(
//!     hex::encode(digest),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//!
//! // Bitcoin double-SHA256 (hash256/sha256d)
//! let double_hash = hash::sha256d(b"hello");
//!
//! // Bitcoin hash160 for addresses
//! let h160 = hash::hash160(b"public_key_bytes");
//! assert_eq!(h160.len(), 20);
//! ```
//!
//! ## Incremental hashing
//!
//! ```rust
//! use bsv_rs::primitives::hash::{self, Sha256, Sha256d};
//!
//! let mut hasher = Sha256::new();
//! hasher.update(b"a").update(b"bc");
//! assert_eq!(hasher.finalize(), hash::sha256(b"abc"));
//!
//! let mut hasher = Sha256d::new();
//! hasher.update(b"hel").update(b"lo");
//! assert_eq!(hasher.finalize(), hash::sha256d(b"hello"));
//! ```
//!
//! ## HMAC
//!
//! ```rust
//! use bsv_rs::primitives::hash;
//!
//! let key = b"secret_key";
//! let message = b"message to authenticate";
//! let mac = hash::sha256_hmac(key, message);
//! assert_eq!(mac.len(), 32);
//! ```
//!
//! ## PBKDF2
//!
//! ```rust
//! use bsv_rs::primitives::hash;
//!
//! let password = b"password";
//! let salt = b"salt";
//! let iterations = 2048;
//! let key_len = 64;
//! let derived_key = hash::pbkdf2_sha512(password, salt, iterations, key_len);
//! assert_eq!(derived_key.len(), 64);
//! ```
//!
//! ## HKDF
//!
//! ```rust
//! use bsv_rs::primitives::hash;
//!
//! // RFC 5869 A.1
//! let ikm = [0x0b; 22];
//! let salt = hex::decode("000102030405060708090a0b0c").unwrap();
//! let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
//! let mut okm = [0u8; 42];
//! hash::hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
//! assert_eq!(
//!     hex::encode(okm),
//!     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
//! );
//! ```

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha512};

/// Computes the SHA-1 hash of the input data.
///
/// # Warning
///
/// SHA-1 is cryptographically broken and should not be used for security-critical
/// applications. It is provided for compatibility with legacy systems.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 20-byte array containing the SHA-1 hash
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha1;
///
/// let hash = sha1(b"abc");
/// assert_eq!(
///     hex::encode(hash),
///     "a9993e364706816aba3e25717850c26c9cd0d89d"
/// );
/// ```
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes the SHA-256 hash of the input data.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 32-byte array containing the SHA-256 hash
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha256;
///
/// let hash = sha256(b"abc");
/// assert_eq!(
///     hex::encode(hash),
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// An incremental SHA-256 hasher.
///
/// Feeding the input in any number of [`update`](Sha256::update) calls, of any
/// sizes, gives the same digest as [`sha256`] over the concatenation: the
/// one-shot function is defined through this hasher. `update` returns the
/// hasher, so calls chain; [`finalize`](Sha256::finalize) consumes it, and a
/// clone finalizes a prefix while the original keeps reading.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::{sha256, Sha256};
///
/// let data = vec![7u8; 200_000];
/// let mut hasher = Sha256::new();
/// for chunk in data.chunks(64 * 1024) {
///     hasher.update(chunk);
/// }
/// assert_eq!(hasher.finalize(), sha256(&data));
/// ```
#[derive(Clone, Default)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Sha256 {
    /// Creates a hasher over the empty input.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `data` to the input; returns the hasher so calls chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Returns the SHA-256 digest of everything updated.
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256").finish_non_exhaustive()
    }
}

/// An incremental double SHA-256 hasher: SHA256(SHA256(input)).
///
/// [`finalize`](Sha256d::finalize) returns the double hash of everything
/// updated, equal to [`sha256d`] over the concatenation for any chunking:
/// the one-shot function is defined through this hasher. `update` chains as
/// on [`Sha256`].
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::{sha256d, Sha256d};
///
/// let mut hasher = Sha256d::new();
/// hasher.update(b"hel").update(b"lo");
/// assert_eq!(hasher.finalize(), sha256d(b"hello"));
/// ```
#[derive(Clone, Default)]
pub struct Sha256d {
    inner: Sha256,
}

impl Sha256d {
    /// Creates a hasher over the empty input.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends `data` to the input; returns the hasher so calls chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Returns SHA256(SHA256(everything updated)).
    pub fn finalize(self) -> [u8; 32] {
        let once = self.inner.finalize();
        let mut second = Sha256::new();
        second.update(&once);
        second.finalize()
    }
}

impl std::fmt::Debug for Sha256d {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256d").finish_non_exhaustive()
    }
}

/// Computes the SHA-512 hash of the input data.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 64-byte array containing the SHA-512 hash
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha512;
///
/// let hash = sha512(b"abc");
/// assert_eq!(
///     hex::encode(hash),
///     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
/// );
/// ```
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes the RIPEMD-160 hash of the input data.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 20-byte array containing the RIPEMD-160 hash
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::ripemd160;
///
/// let hash = ripemd160(b"abc");
/// assert_eq!(
///     hex::encode(hash),
///     "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
/// );
/// ```
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes the double SHA-256 hash: SHA256(SHA256(data)).
///
/// This is commonly used in Bitcoin for transaction IDs and block hashes.
/// Also known as `hash256` in the TypeScript SDK.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 32-byte array containing the double SHA-256 hash
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha256d;
///
/// let hash = sha256d(b"hello");
/// // The result is SHA256(SHA256("hello"))
/// ```
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256d::new();
    hasher.update(data);
    hasher.finalize()
}

/// Computes the hash160: RIPEMD160(SHA256(data)).
///
/// This is commonly used in Bitcoin for generating addresses from public keys.
///
/// # Arguments
///
/// * `data` - The input data to hash
///
/// # Returns
///
/// A 20-byte array containing the hash160 result
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::hash160;
///
/// let hash = hash160(b"public_key_bytes");
/// assert_eq!(hash.len(), 20);
/// ```
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha_hash = sha256(data);
    ripemd160(&sha_hash)
}

/// Computes HMAC-SHA1.
///
/// # Warning
///
/// SHA-1 is cryptographically broken and should not be used for security-critical
/// applications. It is provided for compatibility with legacy systems (e.g., TOTP
/// which defaults to HMAC-SHA1 per RFC 6238).
///
/// # Arguments
///
/// * `key` - The secret key for HMAC
/// * `data` - The message to authenticate
///
/// # Returns
///
/// A 20-byte array containing the HMAC-SHA1 result
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha1_hmac;
///
/// let key = b"secret";
/// let message = b"message";
/// let mac = sha1_hmac(key, message);
/// assert_eq!(mac.len(), 20);
/// ```
pub fn sha1_hmac(key: &[u8], data: &[u8]) -> [u8; 20] {
    type HmacSha1 = Hmac<Sha1>;

    #[allow(clippy::expect_used)]
    // #134: HMAC takes a key of any length; hmac 0.12 has no infallible slice constructor
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Computes HMAC-SHA256.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC
/// * `data` - The message to authenticate
///
/// # Returns
///
/// A 32-byte array containing the HMAC-SHA256 result
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha256_hmac;
///
/// let key = b"secret";
/// let message = b"message";
/// let mac = sha256_hmac(key, message);
/// assert_eq!(mac.len(), 32);
/// ```
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<sha2::Sha256>;

    #[allow(clippy::expect_used)]
    // #134: HMAC takes a key of any length; hmac 0.12 has no infallible slice constructor
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Computes HMAC-SHA512.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC
/// * `data` - The message to authenticate
///
/// # Returns
///
/// A 64-byte array containing the HMAC-SHA512 result
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::sha512_hmac;
///
/// let key = b"secret";
/// let message = b"message";
/// let mac = sha512_hmac(key, message);
/// assert_eq!(mac.len(), 64);
/// ```
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;

    #[allow(clippy::expect_used)]
    // #134: HMAC takes a key of any length; hmac 0.12 has no infallible slice constructor
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Derives a key using PBKDF2 with HMAC-SHA512.
///
/// # Arguments
///
/// * `password` - The password to derive the key from
/// * `salt` - The salt value
/// * `iterations` - The number of iterations (higher = more secure but slower)
/// * `key_len` - The desired length of the derived key in bytes
///
/// # Returns
///
/// A vector containing the derived key of the specified length
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::pbkdf2_sha512;
///
/// let password = b"password";
/// let salt = b"salt";
/// let iterations = 1;
/// let key_len = 32;
///
/// let key = pbkdf2_sha512(password, salt, iterations, key_len);
/// assert_eq!(key.len(), 32);
/// assert_eq!(
///     hex::encode(&key),
///     "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
/// );
/// ```
///
/// # Panics
///
/// Panics if the output buffer cannot be created (should not happen in practice).
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut output = vec![0u8; key_len];
    pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output);
    output
}

/// The longest HKDF-SHA256 output, `255 * 32` bytes (RFC 5869 §2.3).
pub const HKDF_SHA256_MAX_OKM: usize = 255 * 32;

/// The longest HKDF-SHA512 output, `255 * 64` bytes (RFC 5869 §2.3).
pub const HKDF_SHA512_MAX_OKM: usize = 255 * 64;

/// HKDF-Extract over any HMAC (RFC 5869 §2.2): `PRK = HMAC-Hash(salt, IKM)`.
///
/// An empty `salt` is the RFC's "not provided": HMAC pads its key with zeros to
/// the block size, so the empty key and `HashLen` zero bytes are the same key.
fn hkdf_extract_with<M: Mac + hmac::digest::KeyInit>(
    salt: &[u8],
    ikm: &[u8],
) -> hmac::digest::Output<M> {
    #[allow(clippy::expect_used)]
    // #134: HMAC takes a key of any length; hmac 0.12 has no infallible slice constructor
    let mut mac = <M as Mac>::new_from_slice(salt).expect("HMAC can take key of any size");
    Mac::update(&mut mac, ikm);
    mac.finalize().into_bytes()
}

/// HKDF-Expand over any HMAC (RFC 5869 §2.3):
/// `T(i) = HMAC-Hash(PRK, T(i - 1) || info || i)`, `OKM` the first `L` bytes of `T(1) || T(2) || ...`.
///
/// Refuses a `PRK` shorter than `HashLen` and an `okm` longer than `255 * HashLen`
/// (both the RFC's preconditions) without writing `okm`.
fn hkdf_expand_with<M: Mac + hmac::digest::KeyInit + Clone>(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<()> {
    let hash_len = <M as hmac::digest::OutputSizeUser>::output_size();
    if prk.len() < hash_len {
        return Err(Error::InvalidKeyLength {
            expected: hash_len,
            actual: prk.len(),
        });
    }
    if okm.len() > 255 * hash_len {
        return Err(Error::InvalidDataLength {
            expected: 255 * hash_len,
            actual: okm.len(),
        });
    }
    #[allow(clippy::expect_used)]
    // #134: HMAC takes a key of any length; hmac 0.12 has no infallible slice constructor
    let base = <M as Mac>::new_from_slice(prk).expect("HMAC can take key of any size");
    let mut previous: Option<hmac::digest::Output<M>> = None;
    for (i, chunk) in okm.chunks_mut(hash_len).enumerate() {
        let mut mac = base.clone();
        if let Some(t) = &previous {
            Mac::update(&mut mac, t);
        }
        Mac::update(&mut mac, info);
        // i < 255 by the length check, so the counter i + 1 fits one byte
        Mac::update(&mut mac, &[(i + 1) as u8]);
        let t = mac.finalize().into_bytes();
        chunk.copy_from_slice(&t[..chunk.len()]);
        previous = Some(t);
    }
    Ok(())
}

/// HKDF-SHA256 extract (RFC 5869 §2.2): the 32-byte pseudorandom key of `ikm` under `salt`.
///
/// An empty `salt` is the RFC's "not provided" (equal to 32 zero bytes).
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::{hkdf_sha256_expand, hkdf_sha256_extract};
///
/// // RFC 5869 A.3: no salt, no info
/// let prk = hkdf_sha256_extract(&[], &[0x0b; 22]);
/// assert_eq!(
///     hex::encode(prk),
///     "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
/// );
/// let mut okm = [0u8; 42];
/// hkdf_sha256_expand(&prk, &[], &mut okm).unwrap();
/// assert_eq!(
///     hex::encode(okm),
///     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
/// );
/// ```
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hkdf_extract_with::<Hmac<sha2::Sha256>>(salt, ikm).into()
}

/// HKDF-SHA256 expand (RFC 5869 §2.3): fills `okm` from `prk` and `info`.
///
/// # Errors
///
/// [`Error::InvalidKeyLength`] for a `prk` shorter than 32 bytes;
/// [`Error::InvalidDataLength`] for an `okm` longer than [`HKDF_SHA256_MAX_OKM`].
/// `okm` is not written on an error.
pub fn hkdf_sha256_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    hkdf_expand_with::<Hmac<sha2::Sha256>>(prk, info, okm)
}

/// HKDF-SHA256 (RFC 5869): extract with `salt` over `ikm`, then expand `info` into `okm`.
///
/// An empty `salt` is the RFC's "not provided". Intermediate values are not
/// zeroized; a caller holding secrets wipes its own buffers.
///
/// # Errors
///
/// [`Error::InvalidDataLength`] for an `okm` longer than [`HKDF_SHA256_MAX_OKM`];
/// `okm` is not written on an error.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::hkdf_sha256;
///
/// let mut okm = [0u8; 32];
/// hkdf_sha256(b"salt", b"input key material", b"context", &mut okm).unwrap();
/// let mut too_long = vec![0u8; 255 * 32 + 1];
/// assert!(hkdf_sha256(b"salt", b"input key material", b"context", &mut too_long).is_err());
/// ```
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let prk = hkdf_sha256_extract(salt, ikm);
    hkdf_sha256_expand(&prk, info, okm)
}

/// HKDF-SHA512 extract (RFC 5869 §2.2): the 64-byte pseudorandom key of `ikm` under `salt`.
///
/// An empty `salt` is the RFC's "not provided" (equal to 64 zero bytes).
pub fn hkdf_sha512_extract(salt: &[u8], ikm: &[u8]) -> [u8; 64] {
    hkdf_extract_with::<Hmac<Sha512>>(salt, ikm).into()
}

/// HKDF-SHA512 expand (RFC 5869 §2.3): fills `okm` from `prk` and `info`.
///
/// # Errors
///
/// [`Error::InvalidKeyLength`] for a `prk` shorter than 64 bytes;
/// [`Error::InvalidDataLength`] for an `okm` longer than [`HKDF_SHA512_MAX_OKM`].
/// `okm` is not written on an error.
pub fn hkdf_sha512_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    hkdf_expand_with::<Hmac<Sha512>>(prk, info, okm)
}

/// HKDF-SHA512 (RFC 5869): extract with `salt` over `ikm`, then expand `info` into `okm`.
///
/// An empty `salt` is the RFC's "not provided". Intermediate values are not
/// zeroized; a caller holding secrets wipes its own buffers.
///
/// # Errors
///
/// [`Error::InvalidDataLength`] for an `okm` longer than [`HKDF_SHA512_MAX_OKM`];
/// `okm` is not written on an error.
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::hash::hkdf_sha512;
///
/// // Wycheproof hkdf_sha512_test.json tcId 1: empty salt, empty info
/// let ikm = hex::decode("24aeff2645e3e0f5494a9a102778c43a").unwrap();
/// let mut okm = [0u8; 20];
/// hkdf_sha512(&[], &ikm, &[], &mut okm).unwrap();
/// assert_eq!(hex::encode(okm), "dd2599840b09699c6200b5cba79002b3aa75c61b");
/// ```
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let prk = hkdf_sha512_extract(salt, ikm);
    hkdf_sha512_expand(&prk, info, okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-1 test vectors
    #[test]
    fn test_sha1_empty() {
        let hash = sha1(b"");
        assert_eq!(
            hex::encode(hash),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        assert_eq!(
            hex::encode(hash),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn test_sha1_long() {
        let hash = sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex::encode(hash),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    #[test]
    fn test_sha1_hex_input() {
        // SHA1 of bytes [0xde, 0xad, 0xbe, 0xef]
        let input = hex::decode("deadbeef").unwrap();
        let hash = sha1(&input);
        assert_eq!(
            hex::encode(hash),
            "d78f8bb992a56a597f6c7a1fb918bb78271367eb"
        );
    }

    // SHA-256 test vectors
    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        assert_eq!(
            hex::encode(hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_long() {
        let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex::encode(hash),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_hex_input() {
        let input = hex::decode("deadbeef").unwrap();
        let hash = sha256(&input);
        assert_eq!(
            hex::encode(hash),
            "5f78c33274e43fa9de5659265c1d917e25c03722dcb0b8d27db8d5feaa813953"
        );
    }

    // SHA-512 test vectors
    #[test]
    fn test_sha512_abc() {
        let hash = sha512(b"abc");
        assert_eq!(
            hex::encode(hash),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_sha512_long() {
        let hash = sha512(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        );
        assert_eq!(
            hex::encode(hash),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    // RIPEMD-160 test vectors
    #[test]
    fn test_ripemd160_empty() {
        let hash = ripemd160(b"");
        assert_eq!(
            hex::encode(hash),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn test_ripemd160_abc() {
        let hash = ripemd160(b"abc");
        assert_eq!(
            hex::encode(hash),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn test_ripemd160_message_digest() {
        let hash = ripemd160(b"message digest");
        assert_eq!(
            hex::encode(hash),
            "5d0689ef49d2fae572b881b123a85ffa21595f36"
        );
    }

    #[test]
    fn test_ripemd160_long() {
        let hash = ripemd160(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            hex::encode(hash),
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
        );
    }

    #[test]
    fn test_ripemd160_alphanumeric() {
        let hash = ripemd160(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        assert_eq!(
            hex::encode(hash),
            "b0e20b6e3116640286ed3a87a5713079b21f5189"
        );
    }

    // Double SHA-256 (sha256d / hash256) tests
    #[test]
    fn test_sha256d() {
        // Verify it's actually SHA256(SHA256(x))
        let data = b"hello";
        let first = sha256(data);
        let expected = sha256(&first);
        let result = sha256d(data);
        assert_eq!(result, expected);
    }

    // The incremental hashers
    #[test]
    fn test_sha256_hasher_million_a_in_chunks() {
        // FIPS 180-2 appendix B.3: one million repetitions of "a"
        let chunk = [b'a'; 1000];
        let mut hasher = Sha256::new();
        for _ in 0..1000 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hex::encode(hasher.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn test_hashers_empty_input() {
        assert_eq!(Sha256::new().finalize(), sha256(b""));
        assert_eq!(Sha256::default().finalize(), sha256(b""));
        assert_eq!(
            hex::encode(Sha256d::new().finalize()),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
        assert_eq!(Sha256d::default().finalize(), sha256d(b""));
    }

    #[test]
    fn test_sha256d_hasher_chained() {
        let mut hasher = Sha256d::new();
        hasher.update(b"he").update(b"").update(b"llo");
        assert_eq!(
            hex::encode(hasher.finalize()),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn test_hashers_debug_shows_no_state() {
        let mut hasher = Sha256::new();
        hasher.update(b"secret");
        assert_eq!(format!("{hasher:?}"), "Sha256 { .. }");
        let mut hasher = Sha256d::new();
        hasher.update(b"secret");
        assert_eq!(format!("{hasher:?}"), "Sha256d { .. }");
    }

    // hash160 tests
    #[test]
    fn test_hash160() {
        // Verify it's actually RIPEMD160(SHA256(x))
        let data = b"hello";
        let sha_hash = sha256(data);
        let expected = ripemd160(&sha_hash);
        let result = hash160(data);
        assert_eq!(result, expected);
    }

    // HMAC-SHA256 test vectors (from NIST)
    #[test]
    fn test_sha256_hmac_nist1() {
        // Key length = block length (64 bytes)
        let key = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        )
        .unwrap();
        let msg = b"Sample message for keylen=blocklen";
        let result = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(result),
            "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"
        );
    }

    #[test]
    fn test_sha256_hmac_nist2() {
        // Key length < block length (32 bytes)
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let msg = b"Sample message for keylen<blocklen";
        let result = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(result),
            "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790"
        );
    }

    #[test]
    fn test_sha256_hmac_nist3() {
        // Key length > block length (100 bytes)
        let key = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263",
        )
        .unwrap();
        let msg = b"Sample message for keylen=blocklen";
        let result = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(result),
            "bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d"
        );
    }

    #[test]
    fn test_sha256_hmac_nist4() {
        // Key with truncated tag (49 bytes)
        // Original: '00' + '01020304 05060708 090A0B0C 0D0E0F10 11121314 15161718'
        //         + '191A1B1C 1D1E1F20 21222324 25262728 292A2B2C 2D2E2F30'
        let key = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
        )
        .unwrap();
        let msg = b"Sample message for keylen<blocklen, with truncated tag";
        let result = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(result),
            "27a8b157839efeac98df070b331d593618ddb985d403c0c786d23b5d132e57c7"
        );
    }

    #[test]
    fn test_sha256_hmac_regression1() {
        // Regression test from TypeScript SDK
        let key = hex::decode("48f38d0c6a344959cc94502b7b5e8dffb6a5f41795d9066fc9a649557167ee2f")
            .unwrap();
        let msg = hex::decode("1d495eef7761b65dccd0a983d2d7204fea28b5c81f1758046e062eb043755ea1")
            .unwrap();
        let result = sha256_hmac(&key, &msg);
        assert_eq!(
            hex::encode(result),
            "cf5ad5984f9e43917aa9087380dac46e410ddc8a7731859c84e9d0f31bd43655"
        );
    }

    // PBKDF2-SHA512 test vectors
    #[test]
    fn test_pbkdf2_sha512_basic() {
        let key = pbkdf2_sha512(b"password", b"salt", 1, 32);
        assert_eq!(
            hex::encode(&key),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_2_iterations() {
        let key = pbkdf2_sha512(b"password", b"salt", 2, 32);
        assert_eq!(
            hex::encode(&key),
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_64_bytes() {
        let key = pbkdf2_sha512(b"password", b"salt", 1, 64);
        assert_eq!(
            hex::encode(&key),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_2_iterations_64_bytes() {
        let key = pbkdf2_sha512(b"password", b"salt", 2, 64);
        assert_eq!(
            hex::encode(&key),
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_4096_iterations() {
        let key = pbkdf2_sha512(b"password", b"salt", 4096, 32);
        assert_eq!(
            hex::encode(&key),
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_long_password_and_salt() {
        let key = pbkdf2_sha512(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
        );
        assert_eq!(
            hex::encode(&key),
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_with_null_bytes() {
        // JavaScript string "pass\u00000word" means "pass" + null + "0word"
        // JavaScript string "sa\u00000lt" means "sa" + null + "0lt"
        let password = b"pass\x000word";
        let salt = b"sa\x000lt";
        let key = pbkdf2_sha512(password, salt, 4096, 16);
        assert_eq!(hex::encode(&key), "336d14366099e8aac2c46c94a8f178d2");
    }

    #[test]
    fn test_pbkdf2_sha512_hex_key() {
        // Key from hex
        let password = hex::decode("63ffeeddccbbaa").unwrap();
        let key = pbkdf2_sha512(&password, b"salt", 1, 32);
        assert_eq!(
            hex::encode(&key),
            "f69de451247225a7b30cc47632899572bb980f500d7c606ac9b1c04f928a3488"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_short_output() {
        let key = pbkdf2_sha512(b"password", b"salt", 1, 10);
        assert_eq!(hex::encode(&key), "867f70cf1ade02cff375");
    }

    #[test]
    fn test_pbkdf2_sha512_long_output() {
        let key = pbkdf2_sha512(b"password", b"salt", 1, 100);
        assert_eq!(
            hex::encode(&key),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce7b532e206c2967d4c7d2ffa460539fc4d4e5eec70125d74c6c7cf86d25284f297907fcea"
        );
    }

    #[test]
    fn test_pbkdf2_sha512_unicode_salt() {
        // Unicode salt test - the salt is hex-encoded in the test vector
        let password = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let salt = hex::decode("6d6e656d6f6e6963e383a1e383bce38388e383abe382abe38299e3838fe38299e382a6e38299e382a1e381afe3829ae381afe38299e3818fe38299e3829de38299e381a1e381a1e38299e58d81e4babae58d81e889b2").unwrap();
        let key = pbkdf2_sha512(password, &salt, 2048, 64);
        assert_eq!(
            hex::encode(&key),
            "ba553eedefe76e67e2602dc20184c564010859faada929a090dd2c57aacb204ceefd15404ab50ef3e8dbeae5195aeae64b0def4d2eead1cdc728a33ced520ffd"
        );
    }

    // Test UTF-8 handling consistency
    #[test]
    fn test_sha256_utf8_one_byte() {
        // ASCII characters (1 byte per char)
        let hash = sha256("hello".as_bytes());
        assert_eq!(
            hex::encode(hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_utf8_two_bytes() {
        // Cyrillic characters (2 bytes per char in UTF-8)
        let hash = sha256("привет".as_bytes());
        assert_eq!(
            hex::encode(hash),
            "e58f1e8c55fa105bdd3f40e5037eb0b039b5998d52c05e6cd98878dd2da5cab2"
        );
    }

    #[test]
    fn test_sha256_utf8_three_bytes() {
        // Chinese characters (3 bytes per char in UTF-8)
        let hash = sha256("您好".as_bytes());
        assert_eq!(
            hex::encode(hash),
            "609bc0751d56eb467961e2bc6f798f7d44627696248e52315e1d6d091bdf502a"
        );
    }

    #[test]
    fn test_sha256_utf8_four_bytes() {
        // Emoji (4 bytes per char in UTF-8)
        let hash = sha256("👋".as_bytes());
        assert_eq!(
            hex::encode(hash),
            "1d0452e3d194cc7950909b578c611d5ad4cd15105c6aeefc38ce213240ffc457"
        );
    }

    #[test]
    fn test_sha256_utf8_mixed() {
        // Mixed character lengths
        let hash = sha256("hello привет 您好 👋!!!".as_bytes());
        assert_eq!(
            hex::encode(hash),
            "b7858cde6e07b54bb3963e543245909a7b222619b03d647bd011b145f7b29bee"
        );
    }

    // HMAC-SHA1 test vectors (RFC 2202)
    #[test]
    fn test_sha1_hmac_rfc2202_1() {
        // Test case 1 from RFC 2202
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let result = sha1_hmac(&key, data);
        assert_eq!(
            hex::encode(result),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
    }

    #[test]
    fn test_sha1_hmac_rfc2202_2() {
        // Test case 2 from RFC 2202 ("Jefe" key)
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let result = sha1_hmac(key, data);
        assert_eq!(
            hex::encode(result),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn test_sha1_hmac_rfc2202_3() {
        // Test case 3 from RFC 2202 (0xaa key repeated 20 times)
        let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
        let result = sha1_hmac(&key, &data);
        assert_eq!(
            hex::encode(result),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
    }

    #[test]
    fn test_sha1_hmac_totp_vector() {
        // TOTP RFC 6238 test vector with 20-byte secret
        let key = b"12345678901234567890";
        let data = [0u8, 0, 0, 0, 0, 0, 0, 1]; // counter = 1 as big-endian 8 bytes
        let result = sha1_hmac(key, &data);
        assert_eq!(
            hex::encode(result),
            "75a48a19d4cbe100644e8ac1397eea747a2d33ab"
        );
    }

    // HKDF (RFC 5869 Appendix A: A.1 to A.3 are HKDF-SHA256, A.4 to A.7 HKDF-SHA1).
    // The SHA-1 cases run through the same private extract and expand the public
    // SHA-256 and SHA-512 functions use, so all seven vectors exercise the construction.
    struct Rfc5869 {
        case: &'static str,
        ikm: &'static str,
        salt: &'static str,
        info: &'static str,
        l: usize,
        prk: &'static str,
        okm: &'static str,
    }

    const RFC5869_SHA256: [Rfc5869; 3] = [
        Rfc5869 {
            case: "A.1",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            l: 42,
            prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        Rfc5869 {
            case: "A.2",
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            l: 82,
            prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Rfc5869 {
            case: "A.3",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "",
            info: "",
            l: 42,
            prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
    ];

    const RFC5869_SHA1: [Rfc5869; 4] = [
        Rfc5869 {
            case: "A.4",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            l: 42,
            prk: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
            okm: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
        },
        Rfc5869 {
            case: "A.5",
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            l: 82,
            prk: "8adae09a2a307059478d309b26c4115a224cfaf6",
            okm: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
        },
        Rfc5869 {
            case: "A.6",
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "",
            info: "",
            l: 42,
            prk: "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
            okm: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        },
        Rfc5869 { // salt not provided
            case: "A.7",
            ikm: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            salt: "",
            info: "",
            l: 42,
            prk: "2adccada18779e7c2077ad2eb19d3f3e731385dd",
            okm: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        },
    ];

    #[test]
    fn test_hkdf_sha256_rfc5869_a1_to_a3() {
        for v in &RFC5869_SHA256 {
            let (ikm, salt, info) = (
                hex::decode(v.ikm).unwrap(),
                hex::decode(v.salt).unwrap(),
                hex::decode(v.info).unwrap(),
            );
            let prk = hkdf_sha256_extract(&salt, &ikm);
            assert_eq!(hex::encode(prk), v.prk, "{} PRK", v.case);
            let mut okm = vec![0u8; v.l];
            hkdf_sha256_expand(&prk, &info, &mut okm).unwrap();
            assert_eq!(hex::encode(&okm), v.okm, "{} OKM (expand)", v.case);
            let mut okm = vec![0u8; v.l];
            hkdf_sha256(&salt, &ikm, &info, &mut okm).unwrap();
            assert_eq!(hex::encode(&okm), v.okm, "{} OKM (one call)", v.case);
        }
    }

    #[test]
    fn test_hkdf_sha1_rfc5869_a4_to_a7() {
        type HmacSha1 = Hmac<Sha1>;
        for v in &RFC5869_SHA1 {
            let (ikm, salt, info) = (
                hex::decode(v.ikm).unwrap(),
                hex::decode(v.salt).unwrap(),
                hex::decode(v.info).unwrap(),
            );
            let prk = hkdf_extract_with::<HmacSha1>(&salt, &ikm);
            assert_eq!(hex::encode(prk), v.prk, "{} PRK", v.case);
            let mut okm = vec![0u8; v.l];
            hkdf_expand_with::<HmacSha1>(&prk, &info, &mut okm).unwrap();
            assert_eq!(hex::encode(&okm), v.okm, "{} OKM", v.case);
        }
        // A.7's "salt not provided" is HashLen zero bytes (RFC 5869 §2.2), the same key as the empty salt
        let ikm = hex::decode(RFC5869_SHA1[3].ikm).unwrap();
        assert_eq!(
            hex::encode(hkdf_extract_with::<HmacSha1>(&[0u8; 20], &ikm)),
            RFC5869_SHA1[3].prk
        );
    }

    #[test]
    fn test_hkdf_absent_salt_is_hash_len_zeros() {
        let ikm = [0x0b; 22];
        assert_eq!(
            hkdf_sha256_extract(&[], &ikm),
            hkdf_sha256_extract(&[0u8; 32], &ikm)
        );
        assert_eq!(
            hkdf_sha512_extract(&[], &ikm),
            hkdf_sha512_extract(&[0u8; 64], &ikm)
        );
        // and a salt is not ignored
        assert_ne!(
            hkdf_sha256_extract(&[1], &ikm),
            hkdf_sha256_extract(&[], &ikm)
        );
    }

    /// HKDF-SHA512 on RFC 5869 A.1's inputs and on A.3's (empty salt and info), L = 42 and 64;
    /// the expected bytes are `openssl kdf -keylen L -kdfopt digest:SHA512 -kdfopt hexkey:... HKDF`
    /// (OpenSSL 3.6.2 and 3.6.4, an independent implementation).
    #[test]
    fn test_hkdf_sha512_rfc5869_inputs_vs_openssl() {
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        hkdf_sha512(&salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb"
        );
        let mut okm = [0u8; 64];
        hkdf_sha512(&[], &ikm, &[], &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bacc4e7cb6045faaa698e0e3b3eb91331306def1db8319e"
        );
    }

    #[test]
    fn test_hkdf_output_bound_is_255_blocks() {
        let mut okm = vec![0u8; HKDF_SHA256_MAX_OKM];
        hkdf_sha256(b"salt", b"ikm", b"info", &mut okm).unwrap();
        let mut okm = vec![0u8; HKDF_SHA512_MAX_OKM];
        hkdf_sha512(b"salt", b"ikm", b"info", &mut okm).unwrap();

        let mut over = vec![0xaau8; HKDF_SHA256_MAX_OKM + 1];
        assert_eq!(
            hkdf_sha256(b"salt", b"ikm", b"info", &mut over),
            Err(Error::InvalidDataLength {
                expected: HKDF_SHA256_MAX_OKM,
                actual: HKDF_SHA256_MAX_OKM + 1
            })
        );
        assert!(
            over.iter().all(|&b| b == 0xaa),
            "okm is not written on an error"
        );
        let mut over = vec![0xaau8; HKDF_SHA512_MAX_OKM + 1];
        assert_eq!(
            hkdf_sha512(b"salt", b"ikm", b"info", &mut over),
            Err(Error::InvalidDataLength {
                expected: HKDF_SHA512_MAX_OKM,
                actual: HKDF_SHA512_MAX_OKM + 1
            })
        );
        assert!(
            over.iter().all(|&b| b == 0xaa),
            "okm is not written on an error"
        );
    }

    #[test]
    fn test_hkdf_expand_refuses_a_short_prk() {
        let mut okm = [0u8; 32];
        assert_eq!(
            hkdf_sha256_expand(&[0u8; 31], b"", &mut okm),
            Err(Error::InvalidKeyLength {
                expected: 32,
                actual: 31
            })
        );
        assert_eq!(
            hkdf_sha512_expand(&[0u8; 63], b"", &mut okm),
            Err(Error::InvalidKeyLength {
                expected: 64,
                actual: 63
            })
        );
        // a PRK longer than HashLen is accepted (RFC 5869 §2.3: "at least HashLen octets")
        hkdf_sha256_expand(&[0u8; 33], b"", &mut okm).unwrap();
    }

    #[test]
    fn test_hkdf_empty_okm_and_block_boundaries() {
        let mut empty = [0u8; 0];
        hkdf_sha256(b"s", b"k", b"i", &mut empty).unwrap();
        // a shorter output is the prefix of a longer one at every length around a block boundary
        let mut long = [0u8; 200];
        hkdf_sha512(b"s", b"k", b"i", &mut long).unwrap();
        for l in [1, 63, 64, 65, 127, 128, 129, 200] {
            let mut short = vec![0u8; l];
            hkdf_sha512(b"s", b"k", b"i", &mut short).unwrap();
            assert_eq!(short, long[..l], "L = {l}");
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf_sha256(b"s", b"k", b"info-a", &mut a).unwrap();
        hkdf_sha256(b"s", b"k", b"info-b", &mut b).unwrap();
        assert_ne!(a, b);
    }
}
