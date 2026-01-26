//! Cryptographic hash functions and related utilities.
//!
//! This module provides:
//! - Single hash functions: SHA-1, SHA-256, SHA-512, RIPEMD-160
//! - Bitcoin-specific composite hashes: hash256 (double SHA-256), hash160 (RIPEMD-160(SHA-256(x)))
//! - HMAC: HMAC-SHA256, HMAC-SHA512
//! - Key derivation: PBKDF2-SHA512
//!
//! # Examples
//!
//! ## Basic hashing
//!
//! ```rust
//! use bsv_primitives::hash;
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
//! ## HMAC
//!
//! ```rust
//! use bsv_primitives::hash;
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
//! use bsv_primitives::hash;
//!
//! let password = b"password";
//! let salt = b"salt";
//! let iterations = 2048;
//! let key_len = 64;
//! let derived_key = hash::pbkdf2_sha512(password, salt, iterations, key_len);
//! assert_eq!(derived_key.len(), 64);
//! ```

use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

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
/// use bsv_primitives::hash::sha1;
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
/// use bsv_primitives::hash::sha256;
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
    hasher.finalize().into()
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
/// use bsv_primitives::hash::sha512;
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
/// use bsv_primitives::hash::ripemd160;
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
/// use bsv_primitives::hash::sha256d;
///
/// let hash = sha256d(b"hello");
/// // The result is SHA256(SHA256("hello"))
/// ```
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
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
/// use bsv_primitives::hash::hash160;
///
/// let hash = hash160(b"public_key_bytes");
/// assert_eq!(hash.len(), 20);
/// ```
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha_hash = sha256(data);
    ripemd160(&sha_hash)
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
/// use bsv_primitives::hash::sha256_hmac;
///
/// let key = b"secret";
/// let message = b"message";
/// let mac = sha256_hmac(key, message);
/// assert_eq!(mac.len(), 32);
/// ```
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

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
/// use bsv_primitives::hash::sha512_hmac;
///
/// let key = b"secret";
/// let message = b"message";
/// let mac = sha512_hmac(key, message);
/// assert_eq!(mac.len(), 64);
/// ```
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;

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
/// use bsv_primitives::hash::pbkdf2_sha512;
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
        // Just verify it produces consistent output
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_utf8_two_bytes() {
        // Cyrillic characters (2 bytes per char in UTF-8)
        let hash = sha256("привет".as_bytes());
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_utf8_three_bytes() {
        // Chinese characters (3 bytes per char in UTF-8)
        let hash = sha256("您好".as_bytes());
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_utf8_four_bytes() {
        // Emoji (4 bytes per char in UTF-8)
        let hash = sha256("👋".as_bytes());
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_utf8_mixed() {
        // Mixed character lengths
        let hash = sha256("hello привет 您好 👋!!!".as_bytes());
        assert_eq!(hash.len(), 32);
    }
}
