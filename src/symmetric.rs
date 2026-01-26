//! Symmetric encryption using AES-256-GCM with 32-byte nonce.
//!
//! This module provides the [`SymmetricKey`] struct for symmetric encryption and decryption
//! using AES-256-GCM. It is compatible with the BSV TypeScript and Go SDKs.
//!
//! # Important Implementation Details
//!
//! The BSV SDK uses a **non-standard 32-byte nonce** for AES-GCM (instead of the typical
//! 12 bytes). This is intentional for cross-SDK compatibility.
//!
//! ## Output Format
//!
//! Encrypted data is formatted as: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`
//!
//! ## Key Padding
//!
//! Keys shorter than 32 bytes are padded with **leading zeros** to reach 32 bytes.
//! This is critical for handling 31-byte keys derived from elliptic curve X coordinates.
//!
//! # Example
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

use aes_gcm::aead::generic_array::typenum::U32;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};

use crate::error::{Error, Result};

/// AES-256-GCM cipher with 32-byte nonce (non-standard, for BSV SDK compatibility).
type Aes256Gcm32 = AesGcm<Aes256, U32>;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;

/// Size of the initialization vector (nonce) in bytes.
/// Note: This is non-standard. Standard GCM uses 12 bytes.
const IV_SIZE: usize = 32;

/// Size of the authentication tag in bytes.
const TAG_SIZE: usize = 16;

/// Minimum size of valid ciphertext (IV + tag, no actual encrypted data).
const MIN_CIPHERTEXT_SIZE: usize = IV_SIZE + TAG_SIZE;

/// A 256-bit symmetric key for AES-256-GCM encryption.
///
/// This struct wraps a 32-byte key and provides encrypt/decrypt methods
/// compatible with the BSV TypeScript and Go SDKs.
///
/// # Cross-SDK Compatibility
///
/// Keys derived from elliptic curve operations may be 31 bytes (when the X coordinate
/// has a leading zero byte). These keys are automatically padded with a leading zero
/// to reach 32 bytes, matching the behavior of the TypeScript and Go SDKs.
#[derive(Clone)]
pub struct SymmetricKey {
    key: [u8; KEY_SIZE],
}

impl SymmetricKey {
    /// Creates a new symmetric key from random bytes.
    ///
    /// Uses a cryptographically secure random number generator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::symmetric::SymmetricKey;
    ///
    /// let key = SymmetricKey::random();
    /// ```
    pub fn random() -> Self {
        let mut key = [0u8; KEY_SIZE];
        getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
        Self { key }
    }

    /// Creates a symmetric key from existing bytes.
    ///
    /// If the input is shorter than 32 bytes, it is padded with **leading zeros**
    /// to reach 32 bytes. This is critical for compatibility with keys derived
    /// from elliptic curve X coordinates, which may be 31 bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The key bytes (1-32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is empty or longer than 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::symmetric::SymmetricKey;
    ///
    /// // 31-byte key (will be padded with leading zero)
    /// let key_31 = vec![0xFFu8; 31];
    /// let sym_key = SymmetricKey::from_bytes(&key_31).unwrap();
    ///
    /// // First byte should be 0x00 (padding)
    /// assert_eq!(sym_key.as_bytes()[0], 0x00);
    /// assert_eq!(sym_key.as_bytes()[1], 0xFF);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: 0,
            });
        }

        if bytes.len() > KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: KEY_SIZE,
                actual: bytes.len(),
            });
        }

        let mut key = [0u8; KEY_SIZE];

        if bytes.len() < KEY_SIZE {
            // Pad with leading zeros (copy to end of array)
            let offset = KEY_SIZE - bytes.len();
            key[offset..].copy_from_slice(bytes);
        } else {
            key.copy_from_slice(bytes);
        }

        Ok(Self { key })
    }

    /// Returns the raw key bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::symmetric::SymmetricKey;
    ///
    /// let key = SymmetricKey::random();
    /// let bytes = key.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// Returns the ciphertext in the format: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`
    ///
    /// A random 32-byte IV is generated for each encryption operation.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The data to encrypt
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails (which should not happen with valid inputs).
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::symmetric::SymmetricKey;
    ///
    /// let key = SymmetricKey::random();
    /// let plaintext = b"Hello, BSV!";
    /// let ciphertext = key.encrypt(plaintext).expect("encryption failed");
    ///
    /// // Ciphertext includes IV (32) + encrypted data (11) + tag (16) = 59 bytes
    /// assert_eq!(ciphertext.len(), 32 + 11 + 16);
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Create cipher
        let cipher = Aes256Gcm32::new_from_slice(&self.key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {}", e)))?;

        // Generate random 32-byte IV
        let mut iv = [0u8; IV_SIZE];
        getrandom::getrandom(&mut iv)
            .map_err(|e| Error::CryptoError(format!("Failed to generate IV: {}", e)))?;

        #[allow(deprecated)]
        let nonce = Nonce::<U32>::from_slice(&iv);

        // Encrypt (aes-gcm appends the auth tag to the ciphertext)
        let ciphertext_with_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| Error::CryptoError("Encryption failed".to_string()))?;

        // Build output: IV || ciphertext || tag
        // Note: aes-gcm returns ciphertext || tag, so we just prepend IV
        let mut result = Vec::with_capacity(IV_SIZE + ciphertext_with_tag.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext_with_tag);

        Ok(result)
    }

    /// Decrypts ciphertext using AES-256-GCM.
    ///
    /// Expects input in the format: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`
    ///
    /// # Arguments
    ///
    /// * `data` - The encrypted data (IV + ciphertext + auth tag)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input is too short (less than 48 bytes: 32 IV + 16 tag)
    /// - Decryption fails (authentication tag doesn't match)
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_primitives::symmetric::SymmetricKey;
    ///
    /// let key = SymmetricKey::random();
    /// let plaintext = b"Hello, BSV!";
    ///
    /// let ciphertext = key.encrypt(plaintext).expect("encryption failed");
    /// let decrypted = key.decrypt(&ciphertext).expect("decryption failed");
    ///
    /// assert_eq!(plaintext, &decrypted[..]);
    /// ```
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Check minimum length
        if data.len() < MIN_CIPHERTEXT_SIZE {
            return Err(Error::InvalidDataLength {
                expected: MIN_CIPHERTEXT_SIZE,
                actual: data.len(),
            });
        }

        // Create cipher
        let cipher = Aes256Gcm32::new_from_slice(&self.key)
            .map_err(|e| Error::CryptoError(format!("Failed to create cipher: {}", e)))?;

        // Extract IV and ciphertext (including tag)
        let (iv, ciphertext_with_tag) = data.split_at(IV_SIZE);
        #[allow(deprecated)]
        let nonce = Nonce::<U32>::from_slice(iv);

        // Decrypt (aes-gcm expects ciphertext || tag format)
        cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| Error::DecryptionFailed)
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose key bytes in debug output
        f.debug_struct("SymmetricKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        self.key.ct_eq(&other.key).into()
    }
}

impl Eq for SymmetricKey {}

// Ensure key is zeroed when dropped
impl Drop for SymmetricKey {
    fn drop(&mut self) {
        // Zero out key bytes
        // Note: This may be optimized away by the compiler in some cases.
        // For production use, consider using `zeroize` crate.
        self.key.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_key() {
        let key1 = SymmetricKey::random();
        let key2 = SymmetricKey::random();

        // Random keys should be different
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(key1.as_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes_32() {
        let bytes = [0xABu8; 32];
        let key = SymmetricKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_from_bytes_31_padding() {
        // 31-byte key should be padded with leading zero
        let key_31 = vec![0xFFu8; 31];
        let sym_key = SymmetricKey::from_bytes(&key_31).unwrap();

        // First byte should be 0x00 (padding)
        assert_eq!(sym_key.as_bytes()[0], 0x00);
        // Rest should be 0xFF
        assert_eq!(sym_key.as_bytes()[1], 0xFF);
        assert_eq!(sym_key.as_bytes()[31], 0xFF);
    }

    #[test]
    fn test_from_bytes_short_key() {
        // 16-byte key should be padded to 32 bytes
        let key_16 = vec![0xABu8; 16];
        let sym_key = SymmetricKey::from_bytes(&key_16).unwrap();

        // First 16 bytes should be 0x00 (padding)
        for i in 0..16 {
            assert_eq!(sym_key.as_bytes()[i], 0x00);
        }
        // Last 16 bytes should be 0xAB
        for i in 16..32 {
            assert_eq!(sym_key.as_bytes()[i], 0xAB);
        }
    }

    #[test]
    fn test_from_bytes_empty() {
        let result = SymmetricKey::from_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_too_long() {
        let bytes = [0u8; 33];
        let result = SymmetricKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::random();
        let plaintext = b"Hello, BSV!";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_empty_plaintext() {
        let key = SymmetricKey::random();
        let plaintext = b"";

        let ciphertext = key.encrypt(plaintext).unwrap();
        // Should be IV (32) + tag (16) = 48 bytes
        assert_eq!(ciphertext.len(), 48);

        let decrypted = key.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        let key = SymmetricKey::random();
        let plaintext = vec![0xABu8; 10000];

        let ciphertext = key.encrypt(&plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_ciphertext_format() {
        let key = SymmetricKey::random();
        let plaintext = b"test";

        let ciphertext = key.encrypt(plaintext).unwrap();

        // Format: IV (32) + encrypted data (4) + tag (16) = 52 bytes
        assert_eq!(ciphertext.len(), 32 + 4 + 16);
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = SymmetricKey::random();

        // Less than minimum (IV + tag = 48 bytes)
        let short_data = vec![0u8; 47];
        let result = key.decrypt(&short_data);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = SymmetricKey::random();
        let key2 = SymmetricKey::random();
        let plaintext = b"Hello, BSV!";

        let ciphertext = key1.encrypt(plaintext).unwrap();
        let result = key2.decrypt(&ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = SymmetricKey::random();
        let plaintext = b"Hello, BSV!";

        let mut ciphertext = key.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext (not the IV or tag)
        if ciphertext.len() > 40 {
            ciphertext[40] ^= 0xFF;
        }

        let result = key.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_tag() {
        let key = SymmetricKey::random();
        let plaintext = b"Hello, BSV!";

        let mut ciphertext = key.encrypt(plaintext).unwrap();

        // Tamper with the last byte (part of auth tag)
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0xFF;

        let result = key.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertexts() {
        let key = SymmetricKey::random();
        let plaintext = b"Hello, BSV!";

        let ciphertext1 = key.encrypt(plaintext).unwrap();
        let ciphertext2 = key.encrypt(plaintext).unwrap();

        // Different IVs should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = key.decrypt(&ciphertext1).unwrap();
        let decrypted2 = key.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_key_equality_constant_time() {
        let bytes1 = [0xABu8; 32];
        let bytes2 = [0xABu8; 32];
        let bytes3 = [0xCDu8; 32];

        let key1 = SymmetricKey::from_bytes(&bytes1).unwrap();
        let key2 = SymmetricKey::from_bytes(&bytes2).unwrap();
        let key3 = SymmetricKey::from_bytes(&bytes3).unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_debug_redacts_key() {
        let key = SymmetricKey::random();
        let debug_output = format!("{:?}", key);

        // Should not contain actual key bytes
        assert!(debug_output.contains("REDACTED"));
    }

    // Cross-SDK compatibility tests using test vectors from Go/TypeScript SDKs
    mod cross_sdk_tests {
        use super::SymmetricKey;

        /// Decode hex string to bytes
        fn hex_decode(s: &str) -> Vec<u8> {
            hex::decode(s).expect("Invalid hex string")
        }

        /// 31-byte key derived from WIF "L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx"
        /// This is the X coordinate of the public key (31 bytes, so it gets padded)
        fn get_31_byte_key() -> SymmetricKey {
            // X coordinate from Go SDK: 6f54f86a07f22ac6934a61e5a2bf0da03ce1cd6e6f978bfd064a37d0e1a111
            // This is 31 bytes, so SymmetricKey::from_bytes will pad with leading zero
            let key_bytes =
                hex_decode("6f54f86a07f22ac6934a61e5a2bf0da03ce1cd6e6f978bfd064a37d0e1a111");
            assert_eq!(key_bytes.len(), 31, "Expected 31-byte key");
            SymmetricKey::from_bytes(&key_bytes).unwrap()
        }

        /// 32-byte key derived from WIF "KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9"
        /// This is the X coordinate of the public key (exactly 32 bytes)
        fn get_32_byte_key() -> SymmetricKey {
            // X coordinate from Go SDK: cb3b4168ccd86a783945e4cf69243d1b546078610cb9cee3e9beeed2428aa54e
            let key_bytes =
                hex_decode("cb3b4168ccd86a783945e4cf69243d1b546078610cb9cee3e9beeed2428aa54e");
            assert_eq!(key_bytes.len(), 32, "Expected 32-byte key");
            SymmetricKey::from_bytes(&key_bytes).unwrap()
        }

        const EXPECTED_PLAINTEXT: &[u8] = b"cross-sdk test message";

        #[test]
        fn test_decrypt_typescript_ciphertext_31_byte_key() {
            // From Go SDK symmetric_compatibility_test.go
            // WIF: L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx
            // Expected plaintext: "cross-sdk test message"

            let key = get_31_byte_key();

            // Verify the key was padded correctly (leading zero)
            assert_eq!(
                key.as_bytes()[0],
                0x00,
                "31-byte key should be padded with leading zero"
            );
            assert_eq!(
                key.as_bytes()[1],
                0x6f,
                "First byte of original key should be at index 1"
            );

            let ts_ciphertexts = [
                "c374d70a4623036f1dd7b971dbeeea375630dc1da40e7068f4c4aa03487d3b19de3afb26a29173deccfbb1ece4fee6c92406b25948e6fe9cb53383057cb826d0a20269e290bd",
                "1025d330504549601a611b75af4450722353f431ca2fc3f6aed41ca7b53e7859fa9cfea4654c871668449308c420282b372c1008dcd7a21fb5b1410c4f3a913c74c86a1aa070",
                "efb87383667dda0bca519acb50a264cb958447f6d0f5cb20adace5fae8e812d4c39b569ad8a64ba70ca5a941d8096ded43a45cde8eec16b6a396112c248effce132797a73698",
            ];

            for (i, hex_ciphertext) in ts_ciphertexts.iter().enumerate() {
                let ciphertext = hex_decode(hex_ciphertext);
                let decrypted = key.decrypt(&ciphertext).unwrap_or_else(|_| {
                    panic!("Failed to decrypt TS ciphertext {} with 31-byte key", i)
                });
                assert_eq!(
                    decrypted, EXPECTED_PLAINTEXT,
                    "TS ciphertext {} decryption mismatch",
                    i
                );
            }
        }

        #[test]
        fn test_decrypt_go_ciphertext_31_byte_key() {
            // Go-generated ciphertext from symmetric_compatibility_test.go
            let key = get_31_byte_key();

            let go_ciphertext = "7604d5bdb0eb843051d21873c871c9b1507c3de7ba222e1b407c163c2c166277df95de73be9534a2caf9d4b72157f78e5e2e69d97bc25b18ff4cfbd61a1306c02c0b8b2d165e";

            let ciphertext = hex_decode(go_ciphertext);
            let decrypted = key
                .decrypt(&ciphertext)
                .expect("Failed to decrypt Go ciphertext with 31-byte key");
            assert_eq!(decrypted, EXPECTED_PLAINTEXT);
        }

        #[test]
        fn test_decrypt_typescript_ciphertext_32_byte_key() {
            // From Go SDK symmetric_compatibility_test.go
            // WIF: KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9
            // Expected plaintext: "cross-sdk test message"

            let key = get_32_byte_key();

            let ts_ciphertexts = [
                "2059fc32910bef280d89c4c7edbbc587b31be22339e609fdcc23319bf458840a91ad1b2da87aea13a5dc5cb3469b41c52001070b8003863843978acbdf57755b24491581a059",
                "b6b751277049399fdf5d35fda899c8433509268b0528c25ac8cf60c23dbeef23441c9efcdb996312c6aa32352637789bcf19d02b990903003a9a894efe874a65e84b6e57d30b",
            ];

            for (i, hex_ciphertext) in ts_ciphertexts.iter().enumerate() {
                let ciphertext = hex_decode(hex_ciphertext);
                let decrypted = key.decrypt(&ciphertext).unwrap_or_else(|_| {
                    panic!("Failed to decrypt TS ciphertext {} with 32-byte key", i)
                });
                assert_eq!(
                    decrypted, EXPECTED_PLAINTEXT,
                    "TS ciphertext {} decryption mismatch",
                    i
                );
            }
        }

        #[test]
        fn test_decrypt_go_ciphertext_32_byte_key() {
            // Go-generated ciphertext from symmetric_compatibility_test.go
            let key = get_32_byte_key();

            let go_ciphertext = "d7744c85ad3dafcb9fc5752ab0d04c40f87084e8a466f6b6013ebe0fc5170daab8184aaef66ab2c2733f01c0dc3de322ba3ddeea976499548bc6ec166581181f919c69aa2de5";

            let ciphertext = hex_decode(go_ciphertext);
            let decrypted = key
                .decrypt(&ciphertext)
                .expect("Failed to decrypt Go ciphertext with 32-byte key");
            assert_eq!(decrypted, EXPECTED_PLAINTEXT);
        }

        #[test]
        fn test_rust_encrypt_can_be_decrypted() {
            // Verify Rust-encrypted data can decrypt correctly
            let key = get_32_byte_key();
            let ciphertext = key.encrypt(EXPECTED_PLAINTEXT).unwrap();
            let decrypted = key.decrypt(&ciphertext).unwrap();
            assert_eq!(decrypted, EXPECTED_PLAINTEXT);
        }

        #[test]
        fn test_31_byte_key_padding_matches_go() {
            // Verify that our padding produces the same 32-byte key as Go
            let key_31_bytes =
                hex_decode("6f54f86a07f22ac6934a61e5a2bf0da03ce1cd6e6f978bfd064a37d0e1a111");
            let sym_key = SymmetricKey::from_bytes(&key_31_bytes).unwrap();

            // Expected: [0x00, 0x6f, 0x54, 0xf8, ...]
            let expected_padded =
                hex_decode("006f54f86a07f22ac6934a61e5a2bf0da03ce1cd6e6f978bfd064a37d0e1a111");
            assert_eq!(sym_key.as_bytes(), expected_padded.as_slice());
        }
    }

    // Test vectors from JSON file
    mod vector_tests {
        use super::*;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        #[derive(Debug, serde::Deserialize)]
        struct TestVector {
            ciphertext: String,
            key: String,
            plaintext: String,
        }

        fn load_test_vectors() -> Vec<TestVector> {
            let json_str = include_str!("../tests/vectors/symmetric_key.json");
            serde_json::from_str(json_str).expect("Failed to parse test vectors")
        }

        #[test]
        fn test_decrypt_vectors() {
            let vectors = load_test_vectors();

            for (i, vector) in vectors.iter().enumerate() {
                // Decode base64 encoded key and ciphertext
                let key_bytes = BASE64
                    .decode(&vector.key)
                    .unwrap_or_else(|_| panic!("Failed to decode key for vector {}", i));
                let ciphertext = BASE64
                    .decode(&vector.ciphertext)
                    .unwrap_or_else(|_| panic!("Failed to decode ciphertext for vector {}", i));

                // Plaintext is stored as raw UTF-8 string (not base64 encoded)
                // Note: Some plaintexts happen to BE base64 strings (random bytes for testing)
                let expected_plaintext = vector.plaintext.as_bytes();

                // Create symmetric key
                let sym_key = SymmetricKey::from_bytes(&key_bytes)
                    .unwrap_or_else(|_| panic!("Failed to create key for vector {}", i));

                // Decrypt
                let decrypted = sym_key
                    .decrypt(&ciphertext)
                    .unwrap_or_else(|_| panic!("Failed to decrypt vector {}", i));

                assert_eq!(
                    decrypted, expected_plaintext,
                    "Vector {} decryption mismatch",
                    i
                );
            }
        }

        #[test]
        fn test_encrypt_decrypt_vectors() {
            let vectors = load_test_vectors();

            for (i, vector) in vectors.iter().enumerate() {
                // Decode base64 encoded key
                let key_bytes = BASE64
                    .decode(&vector.key)
                    .unwrap_or_else(|_| panic!("Failed to decode key for vector {}", i));

                // Plaintext is stored as raw UTF-8 string
                let plaintext = vector.plaintext.as_bytes();

                // Create symmetric key
                let sym_key = SymmetricKey::from_bytes(&key_bytes)
                    .unwrap_or_else(|_| panic!("Failed to create key for vector {}", i));

                // Encrypt then decrypt (should work with our implementation)
                let ciphertext = sym_key
                    .encrypt(plaintext)
                    .unwrap_or_else(|_| panic!("Failed to encrypt vector {}", i));
                let decrypted = sym_key.decrypt(&ciphertext).unwrap_or_else(|_| {
                    panic!("Failed to decrypt our ciphertext for vector {}", i)
                });

                assert_eq!(decrypted, plaintext, "Vector {} round-trip mismatch", i);
            }
        }
    }
}
