//! ECIES (Elliptic Curve Integrated Encryption Scheme) implementations.
//!
//! This module provides two ECIES variants commonly used in the Bitcoin ecosystem:
//!
//! - **Electrum ECIES**: Used by Electrum wallet, produces output prefixed with "BIE1"
//! - **Bitcore ECIES**: Used by Bitcore library
//!
//! Both use AES-128/256-CBC with PKCS7 padding for symmetric encryption and
//! HMAC-SHA256 for message authentication.
//!
//! # Electrum ECIES
//!
//! ```text
//! Output: "BIE1" || [ephemeral_pubkey (33)] || ciphertext || mac (32)
//! Key derivation: SHA512(compressed_shared_secret) → iv[0:16], aes_key[16:32], hmac_key[32:64]
//! Encryption: AES-128-CBC(message, aes_key, iv)
//! MAC: HMAC-SHA256(hmac_key, "BIE1" || [pubkey] || ciphertext)
//! ```
//!
//! # Bitcore ECIES
//!
//! ```text
//! Output: pubkey (33) || iv (16) || ciphertext || mac (32)
//! Key derivation: SHA512(shared_secret.x) → key_e[0:32], key_m[32:64]
//! Encryption: AES-256-CBC(message, SHA256(key_e), iv)
//! MAC: HMAC-SHA256(key_m, iv || pubkey || ciphertext)
//! ```
//!
//! # Examples
//!
//! ```rust
//! use bsv_sdk::compat::ecies;
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let alice = PrivateKey::random();
//! let bob = PrivateKey::random();
//! let message = b"Hello, BSV!";
//!
//! // Electrum ECIES
//! let encrypted = ecies::electrum_encrypt(message, &bob.public_key(), &alice, false).unwrap();
//! let decrypted = ecies::electrum_decrypt(&encrypted, &bob, Some(&alice.public_key())).unwrap();
//! assert_eq!(decrypted, message);
//!
//! // Bitcore ECIES
//! let encrypted = ecies::bitcore_encrypt(message, &bob.public_key(), &alice, None).unwrap();
//! let decrypted = ecies::bitcore_decrypt(&encrypted, &bob).unwrap();
//! assert_eq!(decrypted, message);
//! ```

use crate::error::{Error, Result};
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::primitives::hash::{sha256_hmac, sha512};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

/// AES-128-CBC encryptor type
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
/// AES-128-CBC decryptor type
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
/// AES-256-CBC encryptor type
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
/// AES-256-CBC decryptor type
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Electrum ECIES magic bytes
const ELECTRUM_MAGIC: &[u8] = b"BIE1";

/// Encrypts a message using Electrum ECIES.
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `to` - The recipient's public key
/// * `from` - The sender's private key (ephemeral key used if None would be passed)
/// * `no_key` - If true, omit the ephemeral public key from the output
///
/// # Returns
///
/// The encrypted message: "BIE1" || \[pubkey\] || ciphertext || mac
///
/// # Algorithm
///
/// 1. Compute ECDH shared secret
/// 2. Derive keys: SHA512(compressed_shared) → iv\[0:16\], aes_key\[16:32\], hmac_key\[32:64\]
/// 3. Encrypt: AES-128-CBC(message, aes_key, iv) with PKCS7 padding
/// 4. MAC: HMAC-SHA256(hmac_key, "BIE1" || \[pubkey\] || ciphertext)
/// 5. Output: "BIE1" || \[pubkey\] || ciphertext || mac
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::ecies;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let encrypted = ecies::electrum_encrypt(
///     b"Hello!",
///     &recipient.public_key(),
///     &sender,
///     false
/// ).unwrap();
/// ```
pub fn electrum_encrypt(
    message: &[u8],
    to: &PublicKey,
    from: &PrivateKey,
    no_key: bool,
) -> Result<Vec<u8>> {
    // Compute ECDH shared secret
    let shared_secret = from.derive_shared_secret(to)?;
    let shared_compressed = shared_secret.to_compressed();

    // Derive keys: SHA512(compressed_shared)
    let key_material = sha512(&shared_compressed);
    let iv: [u8; 16] = key_material[0..16].try_into().unwrap();
    let aes_key: [u8; 16] = key_material[16..32].try_into().unwrap();
    let hmac_key = &key_material[32..64];

    // Encrypt with AES-128-CBC
    let ciphertext = aes_128_cbc_encrypt(message, &aes_key, &iv)?;

    // Build output
    let ephemeral_pubkey = from.public_key();
    let mut encrypted = Vec::with_capacity(4 + 33 + ciphertext.len() + 32);
    encrypted.extend_from_slice(ELECTRUM_MAGIC);
    if !no_key {
        encrypted.extend_from_slice(&ephemeral_pubkey.to_compressed());
    }
    encrypted.extend_from_slice(&ciphertext);

    // Compute MAC over everything except MAC itself
    let mac = sha256_hmac(hmac_key, &encrypted);
    encrypted.extend_from_slice(&mac);

    Ok(encrypted)
}

/// Decrypts a message encrypted with Electrum ECIES.
///
/// # Arguments
///
/// * `data` - The encrypted data: "BIE1" || \[pubkey\] || ciphertext || mac
/// * `to` - The recipient's private key
/// * `from` - The sender's public key (if known/expected)
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::ecies;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let encrypted = ecies::electrum_encrypt(
///     b"Hello!",
///     &recipient.public_key(),
///     &sender,
///     false
/// ).unwrap();
///
/// let decrypted = ecies::electrum_decrypt(
///     &encrypted,
///     &recipient,
///     Some(&sender.public_key())
/// ).unwrap();
/// assert_eq!(decrypted, b"Hello!");
/// ```
pub fn electrum_decrypt(data: &[u8], to: &PrivateKey, from: Option<&PublicKey>) -> Result<Vec<u8>> {
    // Minimum length: 4 (magic) + 16 (min cipher block) + 32 (mac)
    if data.len() < 52 {
        return Err(Error::EciesDecryptionFailed("Data too short".to_string()));
    }

    // Verify magic bytes
    if &data[0..4] != ELECTRUM_MAGIC {
        return Err(Error::EciesDecryptionFailed(
            "Invalid magic bytes".to_string(),
        ));
    }

    // Determine shared secret and ciphertext location
    let (shared_secret, ciphertext) = if let Some(from_pubkey) = from {
        // Use provided counterparty public key
        let shared = to.derive_shared_secret(from_pubkey)?;

        // Ciphertext location depends on whether ephemeral key is present
        // If data is large enough to contain pubkey (4 + 33 + 32 = 69 min with pubkey)
        let ct = if data.len() > 69 {
            // Has pubkey embedded
            &data[37..data.len() - 32]
        } else {
            // No pubkey (noKey mode)
            &data[4..data.len() - 32]
        };

        (shared, ct.to_vec())
    } else {
        // Extract ephemeral public key from data
        if data.len() < 69 {
            return Err(Error::EciesDecryptionFailed(
                "Data too short for embedded public key".to_string(),
            ));
        }

        let ephemeral_pubkey = PublicKey::from_bytes(&data[4..37])?;
        let shared = to.derive_shared_secret(&ephemeral_pubkey)?;
        let ct = &data[37..data.len() - 32];

        (shared, ct.to_vec())
    };

    // Derive keys
    let shared_compressed = shared_secret.to_compressed();
    let key_material = sha512(&shared_compressed);
    let iv: [u8; 16] = key_material[0..16].try_into().unwrap();
    let aes_key: [u8; 16] = key_material[16..32].try_into().unwrap();
    let hmac_key = &key_material[32..64];

    // Verify MAC
    let mac = &data[data.len() - 32..];
    let data_without_mac = &data[..data.len() - 32];
    let expected_mac = sha256_hmac(hmac_key, data_without_mac);

    if !constant_time_eq(mac, &expected_mac) {
        return Err(Error::EciesHmacMismatch);
    }

    // Decrypt
    aes_128_cbc_decrypt(&ciphertext, &aes_key, &iv)
}

/// Encrypts a message using Bitcore ECIES.
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `to` - The recipient's public key
/// * `from` - The sender's private key
/// * `iv` - Optional 16-byte IV (zeros if not provided)
///
/// # Returns
///
/// The encrypted message: pubkey (33) || iv (16) || ciphertext || mac (32)
///
/// # Algorithm
///
/// 1. Compute ECDH shared secret
/// 2. Derive keys: SHA512(shared_secret.x) → key_e\[0:32\], key_m\[32:64\]
/// 3. Encrypt: AES-256-CBC(message, key_e, iv) with PKCS7 padding
/// 4. MAC: HMAC-SHA256(key_m, iv || ciphertext)
/// 5. Output: pubkey || iv || ciphertext || mac
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::ecies;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let encrypted = ecies::bitcore_encrypt(
///     b"Hello!",
///     &recipient.public_key(),
///     &sender,
///     None
/// ).unwrap();
/// ```
pub fn bitcore_encrypt(
    message: &[u8],
    to: &PublicKey,
    from: &PrivateKey,
    iv: Option<&[u8; 16]>,
) -> Result<Vec<u8>> {
    // Use provided IV or zeros (matching Go SDK behavior)
    let iv = iv.copied().unwrap_or([0u8; 16]);

    // Compute ECDH shared secret
    let shared_secret = from.derive_shared_secret(to)?;

    // Key derivation from X coordinate only
    let x_coord = shared_secret.x();
    let key_material = sha512(&x_coord);
    let key_e: [u8; 32] = key_material[0..32].try_into().unwrap();
    let key_m = &key_material[32..64];

    // Encrypt with AES-256-CBC (key_e used directly, not hashed)
    let ciphertext = aes_256_cbc_encrypt(message, &key_e, &iv)?;

    // Get sender's public key (compressed DER format for Bitcore)
    let sender_pubkey = from.public_key().to_compressed();

    // Build iv || ciphertext for MAC computation
    let mut iv_cipher = Vec::with_capacity(16 + ciphertext.len());
    iv_cipher.extend_from_slice(&iv);
    iv_cipher.extend_from_slice(&ciphertext);

    // MAC: HMAC-SHA256(key_m, iv || ciphertext)
    let mac = sha256_hmac(key_m, &iv_cipher);

    // Build output: pubkey || iv || ciphertext || mac
    let mut encrypted = Vec::with_capacity(33 + 16 + ciphertext.len() + 32);
    encrypted.extend_from_slice(&sender_pubkey);
    encrypted.extend_from_slice(&iv);
    encrypted.extend_from_slice(&ciphertext);
    encrypted.extend_from_slice(&mac);

    Ok(encrypted)
}

/// Decrypts a message encrypted with Bitcore ECIES.
///
/// # Arguments
///
/// * `data` - The encrypted data: pubkey (33) || iv (16) || ciphertext || mac (32)
/// * `to` - The recipient's private key
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::ecies;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let encrypted = ecies::bitcore_encrypt(
///     b"Hello!",
///     &recipient.public_key(),
///     &sender,
///     None
/// ).unwrap();
///
/// let decrypted = ecies::bitcore_decrypt(&encrypted, &recipient).unwrap();
/// assert_eq!(decrypted, b"Hello!");
/// ```
pub fn bitcore_decrypt(data: &[u8], to: &PrivateKey) -> Result<Vec<u8>> {
    // Minimum length: 33 (pubkey) + 16 (iv) + 16 (min block) + 32 (mac)
    if data.len() < 97 {
        return Err(Error::EciesDecryptionFailed("Data too short".to_string()));
    }

    // Parse components: pubkey (33) || iv || ciphertext || mac (32)
    let from_pubkey = PublicKey::from_bytes(&data[0..33])?;
    let iv_and_ciphertext = &data[33..data.len() - 32];
    let mac = &data[data.len() - 32..];

    // Extract IV from the start
    if iv_and_ciphertext.len() < 16 {
        return Err(Error::EciesDecryptionFailed(
            "Data too short for IV".to_string(),
        ));
    }
    let iv: [u8; 16] = iv_and_ciphertext[0..16].try_into().unwrap();
    let ciphertext = &iv_and_ciphertext[16..];

    // Compute ECDH shared secret
    let shared_secret = to.derive_shared_secret(&from_pubkey)?;

    // Key derivation from X coordinate only
    let x_coord = shared_secret.x();
    let key_material = sha512(&x_coord);
    let key_e: [u8; 32] = key_material[0..32].try_into().unwrap();
    let key_m = &key_material[32..64];

    // Verify MAC (over iv || ciphertext)
    let expected_mac = sha256_hmac(key_m, iv_and_ciphertext);
    if !constant_time_eq(mac, &expected_mac) {
        return Err(Error::EciesHmacMismatch);
    }

    // Decrypt (key_e used directly, not hashed)
    aes_256_cbc_decrypt(ciphertext, &key_e, &iv)
}

/// Convenience function to encrypt a message using one's own public key.
///
/// This is equivalent to `electrum_encrypt(message, key.public_key(), key, false)`.
///
/// # Arguments
///
/// * `message` - The plaintext message
/// * `key` - The private key (used as both sender and recipient)
///
/// # Returns
///
/// The encrypted message (Electrum ECIES format)
pub fn encrypt_single(message: &[u8], key: &PrivateKey) -> Result<Vec<u8>> {
    electrum_encrypt(message, &key.public_key(), key, false)
}

/// Convenience function to decrypt a message encrypted with `encrypt_single`.
///
/// # Arguments
///
/// * `data` - The encrypted data
/// * `key` - The private key used during encryption
///
/// # Returns
///
/// The decrypted plaintext
pub fn decrypt_single(data: &[u8], key: &PrivateKey) -> Result<Vec<u8>> {
    electrum_decrypt(data, key, None)
}

// =============================================================================
// AES-CBC Helper Functions
// =============================================================================

/// Encrypts data using AES-128-CBC with PKCS7 padding.
fn aes_128_cbc_encrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes128CbcEnc::new(key.into(), iv.into());
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// Decrypts data using AES-128-CBC with PKCS7 padding.
fn aes_128_cbc_decrypt(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes128CbcDec::new(key.into(), iv.into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| Error::EciesDecryptionFailed("AES decryption failed".to_string()))
}

/// Encrypts data using AES-256-CBC with PKCS7 padding.
fn aes_256_cbc_encrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcEnc::new(key.into(), iv.into());
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// Decrypts data using AES-256-CBC with PKCS7 padding.
fn aes_256_cbc_decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| Error::EciesDecryptionFailed("AES decryption failed".to_string()))
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_electrum_encrypt_decrypt() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Hello, ECIES!";

        let encrypted = electrum_encrypt(message, &recipient.public_key(), &sender, false).unwrap();

        // Decrypt with sender's public key
        let decrypted =
            electrum_decrypt(&encrypted, &recipient, Some(&sender.public_key())).unwrap();
        assert_eq!(decrypted, message);

        // Decrypt without sender's public key (extracts from encrypted data)
        let decrypted2 = electrum_decrypt(&encrypted, &recipient, None).unwrap();
        assert_eq!(decrypted2, message);
    }

    #[test]
    fn test_electrum_no_key_mode() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Hello, ECIES!";

        // Encrypt with noKey=true (omit ephemeral public key)
        let encrypted = electrum_encrypt(message, &recipient.public_key(), &sender, true).unwrap();

        // Verify it's shorter (no 33-byte pubkey)
        assert!(encrypted.len() < 4 + 33 + 16 + 32);

        // Must provide sender's public key to decrypt
        let decrypted =
            electrum_decrypt(&encrypted, &recipient, Some(&sender.public_key())).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_bitcore_encrypt_decrypt() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Hello, Bitcore ECIES!";

        let encrypted = bitcore_encrypt(message, &recipient.public_key(), &sender, None).unwrap();

        let decrypted = bitcore_decrypt(&encrypted, &recipient).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_bitcore_with_fixed_iv() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Test message";
        let iv = [0u8; 16];

        let encrypted1 =
            bitcore_encrypt(message, &recipient.public_key(), &sender, Some(&iv)).unwrap();
        let encrypted2 =
            bitcore_encrypt(message, &recipient.public_key(), &sender, Some(&iv)).unwrap();

        // Same IV should produce same ciphertext (deterministic)
        assert_eq!(encrypted1, encrypted2);

        let decrypted = bitcore_decrypt(&encrypted1, &recipient).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_single() {
        let key = PrivateKey::random();
        let message = b"Self-encrypted message";

        let encrypted = encrypt_single(message, &key).unwrap();
        let decrypted = decrypt_single(&encrypted, &key).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_electrum_empty_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"";

        let encrypted = electrum_encrypt(message, &recipient.public_key(), &sender, false).unwrap();
        let decrypted = electrum_decrypt(&encrypted, &recipient, None).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_bitcore_empty_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"";

        let encrypted = bitcore_encrypt(message, &recipient.public_key(), &sender, None).unwrap();
        let decrypted = bitcore_decrypt(&encrypted, &recipient).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_electrum_large_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = vec![0xab; 10000];

        let encrypted =
            electrum_encrypt(&message, &recipient.public_key(), &sender, false).unwrap();
        let decrypted = electrum_decrypt(&encrypted, &recipient, None).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_bitcore_large_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = vec![0xcd; 10000];

        let encrypted = bitcore_encrypt(&message, &recipient.public_key(), &sender, None).unwrap();
        let decrypted = bitcore_decrypt(&encrypted, &recipient).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_electrum_wrong_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let wrong_recipient = PrivateKey::random();
        let message = b"Secret message";

        let encrypted = electrum_encrypt(message, &recipient.public_key(), &sender, false).unwrap();

        // Wrong recipient should fail HMAC verification
        let result = electrum_decrypt(&encrypted, &wrong_recipient, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitcore_wrong_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let wrong_recipient = PrivateKey::random();
        let message = b"Secret message";

        let encrypted = bitcore_encrypt(message, &recipient.public_key(), &sender, None).unwrap();

        // Wrong recipient should fail HMAC verification
        let result = bitcore_decrypt(&encrypted, &wrong_recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_electrum_tampered_data() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Original message";

        let mut encrypted =
            electrum_encrypt(message, &recipient.public_key(), &sender, false).unwrap();

        // Tamper with ciphertext
        let tamper_idx = 40; // Somewhere in ciphertext
        encrypted[tamper_idx] ^= 0xff;

        // Should fail HMAC verification
        let result = electrum_decrypt(&encrypted, &recipient, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitcore_tampered_data() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Original message";

        let mut encrypted =
            bitcore_encrypt(message, &recipient.public_key(), &sender, None).unwrap();

        // Tamper with ciphertext
        let tamper_idx = 50; // Somewhere in ciphertext
        encrypted[tamper_idx] ^= 0xff;

        // Should fail HMAC verification
        let result = bitcore_decrypt(&encrypted, &recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_electrum_invalid_magic() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"BAD!");

        let recipient = PrivateKey::random();
        let result = electrum_decrypt(&data, &recipient, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_electrum_too_short() {
        let recipient = PrivateKey::random();

        // Too short
        let result = electrum_decrypt(&[0u8; 20], &recipient, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_bitcore_too_short() {
        let recipient = PrivateKey::random();

        // Too short
        let result = bitcore_decrypt(&[0u8; 50], &recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_128_cbc_roundtrip() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 16];
        let plaintext = b"Test AES-128-CBC";

        let ciphertext = aes_128_cbc_encrypt(plaintext, &key, &iv).unwrap();
        let decrypted = aes_128_cbc_decrypt(&ciphertext, &key, &iv).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_256_cbc_roundtrip() {
        let key = [0x03u8; 32];
        let iv = [0x04u8; 16];
        let plaintext = b"Test AES-256-CBC";

        let ciphertext = aes_256_cbc_encrypt(plaintext, &key, &iv).unwrap();
        let decrypted = aes_256_cbc_decrypt(&ciphertext, &key, &iv).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_padding() {
        // Test various message lengths to verify PKCS7 padding
        let key = [0x05u8; 16];
        let iv = [0x06u8; 16];

        for len in 0..50 {
            let plaintext = vec![0x42u8; len];
            let ciphertext = aes_128_cbc_encrypt(&plaintext, &key, &iv).unwrap();
            let decrypted = aes_128_cbc_decrypt(&ciphertext, &key, &iv).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_known_electrum_vector() {
        // Test with known keys and verify the structure
        let sender = PrivateKey::from_hex(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let recipient = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let message = b"Hello, BSV!";

        let encrypted = electrum_encrypt(message, &recipient.public_key(), &sender, false).unwrap();

        // Verify magic bytes
        assert_eq!(&encrypted[0..4], b"BIE1");

        // Verify we can decrypt
        let decrypted = electrum_decrypt(&encrypted, &recipient, None).unwrap();
        assert_eq!(decrypted, message);
    }
}
