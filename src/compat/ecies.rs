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
//! use bsv_rs::compat::ecies;
//! use bsv_rs::primitives::ec::PrivateKey;
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

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
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
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
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
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
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
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
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

/// Self-encrypt a message and return base64-encoded result.
///
/// This is a convenience wrapper around `encrypt_single` that returns the
/// encrypted data as a base64 string, matching the Go SDK's `EncryptSingle` API.
///
/// # Arguments
///
/// * `message` - The plaintext message
/// * `key` - The private key (used as both sender and recipient)
///
/// # Returns
///
/// Base64-encoded encrypted data (Electrum ECIES format)
///
/// # Example
///
/// ```rust
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let encrypted = ecies::encrypt_single_base64(b"Hello!", &key).unwrap();
/// let decrypted = ecies::decrypt_single_base64(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, b"Hello!");
/// ```
pub fn encrypt_single_base64(message: &[u8], key: &PrivateKey) -> Result<String> {
    let encrypted = encrypt_single(message, key)?;
    Ok(BASE64.encode(&encrypted))
}

/// Decrypt base64-encoded self-encrypted data.
///
/// This is a convenience wrapper around `decrypt_single` that accepts
/// base64-encoded input, matching the Go SDK's `DecryptSingle` API.
///
/// # Arguments
///
/// * `data` - Base64-encoded encrypted data
/// * `key` - The private key used during encryption
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let encrypted = ecies::encrypt_single_base64(b"Hello!", &key).unwrap();
/// let decrypted = ecies::decrypt_single_base64(&encrypted, &key).unwrap();
/// assert_eq!(decrypted, b"Hello!");
/// ```
pub fn decrypt_single_base64(data: &str, key: &PrivateKey) -> Result<Vec<u8>> {
    let encrypted = BASE64
        .decode(data)
        .map_err(|e| Error::EciesDecryptionFailed(format!("invalid base64: {}", e)))?;
    decrypt_single(&encrypted, key)
}

/// Two-party encrypt a message and return base64-encoded result.
///
/// This is a convenience wrapper around `electrum_encrypt` that returns the
/// encrypted data as a base64 string, matching the Go SDK's `EncryptShared` API.
///
/// # Arguments
///
/// * `message` - The plaintext message
/// * `to_public_key` - The recipient's public key
/// * `from_private_key` - The sender's private key
///
/// # Returns
///
/// Base64-encoded encrypted data (Electrum ECIES format)
///
/// # Example
///
/// ```rust
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let alice = PrivateKey::random();
/// let bob = PrivateKey::random();
///
/// let encrypted = ecies::encrypt_shared_base64(
///     b"Hello Bob!",
///     &bob.public_key(),
///     &alice
/// ).unwrap();
///
/// let decrypted = ecies::decrypt_shared_base64(
///     &encrypted,
///     &bob,
///     &alice.public_key()
/// ).unwrap();
/// assert_eq!(decrypted, b"Hello Bob!");
/// ```
pub fn encrypt_shared_base64(
    message: &[u8],
    to_public_key: &PublicKey,
    from_private_key: &PrivateKey,
) -> Result<String> {
    let encrypted = electrum_encrypt(message, to_public_key, from_private_key, false)?;
    Ok(BASE64.encode(&encrypted))
}

/// Decrypt base64-encoded two-party encrypted data.
///
/// This is a convenience wrapper around `electrum_decrypt` that accepts
/// base64-encoded input, matching the Go SDK's `DecryptShared` API.
///
/// # Arguments
///
/// * `data` - Base64-encoded encrypted data
/// * `to_private_key` - The recipient's private key
/// * `from_public_key` - The sender's public key
///
/// # Returns
///
/// The decrypted plaintext
///
/// # Example
///
/// ```rust
/// use bsv_rs::compat::ecies;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let alice = PrivateKey::random();
/// let bob = PrivateKey::random();
///
/// let encrypted = ecies::encrypt_shared_base64(
///     b"Hello Bob!",
///     &bob.public_key(),
///     &alice
/// ).unwrap();
///
/// let decrypted = ecies::decrypt_shared_base64(
///     &encrypted,
///     &bob,
///     &alice.public_key()
/// ).unwrap();
/// assert_eq!(decrypted, b"Hello Bob!");
/// ```
pub fn decrypt_shared_base64(
    data: &str,
    to_private_key: &PrivateKey,
    from_public_key: &PublicKey,
) -> Result<Vec<u8>> {
    let encrypted = BASE64
        .decode(data)
        .map_err(|e| Error::EciesDecryptionFailed(format!("invalid base64: {}", e)))?;
    electrum_decrypt(&encrypted, to_private_key, Some(from_public_key))
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
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
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
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
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
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
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
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
    }

    #[test]
    fn test_electrum_invalid_magic() {
        let mut data = vec![0u8; 100];
        data[0..4].copy_from_slice(b"BAD!");

        let recipient = PrivateKey::random();
        let result = electrum_decrypt(&data, &recipient, None);
        assert!(matches!(result, Err(Error::EciesDecryptionFailed(_))));
    }

    #[test]
    fn test_electrum_too_short() {
        let recipient = PrivateKey::random();

        // Too short
        let result = electrum_decrypt(&[0u8; 20], &recipient, None);
        assert!(matches!(result, Err(Error::EciesDecryptionFailed(_))));
    }

    #[test]
    fn test_bitcore_too_short() {
        let recipient = PrivateKey::random();

        // Too short
        let result = bitcore_decrypt(&[0u8; 50], &recipient);
        assert!(matches!(result, Err(Error::EciesDecryptionFailed(_))));
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

    // =========================================================================
    // Base64 Wrapper Tests
    // =========================================================================

    #[test]
    fn test_encrypt_single_base64_roundtrip() {
        let key = PrivateKey::random();
        let message = b"Hello, self-encryption!";

        let encrypted = encrypt_single_base64(message, &key).unwrap();
        let decrypted = decrypt_single_base64(&encrypted, &key).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_single_base64_is_valid_base64() {
        let key = PrivateKey::random();
        let message = b"Test message";

        let encrypted = encrypt_single_base64(message, &key).unwrap();

        // Should be valid base64
        let decoded = BASE64.decode(&encrypted);
        assert!(decoded.is_ok());

        // Decoded should start with BIE1 magic bytes
        let bytes = decoded.unwrap();
        assert_eq!(&bytes[0..4], b"BIE1");
    }

    #[test]
    fn test_decrypt_single_base64_invalid_base64() {
        let key = PrivateKey::random();
        let invalid_base64 = "not valid base64!!!";

        let result = decrypt_single_base64(invalid_base64, &key);
        assert!(matches!(result, Err(Error::EciesDecryptionFailed(_))));
    }

    #[test]
    fn test_encrypt_shared_base64_roundtrip() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let message = b"Hello Bob, from Alice!";

        let encrypted = encrypt_shared_base64(message, &bob.public_key(), &alice).unwrap();
        let decrypted = decrypt_shared_base64(&encrypted, &bob, &alice.public_key()).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_encrypt_shared_base64_is_valid_base64() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let message = b"Test shared message";

        let encrypted = encrypt_shared_base64(message, &bob.public_key(), &alice).unwrap();

        // Should be valid base64
        let decoded = BASE64.decode(&encrypted);
        assert!(decoded.is_ok());

        // Decoded should start with BIE1 magic bytes
        let bytes = decoded.unwrap();
        assert_eq!(&bytes[0..4], b"BIE1");
    }

    #[test]
    fn test_decrypt_shared_base64_invalid_base64() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let invalid_base64 = "!!!invalid!!!";

        let result = decrypt_shared_base64(invalid_base64, &bob, &alice.public_key());
        assert!(matches!(result, Err(Error::EciesDecryptionFailed(_))));
    }

    #[test]
    fn test_base64_wrappers_empty_message() {
        let key = PrivateKey::random();
        let message = b"";

        // Single encryption
        let encrypted = encrypt_single_base64(message, &key).unwrap();
        let decrypted = decrypt_single_base64(&encrypted, &key).unwrap();
        assert_eq!(decrypted, message);

        // Shared encryption
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let encrypted = encrypt_shared_base64(message, &bob.public_key(), &alice).unwrap();
        let decrypted = decrypt_shared_base64(&encrypted, &bob, &alice.public_key()).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_base64_wrappers_large_message() {
        let key = PrivateKey::random();
        let message = vec![0xab; 10000];

        // Single encryption
        let encrypted = encrypt_single_base64(&message, &key).unwrap();
        let decrypted = decrypt_single_base64(&encrypted, &key).unwrap();
        assert_eq!(decrypted, message);

        // Shared encryption
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let encrypted = encrypt_shared_base64(&message, &bob.public_key(), &alice).unwrap();
        let decrypted = decrypt_shared_base64(&encrypted, &bob, &alice.public_key()).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_base64_wrapper_wrong_key() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let message = b"Secret message";

        // Encrypt with key1, try to decrypt with key2
        let encrypted = encrypt_single_base64(message, &key1).unwrap();
        let result = decrypt_single_base64(&encrypted, &key2);
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
    }

    // =========================================================================
    // P0-CRYPTO-7: Cross-SDK ECIES ciphertext vectors
    // Ported from TS SDK: compat/__tests/ECIES.test.ts
    // =========================================================================

    #[test]
    fn test_cross_sdk_electrum_decrypt_known_ciphertext_alice() {
        // TS SDK test vector: electrumDecrypt with alicePrivateKey
        // alicePrivateKey = PrivateKey.fromString('77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb', 16)
        // Ciphertext was encrypted to alice by bob.
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();

        let ciphertext_base64 = "QklFMQOGFyMXLo9Qv047K3BYJhmnJgt58EC8skYP/R2QU/U0yXXHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbiaH4FsxKIOOvzolIFVAS0FplUmib2HnlAM1yP/iiPsU=";
        let ciphertext = BASE64.decode(ciphertext_base64).unwrap();

        let plaintext = electrum_decrypt(&ciphertext, &alice_key, None).unwrap();
        assert_eq!(
            plaintext, b"this is my test message",
            "Cross-SDK Electrum ECIES decrypt (alice) plaintext mismatch"
        );
    }

    #[test]
    fn test_cross_sdk_electrum_decrypt_known_ciphertext_bob() {
        // TS SDK test vector: electrumDecrypt with bobPrivateKey
        // bobPrivateKey = PrivateKey.fromString('2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d', 16)
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();

        let ciphertext_base64 = "QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo=";
        let ciphertext = BASE64.decode(ciphertext_base64).unwrap();

        let plaintext = electrum_decrypt(&ciphertext, &bob_key, None).unwrap();
        assert_eq!(
            plaintext, b"this is my test message",
            "Cross-SDK Electrum ECIES decrypt (bob) plaintext mismatch"
        );
    }

    #[test]
    fn test_cross_sdk_electrum_encrypt_deterministic_alice_to_bob() {
        // TS SDK: electrumEncrypt(message, bobPublicKey, alicePrivateKey) produces exact ciphertext
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let message = b"this is my test message";

        let encrypted =
            electrum_encrypt(message, &bob_key.public_key(), &alice_key, false).unwrap();
        let encrypted_base64 = BASE64.encode(&encrypted);

        assert_eq!(
            encrypted_base64,
            "QklFMQM55QTWSSsILaluEejwOXlrBs1IVcEB4kkqbxDz4Fap53XHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbvZJHgyAzxA6SoujduvJXv+A9ri3po9veilrmc8p6dwo=",
            "Cross-SDK Electrum ECIES encrypt (alice->bob) ciphertext mismatch"
        );
    }

    #[test]
    fn test_cross_sdk_electrum_encrypt_deterministic_bob_to_alice() {
        // TS SDK: electrumEncrypt(message, alicePublicKey, bobPrivateKey) produces exact ciphertext
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let message = b"this is my test message";

        let encrypted =
            electrum_encrypt(message, &alice_key.public_key(), &bob_key, false).unwrap();
        let encrypted_base64 = BASE64.encode(&encrypted);

        assert_eq!(
            encrypted_base64,
            "QklFMQOGFyMXLo9Qv047K3BYJhmnJgt58EC8skYP/R2QU/U0yXXHOt6L3tKmrXho6yj6phfoiMkBOhUldRPnEI4fSZXbiaH4FsxKIOOvzolIFVAS0FplUmib2HnlAM1yP/iiPsU=",
            "Cross-SDK Electrum ECIES encrypt (bob->alice) ciphertext mismatch"
        );
    }

    #[test]
    fn test_cross_sdk_electrum_ecdh_no_key_symmetry() {
        // TS SDK: ECDH noKey mode produces identical ciphertext regardless of direction
        // electrumEncrypt(message, bobPub, alicePriv, noKey=true) ==
        // electrumEncrypt(message, alicePub, bobPriv, noKey=true)
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let message = b"this is my ECDH test message";

        let encrypted_bob =
            electrum_encrypt(message, &bob_key.public_key(), &alice_key, true).unwrap();
        let encrypted_alice =
            electrum_encrypt(message, &alice_key.public_key(), &bob_key, true).unwrap();

        // Both directions should produce identical ciphertext
        assert_eq!(
            encrypted_bob, encrypted_alice,
            "ECDH noKey mode should produce identical ciphertext in both directions"
        );

        // Both should decrypt to the original message
        let decrypted_1 =
            electrum_decrypt(&encrypted_alice, &bob_key, Some(&alice_key.public_key())).unwrap();
        assert_eq!(decrypted_1, message);

        let decrypted_2 =
            electrum_decrypt(&encrypted_bob, &alice_key, Some(&bob_key.public_key())).unwrap();
        assert_eq!(decrypted_2, message);
    }

    #[test]
    fn test_cross_sdk_electrum_roundtrip_with_known_keys() {
        // Verify encrypt/decrypt roundtrip with known TS SDK keys
        let alice_key = PrivateKey::from_hex(
            "77e06abc52bf065cb5164c5deca839d0276911991a2730be4d8d0a0307de7ceb",
        )
        .unwrap();
        let bob_key = PrivateKey::from_hex(
            "2b57c7c5e408ce927eef5e2efb49cfdadde77961d342daa72284bb3d6590862d",
        )
        .unwrap();
        let message = b"this is my test message";

        // Encrypt alice -> bob
        let encrypted =
            electrum_encrypt(message, &bob_key.public_key(), &alice_key, false).unwrap();

        // Decrypt as bob, providing alice's pubkey as sender
        let decrypted =
            electrum_decrypt(&encrypted, &bob_key, Some(&alice_key.public_key())).unwrap();
        assert_eq!(decrypted, message);

        // Also decrypt without providing sender pubkey (ephemeral key in ciphertext)
        let decrypted2 = electrum_decrypt(&encrypted, &bob_key, None).unwrap();
        assert_eq!(decrypted2, message);
    }

    #[test]
    fn test_shared_base64_wrapper_wrong_recipient() {
        let alice = PrivateKey::random();
        let bob = PrivateKey::random();
        let charlie = PrivateKey::random();
        let message = b"Secret for Bob";

        // Alice encrypts for Bob
        let encrypted = encrypt_shared_base64(message, &bob.public_key(), &alice).unwrap();

        // Charlie tries to decrypt (should fail)
        let result = decrypt_shared_base64(&encrypted, &charlie, &alice.public_key());
        assert!(matches!(result, Err(Error::EciesHmacMismatch)));
    }
}
