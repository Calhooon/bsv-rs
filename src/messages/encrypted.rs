//! BRC-78 Encrypted Messages
//!
//! This module implements message encryption and decryption per BRC-78.
//! Uses ECDH key derivation with AES-256-GCM symmetric encryption.

use crate::error::{Error, Result};
use crate::primitives::{to_base64, PrivateKey, PublicKey, SymmetricKey};

use super::ENCRYPTED_VERSION;

/// Encrypts a message using BRC-78 protocol.
///
/// # Arguments
///
/// * `message` - The plaintext message bytes to encrypt
/// * `sender` - The sender's private key
/// * `recipient` - The recipient's public key
///
/// # Returns
///
/// The ciphertext bytes in wire format:
/// `[version: 4] [sender_pubkey: 33] [recipient_pubkey: 33] [keyID: 32] [ciphertext]`
///
/// Where ciphertext is: `[IV: 32] [encrypted_data] [GCM_tag: 16]`
///
/// # Example
///
/// ```rust
/// use bsv_sdk::primitives::PrivateKey;
/// use bsv_sdk::messages::encrypt;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let ciphertext = encrypt(b"Secret message", &sender, &recipient.public_key()).unwrap();
/// ```
pub fn encrypt(message: &[u8], sender: &PrivateKey, recipient: &PublicKey) -> Result<Vec<u8>> {
    // Generate random 32-byte key ID
    let key_id: [u8; 32] = rand::random();

    // Create invoice number for BRC-42 key derivation
    let key_id_base64 = to_base64(&key_id);
    let invoice_number = format!("2-message encryption-{}", key_id_base64);

    // Derive sender's private key using BRC-42
    let signing_priv = sender.derive_child(recipient, &invoice_number)?;

    // Derive recipient's public key using BRC-42
    let recipient_pub = recipient.derive_child(sender, &invoice_number)?;

    // Compute shared secret via ECDH
    let shared_secret = signing_priv.derive_shared_secret(&recipient_pub)?;

    // Derive symmetric key from shared secret
    // Take compressed encoding and skip first byte (point format indicator 02/03)
    let shared_secret_bytes = shared_secret.to_compressed();
    let symmetric_key = SymmetricKey::from_bytes(&shared_secret_bytes[1..])?;

    // Encrypt the message
    let encrypted = symmetric_key.encrypt(message)?;

    // Build wire format
    let mut result = Vec::with_capacity(4 + 33 + 33 + 32 + encrypted.len());

    // Version (4 bytes)
    result.extend_from_slice(&ENCRYPTED_VERSION);

    // Sender public key (33 bytes)
    result.extend_from_slice(&sender.public_key().to_compressed());

    // Recipient public key (33 bytes)
    result.extend_from_slice(&recipient.to_compressed());

    // Key ID (32 bytes)
    result.extend_from_slice(&key_id);

    // Encrypted data (IV + ciphertext + tag)
    result.extend_from_slice(&encrypted);

    Ok(result)
}

/// Decrypts an encrypted message using BRC-78 protocol.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted message bytes in wire format
/// * `recipient` - The recipient's private key
///
/// # Returns
///
/// The decrypted plaintext bytes.
///
/// # Errors
///
/// - `MessageVersionMismatch` - Wrong version bytes
/// - `MessageRecipientMismatch` - Ciphertext was encrypted for a different recipient
/// - `DecryptionFailed` - AES-GCM decryption or authentication failed
///
/// # Example
///
/// ```rust
/// use bsv_sdk::primitives::PrivateKey;
/// use bsv_sdk::messages::{encrypt, decrypt};
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let ciphertext = encrypt(b"Secret", &sender, &recipient.public_key()).unwrap();
/// let plaintext = decrypt(&ciphertext, &recipient).unwrap();
/// assert_eq!(plaintext, b"Secret");
/// ```
pub fn decrypt(ciphertext: &[u8], recipient: &PrivateKey) -> Result<Vec<u8>> {
    // Minimum length: version(4) + sender(33) + recipient(33) + keyID(32) + IV(32) + tag(16) = 150
    let min_length = 4 + 33 + 33 + 32 + 32 + 16;
    if ciphertext.len() < min_length {
        return Err(Error::MessageError(format!(
            "message too short: expected at least {} bytes, got {} bytes",
            min_length,
            ciphertext.len()
        )));
    }

    let mut offset = 0;

    // Parse version (4 bytes)
    let version = &ciphertext[offset..offset + 4];
    offset += 4;

    if version != ENCRYPTED_VERSION {
        return Err(Error::MessageVersionMismatch {
            expected: hex::encode(ENCRYPTED_VERSION),
            actual: hex::encode(version),
        });
    }

    // Parse sender public key (33 bytes)
    let sender_pubkey = PublicKey::from_bytes(&ciphertext[offset..offset + 33])?;
    offset += 33;

    // Parse expected recipient public key (33 bytes)
    let expected_recipient_bytes = &ciphertext[offset..offset + 33];
    offset += 33;

    let expected_recipient_pubkey = PublicKey::from_bytes(expected_recipient_bytes)?;
    let actual_recipient_pubkey = recipient.public_key();

    // Verify recipient matches
    if expected_recipient_pubkey.to_compressed() != actual_recipient_pubkey.to_compressed() {
        return Err(Error::MessageRecipientMismatch {
            expected: hex::encode(expected_recipient_pubkey.to_compressed()),
            actual: hex::encode(actual_recipient_pubkey.to_compressed()),
        });
    }

    // Parse key ID (32 bytes)
    let key_id = &ciphertext[offset..offset + 32];
    offset += 32;

    // Parse encrypted data (remaining bytes)
    let encrypted = &ciphertext[offset..];

    // Recreate invoice number and derive keys
    let key_id_base64 = to_base64(key_id);
    let invoice_number = format!("2-message encryption-{}", key_id_base64);

    // Derive sender's public key using BRC-42 (mirror of encrypt)
    let signing_pub = sender_pubkey.derive_child(recipient, &invoice_number)?;

    // Derive recipient's private key using BRC-42
    let recipient_priv = recipient.derive_child(&sender_pubkey, &invoice_number)?;

    // Compute shared secret via ECDH
    let shared_secret = signing_pub.derive_shared_secret(&recipient_priv)?;

    // Derive symmetric key from shared secret
    let shared_secret_bytes = shared_secret.to_compressed();
    let symmetric_key = SymmetricKey::from_bytes(&shared_secret_bytes[1..])?;

    // Decrypt the message
    symmetric_key.decrypt(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Hello, encrypted world!";

        let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        // Should have version + sender + recipient + keyID + encrypted
        assert!(ciphertext.len() > 4 + 33 + 33 + 32 + 48); // 48 = IV(32) + tag(16)

        // Version should be correct
        assert_eq!(&ciphertext[0..4], &ENCRYPTED_VERSION);

        // Decrypt
        let decrypted = decrypt(&ciphertext, &recipient).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_version() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Test message";

        let mut ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        // Tamper with version
        ciphertext[0] = 0xFF;

        let result = decrypt(&ciphertext, &recipient);
        assert!(result.is_err());
        match result {
            Err(Error::MessageVersionMismatch { expected, actual }) => {
                assert_eq!(expected, hex::encode(ENCRYPTED_VERSION));
                assert!(actual.starts_with("ff"));
            }
            _ => panic!("Expected MessageVersionMismatch error"),
        }
    }

    #[test]
    fn test_wrong_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let wrong_recipient = PrivateKey::random();
        let plaintext = b"Test message";

        let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        // Try to decrypt with wrong recipient
        let result = decrypt(&ciphertext, &wrong_recipient);
        assert!(result.is_err());
        match result {
            Err(Error::MessageRecipientMismatch { expected, actual }) => {
                assert_eq!(
                    expected,
                    hex::encode(recipient.public_key().to_compressed())
                );
                assert_eq!(
                    actual,
                    hex::encode(wrong_recipient.public_key().to_compressed())
                );
            }
            _ => panic!("Expected MessageRecipientMismatch error"),
        }
    }

    #[test]
    fn test_tampered_ciphertext() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Test message";

        let mut ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        // Tamper with encrypted data (after the header)
        let data_offset = 4 + 33 + 33 + 32;
        ciphertext[data_offset + 10] ^= 0xFF;

        // Should fail decryption (GCM authentication)
        let result = decrypt(&ciphertext, &recipient);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_short() {
        let recipient = PrivateKey::random();
        let short_message = vec![0u8; 50]; // Too short

        let result = decrypt(&short_message, &recipient);
        assert!(result.is_err());
        match result {
            Err(Error::MessageError(msg)) => {
                assert!(msg.contains("too short"));
            }
            _ => panic!("Expected MessageError"),
        }
    }

    #[test]
    fn test_empty_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"";

        let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();
        let decrypted = decrypt(&ciphertext, &recipient).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_large_message() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = vec![0xAB; 10000]; // 10KB message

        let ciphertext = encrypt(&plaintext, &sender, &recipient.public_key()).unwrap();
        let decrypted = decrypt(&ciphertext, &recipient).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_senders_same_recipient() {
        let sender1 = PrivateKey::random();
        let sender2 = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Same message";

        let ciphertext1 = encrypt(plaintext, &sender1, &recipient.public_key()).unwrap();
        let ciphertext2 = encrypt(plaintext, &sender2, &recipient.public_key()).unwrap();

        // Ciphertexts should be different (different keys, different IV)
        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly
        let decrypted1 = decrypt(&ciphertext1, &recipient).unwrap();
        let decrypted2 = decrypt(&ciphertext2, &recipient).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted1);
        assert_eq!(plaintext.to_vec(), decrypted2);
    }

    #[test]
    fn test_same_message_different_ciphertext() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Same message";

        // Encrypt twice - should produce different ciphertexts due to random keyID and IV
        let ciphertext1 = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();
        let ciphertext2 = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        assert_ne!(ciphertext1, ciphertext2);

        // Both should decrypt correctly
        assert_eq!(
            plaintext.to_vec(),
            decrypt(&ciphertext1, &recipient).unwrap()
        );
        assert_eq!(
            plaintext.to_vec(),
            decrypt(&ciphertext2, &recipient).unwrap()
        );
    }

    /// Helper to create a private key from a small scalar (like Go/TS SDKs)
    fn key_from_scalar(scalar: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        PrivateKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_deterministic_keys_encrypt_decrypt() {
        // Same test as Go/TS SDKs: sender=15, recipient=21
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let message = [1u8, 2, 4, 8, 16, 32];

        let ciphertext = encrypt(&message, &sender, &recipient.public_key()).unwrap();
        let decrypted = decrypt(&ciphertext, &recipient).unwrap();
        assert_eq!(message.to_vec(), decrypted);
    }

    #[test]
    fn test_deterministic_keys_wrong_version_error_format() {
        // Match Go/TS error format: "Expected 42421033, received 01421033"
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let message = [1u8, 2, 4, 8, 16, 32];

        let mut ciphertext = encrypt(&message, &sender, &recipient.public_key()).unwrap();
        ciphertext[0] = 1; // Tamper version

        let result = decrypt(&ciphertext, &recipient);
        match result {
            Err(Error::MessageVersionMismatch { expected, actual }) => {
                assert_eq!(expected, "42421033");
                assert_eq!(actual, "01421033");
            }
            _ => panic!("Expected MessageVersionMismatch error"),
        }
    }

    #[test]
    fn test_deterministic_keys_wrong_recipient_error_format() {
        // Match Go/TS error: shows both expected and actual public keys
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let wrong_recipient = key_from_scalar(22);
        let message = [1u8, 2, 4, 8, 16, 32];

        let ciphertext = encrypt(&message, &sender, &recipient.public_key()).unwrap();
        let result = decrypt(&ciphertext, &wrong_recipient);

        match result {
            Err(Error::MessageRecipientMismatch { expected, actual }) => {
                let expected_hex = hex::encode(recipient.public_key().to_compressed());
                let actual_hex = hex::encode(wrong_recipient.public_key().to_compressed());
                assert_eq!(expected, expected_hex);
                assert_eq!(actual, actual_hex);
            }
            _ => panic!("Expected MessageRecipientMismatch error"),
        }
    }

    #[test]
    fn test_cross_sdk_rare_key_length() {
        // Test vector from TypeScript SDK - encrypted blob that handles rare key length case
        // (leading zeros in key BigNumber array)
        let recipient = key_from_scalar(21);

        // This is an encrypted message from TypeScript that decrypts correctly
        // even with edge cases in key derivation
        let encrypted: Vec<u8> = vec![
            66, 66, 16, 51, 2, 215, 146, 77, 79, 125, 67, 234, 150, 90, 70, 90, 227, 9, 95, 244,
            17, 49, 229, 148, 111, 60, 133, 247, 158, 68, 173, 188, 248, 226, 126, 8, 14, 2, 53,
            43, 191, 74, 76, 221, 18, 86, 79, 147, 250, 51, 44, 227, 51, 48, 29, 154, 212, 2, 113,
            248, 16, 113, 129, 52, 10, 239, 37, 190, 89, 213, 75, 148, 8, 235, 104, 137, 80, 129,
            55, 68, 182, 141, 118, 212, 215, 121, 161, 107, 62, 247, 12, 172, 244, 170, 208, 37,
            213, 198, 103, 118, 75, 166, 166, 131, 191, 105, 48, 232, 101, 223, 255, 169, 176, 204,
            126, 249, 78, 178, 10, 51, 13, 163, 58, 232, 122, 111, 210, 218, 187, 247, 164, 101,
            207, 15, 37, 227, 108, 82, 70, 35, 5, 148, 18, 162, 120, 64, 46, 40, 227, 197, 6, 112,
            207, 200, 238, 81,
        ];

        // Should not panic - tests that rare key lengths are handled correctly
        let result = decrypt(&encrypted, &recipient);
        assert!(
            result.is_ok(),
            "Decryption should succeed for cross-SDK test vector"
        );
    }
}
