//! BRC-77 Signed Messages
//!
//! This module implements message signing and verification per BRC-77.
//! Messages can be signed for a specific recipient or for "anyone" to verify.

use crate::error::{Error, Result};
use crate::primitives::{sha256, to_base64, PrivateKey, PublicKey};
use crate::wallet::KeyDeriver;

use super::SIGNED_VERSION;

/// Signs a message using BRC-77 protocol.
///
/// # Arguments
///
/// * `message` - The message bytes to sign
/// * `signer` - The sender's private key
/// * `verifier` - Optional recipient public key. If None, anyone can verify.
///
/// # Returns
///
/// The signature bytes in wire format:
/// `[version: 4] [sender_pubkey: 33] [recipient: 1 or 33] [keyID: 32] [signature: DER]`
///
/// # Example
///
/// ```rust
/// use bsv_sdk::primitives::PrivateKey;
/// use bsv_sdk::messages::sign;
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// // Sign for specific recipient
/// let sig = sign(b"Hello", &sender, Some(&recipient.public_key())).unwrap();
///
/// // Sign for anyone
/// let sig_anyone = sign(b"Hello", &sender, None).unwrap();
/// ```
pub fn sign(message: &[u8], signer: &PrivateKey, verifier: Option<&PublicKey>) -> Result<Vec<u8>> {
    // Generate random 32-byte key ID
    let key_id: [u8; 32] = rand::random();

    // Create invoice number for BRC-42 key derivation
    let key_id_base64 = to_base64(&key_id);
    let invoice_number = format!("2-message signing-{}", key_id_base64);

    // Determine the verifier public key (anyone key if not specified)
    let (_, anyone_pubkey) = KeyDeriver::anyone_key();
    let verifier_pubkey = verifier.unwrap_or(&anyone_pubkey);

    // Derive signing key using BRC-42
    let signing_key = signer.derive_child(verifier_pubkey, &invoice_number)?;

    // Hash the message and sign
    let message_hash = sha256(message);
    let signature = signing_key.sign(&message_hash)?;
    let signature_der = signature.to_der();

    // Build wire format
    let mut result = Vec::with_capacity(4 + 33 + 33 + 32 + signature_der.len());

    // Version (4 bytes)
    result.extend_from_slice(&SIGNED_VERSION);

    // Sender public key (33 bytes)
    result.extend_from_slice(&signer.public_key().to_compressed());

    // Recipient (1 byte for anyone, 33 bytes for specific recipient)
    if verifier.is_none() {
        result.push(0x00); // Anyone marker
    } else {
        result.extend_from_slice(&verifier_pubkey.to_compressed());
    }

    // Key ID (32 bytes)
    result.extend_from_slice(&key_id);

    // Signature (DER encoded, variable length)
    result.extend_from_slice(&signature_der);

    Ok(result)
}

/// Verifies a signed message using BRC-77 protocol.
///
/// # Arguments
///
/// * `message` - The original message bytes
/// * `sig` - The signature bytes in wire format
/// * `recipient` - Optional recipient private key. Required if the message was signed
///                 for a specific recipient. For "anyone" messages, pass None.
///
/// # Returns
///
/// `Ok(true)` if the signature is valid, `Ok(false)` if the signature doesn't match
/// (but the format is valid), or `Err` for format errors.
///
/// # Errors
///
/// - `MessageVersionMismatch` - Wrong version bytes
/// - `MessageError` - Missing required recipient key
/// - `MessageRecipientMismatch` - Wrong recipient key provided
///
/// # Example
///
/// ```rust
/// use bsv_sdk::primitives::PrivateKey;
/// use bsv_sdk::messages::{sign, verify};
///
/// let sender = PrivateKey::random();
/// let recipient = PrivateKey::random();
///
/// let sig = sign(b"Hello", &sender, Some(&recipient.public_key())).unwrap();
/// let valid = verify(b"Hello", &sig, Some(&recipient)).unwrap();
/// assert!(valid);
/// ```
pub fn verify(message: &[u8], sig: &[u8], recipient: Option<&PrivateKey>) -> Result<bool> {
    // Minimum length check: version(4) + sender(33) + recipient_marker(1) + keyID(32) + min_sig(8)
    if sig.len() < 78 {
        return Err(Error::MessageError(format!(
            "signature too short: expected at least 78 bytes, got {}",
            sig.len()
        )));
    }

    let mut offset = 0;

    // Parse version (4 bytes)
    let version = &sig[offset..offset + 4];
    offset += 4;

    if version != SIGNED_VERSION {
        return Err(Error::MessageVersionMismatch {
            expected: hex::encode(SIGNED_VERSION),
            actual: hex::encode(version),
        });
    }

    // Parse sender public key (33 bytes)
    let sender_pubkey = PublicKey::from_bytes(&sig[offset..offset + 33])?;
    offset += 33;

    // Parse recipient indicator
    let recipient_first_byte = sig[offset];
    offset += 1;

    let verifier_privkey: PrivateKey;

    if recipient_first_byte == 0x00 {
        // Anyone can verify - use anyone key
        let (anyone_priv, _anyone_pub) = KeyDeriver::anyone_key();
        verifier_privkey = anyone_priv;
    } else {
        // Specific recipient - need recipient's private key
        if recipient.is_none() {
            // Reconstruct the expected public key from bytes we've seen
            let expected_pubkey_bytes = &sig[offset - 1..offset + 32];
            return Err(Error::MessageError(format!(
                "this signature can only be verified with knowledge of a specific private key. The associated public key is: {}",
                hex::encode(expected_pubkey_bytes)
            )));
        }

        let recipient_key = recipient.unwrap();
        verifier_privkey = recipient_key.clone();
        let verifier_pubkey = recipient_key.public_key();

        // Parse the expected recipient public key (remaining 32 bytes of the 33-byte key)
        let expected_pubkey_rest = &sig[offset..offset + 32];
        offset += 32;

        // Reconstruct full expected public key
        let mut expected_pubkey_bytes = [0u8; 33];
        expected_pubkey_bytes[0] = recipient_first_byte;
        expected_pubkey_bytes[1..].copy_from_slice(expected_pubkey_rest);

        let expected_pubkey = PublicKey::from_bytes(&expected_pubkey_bytes)?;

        // Verify the recipient matches
        if verifier_pubkey.to_compressed() != expected_pubkey.to_compressed() {
            return Err(Error::MessageRecipientMismatch {
                expected: hex::encode(expected_pubkey.to_compressed()),
                actual: hex::encode(verifier_pubkey.to_compressed()),
            });
        }
    }

    // Parse key ID (32 bytes)
    let key_id = &sig[offset..offset + 32];
    offset += 32;

    // Parse signature (remaining bytes)
    let signature_der = &sig[offset..];
    let signature = crate::primitives::Signature::from_der(signature_der)?;

    // Recreate invoice number and derive signing key
    let key_id_base64 = to_base64(key_id);
    let invoice_number = format!("2-message signing-{}", key_id_base64);

    // Derive the expected signing public key
    let signing_pubkey = sender_pubkey.derive_child(&verifier_privkey, &invoice_number)?;

    // Hash message and verify
    let message_hash = sha256(message);
    Ok(signing_pubkey.verify(&message_hash, &signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_sign_for_specific_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Test message for specific recipient";

        let sig = sign(message, &sender, Some(&recipient.public_key())).unwrap();

        // Should have version + sender + recipient(33) + keyID + signature
        assert!(sig.len() > 4 + 33 + 33 + 32);

        // Version should be correct
        assert_eq!(&sig[0..4], &SIGNED_VERSION);

        // Verify with correct recipient
        let valid = verify(message, &sig, Some(&recipient)).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_for_anyone() {
        let sender = PrivateKey::random();
        let message = b"Test message for anyone";

        let sig = sign(message, &sender, None).unwrap();

        // Should have version + sender + recipient(1) + keyID + signature
        assert!(sig.len() > 4 + 33 + 1 + 32);

        // Version should be correct
        assert_eq!(&sig[0..4], &SIGNED_VERSION);

        // Recipient marker should be 0x00
        assert_eq!(sig[4 + 33], 0x00);

        // Verify without recipient
        let valid = verify(message, &sig, None).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_version() {
        let sender = PrivateKey::random();
        let message = b"Test message";

        let mut sig = sign(message, &sender, None).unwrap();

        // Tamper with version
        sig[0] = 0xFF;

        let result = verify(message, &sig, None);
        assert!(result.is_err());
        match result {
            Err(Error::MessageVersionMismatch { expected, actual }) => {
                assert_eq!(expected, hex::encode(SIGNED_VERSION));
                assert!(actual.starts_with("ff"));
            }
            _ => panic!("Expected MessageVersionMismatch error"),
        }
    }

    #[test]
    fn test_missing_recipient_when_required() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Test message";

        let sig = sign(message, &sender, Some(&recipient.public_key())).unwrap();

        // Try to verify without providing recipient
        let result = verify(message, &sig, None);
        assert!(result.is_err());
        match result {
            Err(Error::MessageError(msg)) => {
                assert!(msg.contains("specific private key"));
            }
            _ => panic!("Expected MessageError"),
        }
    }

    #[test]
    fn test_wrong_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let wrong_recipient = PrivateKey::random();
        let message = b"Test message";

        let sig = sign(message, &sender, Some(&recipient.public_key())).unwrap();

        // Try to verify with wrong recipient
        let result = verify(message, &sig, Some(&wrong_recipient));
        assert!(result.is_err());
        match result {
            Err(Error::MessageRecipientMismatch { expected, actual }) => {
                assert_eq!(expected, hex::encode(recipient.public_key().to_compressed()));
                assert_eq!(
                    actual,
                    hex::encode(wrong_recipient.public_key().to_compressed())
                );
            }
            _ => panic!("Expected MessageRecipientMismatch error"),
        }
    }

    #[test]
    fn test_tampered_message_specific_recipient() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let sig = sign(message, &sender, Some(&recipient.public_key())).unwrap();

        // Verify with tampered message should return false (not error)
        let valid = verify(tampered, &sig, Some(&recipient)).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_tampered_message_anyone() {
        let sender = PrivateKey::random();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let sig = sign(message, &sender, None).unwrap();

        // Verify with tampered message should return false (not error)
        let valid = verify(tampered, &sig, None).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_empty_message() {
        let sender = PrivateKey::random();
        let message = b"";

        let sig = sign(message, &sender, None).unwrap();
        let valid = verify(message, &sig, None).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_large_message() {
        let sender = PrivateKey::random();
        let message = vec![0xAB; 10000]; // 10KB message

        let sig = sign(&message, &sender, None).unwrap();
        let valid = verify(&message, &sig, None).unwrap();
        assert!(valid);
    }

    /// Helper to create a private key from a small scalar (like Go/TS SDKs)
    fn key_from_scalar(scalar: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        PrivateKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn test_deterministic_keys_specific_recipient() {
        // Same test as Go/TS SDKs: sender=15, recipient=21
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let message = [1u8, 2, 4, 8, 16, 32];

        let signature = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
        let valid = verify(&message, &signature, Some(&recipient)).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deterministic_keys_anyone() {
        // Same test as Go/TS SDKs: sender=15, no recipient
        let sender = key_from_scalar(15);
        let message = [1u8, 2, 4, 8, 16, 32];

        let signature = sign(&message, &sender, None).unwrap();
        let valid = verify(&message, &signature, None).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_deterministic_keys_wrong_version_error_format() {
        // Match Go/TS error format: "Expected 42423301, received 01423301"
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let message = [1u8, 2, 4, 8, 16, 32];

        let mut signature = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
        signature[0] = 1; // Tamper version

        let result = verify(&message, &signature, Some(&recipient));
        match result {
            Err(Error::MessageVersionMismatch { expected, actual }) => {
                assert_eq!(expected, "42423301");
                assert_eq!(actual, "01423301");
            }
            _ => panic!("Expected MessageVersionMismatch error"),
        }
    }

    #[test]
    fn test_deterministic_keys_no_verifier_error_format() {
        // Match Go/TS error: shows recipient public key hex
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let message = [1u8, 2, 4, 8, 16, 32];

        let signature = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
        let result = verify(&message, &signature, None);

        match result {
            Err(Error::MessageError(msg)) => {
                // Should contain the recipient's public key
                let recipient_pubkey_hex = hex::encode(recipient.public_key().to_compressed());
                assert!(
                    msg.contains(&recipient_pubkey_hex),
                    "Error should contain recipient pubkey: {}",
                    msg
                );
            }
            _ => panic!("Expected MessageError"),
        }
    }

    #[test]
    fn test_deterministic_keys_wrong_verifier_error_format() {
        // Match Go/TS error: shows both expected and actual public keys
        let sender = key_from_scalar(15);
        let recipient = key_from_scalar(21);
        let wrong_recipient = key_from_scalar(22);
        let message = [1u8, 2, 4, 8, 16, 32];

        let signature = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
        let result = verify(&message, &signature, Some(&wrong_recipient));

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
}
