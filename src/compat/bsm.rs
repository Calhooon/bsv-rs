//! Bitcoin Signed Message (BSM) implementation.
//!
//! This module provides functions for signing and verifying messages using the
//! Bitcoin Signed Message format, which is compatible with most Bitcoin wallets.
//!
//! # Message Format
//!
//! The message is hashed using:
//! ```text
//! SHA256d(varint(len("Bitcoin Signed Message:\n")) || "Bitcoin Signed Message:\n" || varint(len(message)) || message)
//! ```
//!
//! # Signature Format
//!
//! The signature is a 65-byte compact signature:
//! ```text
//! [recovery_flag (1 byte)] [r (32 bytes)] [s (32 bytes)]
//! ```
//!
//! Where `recovery_flag = recovery_id + 27 + (compressed ? 4 : 0)`
//!
//! # Examples
//!
//! ```rust
//! use bsv_sdk::compat::bsm;
//! use bsv_sdk::primitives::ec::PrivateKey;
//!
//! let private_key = PrivateKey::random();
//! let message = b"Hello, BSV!";
//!
//! // Sign the message
//! let signature = bsm::sign_message(&private_key, message).unwrap();
//! assert_eq!(signature.len(), 65);
//!
//! // Verify the signature
//! let address = private_key.public_key().to_address();
//! assert!(bsm::verify_message(&address, &signature, message).unwrap());
//! ```

use crate::error::{Error, Result};
use crate::primitives::ec::{calculate_recovery_id, recover_public_key, PrivateKey, PublicKey};
use crate::primitives::encoding::Writer;
use crate::primitives::hash::sha256d;

/// Bitcoin Signed Message magic prefix.
const BSM_MAGIC: &[u8] = b"Bitcoin Signed Message:\n";

/// Signs a message using the Bitcoin Signed Message format.
///
/// # Arguments
///
/// * `private_key` - The private key to sign with
/// * `message` - The message to sign
///
/// # Returns
///
/// A 65-byte compact signature with recovery flag
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bsm;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let signature = bsm::sign_message(&key, b"Hello!").unwrap();
/// assert_eq!(signature.len(), 65);
/// ```
pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> Result<Vec<u8>> {
    sign_message_with_compression(private_key, message, true)
}

/// Signs a message with explicit compression flag.
///
/// # Arguments
///
/// * `private_key` - The private key to sign with
/// * `message` - The message to sign
/// * `compressed` - Whether to indicate a compressed public key in the signature
///
/// # Returns
///
/// A 65-byte compact signature with recovery flag
pub fn sign_message_with_compression(
    private_key: &PrivateKey,
    message: &[u8],
    compressed: bool,
) -> Result<Vec<u8>> {
    // Compute the message hash
    let msg_hash = compute_message_hash(message);

    // Sign the hash
    let signature = private_key.sign(&msg_hash)?;

    // Calculate recovery ID
    let public_key = private_key.public_key();
    let recovery_id = calculate_recovery_id(&msg_hash, &signature, &public_key)?;

    // Compute recovery flag: recovery_id + 27 + (compressed ? 4 : 0)
    let recovery_flag = recovery_id + 27 + if compressed { 4 } else { 0 };

    // Build 65-byte signature: [recovery_flag (1)] [r (32)] [s (32)]
    let mut result = Vec::with_capacity(65);
    result.push(recovery_flag);
    result.extend_from_slice(signature.r());
    result.extend_from_slice(signature.s());

    Ok(result)
}

/// Verifies a Bitcoin Signed Message.
///
/// # Arguments
///
/// * `address` - The expected Bitcoin address (P2PKH)
/// * `signature` - The 65-byte compact signature
/// * `message` - The original message
///
/// # Returns
///
/// `true` if the signature is valid for the given address, `false` otherwise
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bsm;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let address = key.public_key().to_address();
/// let message = b"Hello!";
///
/// let signature = bsm::sign_message(&key, message).unwrap();
/// assert!(bsm::verify_message(&address, &signature, message).unwrap());
/// ```
pub fn verify_message(address: &str, signature: &[u8], message: &[u8]) -> Result<bool> {
    // Recover the public key from the signature
    let (public_key, was_compressed) = recover_public_key_from_signature(signature, message)?;

    // Generate the address from the recovered public key
    let recovered_address = if was_compressed {
        public_key.to_address()
    } else {
        // For uncompressed, we need to compute hash160 of uncompressed key
        let hash = crate::primitives::hash::hash160(&public_key.to_uncompressed());
        crate::primitives::encoding::to_base58_check(&hash, &[0x00])
    };

    Ok(recovered_address == address)
}

/// Recovers a public key from a Bitcoin Signed Message signature.
///
/// # Arguments
///
/// * `signature` - The 65-byte compact signature
/// * `message` - The original message
///
/// # Returns
///
/// A tuple of (recovered_public_key, was_compressed)
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bsm;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let message = b"Hello!";
/// let signature = bsm::sign_message(&key, message).unwrap();
///
/// let (recovered, compressed) = bsm::recover_public_key_from_signature(&signature, message).unwrap();
/// assert_eq!(recovered.to_compressed(), key.public_key().to_compressed());
/// assert!(compressed);
/// ```
pub fn recover_public_key_from_signature(
    signature: &[u8],
    message: &[u8],
) -> Result<(PublicKey, bool)> {
    // Validate signature length
    if signature.len() != 65 {
        return Err(Error::InvalidSignature(format!(
            "Expected 65 bytes, got {}",
            signature.len()
        )));
    }

    // Extract recovery flag
    let recovery_flag = signature[0];

    // Validate recovery flag range (27-34)
    if !(27..=34).contains(&recovery_flag) {
        return Err(Error::InvalidSignature(format!(
            "Invalid recovery flag: {}, expected 27-34",
            recovery_flag
        )));
    }

    // Parse recovery flag
    let was_compressed = recovery_flag >= 31;
    let recovery_id = if was_compressed {
        recovery_flag - 31
    } else {
        recovery_flag - 27
    };

    // Extract r and s
    let r: [u8; 32] = signature[1..33]
        .try_into()
        .map_err(|_| Error::InvalidSignature("Invalid r value".to_string()))?;
    let s: [u8; 32] = signature[33..65]
        .try_into()
        .map_err(|_| Error::InvalidSignature("Invalid s value".to_string()))?;

    let sig = crate::primitives::ec::Signature::new(r, s);

    // Compute the message hash
    let msg_hash = compute_message_hash(message);

    // Recover the public key
    let public_key = recover_public_key(&msg_hash, &sig, recovery_id)?;

    Ok((public_key, was_compressed))
}

/// Compute the Bitcoin Signed Message hash (SHA256d with prefix).
///
/// This is the "magic hash" used in BSM signatures. The message is prefixed
/// with "Bitcoin Signed Message:\n" and varint-encoded lengths before being
/// double-SHA256 hashed.
///
/// # Algorithm
///
/// ```text
/// Hash = SHA256d(varint(len(magic)) || magic || varint(len(message)) || message)
/// where magic = "Bitcoin Signed Message:\n"
/// ```
///
/// # Arguments
///
/// * `message` - The message to hash
///
/// # Returns
///
/// A 32-byte double-SHA256 hash of the prefixed message
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bsm;
///
/// let hash = bsm::magic_hash(b"Hello, BSV!");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn magic_hash(message: &[u8]) -> [u8; 32] {
    let mut writer = Writer::new();

    // Write magic prefix with varint length
    writer.write_var_int(BSM_MAGIC.len() as u64);
    writer.write_bytes(BSM_MAGIC);

    // Write message with varint length
    writer.write_var_int(message.len() as u64);
    writer.write_bytes(message);

    // Double SHA-256
    sha256d(writer.as_bytes())
}

/// Verifies a Bitcoin Signed Message using a DER-encoded signature and public key.
///
/// Unlike [`verify_message`] which recovers the public key from a compact
/// 65-byte signature and compares against an address, this function verifies
/// a DER-encoded ECDSA signature directly against a provided public key.
///
/// This is compatible with the TypeScript SDK's `BSM.verify()` function
/// which accepts a `Signature` object (potentially DER-encoded) and a
/// `PublicKey` directly.
///
/// # Arguments
///
/// * `der_signature` - The DER-encoded ECDSA signature
/// * `public_key` - The public key to verify against
/// * `message` - The original message
///
/// # Returns
///
/// `true` if the signature is valid for the given public key and message
///
/// # Example
///
/// ```rust
/// use bsv_sdk::compat::bsm;
/// use bsv_sdk::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
/// let message = b"Hello, BSV!";
///
/// // Sign the message and get compact signature
/// let compact_sig = bsm::sign_message(&key, message).unwrap();
///
/// // Also verify using DER format
/// let msg_hash = bsm::magic_hash(message);
/// let der_sig = key.sign(&msg_hash).unwrap().to_der();
/// assert!(bsm::verify_message_der(&der_sig, &key.public_key(), message).unwrap());
/// ```
pub fn verify_message_der(
    der_signature: &[u8],
    public_key: &PublicKey,
    message: &[u8],
) -> Result<bool> {
    // Parse the DER signature
    let sig = crate::primitives::ec::Signature::from_der(der_signature)?;

    // Compute the message hash
    let msg_hash = compute_message_hash(message);

    // Verify the signature directly against the public key
    Ok(public_key.verify(&msg_hash, &sig))
}

/// Computes the Bitcoin Signed Message hash for a message (internal alias).
#[inline]
fn compute_message_hash(message: &[u8]) -> [u8; 32] {
    magic_hash(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_sign_and_verify() {
        let key = PrivateKey::random();
        let address = key.public_key().to_address();
        let message = b"Hello, BSV!";

        let signature = sign_message(&key, message).unwrap();
        assert_eq!(signature.len(), 65);

        assert!(verify_message(&address, &signature, message).unwrap());
    }

    #[test]
    fn test_sign_and_verify_compressed() {
        let key = PrivateKey::random();
        let address = key.public_key().to_address();
        let message = b"Test message";

        let signature = sign_message_with_compression(&key, message, true).unwrap();
        assert!(verify_message(&address, &signature, message).unwrap());

        // Recovery flag should be >= 31 for compressed
        assert!(signature[0] >= 31);
    }

    #[test]
    fn test_sign_and_verify_uncompressed() {
        let key = PrivateKey::random();
        let message = b"Test message";

        // For uncompressed, we need to use the uncompressed address
        let hash = crate::primitives::hash::hash160(&key.public_key().to_uncompressed());
        let address = crate::primitives::encoding::to_base58_check(&hash, &[0x00]);

        let signature = sign_message_with_compression(&key, message, false).unwrap();
        assert!(verify_message(&address, &signature, message).unwrap());

        // Recovery flag should be < 31 for uncompressed
        assert!(signature[0] < 31);
    }

    #[test]
    fn test_recover_public_key() {
        let key = PrivateKey::random();
        let message = b"Hello!";

        let signature = sign_message(&key, message).unwrap();
        let (recovered, compressed) =
            recover_public_key_from_signature(&signature, message).unwrap();

        assert_eq!(recovered.to_compressed(), key.public_key().to_compressed());
        assert!(compressed);
    }

    #[test]
    fn test_invalid_signature_length() {
        let result = recover_public_key_from_signature(&[0u8; 64], b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_recovery_flag() {
        let mut sig = [0u8; 65];
        sig[0] = 26; // Invalid (< 27)
        let result = recover_public_key_from_signature(&sig, b"test");
        assert!(result.is_err());

        sig[0] = 35; // Invalid (> 34)
        let result = recover_public_key_from_signature(&sig, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_address() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let message = b"Hello!";

        let signature = sign_message(&key1, message).unwrap();
        let wrong_address = key2.public_key().to_address();

        // Should return false for wrong address
        assert!(!verify_message(&wrong_address, &signature, message).unwrap());
    }

    #[test]
    fn test_verify_wrong_message() {
        let key = PrivateKey::random();
        let address = key.public_key().to_address();

        let signature = sign_message(&key, b"Hello!").unwrap();

        // Should return false for wrong message
        assert!(!verify_message(&address, &signature, b"Goodbye!").unwrap());
    }

    #[test]
    fn test_message_hash_format() {
        // Verify the message hash is computed correctly
        let message = b"test";
        let hash = compute_message_hash(message);

        // The hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Same message should produce same hash
        let hash2 = compute_message_hash(message);
        assert_eq!(hash, hash2);

        // Different message should produce different hash
        let hash3 = compute_message_hash(b"other");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_magic_hash_public_api() {
        // Verify magic_hash is accessible and matches internal compute_message_hash
        let message = b"Hello, BSV!";
        let hash = magic_hash(message);
        assert_eq!(hash.len(), 32);

        // Verify it produces deterministic output
        let hash2 = magic_hash(message);
        assert_eq!(hash, hash2);

        // Different message produces different hash
        let hash3 = magic_hash(b"Different message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_magic_hash_empty_message() {
        let hash = magic_hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_magic_hash_long_message() {
        let message = vec![b'a'; 10000];
        let hash = magic_hash(&message);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_magic_hash_matches_signing() {
        // Verify that magic_hash produces the same hash used internally by sign_message
        let key = PrivateKey::random();
        let message = b"Test message";

        // Get the hash directly
        let hash = magic_hash(message);

        // Sign and recover public key
        let signature = sign_message(&key, message).unwrap();
        let (recovered, _) = recover_public_key_from_signature(&signature, message).unwrap();

        // The recovered key should match the original
        assert_eq!(recovered.to_compressed(), key.public_key().to_compressed());

        // Verify the hash is 32 bytes (SHA256d output)
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_known_vector() {
        // Test with a known private key
        let key = PrivateKey::from_hex(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let address = key.public_key().to_address();
        let message = b"This is a test message";

        let signature = sign_message(&key, message).unwrap();

        // Verify signature
        assert!(verify_message(&address, &signature, message).unwrap());

        // Recover public key
        let (recovered, _) = recover_public_key_from_signature(&signature, message).unwrap();
        assert_eq!(recovered.to_compressed(), key.public_key().to_compressed());
    }

    // =======================================
    // P0-CRYPTO-6: Cross-SDK BSM signature vector
    // Ported from TS SDK: compat/__tests/BSM.test.ts
    // =======================================

    #[test]
    fn test_cross_sdk_bsm_known_vector() {
        // TS SDK test: PrivateKey.fromWif('L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu')
        // signs "hello world" and produces a specific base64 signature
        let key =
            PrivateKey::from_wif("L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu").unwrap();
        let message = b"hello world";

        let signature = sign_message(&key, message).unwrap();
        assert_eq!(signature.len(), 65, "BSM signature must be 65 bytes");

        // Verify the base64 encoding matches the TS SDK output exactly
        let sig_base64 = base64::engine::general_purpose::STANDARD.encode(&signature);
        assert_eq!(
            sig_base64,
            "H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk=",
            "Cross-SDK BSM signature base64 mismatch with TS SDK"
        );

        // Verify the signature is valid via address verification
        let address = key.public_key().to_address();
        assert!(
            verify_message(&address, &signature, message).unwrap(),
            "Cross-SDK BSM signature should verify"
        );

        // Also verify recovery: the recovered public key should match
        let (recovered, compressed) =
            recover_public_key_from_signature(&signature, message).unwrap();
        assert_eq!(
            recovered.to_compressed(),
            key.public_key().to_compressed(),
            "Recovered public key should match original"
        );
        assert!(compressed, "Signature should indicate compressed key");
    }

    #[test]
    fn test_empty_message() {
        let key = PrivateKey::random();
        let address = key.public_key().to_address();
        let message = b"";

        let signature = sign_message(&key, message).unwrap();
        assert!(verify_message(&address, &signature, message).unwrap());
    }

    #[test]
    fn test_long_message() {
        let key = PrivateKey::random();
        let address = key.public_key().to_address();
        let message = vec![b'a'; 10000];

        let signature = sign_message(&key, &message).unwrap();
        assert!(verify_message(&address, &signature, &message).unwrap());
    }

    // =======================================
    // Tests for verify_message_der
    // =======================================

    #[test]
    fn test_verify_message_der_basic() {
        let key = PrivateKey::random();
        let message = b"Hello, BSV!";

        // Sign the message hash with the private key (produces DER signature)
        let msg_hash = magic_hash(message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        // Verify using DER method
        assert!(verify_message_der(&der, &key.public_key(), message).unwrap());
    }

    #[test]
    fn test_verify_message_der_wrong_key() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let message = b"Hello!";

        let msg_hash = magic_hash(message);
        let sig = key1.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        // Should return false for wrong public key
        assert!(!verify_message_der(&der, &key2.public_key(), message).unwrap());
    }

    #[test]
    fn test_verify_message_der_wrong_message() {
        let key = PrivateKey::random();
        let message = b"Hello!";

        let msg_hash = magic_hash(message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        // Should return false for wrong message
        assert!(!verify_message_der(&der, &key.public_key(), b"Goodbye!").unwrap());
    }

    #[test]
    fn test_verify_message_der_invalid_der() {
        let key = PrivateKey::random();
        let message = b"Hello!";

        // Invalid DER data
        let result = verify_message_der(&[0x30, 0x00], &key.public_key(), message);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_message_der_empty_message() {
        let key = PrivateKey::random();
        let message = b"";

        let msg_hash = magic_hash(message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        assert!(verify_message_der(&der, &key.public_key(), message).unwrap());
    }

    #[test]
    fn test_verify_message_der_long_message() {
        let key = PrivateKey::random();
        let message = vec![b'a'; 10000];

        let msg_hash = magic_hash(&message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        assert!(verify_message_der(&der, &key.public_key(), &message).unwrap());
    }

    #[test]
    fn test_verify_message_der_known_key() {
        // Test with a known private key for reproducibility
        let key = PrivateKey::from_hex(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let message = b"This is a test message";

        let msg_hash = magic_hash(message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();

        assert!(verify_message_der(&der, &key.public_key(), message).unwrap());
    }

    #[test]
    fn test_verify_message_der_consistent_with_compact() {
        // Verify that both DER and compact verification agree
        let key = PrivateKey::random();
        let message = b"Consistency check";

        // Compact verification (standard BSM)
        let compact_sig = sign_message(&key, message).unwrap();
        let address = key.public_key().to_address();
        let compact_result = verify_message(&address, &compact_sig, message).unwrap();

        // DER verification
        let msg_hash = magic_hash(message);
        let sig = key.sign(&msg_hash).unwrap();
        let der = sig.to_der();
        let der_result = verify_message_der(&der, &key.public_key(), message).unwrap();

        // Both should agree
        assert_eq!(compact_result, der_result);
        assert!(compact_result);
    }

    #[test]
    fn test_verify_message_der_from_compact_roundtrip() {
        // Verify that a compact signature can be converted to DER and verified
        let key = PrivateKey::random();
        let message = b"Roundtrip test";

        let compact_sig = sign_message(&key, message).unwrap();

        // Extract r and s from compact signature and create DER
        let r: [u8; 32] = compact_sig[1..33].try_into().unwrap();
        let s: [u8; 32] = compact_sig[33..65].try_into().unwrap();
        let sig = crate::primitives::ec::Signature::new(r, s);
        let der = sig.to_der();

        // Verify using DER method
        assert!(verify_message_der(&der, &key.public_key(), message).unwrap());
    }
}
