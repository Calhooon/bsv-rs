//! ECDSA signature operations.
//!
//! This module provides functions for signing, verifying, and recovering public keys
//! from ECDSA signatures on the secp256k1 curve.

use crate::error::{Error, Result};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, VerifyingKey};

use super::{PrivateKey, PublicKey, Signature};

/// Signs a message hash with a private key.
///
/// Returns a low-S signature (BIP 62 compliant) using RFC 6979 deterministic nonce.
///
/// # Arguments
///
/// * `msg_hash` - The 32-byte message hash
/// * `private_key` - The private key to sign with
///
/// # Returns
///
/// A low-S signature
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::ec::{PrivateKey, sign, verify};
/// use bsv_rs::primitives::hash::sha256;
///
/// let key = PrivateKey::random();
/// let msg_hash = sha256(b"Hello!");
///
/// let signature = sign(&msg_hash, &key).unwrap();
/// assert!(verify(&msg_hash, &signature, &key.public_key()));
/// ```
pub fn sign(msg_hash: &[u8; 32], private_key: &PrivateKey) -> Result<Signature> {
    private_key.sign(msg_hash)
}

/// Verifies a signature against a public key and message hash.
///
/// # Arguments
///
/// * `msg_hash` - The 32-byte message hash
/// * `signature` - The signature to verify
/// * `public_key` - The public key to verify against
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::ec::{PrivateKey, sign, verify};
/// use bsv_rs::primitives::hash::sha256;
///
/// let key = PrivateKey::random();
/// let msg_hash = sha256(b"Hello!");
///
/// let signature = sign(&msg_hash, &key).unwrap();
/// assert!(verify(&msg_hash, &signature, &key.public_key()));
///
/// // Wrong public key should fail
/// let other_key = PrivateKey::random();
/// assert!(!verify(&msg_hash, &signature, &other_key.public_key()));
/// ```
pub fn verify(msg_hash: &[u8; 32], signature: &Signature, public_key: &PublicKey) -> bool {
    // Convert to k256 types
    let verifying_key = match VerifyingKey::from_sec1_bytes(&public_key.to_compressed()) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    // Convert signature to k256 format
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(signature.r());
    sig_bytes[32..].copy_from_slice(signature.s());

    let k256_sig = match k256::ecdsa::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify
    verifying_key.verify_prehash(msg_hash, &k256_sig).is_ok()
}

/// Recovers a public key from a signature and message hash.
///
/// ECDSA signatures have multiple possible public keys that could have created them.
/// The `recovery_id` (0 or 1) specifies which of the two possible keys to return.
///
/// # Arguments
///
/// * `msg_hash` - The 32-byte message hash
/// * `signature` - The signature
/// * `recovery_id` - Which public key to recover (0 or 1)
///
/// # Returns
///
/// The recovered public key, or an error if recovery fails
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::ec::{PrivateKey, sign, recover_public_key};
/// use bsv_rs::primitives::hash::sha256;
///
/// let key = PrivateKey::random();
/// let msg_hash = sha256(b"Hello!");
/// let signature = sign(&msg_hash, &key).unwrap();
///
/// // Try both recovery IDs to find the correct public key
/// let pub_key = key.public_key();
/// let mut found = false;
/// for recovery_id in 0..2 {
///     if let Ok(recovered) = recover_public_key(&msg_hash, &signature, recovery_id) {
///         if recovered.to_compressed() == pub_key.to_compressed() {
///             found = true;
///             break;
///         }
///     }
/// }
/// assert!(found);
/// ```
pub fn recover_public_key(
    msg_hash: &[u8; 32],
    signature: &Signature,
    recovery_id: u8,
) -> Result<PublicKey> {
    if recovery_id > 1 {
        return Err(Error::InvalidSignature(format!(
            "Recovery ID must be 0 or 1, got {}",
            recovery_id
        )));
    }

    // Convert signature to k256 format
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(signature.r());
    sig_bytes[32..].copy_from_slice(signature.s());

    let k256_sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid signature format: {}", e)))?;

    let recid = RecoveryId::from_byte(recovery_id)
        .ok_or_else(|| Error::InvalidSignature("Invalid recovery ID".to_string()))?;

    // Recover the verifying key
    let verifying_key = VerifyingKey::recover_from_prehash(msg_hash, &k256_sig, recid)
        .map_err(|e| Error::CryptoError(format!("Public key recovery failed: {}", e)))?;

    // Convert to our PublicKey type
    let encoded = verifying_key.to_encoded_point(true);
    PublicKey::from_bytes(encoded.as_bytes())
}

/// Calculates the recovery ID for a given signature and public key.
///
/// This is useful when you have a signature and know the public key, and need
/// to determine which recovery ID would recover that public key.
///
/// # Arguments
///
/// * `msg_hash` - The 32-byte message hash
/// * `signature` - The signature
/// * `public_key` - The expected public key
///
/// # Returns
///
/// The recovery ID (0 or 1), or an error if no valid recovery ID is found
pub fn calculate_recovery_id(
    msg_hash: &[u8; 32],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<u8> {
    let expected = public_key.to_compressed();

    for recovery_id in 0..2u8 {
        if let Ok(recovered) = recover_public_key(msg_hash, signature, recovery_id) {
            if recovered.to_compressed() == expected {
                return Ok(recovery_id);
            }
        }
    }

    Err(Error::CryptoError(
        "Could not find valid recovery ID".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::sha256;

    #[test]
    fn test_sign_and_verify() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let msg_hash = sha256(b"Hello, BSV!");
        let signature = sign(&msg_hash, &key).unwrap();

        assert!(verify(&msg_hash, &signature, &pubkey));
    }

    #[test]
    fn test_verify_wrong_key() {
        let key = PrivateKey::random();
        let other_key = PrivateKey::random();

        let msg_hash = sha256(b"Hello, BSV!");
        let signature = sign(&msg_hash, &key).unwrap();

        assert!(!verify(&msg_hash, &signature, &other_key.public_key()));
    }

    #[test]
    fn test_verify_wrong_message() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let msg_hash1 = sha256(b"Hello, BSV!");
        let msg_hash2 = sha256(b"Goodbye, BSV!");
        let signature = sign(&msg_hash1, &key).unwrap();

        assert!(!verify(&msg_hash2, &signature, &pubkey));
    }

    #[test]
    fn test_recover_public_key() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let msg_hash = sha256(b"Hello, BSV!");
        let signature = sign(&msg_hash, &key).unwrap();

        // One of the recovery IDs should give us the correct public key
        let mut found = false;
        for recovery_id in 0..2u8 {
            if let Ok(recovered) = recover_public_key(&msg_hash, &signature, recovery_id) {
                if recovered.to_compressed() == pubkey.to_compressed() {
                    found = true;
                    break;
                }
            }
        }
        assert!(found);
    }

    #[test]
    fn test_calculate_recovery_id() {
        let key = PrivateKey::random();
        let pubkey = key.public_key();

        let msg_hash = sha256(b"Hello, BSV!");
        let signature = sign(&msg_hash, &key).unwrap();

        let recovery_id = calculate_recovery_id(&msg_hash, &signature, &pubkey).unwrap();
        assert!(recovery_id < 2);

        // Verify that the recovery ID works
        let recovered = recover_public_key(&msg_hash, &signature, recovery_id).unwrap();
        assert_eq!(recovered.to_compressed(), pubkey.to_compressed());
    }

    #[test]
    fn test_invalid_recovery_id() {
        let msg_hash = sha256(b"test");
        let sig = Signature::new([1u8; 32], [2u8; 32]);

        assert!(recover_public_key(&msg_hash, &sig, 2).is_err());
        assert!(recover_public_key(&msg_hash, &sig, 255).is_err());
    }

    #[test]
    fn test_signature_low_s() {
        let key = PrivateKey::random();

        let msg_hash = sha256(b"Test message");
        let signature = sign(&msg_hash, &key).unwrap();

        // All signatures should be low-S
        assert!(signature.is_low_s());
    }

    #[test]
    fn test_deterministic_signing() {
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let msg_hash = sha256(b"test");

        let sig1 = sign(&msg_hash, &key).unwrap();
        let sig2 = sign(&msg_hash, &key).unwrap();

        // RFC 6979 produces deterministic signatures
        assert_eq!(sig1.r(), sig2.r());
        assert_eq!(sig1.s(), sig2.s());
    }
}
