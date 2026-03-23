//! # Messages Module
//!
//! Peer-to-peer signed and encrypted messaging for BSV.
//!
//! This module implements:
//! - **BRC-77**: Signed messages with optional recipient-specific verification
//! - **BRC-78**: Encrypted messages using ECDH key derivation
//!
//! ## Quick Start
//!
//! ### Signed Messages (BRC-77)
//!
//! ```rust
//! use bsv_rs::primitives::PrivateKey;
//! use bsv_rs::messages::{sign, verify};
//!
//! let sender = PrivateKey::random();
//! let recipient = PrivateKey::random();
//!
//! // Sign for a specific recipient
//! let message = b"Hello, BSV!";
//! let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();
//!
//! // Verify with recipient's private key
//! let valid = verify(message, &signature, Some(&recipient)).unwrap();
//! assert!(valid);
//!
//! // Sign for anyone to verify
//! let sig_anyone = sign(message, &sender, None).unwrap();
//! let valid_anyone = verify(message, &sig_anyone, None).unwrap();
//! assert!(valid_anyone);
//! ```
//!
//! ### Encrypted Messages (BRC-78)
//!
//! ```rust
//! use bsv_rs::primitives::PrivateKey;
//! use bsv_rs::messages::{encrypt, decrypt};
//!
//! let sender = PrivateKey::random();
//! let recipient = PrivateKey::random();
//!
//! // Encrypt a message
//! let plaintext = b"Secret message";
//! let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();
//!
//! // Decrypt with recipient's private key
//! let decrypted = decrypt(&ciphertext, &recipient).unwrap();
//! assert_eq!(plaintext.to_vec(), decrypted);
//! ```
//!
//! ## Wire Formats
//!
//! ### Signed Message Format
//! ```text
//! [version: 4 bytes] [sender_pubkey: 33 bytes] [recipient: 1 or 33 bytes] [keyID: 32 bytes] [signature: DER]
//! ```
//! - Version: `0x42423301`
//! - Recipient: `0x00` for anyone, or 33-byte compressed public key
//!
//! ### Encrypted Message Format
//! ```text
//! [version: 4 bytes] [sender_pubkey: 33 bytes] [recipient_pubkey: 33 bytes] [keyID: 32 bytes] [ciphertext]
//! ```
//! - Version: `0x42421033`
//! - Ciphertext includes 32-byte IV and 16-byte GCM tag

mod encrypted;
mod signed;

pub use encrypted::{decrypt, encrypt};
pub use signed::{sign, verify};

/// Version bytes for signed messages (BRC-77): 0x42423301
pub const SIGNED_VERSION: [u8; 4] = [0x42, 0x42, 0x33, 0x01];

/// Version bytes for encrypted messages (BRC-78): 0x42421033
pub const ENCRYPTED_VERSION: [u8; 4] = [0x42, 0x42, 0x10, 0x33];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_sign_verify_roundtrip() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let message = b"Test message for signing";

        // Sign for specific recipient
        let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();

        // Verify with correct recipient
        let valid = verify(message, &signature, Some(&recipient)).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_verify_anyone() {
        let sender = PrivateKey::random();
        let message = b"Anyone can verify this";

        // Sign for anyone
        let signature = sign(message, &sender, None).unwrap();

        // Verify without recipient
        let valid = verify(message, &signature, None).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = PrivateKey::random();
        let recipient = PrivateKey::random();
        let plaintext = b"Secret message content";

        // Encrypt
        let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

        // Decrypt
        let decrypted = decrypt(&ciphertext, &recipient).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_version_bytes() {
        assert_eq!(SIGNED_VERSION, [0x42, 0x42, 0x33, 0x01]);
        assert_eq!(ENCRYPTED_VERSION, [0x42, 0x42, 0x10, 0x33]);
    }
}
