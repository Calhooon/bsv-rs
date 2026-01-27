//! Messages module integration tests.
//!
//! Tests for BRC-77 message signing/verification and BRC-78 encryption/decryption.
//! Includes cross-SDK test vectors from TypeScript SDK for compatibility verification.

#![cfg(feature = "messages")]

use bsv_sdk::messages::{decrypt, encrypt, sign, verify, ENCRYPTED_VERSION, SIGNED_VERSION};
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::Error;

// =================
// Helper Functions
// =================

/// Creates a private key from a small scalar value (like Go/TS SDKs for test vectors)
fn key_from_scalar(scalar: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

// =================
// BRC-77 Signed Message Tests
// =================

#[test]
fn test_sign_and_verify_roundtrip_specific_recipient() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let message = b"Test message for specific recipient";

    // Sign for specific recipient
    let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();

    // Should have version + sender + recipient(33) + keyID + signature
    assert!(signature.len() > 4 + 33 + 33 + 32);

    // Version should be correct
    assert_eq!(&signature[0..4], &SIGNED_VERSION);

    // Verify with correct recipient
    let valid = verify(message, &signature, Some(&recipient)).unwrap();
    assert!(valid, "Signature should verify with correct recipient");
}

#[test]
fn test_sign_and_verify_roundtrip_anyone() {
    let sender = PrivateKey::random();
    let message = b"Test message for anyone to verify";

    // Sign for anyone
    let signature = sign(message, &sender, None).unwrap();

    // Should have version + sender + recipient(1) + keyID + signature
    assert!(signature.len() > 4 + 33 + 1 + 32);

    // Version should be correct
    assert_eq!(&signature[0..4], &SIGNED_VERSION);

    // Recipient marker should be 0x00
    assert_eq!(signature[4 + 33], 0x00, "Anyone marker should be 0x00");

    // Verify without recipient
    let valid = verify(message, &signature, None).unwrap();
    assert!(valid, "Anyone signature should verify without recipient key");
}

#[test]
fn test_verify_with_different_key_fails() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let wrong_recipient = PrivateKey::random();
    let message = b"Test message";

    // Sign for specific recipient
    let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();

    // Try to verify with wrong recipient - should return error
    let result = verify(message, &signature, Some(&wrong_recipient));
    assert!(result.is_err(), "Verification with wrong recipient should fail");

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
fn test_sign_and_verify_empty_message() {
    let sender = PrivateKey::random();
    let message = b"";

    // Sign empty message for anyone
    let signature = sign(message, &sender, None).unwrap();
    let valid = verify(message, &signature, None).unwrap();
    assert!(valid, "Empty message should sign and verify correctly");

    // Sign empty message for specific recipient
    let recipient = PrivateKey::random();
    let signature2 = sign(message, &sender, Some(&recipient.public_key())).unwrap();
    let valid2 = verify(message, &signature2, Some(&recipient)).unwrap();
    assert!(
        valid2,
        "Empty message should sign and verify with specific recipient"
    );
}

#[test]
fn test_sign_and_verify_large_message() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();

    // 100KB message
    let message = vec![0xAB; 100_000];

    // Sign for anyone
    let signature_anyone = sign(&message, &sender, None).unwrap();
    let valid_anyone = verify(&message, &signature_anyone, None).unwrap();
    assert!(valid_anyone, "Large message should verify for anyone");

    // Sign for specific recipient
    let signature_specific = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
    let valid_specific = verify(&message, &signature_specific, Some(&recipient)).unwrap();
    assert!(
        valid_specific,
        "Large message should verify for specific recipient"
    );
}

#[test]
fn test_tampered_message_returns_false_not_error() {
    let sender = PrivateKey::random();
    let message = b"Original message";
    let tampered = b"Tampered message";

    // Sign original message
    let signature = sign(message, &sender, None).unwrap();

    // Verify with tampered message should return false (not error)
    let valid = verify(tampered, &signature, None).unwrap();
    assert!(
        !valid,
        "Tampered message should return false, not verification error"
    );
}

#[test]
fn test_verify_without_recipient_when_required() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let message = b"Test message";

    // Sign for specific recipient
    let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();

    // Try to verify without providing recipient
    let result = verify(message, &signature, None);
    assert!(
        result.is_err(),
        "Verification without recipient should fail for recipient-specific signature"
    );

    match result {
        Err(Error::MessageError(msg)) => {
            assert!(
                msg.contains("specific private key"),
                "Error message should mention specific private key"
            );
            // Should contain the recipient's public key
            let recipient_pubkey_hex = hex::encode(recipient.public_key().to_compressed());
            assert!(
                msg.contains(&recipient_pubkey_hex),
                "Error message should contain recipient's public key"
            );
        }
        _ => panic!("Expected MessageError"),
    }
}

#[test]
fn test_signature_wrong_version() {
    let sender = PrivateKey::random();
    let message = b"Test message";

    let mut signature = sign(message, &sender, None).unwrap();

    // Tamper with version
    signature[0] = 0xFF;

    let result = verify(message, &signature, None);
    assert!(result.is_err());
    match result {
        Err(Error::MessageVersionMismatch { expected, actual }) => {
            assert_eq!(expected, hex::encode(SIGNED_VERSION));
            assert!(actual.starts_with("ff"));
        }
        _ => panic!("Expected MessageVersionMismatch error"),
    }
}

// =================
// BRC-78 Encrypted Message Tests
// =================

#[test]
fn test_encrypt_and_decrypt_roundtrip() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let plaintext = b"Hello, encrypted world!";

    // Encrypt
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
fn test_decrypt_with_wrong_key_fails() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let wrong_recipient = PrivateKey::random();
    let plaintext = b"Secret message";

    let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

    // Try to decrypt with wrong recipient
    let result = decrypt(&ciphertext, &wrong_recipient);
    assert!(result.is_err(), "Decryption with wrong key should fail");

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
fn test_encrypt_and_decrypt_empty_message() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let plaintext = b"";

    let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();
    let decrypted = decrypt(&ciphertext, &recipient).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_encrypt_and_decrypt_large_message() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();

    // 1MB message
    let plaintext = vec![0xAB; 1_000_000];

    let ciphertext = encrypt(&plaintext, &sender, &recipient.public_key()).unwrap();
    let decrypted = decrypt(&ciphertext, &recipient).unwrap();
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_tampered_ciphertext_fails_decryption() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let plaintext = b"Secret message";

    let mut ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

    // Tamper with encrypted data (after the header)
    let data_offset = 4 + 33 + 33 + 32;
    ciphertext[data_offset + 10] ^= 0xFF;

    // Should fail decryption (GCM authentication)
    let result = decrypt(&ciphertext, &recipient);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail decryption"
    );
}

#[test]
fn test_encrypted_message_wrong_version() {
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
fn test_same_plaintext_different_ciphertext() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let plaintext = b"Same message";

    // Encrypt twice - should produce different ciphertexts due to random keyID and IV
    let ciphertext1 = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();
    let ciphertext2 = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

    assert_ne!(
        ciphertext1, ciphertext2,
        "Same plaintext should produce different ciphertext each time"
    );

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

#[test]
fn test_different_senders_same_recipient() {
    let sender1 = PrivateKey::random();
    let sender2 = PrivateKey::random();
    let recipient = PrivateKey::random();
    let plaintext = b"Same message";

    let ciphertext1 = encrypt(plaintext, &sender1, &recipient.public_key()).unwrap();
    let ciphertext2 = encrypt(plaintext, &sender2, &recipient.public_key()).unwrap();

    // Ciphertexts should be different (different keys)
    assert_ne!(ciphertext1, ciphertext2);

    // Both should decrypt correctly
    let decrypted1 = decrypt(&ciphertext1, &recipient).unwrap();
    let decrypted2 = decrypt(&ciphertext2, &recipient).unwrap();
    assert_eq!(plaintext.to_vec(), decrypted1);
    assert_eq!(plaintext.to_vec(), decrypted2);
}

// =================
// Cross-SDK Compatibility Tests
// =================

#[test]
fn test_cross_sdk_sign_verify_specific_recipient() {
    // Same test as Go/TS SDKs: sender=15, recipient=21
    let sender = key_from_scalar(15);
    let recipient = key_from_scalar(21);
    let message = [1u8, 2, 4, 8, 16, 32];

    let signature = sign(&message, &sender, Some(&recipient.public_key())).unwrap();
    let valid = verify(&message, &signature, Some(&recipient)).unwrap();
    assert!(valid, "Cross-SDK test vector should verify");
}

#[test]
fn test_cross_sdk_sign_verify_anyone() {
    // Same test as Go/TS SDKs: sender=15, no recipient
    let sender = key_from_scalar(15);
    let message = [1u8, 2, 4, 8, 16, 32];

    let signature = sign(&message, &sender, None).unwrap();
    let valid = verify(&message, &signature, None).unwrap();
    assert!(valid, "Cross-SDK anyone signature should verify");
}

#[test]
fn test_cross_sdk_encrypt_decrypt() {
    // Same test as Go/TS SDKs: sender=15, recipient=21
    let sender = key_from_scalar(15);
    let recipient = key_from_scalar(21);
    let message = [1u8, 2, 4, 8, 16, 32];

    let ciphertext = encrypt(&message, &sender, &recipient.public_key()).unwrap();
    let decrypted = decrypt(&ciphertext, &recipient).unwrap();
    assert_eq!(message.to_vec(), decrypted);
}

#[test]
fn test_cross_sdk_wrong_version_signed_error_format() {
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
fn test_cross_sdk_no_verifier_error_format() {
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
fn test_cross_sdk_wrong_verifier_error_format() {
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

#[test]
fn test_cross_sdk_wrong_version_encrypted_error_format() {
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
fn test_cross_sdk_wrong_recipient_encrypted_error_format() {
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
fn test_cross_sdk_rare_key_length_encrypted() {
    // Test vector from TypeScript SDK - encrypted blob that handles rare key length case
    // (leading zeros in key BigNumber array)
    let recipient = key_from_scalar(21);

    // This is an encrypted message from TypeScript that decrypts correctly
    // even with edge cases in key derivation
    let encrypted: Vec<u8> = vec![
        66, 66, 16, 51, 2, 215, 146, 77, 79, 125, 67, 234, 150, 90, 70, 90, 227, 9, 95, 244, 17,
        49, 229, 148, 111, 60, 133, 247, 158, 68, 173, 188, 248, 226, 126, 8, 14, 2, 53, 43, 191,
        74, 76, 221, 18, 86, 79, 147, 250, 51, 44, 227, 51, 48, 29, 154, 212, 2, 113, 248, 16, 113,
        129, 52, 10, 239, 37, 190, 89, 213, 75, 148, 8, 235, 104, 137, 80, 129, 55, 68, 182, 141,
        118, 212, 215, 121, 161, 107, 62, 247, 12, 172, 244, 170, 208, 37, 213, 198, 103, 118, 75,
        166, 166, 131, 191, 105, 48, 232, 101, 223, 255, 169, 176, 204, 126, 249, 78, 178, 10, 51,
        13, 163, 58, 232, 122, 111, 210, 218, 187, 247, 164, 101, 207, 15, 37, 227, 108, 82, 70,
        35, 5, 148, 18, 162, 120, 64, 46, 40, 227, 197, 6, 112, 207, 200, 238, 81,
    ];

    // Should not panic - tests that rare key lengths are handled correctly
    let result = decrypt(&encrypted, &recipient);
    assert!(
        result.is_ok(),
        "Decryption should succeed for cross-SDK test vector with rare key length: {:?}",
        result.err()
    );
}

// =================
// Version Constant Tests
// =================

#[test]
fn test_version_constants() {
    // BRC-77 signed message version: 0x42423301
    assert_eq!(SIGNED_VERSION, [0x42, 0x42, 0x33, 0x01]);

    // BRC-78 encrypted message version: 0x42421033
    assert_eq!(ENCRYPTED_VERSION, [0x42, 0x42, 0x10, 0x33]);
}

// =================
// Unicode and Binary Data Tests
// =================

#[test]
fn test_sign_verify_unicode_message() {
    let sender = PrivateKey::random();
    let message = "Hello, world! \u{1F600} \u{1F389} \u{1F4BB}".as_bytes();

    let signature = sign(message, &sender, None).unwrap();
    let valid = verify(message, &signature, None).unwrap();
    assert!(valid, "Unicode message should sign and verify correctly");
}

#[test]
fn test_encrypt_decrypt_unicode_message() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    let message = "Hello, world! \u{1F600} \u{1F389} \u{1F4BB}".as_bytes();

    let ciphertext = encrypt(message, &sender, &recipient.public_key()).unwrap();
    let decrypted = decrypt(&ciphertext, &recipient).unwrap();
    assert_eq!(message.to_vec(), decrypted);
}

#[test]
fn test_sign_verify_binary_data() {
    let sender = PrivateKey::random();
    // Binary data with null bytes and all byte values
    let message: Vec<u8> = (0..=255).collect();

    let signature = sign(&message, &sender, None).unwrap();
    let valid = verify(&message, &signature, None).unwrap();
    assert!(valid, "Binary data should sign and verify correctly");
}

#[test]
fn test_encrypt_decrypt_binary_data() {
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();
    // Binary data with null bytes and all byte values
    let message: Vec<u8> = (0..=255).collect();

    let ciphertext = encrypt(&message, &sender, &recipient.public_key()).unwrap();
    let decrypted = decrypt(&ciphertext, &recipient).unwrap();
    assert_eq!(message, decrypted);
}

// =================
// Multiple Operations Tests
// =================

#[test]
fn test_multiple_signatures_same_message() {
    let sender = PrivateKey::random();
    let message = b"Same message";

    // Sign multiple times - each signature should be different (random keyID)
    let sig1 = sign(message, &sender, None).unwrap();
    let sig2 = sign(message, &sender, None).unwrap();
    let sig3 = sign(message, &sender, None).unwrap();

    // Signatures should be different
    assert_ne!(sig1, sig2);
    assert_ne!(sig2, sig3);
    assert_ne!(sig1, sig3);

    // All should verify
    assert!(verify(message, &sig1, None).unwrap());
    assert!(verify(message, &sig2, None).unwrap());
    assert!(verify(message, &sig3, None).unwrap());
}

#[test]
fn test_cross_communication() {
    // Alice and Bob can both sign and encrypt messages to each other
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    let alice_message = b"Hello Bob, this is Alice!";
    let bob_message = b"Hello Alice, this is Bob!";

    // Alice signs for Bob
    let alice_sig = sign(alice_message, &alice, Some(&bob.public_key())).unwrap();
    assert!(verify(alice_message, &alice_sig, Some(&bob)).unwrap());

    // Bob signs for Alice
    let bob_sig = sign(bob_message, &bob, Some(&alice.public_key())).unwrap();
    assert!(verify(bob_message, &bob_sig, Some(&alice)).unwrap());

    // Alice encrypts for Bob
    let alice_encrypted = encrypt(alice_message, &alice, &bob.public_key()).unwrap();
    assert_eq!(
        alice_message.to_vec(),
        decrypt(&alice_encrypted, &bob).unwrap()
    );

    // Bob encrypts for Alice
    let bob_encrypted = encrypt(bob_message, &bob, &alice.public_key()).unwrap();
    assert_eq!(
        bob_message.to_vec(),
        decrypt(&bob_encrypted, &alice).unwrap()
    );
}
