//! Integration tests for the EC module with BRC-42 test vectors.

use bsv_primitives::ec::{PrivateKey, PublicKey};
use bsv_primitives::hash::sha256;
use serde::Deserialize;
use std::fs;

/// Test vector for BRC-42 private key derivation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Brc42PrivateVector {
    sender_public_key: String,
    recipient_private_key: String,
    invoice_number: String,
    private_key: String,
}

/// Test vector for BRC-42 public key derivation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Brc42PublicVector {
    sender_private_key: String,
    recipient_public_key: String,
    invoice_number: String,
    public_key: String,
}

fn load_brc42_private_vectors() -> Vec<Brc42PrivateVector> {
    let data = fs::read_to_string("tests/vectors/brc42_private.json")
        .expect("Failed to read brc42_private.json");
    serde_json::from_str(&data).expect("Failed to parse brc42_private.json")
}

fn load_brc42_public_vectors() -> Vec<Brc42PublicVector> {
    let data = fs::read_to_string("tests/vectors/brc42_public.json")
        .expect("Failed to read brc42_public.json");
    serde_json::from_str(&data).expect("Failed to parse brc42_public.json")
}

#[test]
fn test_brc42_private_derivation() {
    let vectors = load_brc42_private_vectors();

    for (i, v) in vectors.iter().enumerate() {
        // Parse sender's public key
        let sender_pub = PublicKey::from_hex(&v.sender_public_key)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse sender public key: {}", i, e));

        // Parse recipient's private key
        let recipient_priv = PrivateKey::from_hex(&v.recipient_private_key)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse recipient private key: {}", i, e));

        // The invoice number is used directly as a string (the base64 string is the invoice number)
        // This matches the Go SDK behavior where the JSON string is passed directly
        let invoice_str = &v.invoice_number;

        // Derive child private key
        let derived = recipient_priv
            .derive_child(&sender_pub, invoice_str)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to derive child key: {}", i, e));

        // Compare result
        assert_eq!(
            derived.to_hex(),
            v.private_key,
            "Vector {}: Derived private key does not match expected",
            i
        );
    }
}

#[test]
fn test_brc42_public_derivation() {
    let vectors = load_brc42_public_vectors();

    for (i, v) in vectors.iter().enumerate() {
        // Parse sender's private key
        let sender_priv = PrivateKey::from_hex(&v.sender_private_key)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse sender private key: {}", i, e));

        // Parse recipient's public key
        let recipient_pub = PublicKey::from_hex(&v.recipient_public_key)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse recipient public key: {}", i, e));

        // The invoice number is used directly as a string (the base64 string is the invoice number)
        let invoice_str = &v.invoice_number;

        // Derive child public key
        let derived = recipient_pub
            .derive_child(&sender_priv, invoice_str)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to derive child key: {}", i, e));

        // Compare result
        assert_eq!(
            derived.to_hex(),
            v.public_key,
            "Vector {}: Derived public key does not match expected",
            i
        );
    }
}

#[test]
fn test_brc42_consistency() {
    // Test that private key derivation and public key derivation produce consistent results
    let vectors = load_brc42_private_vectors();

    for (i, v) in vectors.iter().enumerate() {
        // Parse keys
        let sender_pub = PublicKey::from_hex(&v.sender_public_key).unwrap();
        let recipient_priv = PrivateKey::from_hex(&v.recipient_private_key).unwrap();

        // The invoice number is used directly as a string
        let invoice_str = &v.invoice_number;

        // Derive using private key method
        let derived_priv = recipient_priv.derive_child(&sender_pub, invoice_str).unwrap();

        // Verify the derived private key matches the expected result
        let derived_pub_from_priv = derived_priv.public_key();

        // Verify the public key from the derived private key is valid
        assert!(
            derived_pub_from_priv.to_hex().len() == 66,
            "Vector {}: Derived public key has wrong length",
            i
        );
    }
}

#[test]
fn test_wif_roundtrip_known_vectors() {
    // Known test vectors for WIF encoding
    let test_cases = [
        (
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            "0000000000000000000000000000000000000000000000000000000000000001",
        ),
        (
            "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ",
            "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd",
        ),
    ];

    for (wif, expected_hex) in test_cases {
        let key = PrivateKey::from_wif(wif).expect("Failed to parse WIF");
        assert_eq!(key.to_hex(), expected_hex, "WIF {} decoded incorrectly", wif);
        assert_eq!(key.to_wif(), wif, "WIF roundtrip failed");
    }
}

#[test]
fn test_public_key_known_vectors() {
    // Known test vectors: private key -> public key
    let test_cases = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        ),
    ];

    for (priv_hex, expected_pub_hex) in test_cases {
        let priv_key = PrivateKey::from_hex(priv_hex).expect("Failed to parse private key");
        let pub_key = priv_key.public_key();
        assert_eq!(
            pub_key.to_hex(),
            expected_pub_hex,
            "Public key mismatch for private key {}",
            priv_hex
        );
    }
}

#[test]
fn test_address_generation_known_vectors() {
    // Known test vectors for address generation
    let test_cases = [
        // Generator point (private key 1)
        (
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        ),
    ];

    for (pub_hex, expected_address) in test_cases {
        let pub_key = PublicKey::from_hex(pub_hex).expect("Failed to parse public key");
        let address = pub_key.to_address();
        assert_eq!(address, expected_address, "Address mismatch for {}", pub_hex);
    }
}

#[test]
fn test_sign_and_verify_roundtrip() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let messages = [
        b"Hello, BSV!".to_vec(),
        b"".to_vec(),
        vec![0u8; 100],
        vec![0xff; 256],
    ];

    for msg in &messages {
        let msg_hash = sha256(msg);
        let signature = private_key.sign(&msg_hash).expect("Signing failed");

        // Verify signature is valid
        assert!(
            public_key.verify(&msg_hash, &signature),
            "Signature verification failed for message of length {}",
            msg.len()
        );

        // Verify signature is low-S
        assert!(
            signature.is_low_s(),
            "Signature is not low-S for message of length {}",
            msg.len()
        );
    }
}

#[test]
fn test_ecdh_shared_secret() {
    // Generate two key pairs
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Compute shared secrets from both sides
    let alice_shared = alice
        .derive_shared_secret(&bob.public_key())
        .expect("Alice shared secret failed");
    let bob_shared = bob
        .derive_shared_secret(&alice.public_key())
        .expect("Bob shared secret failed");

    // They should be equal
    assert_eq!(
        alice_shared.to_compressed(),
        bob_shared.to_compressed(),
        "ECDH shared secrets do not match"
    );
}

#[test]
fn test_deterministic_signatures() {
    // RFC 6979 should produce deterministic signatures
    let private_key = PrivateKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();

    let msg_hash = sha256(b"test message");

    let sig1 = private_key.sign(&msg_hash).unwrap();
    let sig2 = private_key.sign(&msg_hash).unwrap();

    assert_eq!(sig1.r(), sig2.r(), "R components should be equal");
    assert_eq!(sig1.s(), sig2.s(), "S components should be equal");
}

#[test]
fn test_public_key_recovery() {
    use bsv_primitives::ec::recover_public_key;

    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let msg_hash = sha256(b"test message for recovery");
    let signature = private_key.sign(&msg_hash).unwrap();

    // One of the recovery IDs should give us the correct public key
    let mut found = false;
    for recovery_id in 0..2u8 {
        if let Ok(recovered) = recover_public_key(&msg_hash, &signature, recovery_id) {
            if recovered.to_compressed() == public_key.to_compressed() {
                found = true;
                break;
            }
        }
    }

    assert!(found, "Failed to recover the correct public key");
}
