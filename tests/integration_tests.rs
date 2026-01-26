//! Integration tests that verify cross-module functionality.
//!
//! These tests validate that all modules work together correctly,
//! testing complete workflows from key generation to transaction signing.

use bsv_primitives::bsv::schnorr::Schnorr;
use bsv_primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_primitives::bsv::sighash::{
    compute_sighash, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv_primitives::ec::{recover_public_key, PrivateKey};
use bsv_primitives::hash::{hash160, sha256, sha256_hmac, sha256d, sha512_hmac};
use bsv_primitives::p256::{P256PrivateKey, P256PublicKey};
use bsv_primitives::symmetric::SymmetricKey;
use bsv_primitives::{from_base58, from_base64, from_hex, to_base58, to_base64, to_hex};

// ============================================================================
// Full Key Derivation Workflow Tests
// ============================================================================

#[test]
fn test_full_key_derivation_workflow() {
    // Generate keys for Sender and Recipient
    // BRC-42: Recipient derives child private key, Sender derives matching public key
    let sender = PrivateKey::random();
    let recipient = PrivateKey::random();

    // Derive child keys for a specific invoice
    let invoice = "order-12345";
    // Recipient derives child private key using sender's public key
    let recipient_child = recipient
        .derive_child(&sender.public_key(), invoice)
        .unwrap();
    // Sender derives the corresponding public key using recipient's public key
    let sender_derived_pub = recipient
        .public_key()
        .derive_child(&sender, invoice)
        .unwrap();

    // The derived keys should match
    assert_eq!(
        recipient_child.public_key().to_compressed(),
        sender_derived_pub.to_compressed(),
        "BRC-42 key derivation should produce matching keys"
    );
}

#[test]
fn test_key_derivation_multiple_invoices() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Different invoices should produce different keys
    let invoices = ["invoice-001", "invoice-002", "payment-abc", ""];
    let mut derived_keys = Vec::new();

    for invoice in invoices {
        let child = alice.derive_child(&bob.public_key(), invoice).unwrap();
        derived_keys.push(child.public_key().to_compressed());
    }

    // All derived keys should be unique
    for i in 0..derived_keys.len() {
        for j in (i + 1)..derived_keys.len() {
            assert_ne!(
                derived_keys[i], derived_keys[j],
                "Different invoices should produce different keys"
            );
        }
    }
}

// ============================================================================
// Sign and Verify with Derived Keys
// ============================================================================

#[test]
fn test_sign_and_verify_with_derived_keys() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    let child = alice
        .derive_child(&bob.public_key(), "test-invoice")
        .unwrap();
    let msg_hash = sha256(b"Hello, BSV!");

    let sig = child.sign(&msg_hash).unwrap();
    assert!(
        child.public_key().verify(&msg_hash, &sig),
        "Signature should verify with derived key"
    );
    assert!(
        sig.is_low_s(),
        "Signature should be low-S (BIP 62 compliant)"
    );
}

#[test]
fn test_signature_recovery_with_derived_keys() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    let child = alice
        .derive_child(&bob.public_key(), "recovery-test")
        .unwrap();
    let child_pub = child.public_key();

    let msg_hash = sha256(b"test message for recovery");
    let signature = child.sign(&msg_hash).unwrap();

    // One of the recovery IDs should give us the correct public key
    let mut found = false;
    for recovery_id in 0..2u8 {
        if let Ok(recovered) = recover_public_key(&msg_hash, &signature, recovery_id) {
            if recovered.to_compressed() == child_pub.to_compressed() {
                found = true;
                break;
            }
        }
    }

    assert!(found, "Should recover the correct public key");
}

// ============================================================================
// Symmetric Encryption with Derived Key
// ============================================================================

#[test]
fn test_symmetric_encryption_with_derived_key() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Derive shared secret using ECDH
    let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

    // Use X coordinate as symmetric key
    let x = shared.x();
    let sym_key = SymmetricKey::from_bytes(&x).unwrap();

    // Encrypt and decrypt
    let plaintext = b"Secret message";
    let ciphertext = sym_key.encrypt(plaintext).unwrap();
    let decrypted = sym_key.decrypt(&ciphertext).unwrap();

    assert_eq!(
        plaintext.as_slice(),
        &decrypted[..],
        "Decrypted message should match original"
    );
}

#[test]
fn test_symmetric_encryption_bidirectional() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Both parties derive the same shared secret
    let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
    let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();

    assert_eq!(
        alice_shared.to_compressed(),
        bob_shared.to_compressed(),
        "ECDH shared secrets should match"
    );

    // Both can encrypt/decrypt using the same key
    let alice_key = SymmetricKey::from_bytes(&alice_shared.x()).unwrap();
    let bob_key = SymmetricKey::from_bytes(&bob_shared.x()).unwrap();

    let message = b"Hello from Alice";
    let ciphertext = alice_key.encrypt(message).unwrap();
    let decrypted = bob_key.decrypt(&ciphertext).unwrap();

    assert_eq!(message.as_slice(), &decrypted[..]);
}

// ============================================================================
// WIF and Address Roundtrip
// ============================================================================

#[test]
fn test_wif_address_roundtrip() {
    let key = PrivateKey::random();

    // Export to WIF
    let wif = key.to_wif();

    // Re-import
    let recovered = PrivateKey::from_wif(&wif).unwrap();

    // Generate address
    let address = recovered.public_key().to_address();

    // Verify same key
    assert_eq!(
        key.to_bytes(),
        recovered.to_bytes(),
        "WIF roundtrip should preserve key"
    );

    // Address should start with '1' (mainnet P2PKH)
    assert!(
        address.starts_with('1'),
        "Mainnet address should start with '1'"
    );
}

#[test]
fn test_testnet_wif_address() {
    let key = PrivateKey::random();

    // Export as testnet WIF (prefix 0xEF)
    let wif_testnet = key.to_wif_with_prefix(0xEF);

    // Re-import
    let recovered = PrivateKey::from_wif(&wif_testnet).unwrap();

    // Generate testnet address (prefix 0x6F)
    let address = recovered.public_key().to_address_with_prefix(0x6F);

    assert_eq!(key.to_bytes(), recovered.to_bytes());
    // Testnet addresses start with 'm' or 'n'
    assert!(
        address.starts_with('m') || address.starts_with('n'),
        "Testnet address should start with 'm' or 'n'"
    );
}

// ============================================================================
// Schnorr Proof with Derived Keys
// ============================================================================

#[test]
fn test_schnorr_proof_with_derived_keys() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    let alice_pub = alice.public_key();
    let bob_pub = bob.public_key();

    // Alice computes shared secret
    let shared = alice.derive_shared_secret(&bob_pub).unwrap();

    // Generate and verify Schnorr proof
    let proof = Schnorr::generate_proof(&alice, &alice_pub, &bob_pub, &shared).unwrap();
    assert!(
        Schnorr::verify_proof(&alice_pub, &bob_pub, &shared, &proof),
        "Schnorr proof should verify"
    );
}

#[test]
fn test_schnorr_proof_fails_with_wrong_secret() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let carol = PrivateKey::random();

    let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
    let wrong_shared = alice.derive_shared_secret(&carol.public_key()).unwrap();

    let proof =
        Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared).unwrap();

    // Verification should fail with wrong shared secret
    assert!(
        !Schnorr::verify_proof(
            &alice.public_key(),
            &bob.public_key(),
            &wrong_shared,
            &proof
        ),
        "Proof should not verify with wrong shared secret"
    );
}

// ============================================================================
// Shamir Secret Sharing with WIF Export
// ============================================================================

#[test]
fn test_shamir_with_wif_export() {
    let original = PrivateKey::random();
    let original_wif = original.to_wif();

    // Split into shares
    let shares = split_private_key(&original, 3, 5).unwrap();
    let backup = shares.to_backup_format();

    // Recover from backup format (using first 3 shares)
    let restored = KeyShares::from_backup_format(&backup[0..3]).unwrap();
    let recovered = restored.recover_private_key().unwrap();

    // WIFs should match
    assert_eq!(
        original_wif,
        recovered.to_wif(),
        "Recovered key should have same WIF"
    );
}

#[test]
fn test_shamir_different_subsets() {
    let key = PrivateKey::random();
    let key_bytes = key.to_bytes();

    let shares = split_private_key(&key, 3, 5).unwrap();
    let backup = shares.to_backup_format();

    // Test recovery with different subsets of 3 shares
    let subsets: Vec<Vec<String>> = vec![
        backup[0..3].to_vec(),                                         // First 3
        backup[1..4].to_vec(),                                         // Middle 3
        backup[2..5].to_vec(),                                         // Last 3
        vec![backup[0].clone(), backup[2].clone(), backup[4].clone()], // Every other
    ];

    for (i, subset) in subsets.iter().enumerate() {
        let restored = KeyShares::from_backup_format(subset).unwrap();
        let recovered = restored.recover_private_key().unwrap();
        assert_eq!(
            key_bytes,
            recovered.to_bytes(),
            "Subset {} should recover the same key",
            i
        );
    }
}

// ============================================================================
// P-256 Integration
// ============================================================================

#[test]
fn test_p256_sign_verify_roundtrip() {
    let private_key = P256PrivateKey::random();
    let public_key = private_key.public_key();

    let message = b"Hello, P-256!";
    let signature = private_key.sign(message);

    assert!(
        public_key.verify(message, &signature),
        "P-256 signature should verify"
    );
}

#[test]
fn test_p256_key_serialization() {
    let private_key = P256PrivateKey::random();
    let public_key = private_key.public_key();

    // Test hex roundtrip
    let priv_hex = private_key.to_hex();
    let recovered_priv = P256PrivateKey::from_hex(&priv_hex).unwrap();
    assert_eq!(private_key.to_bytes(), recovered_priv.to_bytes());

    // Test compressed/uncompressed public key
    let compressed = public_key.to_compressed();
    let uncompressed = public_key.to_uncompressed();

    let from_compressed = P256PublicKey::from_bytes(&compressed).unwrap();
    let from_uncompressed = P256PublicKey::from_bytes(&uncompressed).unwrap();

    assert_eq!(public_key.x(), from_compressed.x());
    assert_eq!(public_key.x(), from_uncompressed.x());
}

// ============================================================================
// Hash Chain Tests
// ============================================================================

#[test]
fn test_hash_chain_for_key_derivation() {
    let seed = b"master seed for key derivation";

    // Chain of hashes for deterministic key generation
    let h1 = sha256(seed);
    let h2 = sha256d(&h1);
    let h3 = hash160(&h2);

    // Each step should produce different output
    assert_ne!(h1.as_slice(), h2.as_slice());
    assert_ne!(h1[..20], h3);

    // Results should be deterministic
    let h1_repeat = sha256(seed);
    assert_eq!(h1, h1_repeat);
}

#[test]
fn test_hmac_for_key_derivation() {
    let master_key = b"master secret key";
    let data = b"child key derivation";

    let hmac256 = sha256_hmac(master_key, data);
    let hmac512 = sha512_hmac(master_key, data);

    assert_eq!(hmac256.len(), 32);
    assert_eq!(hmac512.len(), 64);

    // HMAC should be deterministic
    let hmac256_repeat = sha256_hmac(master_key, data);
    assert_eq!(hmac256, hmac256_repeat);
}

// ============================================================================
// Encoding Integration
// ============================================================================

#[test]
fn test_encoding_roundtrips() {
    let data = b"test data for encoding";

    // Hex roundtrip
    let hex = to_hex(data);
    let from_hex_data = from_hex(&hex).unwrap();
    assert_eq!(data.as_slice(), from_hex_data.as_slice());

    // Base64 roundtrip
    let b64 = to_base64(data);
    let from_b64_data = from_base64(&b64).unwrap();
    assert_eq!(data.as_slice(), from_b64_data.as_slice());

    // Base58 roundtrip
    let b58 = to_base58(data);
    let from_b58_data = from_base58(&b58).unwrap();
    assert_eq!(data.as_slice(), from_b58_data.as_slice());
}

#[test]
fn test_address_encoding_integration() {
    let key = PrivateKey::random();
    let pub_key = key.public_key();

    // Get hash160 of public key
    let h160 = pub_key.hash160();

    // Create address manually
    let manual_address = pub_key.to_address();

    // Address should be Base58Check encoded hash160 with version byte 0x00
    let (version, payload) = bsv_primitives::from_base58_check(&manual_address).unwrap();
    assert_eq!(version, vec![0x00]);
    assert_eq!(payload, h160.to_vec());
}

// ============================================================================
// Sighash Integration
// ============================================================================

#[test]
fn test_sighash_with_signature() {
    // Create a simple transaction structure
    let inputs = vec![TxInput {
        txid: [0u8; 32],
        output_index: 0,
        script: vec![],
        sequence: 0xffffffff,
    }];

    let outputs = vec![TxOutput {
        satoshis: 50000,
        script: vec![0x76, 0xa9, 0x14], // Partial P2PKH script
    }];

    let subscript = vec![0x76, 0xa9, 0x14]; // P2PKH script

    let params = SighashParams {
        version: 1,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
        input_index: 0,
        subscript: &subscript,
        satoshis: 100000,
        scope: SIGHASH_ALL | SIGHASH_FORKID,
    };

    // Compute sighash
    let sighash = compute_sighash(&params);

    // Sign the sighash
    let key = PrivateKey::random();
    let signature = key.sign(&sighash).unwrap();

    // Verify signature
    assert!(key.public_key().verify(&sighash, &signature));
}

// ============================================================================
// Complete Workflow Tests
// ============================================================================

#[test]
fn test_complete_payment_workflow() {
    // Simulate a complete payment workflow:
    // 1. Merchant generates a key pair
    // 2. Customer generates a key pair
    // 3. Both derive a payment-specific key using BRC-42
    // 4. Customer encrypts payment data
    // 5. Merchant can decrypt and verify

    // Step 1: Merchant key pair
    let merchant = PrivateKey::random();
    let merchant_pub = merchant.public_key();

    // Step 2: Customer key pair
    let customer = PrivateKey::random();
    let customer_pub = customer.public_key();

    // Step 3: Derive payment keys
    let invoice = "INV-2024-001";
    let customer_payment_key = customer.derive_child(&merchant_pub, invoice).unwrap();
    let merchant_derived_pub = customer_pub.derive_child(&merchant, invoice).unwrap();

    // Keys should match
    assert_eq!(
        customer_payment_key.public_key().to_compressed(),
        merchant_derived_pub.to_compressed()
    );

    // Step 4: Encrypt payment data using shared secret
    let shared_secret = customer.derive_shared_secret(&merchant_pub).unwrap();
    let encryption_key = SymmetricKey::from_bytes(&shared_secret.x()).unwrap();

    let payment_data = b"Payment of $100 for order #12345";
    let encrypted = encryption_key.encrypt(payment_data).unwrap();

    // Step 5: Merchant derives same shared secret and decrypts
    let merchant_shared = merchant.derive_shared_secret(&customer_pub).unwrap();
    let merchant_key = SymmetricKey::from_bytes(&merchant_shared.x()).unwrap();

    let decrypted = merchant_key.decrypt(&encrypted).unwrap();
    assert_eq!(payment_data.as_slice(), decrypted.as_slice());

    // Verify payment signature
    let payment_hash = sha256(payment_data);
    let signature = customer_payment_key.sign(&payment_hash).unwrap();

    assert!(merchant_derived_pub.verify(&payment_hash, &signature));
}

#[test]
fn test_key_backup_and_recovery_workflow() {
    // Complete key backup workflow:
    // 1. Generate master key
    // 2. Split into shares
    // 3. Export shares in backup format
    // 4. Recover from threshold shares
    // 5. Verify recovered key works for signing

    // Step 1: Generate master key
    let master_key = PrivateKey::random();
    let master_pub = master_key.public_key();

    // Step 2: Split into 5 shares, threshold 3
    let shares = split_private_key(&master_key, 3, 5).unwrap();

    // Step 3: Export to backup format
    let backup_strings = shares.to_backup_format();
    assert_eq!(backup_strings.len(), 5);

    // Step 4: Recover from any 3 shares (simulate user selecting shares 1, 3, 4)
    let selected_backups = vec![
        backup_strings[0].clone(),
        backup_strings[2].clone(),
        backup_strings[3].clone(),
    ];

    let restored_shares = KeyShares::from_backup_format(&selected_backups).unwrap();
    let recovered_key = restored_shares.recover_private_key().unwrap();

    // Step 5: Verify recovered key
    assert_eq!(master_key.to_bytes(), recovered_key.to_bytes());

    // Test that recovered key can sign
    let message_hash = sha256(b"Test message after recovery");
    let signature = recovered_key.sign(&message_hash).unwrap();

    assert!(master_pub.verify(&message_hash, &signature));
}

#[test]
fn test_multi_party_schnorr_verification() {
    // Test that both parties can generate and verify Schnorr proofs

    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Both compute the same shared secret
    let alice_shared = alice.derive_shared_secret(&bob.public_key()).unwrap();
    let bob_shared = bob.derive_shared_secret(&alice.public_key()).unwrap();

    assert_eq!(alice_shared.to_compressed(), bob_shared.to_compressed());

    // Alice generates proof
    let alice_proof = Schnorr::generate_proof(
        &alice,
        &alice.public_key(),
        &bob.public_key(),
        &alice_shared,
    )
    .unwrap();

    // Bob generates proof
    let bob_proof =
        Schnorr::generate_proof(&bob, &bob.public_key(), &alice.public_key(), &bob_shared).unwrap();

    // Cross verification
    assert!(Schnorr::verify_proof(
        &alice.public_key(),
        &bob.public_key(),
        &alice_shared,
        &alice_proof
    ));

    assert!(Schnorr::verify_proof(
        &bob.public_key(),
        &alice.public_key(),
        &bob_shared,
        &bob_proof
    ));
}
