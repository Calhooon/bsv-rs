//! Compat module integration tests.
//!
//! Tests full workflows for BIP-32, BIP-39, BSM, and ECIES modules.

#![cfg(feature = "compat")]

use bsv_sdk::compat::base58;
use bsv_sdk::compat::bip32::{
    generate_hd_key_from_mnemonic, ExtendedKey, Network, HARDENED_KEY_START,
};
use bsv_sdk::compat::bip39::{Language, Mnemonic, WordCount};
use bsv_sdk::compat::bsm;
use bsv_sdk::compat::ecies;
use bsv_sdk::primitives::{from_hex, PrivateKey};

// =================
// BIP-39 + BIP-32 Integration Tests
// =================

#[test]
fn test_full_hd_wallet_generation_flow() {
    // Generate a mnemonic
    let mnemonic = Mnemonic::new(WordCount::Words12).expect("Failed to generate mnemonic");

    // Verify word count
    assert_eq!(mnemonic.words().len(), 12);

    // Convert to seed
    let seed = mnemonic.to_seed("");
    assert_eq!(seed.len(), 64);

    // Generate master key
    let master =
        ExtendedKey::new_master(&seed, Network::Mainnet).expect("Failed to create master key");

    // Verify it's a private key
    assert!(master.is_private());
    assert!(master.to_string().starts_with("xprv"));

    // Derive BIP-44 path for BSV: m/44'/236'/0'/0/0
    let derived = master
        .derive_path("m/44'/236'/0'/0/0")
        .expect("Failed to derive path");

    // Get address
    let address = derived.address(true).expect("Failed to get address");
    assert!(address.starts_with('1')); // Mainnet P2PKH address
}

#[test]
fn test_mnemonic_to_hd_key_helper() {
    let mnemonic = Mnemonic::new(WordCount::Words24).expect("Failed to generate mnemonic");

    // Use the helper function
    let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet)
        .expect("Failed to generate HD key from mnemonic");

    assert!(master.is_private());

    // Derive public extended key
    let xpub = master.neuter().expect("Failed to neuter");
    assert!(!xpub.is_private());
    assert!(xpub.to_string().starts_with("xpub"));
}

#[test]
fn test_testnet_hd_key_derivation() {
    let seed = [0u8; 32];
    let master =
        ExtendedKey::new_master(&seed, Network::Testnet).expect("Failed to create testnet master");

    assert!(master.to_string().starts_with("tprv"));

    let xpub = master.neuter().expect("Failed to neuter");
    assert!(xpub.to_string().starts_with("tpub"));

    // Testnet address
    let address = master
        .address(false)
        .expect("Failed to get testnet address");
    assert!(address.starts_with('m') || address.starts_with('n'));
}

#[test]
fn test_hardened_derivation() {
    let seed = [0u8; 32];
    let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

    // Hardened derivation using index
    let child_0h = master.derive_child(HARDENED_KEY_START).unwrap();

    // Hardened derivation using path notation
    let child_0h_path = master.derive_path("m/0'").unwrap();

    // Should produce the same keys
    assert_eq!(
        child_0h.to_string(),
        child_0h_path.to_string(),
        "Hardened derivation mismatch"
    );
}

#[test]
fn test_public_key_derivation_only() {
    let seed = [0u8; 32];
    let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

    // Get public master
    let xpub = master.neuter().unwrap();

    // Derive non-hardened children from public key
    let pub_child_0 = xpub.derive_child(0).unwrap();
    let priv_child_0 = master.derive_child(0).unwrap().neuter().unwrap();

    assert_eq!(
        pub_child_0.to_string(),
        priv_child_0.to_string(),
        "Public derivation should match private derivation result"
    );

    // Hardened derivation from public key should fail
    let result = xpub.derive_child(HARDENED_KEY_START);
    assert!(result.is_err(), "Hardened from public should fail");
}

#[test]
fn test_extended_key_serialization_roundtrip() {
    let seed = [0x42u8; 32];
    let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

    // Serialize to string
    let xprv_str = master.to_string();

    // Parse back
    let parsed = ExtendedKey::from_string(&xprv_str).unwrap();

    // Should be identical
    assert_eq!(master.to_string(), parsed.to_string());
    assert_eq!(master.depth(), parsed.depth());
    assert_eq!(master.child_number(), parsed.child_number());
    assert_eq!(master.chain_code(), parsed.chain_code());
}

// =================
// Bitcoin Signed Message Tests
// =================

#[test]
fn test_bsm_sign_verify_roundtrip() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();
    let message = b"Hello, Bitcoin!";

    // Sign
    let signature = bsm::sign_message(&key, message).expect("Failed to sign");
    assert_eq!(signature.len(), 65);

    // Verify
    let valid = bsm::verify_message(&address, &signature, message).expect("Verification failed");
    assert!(valid, "Signature should be valid");
}

#[test]
fn test_bsm_compressed_and_uncompressed() {
    let key = PrivateKey::random();
    let message = b"Test message";

    // Compressed signature (default)
    let sig_compressed = bsm::sign_message_with_compression(&key, message, true).unwrap();
    let recovered_comp = bsm::recover_public_key_from_signature(&sig_compressed, message).unwrap();
    assert!(recovered_comp.1, "Should be compressed");

    // Uncompressed signature
    let sig_uncompressed = bsm::sign_message_with_compression(&key, message, false).unwrap();
    let recovered_uncomp =
        bsm::recover_public_key_from_signature(&sig_uncompressed, message).unwrap();
    assert!(!recovered_uncomp.1, "Should be uncompressed");

    // Both should recover to the same public key
    assert_eq!(
        recovered_comp.0.to_compressed(),
        recovered_uncomp.0.to_compressed(),
        "Recovered public keys should match"
    );
}

#[test]
fn test_bsm_different_messages_different_signatures() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    let message1 = b"Message 1";
    let message2 = b"Message 2";

    let sig1 = bsm::sign_message(&key, message1).unwrap();
    let sig2 = bsm::sign_message(&key, message2).unwrap();

    // Signatures should be different
    assert_ne!(sig1, sig2);

    // Cross-verify should fail
    let cross1 = bsm::verify_message(&address, &sig1, message2).unwrap();
    let cross2 = bsm::verify_message(&address, &sig2, message1).unwrap();
    assert!(!cross1, "Signature 1 should not verify message 2");
    assert!(!cross2, "Signature 2 should not verify message 1");
}

#[test]
fn test_bsm_public_key_recovery() {
    let key = PrivateKey::random();
    let original_pubkey = key.public_key();
    let message = b"Recover me";

    let signature = bsm::sign_message(&key, message).unwrap();
    let (recovered, _compressed) =
        bsm::recover_public_key_from_signature(&signature, message).unwrap();

    assert_eq!(
        recovered.to_compressed(),
        original_pubkey.to_compressed(),
        "Recovered public key should match original"
    );
}

#[test]
fn test_bsm_empty_and_long_messages() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // Empty message
    let empty_sig = bsm::sign_message(&key, b"").unwrap();
    assert!(bsm::verify_message(&address, &empty_sig, b"").unwrap());

    // Long message (1KB)
    let long_message = vec![0x42u8; 1024];
    let long_sig = bsm::sign_message(&key, &long_message).unwrap();
    assert!(bsm::verify_message(&address, &long_sig, &long_message).unwrap());
}

// =================
// ECIES Encryption Tests
// =================

#[test]
fn test_electrum_ecies_roundtrip() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let message = b"Secret message from Alice to Bob";

    // Alice encrypts for Bob
    let encrypted = ecies::electrum_encrypt(message, &bob.public_key(), &alice, false)
        .expect("Encryption failed");

    // Encrypted should be larger than plaintext (has header, IV, MAC)
    assert!(encrypted.len() > message.len());
    assert!(encrypted.starts_with(b"BIE1"));

    // Bob decrypts
    let decrypted = ecies::electrum_decrypt(&encrypted, &bob, Some(&alice.public_key()))
        .expect("Decryption failed");

    assert_eq!(decrypted, message);
}

#[test]
fn test_electrum_ecies_no_key_mode() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let message = b"Anonymous message";

    // Encrypt with no_key = true (omits ephemeral public key from output)
    let encrypted = ecies::electrum_encrypt(message, &bob.public_key(), &alice, true)
        .expect("Encryption failed");

    // When no_key=true, the sender's public key is not embedded,
    // so Bob must know Alice's public key to decrypt
    let decrypted = ecies::electrum_decrypt(&encrypted, &bob, Some(&alice.public_key()))
        .expect("Decryption failed");

    assert_eq!(decrypted, message);

    // Verify that trying to decrypt without sender's key fails (no embedded key to extract)
    let result = ecies::electrum_decrypt(&encrypted, &bob, None);
    assert!(
        result.is_err(),
        "Should fail without sender's public key when no_key=true"
    );
}

#[test]
fn test_bitcore_ecies_roundtrip() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let message = b"Bitcore-style encrypted message";

    // Encrypt
    let encrypted = ecies::bitcore_encrypt(message, &bob.public_key(), &alice, None)
        .expect("Encryption failed");

    // Decrypt
    let decrypted = ecies::bitcore_decrypt(&encrypted, &bob).expect("Decryption failed");

    assert_eq!(decrypted, message);
}

#[test]
fn test_bitcore_ecies_with_fixed_iv() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let message = b"Deterministic encryption test";

    // Fixed IV for deterministic output
    let iv = [0x42u8; 16];

    // Encrypt twice with same IV
    let encrypted1 = ecies::bitcore_encrypt(message, &bob.public_key(), &alice, Some(&iv)).unwrap();
    let encrypted2 = ecies::bitcore_encrypt(message, &bob.public_key(), &alice, Some(&iv)).unwrap();

    // Should be identical
    assert_eq!(encrypted1, encrypted2);

    // Decrypt
    let decrypted = ecies::bitcore_decrypt(&encrypted1, &bob).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_ecies_self_encryption() {
    let key = PrivateKey::random();
    let message = b"Self-encrypted message";

    // Encrypt to self
    let encrypted = ecies::encrypt_single(message, &key).expect("Self-encryption failed");

    // Decrypt
    let decrypted = ecies::decrypt_single(&encrypted, &key).expect("Self-decryption failed");

    assert_eq!(decrypted, message);
}

#[test]
fn test_ecies_wrong_key_fails() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let charlie = PrivateKey::random(); // Wrong key
    let message = b"This should not be readable by Charlie";

    // Alice encrypts for Bob
    let encrypted = ecies::electrum_encrypt(message, &bob.public_key(), &alice, false).unwrap();

    // Charlie tries to decrypt (should fail)
    let result = ecies::electrum_decrypt(&encrypted, &charlie, Some(&alice.public_key()));
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_ecies_empty_and_large_messages() {
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();

    // Empty message
    let empty_encrypted = ecies::electrum_encrypt(b"", &bob.public_key(), &alice, false).unwrap();
    let empty_decrypted =
        ecies::electrum_decrypt(&empty_encrypted, &bob, Some(&alice.public_key())).unwrap();
    assert_eq!(empty_decrypted, b"");

    // Large message (64KB)
    let large_message = vec![0xAB_u8; 65536];
    let large_encrypted =
        ecies::bitcore_encrypt(&large_message, &bob.public_key(), &alice, None).unwrap();
    let large_decrypted = ecies::bitcore_decrypt(&large_encrypted, &bob).unwrap();
    assert_eq!(large_decrypted, large_message);
}

// =================
// Base58 Tests
// =================

#[test]
fn test_base58_roundtrip() {
    let test_data = vec![
        vec![0x00],
        vec![0x00, 0x00, 0x01],
        vec![0x00, 0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd],
        vec![0xFF; 32],
        (0..100).collect::<Vec<u8>>(),
    ];

    for data in test_data {
        let encoded = base58::encode(&data);
        let decoded = base58::decode(&encoded).expect("Decode failed");
        assert_eq!(
            decoded,
            data,
            "Roundtrip failed for data of length {}",
            data.len()
        );
    }
}

#[test]
fn test_base58_leading_zeros() {
    // Leading zeros should become leading '1's
    let data = [0x00, 0x00, 0x00, 0x01];
    let encoded = base58::encode(&data);
    assert!(
        encoded.starts_with("111"),
        "Expected leading 1s for leading zeros"
    );

    let decoded = base58::decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_base58_known_values() {
    // Bitcoin genesis block hash
    let genesis_hash =
        from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
    let encoded = base58::encode(&genesis_hash);
    let decoded = base58::decode(&encoded).unwrap();
    assert_eq!(decoded, genesis_hash);
}

// =================
// Cross-Module Integration Tests
// =================

#[test]
fn test_mnemonic_to_signed_message() {
    // Generate mnemonic
    let mnemonic = Mnemonic::new(WordCount::Words12).unwrap();

    // Derive key
    let master = generate_hd_key_from_mnemonic(&mnemonic, "", Network::Mainnet).unwrap();
    let derived = master.derive_path("m/44'/0'/0'/0/0").unwrap();

    // Get private key and address
    let private_key = derived.private_key().unwrap();
    let address = derived.address(true).unwrap();

    // Sign message
    let message = b"Signed with HD key";
    let signature = bsm::sign_message(&private_key, message).unwrap();

    // Verify
    assert!(bsm::verify_message(&address, &signature, message).unwrap());
}

#[test]
fn test_mnemonic_to_ecies_encryption() {
    // Generate two mnemonics (Alice and Bob)
    let mnemonic_alice = Mnemonic::new(WordCount::Words12).unwrap();
    let mnemonic_bob = Mnemonic::new(WordCount::Words12).unwrap();

    // Derive keys
    let alice_master =
        generate_hd_key_from_mnemonic(&mnemonic_alice, "", Network::Mainnet).unwrap();
    let bob_master = generate_hd_key_from_mnemonic(&mnemonic_bob, "", Network::Mainnet).unwrap();

    let alice_key = alice_master
        .derive_path("m/44'/0'/0'/0/0")
        .unwrap()
        .private_key()
        .unwrap();
    let bob_key = bob_master
        .derive_path("m/44'/0'/0'/0/0")
        .unwrap()
        .private_key()
        .unwrap();

    // Alice encrypts for Bob
    let message = b"Secret from Alice to Bob using HD keys";
    let encrypted =
        ecies::electrum_encrypt(message, &bob_key.public_key(), &alice_key, false).unwrap();

    // Bob decrypts
    let decrypted =
        ecies::electrum_decrypt(&encrypted, &bob_key, Some(&alice_key.public_key())).unwrap();
    assert_eq!(decrypted, message);
}

// =================
// Error Handling Tests
// =================

#[test]
fn test_invalid_mnemonic_phrase() {
    // Invalid word
    let result = Mnemonic::from_phrase("invalid word here abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    assert!(result.is_err());

    // Wrong word count
    let result = Mnemonic::from_phrase("abandon abandon");
    assert!(result.is_err());

    // Invalid checksum
    let result = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    assert!(result.is_err());
}

#[test]
fn test_invalid_extended_key_string() {
    // Invalid prefix
    let result = ExtendedKey::from_string("invalid_xprv_string");
    assert!(result.is_err());

    // Wrong length
    let result = ExtendedKey::from_string("xprv123");
    assert!(result.is_err());

    // Bad checksum (last char changed from 'i' to 'j' to corrupt checksum)
    let result = ExtendedKey::from_string("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHj");
    assert!(result.is_err());
}

#[test]
fn test_invalid_derivation_path() {
    let seed = [0u8; 32];
    let master = ExtendedKey::new_master(&seed, Network::Mainnet).unwrap();

    // Invalid format
    let result = master.derive_path("not/a/path");
    assert!(result.is_err());

    // Negative index (not supported)
    let result = master.derive_path("m/-1");
    assert!(result.is_err());
}

#[test]
fn test_invalid_bsm_signature() {
    let key = PrivateKey::random();
    let address = key.public_key().to_address();

    // Too short
    let result = bsm::verify_message(&address, &[0u8; 64], b"test");
    assert!(result.is_err());

    // Too long
    let result = bsm::verify_message(&address, &[0u8; 66], b"test");
    assert!(result.is_err());
}

#[test]
fn test_invalid_ecies_ciphertext() {
    let key = PrivateKey::random();

    // Electrum: wrong magic
    let result = ecies::electrum_decrypt(&[0u8; 100], &key, None);
    assert!(result.is_err());

    // Bitcore: too short
    let result = ecies::bitcore_decrypt(&[0u8; 32], &key);
    assert!(result.is_err());
}

// =================
// Vector Count Test
// =================

#[test]
fn test_word_count_enum() {
    assert_eq!(WordCount::Words12.word_count(), 12);
    assert_eq!(WordCount::Words15.word_count(), 15);
    assert_eq!(WordCount::Words18.word_count(), 18);
    assert_eq!(WordCount::Words21.word_count(), 21);
    assert_eq!(WordCount::Words24.word_count(), 24);

    assert_eq!(WordCount::Words12.entropy_bytes(), 16);
    assert_eq!(WordCount::Words24.entropy_bytes(), 32);
}

#[test]
fn test_language_enum() {
    // Currently only English is supported
    let lang = Language::English;
    assert!(matches!(lang, Language::English));
}

#[test]
fn test_network_enum() {
    // Test network discrimination
    let mainnet = Network::Mainnet;
    let testnet = Network::Testnet;

    // These should be different networks
    assert!(matches!(mainnet, Network::Mainnet));
    assert!(matches!(testnet, Network::Testnet));
}
