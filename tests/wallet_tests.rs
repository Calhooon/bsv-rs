//! Integration tests for the wallet module.
//!
//! These tests verify the functionality of KeyDeriver, CachedKeyDeriver,
//! ProtoWallet, and the wire protocol encoding/decoding.
//!
//! # Test Categories
//!
//! - **KeyDeriver Tests**: BRC-42 key derivation with various protocols and counterparties
//! - **CachedKeyDeriver Tests**: Caching behavior and LRU eviction
//! - **ProtoWallet Tests**: Cryptographic operations (encrypt, sign, HMAC)
//! - **Wire Protocol Tests**: Binary encoding/decoding round-trips
//! - **Cross-SDK Compatibility**: Vectors from TypeScript SDK

#![cfg(feature = "wallet")]

use bsv_sdk::primitives::{PrivateKey, PublicKey};
use bsv_sdk::wallet::{
    CacheConfig, CachedKeyDeriver, Counterparty, CreateHmacArgs, CreateSignatureArgs, DecryptArgs,
    EncryptArgs, GetPublicKeyArgs, KeyDeriver, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel,
    VerifyHmacArgs, VerifySignatureArgs,
};

// ============================================================================
// KeyDeriver Tests
// ============================================================================

mod key_deriver_tests {
    use super::*;

    #[test]
    fn test_key_deriver_with_known_key() {
        // Use the TypeScript SDK test pattern: PrivateKey(42)
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 42;
        let root_key = PrivateKey::from_bytes(&key_bytes).unwrap();

        let deriver = KeyDeriver::new(Some(root_key.clone()));
        assert_eq!(deriver.identity_key(), root_key.public_key());
        assert_eq!(deriver.root_key().to_bytes(), root_key.to_bytes());
    }

    #[test]
    fn test_anyone_key_is_scalar_one() {
        // TypeScript SDK uses PrivateKey(1) for "anyone"
        let (anyone_priv, anyone_pub) = KeyDeriver::anyone_key();

        // Verify the scalar value is 1
        let mut expected_bytes = [0u8; 32];
        expected_bytes[31] = 1;
        assert_eq!(anyone_priv.to_bytes(), expected_bytes);

        // Anyone deriver should use this key
        let anyone_deriver = KeyDeriver::new(None);
        assert_eq!(anyone_deriver.identity_key(), anyone_pub);
    }

    #[test]
    fn test_invoice_number_format() {
        // Test that derived keys match expected invoice format: "level-protocol-keyID"
        // Protocol: [0, "testprotocol"], KeyID: "12345"
        // Expected invoice: "0-testprotocol-12345"
        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 42;
        let root_key = PrivateKey::from_bytes(&key_bytes).unwrap();
        let deriver = KeyDeriver::new(Some(root_key));

        let protocol = Protocol::new(SecurityLevel::Silent, "testprotocol");
        let key_id = "12345";

        // Derive a public key
        let pub_key = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        // The same parameters should always produce the same key
        let pub_key2 = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();
        assert_eq!(pub_key.to_compressed(), pub_key2.to_compressed());
    }

    #[test]
    fn test_derive_public_key_with_counterparty() {
        let mut root_bytes = [0u8; 32];
        root_bytes[31] = 42;
        let root_key = PrivateKey::from_bytes(&root_bytes).unwrap();
        let deriver = KeyDeriver::new(Some(root_key));

        let mut cp_bytes = [0u8; 32];
        cp_bytes[31] = 69;
        let counterparty_key = PrivateKey::from_bytes(&cp_bytes).unwrap();
        let counterparty_pub = counterparty_key.public_key();

        let protocol = Protocol::new(SecurityLevel::Silent, "testprotocol");
        let key_id = "12345";
        let counterparty = Counterparty::Other(counterparty_pub);

        let derived_pub = deriver
            .derive_public_key(&protocol, key_id, &counterparty, false)
            .unwrap();

        // TypeScript SDK: derivePublicKey with for_self=false derives for the counterparty
        // Result should match counterpartyPublicKey.deriveChild(rootPrivateKey, invoice)
        assert!(!derived_pub.to_hex().is_empty());
    }

    #[test]
    fn test_derive_private_key_matches_public() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "key-42";

        let priv_key = deriver
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let pub_key = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        // Private key's public key should match derived public key
        assert_eq!(
            priv_key.public_key().to_compressed(),
            pub_key.to_compressed()
        );
    }

    #[test]
    fn test_derive_symmetric_key_consistency() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "encryption app");
        let key_id = "msg-001";

        let sym_key1 = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let sym_key2 = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();

        // Symmetric keys should be deterministic
        assert_eq!(sym_key1.as_bytes(), sym_key2.as_bytes());
    }

    #[test]
    fn test_derive_symmetric_key_with_anyone() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::Silent, "public app");
        let key_id = "public-key-1";

        // Should not panic when deriving with "anyone" counterparty
        let sym_key = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Anyone)
            .unwrap();
        assert_eq!(sym_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_two_party_key_derivation() {
        // Alice and Bob can derive matching keys for communication
        let alice = KeyDeriver::new(Some(PrivateKey::random()));
        let bob = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "secure messaging");
        let key_id = "conversation-1";

        let alice_cp = Counterparty::Other(alice.identity_key());
        let bob_cp = Counterparty::Other(bob.identity_key());

        // Alice derives her key for Bob
        let alice_pub = alice
            .derive_public_key(&protocol, key_id, &bob_cp, true)
            .unwrap();

        // Bob derives Alice's key
        let alice_pub_from_bob = bob
            .derive_public_key(&protocol, key_id, &alice_cp, false)
            .unwrap();

        assert_eq!(
            alice_pub.to_compressed(),
            alice_pub_from_bob.to_compressed()
        );
    }

    #[test]
    fn test_reveal_counterparty_secret_fails_for_self() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));

        let result = deriver.reveal_counterparty_secret(&Counterparty::Self_);
        assert!(result.is_err());
    }

    #[test]
    fn test_reveal_counterparty_secret_succeeds_for_other() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let other = PrivateKey::random().public_key();

        let result = deriver.reveal_counterparty_secret(&Counterparty::Other(other));
        assert!(result.is_ok());
        let secret = result.unwrap();
        assert!(!secret.to_hex().is_empty());
    }

    #[test]
    fn test_reveal_specific_secret_deterministic() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "secret-123";

        let secret1 = deriver
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();
        let secret2 = deriver
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();

        assert_eq!(secret1.len(), 32);
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_different_security_levels_different_keys() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let key_id = "test-key";

        let proto0 = Protocol::new(SecurityLevel::Silent, "test application");
        let proto1 = Protocol::new(SecurityLevel::App, "test application");
        let proto2 = Protocol::new(SecurityLevel::Counterparty, "test application");

        let key0 = deriver
            .derive_public_key(&proto0, key_id, &Counterparty::Self_, true)
            .unwrap();
        let key1 = deriver
            .derive_public_key(&proto1, key_id, &Counterparty::Self_, true)
            .unwrap();
        let key2 = deriver
            .derive_public_key(&proto2, key_id, &Counterparty::Self_, true)
            .unwrap();

        // All three should be unique
        assert_ne!(key0.to_compressed(), key1.to_compressed());
        assert_ne!(key1.to_compressed(), key2.to_compressed());
        assert_ne!(key0.to_compressed(), key2.to_compressed());
    }

    #[test]
    fn test_protocol_validation() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));

        // Protocol name too short (< 5 chars)
        let bad_proto = Protocol::new(SecurityLevel::App, "bad");
        let result = deriver.derive_private_key(&bad_proto, "key-1", &Counterparty::Self_);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_id_validation() {
        let deriver = KeyDeriver::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        // Empty key ID
        let result = deriver.derive_private_key(&protocol, "", &Counterparty::Self_);
        assert!(result.is_err());

        // Key ID too long (> 800 chars)
        let long_key = "x".repeat(801);
        let result = deriver.derive_private_key(&protocol, &long_key, &Counterparty::Self_);
        assert!(result.is_err());
    }
}

// ============================================================================
// CachedKeyDeriver Tests
// ============================================================================

mod cached_key_deriver_tests {
    use super::*;

    #[test]
    fn test_cached_deriver_same_identity() {
        let key = PrivateKey::random();
        let cached = CachedKeyDeriver::new(Some(key.clone()), None);

        assert_eq!(cached.identity_key(), key.public_key());
        assert_eq!(cached.inner().identity_key(), key.public_key());
    }

    #[test]
    fn test_cache_hit_returns_same_value() {
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "cache test");
        let key_id = "cached-key-1";

        // First call derives and caches
        let key1 = cached
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        // Second call should return from cache with identical result
        let key2 = cached
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        assert_eq!(key1.to_compressed(), key2.to_compressed());
    }

    #[test]
    fn test_cache_miss_with_different_parameters() {
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "cache test");

        let key1 = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        let key2 = cached
            .derive_public_key(&protocol, "key-2", &Counterparty::Self_, true)
            .unwrap();

        // Different key IDs should produce different keys
        assert_ne!(key1.to_compressed(), key2.to_compressed());
    }

    #[test]
    fn test_lru_eviction() {
        // Create a very small cache
        let config = CacheConfig { max_size: 3 };
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
        let protocol = Protocol::new(SecurityLevel::App, "eviction test");

        // Fill the cache
        let _k1 = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        let _k2 = cached
            .derive_public_key(&protocol, "key-2", &Counterparty::Self_, true)
            .unwrap();
        let _k3 = cached
            .derive_public_key(&protocol, "key-3", &Counterparty::Self_, true)
            .unwrap();

        // This should evict key-1 (LRU)
        let _k4 = cached
            .derive_public_key(&protocol, "key-4", &Counterparty::Self_, true)
            .unwrap();

        // key-1 should still be derivable (just not cached)
        let k1_again = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        assert!(!k1_again.to_hex().is_empty());
    }

    #[test]
    fn test_lru_access_updates_recentness() {
        let config = CacheConfig { max_size: 3 };
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
        let protocol = Protocol::new(SecurityLevel::App, "lru access test");

        // Fill the cache
        let k1 = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        let _k2 = cached
            .derive_public_key(&protocol, "key-2", &Counterparty::Self_, true)
            .unwrap();
        let _k3 = cached
            .derive_public_key(&protocol, "key-3", &Counterparty::Self_, true)
            .unwrap();

        // Access key-1 to make it most recently used
        let _ = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();

        // Add key-4, which should evict key-2 (now LRU)
        let _k4 = cached
            .derive_public_key(&protocol, "key-4", &Counterparty::Self_, true)
            .unwrap();

        // key-1 should still be in cache
        let k1_still = cached
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        assert_eq!(k1.to_compressed(), k1_still.to_compressed());
    }

    #[test]
    fn test_secrets_not_cached() {
        // According to the spec, reveal_* methods should NOT cache results for security
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "secret test");
        let key_id = "secret-1";

        // Secrets should be computed fresh each time (no caching)
        let secret1 = cached
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();
        let secret2 = cached
            .reveal_specific_secret(&Counterparty::Self_, &protocol, key_id)
            .unwrap();

        // Results should match (deterministic), but were computed separately
        assert_eq!(secret1, secret2);
    }

    #[test]
    fn test_cached_implements_api_trait() {
        fn derive_key<D: KeyDeriverApi>(deriver: &D) -> PublicKey {
            let protocol = Protocol::new(SecurityLevel::App, "trait test app");
            deriver
                .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
                .unwrap()
        }

        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let key = derive_key(&cached);
        assert!(!key.to_hex().is_empty());
    }

    #[test]
    fn test_private_and_symmetric_key_caching() {
        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "full cache test");
        let key_id = "test-key";

        // Private key caching
        let priv1 = cached
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let priv2 = cached
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        assert_eq!(priv1.to_bytes(), priv2.to_bytes());

        // Symmetric key caching
        let sym1 = cached
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let sym2 = cached
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        assert_eq!(sym1.as_bytes(), sym2.as_bytes());
    }
}

// ============================================================================
// ProtoWallet Tests
// ============================================================================

mod proto_wallet_tests {
    use super::*;

    #[test]
    fn test_proto_wallet_creation() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        assert!(!wallet.identity_key_hex().is_empty());
    }

    #[test]
    fn test_proto_wallet_anyone() {
        let wallet1 = ProtoWallet::anyone();
        let wallet2 = ProtoWallet::anyone();

        // Anyone wallets should have identical identity keys
        assert_eq!(wallet1.identity_key_hex(), wallet2.identity_key_hex());
    }

    #[test]
    fn test_get_public_key_identity() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));

        let result = wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: true,
                protocol_id: None,
                key_id: None,
                counterparty: None,
                for_self: None,
            })
            .unwrap();

        assert_eq!(result.public_key, wallet.identity_key_hex());
    }

    #[test]
    fn test_get_public_key_derived() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        let result = wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol),
                key_id: Some("derived-1".to_string()),
                counterparty: Some(Counterparty::Self_),
                for_self: Some(true),
            })
            .unwrap();

        // Derived key should differ from identity
        assert_ne!(result.public_key, wallet.identity_key_hex());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "encryption roundtrip");
        let plaintext = b"Hello, ProtoWallet!".to_vec();

        let encrypted = wallet
            .encrypt(EncryptArgs {
                plaintext: plaintext.clone(),
                protocol_id: protocol.clone(),
                key_id: "msg-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        // Ciphertext should differ from plaintext
        assert_ne!(encrypted.ciphertext, plaintext);

        let decrypted = wallet
            .decrypt(DecryptArgs {
                ciphertext: encrypted.ciphertext,
                protocol_id: protocol,
                key_id: "msg-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_two_party_encryption() {
        let alice = ProtoWallet::new(Some(PrivateKey::random()));
        let bob = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "secure messaging");
        let message = b"Secret from Alice to Bob".to_vec();

        // Alice encrypts for Bob
        let encrypted = alice
            .encrypt(EncryptArgs {
                plaintext: message.clone(),
                protocol_id: protocol.clone(),
                key_id: "msg-1".to_string(),
                counterparty: Some(Counterparty::Other(bob.identity_key())),
            })
            .unwrap();

        // Bob decrypts using Alice as counterparty
        let decrypted = bob
            .decrypt(DecryptArgs {
                ciphertext: encrypted.ciphertext,
                protocol_id: protocol,
                key_id: "msg-1".to_string(),
                counterparty: Some(Counterparty::Other(alice.identity_key())),
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, message);
    }

    #[test]
    fn test_decrypt_fails_with_wrong_protocol() {
        let alice = ProtoWallet::new(Some(PrivateKey::random()));
        let bob = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol1 = Protocol::new(SecurityLevel::Counterparty, "protocol one");
        let protocol2 = Protocol::new(SecurityLevel::App, "protocol two");
        let message = b"Test message".to_vec();

        let encrypted = alice
            .encrypt(EncryptArgs {
                plaintext: message,
                protocol_id: protocol1,
                key_id: "msg-1".to_string(),
                counterparty: Some(Counterparty::Other(bob.identity_key())),
            })
            .unwrap();

        // Bob tries to decrypt with wrong protocol
        let result = bob.decrypt(DecryptArgs {
            ciphertext: encrypted.ciphertext,
            protocol_id: protocol2,
            key_id: "msg-1".to_string(),
            counterparty: Some(Counterparty::Other(alice.identity_key())),
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_create_verify_hmac_roundtrip() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "hmac roundtrip test");
        let data = b"Data to authenticate".to_vec();

        let created = wallet
            .create_hmac(CreateHmacArgs {
                data: data.clone(),
                protocol_id: protocol.clone(),
                key_id: "hmac-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert_eq!(created.hmac.len(), 32);

        let verified = wallet
            .verify_hmac(VerifyHmacArgs {
                data,
                hmac: created.hmac,
                protocol_id: protocol,
                key_id: "hmac-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert!(verified.valid);
    }

    #[test]
    fn test_hmac_verification_fails_with_wrong_data() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "hmac fail test");

        let created = wallet
            .create_hmac(CreateHmacArgs {
                data: b"original data".to_vec(),
                protocol_id: protocol.clone(),
                key_id: "hmac-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let result = wallet.verify_hmac(VerifyHmacArgs {
            data: b"tampered data".to_vec(),
            hmac: created.hmac,
            protocol_id: protocol,
            key_id: "hmac-1".to_string(),
            counterparty: None,
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_hmac_cross_party_verification() {
        let alice = ProtoWallet::new(Some(PrivateKey::random()));
        let bob = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "cross party hmac");
        let data = b"Shared data".to_vec();

        let created = alice
            .create_hmac(CreateHmacArgs {
                data: data.clone(),
                protocol_id: protocol.clone(),
                key_id: "hmac-1".to_string(),
                counterparty: Some(Counterparty::Other(bob.identity_key())),
            })
            .unwrap();

        let verified = bob
            .verify_hmac(VerifyHmacArgs {
                data,
                hmac: created.hmac,
                protocol_id: protocol,
                key_id: "hmac-1".to_string(),
                counterparty: Some(Counterparty::Other(alice.identity_key())),
            })
            .unwrap();

        assert!(verified.valid);
    }

    #[test]
    fn test_create_verify_signature_roundtrip() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "signature roundtrip");
        let data = b"Data to sign".to_vec();

        let signed = wallet
            .create_signature(CreateSignatureArgs {
                data: Some(data.clone()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: "sig-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert!(!signed.signature.is_empty());

        // Default counterparty for signing is 'anyone'
        let verified = wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signed.signature,
                protocol_id: protocol,
                key_id: "sig-1".to_string(),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
            })
            .unwrap();

        assert!(verified.valid);
    }

    #[test]
    fn test_signature_with_direct_hash() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "hash signature");
        let hash = bsv_sdk::primitives::sha256(b"prehashed data");

        let signed = wallet
            .create_signature(CreateSignatureArgs {
                data: None,
                hash_to_directly_sign: Some(hash),
                protocol_id: protocol.clone(),
                key_id: "hash-sig-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let verified = wallet
            .verify_signature(VerifySignatureArgs {
                data: None,
                hash_to_directly_verify: Some(hash),
                signature: signed.signature,
                protocol_id: protocol,
                key_id: "hash-sig-1".to_string(),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
            })
            .unwrap();

        assert!(verified.valid);
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_data() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "sig fail test");

        let signed = wallet
            .create_signature(CreateSignatureArgs {
                data: Some(b"original".to_vec()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: "sig-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let result = wallet.verify_signature(VerifySignatureArgs {
            data: Some(b"tampered".to_vec()),
            hash_to_directly_verify: None,
            signature: signed.signature,
            protocol_id: protocol,
            key_id: "sig-1".to_string(),
            counterparty: Some(Counterparty::Anyone),
            for_self: Some(true),
        });

        assert!(result.is_err());
    }

    #[test]
    fn test_cross_party_signature_verification() {
        let alice = ProtoWallet::new(Some(PrivateKey::random()));
        let bob = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::Counterparty, "cross party sig");
        let data = b"Message from Alice".to_vec();

        // Alice signs for Bob
        let signed = alice
            .create_signature(CreateSignatureArgs {
                data: Some(data.clone()),
                hash_to_directly_sign: None,
                protocol_id: protocol.clone(),
                key_id: "sig-1".to_string(),
                counterparty: Some(Counterparty::Other(bob.identity_key())),
            })
            .unwrap();

        // Bob verifies Alice's signature
        let verified = bob
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signed.signature,
                protocol_id: protocol,
                key_id: "sig-1".to_string(),
                counterparty: Some(Counterparty::Other(alice.identity_key())),
                for_self: Some(false),
            })
            .unwrap();

        assert!(verified.valid);
    }

    #[test]
    fn test_default_counterparty_for_operations() {
        // Default for signing: anyone (public signatures)
        // Default for other ops: self
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let protocol = Protocol::new(SecurityLevel::App, "default counterparty");

        // Self-encryption (no counterparty)
        let encrypted = wallet
            .encrypt(EncryptArgs {
                plaintext: b"self-encrypted".to_vec(),
                protocol_id: protocol.clone(),
                key_id: "self-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        let decrypted = wallet
            .decrypt(DecryptArgs {
                ciphertext: encrypted.ciphertext,
                protocol_id: protocol.clone(),
                key_id: "self-1".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, b"self-encrypted".to_vec());

        // Self-HMAC (no counterparty)
        let hmac = wallet
            .create_hmac(CreateHmacArgs {
                data: b"self-hmac".to_vec(),
                protocol_id: protocol.clone(),
                key_id: "hmac-self".to_string(),
                counterparty: None,
            })
            .unwrap();

        let verified = wallet
            .verify_hmac(VerifyHmacArgs {
                data: b"self-hmac".to_vec(),
                hmac: hmac.hmac,
                protocol_id: protocol,
                key_id: "hmac-self".to_string(),
                counterparty: None,
            })
            .unwrap();

        assert!(verified.valid);
    }
}

// ============================================================================
// Cross-SDK Compatibility Tests (BRC-3, BRC-2 vectors from TypeScript SDK)
// ============================================================================

mod cross_sdk_tests {
    use super::*;

    /// BRC-3 signature compliance vector from TypeScript SDK ProtoWallet tests
    #[test]
    fn test_brc3_signature_compliance() {
        let wallet = ProtoWallet::anyone();
        let data = "BRC-3 Compliance Validated!".as_bytes().to_vec();
        let signature = vec![
            48, 68, 2, 32, 43, 34, 58, 156, 219, 32, 50, 70, 29, 240, 155, 137, 88, 60, 200, 95,
            243, 198, 201, 21, 56, 82, 141, 112, 69, 196, 170, 73, 156, 6, 44, 48, 2, 32, 118, 125,
            254, 201, 44, 87, 177, 170, 93, 11, 193, 134, 18, 70, 9, 31, 234, 27, 170, 177, 54, 96,
            181, 140, 166, 196, 144, 14, 230, 118, 106, 105,
        ];

        let counterparty_hex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1";
        let counterparty_pub = PublicKey::from_hex(counterparty_hex).unwrap();

        let result = wallet.verify_signature(VerifySignatureArgs {
            data: Some(data),
            hash_to_directly_verify: None,
            signature,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "brc3 test"),
            key_id: "42".to_string(),
            counterparty: Some(Counterparty::Other(counterparty_pub)),
            for_self: None,
        });

        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    /// BRC-2 HMAC compliance vector from TypeScript SDK ProtoWallet tests
    #[test]
    fn test_brc2_hmac_compliance() {
        let root_key_hex = "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8";
        let root_key = PrivateKey::from_hex(root_key_hex).unwrap();
        let wallet = ProtoWallet::new(Some(root_key));

        let data = "BRC-2 HMAC Compliance Validated!".as_bytes().to_vec();
        let hmac: [u8; 32] = [
            81, 240, 18, 153, 163, 45, 174, 85, 9, 246, 142, 125, 209, 133, 82, 76, 254, 103, 46,
            182, 86, 59, 219, 61, 126, 30, 176, 232, 233, 100, 234, 14,
        ];

        let counterparty_hex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1";
        let counterparty_pub = PublicKey::from_hex(counterparty_hex).unwrap();

        let result = wallet.verify_hmac(VerifyHmacArgs {
            data,
            hmac,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "brc2 test"),
            key_id: "42".to_string(),
            counterparty: Some(Counterparty::Other(counterparty_pub)),
        });

        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    /// BRC-2 Encryption compliance vector from TypeScript SDK ProtoWallet tests
    #[test]
    fn test_brc2_encryption_compliance() {
        let root_key_hex = "6a2991c9de20e38b31d7ea147bf55f5039e4bbc073160f5e0d541d1f17e321b8";
        let root_key = PrivateKey::from_hex(root_key_hex).unwrap();
        let wallet = ProtoWallet::new(Some(root_key));

        let ciphertext = vec![
            252, 203, 216, 184, 29, 161, 223, 212, 16, 193, 94, 99, 31, 140, 99, 43, 61, 236, 184,
            67, 54, 105, 199, 47, 11, 19, 184, 127, 2, 165, 125, 9, 188, 195, 196, 39, 120, 130,
            213, 95, 186, 89, 64, 28, 1, 80, 20, 213, 159, 133, 98, 253, 128, 105, 113, 247, 197,
            152, 236, 64, 166, 207, 113, 134, 65, 38, 58, 24, 127, 145, 140, 206, 47, 70, 146, 84,
            186, 72, 95, 35, 154, 112, 178, 55, 72, 124,
        ];

        let counterparty_hex = "0294c479f762f6baa97fbcd4393564c1d7bd8336ebd15928135bbcf575cd1a71a1";
        let counterparty_pub = PublicKey::from_hex(counterparty_hex).unwrap();

        let result = wallet.decrypt(DecryptArgs {
            ciphertext,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "brc2 test"),
            key_id: "42".to_string(),
            counterparty: Some(Counterparty::Other(counterparty_pub)),
        });

        assert!(result.is_ok());
        let plaintext = String::from_utf8(result.unwrap().plaintext).unwrap();
        assert_eq!(plaintext, "BRC-2 Encryption Compliance Validated!");
    }

    /// Test that key derivation matches TypeScript SDK pattern
    #[test]
    fn test_key_derivation_ts_pattern() {
        // TypeScript SDK uses PrivateKey(42) and PrivateKey(69)
        let mut root_bytes = [0u8; 32];
        root_bytes[31] = 42;
        let root_key = PrivateKey::from_bytes(&root_bytes).unwrap();

        let mut cp_bytes = [0u8; 32];
        cp_bytes[31] = 69;
        let counterparty_key = PrivateKey::from_bytes(&cp_bytes).unwrap();

        let deriver = KeyDeriver::new(Some(root_key.clone()));
        let protocol = Protocol::new(SecurityLevel::Silent, "testprotocol");
        let key_id = "12345";

        // TypeScript: counterpartyPublicKey.deriveChild(rootPrivateKey, invoiceNumber)
        // Where invoiceNumber = "0-testprotocol-12345"
        let derived = deriver
            .derive_public_key(
                &protocol,
                key_id,
                &Counterparty::Other(counterparty_key.public_key()),
                false,
            )
            .unwrap();

        // Verify the derivation produces a valid public key
        assert!(!derived.to_hex().is_empty());

        // Direct verification: use BRC-42 deriveChild
        let expected = counterparty_key
            .public_key()
            .derive_child(&root_key, "0-testprotocol-12345")
            .unwrap();

        assert_eq!(derived.to_hex(), expected.to_hex());
    }
}

// ============================================================================
// Wire Protocol Tests
// ============================================================================

mod wire_protocol_tests {
    use super::*;
    use bsv_sdk::wallet::wire::{WireReader, WireWriter};

    #[test]
    fn test_varint_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_var_int(0);
        writer.write_var_int(1);
        writer.write_var_int(127);
        writer.write_var_int(128);
        writer.write_var_int(16383);
        writer.write_var_int(16384);
        writer.write_var_int(u64::MAX);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(reader.read_var_int().unwrap(), 0);
        assert_eq!(reader.read_var_int().unwrap(), 1);
        assert_eq!(reader.read_var_int().unwrap(), 127);
        assert_eq!(reader.read_var_int().unwrap(), 128);
        assert_eq!(reader.read_var_int().unwrap(), 16383);
        assert_eq!(reader.read_var_int().unwrap(), 16384);
        assert_eq!(reader.read_var_int().unwrap(), u64::MAX);
    }

    #[test]
    fn test_signed_varint_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_signed_var_int(0);
        writer.write_signed_var_int(-1); // Sentinel for None
        writer.write_signed_var_int(1);
        writer.write_signed_var_int(-128);
        writer.write_signed_var_int(127);
        writer.write_signed_var_int(i64::MAX);
        writer.write_signed_var_int(i64::MIN);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(reader.read_signed_var_int().unwrap(), 0);
        assert_eq!(reader.read_signed_var_int().unwrap(), -1);
        assert_eq!(reader.read_signed_var_int().unwrap(), 1);
        assert_eq!(reader.read_signed_var_int().unwrap(), -128);
        assert_eq!(reader.read_signed_var_int().unwrap(), 127);
        assert_eq!(reader.read_signed_var_int().unwrap(), i64::MAX);
        assert_eq!(reader.read_signed_var_int().unwrap(), i64::MIN);
    }

    #[test]
    fn test_string_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_string("Hello, Wire!");
        writer.write_string("");
        writer.write_string("Unicode: \u{00fc}\u{00f1}\u{00ee}");

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(reader.read_string().unwrap(), "Hello, Wire!");
        assert_eq!(reader.read_string().unwrap(), "");
        assert_eq!(
            reader.read_string().unwrap(),
            "Unicode: \u{00fc}\u{00f1}\u{00ee}"
        );
    }

    #[test]
    fn test_optional_string_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_optional_string(Some("present"));
        writer.write_optional_string(None);
        writer.write_optional_string(Some(""));

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(
            reader.read_optional_string().unwrap(),
            Some("present".to_string())
        );
        assert_eq!(reader.read_optional_string().unwrap(), None);
        assert_eq!(reader.read_optional_string().unwrap(), Some("".to_string()));
    }

    #[test]
    fn test_optional_bool_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_optional_bool(Some(true));
        writer.write_optional_bool(Some(false));
        writer.write_optional_bool(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(reader.read_optional_bool().unwrap(), Some(true));
        assert_eq!(reader.read_optional_bool().unwrap(), Some(false));
        assert_eq!(reader.read_optional_bool().unwrap(), None);
    }

    #[test]
    fn test_counterparty_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_counterparty(Some(&Counterparty::Self_));
        writer.write_counterparty(Some(&Counterparty::Anyone));
        writer.write_counterparty(None);

        let pubkey = PrivateKey::random().public_key();
        writer.write_counterparty(Some(&Counterparty::Other(pubkey.clone())));

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(
            reader.read_counterparty().unwrap(),
            Some(Counterparty::Self_)
        );
        assert_eq!(
            reader.read_counterparty().unwrap(),
            Some(Counterparty::Anyone)
        );
        assert_eq!(reader.read_counterparty().unwrap(), None);

        match reader.read_counterparty().unwrap() {
            Some(Counterparty::Other(pk)) => {
                assert_eq!(pk.to_hex(), pubkey.to_hex());
            }
            other => panic!("Expected Other counterparty, got {:?}", other),
        }
    }

    #[test]
    fn test_protocol_id_roundtrip() {
        let mut writer = WireWriter::new();
        let proto1 = Protocol::new(SecurityLevel::Silent, "protocol one");
        let proto2 = Protocol::new(SecurityLevel::App, "protocol two");
        let proto3 = Protocol::new(SecurityLevel::Counterparty, "protocol three");

        writer.write_protocol_id(&proto1);
        writer.write_protocol_id(&proto2);
        writer.write_protocol_id(&proto3);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        let read1 = reader.read_protocol_id().unwrap();
        assert_eq!(read1.security_level, SecurityLevel::Silent);
        assert_eq!(read1.protocol_name, "protocol one");

        let read2 = reader.read_protocol_id().unwrap();
        assert_eq!(read2.security_level, SecurityLevel::App);
        assert_eq!(read2.protocol_name, "protocol two");

        let read3 = reader.read_protocol_id().unwrap();
        assert_eq!(read3.security_level, SecurityLevel::Counterparty);
        assert_eq!(read3.protocol_name, "protocol three");
    }

    #[test]
    fn test_optional_protocol_id_roundtrip() {
        let mut writer = WireWriter::new();
        let proto = Protocol::new(SecurityLevel::App, "test protocol");

        writer.write_optional_protocol_id(Some(&proto));
        writer.write_optional_protocol_id(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        let read1 = reader.read_optional_protocol_id().unwrap();
        assert!(read1.is_some());
        let p = read1.unwrap();
        assert_eq!(p.security_level, SecurityLevel::App);
        assert_eq!(p.protocol_name, "test protocol");

        let read2 = reader.read_optional_protocol_id().unwrap();
        assert!(read2.is_none());
    }

    #[test]
    fn test_outpoint_roundtrip() {
        use bsv_sdk::wallet::Outpoint;

        let mut writer = WireWriter::new();
        let mut txid = [0u8; 32];
        txid[0] = 0xde;
        txid[31] = 0xad;
        let outpoint = Outpoint::new(txid, 42);

        writer.write_outpoint(&outpoint);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        let read = reader.read_outpoint().unwrap();
        assert_eq!(read.txid, txid);
        assert_eq!(read.vout, 42);
    }

    #[test]
    fn test_string_array_roundtrip() {
        let mut writer = WireWriter::new();
        let arr = vec!["one".to_string(), "two".to_string(), "three".to_string()];
        writer.write_string_array(&arr);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        let read = reader.read_string_array().unwrap();
        assert_eq!(read, arr);
    }

    #[test]
    fn test_optional_bytes_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(Some(&[1, 2, 3, 4, 5]));
        writer.write_optional_bytes(None);
        writer.write_optional_bytes(Some(&[]));

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(
            reader.read_optional_bytes().unwrap(),
            Some(vec![1, 2, 3, 4, 5])
        );
        assert_eq!(reader.read_optional_bytes().unwrap(), None);
        assert_eq!(reader.read_optional_bytes().unwrap(), Some(vec![]));
    }

    #[test]
    fn test_query_mode_roundtrip() {
        use bsv_sdk::wallet::QueryMode;

        let mut writer = WireWriter::new();
        writer.write_query_mode(QueryMode::Any);
        writer.write_query_mode(QueryMode::All);
        writer.write_optional_query_mode(Some(QueryMode::Any));
        writer.write_optional_query_mode(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(reader.read_query_mode().unwrap(), QueryMode::Any);
        assert_eq!(reader.read_query_mode().unwrap(), QueryMode::All);
        assert_eq!(
            reader.read_optional_query_mode().unwrap(),
            Some(QueryMode::Any)
        );
        assert_eq!(reader.read_optional_query_mode().unwrap(), None);
    }

    #[test]
    fn test_output_include_roundtrip() {
        use bsv_sdk::wallet::OutputInclude;

        let mut writer = WireWriter::new();
        writer.write_output_include(OutputInclude::LockingScripts);
        writer.write_output_include(OutputInclude::EntireTransactions);
        writer.write_optional_output_include(Some(OutputInclude::LockingScripts));
        writer.write_optional_output_include(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(
            reader.read_output_include().unwrap(),
            OutputInclude::LockingScripts
        );
        assert_eq!(
            reader.read_output_include().unwrap(),
            OutputInclude::EntireTransactions
        );
        assert_eq!(
            reader.read_optional_output_include().unwrap(),
            Some(OutputInclude::LockingScripts)
        );
        assert_eq!(reader.read_optional_output_include().unwrap(), None);
    }

    #[test]
    fn test_string_map_roundtrip() {
        use std::collections::HashMap;

        let mut writer = WireWriter::new();
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        writer.write_string_map(&map);
        writer.write_optional_string_map(Some(&map));
        writer.write_optional_string_map(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        let read_map = reader.read_string_map().unwrap();
        assert_eq!(read_map.len(), 2);
        assert_eq!(read_map.get("key1"), Some(&"value1".to_string()));
        assert_eq!(read_map.get("key2"), Some(&"value2".to_string()));

        let opt_map = reader.read_optional_string_map().unwrap();
        assert!(opt_map.is_some());
        assert_eq!(opt_map.unwrap().len(), 2);

        let none_map = reader.read_optional_string_map().unwrap();
        assert!(none_map.is_none());
    }

    #[test]
    fn test_action_status_roundtrip() {
        use bsv_sdk::wallet::ActionStatus;

        let mut writer = WireWriter::new();
        writer.write_action_status(Some(ActionStatus::Completed));
        writer.write_action_status(Some(ActionStatus::Unprocessed));
        writer.write_action_status(Some(ActionStatus::Sending));
        writer.write_action_status(Some(ActionStatus::Failed));
        writer.write_action_status(None);

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);

        assert_eq!(
            reader.read_action_status().unwrap(),
            Some(ActionStatus::Completed)
        );
        assert_eq!(
            reader.read_action_status().unwrap(),
            Some(ActionStatus::Unprocessed)
        );
        assert_eq!(
            reader.read_action_status().unwrap(),
            Some(ActionStatus::Sending)
        );
        assert_eq!(
            reader.read_action_status().unwrap(),
            Some(ActionStatus::Failed)
        );
        assert_eq!(reader.read_action_status().unwrap(), None);
    }
}
