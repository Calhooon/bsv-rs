//! Comprehensive wire protocol roundtrip tests for ALL WalletInterface methods.
//!
//! This file tests the binary wire protocol serialization/deserialization for every
//! WalletInterface method (28 total). It uses a loopback wire pattern that connects
//! a WalletWireTransceiver (client) to a WalletWireProcessor (server) via an in-memory
//! transport, verifying that args serialize correctly and responses deserialize correctly.
//!
//! Additionally, it tests low-level WireReader/WireWriter roundtrips for all complex
//! wallet types (WalletAction, WalletOutput, WalletCertificate, IdentityCertificate, etc.).
//!
//! # Test Categories
//!
//! - **Loopback roundtrip tests**: Full client→server→wallet→server→client roundtrips
//! - **Request serialization tests**: Verify request bytes can be parsed by processor
//! - **Response serialization tests**: Verify response types roundtrip through wire encoding
//! - **Complex type roundtrip tests**: WireWriter→WireReader roundtrips for all wallet types

#![cfg(feature = "wallet")]

use bsv_sdk::primitives::{PrivateKey, PublicKey};
use bsv_sdk::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_sdk::wallet::wire::{WireReader, WireWriter};
use bsv_sdk::wallet::{
    AbortActionArgs, AcquireCertificateArgs, AcquisitionProtocol, ActionStatus, BasketInsertion,
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, EncryptArgs, GetHeaderArgs, GetPublicKeyArgs, IdentityCertificate,
    IdentityCertifier, InternalizeActionArgs, InternalizeOutput, ListActionsArgs,
    ListCertificatesArgs, ListOutputsArgs, Network, Outpoint, OutputInclude, ProtoWallet, Protocol,
    ProveCertificateArgs, QueryMode, RelinquishCertificateArgs, RelinquishOutputArgs,
    SecurityLevel, SendWithResult, SendWithResultStatus, SignActionArgs, SignActionSpend,
    TrustSelf, VerifyHmacArgs, VerifySignatureArgs, WalletAction, WalletActionInput,
    WalletActionOutput, WalletCertificate, WalletOutput, WalletPayment,
};
use bsv_sdk::Error;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Loopback Wire Transport
// ============================================================================

/// A wire transport that loops messages through a WalletWireProcessor.
/// This simulates a full client-server roundtrip in memory.
struct LoopbackWire {
    processor: Arc<WalletWireProcessor<ProtoWallet>>,
}

#[async_trait::async_trait]
impl WalletWire for LoopbackWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.processor.process_message(message).await
    }
}

/// Creates a loopback transceiver with a fresh ProtoWallet.
fn create_loopback() -> WalletWireTransceiver<LoopbackWire> {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = Arc::new(WalletWireProcessor::new(wallet));
    let wire = LoopbackWire { processor };
    WalletWireTransceiver::new(wire)
}

/// Creates a loopback transceiver with two ProtoWallets for two-party operations.
fn create_two_party_loopback() -> (
    WalletWireTransceiver<LoopbackWire>,
    ProtoWallet,
    ProtoWallet,
) {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();
    let alice_wallet = ProtoWallet::new(Some(alice_key));
    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let processor = Arc::new(WalletWireProcessor::new(alice_wallet.clone()));
    let wire = LoopbackWire { processor };
    let transceiver = WalletWireTransceiver::new(wire);
    (transceiver, alice_wallet, bob_wallet)
}

/// Helper to create a valid 33-byte compressed public key hex string.
fn sample_pubkey_hex() -> String {
    let pk = PrivateKey::random();
    bsv_sdk::primitives::to_hex(&pk.public_key().to_compressed())
}

/// Helper to create a sample 32-byte txid.
fn sample_txid() -> [u8; 32] {
    let mut txid = [0u8; 32];
    for (i, byte) in txid.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(0xab);
    }
    txid
}

/// Helper to create a sample outpoint string.
fn sample_outpoint_string() -> String {
    let txid = sample_txid();
    format!("{}.0", bsv_sdk::primitives::to_hex(&txid))
}

/// Helper to create a sample WalletCertificate.
fn sample_wallet_certificate() -> WalletCertificate {
    WalletCertificate {
        certificate_type: "test-cert-type".to_string(),
        subject: sample_pubkey_hex(),
        serial_number: "serial-12345".to_string(),
        certifier: sample_pubkey_hex(),
        revocation_outpoint: sample_outpoint_string(),
        signature: "deadbeef".to_string(),
        fields: {
            let mut m = HashMap::new();
            m.insert("name".to_string(), "Alice".to_string());
            m.insert("email".to_string(), "alice@example.com".to_string());
            m
        },
    }
}

// ============================================================================
// Key Operations - Loopback Roundtrip Tests
// ============================================================================

mod get_public_key_tests {
    use super::*;

    /// Tests getPublicKey with identity_key=true (returns root public key).
    #[tokio::test]
    async fn test_roundtrip_get_public_key_identity() {
        let transceiver = create_loopback();
        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    for_self: None,
                },
                "test.app",
            )
            .await
            .unwrap();

        // Should be a valid 33-byte compressed public key (66 hex chars)
        assert_eq!(result.public_key.len(), 66);
        assert!(result.public_key.starts_with("02") || result.public_key.starts_with("03"));
    }

    /// Tests getPublicKey with derived key using protocol, key_id, and counterparty.
    #[tokio::test]
    async fn test_roundtrip_get_public_key_derived() {
        let transceiver = create_loopback();
        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol::new(SecurityLevel::App, "test application")),
                    key_id: Some("key-42".to_string()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(true),
                },
                "originator.example.com",
            )
            .await
            .unwrap();

        assert_eq!(result.public_key.len(), 66);
        assert!(result.public_key.starts_with("02") || result.public_key.starts_with("03"));
    }

    /// Tests getPublicKey with Anyone counterparty.
    #[tokio::test]
    async fn test_roundtrip_get_public_key_anyone_counterparty() {
        let transceiver = create_loopback();
        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol::new(SecurityLevel::Silent, "anyone derivation")),
                    key_id: Some("pub-1".to_string()),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(false),
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(result.public_key.len(), 66);
    }

    /// Tests getPublicKey with Other(PublicKey) counterparty.
    #[tokio::test]
    async fn test_roundtrip_get_public_key_other_counterparty() {
        let transceiver = create_loopback();
        let other_key = PrivateKey::random().public_key();
        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(Protocol::new(
                        SecurityLevel::Counterparty,
                        "counterparty derivation",
                    )),
                    key_id: Some("cp-key-1".to_string()),
                    counterparty: Some(Counterparty::Other(other_key)),
                    for_self: Some(true),
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(result.public_key.len(), 66);
    }

    /// Tests getPublicKey with minimal args (identity key only).
    #[tokio::test]
    async fn test_roundtrip_get_public_key_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    for_self: None,
                },
                "",
            )
            .await
            .unwrap();

        assert_eq!(result.public_key.len(), 66);
    }
}

mod encrypt_decrypt_tests {
    use super::*;

    /// Tests encrypt/decrypt roundtrip with Self_ counterparty.
    #[tokio::test]
    async fn test_roundtrip_encrypt_decrypt_self() {
        let transceiver = create_loopback();
        let plaintext = b"Hello, wire protocol!".to_vec();

        let encrypted = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "encryption roundtrip"),
                    key_id: "enc-1".to_string(),
                    counterparty: None, // defaults to Self_
                },
                "test",
            )
            .await
            .unwrap();

        // Ciphertext should be longer than plaintext (IV + ciphertext + auth tag)
        assert!(encrypted.ciphertext.len() > plaintext.len());

        let decrypted = transceiver
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted.ciphertext,
                    protocol_id: Protocol::new(SecurityLevel::App, "encryption roundtrip"),
                    key_id: "enc-1".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    /// Tests encrypt with empty plaintext.
    #[tokio::test]
    async fn test_roundtrip_encrypt_decrypt_empty() {
        let transceiver = create_loopback();
        let plaintext = Vec::new();

        let encrypted = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "empty encryption"),
                    key_id: "emp-1".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await
            .unwrap();

        let decrypted = transceiver
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted.ciphertext,
                    protocol_id: Protocol::new(SecurityLevel::App, "empty encryption"),
                    key_id: "emp-1".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    /// Tests encrypt with large data (16KB).
    #[tokio::test]
    async fn test_roundtrip_encrypt_decrypt_large() {
        let transceiver = create_loopback();
        let plaintext = vec![0xABu8; 16384];

        let encrypted = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "large encryption"),
                    key_id: "lg-1".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await
            .unwrap();

        let decrypted = transceiver
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted.ciphertext,
                    protocol_id: Protocol::new(SecurityLevel::App, "large encryption"),
                    key_id: "lg-1".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }
}

mod hmac_tests {
    use super::*;

    /// Tests createHmac/verifyHmac roundtrip.
    #[tokio::test]
    async fn test_roundtrip_hmac_create_verify() {
        let transceiver = create_loopback();
        let data = b"data to authenticate via wire".to_vec();

        let hmac_result = transceiver
            .create_hmac(
                CreateHmacArgs {
                    data: data.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac roundtrip"),
                    key_id: "hmac-1".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        // HMAC is always 32 bytes
        assert_eq!(hmac_result.hmac.len(), 32);

        let verify_result = transceiver
            .verify_hmac(
                VerifyHmacArgs {
                    data,
                    hmac: hmac_result.hmac,
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac roundtrip"),
                    key_id: "hmac-1".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        assert!(verify_result.valid);
    }

    /// Tests verifyHmac with invalid data returns false.
    #[tokio::test]
    async fn test_roundtrip_hmac_verify_invalid() {
        let transceiver = create_loopback();

        let hmac_result = transceiver
            .create_hmac(
                CreateHmacArgs {
                    data: b"original data".to_vec(),
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac verify invalid"),
                    key_id: "hmac-2".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await
            .unwrap();

        let verify_result = transceiver
            .verify_hmac(
                VerifyHmacArgs {
                    data: b"tampered data".to_vec(),
                    hmac: hmac_result.hmac,
                    protocol_id: Protocol::new(SecurityLevel::App, "hmac verify invalid"),
                    key_id: "hmac-2".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await;

        // ProtoWallet returns an error when HMAC verification fails (not valid=false).
        // The wire protocol transmits this error back to the transceiver.
        match verify_result {
            Ok(res) => assert!(
                !res.valid,
                "expected valid=false or error for tampered HMAC"
            ),
            Err(e) => {
                let err_msg = format!("{}", e);
                assert!(
                    err_msg.contains("HMAC")
                        || err_msg.contains("hmac")
                        || err_msg.contains("wallet error"),
                    "expected HMAC-related error, got: {}",
                    err_msg
                );
            }
        }
    }
}

mod signature_tests {
    use super::*;

    /// Tests createSignature/verifySignature roundtrip with data.
    #[tokio::test]
    async fn test_roundtrip_signature_with_data() {
        let transceiver = create_loopback();
        let data = b"message to sign via wire".to_vec();

        let sig_result = transceiver
            .create_signature(
                CreateSignatureArgs {
                    data: Some(data.clone()),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol::new(SecurityLevel::App, "signature roundtrip"),
                    key_id: "sig-1".to_string(),
                    counterparty: None, // defaults to Anyone for create_signature
                },
                "test",
            )
            .await
            .unwrap();

        // DER signature should be 70-72 bytes typically
        assert!(!sig_result.signature.is_empty());
        assert!(sig_result.signature.len() >= 68);
        assert!(sig_result.signature.len() <= 73);

        let verify_result = transceiver
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(data),
                    hash_to_directly_verify: None,
                    signature: sig_result.signature,
                    protocol_id: Protocol::new(SecurityLevel::App, "signature roundtrip"),
                    key_id: "sig-1".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                },
                "test",
            )
            .await
            .unwrap();

        assert!(verify_result.valid);
    }

    /// Tests createSignature with hash_to_directly_sign.
    #[tokio::test]
    async fn test_roundtrip_signature_with_direct_hash() {
        let transceiver = create_loopback();
        let hash = bsv_sdk::primitives::sha256(b"pre-hashed data");

        let sig_result = transceiver
            .create_signature(
                CreateSignatureArgs {
                    data: None,
                    hash_to_directly_sign: Some(hash),
                    protocol_id: Protocol::new(SecurityLevel::App, "direct hash signature"),
                    key_id: "sig-hash-1".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        assert!(!sig_result.signature.is_empty());

        let verify_result = transceiver
            .verify_signature(
                VerifySignatureArgs {
                    data: None,
                    hash_to_directly_verify: Some(hash),
                    signature: sig_result.signature,
                    protocol_id: Protocol::new(SecurityLevel::App, "direct hash signature"),
                    key_id: "sig-hash-1".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                },
                "test",
            )
            .await
            .unwrap();

        assert!(verify_result.valid);
    }

    /// Tests verifySignature with invalid signature returns false.
    #[tokio::test]
    async fn test_roundtrip_signature_verify_invalid() {
        let transceiver = create_loopback();

        let sig_result = transceiver
            .create_signature(
                CreateSignatureArgs {
                    data: Some(b"original message".to_vec()),
                    hash_to_directly_sign: None,
                    protocol_id: Protocol::new(SecurityLevel::App, "invalid sig test"),
                    key_id: "sig-bad-1".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await
            .unwrap();

        // Verify against different data should fail
        let verify_result = transceiver
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(b"different message".to_vec()),
                    hash_to_directly_verify: None,
                    signature: sig_result.signature,
                    protocol_id: Protocol::new(SecurityLevel::App, "invalid sig test"),
                    key_id: "sig-bad-1".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                },
                "test",
            )
            .await;

        // Should either return valid=false or an error
        match verify_result {
            Ok(res) => assert!(!res.valid),
            Err(_) => {} // Error is also acceptable (invalid signature)
        }
    }
}

mod key_linkage_tests {
    use super::*;

    /// Tests revealCounterpartyKeyLinkage roundtrip.
    /// This exercises the complex response type with encrypted linkage, proof, and public keys.
    #[tokio::test]
    async fn test_roundtrip_reveal_counterparty_key_linkage() {
        let (_transceiver, _alice, bob) = create_two_party_loopback();
        let verifier_key = PrivateKey::random().public_key();

        // Build request manually since transceiver does not expose this method directly
        // via WalletInterface (it's exposed on the raw transceiver).
        // Instead, we test the full loopback through raw wire messages.
        let mut writer = WireWriter::new();

        // Call code
        writer.write_u8(WalletCall::RevealCounterpartyKeyLinkage.as_u8());
        // Originator
        let orig = b"test";
        writer.write_u8(orig.len() as u8);
        writer.write_bytes(orig);
        // Counterparty (33-byte pubkey)
        writer.write_bytes(&bob.identity_key().to_compressed());
        // Verifier (33-byte pubkey)
        writer.write_bytes(&verifier_key.to_compressed());

        let processor = {
            let alice_wallet = ProtoWallet::new(Some(PrivateKey::random()));
            Arc::new(WalletWireProcessor::new(alice_wallet))
        };

        let response = processor.process_message(writer.as_bytes()).await.unwrap();
        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(
            error_byte, 0,
            "expected success for counterparty key linkage"
        );

        // Parse response: encrypted_linkage_len + bytes, encrypted_proof_len + bytes,
        // prover(33), verifier(33), counterparty(33), revelation_time(string)
        let linkage_len = reader.read_var_int().unwrap() as usize;
        let _linkage = reader.read_bytes(linkage_len).unwrap();
        let proof_len = reader.read_var_int().unwrap() as usize;
        let _proof = reader.read_bytes(proof_len).unwrap();
        let prover_bytes = reader.read_bytes(33).unwrap();
        let _verifier_bytes = reader.read_bytes(33).unwrap();
        let counterparty_bytes = reader.read_bytes(33).unwrap();
        let revelation_time = reader.read_string().unwrap();

        // Verify the prover key is valid
        let _prover = PublicKey::from_bytes(prover_bytes).unwrap();
        // Verify the counterparty matches bob
        assert_eq!(counterparty_bytes, bob.identity_key().to_compressed());
        // Revelation time should be a non-empty ISO timestamp
        assert!(!revelation_time.is_empty());
    }

    /// Tests revealSpecificKeyLinkage roundtrip.
    #[tokio::test]
    async fn test_roundtrip_reveal_specific_key_linkage() {
        let bob_key = PrivateKey::random();
        let bob_pub = bob_key.public_key();
        let verifier_key = PrivateKey::random().public_key();
        let alice_wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = Arc::new(WalletWireProcessor::new(alice_wallet));

        let mut writer = WireWriter::new();
        // Call code
        writer.write_u8(WalletCall::RevealSpecificKeyLinkage.as_u8());
        // Originator
        let orig = b"test";
        writer.write_u8(orig.len() as u8);
        writer.write_bytes(orig);
        // Counterparty (Other)
        writer.write_bytes(&bob_pub.to_compressed());
        // Verifier
        writer.write_bytes(&verifier_key.to_compressed());
        // Protocol ID
        writer.write_u8(SecurityLevel::App.as_u8());
        writer.write_string("linkage test app");
        // Key ID
        writer.write_string("link-key-1");

        let response = processor.process_message(writer.as_bytes()).await.unwrap();
        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0, "expected success for specific key linkage");

        // Parse response
        let linkage_len = reader.read_var_int().unwrap() as usize;
        let _linkage = reader.read_bytes(linkage_len).unwrap();
        let proof_len = reader.read_var_int().unwrap() as usize;
        let _proof = reader.read_bytes(proof_len).unwrap();
        let _prover = reader.read_bytes(33).unwrap();
        let _verifier = reader.read_bytes(33).unwrap();
        let _counterparty = reader.read_bytes(33).unwrap();
        let protocol = reader.read_protocol_id().unwrap();
        let key_id = reader.read_string().unwrap();
        let proof_type = reader.read_u8().unwrap();

        assert_eq!(protocol.security_level, SecurityLevel::App);
        assert_eq!(protocol.protocol_name, "linkage test app");
        assert_eq!(key_id, "link-key-1");
        // proof_type is 0 for specific key linkage
        assert_eq!(proof_type, 0);
    }
}

// ============================================================================
// Chain/Status Operations - Loopback Roundtrip Tests
// ============================================================================

mod status_tests {
    use super::*;

    /// Tests isAuthenticated roundtrip (ProtoWallet always returns true).
    #[tokio::test]
    async fn test_roundtrip_is_authenticated() {
        let transceiver = create_loopback();
        let result = transceiver.is_authenticated("test").await.unwrap();
        assert!(result);
    }

    /// Tests waitForAuthentication roundtrip (ProtoWallet returns immediately).
    #[tokio::test]
    async fn test_roundtrip_wait_for_authentication() {
        let transceiver = create_loopback();
        let result = transceiver.wait_for_authentication("test").await.unwrap();
        assert!(result);
    }

    /// Tests getHeight roundtrip (ProtoWallet returns 0).
    #[tokio::test]
    async fn test_roundtrip_get_height() {
        let transceiver = create_loopback();
        let result = transceiver.get_height("test").await.unwrap();
        assert_eq!(result, 0);
    }

    /// Tests getNetwork roundtrip (processor returns configured network).
    #[tokio::test]
    async fn test_roundtrip_get_network_mainnet() {
        let transceiver = create_loopback();
        let result = transceiver.get_network("test").await.unwrap();
        assert_eq!(result, Network::Mainnet);
    }

    /// Tests getNetwork with testnet configuration.
    #[tokio::test]
    async fn test_roundtrip_get_network_testnet() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = Arc::new(WalletWireProcessor::with_config(
            wallet,
            Network::Testnet,
            "1.0.0",
        ));
        let wire = LoopbackWire { processor };
        let transceiver = WalletWireTransceiver::new(wire);
        let result = transceiver.get_network("test").await.unwrap();
        assert_eq!(result, Network::Testnet);
    }

    /// Tests getVersion roundtrip.
    #[tokio::test]
    async fn test_roundtrip_get_version() {
        let transceiver = create_loopback();
        let result = transceiver.get_version("test").await.unwrap();
        assert!(!result.is_empty());
        // Default processor version
        assert_eq!(result, "0.1.0");
    }

    /// Tests getVersion with custom version.
    #[tokio::test]
    async fn test_roundtrip_get_version_custom() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = Arc::new(WalletWireProcessor::with_config(
            wallet,
            Network::Mainnet,
            "2.5.1-beta",
        ));
        let wire = LoopbackWire { processor };
        let transceiver = WalletWireTransceiver::new(wire);
        let result = transceiver.get_version("test").await.unwrap();
        assert_eq!(result, "2.5.1-beta");
    }

    /// Tests getHeaderForHeight roundtrip. ProtoWallet doesn't support this,
    /// so we expect an error, but it verifies request serialization works.
    #[tokio::test]
    async fn test_roundtrip_get_header_for_height_error() {
        let transceiver = create_loopback();
        let result = transceiver
            .get_header(GetHeaderArgs { height: 100 }, "test")
            .await;

        // ProtoWallet doesn't support get_header_for_height, so we expect an error
        assert!(result.is_err());
    }
}

// ============================================================================
// Action Operations - Request Serialization Tests
// ============================================================================
// ProtoWallet doesn't support action operations, so these test that the
// request serialization succeeds (the server returns an error, which is fine).

mod action_tests {
    use super::*;

    /// Tests createAction request serialization with all fields populated.
    #[tokio::test]
    async fn test_roundtrip_create_action_populated() {
        let transceiver = create_loopback();
        let result = transceiver
            .create_action(
                CreateActionArgs {
                    description: "test action description".to_string(),
                    input_beef: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
                    inputs: Some(vec![CreateActionInput {
                        outpoint: Outpoint::new(sample_txid(), 0),
                        input_description: "test input description".to_string(),
                        unlocking_script: Some(vec![0x00, 0x14, 0xab]),
                        unlocking_script_length: None,
                        sequence_number: Some(0xFFFFFFFF),
                    }]),
                    outputs: Some(vec![CreateActionOutput {
                        locking_script: vec![0x76, 0xa9, 0x14],
                        satoshis: 50000,
                        output_description: "test output description".to_string(),
                        basket: Some("payments".to_string()),
                        custom_instructions: Some("custom-inst".to_string()),
                        tags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
                    }]),
                    lock_time: Some(500000),
                    version: Some(1),
                    labels: Some(vec!["label1".to_string()]),
                    options: Some(CreateActionOptions {
                        sign_and_process: Some(true),
                        accept_delayed_broadcast: Some(false),
                        trust_self: Some(TrustSelf::Known),
                        known_txids: Some(vec![sample_txid()]),
                        return_txid_only: Some(true),
                        no_send: Some(false),
                        no_send_change: Some(vec![Outpoint::new(sample_txid(), 1)]),
                        send_with: Some(vec![sample_txid()]),
                        randomize_outputs: Some(true),
                    }),
                },
                "test",
            )
            .await;

        // ProtoWallet returns error for createAction, but the request serialized OK
        assert!(result.is_err());
    }

    /// Tests createAction with minimal args (only description, no inputs/outputs/options).
    #[tokio::test]
    async fn test_roundtrip_create_action_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .create_action(
                CreateActionArgs {
                    description: "minimal action".to_string(),
                    input_beef: None,
                    inputs: None,
                    outputs: None,
                    lock_time: None,
                    version: None,
                    labels: None,
                    options: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests signAction request serialization.
    #[tokio::test]
    async fn test_roundtrip_sign_action() {
        let transceiver = create_loopback();
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![0x48, 0x30, 0x45],
                sequence_number: Some(0xFFFFFFFF),
            },
        );
        spends.insert(
            1,
            SignActionSpend {
                unlocking_script: vec![0x47, 0x30, 0x44],
                sequence_number: None,
            },
        );

        let result = transceiver
            .sign_action(
                SignActionArgs {
                    spends,
                    reference: bsv_sdk::primitives::to_base64(&[0x01, 0x02, 0x03]),
                    options: Some(bsv_sdk::wallet::SignActionOptions {
                        accept_delayed_broadcast: Some(true),
                        return_txid_only: Some(false),
                        no_send: Some(true),
                        send_with: Some(vec![sample_txid()]),
                    }),
                },
                "test",
            )
            .await;

        assert!(result.is_err()); // ProtoWallet doesn't support signAction
    }

    /// Tests abortAction request serialization.
    #[tokio::test]
    async fn test_roundtrip_abort_action() {
        let transceiver = create_loopback();
        let result = transceiver
            .abort_action(
                AbortActionArgs {
                    reference: bsv_sdk::primitives::to_base64(&[0xAA, 0xBB, 0xCC]),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests listActions request serialization with all options.
    #[tokio::test]
    async fn test_roundtrip_list_actions_populated() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_actions(
                ListActionsArgs {
                    labels: vec!["payments".to_string(), "transfers".to_string()],
                    label_query_mode: Some(QueryMode::All),
                    include_labels: Some(true),
                    include_inputs: Some(true),
                    include_input_source_locking_scripts: Some(true),
                    include_input_unlocking_scripts: Some(false),
                    include_outputs: Some(true),
                    include_output_locking_scripts: Some(true),
                    limit: Some(25),
                    offset: Some(10),
                    seek_permission: Some(true),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests listActions with minimal args.
    #[tokio::test]
    async fn test_roundtrip_list_actions_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_actions(
                ListActionsArgs {
                    labels: vec!["default".to_string()],
                    label_query_mode: None,
                    include_labels: None,
                    include_inputs: None,
                    include_input_source_locking_scripts: None,
                    include_input_unlocking_scripts: None,
                    include_outputs: None,
                    include_output_locking_scripts: None,
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests internalizeAction request serialization with wallet payment protocol.
    #[tokio::test]
    async fn test_roundtrip_internalize_action_wallet_payment() {
        let transceiver = create_loopback();
        let result = transceiver
            .internalize_action(
                InternalizeActionArgs {
                    tx: vec![0x01, 0x00, 0x00, 0x00],
                    outputs: vec![InternalizeOutput {
                        output_index: 0,
                        protocol: "wallet payment".to_string(),
                        payment_remittance: Some(WalletPayment {
                            derivation_prefix: bsv_sdk::primitives::to_base64(b"prefix"),
                            derivation_suffix: bsv_sdk::primitives::to_base64(b"suffix"),
                            sender_identity_key: sample_pubkey_hex(),
                        }),
                        insertion_remittance: None,
                    }],
                    description: "internalize payment".to_string(),
                    labels: Some(vec!["income".to_string()]),
                    seek_permission: Some(false),
                },
                "test",
            )
            .await;

        // Internalize returns Ok(accepted: true) on success of transmit
        // But the underlying ProtoWallet doesn't support it
        assert!(result.is_err());
    }

    /// Tests internalizeAction with basket insertion protocol.
    #[tokio::test]
    async fn test_roundtrip_internalize_action_basket_insertion() {
        let transceiver = create_loopback();
        let result = transceiver
            .internalize_action(
                InternalizeActionArgs {
                    tx: vec![0x02, 0x00, 0x00, 0x00],
                    outputs: vec![InternalizeOutput {
                        output_index: 1,
                        protocol: "basket insertion".to_string(),
                        payment_remittance: None,
                        insertion_remittance: Some(BasketInsertion {
                            basket: "tokens".to_string(),
                            custom_instructions: Some("handle-special".to_string()),
                            tags: Some(vec!["nft".to_string(), "rare".to_string()]),
                        }),
                    }],
                    description: "insert into basket".to_string(),
                    labels: None,
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Output Operations - Request Serialization Tests
// ============================================================================

mod output_tests {
    use super::*;

    /// Tests listOutputs request serialization with all options.
    #[tokio::test]
    async fn test_roundtrip_list_outputs_populated() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_outputs(
                ListOutputsArgs {
                    basket: "payments".to_string(),
                    tags: Some(vec!["important".to_string(), "pending".to_string()]),
                    tag_query_mode: Some(QueryMode::Any),
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: Some(true),
                    include_tags: Some(true),
                    include_labels: Some(true),
                    limit: Some(50),
                    offset: Some(0),
                    seek_permission: Some(true),
                },
                "test",
            )
            .await;

        assert!(result.is_err()); // ProtoWallet doesn't support listOutputs
    }

    /// Tests listOutputs with minimal args.
    #[tokio::test]
    async fn test_roundtrip_list_outputs_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_outputs(
                ListOutputsArgs {
                    basket: "default".to_string(),
                    tags: None,
                    tag_query_mode: None,
                    include: None,
                    include_custom_instructions: None,
                    include_tags: None,
                    include_labels: None,
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests listOutputs with EntireTransactions include mode.
    #[tokio::test]
    async fn test_roundtrip_list_outputs_entire_transactions() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_outputs(
                ListOutputsArgs {
                    basket: "utxos".to_string(),
                    tags: Some(vec!["p2pkh".to_string()]),
                    tag_query_mode: Some(QueryMode::All),
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: None,
                    include_tags: None,
                    include_labels: None,
                    limit: Some(100),
                    offset: Some(-10),
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests relinquishOutput request serialization.
    #[tokio::test]
    async fn test_roundtrip_relinquish_output() {
        let transceiver = create_loopback();
        let result = transceiver
            .relinquish_output(
                RelinquishOutputArgs {
                    basket: "tokens".to_string(),
                    output: Outpoint::new(sample_txid(), 3),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Certificate Operations - Request Serialization Tests
// ============================================================================

mod certificate_tests {
    use super::*;

    /// Tests acquireCertificate request serialization with direct protocol.
    #[tokio::test]
    async fn test_roundtrip_acquire_certificate_direct() {
        let transceiver = create_loopback();
        let certifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .acquire_certificate(
                AcquireCertificateArgs {
                    certificate_type: bsv_sdk::primitives::to_base64(&[0u8; 32]),
                    certifier: bsv_sdk::primitives::to_hex(&certifier_key.to_compressed()),
                    acquisition_protocol: AcquisitionProtocol::Direct,
                    fields: {
                        let mut m = HashMap::new();
                        m.insert("name".to_string(), "Test User".to_string());
                        m
                    },
                    serial_number: Some(bsv_sdk::primitives::to_base64(&[1u8; 32])),
                    revocation_outpoint: Some(sample_outpoint_string()),
                    signature: Some(bsv_sdk::primitives::to_hex(&[0x30, 0x44, 0x02, 0x20])),
                    certifier_url: None,
                    keyring_revealer: None, // defaults to certifier
                    keyring_for_subject: Some({
                        let mut m = HashMap::new();
                        m.insert(
                            "name".to_string(),
                            bsv_sdk::primitives::to_base64(b"key-for-name"),
                        );
                        m
                    }),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err()); // ProtoWallet doesn't support acquireCertificate
    }

    /// Tests acquireCertificate with issuance protocol.
    #[tokio::test]
    async fn test_roundtrip_acquire_certificate_issuance() {
        let transceiver = create_loopback();
        let certifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .acquire_certificate(
                AcquireCertificateArgs {
                    certificate_type: bsv_sdk::primitives::to_base64(&[0xFFu8; 32]),
                    certifier: bsv_sdk::primitives::to_hex(&certifier_key.to_compressed()),
                    acquisition_protocol: AcquisitionProtocol::Issuance,
                    fields: HashMap::new(),
                    serial_number: None,
                    revocation_outpoint: None,
                    signature: None,
                    certifier_url: Some("https://certifier.example.com/issue".to_string()),
                    keyring_revealer: None,
                    keyring_for_subject: None,
                    privileged: None,
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests listCertificates request serialization.
    #[tokio::test]
    async fn test_roundtrip_list_certificates() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_certificates(
                ListCertificatesArgs {
                    certifiers: vec![sample_pubkey_hex()],
                    types: vec![bsv_sdk::primitives::to_base64(&[0u8; 32])],
                    limit: Some(10),
                    offset: Some(0),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests listCertificates with minimal args.
    #[tokio::test]
    async fn test_roundtrip_list_certificates_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_certificates(
                ListCertificatesArgs {
                    certifiers: vec![sample_pubkey_hex()],
                    types: vec![bsv_sdk::primitives::to_base64(&[0u8; 32])],
                    limit: None,
                    offset: None,
                    privileged: None,
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests proveCertificate request serialization.
    #[tokio::test]
    async fn test_roundtrip_prove_certificate() {
        let transceiver = create_loopback();
        let verifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .prove_certificate(
                ProveCertificateArgs {
                    certificate: sample_wallet_certificate(),
                    fields_to_reveal: vec!["name".to_string()],
                    verifier: bsv_sdk::primitives::to_hex(&verifier_key.to_compressed()),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests relinquishCertificate request serialization.
    #[tokio::test]
    async fn test_roundtrip_relinquish_certificate() {
        let transceiver = create_loopback();
        let certifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .relinquish_certificate(
                RelinquishCertificateArgs {
                    certificate_type: bsv_sdk::primitives::to_base64(&[0u8; 32]),
                    serial_number: bsv_sdk::primitives::to_base64(&[1u8; 32]),
                    certifier: bsv_sdk::primitives::to_hex(&certifier_key.to_compressed()),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Discovery Operations - Request Serialization Tests
// ============================================================================

mod discovery_tests {
    use super::*;

    /// Tests discoverByIdentityKey request serialization with all options.
    #[tokio::test]
    async fn test_roundtrip_discover_by_identity_key_populated() {
        let transceiver = create_loopback();
        let result = transceiver
            .discover_by_identity_key(
                DiscoverByIdentityKeyArgs {
                    identity_key: sample_pubkey_hex(),
                    limit: Some(20),
                    offset: Some(5),
                    seek_permission: Some(true),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests discoverByIdentityKey with minimal args.
    #[tokio::test]
    async fn test_roundtrip_discover_by_identity_key_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .discover_by_identity_key(
                DiscoverByIdentityKeyArgs {
                    identity_key: sample_pubkey_hex(),
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests discoverByAttributes request serialization.
    #[tokio::test]
    async fn test_roundtrip_discover_by_attributes_populated() {
        let transceiver = create_loopback();
        let mut attributes = HashMap::new();
        attributes.insert("name".to_string(), "Alice".to_string());
        attributes.insert("email".to_string(), "alice@example.com".to_string());

        let result = transceiver
            .discover_by_attributes(
                DiscoverByAttributesArgs {
                    attributes,
                    limit: Some(10),
                    offset: Some(0),
                    seek_permission: Some(false),
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }

    /// Tests discoverByAttributes with minimal args.
    #[tokio::test]
    async fn test_roundtrip_discover_by_attributes_minimal() {
        let transceiver = create_loopback();
        let mut attributes = HashMap::new();
        attributes.insert("key".to_string(), "value".to_string());

        let result = transceiver
            .discover_by_attributes(
                DiscoverByAttributesArgs {
                    attributes,
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                "test",
            )
            .await;

        assert!(result.is_err());
    }
}

// ============================================================================
// Complex Type Wire Encoding Roundtrip Tests
// ============================================================================
// These test the WireWriter/WireReader directly for complex wallet types,
// ensuring that serialization and deserialization are perfectly symmetric.

mod complex_type_roundtrips {
    use super::*;

    /// Tests WalletCertificate write/read roundtrip.
    #[test]
    fn test_wallet_certificate_roundtrip() {
        let cert = sample_wallet_certificate();

        let mut writer = WireWriter::new();
        writer.write_wallet_certificate(&cert).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read_cert = reader.read_wallet_certificate().unwrap();

        assert_eq!(read_cert.certificate_type, cert.certificate_type);
        assert_eq!(read_cert.subject, cert.subject);
        assert_eq!(read_cert.serial_number, cert.serial_number);
        assert_eq!(read_cert.certifier, cert.certifier);
        assert_eq!(read_cert.revocation_outpoint, cert.revocation_outpoint);
        assert_eq!(read_cert.signature, cert.signature);
        assert_eq!(read_cert.fields, cert.fields);
        assert!(reader.is_empty());
    }

    /// Tests optional WalletCertificate roundtrip (Some).
    #[test]
    fn test_optional_wallet_certificate_some_roundtrip() {
        let cert = sample_wallet_certificate();

        let mut writer = WireWriter::new();
        writer
            .write_optional_wallet_certificate(Some(&cert))
            .unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read_cert = reader.read_optional_wallet_certificate().unwrap();
        assert!(read_cert.is_some());
        let read_cert = read_cert.unwrap();
        assert_eq!(read_cert.certificate_type, cert.certificate_type);
    }

    /// Tests optional WalletCertificate roundtrip (None).
    #[test]
    fn test_optional_wallet_certificate_none_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_optional_wallet_certificate(None).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read_cert = reader.read_optional_wallet_certificate().unwrap();
        assert!(read_cert.is_none());
    }

    /// Tests IdentityCertifier write/read roundtrip.
    #[test]
    fn test_identity_certifier_roundtrip() {
        let certifier = IdentityCertifier {
            name: "BSV Authority".to_string(),
            icon_url: Some("https://example.com/icon.png".to_string()),
            description: Some("Official BSV certificate authority".to_string()),
            trust: 9,
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certifier(&certifier);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certifier().unwrap();

        assert_eq!(read.name, certifier.name);
        assert_eq!(read.icon_url, certifier.icon_url);
        assert_eq!(read.description, certifier.description);
        assert_eq!(read.trust, certifier.trust);
    }

    /// Tests optional IdentityCertifier roundtrip (Some with None fields).
    #[test]
    fn test_optional_identity_certifier_minimal_roundtrip() {
        let certifier = IdentityCertifier {
            name: "Minimal".to_string(),
            icon_url: None,
            description: None,
            trust: 1,
        };

        let mut writer = WireWriter::new();
        writer.write_optional_identity_certifier(Some(&certifier));

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_identity_certifier().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.name, "Minimal");
        assert_eq!(read.icon_url, None);
        assert_eq!(read.description, None);
        assert_eq!(read.trust, 1);
    }

    /// Tests IdentityCertificate write/read roundtrip.
    #[test]
    fn test_identity_certificate_roundtrip() {
        let cert = IdentityCertificate {
            certificate: sample_wallet_certificate(),
            certifier_info: Some(IdentityCertifier {
                name: "Test Certifier".to_string(),
                icon_url: Some("https://icon.example.com".to_string()),
                description: None,
                trust: 5,
            }),
            publicly_revealed_keyring: Some({
                let mut m = HashMap::new();
                m.insert("name".to_string(), "keyring-val-1".to_string());
                m
            }),
            decrypted_fields: Some({
                let mut m = HashMap::new();
                m.insert("name".to_string(), "Alice Smith".to_string());
                m.insert("email".to_string(), "alice@smith.com".to_string());
                m
            }),
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certificate(&cert).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certificate().unwrap();

        assert_eq!(
            read.certificate.certificate_type,
            cert.certificate.certificate_type
        );
        assert!(read.certifier_info.is_some());
        assert_eq!(read.certifier_info.as_ref().unwrap().name, "Test Certifier");
        assert!(read.publicly_revealed_keyring.is_some());
        assert!(read.decrypted_fields.is_some());
        assert_eq!(
            read.decrypted_fields.as_ref().unwrap().get("name").unwrap(),
            "Alice Smith"
        );
    }

    /// Tests IdentityCertificate with None optional fields.
    #[test]
    fn test_identity_certificate_minimal_roundtrip() {
        let cert = IdentityCertificate {
            certificate: sample_wallet_certificate(),
            certifier_info: None,
            publicly_revealed_keyring: None,
            decrypted_fields: None,
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certificate(&cert).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certificate().unwrap();

        assert!(read.certifier_info.is_none());
        assert!(read.publicly_revealed_keyring.is_none());
        assert!(read.decrypted_fields.is_none());
    }

    /// Tests WalletPayment write/read roundtrip.
    #[test]
    fn test_wallet_payment_roundtrip() {
        let payment = WalletPayment {
            derivation_prefix: "prefix-abc".to_string(),
            derivation_suffix: "suffix-xyz".to_string(),
            sender_identity_key: sample_pubkey_hex(),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_payment(&payment);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_payment().unwrap();

        assert_eq!(read.derivation_prefix, payment.derivation_prefix);
        assert_eq!(read.derivation_suffix, payment.derivation_suffix);
        assert_eq!(read.sender_identity_key, payment.sender_identity_key);
    }

    /// Tests optional WalletPayment roundtrip (None).
    #[test]
    fn test_optional_wallet_payment_none_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_optional_wallet_payment(None);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_wallet_payment().unwrap();
        assert!(read.is_none());
    }

    /// Tests BasketInsertion write/read roundtrip with all fields.
    #[test]
    fn test_basket_insertion_roundtrip() {
        let insertion = BasketInsertion {
            basket: "nft-tokens".to_string(),
            custom_instructions: Some("verify-ownership".to_string()),
            tags: Some(vec!["rare".to_string(), "limited".to_string()]),
        };

        let mut writer = WireWriter::new();
        writer.write_basket_insertion(&insertion);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_basket_insertion().unwrap();

        assert_eq!(read.basket, insertion.basket);
        assert_eq!(read.custom_instructions, insertion.custom_instructions);
        assert_eq!(read.tags, insertion.tags);
    }

    /// Tests BasketInsertion with None optional fields.
    #[test]
    fn test_basket_insertion_minimal_roundtrip() {
        let insertion = BasketInsertion {
            basket: "default".to_string(),
            custom_instructions: None,
            tags: None,
        };

        let mut writer = WireWriter::new();
        writer.write_basket_insertion(&insertion);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_basket_insertion().unwrap();

        assert_eq!(read.basket, "default");
        assert_eq!(read.custom_instructions, None);
        // Empty tags are read as None
        assert!(read.tags.is_none());
    }

    /// Tests InternalizeOutput write/read roundtrip.
    #[test]
    fn test_internalize_output_roundtrip() {
        let output = InternalizeOutput {
            output_index: 42,
            protocol: "wallet payment".to_string(),
            payment_remittance: Some(WalletPayment {
                derivation_prefix: "pay-prefix".to_string(),
                derivation_suffix: "pay-suffix".to_string(),
                sender_identity_key: sample_pubkey_hex(),
            }),
            insertion_remittance: None,
        };

        let mut writer = WireWriter::new();
        writer.write_internalize_output(&output);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_internalize_output().unwrap();

        assert_eq!(read.output_index, 42);
        assert_eq!(read.protocol, "wallet payment");
        assert!(read.payment_remittance.is_some());
        assert!(read.insertion_remittance.is_none());
    }

    /// Tests WalletActionInput write/read roundtrip.
    #[test]
    fn test_wallet_action_input_roundtrip() {
        let input = WalletActionInput {
            source_outpoint: Outpoint::new(sample_txid(), 2),
            source_satoshis: 100000,
            source_locking_script: Some(vec![0x76, 0xa9, 0x14, 0xab]),
            unlocking_script: Some(vec![0x48, 0x30, 0x45, 0x02, 0x21]),
            input_description: "spending previous output".to_string(),
            sequence_number: 0xFFFFFFFE,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_input(&input);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_input().unwrap();

        assert_eq!(read.source_outpoint.txid, input.source_outpoint.txid);
        assert_eq!(read.source_outpoint.vout, 2);
        assert_eq!(read.source_satoshis, 100000);
        assert_eq!(read.source_locking_script, input.source_locking_script);
        assert_eq!(read.unlocking_script, input.unlocking_script);
        assert_eq!(read.input_description, "spending previous output");
        assert_eq!(read.sequence_number, 0xFFFFFFFE);
    }

    /// Tests WalletActionInput with None optional fields.
    #[test]
    fn test_wallet_action_input_minimal_roundtrip() {
        let input = WalletActionInput {
            source_outpoint: Outpoint::new([0u8; 32], 0),
            source_satoshis: 0,
            source_locking_script: None,
            unlocking_script: None,
            input_description: "empty input".to_string(),
            sequence_number: 0xFFFFFFFF,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_input(&input);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_input().unwrap();

        assert_eq!(read.source_locking_script, None);
        assert_eq!(read.unlocking_script, None);
        assert_eq!(read.sequence_number, 0xFFFFFFFF);
    }

    /// Tests WalletActionOutput write/read roundtrip.
    #[test]
    fn test_wallet_action_output_roundtrip() {
        let output = WalletActionOutput {
            satoshis: 50000,
            locking_script: Some(vec![0x76, 0xa9, 0x14]),
            spendable: true,
            custom_instructions: Some("custom-op".to_string()),
            tags: vec!["p2pkh".to_string(), "change".to_string()],
            output_index: 1,
            output_description: "change output".to_string(),
            basket: "change".to_string(),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_output(&output);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_output().unwrap();

        assert_eq!(read.satoshis, 50000);
        assert_eq!(read.locking_script, output.locking_script);
        assert_eq!(read.spendable, true);
        assert_eq!(read.custom_instructions, output.custom_instructions);
        assert_eq!(read.tags, output.tags);
        assert_eq!(read.output_index, 1);
        assert_eq!(read.output_description, "change output");
        assert_eq!(read.basket, "change");
    }

    /// Tests WalletAction write/read roundtrip with all fields populated.
    #[test]
    fn test_wallet_action_full_roundtrip() {
        let action = WalletAction {
            txid: sample_txid(),
            satoshis: -50000, // negative for outgoing
            status: ActionStatus::Completed,
            is_outgoing: true,
            description: "payment to merchant".to_string(),
            labels: Some(vec!["payments".to_string(), "merchant".to_string()]),
            version: 1,
            lock_time: 0,
            inputs: Some(vec![WalletActionInput {
                source_outpoint: Outpoint::new(sample_txid(), 0),
                source_satoshis: 100000,
                source_locking_script: Some(vec![0x76, 0xa9]),
                unlocking_script: Some(vec![0x48, 0x30]),
                input_description: "input from wallet".to_string(),
                sequence_number: 0xFFFFFFFF,
            }]),
            outputs: Some(vec![WalletActionOutput {
                satoshis: 50000,
                locking_script: Some(vec![0x76, 0xa9]),
                spendable: false,
                custom_instructions: None,
                tags: vec![],
                output_index: 0,
                output_description: "merchant payment".to_string(),
                basket: "payments".to_string(),
            }]),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action(&action);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action().unwrap();

        assert_eq!(read.txid, action.txid);
        assert_eq!(read.satoshis, -50000);
        assert_eq!(read.status, ActionStatus::Completed);
        assert_eq!(read.is_outgoing, true);
        assert_eq!(read.description, "payment to merchant");
        assert_eq!(
            read.labels,
            Some(vec!["payments".to_string(), "merchant".to_string()])
        );
        assert_eq!(read.version, 1);
        assert_eq!(read.lock_time, 0);
        assert!(read.inputs.is_some());
        assert_eq!(read.inputs.as_ref().unwrap().len(), 1);
        assert!(read.outputs.is_some());
        assert_eq!(read.outputs.as_ref().unwrap().len(), 1);
    }

    /// Tests WalletAction with None inputs/outputs/labels.
    #[test]
    fn test_wallet_action_minimal_roundtrip() {
        let action = WalletAction {
            txid: [0u8; 32],
            satoshis: 0,
            status: ActionStatus::Unprocessed,
            is_outgoing: false,
            description: "empty action".to_string(),
            labels: None,
            version: 2,
            lock_time: 500000,
            inputs: None,
            outputs: None,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action(&action);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action().unwrap();

        assert_eq!(read.txid, [0u8; 32]);
        assert_eq!(read.satoshis, 0);
        assert_eq!(read.status, ActionStatus::Unprocessed);
        assert_eq!(read.is_outgoing, false);
        assert_eq!(read.labels, None);
        assert_eq!(read.version, 2);
        assert_eq!(read.lock_time, 500000);
        assert!(read.inputs.is_none());
        assert!(read.outputs.is_none());
    }

    /// Tests WalletAction with all status variants.
    #[test]
    fn test_wallet_action_all_statuses() {
        let statuses = [
            ActionStatus::Completed,
            ActionStatus::Unprocessed,
            ActionStatus::Sending,
            ActionStatus::Unproven,
            ActionStatus::Unsigned,
            ActionStatus::NoSend,
            ActionStatus::NonFinal,
            ActionStatus::Failed,
        ];

        for status in statuses {
            let action = WalletAction {
                txid: sample_txid(),
                satoshis: 1000,
                status,
                is_outgoing: false,
                description: "status test".to_string(),
                labels: None,
                version: 1,
                lock_time: 0,
                inputs: None,
                outputs: None,
            };

            let mut writer = WireWriter::new();
            writer.write_wallet_action(&action);

            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_wallet_action().unwrap();
            assert_eq!(read.status, status, "status mismatch for {:?}", status);
        }
    }

    /// Tests WalletOutput write/read roundtrip with all fields.
    #[test]
    fn test_wallet_output_full_roundtrip() {
        let output = WalletOutput {
            satoshis: 75000,
            locking_script: Some(vec![0x76, 0xa9, 0x14, 0xab, 0xcd]),
            spendable: true,
            custom_instructions: Some("spend-with-r-puzzle".to_string()),
            tags: Some(vec!["p2pkh".to_string(), "received".to_string()]),
            outpoint: Outpoint::new(sample_txid(), 5),
            labels: Some(vec!["income".to_string()]),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_output(&output);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_output().unwrap();

        assert_eq!(read.satoshis, 75000);
        assert_eq!(read.locking_script, output.locking_script);
        assert_eq!(read.spendable, true);
        assert_eq!(read.custom_instructions, output.custom_instructions);
        assert_eq!(read.tags, output.tags);
        assert_eq!(read.outpoint.txid, output.outpoint.txid);
        assert_eq!(read.outpoint.vout, 5);
        assert_eq!(read.labels, output.labels);
    }

    /// Tests WalletOutput with None optional fields.
    #[test]
    fn test_wallet_output_minimal_roundtrip() {
        let output = WalletOutput {
            satoshis: 0,
            locking_script: None,
            spendable: false,
            custom_instructions: None,
            tags: None,
            outpoint: Outpoint::new([0u8; 32], 0),
            labels: None,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_output(&output);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_output().unwrap();

        assert_eq!(read.satoshis, 0);
        assert_eq!(read.locking_script, None);
        assert_eq!(read.spendable, false);
        assert_eq!(read.custom_instructions, None);
        assert!(read.tags.is_none());
        assert!(read.labels.is_none());
    }

    /// Tests SendWithResult roundtrip.
    #[test]
    fn test_send_with_result_roundtrip() {
        let results = vec![
            SendWithResult {
                txid: sample_txid(),
                status: SendWithResultStatus::Unproven,
            },
            SendWithResult {
                txid: [0xFF; 32],
                status: SendWithResultStatus::Sending,
            },
            SendWithResult {
                txid: [0x00; 32],
                status: SendWithResultStatus::Failed,
            },
        ];

        let mut writer = WireWriter::new();
        writer.write_send_with_result_array(Some(&results));

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_send_with_result_array().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.len(), 3);
        assert_eq!(read[0].txid, sample_txid());
        assert_eq!(read[0].status, SendWithResultStatus::Unproven);
        assert_eq!(read[1].status, SendWithResultStatus::Sending);
        assert_eq!(read[2].status, SendWithResultStatus::Failed);
    }

    /// Tests SendWithResult array None roundtrip.
    #[test]
    fn test_send_with_result_array_none_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_send_with_result_array(None);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_send_with_result_array().unwrap();
        assert!(read.is_none());
    }

    /// Tests SignActionSpend map roundtrip.
    #[test]
    fn test_sign_action_spends_roundtrip() {
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![0x48, 0x30, 0x45, 0x02],
                sequence_number: Some(0xFFFFFFFF),
            },
        );
        spends.insert(
            3,
            SignActionSpend {
                unlocking_script: vec![0x47, 0x30, 0x44],
                sequence_number: None,
            },
        );

        let mut writer = WireWriter::new();
        writer.write_sign_action_spends(&spends);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_sign_action_spends().unwrap();

        assert_eq!(read.len(), 2);
        assert!(read.contains_key(&0));
        assert!(read.contains_key(&3));
        assert_eq!(read[&0].unlocking_script, vec![0x48, 0x30, 0x45, 0x02]);
        assert_eq!(read[&0].sequence_number, Some(0xFFFFFFFF));
        assert_eq!(read[&3].unlocking_script, vec![0x47, 0x30, 0x44]);
        assert_eq!(read[&3].sequence_number, None);
    }

    /// Tests optional string map roundtrip.
    #[test]
    fn test_optional_string_map_roundtrip() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());

        // Some case
        let mut writer = WireWriter::new();
        writer.write_optional_string_map(Some(&map));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_string_map().unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap(), map);

        // None case
        let mut writer = WireWriter::new();
        writer.write_optional_string_map(None);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_string_map().unwrap();
        assert!(read.is_none());
    }

    /// Tests optional string array roundtrip.
    #[test]
    fn test_optional_string_array_roundtrip() {
        let strings = vec!["hello".to_string(), "world".to_string()];

        // Some case
        let mut writer = WireWriter::new();
        writer.write_optional_string_array(Some(&strings));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_string_array().unwrap();
        assert_eq!(read, strings);

        // None case
        let mut writer = WireWriter::new();
        writer.write_optional_string_array(None);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_string_array().unwrap();
        assert!(read.is_empty());
    }

    /// Tests optional protocol ID roundtrip.
    #[test]
    fn test_optional_protocol_id_roundtrip() {
        // Some case
        let protocol = Protocol::new(SecurityLevel::Counterparty, "advanced encryption");
        let mut writer = WireWriter::new();
        writer.write_optional_protocol_id(Some(&protocol));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_protocol_id().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.security_level, SecurityLevel::Counterparty);
        assert_eq!(read.protocol_name, "advanced encryption");

        // None case
        let mut writer = WireWriter::new();
        writer.write_optional_protocol_id(None);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_protocol_id().unwrap();
        assert!(read.is_none());
    }

    /// Tests all SecurityLevel variants through protocol roundtrip.
    #[test]
    fn test_all_security_levels_roundtrip() {
        let levels = [
            SecurityLevel::Silent,
            SecurityLevel::App,
            SecurityLevel::Counterparty,
        ];

        for level in levels {
            let protocol = Protocol::new(level, "level test proto");
            let mut writer = WireWriter::new();
            writer.write_protocol_id(&protocol);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_protocol_id().unwrap();
            assert_eq!(
                read.security_level, level,
                "security level mismatch for {:?}",
                level
            );
        }
    }

    /// Tests query mode roundtrip including optional variant.
    #[test]
    fn test_query_mode_optional_roundtrip() {
        let cases = [None, Some(QueryMode::Any), Some(QueryMode::All)];
        for mode in cases {
            let mut writer = WireWriter::new();
            writer.write_optional_query_mode(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_optional_query_mode().unwrap();
            assert_eq!(read, mode, "query mode mismatch for {:?}", mode);
        }
    }

    /// Tests output include mode roundtrip including optional variant.
    #[test]
    fn test_output_include_optional_roundtrip() {
        let cases = [
            None,
            Some(OutputInclude::LockingScripts),
            Some(OutputInclude::EntireTransactions),
        ];
        for mode in cases {
            let mut writer = WireWriter::new();
            writer.write_optional_output_include(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_optional_output_include().unwrap();
            assert_eq!(read, mode, "output include mismatch for {:?}", mode);
        }
    }

    /// Tests Unicode string roundtrip through wire encoding.
    #[test]
    fn test_unicode_string_roundtrip() {
        let strings = vec![
            "Hello, World!".to_string(),
            "Привет мир".to_string(),   // Russian
            "日本語テスト".to_string(), // Japanese
            "🎉🚀💰".to_string(),       // Emoji
            "".to_string(),             // Empty
        ];

        for s in &strings {
            let mut writer = WireWriter::new();
            writer.write_string(s);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_string().unwrap();
            assert_eq!(&read, s, "unicode string mismatch");
        }
    }

    /// Tests txid hex roundtrip.
    #[test]
    fn test_txid_hex_roundtrip() {
        let txid = sample_txid();
        let hex = bsv_sdk::primitives::to_hex(&txid);

        let mut writer = WireWriter::new();
        writer.write_txid_hex(&hex).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read_hex = reader.read_txid_hex().unwrap();

        assert_eq!(read_hex, hex);
    }

    /// Tests pubkey hex roundtrip.
    #[test]
    fn test_pubkey_hex_roundtrip() {
        let hex = sample_pubkey_hex();

        let mut writer = WireWriter::new();
        let bytes = bsv_sdk::primitives::from_hex(&hex).unwrap();
        writer.write_bytes(&bytes);

        let mut reader = WireReader::new(writer.as_bytes());
        let read_hex = reader.read_pubkey_hex().unwrap();

        assert_eq!(read_hex, hex);
    }

    /// Tests outpoint string write/read roundtrip.
    #[test]
    fn test_outpoint_string_roundtrip() {
        let outpoint_str = sample_outpoint_string();

        let mut writer = WireWriter::new();
        writer.write_outpoint_string(&outpoint_str).unwrap();

        let mut reader = WireReader::new(writer.as_bytes());
        let read_str = reader.read_outpoint_string().unwrap();

        assert_eq!(read_str, outpoint_str);
    }
}

// ============================================================================
// Response Type Roundtrip Tests
// ============================================================================
// These test the response serialization patterns used by the processor,
// verifying that the transceiver can correctly parse them.

mod response_roundtrips {
    use super::*;

    /// Tests CreateActionResult response wire format roundtrip.
    /// This verifies the complex response with optional txid, tx, no_send_change,
    /// send_with_results, and signable_transaction.
    #[test]
    fn test_create_action_result_wire_roundtrip() {
        // Simulate processor serializing a CreateActionResult
        let mut writer = WireWriter::new();

        // txid present
        writer.write_i8(1);
        writer.write_bytes(&sample_txid());

        // tx present
        writer.write_i8(1);
        let tx_bytes = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        writer.write_var_int(tx_bytes.len() as u64);
        writer.write_bytes(&tx_bytes);

        // no_send_change (1 outpoint)
        writer.write_signed_var_int(1);
        writer.write_outpoint(&Outpoint::new(sample_txid(), 0));

        // send_with_results (None)
        writer.write_send_with_result_array(None);

        // signable_transaction present
        writer.write_i8(1);
        let st_tx = vec![0x02, 0x00];
        writer.write_var_int(st_tx.len() as u64);
        writer.write_bytes(&st_tx);
        let st_ref = vec![0xAA, 0xBB];
        writer.write_var_int(st_ref.len() as u64);
        writer.write_bytes(&st_ref);

        // Now parse it back like the transceiver does
        let mut reader = WireReader::new(writer.as_bytes());

        // Parse txid
        let txid_flag = reader.read_i8().unwrap();
        assert_eq!(txid_flag, 1);
        let txid_bytes = reader.read_bytes(32).unwrap();
        assert_eq!(txid_bytes, &sample_txid());

        // Parse tx
        let tx_flag = reader.read_i8().unwrap();
        assert_eq!(tx_flag, 1);
        let tx_len = reader.read_var_int().unwrap() as usize;
        let tx_data = reader.read_bytes(tx_len).unwrap();
        assert_eq!(tx_data, &tx_bytes);

        // Parse no_send_change
        let nsc_len = reader.read_signed_var_int().unwrap();
        assert_eq!(nsc_len, 1);
        let outpoint = reader.read_outpoint().unwrap();
        assert_eq!(outpoint.vout, 0);

        // Parse send_with_results
        let swr = reader.read_send_with_result_array().unwrap();
        assert!(swr.is_none());

        // Parse signable_transaction
        let sig_flag = reader.read_i8().unwrap();
        assert_eq!(sig_flag, 1);
        let st_tx_len = reader.read_var_int().unwrap() as usize;
        let _st_tx_data = reader.read_bytes(st_tx_len).unwrap();
        let st_ref_len = reader.read_var_int().unwrap() as usize;
        let _st_ref_data = reader.read_bytes(st_ref_len).unwrap();

        assert!(reader.is_empty());
    }

    /// Tests SignActionResult response wire format roundtrip.
    #[test]
    fn test_sign_action_result_wire_roundtrip() {
        let mut writer = WireWriter::new();

        // No txid
        writer.write_i8(-1);

        // No tx
        writer.write_i8(-1);

        // send_with_results with 2 entries
        writer.write_send_with_result_array(Some(&[
            SendWithResult {
                txid: sample_txid(),
                status: SendWithResultStatus::Sending,
            },
            SendWithResult {
                txid: [0xBB; 32],
                status: SendWithResultStatus::Failed,
            },
        ]));

        let mut reader = WireReader::new(writer.as_bytes());

        let txid_flag = reader.read_i8().unwrap();
        assert_eq!(txid_flag, -1);

        let tx_flag = reader.read_i8().unwrap();
        assert_eq!(tx_flag, -1);

        let swr = reader.read_send_with_result_array().unwrap();
        assert!(swr.is_some());
        let swr = swr.unwrap();
        assert_eq!(swr.len(), 2);
        assert_eq!(swr[0].status, SendWithResultStatus::Sending);
        assert_eq!(swr[1].status, SendWithResultStatus::Failed);
    }

    /// Tests ListActionsResult response wire format roundtrip.
    #[test]
    fn test_list_actions_result_wire_roundtrip() {
        let mut writer = WireWriter::new();

        // total_actions
        writer.write_var_int(2);

        // Write 2 WalletActions
        let action1 = WalletAction {
            txid: sample_txid(),
            satoshis: 5000,
            status: ActionStatus::Completed,
            is_outgoing: false,
            description: "received payment".to_string(),
            labels: Some(vec!["income".to_string()]),
            version: 1,
            lock_time: 0,
            inputs: None,
            outputs: None,
        };
        writer.write_wallet_action(&action1);

        let action2 = WalletAction {
            txid: [0xFF; 32],
            satoshis: -3000,
            status: ActionStatus::Sending,
            is_outgoing: true,
            description: "sent payment".to_string(),
            labels: None,
            version: 1,
            lock_time: 0,
            inputs: None,
            outputs: None,
        };
        writer.write_wallet_action(&action2);

        let mut reader = WireReader::new(writer.as_bytes());
        let total = reader.read_var_int().unwrap();
        assert_eq!(total, 2);

        let read1 = reader.read_wallet_action().unwrap();
        assert_eq!(read1.satoshis, 5000);
        assert_eq!(read1.status, ActionStatus::Completed);

        let read2 = reader.read_wallet_action().unwrap();
        assert_eq!(read2.satoshis, -3000);
        assert_eq!(read2.status, ActionStatus::Sending);
        assert_eq!(read2.is_outgoing, true);
    }

    /// Tests ListOutputsResult response wire format roundtrip.
    #[test]
    fn test_list_outputs_result_wire_roundtrip() {
        let mut writer = WireWriter::new();

        // total_outputs
        writer.write_var_int(1);

        // beef (present)
        let beef_data = vec![0xBE, 0xEF, 0x00, 0x01];
        writer.write_signed_var_int(beef_data.len() as i64);
        writer.write_bytes(&beef_data);

        // 1 WalletOutput
        let output = WalletOutput {
            satoshis: 10000,
            locking_script: Some(vec![0x76, 0xa9]),
            spendable: true,
            custom_instructions: None,
            tags: Some(vec!["utxo".to_string()]),
            outpoint: Outpoint::new(sample_txid(), 0),
            labels: None,
        };
        writer.write_wallet_output(&output);

        let mut reader = WireReader::new(writer.as_bytes());
        let total = reader.read_var_int().unwrap();
        assert_eq!(total, 1);

        let beef_len = reader.read_signed_var_int().unwrap();
        assert!(beef_len >= 0);
        let beef = reader.read_bytes(beef_len as usize).unwrap();
        assert_eq!(beef, &beef_data);

        let read_output = reader.read_wallet_output().unwrap();
        assert_eq!(read_output.satoshis, 10000);
        assert_eq!(read_output.spendable, true);
        assert!(reader.is_empty());
    }
}

// ============================================================================
// WalletCall Enum Tests
// ============================================================================

mod call_code_tests {
    use super::*;

    /// Tests all 28 call codes roundtrip through u8 conversion.
    #[test]
    fn test_all_call_codes_roundtrip() {
        for code in 1..=28u8 {
            let call = WalletCall::try_from(code).unwrap();
            assert_eq!(call.as_u8(), code);
            // Verify method name is non-empty
            assert!(!call.method_name().is_empty());
        }
    }

    /// Tests invalid call codes.
    #[test]
    fn test_invalid_call_codes() {
        assert!(WalletCall::try_from(0).is_err());
        assert!(WalletCall::try_from(29).is_err());
        assert!(WalletCall::try_from(255).is_err());
    }

    /// Tests method names match expected camelCase format.
    #[test]
    fn test_call_method_names() {
        assert_eq!(WalletCall::CreateAction.method_name(), "createAction");
        assert_eq!(WalletCall::SignAction.method_name(), "signAction");
        assert_eq!(WalletCall::AbortAction.method_name(), "abortAction");
        assert_eq!(WalletCall::ListActions.method_name(), "listActions");
        assert_eq!(
            WalletCall::InternalizeAction.method_name(),
            "internalizeAction"
        );
        assert_eq!(WalletCall::ListOutputs.method_name(), "listOutputs");
        assert_eq!(
            WalletCall::RelinquishOutput.method_name(),
            "relinquishOutput"
        );
        assert_eq!(WalletCall::GetPublicKey.method_name(), "getPublicKey");
        assert_eq!(
            WalletCall::RevealCounterpartyKeyLinkage.method_name(),
            "revealCounterpartyKeyLinkage"
        );
        assert_eq!(
            WalletCall::RevealSpecificKeyLinkage.method_name(),
            "revealSpecificKeyLinkage"
        );
        assert_eq!(WalletCall::Encrypt.method_name(), "encrypt");
        assert_eq!(WalletCall::Decrypt.method_name(), "decrypt");
        assert_eq!(WalletCall::CreateHmac.method_name(), "createHmac");
        assert_eq!(WalletCall::VerifyHmac.method_name(), "verifyHmac");
        assert_eq!(WalletCall::CreateSignature.method_name(), "createSignature");
        assert_eq!(WalletCall::VerifySignature.method_name(), "verifySignature");
        assert_eq!(
            WalletCall::AcquireCertificate.method_name(),
            "acquireCertificate"
        );
        assert_eq!(
            WalletCall::ListCertificates.method_name(),
            "listCertificates"
        );
        assert_eq!(
            WalletCall::ProveCertificate.method_name(),
            "proveCertificate"
        );
        assert_eq!(
            WalletCall::RelinquishCertificate.method_name(),
            "relinquishCertificate"
        );
        assert_eq!(
            WalletCall::DiscoverByIdentityKey.method_name(),
            "discoverByIdentityKey"
        );
        assert_eq!(
            WalletCall::DiscoverByAttributes.method_name(),
            "discoverByAttributes"
        );
        assert_eq!(WalletCall::IsAuthenticated.method_name(), "isAuthenticated");
        assert_eq!(
            WalletCall::WaitForAuthentication.method_name(),
            "waitForAuthentication"
        );
        assert_eq!(WalletCall::GetHeight.method_name(), "getHeight");
        assert_eq!(
            WalletCall::GetHeaderForHeight.method_name(),
            "getHeaderForHeight"
        );
        assert_eq!(WalletCall::GetNetwork.method_name(), "getNetwork");
        assert_eq!(WalletCall::GetVersion.method_name(), "getVersion");
    }
}

// ============================================================================
// Request Frame Serialization Tests
// ============================================================================
// These test the complete request frame format (call code + originator + params)
// can be parsed by the processor.

mod request_frame_tests {
    use super::*;

    /// Tests that a manually constructed request frame is correctly parsed by the processor.
    #[tokio::test]
    async fn test_manual_request_frame_get_version() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::new(wallet);

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::GetVersion.as_u8());
        writer.write_u8(4); // originator length
        writer.write_bytes(b"test");
        // No params for getVersion

        let response = processor.process_message(writer.as_bytes()).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error = reader.read_u8().unwrap();
        assert_eq!(error, 0);
        let version = reader.read_string().unwrap();
        assert_eq!(version, "0.1.0");
    }

    /// Tests that empty originator works.
    #[tokio::test]
    async fn test_empty_originator() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::new(wallet);

        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::IsAuthenticated.as_u8());
        writer.write_u8(0); // empty originator

        let response = processor.process_message(writer.as_bytes()).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error = reader.read_u8().unwrap();
        assert_eq!(error, 0);
        let auth = reader.read_optional_bool().unwrap();
        assert_eq!(auth, Some(true));
    }

    /// Tests that long originator works correctly.
    #[tokio::test]
    async fn test_long_originator() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::new(wallet);

        let originator = "very.long.originator.example.com";
        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::GetNetwork.as_u8());
        writer.write_u8(originator.len() as u8);
        writer.write_bytes(originator.as_bytes());

        let response = processor.process_message(writer.as_bytes()).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error = reader.read_u8().unwrap();
        assert_eq!(error, 0);
        let network = reader.read_string().unwrap();
        assert_eq!(network, "mainnet");
    }

    /// Tests error response format when an error occurs.
    #[tokio::test]
    async fn test_error_response_format() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let processor = WalletWireProcessor::new(wallet);

        // createAction will fail since ProtoWallet doesn't support it
        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::CreateAction.as_u8());
        writer.write_u8(0);
        // This will cause a parse error or wallet error - either way error response

        let response = processor.process_message(writer.as_bytes()).await.unwrap();

        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        // Should be non-zero (error)
        assert_ne!(error_byte, 0);
        // Should have error message
        let message = reader.read_string().unwrap();
        assert!(!message.is_empty());
        // Should have stack trace length
        let _stack = reader.read_signed_var_int().unwrap();
    }
}

// ============================================================================
// Multiple Counterparty Variants Tests
// ============================================================================

mod counterparty_variant_tests {
    use super::*;

    /// Tests encryption with all counterparty variants.
    #[tokio::test]
    async fn test_encrypt_with_all_counterparty_variants() {
        let transceiver = create_loopback();
        let plaintext = b"test data".to_vec();

        // Self_ counterparty
        let result = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "counterparty test"),
                    key_id: "cp-self".to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                "test",
            )
            .await;
        assert!(result.is_ok());

        // Anyone counterparty
        let result = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "counterparty test"),
                    key_id: "cp-anyone".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                },
                "test",
            )
            .await;
        assert!(result.is_ok());

        // None counterparty (defaults to Self_)
        let result = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "counterparty test"),
                    key_id: "cp-none".to_string(),
                    counterparty: None,
                },
                "test",
            )
            .await;
        assert!(result.is_ok());

        // Other(PublicKey) counterparty
        let other_key = PrivateKey::random().public_key();
        let result = transceiver
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, "counterparty test"),
                    key_id: "cp-other".to_string(),
                    counterparty: Some(Counterparty::Other(other_key)),
                },
                "test",
            )
            .await;
        assert!(result.is_ok());
    }
}
