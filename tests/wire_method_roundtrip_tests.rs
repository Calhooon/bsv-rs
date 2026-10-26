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

use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::wire::{WireReader, WireWriter};
use bsv_rs::wallet::{
    AbortActionArgs, AcquireCertificateArgs, AcquisitionProtocol, ActionStatus, BasketInsertion,
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, EncryptArgs, GetHeaderArgs, GetPublicKeyArgs, IdentityCertifier,
    InternalizeActionArgs, InternalizeOutput, ListActionsArgs, ListCertificatesArgs,
    ListOutputsArgs, Network, Outpoint, OutputInclude, ProtoWallet, Protocol, ProveCertificateArgs,
    QueryMode, RelinquishCertificateArgs, RelinquishOutputArgs, SecurityLevel, SendWithResult,
    SendWithResultStatus, SignActionArgs, SignActionSpend, TrustSelf, VerifyHmacArgs,
    VerifySignatureArgs, WalletAction, WalletActionInput, WalletActionOutput, WalletCertificate,
    WalletInterface, WalletOutput, WalletPayment,
};
use bsv_rs::Error;
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
    bsv_rs::primitives::to_hex(&pk.public_key().to_compressed())
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
    format!("{}.0", bsv_rs::primitives::to_hex(&txid))
}

/// Helper to create a sample WalletCertificate.
fn sample_wallet_certificate() -> WalletCertificate {
    // certificate_type and serial_number must be valid base64 encoding of 32 bytes
    use bsv_rs::primitives::to_base64;
    WalletCertificate {
        certificate_type: to_base64(&[0xaa; 32]),
        subject: sample_pubkey_hex(),
        serial_number: to_base64(&[0xbb; 32]),
        certifier: sample_pubkey_hex(),
        revocation_outpoint: sample_outpoint_string(),
        signature: "3006020101020101".to_string(),
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();

        // A DER signature: it parses, re-encodes to the same bytes and is 8 to
        // 72 bytes long (`r` and `s` are 1 to 33 bytes each); a fixed lower
        // bound fails on a key whose `r` or `s` has leading zero bytes (#16).
        assert!(!sig_result.signature.is_empty());
        let parsed = bsv_rs::primitives::Signature::from_der(&sig_result.signature)
            .expect("a DER signature");
        assert_eq!(parsed.to_der(), sig_result.signature);
        assert!((8..=72).contains(&sig_result.signature.len()));

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
                    ..Default::default()
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
        let hash = bsv_rs::primitives::sha256(b"pre-hashed data");

        let sig_result = transceiver
            .create_signature(
                CreateSignatureArgs {
                    data: None,
                    hash_to_directly_sign: Some(hash),
                    protocol_id: Protocol::new(SecurityLevel::App, "direct hash signature"),
                    key_id: "sig-hash-1".to_string(),
                    counterparty: None,
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
                },
                "test",
            )
            .await;

        // Should either return valid=false or an error
        if let Ok(res) = verify_result {
            assert!(!res.valid);
        }
        // Error is also acceptable (invalid signature)
    }
}

/// #199: the frames the hmac and signature roundtrips carry are the
/// reference's: verifyHmac's 32 raw HMAC bytes ahead of the data
/// (`ts-stack@edf6e03` `WalletWireTransceiver.ts:1048-1050`), the signature
/// calls' data-type flag, `01` then the data behind its length or `02` then
/// the 32 bytes of the hash (`:1082-1090`, `:1137-1144`), verifySignature's
/// signature ahead of the flag (`:1135-1136`). This crate writes no privileged
/// pair or seekPermission yet (#193), so each frame ends with these bytes.
mod reference_request_frames {
    use super::*;
    use std::sync::Mutex;

    /// A loopback that keeps the last request it carried.
    struct RecordingLoopback {
        inner: LoopbackWire,
        sent: Mutex<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl WalletWire for RecordingLoopback {
        async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            *self
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = message.to_vec();
            self.inner.transmit_to_wallet(message).await
        }
    }

    fn recording_loopback() -> WalletWireTransceiver<RecordingLoopback> {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let inner = LoopbackWire {
            processor: Arc::new(WalletWireProcessor::new(wallet)),
        };
        WalletWireTransceiver::new(RecordingLoopback {
            inner,
            sent: Mutex::new(Vec::new()),
        })
    }

    fn last_request(client: &WalletWireTransceiver<RecordingLoopback>) -> Vec<u8> {
        client
            .wire()
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn protocol() -> Protocol {
        Protocol::new(SecurityLevel::App, "request frames")
    }

    #[tokio::test]
    async fn verify_hmac_carries_the_raw_hmac_ahead_of_the_data() {
        let client = recording_loopback();
        let data = b"hmac frame".to_vec();
        let hmac = client
            .create_hmac(
                CreateHmacArgs {
                    data: data.clone(),
                    protocol_id: protocol(),
                    key_id: "k".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "",
            )
            .await
            .unwrap()
            .hmac;
        let result = client
            .verify_hmac(
                VerifyHmacArgs {
                    data: data.clone(),
                    hmac,
                    protocol_id: protocol(),
                    key_id: "k".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "",
            )
            .await
            .unwrap();
        assert!(result.valid);
        // seekPermission absent (`ff`) last (#193)
        let tail = [&hmac[..], &[data.len() as u8], &data, &[0xff]].concat();
        assert!(last_request(&client).ends_with(&tail));
    }

    #[tokio::test]
    async fn the_signature_calls_carry_the_data_type_flag_in_both_forms() {
        let client = recording_loopback();
        let data = b"signature frame".to_vec();
        let hash = bsv_rs::primitives::sha256(&data);
        // Flag 1 and flag 2 sign the same digest: SHA-256 of the data.
        for (sign_data, sign_hash, flag_tail) in [
            (
                Some(data.clone()),
                None,
                [&[1u8, data.len() as u8][..], &data].concat(),
            ),
            (None, Some(hash), [&[2u8][..], &hash].concat()),
        ] {
            let signature = client
                .create_signature(
                    CreateSignatureArgs {
                        data: sign_data.clone(),
                        hash_to_directly_sign: sign_hash,
                        protocol_id: protocol(),
                        key_id: "k".to_string(),
                        counterparty: None,
                        ..Default::default()
                    },
                    "",
                )
                .await
                .unwrap()
                .signature;
            // seekPermission absent (`ff`) last (#193)
            assert!(last_request(&client).ends_with(&[&flag_tail[..], &[0xff]].concat()));

            let result = client
                .verify_signature(
                    VerifySignatureArgs {
                        data: sign_data,
                        hash_to_directly_verify: sign_hash,
                        signature: signature.clone(),
                        protocol_id: protocol(),
                        key_id: "k".to_string(),
                        counterparty: Some(Counterparty::Anyone),
                        for_self: Some(true),
                        ..Default::default()
                    },
                    "",
                )
                .await
                .unwrap();
            assert!(result.valid);
            let tail = [
                &[signature.len() as u8][..],
                &signature,
                &flag_tail,
                &[0xff],
            ]
            .concat();
            assert!(last_request(&client).ends_with(&tail));
        }
    }

    /// The reference refuses both or neither of the data and the hash before
    /// it writes (`validationHelpers.ts:1777-1787`); so does this transceiver,
    /// nothing sent.
    #[tokio::test]
    async fn the_signature_calls_refuse_both_or_neither_of_the_data_and_the_hash() {
        let client = recording_loopback();
        for (data, hash) in [(Some(vec![1]), Some([0u8; 32])), (None, None)] {
            let signed = client
                .create_signature(
                    CreateSignatureArgs {
                        data: data.clone(),
                        hash_to_directly_sign: hash,
                        protocol_id: protocol(),
                        key_id: "k".to_string(),
                        counterparty: None,
                        ..Default::default()
                    },
                    "",
                )
                .await;
            assert_eq!(
                signed.unwrap_err(),
                Error::WalletError(
                    "The data, hashToDirectlySign parameter must be exactly one value".into()
                )
            );
            let verified = client
                .verify_signature(
                    VerifySignatureArgs {
                        data,
                        hash_to_directly_verify: hash,
                        signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
                        protocol_id: protocol(),
                        key_id: "k".to_string(),
                        counterparty: None,
                        for_self: None,
                        ..Default::default()
                    },
                    "",
                )
                .await;
            assert_eq!(
                verified.unwrap_err(),
                Error::WalletError(
                    "The data, hashToDirectlyVerify parameter must be exactly one value".into()
                )
            );
        }
        assert!(last_request(&client).is_empty());
    }
}

// =============================================================================
// The seven key-related calls with their permission fields (#193)
// =============================================================================

mod permission_field_tests {
    use super::*;

    /// The three fields set, each the value the reference's default is not.
    fn privileged<T>(mut args: T, set: impl FnOnce(&mut T)) -> T {
        set(&mut args);
        args
    }

    macro_rules! with_fields {
        ($args:expr) => {
            privileged($args, |a| {
                a.privileged = Some(true);
                a.privileged_reason = Some("roundtrip reason".to_string());
                a.seek_permission = Some(false);
            })
        };
    }

    fn protocol() -> Protocol {
        Protocol::new(SecurityLevel::App, "permission fields")
    }

    /// #193: each of the seven calls crosses the wire with the privileged
    /// pair and seekPermission present and absent, and the ProtoWallet,
    /// which reads neither (as the reference's ProtoWallet does not), answers
    /// both alike: a field the processor misread would shift every byte after
    /// it, as the privileged flag once became the plaintext's length.
    #[tokio::test]
    async fn the_seven_key_related_calls_roundtrip_with_and_without_the_permission_fields() {
        let client = create_loopback();
        let key = |for_self| GetPublicKeyArgs {
            protocol_id: Some(protocol()),
            key_id: Some("k".to_string()),
            for_self,
            ..Default::default()
        };
        let identity = GetPublicKeyArgs {
            identity_key: true,
            ..Default::default()
        };
        for args in [key(Some(true)), identity] {
            let plain = client.get_public_key(args.clone(), "").await.unwrap();
            let with = client.get_public_key(with_fields!(args), "").await.unwrap();
            assert_eq!(plain.public_key, with.public_key);
        }

        let data = b"permission fields".to_vec();
        let encrypt = EncryptArgs {
            plaintext: data.clone(),
            protocol_id: protocol(),
            key_id: "k".to_string(),
            ..Default::default()
        };
        for args in [encrypt.clone(), with_fields!(encrypt)] {
            let ciphertext = client.encrypt(args, "").await.unwrap().ciphertext;
            let decrypt = DecryptArgs {
                ciphertext,
                protocol_id: protocol(),
                key_id: "k".to_string(),
                ..Default::default()
            };
            for args in [decrypt.clone(), with_fields!(decrypt)] {
                assert_eq!(client.decrypt(args, "").await.unwrap().plaintext, data);
            }
        }

        let hmac_args = CreateHmacArgs {
            data: data.clone(),
            protocol_id: protocol(),
            key_id: "k".to_string(),
            ..Default::default()
        };
        let hmac = client
            .create_hmac(hmac_args.clone(), "")
            .await
            .unwrap()
            .hmac;
        let with = client
            .create_hmac(with_fields!(hmac_args), "")
            .await
            .unwrap();
        assert_eq!(hmac, with.hmac);
        let verify = VerifyHmacArgs {
            data: data.clone(),
            hmac,
            protocol_id: protocol(),
            key_id: "k".to_string(),
            ..Default::default()
        };
        for args in [verify.clone(), with_fields!(verify)] {
            assert!(client.verify_hmac(args, "").await.unwrap().valid);
        }

        let sign = CreateSignatureArgs {
            data: Some(data.clone()),
            protocol_id: protocol(),
            key_id: "k".to_string(),
            ..Default::default()
        };
        let signature = client.create_signature(sign.clone(), "").await.unwrap();
        let with = client
            .create_signature(with_fields!(sign), "")
            .await
            .unwrap();
        assert_eq!(signature.signature, with.signature);
        let verify = VerifySignatureArgs {
            data: Some(data),
            signature: signature.signature,
            protocol_id: protocol(),
            key_id: "k".to_string(),
            counterparty: Some(Counterparty::Anyone),
            for_self: Some(true),
            ..Default::default()
        };
        for args in [verify.clone(), with_fields!(verify)] {
            assert!(client.verify_signature(args, "").await.unwrap().valid);
        }
    }

    /// A privileged reason the frame cannot carry (past 127 bytes, an `i8`
    /// length) is refused before a byte is sent.
    #[tokio::test]
    async fn a_privileged_reason_past_127_bytes_is_refused_before_it_is_sent() {
        let client = create_loopback();
        let error = client
            .encrypt(
                EncryptArgs {
                    plaintext: vec![1],
                    protocol_id: protocol(),
                    key_id: "k".to_string(),
                    privileged_reason: Some("r".repeat(128)),
                    ..Default::default()
                },
                "",
            )
            .await
            .unwrap_err();
        assert_eq!(
            error,
            Error::WalletError(
                "Invalid privilegedReason length: expected 0 to 127 bytes, got 128".to_string()
            )
        );
    }
}

mod key_linkage_tests {
    use super::*;

    /// Tests revealCounterpartyKeyLinkage roundtrip.
    /// This exercises the complex response type with encrypted linkage, proof, and public keys.
    #[tokio::test]
    async fn test_roundtrip_reveal_counterparty_key_linkage_privileged() {
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
        // Privileged flag and reason ahead of the keys, as the reference
        // writes them (`WalletWireTransceiver.ts:809-811`; #191)
        writer.write_optional_bool(Some(true));
        writer.write_i8(11);
        writer.write_bytes(b"test-reason");
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

        // Parse response in the reference's order (`WalletWireTransceiver.ts:818-836`;
        // #194): prover(33), verifier(33), counterparty(33), revelation_time(string),
        // encrypted_linkage_len + bytes, encrypted_proof_len + bytes
        let prover_bytes = reader.read_bytes(33).unwrap();
        let verifier_bytes = reader.read_bytes(33).unwrap();
        let counterparty_bytes = reader.read_bytes(33).unwrap();
        let revelation_time = reader.read_string().unwrap();
        let linkage_len = reader.read_var_int().unwrap() as usize;
        let linkage = reader.read_bytes(linkage_len).unwrap();
        let proof_len = reader.read_var_int().unwrap() as usize;
        let _proof = reader.read_bytes(proof_len).unwrap();
        assert_eq!(reader.remaining(), 0, "the response is read to its end");

        // Verify the prover key is valid
        let _prover = PublicKey::from_bytes(prover_bytes).unwrap();
        // The verifier and the counterparty are the request's
        assert_eq!(verifier_bytes, verifier_key.to_compressed());
        assert_eq!(counterparty_bytes, bob.identity_key().to_compressed());
        // Revelation time should be a non-empty ISO timestamp
        assert!(!revelation_time.is_empty());
        assert!(!linkage.is_empty());
    }

    /// The reason's length is an `i8`, -1 absent or 0 to 127; another negative
    /// length is refused, as the reference's `#readOptionalInt8Length` refuses
    /// it (`WalletWireProcessor.ts:54-61`; #191).
    #[tokio::test]
    async fn a_linkage_privileged_reason_length_below_minus_one_is_refused() {
        let processor = WalletWireProcessor::new(ProtoWallet::new(Some(PrivateKey::random())));
        let key = PrivateKey::random().public_key().to_compressed();
        let mut writer = WireWriter::new();
        writer.write_u8(WalletCall::RevealCounterpartyKeyLinkage.as_u8());
        writer.write_u8(0);
        writer.write_optional_bool(Some(true));
        writer.write_i8(-2);
        writer.write_bytes(&key).write_bytes(&key);
        let response = processor.process_message(writer.as_bytes()).await.unwrap();
        assert_ne!(response[0], 0, "an error frame");
        let message = WireReader::new(&response[1..]).read_string().unwrap();
        assert!(message.contains("privilegedReason length"), "{message}");
    }

    /// Tests revealSpecificKeyLinkage roundtrip.
    #[tokio::test]
    async fn test_roundtrip_reveal_specific_key_linkage_privileged() {
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
        // The key-related parameters, then the verifier, as the reference
        // writes them (`WalletWireTransceiver.ts:874-883`; #191)
        writer.write_u8(SecurityLevel::App.as_u8());
        writer.write_string("linkage test app");
        writer.write_string("link-key-1");
        writer.write_bytes(&bob_pub.to_compressed());
        writer.write_optional_bool(Some(false));
        writer.write_i8(-1);
        writer.write_bytes(&verifier_key.to_compressed());

        let response = processor.process_message(writer.as_bytes()).await.unwrap();
        let mut reader = WireReader::new(&response);
        let error_byte = reader.read_u8().unwrap();
        assert_eq!(error_byte, 0, "expected success for specific key linkage");

        // Parse response in the reference's order (`WalletWireTransceiver.ts:890-908`;
        // #194): the three keys, the protocol, the key ID, the linkage, the proof,
        // the proof type
        let _prover = reader.read_bytes(33).unwrap();
        let verifier = reader.read_bytes(33).unwrap();
        let counterparty = reader.read_bytes(33).unwrap();
        let protocol = reader.read_protocol_id().unwrap();
        let key_id = reader.read_string().unwrap();
        let linkage_len = reader.read_var_int().unwrap() as usize;
        let linkage = reader.read_bytes(linkage_len).unwrap();
        let proof_len = reader.read_var_int().unwrap() as usize;
        let _proof = reader.read_bytes(proof_len).unwrap();
        let proof_type = reader.read_u8().unwrap();
        assert_eq!(reader.remaining(), 0, "the response is read to its end");

        assert_eq!(verifier, verifier_key.to_compressed());
        assert_eq!(counterparty, bob_pub.to_compressed());
        assert!(!linkage.is_empty());
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

    /// Tests getHeight roundtrip: ProtoWallet answers 0, a height the
    /// reference's result check refuses (`WalletResultValidation.ts:2293-2295`,
    /// bsv-rs#216), so the client reads the processor's refusal.
    #[tokio::test]
    async fn test_roundtrip_get_height() {
        let transceiver = create_loopback();
        let error = transceiver.get_height("test").await.unwrap_err();
        assert_eq!(
            error,
            Error::WalletError(
                "wallet error (code 1): Invalid getHeight result height: expected an integer from 1 to 4294967295"
                    .into()
            )
        );
    }

    /// Tests getNetwork roundtrip (the wallet's answer, ProtoWallet's mainnet; #222).
    #[tokio::test]
    async fn test_roundtrip_get_network_mainnet() {
        let transceiver = create_loopback();
        let result = transceiver.get_network("test").await.unwrap();
        assert_eq!(result, Network::Mainnet);
    }

    /// getNetwork answers the wallet's own `get_network`, byte for byte (#222).
    #[tokio::test]
    async fn test_roundtrip_get_network_is_the_wallets_answer() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let expected = wallet.get_network("test").await.unwrap().network;
        let processor = Arc::new(WalletWireProcessor::new(wallet));
        let wire = LoopbackWire { processor };
        let transceiver = WalletWireTransceiver::new(wire);
        let result = transceiver.get_network("test").await.unwrap();
        assert_eq!(result, expected);
    }

    /// Tests getVersion roundtrip (the wallet's answer; #222).
    #[tokio::test]
    async fn test_roundtrip_get_version() {
        let transceiver = create_loopback();
        let result = transceiver.get_version("test").await.unwrap();
        assert_eq!(result, concat!("bsv-rs-", env!("CARGO_PKG_VERSION")));
    }

    /// getVersion answers the wallet's own `get_version`, byte for byte (#222).
    #[tokio::test]
    async fn test_roundtrip_get_version_is_the_wallets_answer() {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let expected = wallet.get_version("test").await.unwrap().version;
        let processor = Arc::new(WalletWireProcessor::new(wallet));
        let wire = LoopbackWire { processor };
        let transceiver = WalletWireTransceiver::new(wire);
        let result = transceiver.get_version("test").await.unwrap();
        assert_eq!(result, expected);
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
        assert!(
            matches!(result, Err(Error::WalletError(_))),
            "expected WalletError, got {:?}",
            result
        );
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
        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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
                    reference: bsv_rs::primitives::to_base64(&[0x01, 0x02, 0x03]),
                    options: Some(bsv_rs::wallet::SignActionOptions {
                        accept_delayed_broadcast: Some(true),
                        return_txid_only: Some(false),
                        no_send: Some(true),
                        send_with: Some(vec![sample_txid()]),
                    }),
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_)))); // ProtoWallet doesn't support signAction
    }

    /// Tests abortAction request serialization.
    #[tokio::test]
    async fn test_roundtrip_abort_action() {
        let transceiver = create_loopback();
        let result = transceiver
            .abort_action(
                AbortActionArgs {
                    reference: bsv_rs::primitives::to_base64(&[0xAA, 0xBB, 0xCC]),
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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
                            derivation_prefix: bsv_rs::primitives::to_base64(b"prefix"),
                            derivation_suffix: bsv_rs::primitives::to_base64(b"suffix"),
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
        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_)))); // ProtoWallet doesn't support listOutputs
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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
                    certificate_type: bsv_rs::primitives::to_base64(&[0u8; 32]),
                    certifier: bsv_rs::primitives::to_hex(&certifier_key.to_compressed()),
                    acquisition_protocol: AcquisitionProtocol::Direct,
                    fields: {
                        let mut m = HashMap::new();
                        m.insert("name".to_string(), "Test User".to_string());
                        m
                    },
                    serial_number: Some(bsv_rs::primitives::to_base64(&[1u8; 32])),
                    revocation_outpoint: Some(sample_outpoint_string()),
                    signature: Some(bsv_rs::primitives::to_hex(&[0x30, 0x44, 0x02, 0x20])),
                    certifier_url: None,
                    keyring_revealer: None, // defaults to certifier
                    keyring_for_subject: Some({
                        let mut m = HashMap::new();
                        m.insert(
                            "name".to_string(),
                            bsv_rs::primitives::to_base64(b"key-for-name"),
                        );
                        m
                    }),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_)))); // ProtoWallet doesn't support acquireCertificate
    }

    /// Tests acquireCertificate with issuance protocol.
    #[tokio::test]
    async fn test_roundtrip_acquire_certificate_issuance() {
        let transceiver = create_loopback();
        let certifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .acquire_certificate(
                AcquireCertificateArgs {
                    certificate_type: bsv_rs::primitives::to_base64(&[0xFFu8; 32]),
                    certifier: bsv_rs::primitives::to_hex(&certifier_key.to_compressed()),
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

        assert!(matches!(result, Err(Error::WalletError(_))));
    }

    /// Tests listCertificates request serialization.
    #[tokio::test]
    async fn test_roundtrip_list_certificates() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_certificates(
                ListCertificatesArgs {
                    certifiers: vec![sample_pubkey_hex()],
                    types: vec![bsv_rs::primitives::to_base64(&[0u8; 32])],
                    limit: Some(10),
                    offset: Some(0),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_))));
    }

    /// Tests listCertificates with minimal args.
    #[tokio::test]
    async fn test_roundtrip_list_certificates_minimal() {
        let transceiver = create_loopback();
        let result = transceiver
            .list_certificates(
                ListCertificatesArgs {
                    certifiers: vec![sample_pubkey_hex()],
                    types: vec![bsv_rs::primitives::to_base64(&[0u8; 32])],
                    limit: None,
                    offset: None,
                    privileged: None,
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_))));
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
                    verifier: bsv_rs::primitives::to_hex(&verifier_key.to_compressed()),
                    privileged: Some(false),
                    privileged_reason: None,
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_))));
    }

    /// Tests relinquishCertificate request serialization.
    #[tokio::test]
    async fn test_roundtrip_relinquish_certificate() {
        let transceiver = create_loopback();
        let certifier_key = PrivateKey::random().public_key();
        let result = transceiver
            .relinquish_certificate(
                RelinquishCertificateArgs {
                    certificate_type: bsv_rs::primitives::to_base64(&[0u8; 32]),
                    serial_number: bsv_rs::primitives::to_base64(&[1u8; 32]),
                    certifier: bsv_rs::primitives::to_hex(&certifier_key.to_compressed()),
                },
                "test",
            )
            .await;

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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

        assert!(matches!(result, Err(Error::WalletError(_))));
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
            icon_url: "https://example.com/icon.png".to_string(),
            description: "Official BSV certificate authority".to_string(),
            trust: 9,
        };

        let mut writer = WireWriter::new();
        writer.write_string(&certifier.name);
        writer.write_string(&certifier.icon_url);
        writer.write_string(&certifier.description);
        writer.write_u8(certifier.trust);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certifier().unwrap();

        assert_eq!(read.name, certifier.name);
        assert_eq!(read.icon_url, certifier.icon_url);
        assert_eq!(read.description, certifier.description);
        assert_eq!(read.trust, certifier.trust);
    }

    /// Tests the optional IdentityCertifier read of a minimal entry: the
    /// reference's layout has no present flag, an empty iconUrl or description
    /// is length 0 and reads as `""`, as the transceiver reads it (#184).
    #[test]
    fn test_optional_identity_certifier_minimal_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_string("Minimal");
        writer.write_string("");
        writer.write_string("");
        writer.write_u8(1);

        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_identity_certifier().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.name, "Minimal");
        assert_eq!(read.icon_url, "");
        assert_eq!(read.description, "");
        assert_eq!(read.trust, 1);
        assert_eq!(reader.remaining(), 0);
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
        assert!(read.spendable);
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
        assert!(read.is_outgoing);
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
        assert!(!read.is_outgoing);
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
        assert!(read.spendable);
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
        // Go wire format has no spendable field; defaults to true on read
        assert!(read.spendable);
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

        // Some case: a count and its pairs
        let mut writer = WireWriter::new();
        writer.write_string_map(&map);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_string_map().unwrap();
        assert!(read.is_some());
        assert_eq!(read.unwrap(), map);

        // None case: the NIL sentinel
        let mut writer = WireWriter::new();
        writer.write_var_int(u64::MAX);
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
        let hex = bsv_rs::primitives::to_hex(&txid);

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
        let bytes = bsv_rs::primitives::from_hex(&hex).unwrap();
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
        writer.write_signed_var_int("noSendChange", 1).unwrap();
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
        assert!(read2.is_outgoing);
    }

    /// Tests ListOutputsResult response wire format roundtrip.
    #[test]
    fn test_list_outputs_result_wire_roundtrip() {
        let mut writer = WireWriter::new();

        // total_outputs
        writer.write_var_int(1);

        // beef (present)
        let beef_data = vec![0xBE, 0xEF, 0x00, 0x01];
        writer
            .write_signed_var_int("beef", beef_data.len() as i64)
            .unwrap();
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
        assert!(read_output.spendable);
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
        assert!(matches!(
            WalletCall::try_from(0),
            Err(Error::WalletError(_))
        ));
        assert!(matches!(
            WalletCall::try_from(29),
            Err(Error::WalletError(_))
        ));
        assert!(matches!(
            WalletCall::try_from(255),
            Err(Error::WalletError(_))
        ));
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
        // Go wire format: raw UTF-8 bytes (no length prefix)
        let version = std::str::from_utf8(reader.read_remaining()).unwrap();
        assert_eq!(version, concat!("bsv-rs-", env!("CARGO_PKG_VERSION")));
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
        // Go wire format: single byte (0x00=mainnet, 0x01=testnet)
        let network_byte = reader.read_u8().unwrap();
        assert_eq!(network_byte, 0x00); // mainnet
    }

    /// Tests error response format when an error occurs: unknownError (1),
    /// the refusal's bare words, an empty stack (bsv-rs#202,
    /// `WalletWireProcessor.ts:2379-2396` at `ts-stack@edf6e03`).
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
        assert_eq!(reader.read_u8().unwrap(), 1);
        assert_eq!(
            reader.read_string().unwrap(),
            "createAction requires a full wallet implementation"
        );
        assert_eq!(reader.read_var_int().unwrap(), 0);
        assert_eq!(reader.remaining(), 0);
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
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
                    ..Default::default()
                },
                "test",
            )
            .await;
        assert!(result.is_ok());
    }
}

// ============================================================================
// Index bounds (bsv-rs#120): a varint index above u32::MAX is refused
// ============================================================================

mod index_bounds_tests {
    use super::*;

    /// Replaces the writer's 5-byte varint for `u32::MAX` at `at` with the
    /// writer's 9-byte varint for `u32::MAX + 1`, leaving every other byte.
    fn widen_index_past_u32(frame: &[u8], at: usize) -> Vec<u8> {
        let mut max = WireWriter::new();
        max.write_var_int(u32::MAX as u64);
        assert_eq!(&frame[at..at + 5], max.as_bytes());
        let mut over = WireWriter::new();
        over.write_var_int(u32::MAX as u64 + 1);
        let mut out = frame[..at].to_vec();
        out.extend_from_slice(over.as_bytes());
        out.extend_from_slice(&frame[at + 5..]);
        out
    }

    fn assert_index_refused(err: Error, field: &str) {
        assert_eq!(
            err,
            Error::WalletError(format!(
                "Invalid {}: expected an integer from 0 to 4294967295, received 4294967296",
                field
            ))
        );
    }

    #[test]
    fn an_outpoint_index_above_u32_max_is_refused_not_truncated() {
        let mut writer = WireWriter::new();
        writer.write_outpoint(&Outpoint::new([7u8; 32], u32::MAX));
        let frame = writer.into_bytes();

        let outpoint = WireReader::new(&frame).read_outpoint().unwrap();
        assert_eq!(outpoint, Outpoint::new([7u8; 32], u32::MAX));

        let over = widen_index_past_u32(&frame, 32);
        let err = WireReader::new(&over).read_outpoint().unwrap_err();
        assert_index_refused(err, "outpoint index");
    }

    #[test]
    fn a_sign_action_spend_index_above_u32_max_is_refused_not_truncated() {
        let mut spends = HashMap::new();
        spends.insert(
            u32::MAX,
            SignActionSpend {
                unlocking_script: vec![0x51],
                sequence_number: None,
            },
        );
        let mut writer = WireWriter::new();
        writer.write_sign_action_spends(&spends);
        let frame = writer.into_bytes();

        let read = WireReader::new(&frame).read_sign_action_spends().unwrap();
        assert_eq!(read.keys().copied().collect::<Vec<_>>(), vec![u32::MAX]);
        assert_eq!(read[&u32::MAX].unlocking_script, vec![0x51]);

        // [count: varint 1][index: varint][spend]
        let over = widen_index_past_u32(&frame, 1);
        let err = WireReader::new(&over)
            .read_sign_action_spends()
            .unwrap_err();
        assert_index_refused(err, "sign action spend input index");
    }

    #[test]
    fn an_internalize_output_index_above_u32_max_is_refused_not_truncated() {
        let output = InternalizeOutput {
            output_index: u32::MAX,
            protocol: "basket insertion".to_string(),
            payment_remittance: None,
            insertion_remittance: None,
        };
        let mut writer = WireWriter::new();
        writer.write_internalize_output(&output);
        let frame = writer.into_bytes();

        let read = WireReader::new(&frame).read_internalize_output().unwrap();
        assert_eq!(read.output_index, u32::MAX);
        assert_eq!(read.protocol, "basket insertion");

        let over = widen_index_past_u32(&frame, 0);
        let err = WireReader::new(&over)
            .read_internalize_output()
            .unwrap_err();
        assert_index_refused(err, "internalize output index");
    }

    #[test]
    fn a_wallet_action_output_index_above_u32_max_is_refused_not_truncated() {
        let output = WalletActionOutput {
            satoshis: 1000,
            locking_script: Some(vec![0x51]),
            spendable: true,
            custom_instructions: None,
            tags: vec![],
            output_index: u32::MAX,
            output_description: "out".to_string(),
            basket: "default".to_string(),
        };
        let mut writer = WireWriter::new();
        writer.write_wallet_action_output(&output);
        let frame = writer.into_bytes();

        let read = WireReader::new(&frame).read_wallet_action_output().unwrap();
        assert_eq!(read.output_index, u32::MAX);
        assert_eq!(read.satoshis, 1000);

        let over = widen_index_past_u32(&frame, 0);
        let err = WireReader::new(&over)
            .read_wallet_action_output()
            .unwrap_err();
        assert_index_refused(err, "listActions output outputIndex");
    }
}

// ============================================================================
// The seven result frames of #197, read to their last byte
// ============================================================================

mod result_frame_tests {
    use super::*;
    use std::sync::Mutex;

    /// A loopback that keeps the processor's last response frame.
    struct TapeWire {
        processor: WalletWireProcessor<ProtoWallet>,
        tape: Mutex<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl WalletWire for TapeWire {
        async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            let response = self.processor.process_message(message).await?;
            if let Ok(mut tape) = self.tape.lock() {
                *tape = response.clone();
            }
            Ok(response)
        }
    }

    fn taped() -> WalletWireTransceiver<TapeWire> {
        WalletWireTransceiver::new(TapeWire {
            processor: WalletWireProcessor::new(ProtoWallet::new(Some(PrivateKey::random()))),
            tape: Mutex::default(),
        })
    }

    fn last_frame(client: &WalletWireTransceiver<TapeWire>) -> Vec<u8> {
        client
            .wire()
            .tape
            .lock()
            .map(|tape| tape.clone())
            .unwrap_or_default()
    }

    /// The error byte then `bytes`, nothing between and nothing after.
    fn success(bytes: &[u8]) -> Vec<u8> {
        let mut frame = vec![0];
        frame.extend_from_slice(bytes);
        frame
    }

    fn protocol() -> Protocol {
        Protocol::new(SecurityLevel::App, "result frames")
    }

    /// Answers every request with one frame.
    struct FrameWire(Vec<u8>);

    #[async_trait::async_trait]
    impl WalletWire for FrameWire {
        async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    /// #197: encrypt's frame is the error byte then the ciphertext alone,
    /// decrypt's the error byte then the plaintext alone.
    #[tokio::test]
    async fn the_encrypt_and_decrypt_frames_carry_the_bytes_alone() {
        let client = taped();
        let plaintext = b"the rest of the frame".to_vec();
        let encrypted = client
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.clone(),
                    protocol_id: protocol(),
                    key_id: "frame-1".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert_eq!(last_frame(&client), success(&encrypted.ciphertext));
        let decrypted = client
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted.ciphertext,
                    protocol_id: protocol(),
                    key_id: "frame-1".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, plaintext);
        assert_eq!(last_frame(&client), success(&plaintext));
    }

    /// #197: createHmac's frame is 33 bytes, the error byte then the HMAC;
    /// verifyHmac's is the error byte alone.
    #[tokio::test]
    async fn the_hmac_frames_carry_the_32_bytes_then_nothing() {
        let client = taped();
        let created = client
            .create_hmac(
                CreateHmacArgs {
                    data: b"frame data".to_vec(),
                    protocol_id: protocol(),
                    key_id: "frame-2".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert_eq!(last_frame(&client), success(&created.hmac));
        assert_eq!(last_frame(&client).len(), 33);
        let verified = client
            .verify_hmac(
                VerifyHmacArgs {
                    data: b"frame data".to_vec(),
                    hmac: created.hmac,
                    protocol_id: protocol(),
                    key_id: "frame-2".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert!(verified.valid);
        assert_eq!(last_frame(&client), vec![0]);
    }

    /// #197: createSignature's frame is the error byte then the DER alone;
    /// verifySignature's is the error byte alone.
    #[tokio::test]
    async fn the_signature_frames_carry_the_der_then_nothing() {
        let client = taped();
        let created = client
            .create_signature(
                CreateSignatureArgs {
                    data: Some(b"frame message".to_vec()),
                    hash_to_directly_sign: None,
                    protocol_id: protocol(),
                    key_id: "frame-3".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert_eq!(last_frame(&client), success(&created.signature));
        bsv_rs::primitives::Signature::from_der(&created.signature).expect("a DER signature");
        let verified = client
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(b"frame message".to_vec()),
                    hash_to_directly_verify: None,
                    signature: created.signature,
                    protocol_id: protocol(),
                    key_id: "frame-3".to_string(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                    ..Default::default()
                },
                "test",
            )
            .await
            .unwrap();
        assert!(verified.valid);
        assert_eq!(last_frame(&client), vec![0]);
    }

    /// #197: waitForAuthentication's frame is the error byte alone.
    #[tokio::test]
    async fn the_wait_for_authentication_frame_is_the_error_byte_alone() {
        let client = taped();
        assert!(client.wait_for_authentication("test").await.unwrap());
        assert_eq!(last_frame(&client), vec![0]);
    }

    /// The three verdict calls through a transceiver answered with `frame`.
    async fn verdicts(frame: &[u8]) -> [Result<bool, Error>; 3] {
        let client = WalletWireTransceiver::new(FrameWire(frame.to_vec()));
        let hmac = client
            .verify_hmac(
                VerifyHmacArgs {
                    data: vec![1],
                    hmac: [0; 32],
                    protocol_id: protocol(),
                    key_id: "frame-4".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .map(|r| r.valid);
        let signature = client
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(vec![1]),
                    hash_to_directly_verify: None,
                    signature: vec![0x30, 0x00],
                    protocol_id: protocol(),
                    key_id: "frame-4".to_string(),
                    counterparty: None,
                    for_self: None,
                    ..Default::default()
                },
                "test",
            )
            .await
            .map(|r| r.valid);
        let authenticated = client.wait_for_authentication("test").await;
        [hmac, signature, authenticated]
    }

    /// #197: the error byte alone reads as true for the three verdicts.
    #[tokio::test]
    async fn the_error_byte_alone_reads_as_a_true_verdict() {
        for verdict in verdicts(&[0]).await {
            assert_eq!(verdict, Ok(true));
        }
    }

    /// #197: an error frame reads as the error for the three verdicts, never
    /// as a false verdict.
    #[tokio::test]
    async fn an_error_frame_reads_as_the_error_for_a_verdict() {
        let mut frame = WireWriter::new();
        frame.write_u8(1);
        frame.write_string("HMAC is not valid");
        frame.write_var_int(0);
        for verdict in verdicts(frame.as_bytes()).await {
            assert_eq!(
                verdict,
                Err(Error::WalletError(
                    "wallet error (code 1): HMAC is not valid".to_string()
                ))
            );
        }
    }

    /// #197: a byte after the error byte is refused, as the reference's
    /// `#requireEmptyResponse` refuses it: an older bsv-rs processor's `00 00`
    /// (its false verdict) is never read as true, nor its `00 01`.
    #[tokio::test]
    async fn a_byte_after_a_verdicts_error_byte_is_refused() {
        for frame in [[0u8, 0], [0, 1]] {
            let [hmac, signature, authenticated] = verdicts(&frame).await;
            for (verdict, call) in [
                (hmac, "verifyHmac"),
                (signature, "verifySignature"),
                (authenticated, "waitForAuthentication"),
            ] {
                assert_eq!(
                    verdict,
                    Err(Error::WalletError(format!(
                        "Wallet Wire {call} response has an invalid length"
                    ))),
                    "{frame:?}"
                );
            }
        }
    }

    /// #197: createHmac's result is 32 bytes: an older bsv-rs processor's
    /// length-prefixed 33 is refused, as the reference refuses it
    /// (`WalletWireTransceiver.ts:1020`).
    #[tokio::test]
    async fn a_create_hmac_result_other_than_32_bytes_is_refused() {
        let mut frame = vec![0, 0x20];
        frame.extend([0x0d; 32]);
        let client = WalletWireTransceiver::new(FrameWire(frame));
        let result = client
            .create_hmac(
                CreateHmacArgs {
                    data: vec![1],
                    protocol_id: protocol(),
                    key_id: "frame-5".to_string(),
                    counterparty: None,
                    ..Default::default()
                },
                "test",
            )
            .await;
        assert_eq!(
            result.err(),
            Some(Error::WalletError(
                "Wallet Wire createHmac response has an invalid length".to_string()
            ))
        );
    }
}
