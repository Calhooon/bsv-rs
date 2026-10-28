//! ProtoWallet cryptographic and linkage regression tests.
#![cfg(test)]

use super::*;

#[test]
fn test_proto_wallet_creation() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    assert!(!wallet.identity_key_hex().is_empty());
}

#[test]
fn test_proto_wallet_anyone() {
    let wallet = ProtoWallet::anyone();
    let wallet2 = ProtoWallet::anyone();
    // Anyone wallets should have the same identity key
    assert_eq!(wallet.identity_key_hex(), wallet2.identity_key_hex());
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
            ..Default::default()
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
            protocol_id: Some(protocol.clone()),
            key_id: Some("key-1".to_string()),
            counterparty: Some(Counterparty::Self_),
            for_self: Some(true),
            ..Default::default()
        })
        .unwrap();

    // Should be different from identity key
    assert_ne!(result.public_key, wallet.identity_key_hex());

    // Should be deterministic
    let result2 = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(protocol),
            key_id: Some("key-1".to_string()),
            counterparty: Some(Counterparty::Self_),
            for_self: Some(true),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.public_key, result2.public_key);
}

#[test]
fn test_encrypt_decrypt() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "encryption test");
    let plaintext = b"Hello, ProtoWallet!".to_vec();

    let encrypted = wallet
        .encrypt(EncryptArgs {
            plaintext: plaintext.clone(),
            protocol_id: protocol.clone(),
            key_id: "enc-1".to_string(),
            counterparty: None,
            ..Default::default()
        })
        .unwrap();

    let decrypted = wallet
        .decrypt(DecryptArgs {
            ciphertext: encrypted.ciphertext,
            protocol_id: protocol,
            key_id: "enc-1".to_string(),
            counterparty: None,
            ..Default::default()
        })
        .unwrap();

    assert_eq!(decrypted.plaintext, plaintext);
}

#[test]
fn test_create_verify_hmac() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "hmac test");
    let data = b"HMAC me!".to_vec();

    let created = wallet
        .create_hmac(CreateHmacArgs {
            data: data.clone(),
            protocol_id: protocol.clone(),
            key_id: "hmac-1".to_string(),
            counterparty: None,
            ..Default::default()
        })
        .unwrap();

    // Verify should pass
    let verified = wallet
        .verify_hmac(VerifyHmacArgs {
            data: data.clone(),
            hmac: created.hmac,
            protocol_id: protocol.clone(),
            key_id: "hmac-1".to_string(),
            counterparty: None,
            ..Default::default()
        })
        .unwrap();
    assert!(verified.valid);

    // Verify with wrong data should fail
    let bad_result = wallet.verify_hmac(VerifyHmacArgs {
        data: b"wrong data".to_vec(),
        hmac: created.hmac,
        protocol_id: protocol,
        key_id: "hmac-1".to_string(),
        counterparty: None,
        ..Default::default()
    });
    assert!(bad_result.is_err());
}

#[test]
fn test_create_verify_signature() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "signature test");
    let data = b"Sign me!".to_vec();

    let signed = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(data.clone()),
            hash_to_directly_sign: None,
            protocol_id: protocol.clone(),
            key_id: "sig-1".to_string(),
            counterparty: None,
            ..Default::default()
        })
        .unwrap();

    // Verify should pass (note: for_self must be true to verify our own signature)
    let verified = wallet
        .verify_signature(VerifySignatureArgs {
            data: Some(data.clone()),
            hash_to_directly_verify: None,
            signature: signed.signature.clone(),
            protocol_id: protocol.clone(),
            key_id: "sig-1".to_string(),
            counterparty: Some(Counterparty::Anyone),
            for_self: Some(true),
            ..Default::default()
        })
        .unwrap();
    assert!(verified.valid);

    // Verify with wrong data should fail
    let bad_result = wallet.verify_signature(VerifySignatureArgs {
        data: Some(b"wrong data".to_vec()),
        hash_to_directly_verify: None,
        signature: signed.signature,
        protocol_id: protocol,
        key_id: "sig-1".to_string(),
        counterparty: Some(Counterparty::Anyone),
        for_self: Some(true),
        ..Default::default()
    });
    assert!(bad_result.is_err());
}

#[test]
fn test_signature_with_hash() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "hash signature test");
    let hash = sha256(b"prehashed data");

    let signed = wallet
        .create_signature(CreateSignatureArgs {
            data: None,
            hash_to_directly_sign: Some(hash),
            protocol_id: protocol.clone(),
            key_id: "hash-sig-1".to_string(),
            counterparty: None,
            ..Default::default()
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
            ..Default::default()
        })
        .unwrap();
    assert!(verified.valid);
}

#[test]
fn test_reveal_specific_key_linkage() {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let verifier = PrivateKey::random().public_key();
    let protocol = Protocol::new(SecurityLevel::App, "linkage test");

    let result = wallet
        .reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs {
            counterparty: Counterparty::Self_,
            verifier: verifier.clone(),
            protocol_id: protocol.clone(),
            key_id: "linkage-1".to_string(),
        })
        .unwrap();

    assert_eq!(result.prover, wallet.identity_key_hex());
    assert_eq!(result.verifier, verifier.to_hex());
    assert_eq!(result.counterparty, wallet.identity_key_hex());
    assert_eq!(result.proof_type, 0);
    assert!(!result.encrypted_linkage.is_empty());
}

#[test]
fn test_reveal_counterparty_key_linkage() {
    let prover_key = PrivateKey::random();
    let wallet = ProtoWallet::new(Some(prover_key.clone()));
    let counterparty = PrivateKey::random().public_key();
    let verifier_key = PrivateKey::random();
    let verifier = verifier_key.public_key();

    let result = wallet
        .reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs {
            counterparty: counterparty.clone(),
            verifier: verifier.clone(),
        })
        .unwrap();

    assert_eq!(result.prover, wallet.identity_key_hex());
    assert_eq!(result.verifier, verifier.to_hex());
    assert_eq!(result.counterparty, counterparty.to_hex());
    assert!(!result.revelation_time.is_empty());
    assert!(!result.encrypted_linkage.is_empty());
    assert!(!result.encrypted_linkage_proof.is_empty());

    verify_counterparty_proof(&wallet, &counterparty, verifier_key, result);
}

fn verify_counterparty_proof(
    wallet: &ProtoWallet,
    counterparty: &PublicKey,
    verifier_key: PrivateKey,
    result: RevealCounterpartyKeyLinkageResult,
) {
    // Verifier decrypts and validates the Schnorr proof.
    let verifier_wallet = ProtoWallet::new(Some(verifier_key));
    let protocol = Protocol::new(
        SecurityLevel::Counterparty,
        "counterparty linkage revelation",
    );

    // Decrypt the linkage
    let decrypted_linkage = verifier_wallet
        .decrypt(DecryptArgs {
            ciphertext: result.encrypted_linkage,
            protocol_id: protocol.clone(),
            key_id: result.revelation_time.clone(),
            counterparty: Some(Counterparty::Other(wallet.identity_key())),
            ..Default::default()
        })
        .unwrap();
    let linkage_point = PublicKey::from_bytes(&decrypted_linkage.plaintext).unwrap();

    // Decrypt the proof
    let decrypted_proof = verifier_wallet
        .decrypt(DecryptArgs {
            ciphertext: result.encrypted_linkage_proof,
            protocol_id: protocol,
            key_id: result.revelation_time,
            counterparty: Some(Counterparty::Other(wallet.identity_key())),
            ..Default::default()
        })
        .unwrap();

    // Parse the 98-byte proof: R (33) || S' (33) || z (32)
    let proof_bytes = &decrypted_proof.plaintext;
    assert_eq!(proof_bytes.len(), 98);

    use crate::primitives::bsv::schnorr::{Schnorr, SchnorrProof};
    use crate::primitives::BigNumber;

    let r = PublicKey::from_bytes(&proof_bytes[0..33]).unwrap();
    let s_prime = PublicKey::from_bytes(&proof_bytes[33..66]).unwrap();
    let z = BigNumber::from_bytes_be(&proof_bytes[66..98]);

    let proof = SchnorrProof { r, s_prime, z };

    // Verify the Schnorr proof
    assert!(Schnorr::verify_proof(
        &wallet.identity_key(),
        counterparty,
        &linkage_point,
        &proof,
    ));
}

#[test]
fn test_two_party_encryption() {
    let alice = ProtoWallet::new(Some(PrivateKey::random()));
    let bob = ProtoWallet::new(Some(PrivateKey::random()));
    let protocol = Protocol::new(SecurityLevel::App, "two party encryption");
    let message = b"Secret message from Alice to Bob".to_vec();

    // Alice encrypts for Bob
    let encrypted = alice
        .encrypt(EncryptArgs {
            plaintext: message.clone(),
            protocol_id: protocol.clone(),
            key_id: "message-1".to_string(),
            counterparty: Some(Counterparty::Other(bob.identity_key())),
            ..Default::default()
        })
        .unwrap();

    // Bob decrypts using Alice as counterparty
    let decrypted = bob
        .decrypt(DecryptArgs {
            ciphertext: encrypted.ciphertext,
            protocol_id: protocol,
            key_id: "message-1".to_string(),
            counterparty: Some(Counterparty::Other(alice.identity_key())),
            ..Default::default()
        })
        .unwrap();

    assert_eq!(decrypted.plaintext, message);
}

#[test]
fn test_iso_timestamp() {
    let timestamp = get_iso_timestamp();
    // Should be in format "YYYY-MM-DDTHH:MM:SS.mmmZ"
    assert!(timestamp.len() == 24, "Timestamp: {}", timestamp);
    assert!(timestamp.ends_with('Z'));
    assert!(timestamp.contains('T'));
}
