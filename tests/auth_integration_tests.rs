//! Auth module integration tests.
//!
//! Tests full authentication flows including handshake, certificate exchange,
//! and general message passing using mock transport.

#![cfg(feature = "auth")]

use bsv_rs::auth::transports::{HttpRequest, HttpResponse, MockTransport, Transport};
use bsv_rs::auth::{
    AuthMessage, Certificate, MessageType, PeerSession, RequestedCertificateSet, SessionManager,
    VerifiableCertificate,
};
use bsv_rs::primitives::PrivateKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// =================
// Session Manager Integration Tests
// =================

#[test]
fn test_session_manager_lifecycle() {
    let mut mgr = SessionManager::new();

    // Create sessions for multiple peers
    let session1 = PeerSession::with_nonce("session-1".to_string());
    let session2 = PeerSession::with_nonce("session-2".to_string());
    let session3 = PeerSession::with_nonce("session-3".to_string());

    mgr.add_session(session1).unwrap();
    mgr.add_session(session2).unwrap();
    mgr.add_session(session3).unwrap();

    assert_eq!(mgr.len(), 3);

    // Lookup by nonce
    assert!(mgr.get_session("session-1").is_some());
    assert!(mgr.get_session("session-2").is_some());
    assert!(mgr.get_session("nonexistent").is_none());

    // Remove and verify
    mgr.remove_by_nonce("session-2");
    assert_eq!(mgr.len(), 2);
    assert!(mgr.get_session("session-2").is_none());

    // Clear all
    mgr.clear();
    assert!(mgr.is_empty());
}

#[test]
fn test_session_manager_identity_lookup() {
    let mut mgr = SessionManager::new();

    let key1 = PrivateKey::random().public_key();
    let key2 = PrivateKey::random().public_key();

    // Create authenticated session for key1
    let mut session1 = PeerSession::with_nonce("session-1".to_string());
    session1.peer_identity_key = Some(key1.clone());
    session1.is_authenticated = true;

    // Create unauthenticated session for key1
    let mut session2 = PeerSession::with_nonce("session-2".to_string());
    session2.peer_identity_key = Some(key1.clone());
    session2.is_authenticated = false;

    // Create session for key2
    let mut session3 = PeerSession::with_nonce("session-3".to_string());
    session3.peer_identity_key = Some(key2.clone());
    session3.is_authenticated = true;

    mgr.add_session(session1).unwrap();
    mgr.add_session(session2).unwrap();
    mgr.add_session(session3).unwrap();

    // Lookup by identity should prefer authenticated session
    let found = mgr.get_session(&key1.to_hex()).unwrap();
    assert!(found.is_authenticated);
    assert_eq!(found.session_nonce.as_deref(), Some("session-1"));

    // Multiple sessions for same identity
    let sessions = mgr.get_sessions_for_identity(&key1.to_hex());
    assert_eq!(sessions.len(), 2);
}

#[test]
fn test_session_manager_prune_stale() {
    let mut mgr = SessionManager::new();

    // Create old session
    let mut old_session = PeerSession::with_nonce("old-session".to_string());
    old_session.last_update = 0; // Unix epoch

    // Create new session
    let new_session = PeerSession::with_nonce("new-session".to_string());

    mgr.add_session(old_session).unwrap();
    mgr.add_session(new_session).unwrap();

    assert_eq!(mgr.len(), 2);

    // Prune sessions older than 1 hour
    let pruned = mgr.prune_stale_sessions(3600 * 1000);
    assert_eq!(pruned, 1);
    assert_eq!(mgr.len(), 1);
    assert!(mgr.get_session("new-session").is_some());
    assert!(mgr.get_session("old-session").is_none());
}

// =================
// AuthMessage Tests
// =================

#[test]
fn test_auth_message_validation() {
    let key = PrivateKey::random().public_key();

    // InitialRequest needs initial_nonce
    let mut msg = AuthMessage::new(MessageType::InitialRequest, key.clone());
    assert!(msg.validate().is_err());

    msg.initial_nonce = Some("test-nonce".to_string());
    assert!(msg.validate().is_ok());

    // InitialResponse needs at least one of nonce/initial_nonce, plus your_nonce and signature
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key.clone());
    assert!(msg.validate().is_err());

    // Go-style: both nonce and initial_nonce present
    msg.nonce = Some("session-nonce".to_string());
    msg.initial_nonce = Some("initial-nonce".to_string());
    msg.your_nonce = Some("peer-nonce".to_string());
    msg.signature = Some(vec![0x30, 0x44]); // Fake signature
    assert!(msg.validate().is_ok());

    // TS-style: only initial_nonce (no nonce field) - should also validate
    let mut ts_msg = AuthMessage::new(MessageType::InitialResponse, key.clone());
    ts_msg.initial_nonce = Some("initial-nonce".to_string());
    ts_msg.your_nonce = Some("peer-nonce".to_string());
    ts_msg.signature = Some(vec![0x30, 0x44]);
    assert!(
        ts_msg.validate().is_ok(),
        "TS-style InitialResponse (no nonce, only initialNonce) should validate"
    );

    // General message needs signature
    let mut msg = AuthMessage::new(MessageType::General, key.clone());
    assert!(msg.validate().is_err());

    msg.signature = Some(vec![0x30, 0x44]);
    assert!(msg.validate().is_ok());
}

#[test]
fn test_auth_message_signing_data() {
    let key = PrivateKey::random().public_key();

    // InitialResponse signing data is yourNonce || initialNonce (initiator || responder)
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key.clone());
    msg.your_nonce = Some(bsv_rs::primitives::to_base64(&[1, 2, 3, 4])); // initiator's nonce
    msg.initial_nonce = Some(bsv_rs::primitives::to_base64(&[5, 6, 7, 8])); // responder's nonce

    let signing_data = msg.signing_data();
    assert_eq!(signing_data, vec![1, 2, 3, 4, 5, 6, 7, 8]);

    // General message signing data is the payload
    let mut msg = AuthMessage::new(MessageType::General, key.clone());
    msg.payload = Some(b"hello world".to_vec());

    let signing_data = msg.signing_data();
    assert_eq!(signing_data, b"hello world".to_vec());
}

#[test]
fn test_auth_message_key_id() {
    let key = PrivateKey::random().public_key();

    // General message key ID is "{nonce} {peer_session_nonce}"
    let mut msg = AuthMessage::new(MessageType::General, key.clone());
    msg.nonce = Some("my-nonce".to_string());

    let key_id = msg.get_key_id(Some("peer-nonce"));
    assert_eq!(key_id, "my-nonce peer-nonce");

    // InitialResponse key ID is "{yourNonce} {initialNonce}" = "{initiator} {responder}"
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key.clone());
    msg.your_nonce = Some("initiator-nonce".to_string());
    msg.initial_nonce = Some("responder-nonce".to_string());

    let key_id = msg.get_key_id(None);
    assert_eq!(key_id, "initiator-nonce responder-nonce");
}

// =================
// Mock Transport Tests
// =================

#[tokio::test]
async fn test_mock_transport_multiple_responses() {
    let transport = MockTransport::new();

    let key1 = PrivateKey::random().public_key();
    let key2 = PrivateKey::random().public_key();

    // Queue multiple responses
    transport
        .queue_response(AuthMessage::new(MessageType::InitialResponse, key1.clone()))
        .await;
    transport
        .queue_response(AuthMessage::new(
            MessageType::CertificateResponse,
            key2.clone(),
        ))
        .await;

    // Set up callback to capture responses
    let received = Arc::new(RwLock::new(Vec::new()));
    let received_clone = received.clone();
    transport.set_callback(Box::new(move |msg| {
        let received = received_clone.clone();
        Box::pin(async move {
            let mut r = received.write().await;
            r.push(msg);
            Ok(())
        })
    }));

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Send requests and get responses in order
    transport
        .send(&AuthMessage::new(MessageType::InitialRequest, key1.clone()))
        .await
        .unwrap();
    transport
        .send(&AuthMessage::new(
            MessageType::CertificateRequest,
            key2.clone(),
        ))
        .await
        .unwrap();

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    let recv = received.read().await;
    assert_eq!(recv.len(), 2);
    assert_eq!(recv[0].message_type, MessageType::InitialResponse);
    assert_eq!(recv[1].message_type, MessageType::CertificateResponse);
}

#[tokio::test]
async fn test_mock_transport_receive_message() {
    let transport = MockTransport::new();

    let received = Arc::new(RwLock::new(Vec::new()));
    let received_clone = received.clone();
    transport.set_callback(Box::new(move |msg| {
        let received = received_clone.clone();
        Box::pin(async move {
            let mut r = received.write().await;
            r.push(msg);
            Ok(())
        })
    }));

    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    // Simulate receiving a message from remote
    let key = PrivateKey::random().public_key();
    let incoming = AuthMessage::new(MessageType::General, key);
    transport.receive_message(incoming.clone()).await.unwrap();

    let recv = received.read().await;
    assert_eq!(recv.len(), 1);
    assert_eq!(recv[0].message_type, MessageType::General);
}

// =================
// HTTP Request/Response Payload Tests
// =================

#[test]
fn test_http_request_payload_complex() {
    let request = HttpRequest {
        request_id: [0xAB; 32],
        method: "POST".to_string(),
        path: "/api/v2/transactions".to_string(),
        search: String::new(),
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-bsv-topic".to_string(), "tm_test".to_string()),
            ("authorization".to_string(), "Bearer token123".to_string()),
        ],
        body: br#"{"txid":"abc123"}"#.to_vec(),
    };

    let payload = request.to_payload();
    let decoded = HttpRequest::from_payload(&payload).unwrap();

    assert_eq!(decoded.request_id, [0xAB; 32]);
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.url_postfix(), "/api/v2/transactions");
    assert_eq!(decoded.headers.len(), 3);
    assert_eq!(decoded.body, br#"{"txid":"abc123"}"#.to_vec());
}

#[test]
fn test_http_response_payload_with_headers() {
    let response = HttpResponse {
        request_id: [0xCD; 32],
        status: 201,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-bsv-txid".to_string(), "abc123def456".to_string()),
        ],
        body: br#"{"success":true}"#.to_vec(),
    };

    let payload = response.to_payload();
    let decoded = HttpResponse::from_payload(&payload).unwrap();

    assert_eq!(decoded.request_id, [0xCD; 32]);
    assert_eq!(decoded.status, 201);
    assert_eq!(decoded.headers.len(), 2);
    assert_eq!(decoded.body, br#"{"success":true}"#.to_vec());
}

// =================
// Certificate Tests
// =================

#[test]
fn test_certificate_creation_and_signing() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32], // cert_type
        [2u8; 32], // serial_number
        subject_key.clone(),
        certifier_key.public_key(),
    );

    // Add encrypted fields
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());
    cert.fields
        .insert("email".to_string(), b"encrypted_email".to_vec());

    // Sign the certificate
    cert.sign(&certifier_key).unwrap();

    assert!(cert.signature.is_some());

    // Verify the certificate
    let is_valid = cert.verify().unwrap();
    assert!(is_valid);
}

#[test]
fn test_certificate_binary_roundtrip() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [0xAA; 32],
        [0xBB; 32],
        subject_key,
        certifier_key.public_key(),
    );

    cert.fields.insert("field1".to_string(), b"value1".to_vec());
    cert.sign(&certifier_key).unwrap();

    // Binary roundtrip
    let binary = cert.to_binary(true);
    let decoded = Certificate::from_binary(&binary).unwrap();

    assert_eq!(decoded.cert_type, cert.cert_type);
    assert_eq!(decoded.serial_number, cert.serial_number);
    assert_eq!(decoded.subject.to_hex(), cert.subject.to_hex());
    assert_eq!(decoded.certifier.to_hex(), cert.certifier.to_hex());
    assert_eq!(decoded.fields, cert.fields);
    assert!(decoded.signature.is_some());
}

#[test]
fn test_certificate_wrong_signer_fails() {
    let certifier_key = PrivateKey::random();
    let wrong_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    // Sign with wrong key should fail (implementation enforces signer matches certifier)
    let result = cert.sign(&wrong_key);
    assert!(result.is_err());
}

#[test]
fn test_verifiable_certificate_creation() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields
        .insert("name".to_string(), b"encrypted".to_vec());
    cert.sign(&certifier_key).unwrap();

    // Create verifiable certificate with keyring
    let mut keyring = HashMap::new();
    keyring.insert("name".to_string(), b"decryption_key".to_vec());

    let verifiable = VerifiableCertificate::new(cert.clone(), keyring);

    // Verify through VerifiableCertificate
    assert!(verifiable.verify().unwrap());

    // Access certificate fields through deref
    assert_eq!(verifiable.cert_type, cert.cert_type);
    assert!(verifiable.keyring.contains_key("name"));
}

// =================
// RequestedCertificateSet Tests
// =================

#[test]
fn test_requested_certificate_set_matching() {
    let mut req = RequestedCertificateSet::new();

    // Empty request accepts anything
    assert!(req.is_certifier_trusted("any-certifier"));
    assert!(req.is_type_requested("any-type"));

    // Add specific certifier
    let certifier_key = PrivateKey::random().public_key();
    req.add_certifier(certifier_key.to_hex());

    assert!(req.is_certifier_trusted(&certifier_key.to_hex()));
    assert!(!req.is_certifier_trusted("wrong-certifier"));

    // Add specific type with fields
    let type_id = bsv_rs::primitives::to_base64(&[1u8; 32]);
    req.add_type(&type_id, vec!["name".to_string(), "email".to_string()]);

    assert!(req.is_type_requested(&type_id));
    assert!(!req.is_type_requested("wrong-type"));

    let fields = req.get_fields_for_type(&type_id).unwrap();
    assert_eq!(fields.len(), 2);
    assert!(fields.contains(&"name".to_string()));
}

#[test]
fn test_requested_certificate_set_json_roundtrip() {
    let mut req = RequestedCertificateSet::new();
    req.add_certifier("02abc123");
    req.add_type("type1", vec!["field1".to_string()]);

    let json = serde_json::to_string(&req).unwrap();
    let decoded: RequestedCertificateSet = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.certifiers, req.certifiers);
    assert_eq!(decoded.types, req.types);
}

// =================
// Peer Session State Tests
// =================

#[test]
fn test_peer_session_ready_states() {
    let mut session = PeerSession::new();

    // Not authenticated, not ready
    assert!(!session.is_ready());

    // Authenticated but no certs required, ready
    session.is_authenticated = true;
    assert!(session.is_ready());

    // Authenticated with certs required but not validated, not ready
    session.certificates_required = true;
    assert!(!session.is_ready());

    // Authenticated with certs required and validated, ready
    session.certificates_validated = true;
    assert!(session.is_ready());
}

#[test]
fn test_peer_session_touch() {
    let mut session = PeerSession::new();
    let initial_time = session.last_update;

    // Sleep briefly and touch
    std::thread::sleep(std::time::Duration::from_millis(10));
    session.touch();

    assert!(session.last_update > initial_time);
}

// =================
// Error Handling Tests
// =================

#[test]
fn test_invalid_auth_version() {
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialRequest, key);
    msg.version = "99.0".to_string(); // Wrong version
    msg.initial_nonce = Some("test".to_string());

    let result = msg.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid auth version"));
}

#[test]
fn test_duplicate_session_nonce_rejected() {
    let mut mgr = SessionManager::new();

    let session1 = PeerSession::with_nonce("same-nonce".to_string());
    let session2 = PeerSession::with_nonce("same-nonce".to_string());

    mgr.add_session(session1).unwrap();

    let result = mgr.add_session(session2);
    assert!(result.is_err());
}

#[test]
fn test_session_without_nonce_rejected() {
    let mut mgr = SessionManager::new();

    let session = PeerSession::new(); // No nonce
    let result = mgr.add_session(session);
    assert!(result.is_err());
}

// =================
// HTTP Payload Edge Cases
// =================

#[test]
fn test_http_request_empty_values() {
    let request = HttpRequest {
        request_id: [0u8; 32],
        method: String::new(), // Empty method should default to GET
        path: String::new(),
        search: String::new(),
        headers: vec![],
        body: vec![],
    };

    let payload = request.to_payload();
    let decoded = HttpRequest::from_payload(&payload).unwrap();

    assert!(decoded.method.is_empty() || decoded.method == "GET");
    assert!(decoded.url_postfix().is_empty());
    assert!(decoded.headers.is_empty());
    assert!(decoded.body.is_empty());
}

#[test]
fn test_http_request_unicode_values() {
    let request = HttpRequest {
        request_id: [0u8; 32],
        method: "POST".to_string(),
        path: "/api/users/test".to_string(), // URL
        search: String::new(),
        headers: vec![("x-custom".to_string(), "unicode-value".to_string())], // Header value
        body: "hello".as_bytes().to_vec(),                                    // Body
    };

    let payload = request.to_payload();
    let decoded = HttpRequest::from_payload(&payload).unwrap();

    assert_eq!(decoded.url_postfix(), "/api/users/test");
    assert_eq!(decoded.headers[0].1, "unicode-value");
    assert_eq!(decoded.body, "hello".as_bytes());
}

#[test]
fn test_http_request_large_header_count() {
    let mut headers = Vec::new();
    for i in 0..100 {
        headers.push((format!("x-header-{}", i), format!("value-{}", i)));
    }

    let request = HttpRequest {
        request_id: [0u8; 32],
        method: "GET".to_string(),
        path: "/test".to_string(),
        search: String::new(),
        headers,
        body: vec![],
    };

    let payload = request.to_payload();
    let decoded = HttpRequest::from_payload(&payload).unwrap();

    assert_eq!(decoded.headers.len(), 100);
}

// =================
// Certificate JSON Serialization
// =================

#[test]
fn test_certificate_json_roundtrip() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields.insert("name".to_string(), b"test".to_vec());
    cert.sign(&certifier_key).unwrap();

    let json = serde_json::to_string(&cert).unwrap();
    let decoded: Certificate = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.cert_type, cert.cert_type);
    assert_eq!(decoded.serial_number, cert.serial_number);
    assert!(decoded.verify().unwrap());
}

#[test]
fn test_verifiable_certificate_json_roundtrip() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.sign(&certifier_key).unwrap();

    let mut keyring = HashMap::new();
    keyring.insert("field1".to_string(), b"key1".to_vec());

    let verifiable = VerifiableCertificate::new(cert, keyring);

    let json = serde_json::to_string(&verifiable).unwrap();
    let decoded: VerifiableCertificate = serde_json::from_str(&json).unwrap();

    assert!(decoded.verify().unwrap());
    assert!(decoded.keyring.contains_key("field1"));
}

// =================
// P0-CERT-3: Tampered certificate detection
// =================

#[test]
fn test_tampered_certificate_field_fails_verification() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());
    cert.fields
        .insert("email".to_string(), b"encrypted_email".to_vec());

    // Sign the certificate
    cert.sign(&certifier_key).unwrap();
    assert!(
        cert.verify().unwrap(),
        "Certificate should verify before tampering"
    );

    // Tamper with a field value after signing
    cert.fields
        .insert("email".to_string(), b"attacker@evil.com".to_vec());

    // Verify should now return false (signature does not match modified content)
    let result = cert.verify().unwrap();
    assert!(
        !result,
        "Certificate verification should fail after field tampering"
    );
}

#[test]
fn test_tampered_certificate_subject_fails_verification() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());

    cert.sign(&certifier_key).unwrap();
    assert!(
        cert.verify().unwrap(),
        "Certificate should verify before tampering"
    );

    // Tamper with the subject public key
    let different_subject = PrivateKey::random().public_key();
    cert.subject = different_subject;

    // Verify should now return false
    let result = cert.verify().unwrap();
    assert!(
        !result,
        "Certificate verification should fail after subject tampering"
    );
}

#[test]
fn test_tampered_certificate_serial_number_fails_verification() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    cert.sign(&certifier_key).unwrap();
    assert!(
        cert.verify().unwrap(),
        "Certificate should verify before tampering"
    );

    // Tamper with the serial number
    cert.serial_number = [99u8; 32];

    let result = cert.verify().unwrap();
    assert!(
        !result,
        "Certificate verification should fail after serial number tampering"
    );
}

#[test]
fn test_tampered_certificate_type_fails_verification() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    cert.sign(&certifier_key).unwrap();
    assert!(cert.verify().unwrap());

    // Tamper with the cert type
    cert.cert_type = [99u8; 32];

    let result = cert.verify().unwrap();
    assert!(
        !result,
        "Certificate verification should fail after cert_type tampering"
    );
}

// =================
// P0-CERT-4: Missing signature verification
// =================

#[test]
fn test_unsigned_certificate_verify_returns_error() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    // Certificate has no signature - verify() should return an error
    let result = cert.verify();
    assert!(
        result.is_err(),
        "Verifying an unsigned certificate should return an error"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not signed"),
        "Error should mention missing signature, got: {}",
        err_msg
    );
}

#[test]
fn test_certificate_with_invalid_der_signature_fails() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    // Set an invalid DER signature
    cert.signature = Some(vec![0x30, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

    let result = cert.verify();
    assert!(
        result.is_err(),
        "Certificate with invalid DER signature should fail verification"
    );
}

// =================
// P0-CERT-7: Nonce create/verify round-trip
// =================

#[tokio::test]
async fn test_nonce_create_verify_roundtrip() {
    use bsv_rs::auth::{create_nonce, verify_nonce};
    use bsv_rs::wallet::ProtoWallet;

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));

    // Create a nonce with self counterparty (no counterparty = self)
    let nonce = create_nonce(&wallet, None, "test-app").await.unwrap();

    // Nonce should not be empty
    assert!(!nonce.is_empty(), "Created nonce should not be empty");

    // Verify the nonce with the same wallet and same counterparty
    let is_valid = verify_nonce(&nonce, &wallet, None, "test-app")
        .await
        .unwrap();
    assert!(
        is_valid,
        "Nonce should verify with the same wallet and counterparty"
    );
}

#[tokio::test]
async fn test_nonce_uniqueness() {
    use bsv_rs::auth::create_nonce;
    use bsv_rs::wallet::ProtoWallet;

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));

    let nonce1 = create_nonce(&wallet, None, "test-app").await.unwrap();
    let nonce2 = create_nonce(&wallet, None, "test-app").await.unwrap();

    assert_ne!(
        nonce1, nonce2,
        "Two nonces created by the same wallet should be different"
    );
}

#[tokio::test]
async fn test_nonce_verify_fails_with_wrong_counterparty() {
    use bsv_rs::auth::{create_nonce, verify_nonce};
    use bsv_rs::wallet::ProtoWallet;

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let other_key = PrivateKey::random().public_key();

    // Create nonce with self counterparty (None)
    let nonce = create_nonce(&wallet, None, "test-app").await.unwrap();

    // Verify with a different counterparty should fail
    let is_valid = verify_nonce(&nonce, &wallet, Some(&other_key), "test-app")
        .await
        .unwrap();
    assert!(
        !is_valid,
        "Nonce should not verify with a different counterparty"
    );
}

#[tokio::test]
async fn test_nonce_verify_fails_with_different_wallet() {
    use bsv_rs::auth::{create_nonce, verify_nonce};
    use bsv_rs::wallet::ProtoWallet;

    let wallet1 = ProtoWallet::new(Some(PrivateKey::random()));
    let wallet2 = ProtoWallet::new(Some(PrivateKey::random()));

    // Create nonce with wallet1
    let nonce = create_nonce(&wallet1, None, "test-app").await.unwrap();

    // Verify with wallet2 should fail
    let is_valid = verify_nonce(&nonce, &wallet2, None, "test-app")
        .await
        .unwrap();
    assert!(!is_valid, "Nonce should not verify with a different wallet");
}

#[tokio::test]
async fn test_nonce_with_specific_counterparty_roundtrip() {
    use bsv_rs::auth::{create_nonce, verify_nonce};
    use bsv_rs::wallet::ProtoWallet;

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let counterparty_key = PrivateKey::random().public_key();

    // Create nonce with specific counterparty
    let nonce = create_nonce(&wallet, Some(&counterparty_key), "test-app")
        .await
        .unwrap();

    // Verify with same counterparty should succeed
    let is_valid = verify_nonce(&nonce, &wallet, Some(&counterparty_key), "test-app")
        .await
        .unwrap();
    assert!(is_valid, "Nonce should verify with the same counterparty");

    // Verify with different counterparty should fail
    let other_key = PrivateKey::random().public_key();
    let is_valid2 = verify_nonce(&nonce, &wallet, Some(&other_key), "test-app")
        .await
        .unwrap();
    assert!(
        !is_valid2,
        "Nonce should not verify with a different counterparty"
    );
}

#[tokio::test]
async fn test_nonce_verify_invalid_format() {
    use bsv_rs::auth::verify_nonce;
    use bsv_rs::wallet::ProtoWallet;

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));

    // Verify a too-short nonce should return an error
    let short_nonce = bsv_rs::primitives::to_base64(&[0u8; 16]);
    let result = verify_nonce(&short_nonce, &wallet, None, "test-app").await;
    assert!(
        result.is_err(),
        "Verifying a too-short nonce should return an error"
    );
}

// =================
// P0-CERT-1: MasterCertificate async tests
// =================

#[tokio::test]
async fn test_master_certificate_issue_for_subject() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    let cert_type = [1u8; 32];
    let serial_number = [2u8; 32];

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        cert_type,
        Some(serial_number),
        "test-app",
    )
    .await
    .unwrap();

    // Verify the certificate is signed
    assert!(
        master_cert.certificate.signature.is_some(),
        "Issued certificate should have a signature"
    );

    // Verify the signature is valid
    assert!(
        master_cert.verify().unwrap(),
        "Issued certificate signature should be valid"
    );

    // Verify certificate metadata
    assert_eq!(master_cert.certificate.cert_type, cert_type);
    assert_eq!(master_cert.certificate.serial_number, serial_number);
    assert_eq!(master_cert.certificate.subject, subject_key.public_key());
    assert_eq!(
        master_cert.certificate.certifier,
        certifier_key.public_key()
    );

    // Verify fields are encrypted (not plaintext)
    assert_eq!(
        master_cert.certificate.fields.len(),
        3,
        "Certificate should have 3 encrypted fields"
    );
    for (field_name, encrypted_value) in &master_cert.certificate.fields {
        assert!(
            plain_fields.contains_key(field_name),
            "Field '{}' should be a known field",
            field_name
        );
        // Encrypted values should not equal the plaintext
        let plain_value = plain_fields[field_name].as_bytes();
        assert_ne!(
            encrypted_value,
            &plain_value.to_vec(),
            "Field '{}' should be encrypted, not plaintext",
            field_name
        );
        // Encrypted values should be non-empty
        assert!(
            !encrypted_value.is_empty(),
            "Encrypted field '{}' should not be empty",
            field_name
        );
    }

    // Verify master keyring has entries for all fields
    assert_eq!(
        master_cert.master_keyring.len(),
        3,
        "Master keyring should have 3 entries"
    );
    for field_name in plain_fields.keys() {
        assert!(
            master_cert.master_keyring.contains_key(field_name),
            "Master keyring should contain key for field '{}'",
            field_name
        );
    }
}

#[tokio::test]
async fn test_master_certificate_decrypt_fields() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Subject decrypts all fields using their wallet
    let decrypted = master_cert
        .decrypt_fields(&subject_wallet, &certifier_key.public_key(), "test-app")
        .await
        .unwrap();

    // All fields should be decrypted to their original plaintext
    assert_eq!(
        decrypted.len(),
        plain_fields.len(),
        "Should decrypt all fields"
    );
    for (field_name, expected_value) in &plain_fields {
        let actual = decrypted.get(field_name).unwrap_or_else(|| {
            panic!("Decrypted fields should contain '{}'", field_name);
        });
        assert_eq!(
            actual, expected_value,
            "Decrypted value for '{}' should match plaintext",
            field_name
        );
    }
}

#[tokio::test]
async fn test_master_certificate_decrypt_single_field() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Decrypt a single field
    let name_value = master_cert
        .decrypt_field(
            &subject_wallet,
            &certifier_key.public_key(),
            "name",
            "test-app",
        )
        .await
        .unwrap();
    assert_eq!(name_value, "Alice", "Decrypted name should be 'Alice'");

    let email_value = master_cert
        .decrypt_field(
            &subject_wallet,
            &certifier_key.public_key(),
            "email",
            "test-app",
        )
        .await
        .unwrap();
    assert_eq!(
        email_value, "alice@example.com",
        "Decrypted email should be 'alice@example.com'"
    );
}

#[tokio::test]
async fn test_master_certificate_create_keyring_for_verifier() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Create keyring for verifier revealing only "name" field
    let fields_to_reveal = vec!["name".to_string()];
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_key.public_key(),
        &verifier_key.public_key(),
        &fields_to_reveal,
        &master_cert.certificate.fields,
        &master_cert.certificate.serial_number,
        "test-app",
    )
    .await
    .unwrap();

    // Keyring should contain only the revealed field
    assert_eq!(
        keyring.len(),
        1,
        "Keyring should have 1 entry for the revealed field"
    );
    assert!(
        keyring.contains_key("name"),
        "Keyring should contain entry for 'name'"
    );
    assert!(
        !keyring.contains_key("email"),
        "Keyring should not contain entry for unrevealed 'email'"
    );
    assert!(
        !keyring.contains_key("department"),
        "Keyring should not contain entry for unrevealed 'department'"
    );
}

// =================
// P0-CERT-2: VerifiableCertificate async tests
// =================

#[tokio::test]
async fn test_verifiable_certificate_full_chain() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));
    let verifier_wallet = ProtoWallet::new(Some(verifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("organization".to_string(), "Example Corp".to_string());

    // Step 1: Certifier issues master certificate
    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Step 2: Subject creates keyring for verifier (reveal all fields)
    let all_field_names: Vec<String> = plain_fields.keys().cloned().collect();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_key.public_key(),
        &verifier_key.public_key(),
        &all_field_names,
        &master_cert.certificate.fields,
        &master_cert.certificate.serial_number,
        "test-app",
    )
    .await
    .unwrap();

    // Step 3: Construct VerifiableCertificate
    let mut verifiable = VerifiableCertificate::new(master_cert.certificate.clone(), keyring);

    // Verify the underlying certificate signature
    assert!(
        verifiable.verify().unwrap(),
        "VerifiableCertificate should verify"
    );

    // Step 4: Verifier decrypts fields
    let decrypted = verifiable
        .decrypt_fields(&verifier_wallet, &subject_key.public_key(), "test-app")
        .await
        .unwrap();

    // All plaintext fields should match
    assert_eq!(
        decrypted.len(),
        plain_fields.len(),
        "Should decrypt all fields"
    );
    for (field_name, expected_value) in &plain_fields {
        let actual = decrypted.get(field_name).unwrap_or_else(|| {
            panic!("Decrypted fields should contain '{}'", field_name);
        });
        assert_eq!(
            actual, expected_value,
            "Decrypted '{}' should match plaintext",
            field_name
        );
    }
}

#[tokio::test]
async fn test_verifiable_certificate_selective_disclosure() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));
    let verifier_wallet = ProtoWallet::new(Some(verifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    // Issue master certificate
    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Create keyring revealing only "name"
    let fields_to_reveal = vec!["name".to_string()];
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_key.public_key(),
        &verifier_key.public_key(),
        &fields_to_reveal,
        &master_cert.certificate.fields,
        &master_cert.certificate.serial_number,
        "test-app",
    )
    .await
    .unwrap();

    let mut verifiable = VerifiableCertificate::new(master_cert.certificate.clone(), keyring);

    // Verifier can only decrypt revealed fields
    let decrypted = verifiable
        .decrypt_fields(&verifier_wallet, &subject_key.public_key(), "test-app")
        .await
        .unwrap();

    assert_eq!(decrypted.len(), 1, "Only 1 field should be decryptable");
    assert_eq!(
        decrypted.get("name").unwrap(),
        "Alice",
        "Decrypted 'name' should be 'Alice'"
    );
    assert!(
        !decrypted.contains_key("email"),
        "'email' should not be decryptable"
    );
    assert!(
        !decrypted.contains_key("department"),
        "'department' should not be decryptable"
    );
}

// =================
// P0-CERT-5: Wrong-key decryption
// =================

#[tokio::test]
async fn test_verifiable_certificate_wrong_key_decryption_fails() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_a_key = PrivateKey::random();
    let verifier_b_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));
    let wrong_wallet = ProtoWallet::new(Some(verifier_b_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());

    // Issue certificate
    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Create keyring for verifier A
    let fields_to_reveal = vec!["name".to_string(), "email".to_string()];
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_key.public_key(),
        &verifier_a_key.public_key(),
        &fields_to_reveal,
        &master_cert.certificate.fields,
        &master_cert.certificate.serial_number,
        "test-app",
    )
    .await
    .unwrap();

    let mut verifiable = VerifiableCertificate::new(master_cert.certificate.clone(), keyring);

    // Try to decrypt with verifier B's wallet (wrong key) -- should fail
    let result = verifiable
        .decrypt_fields(&wrong_wallet, &subject_key.public_key(), "test-app")
        .await;

    assert!(
        result.is_err(),
        "Decrypting with wrong verifier's wallet should fail"
    );
}

// =================
// P0-CERT-6: Full issuance-to-verification chain
// =================

#[tokio::test]
async fn test_full_issuance_to_verification_chain() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject_key.clone()));
    let verifier_wallet = ProtoWallet::new(Some(verifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());
    plain_fields.insert("email".to_string(), "alice@example.com".to_string());
    plain_fields.insert("clearance_level".to_string(), "Top Secret".to_string());
    plain_fields.insert("department".to_string(), "Engineering".to_string());

    let cert_type = [42u8; 32];
    let serial_number = [99u8; 32];

    // === Phase 1: Certifier issues certificate ===
    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        cert_type,
        Some(serial_number),
        "test-app",
    )
    .await
    .unwrap();

    // Verify it's properly signed
    assert!(
        master_cert.verify().unwrap(),
        "Issued cert should be signed"
    );
    assert_eq!(master_cert.certificate.cert_type, cert_type);
    assert_eq!(master_cert.certificate.serial_number, serial_number);
    assert_eq!(
        master_cert.certificate.certifier,
        certifier_key.public_key()
    );
    assert_eq!(master_cert.certificate.subject, subject_key.public_key());

    // === Phase 2: Subject verifies they can decrypt all fields ===
    let all_decrypted = master_cert
        .decrypt_fields(&subject_wallet, &certifier_key.public_key(), "test-app")
        .await
        .unwrap();

    assert_eq!(all_decrypted.len(), 4);
    assert_eq!(all_decrypted["name"], "Alice");
    assert_eq!(all_decrypted["email"], "alice@example.com");
    assert_eq!(all_decrypted["clearance_level"], "Top Secret");
    assert_eq!(all_decrypted["department"], "Engineering");

    // === Phase 3: Subject selectively reveals only name and email to verifier ===
    let fields_to_reveal = vec!["name".to_string(), "email".to_string()];
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_key.public_key(),
        &verifier_key.public_key(),
        &fields_to_reveal,
        &master_cert.certificate.fields,
        &master_cert.certificate.serial_number,
        "test-app",
    )
    .await
    .unwrap();

    assert_eq!(keyring.len(), 2, "Keyring should have 2 entries");
    assert!(keyring.contains_key("name"), "Keyring should have 'name'");
    assert!(keyring.contains_key("email"), "Keyring should have 'email'");

    // === Phase 4: Construct VerifiableCertificate and send to verifier ===
    let mut verifiable = VerifiableCertificate::new(master_cert.certificate.clone(), keyring);

    // Verifier validates signature
    assert!(
        verifiable.verify().unwrap(),
        "Verifier should be able to verify cert signature"
    );

    // Verifier checks metadata
    assert_eq!(*verifiable.cert_type(), cert_type);
    assert_eq!(*verifiable.serial_number(), serial_number);
    assert_eq!(*verifiable.subject(), subject_key.public_key());
    assert_eq!(*verifiable.certifier(), certifier_key.public_key());

    // === Phase 5: Verifier decrypts only revealed fields ===
    let verifier_decrypted = verifiable
        .decrypt_fields(&verifier_wallet, &subject_key.public_key(), "test-app")
        .await
        .unwrap();

    assert_eq!(
        verifier_decrypted.len(),
        2,
        "Verifier should only see 2 fields"
    );
    assert_eq!(verifier_decrypted["name"], "Alice");
    assert_eq!(verifier_decrypted["email"], "alice@example.com");
    assert!(
        !verifier_decrypted.contains_key("clearance_level"),
        "Verifier should not see clearance_level"
    );
    assert!(
        !verifier_decrypted.contains_key("department"),
        "Verifier should not see department"
    );

    // === Phase 6: Verify caching works ===
    let cached = verifiable.get_decrypted_fields();
    assert!(cached.is_some(), "Decrypted fields should be cached");
    assert_eq!(cached.unwrap().len(), 2);

    verifiable.clear_decrypted_cache();
    assert!(
        verifiable.get_decrypted_fields().is_none(),
        "Cache should be cleared"
    );
}

// =================
// P1-CERT-8: WalletCertificate conversion roundtrip
// =================

#[test]
fn test_wallet_certificate_conversion_roundtrip() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [0xAA; 32],
        [0xBB; 32],
        subject_key.clone(),
        certifier_key.public_key(),
    );
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());
    cert.fields
        .insert("email".to_string(), b"encrypted_email".to_vec());
    cert.revocation_outpoint = Some(bsv_rs::wallet::types::Outpoint::new([0xCC; 32], 7));
    cert.sign(&certifier_key).unwrap();

    // Convert to WalletCertificate
    let wallet_cert = cert.to_wallet_certificate();

    // Verify all fields are preserved in WalletCertificate
    assert_eq!(
        wallet_cert.certificate_type,
        cert.type_base64(),
        "Certificate type should be preserved"
    );
    assert_eq!(
        wallet_cert.serial_number,
        cert.serial_number_base64(),
        "Serial number should be preserved"
    );
    assert_eq!(
        wallet_cert.subject, cert.subject,
        "Subject should be preserved"
    );
    assert_eq!(
        wallet_cert.certifier, cert.certifier,
        "Certifier should be preserved"
    );
    assert!(
        wallet_cert.signature.is_some(),
        "Signature should be preserved"
    );
    assert_eq!(
        wallet_cert.signature.as_ref().unwrap(),
        cert.signature.as_ref().unwrap(),
        "Signature bytes should match"
    );

    // Verify revocation outpoint is preserved
    assert!(wallet_cert.revocation_outpoint.is_some());
    let outpoint = wallet_cert.revocation_outpoint.as_ref().unwrap();
    assert_eq!(outpoint.txid, [0xCC; 32]);
    assert_eq!(outpoint.vout, 7);

    // Verify fields are base64-encoded in WalletCertificate
    assert_eq!(wallet_cert.fields.len(), 2);
    let name_b64 = wallet_cert.fields.get("name").unwrap();
    let email_b64 = wallet_cert.fields.get("email").unwrap();

    // Decode base64 fields back and verify they match original bytes
    let name_bytes = bsv_rs::primitives::from_base64(name_b64).unwrap();
    assert_eq!(name_bytes, b"encrypted_name");
    let email_bytes = bsv_rs::primitives::from_base64(email_b64).unwrap();
    assert_eq!(email_bytes, b"encrypted_email");
}

#[test]
fn test_wallet_certificate_conversion_without_signature() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields
        .insert("status".to_string(), b"approved".to_vec());

    // Do NOT sign - test unsigned conversion
    let wallet_cert = cert.to_wallet_certificate();

    assert!(
        wallet_cert.signature.is_none(),
        "Unsigned cert should have no signature in wallet format"
    );
    assert_eq!(wallet_cert.fields.len(), 1);
}

#[test]
fn test_wallet_certificate_conversion_no_revocation() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    let wallet_cert = cert.to_wallet_certificate();

    assert!(
        wallet_cert.revocation_outpoint.is_none(),
        "Certificate without revocation outpoint should preserve None"
    );
}

#[test]
fn test_wallet_certificate_conversion_empty_fields() {
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    let wallet_cert = cert.to_wallet_certificate();

    assert!(
        wallet_cert.fields.is_empty(),
        "Empty fields should be preserved"
    );
}

// =================
// Additional MasterCertificate edge case tests
// =================

#[tokio::test]
async fn test_master_certificate_issue_with_random_serial() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Bob".to_string());

    // Pass None for serial_number to get random one
    let cert1 = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields.clone(),
        [1u8; 32],
        None, // Random serial
        "test-app",
    )
    .await
    .unwrap();

    let cert2 = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        None, // Random serial
        "test-app",
    )
    .await
    .unwrap();

    // Two certificates with random serial numbers should differ
    assert_ne!(
        cert1.certificate.serial_number, cert2.certificate.serial_number,
        "Two certs with random serials should have different serial numbers"
    );

    // Both should verify
    assert!(cert1.verify().unwrap());
    assert!(cert2.verify().unwrap());
}

#[tokio::test]
async fn test_master_certificate_decrypt_with_wrong_wallet_fails() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let wrong_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let wrong_wallet = ProtoWallet::new(Some(wrong_key));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Try to decrypt with wrong wallet (not the subject)
    let result = master_cert
        .decrypt_fields(&wrong_wallet, &certifier_key.public_key(), "test-app")
        .await;

    assert!(result.is_err(), "Decrypting with wrong wallet should fail");
}

// =================
// P1-CERT-9: Self-signed certificate (certifier == subject)
// =================

#[tokio::test]
async fn test_self_signed_master_certificate() {
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    // One wallet acts as BOTH certifier and subject
    let self_key = PrivateKey::random();
    let self_wallet = ProtoWallet::new(Some(self_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Self-Certifier".to_string());
    plain_fields.insert("email".to_string(), "self@example.com".to_string());
    plain_fields.insert("role".to_string(), "admin".to_string());

    let cert_type = [0x55; 32];
    let serial_number = [0x77; 32];

    // Issue certificate to self: certifier_key == subject_key
    let master_cert = MasterCertificate::issue_for_subject(
        &self_wallet,
        &self_key,
        self_key.public_key(), // Subject IS the certifier
        plain_fields.clone(),
        cert_type,
        Some(serial_number),
        "test-app",
    )
    .await
    .unwrap();

    // Verify certificate metadata: certifier_key == subject_key
    assert_eq!(
        master_cert.certificate.certifier.to_hex(),
        master_cert.certificate.subject.to_hex(),
        "Certifier and subject should be the same key"
    );
    assert_eq!(master_cert.certificate.cert_type, cert_type);
    assert_eq!(master_cert.certificate.serial_number, serial_number);

    // Verify the signature is present and valid
    assert!(
        master_cert.certificate.signature.is_some(),
        "Self-signed certificate should have a signature"
    );
    assert!(
        master_cert.verify().unwrap(),
        "Self-signed certificate signature should be valid"
    );

    // Verify fields are encrypted (not plaintext)
    assert_eq!(master_cert.certificate.fields.len(), 3);
    for (field_name, encrypted_value) in &master_cert.certificate.fields {
        let plain_value = plain_fields[field_name].as_bytes();
        assert_ne!(
            encrypted_value,
            &plain_value.to_vec(),
            "Field '{}' should be encrypted, not plaintext",
            field_name
        );
    }

    // Subject can decrypt its own fields (same wallet used for both roles)
    let decrypted = master_cert
        .decrypt_fields(&self_wallet, &self_key.public_key(), "test-app")
        .await
        .unwrap();

    assert_eq!(decrypted.len(), 3, "Should decrypt all 3 fields");
    assert_eq!(decrypted["name"], "Self-Certifier");
    assert_eq!(decrypted["email"], "self@example.com");
    assert_eq!(decrypted["role"], "admin");

    // Also test single-field decrypt
    let name_val = master_cert
        .decrypt_field(&self_wallet, &self_key.public_key(), "name", "test-app")
        .await
        .unwrap();
    assert_eq!(name_val, "Self-Certifier");
}

// =================
// P1-CERT-10: Certificate rejection / validation failure tests
// =================

#[test]
fn test_tampered_revocation_outpoint_fails_verification() {
    // Sign a cert with a revocation outpoint, then tamper with it after signing.
    // verify() should fail because the revocation outpoint is part of the signed data.
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.revocation_outpoint = Some(bsv_rs::wallet::types::Outpoint::new([0xAA; 32], 0));
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());

    cert.sign(&certifier_key).unwrap();
    assert!(
        cert.verify().unwrap(),
        "Certificate should verify before tampering"
    );

    // Tamper with the revocation outpoint
    cert.revocation_outpoint = Some(bsv_rs::wallet::types::Outpoint::new([0xBB; 32], 5));

    let result = cert.verify().unwrap();
    assert!(
        !result,
        "Certificate verification should fail after revocation outpoint tampering"
    );
}

#[test]
fn test_verifiable_certificate_with_garbage_keyring() {
    // Create a valid signed certificate, then construct a VerifiableCertificate
    // with garbage keyring entries. The signature should still verify (keyring is
    // not part of the signed data), but attempting to decrypt should fail.
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );
    cert.fields
        .insert("name".to_string(), b"encrypted_name".to_vec());
    cert.sign(&certifier_key).unwrap();

    // Create VerifiableCertificate with garbage keyring
    let mut garbage_keyring = HashMap::new();
    garbage_keyring.insert("name".to_string(), vec![0xFF, 0xFE, 0xFD, 0xFC]);

    let verifiable = VerifiableCertificate::new(cert, garbage_keyring);

    // Signature verification should still pass (keyring is not signed)
    assert!(
        verifiable.verify().unwrap(),
        "Certificate signature should still verify with garbage keyring"
    );

    // But the keyring has garbage, so the revealable_fields still lists "name"
    let fields = verifiable.revealable_fields();
    assert_eq!(fields.len(), 1, "Should report 1 revealable field");
}

#[test]
fn test_certificate_with_empty_fields_map() {
    // Create, sign, and verify a certificate with no fields at all
    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random().public_key();

    let mut cert = Certificate::new(
        [1u8; 32],
        [2u8; 32],
        subject_key,
        certifier_key.public_key(),
    );

    // fields is already empty by default
    assert!(cert.fields.is_empty(), "Fields should start empty");

    cert.sign(&certifier_key).unwrap();
    assert!(
        cert.verify().unwrap(),
        "Certificate with empty fields should verify"
    );

    // Binary roundtrip should work with empty fields
    let binary = cert.to_binary(true);
    let decoded = Certificate::from_binary(&binary).unwrap();
    assert!(
        decoded.fields.is_empty(),
        "Decoded cert should also have empty fields"
    );
    assert!(
        decoded.verify().unwrap(),
        "Decoded cert with empty fields should verify"
    );
}

#[tokio::test]
async fn test_verifiable_certificate_garbage_keyring_decrypt_fails() {
    // Full async test: construct a properly-issued certificate, then replace the
    // keyring with garbage data and attempt to decrypt -- should error.
    use bsv_rs::auth::MasterCertificate;
    use bsv_rs::wallet::ProtoWallet;

    let certifier_key = PrivateKey::random();
    let subject_key = PrivateKey::random();
    let verifier_key = PrivateKey::random();
    let certifier_wallet = ProtoWallet::new(Some(certifier_key.clone()));
    let verifier_wallet = ProtoWallet::new(Some(verifier_key.clone()));

    let mut plain_fields = HashMap::new();
    plain_fields.insert("name".to_string(), "Alice".to_string());

    let master_cert = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        &certifier_key,
        subject_key.public_key(),
        plain_fields,
        [1u8; 32],
        Some([2u8; 32]),
        "test-app",
    )
    .await
    .unwrap();

    // Create VerifiableCertificate with garbage keyring bytes
    let mut garbage_keyring = HashMap::new();
    garbage_keyring.insert("name".to_string(), vec![0x00, 0x01, 0x02, 0x03, 0x04]);

    let mut verifiable =
        VerifiableCertificate::new(master_cert.certificate.clone(), garbage_keyring);

    // Signature still verifies
    assert!(verifiable.verify().unwrap());

    // Attempting to decrypt with garbage keyring should fail
    let result = verifiable
        .decrypt_fields(&verifier_wallet, &subject_key.public_key(), "test-app")
        .await;

    assert!(
        result.is_err(),
        "Decrypting with garbage keyring should fail"
    );
}

// =================
// Cross-SDK Compatibility Tests: TS-shaped InitialResponse
// =================
// The TypeScript SDK's Peer.processInitialRequest() sends an InitialResponse
// with initialNonce and yourNonce but WITHOUT a nonce field. The Go SDK sends
// both nonce and initialNonce. These tests verify our Rust client handles both.

#[test]
fn test_ts_style_initial_response_no_nonce_field_validates() {
    // TS SDK InitialResponse shape: { initialNonce, yourNonce, signature } — no nonce
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);
    // Only set initialNonce (not nonce) - this is what the TS SDK sends
    msg.initial_nonce = Some("responder-session-nonce".to_string());
    msg.your_nonce = Some("initiator-session-nonce".to_string());
    msg.signature = Some(vec![0x30, 0x44]);

    let result = msg.validate();
    assert!(
        result.is_ok(),
        "TS-style InitialResponse (initialNonce only, no nonce) should validate, got: {:?}",
        result.err()
    );
}

#[test]
fn test_go_style_initial_response_both_nonces_validates() {
    // Go SDK InitialResponse shape: { nonce, initialNonce, yourNonce, signature }
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);
    msg.nonce = Some("responder-nonce".to_string());
    msg.initial_nonce = Some("responder-session-nonce".to_string());
    msg.your_nonce = Some("initiator-session-nonce".to_string());
    msg.signature = Some(vec![0x30, 0x44]);

    assert!(
        msg.validate().is_ok(),
        "Go-style InitialResponse (both nonce and initialNonce) should validate"
    );
}

#[test]
fn test_initial_response_neither_nonce_nor_initial_nonce_fails() {
    // Edge case: neither nonce nor initialNonce — must fail
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);
    msg.your_nonce = Some("initiator-nonce".to_string());
    msg.signature = Some(vec![0x30, 0x44]);

    let result = msg.validate();
    assert!(
        result.is_err(),
        "InitialResponse with neither nonce nor initialNonce should fail validation"
    );
    assert!(
        result.unwrap_err().to_string().contains("nonce"),
        "Error should mention nonce"
    );
}

#[test]
fn test_ts_style_initial_response_signing_data_uses_initial_nonce() {
    // When nonce is absent, signing_data should use initial_nonce for the responder's nonce
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);

    let initiator_bytes = [1u8, 2, 3, 4];
    let responder_bytes = [5u8, 6, 7, 8];

    msg.your_nonce = Some(bsv_rs::primitives::to_base64(&initiator_bytes));
    msg.initial_nonce = Some(bsv_rs::primitives::to_base64(&responder_bytes));
    // No nonce field - TS style

    let signing_data = msg.signing_data();
    // signing_data should be: decoded(your_nonce) || decoded(initial_nonce)
    assert_eq!(
        signing_data,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        "Signing data should be initiator || responder decoded bytes"
    );
}

#[test]
fn test_ts_style_initial_response_key_id_uses_initial_nonce() {
    // get_key_id for InitialResponse uses your_nonce and initial_nonce regardless of nonce field
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);
    msg.your_nonce = Some("initiator-nonce".to_string());
    msg.initial_nonce = Some("responder-nonce".to_string());
    // No nonce field

    let key_id = msg.get_key_id(None);
    assert_eq!(
        key_id, "initiator-nonce responder-nonce",
        "Key ID should use your_nonce and initial_nonce even without nonce field"
    );
}

#[test]
fn test_initial_response_json_deserialization_ts_format() {
    // Simulate deserializing a TS SDK InitialResponse JSON (no nonce field)
    let key = PrivateKey::random().public_key();
    let json = serde_json::json!({
        "version": "0.1",
        "messageType": "initialResponse",
        "identityKey": key.to_hex(),
        "initialNonce": "dGVzdC1yZXNwb25kZXItbm9uY2U=",
        "yourNonce": "dGVzdC1pbml0aWF0b3Itbm9uY2U=",
        "signature": [0x30, 0x44, 0x02, 0x20]
    });

    let msg: AuthMessage = serde_json::from_value(json).unwrap();
    assert_eq!(msg.message_type, MessageType::InitialResponse);
    assert!(
        msg.nonce.is_none(),
        "TS-style response should have no nonce"
    );
    assert!(msg.initial_nonce.is_some(), "Should have initialNonce");
    assert!(msg.your_nonce.is_some(), "Should have yourNonce");
    assert!(msg.validate().is_ok(), "Should pass validation");
}

#[test]
fn test_initial_response_json_deserialization_go_format() {
    // Simulate deserializing a Go SDK InitialResponse JSON (has nonce field)
    let key = PrivateKey::random().public_key();
    let json = serde_json::json!({
        "version": "0.1",
        "messageType": "initialResponse",
        "identityKey": key.to_hex(),
        "nonce": "dGVzdC1yZXNwb25kZXItbm9uY2U=",
        "initialNonce": "dGVzdC1yZXNwb25kZXItbm9uY2U=",
        "yourNonce": "dGVzdC1pbml0aWF0b3Itbm9uY2U=",
        "signature": [0x30, 0x44, 0x02, 0x20]
    });

    let msg: AuthMessage = serde_json::from_value(json).unwrap();
    assert_eq!(msg.message_type, MessageType::InitialResponse);
    assert!(msg.nonce.is_some(), "Go-style response should have nonce");
    assert!(msg.initial_nonce.is_some(), "Should have initialNonce");
    assert!(msg.validate().is_ok(), "Should pass validation");
}

#[tokio::test]
async fn test_ts_style_initial_response_through_mock_transport() {
    // Simulate a TS server: receives InitialRequest, responds with InitialResponse
    // that has initialNonce and yourNonce but NO nonce field.
    use bsv_rs::auth::{Peer, PeerOptions};
    use bsv_rs::wallet::ProtoWallet;

    let client_key = PrivateKey::random();
    let server_key = PrivateKey::random();

    let transport = MockTransport::new();

    let client_wallet = ProtoWallet::new(Some(client_key.clone()));
    let client = Peer::new(PeerOptions {
        wallet: client_wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("cross-sdk-test".into()),
    });
    client.start();

    // The mock transport's set_callback uses tokio::spawn, give it time
    tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

    // We can't easily inject a TS-shaped response through the mock transport's
    // queue_response because the Peer.start() callback processes it. But we can
    // test directly via handle_incoming_message with a TS-shaped response.

    // First, manually create a session as if we had sent an InitialRequest
    let our_nonce = "dGVzdC1jbGllbnQtbm9uY2U=".to_string(); // base64 of test data
    {
        let mut mgr = client.session_manager().write().await;
        let session = PeerSession::with_nonce(our_nonce.clone());
        mgr.add_session(session).unwrap();
    }

    // Craft a TS-style InitialResponse (no nonce field)
    let server_nonce = bsv_rs::primitives::to_base64(&[0xBB; 32]);
    let mut ts_response = AuthMessage::new(MessageType::InitialResponse, server_key.public_key());
    ts_response.initial_nonce = Some(server_nonce.clone());
    ts_response.your_nonce = Some(our_nonce.clone());
    // nonce is NOT set - this is the TS SDK behavior
    ts_response.signature = Some(vec![0x30, 0x44]); // Fake sig - verification will fail

    // handle_incoming_message should NOT fail with "missing nonce"
    let result = client.handle_incoming_message(ts_response).await;

    // The signature verification will fail (fake sig), but the important thing
    // is that we don't get "InitialResponse missing nonce" error
    match result {
        Ok(_) => {} // Unlikely with fake sig, but not an error
        Err(e) => {
            let err_msg = e.to_string();
            assert!(
                !err_msg.contains("missing nonce"),
                "Should NOT fail with 'missing nonce' for TS-style response. Got: {}",
                err_msg
            );
            // Expected: signature verification failure (since we used a fake sig)
            assert!(
                err_msg.contains("signature") || err_msg.contains("Signature"),
                "Expected signature error for fake sig, got: {}",
                err_msg
            );
        }
    }
}

#[test]
fn test_initial_response_missing_both_nonces_fails_validation() {
    // When both nonce and initial_nonce are absent, validation must fail.
    // This is the condition that previously caused "InitialResponse missing nonce"
    // errors when connecting to TS SDK servers (which only send initialNonce).
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key);
    msg.your_nonce = Some("some-client-nonce".to_string());
    // Neither nonce nor initial_nonce set
    msg.signature = Some(vec![0x30, 0x44]);

    let result = msg.validate();
    assert!(
        result.is_err(),
        "Should fail when both nonce and initial_nonce are missing"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("nonce or initial_nonce"),
        "Error should mention both fields, got: {}",
        err_msg
    );
}

// =================
// Regression: field presence requirements by message type
// =================

#[test]
fn test_initial_request_only_needs_initial_nonce() {
    // TS/Go SDKs: InitialRequest has initialNonce only (no nonce, no signature)
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::InitialRequest, key);
    msg.initial_nonce = Some("test-nonce".to_string());
    assert!(msg.validate().is_ok());
}

#[test]
fn test_general_message_needs_signature_only() {
    // General messages need signature; nonce/your_nonce optional per spec
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::General, key);
    msg.signature = Some(vec![0x30, 0x44]);
    assert!(msg.validate().is_ok());
}

#[test]
fn test_certificate_request_needs_requested_certificates() {
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::CertificateRequest, key);
    assert!(msg.validate().is_err());

    msg.requested_certificates = Some(RequestedCertificateSet::new());
    assert!(msg.validate().is_ok());
}

#[test]
fn test_certificate_response_needs_certificates() {
    let key = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::CertificateResponse, key);
    assert!(msg.validate().is_err());

    msg.certificates = Some(vec![]);
    assert!(msg.validate().is_ok());
}
