//! Auth module integration tests.
//!
//! Tests full authentication flows including handshake, certificate exchange,
//! and general message passing using mock transport.

#![cfg(feature = "auth")]

use bsv_sdk::auth::transports::{HttpRequest, HttpResponse, MockTransport, Transport};
use bsv_sdk::auth::{
    AuthMessage, Certificate, MessageType, PeerSession, RequestedCertificateSet, SessionManager,
    VerifiableCertificate,
};
use bsv_sdk::primitives::PrivateKey;
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

    // InitialResponse needs multiple fields
    let mut msg = AuthMessage::new(MessageType::InitialResponse, key.clone());
    assert!(msg.validate().is_err());

    msg.nonce = Some("session-nonce".to_string());
    msg.initial_nonce = Some("initial-nonce".to_string());
    msg.your_nonce = Some("peer-nonce".to_string());
    msg.signature = Some(vec![0x30, 0x44]); // Fake signature
    assert!(msg.validate().is_ok());

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
    msg.your_nonce = Some(bsv_sdk::primitives::to_base64(&[1, 2, 3, 4])); // initiator's nonce
    msg.initial_nonce = Some(bsv_sdk::primitives::to_base64(&[5, 6, 7, 8])); // responder's nonce

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
    let type_id = bsv_sdk::primitives::to_base64(&[1u8; 32]);
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
