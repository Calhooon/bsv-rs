//! Peer mutual authentication end-to-end handshake tests.
//!
//! Tests the full BRC-31 authentication flow between two Peer instances
//! connected via channel-based loopback transports. These tests verify:
//! - Basic mutual authentication (no certificates)
//! - Message exchange after authentication
//! - Session persistence across multiple messages
//! - Certificate request and response flows
//! - Bidirectional certificate exchange
//! - Error handling for invalid auth version
//! - General message callback invocation
//! - Certificate request callback invocation

#![cfg(feature = "auth")]

use async_trait::async_trait;
use bsv_sdk::auth::transports::{Transport, TransportCallback};
use bsv_sdk::auth::{
    AuthMessage, Certificate, MessageType, Peer, PeerOptions, RequestedCertificateSet,
    VerifiableCertificate,
};
use bsv_sdk::primitives::PrivateKey;
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// =============================================================================
// ChannelTransport: sends messages to an mpsc channel, receives via callback
// =============================================================================

/// A transport that sends messages into an mpsc channel.
/// Messages are routed to the receiving peer by an external task.
struct ChannelTransport {
    sender: mpsc::UnboundedSender<AuthMessage>,
    callback: Arc<std::sync::RwLock<Option<Box<TransportCallback>>>>,
}

impl ChannelTransport {
    fn new(sender: mpsc::UnboundedSender<AuthMessage>) -> Self {
        Self {
            sender,
            callback: Arc::new(std::sync::RwLock::new(None)),
        }
    }
}

#[async_trait]
impl Transport for ChannelTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.sender
            .send(message.clone())
            .map_err(|e| bsv_sdk::Error::AuthError(format!("Channel send failed: {}", e)))?;
        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        let mut cb = self
            .callback
            .write()
            .expect("Failed to acquire callback lock");
        *cb = Some(callback);
    }

    fn clear_callback(&self) {
        let mut cb = self
            .callback
            .write()
            .expect("Failed to acquire callback lock");
        *cb = None;
    }
}

// =============================================================================
// Helper: create a connected peer pair with routing tasks
// =============================================================================

/// Creates two Peers connected by channel-based transports.
/// Spawns background tasks that route messages between them via handle_incoming_message.
///
/// Returns (alice_peer, bob_peer) both wrapped in Arc for shared access.
async fn create_connected_peers(
    alice_key: &PrivateKey,
    bob_key: &PrivateKey,
    alice_certs_to_request: Option<RequestedCertificateSet>,
    bob_certs_to_request: Option<RequestedCertificateSet>,
) -> (
    Arc<Peer<ProtoWallet, ChannelTransport>>,
    Arc<Peer<ProtoWallet, ChannelTransport>>,
) {
    // Create bidirectional channels
    let (alice_tx, mut alice_rx) = mpsc::unbounded_channel::<AuthMessage>();
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel::<AuthMessage>();

    // Create transports: Alice sends to bob_tx, Bob sends to alice_tx
    let alice_transport = ChannelTransport::new(bob_tx);
    let bob_transport = ChannelTransport::new(alice_tx);

    // Create peers
    let alice_wallet = ProtoWallet::new(Some(alice_key.clone()));
    let alice = Arc::new(Peer::new(PeerOptions {
        wallet: alice_wallet,
        transport: alice_transport,
        certificates_to_request: alice_certs_to_request,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    }));

    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let bob = Arc::new(Peer::new(PeerOptions {
        wallet: bob_wallet,
        transport: bob_transport,
        certificates_to_request: bob_certs_to_request,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    }));

    // Spawn routing task: messages from Alice's channel go to Alice's handle_incoming_message
    let alice_clone = alice.clone();
    tokio::spawn(async move {
        while let Some(msg) = alice_rx.recv().await {
            if let Err(e) = alice_clone.handle_incoming_message(msg).await {
                eprintln!("Alice routing error: {}", e);
            }
        }
    });

    // Spawn routing task: messages from Bob's channel go to Bob's handle_incoming_message
    let bob_clone = bob.clone();
    tokio::spawn(async move {
        while let Some(msg) = bob_rx.recv().await {
            if let Err(e) = bob_clone.handle_incoming_message(msg).await {
                eprintln!("Bob routing error: {}", e);
            }
        }
    });

    // Small delay to let routing tasks start
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    (alice, bob)
}

/// Creates a simple connected peer pair with no certificate requirements.
async fn create_simple_peers(
    alice_key: &PrivateKey,
    bob_key: &PrivateKey,
) -> (
    Arc<Peer<ProtoWallet, ChannelTransport>>,
    Arc<Peer<ProtoWallet, ChannelTransport>>,
) {
    create_connected_peers(alice_key, bob_key, None, None).await
}

/// Small delay to let async tasks complete.
async fn settle() {
    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
}

// =============================================================================
// Test 1: Basic mutual authentication with no certificates
// =============================================================================

/// Two peers authenticate without requesting any certificates.
/// Alice initiates a handshake with Bob. Both sides end up with authenticated sessions.
#[tokio::test]
async fn test_basic_mutual_auth_no_certificates() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    // Set up Bob's listener for general messages
    let received_payload: Arc<RwLock<Option<Vec<u8>>>> = Arc::new(RwLock::new(None));
    let received_clone = received_payload.clone();
    bob.listen_for_general_messages(move |_sender, payload| {
        let received = received_clone.clone();
        Box::pin(async move {
            let mut r = received.write().await;
            *r = Some(payload);
            Ok(())
        })
    })
    .await;

    // Alice sends message to Bob (this triggers the handshake internally)
    alice
        .to_peer(b"Hello Bob!", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    // Small delay for the general message to be routed through Bob
    settle().await;

    // Verify Bob received the message
    let payload = received_payload.read().await;
    assert_eq!(payload.as_deref(), Some(b"Hello Bob!".as_slice()));

    // Verify Alice has an authenticated session
    let alice_mgr = alice.session_manager().read().await;
    let alice_session = alice_mgr.get_session(&bob_hex);
    assert!(
        alice_session.is_some(),
        "Alice should have a session with Bob"
    );
    assert!(
        alice_session.unwrap().is_authenticated,
        "Alice's session should be authenticated"
    );
}

// =============================================================================
// Test 2: Bidirectional message exchange after auth
// =============================================================================

/// After successful auth, both peers can exchange messages in both directions.
#[tokio::test]
async fn test_bidirectional_message_exchange() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();
    let alice_hex = alice.get_identity_key().await.unwrap().to_hex();

    // Set up listeners
    let bob_received: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(Vec::new()));
    let bob_received_clone = bob_received.clone();
    bob.listen_for_general_messages(move |_sender, payload| {
        let received = bob_received_clone.clone();
        Box::pin(async move {
            received.write().await.push(payload);
            Ok(())
        })
    })
    .await;

    let alice_received: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(Vec::new()));
    let alice_received_clone = alice_received.clone();
    alice
        .listen_for_general_messages(move |_sender, payload| {
            let received = alice_received_clone.clone();
            Box::pin(async move {
                received.write().await.push(payload);
                Ok(())
            })
        })
        .await;

    // Alice sends to Bob (triggers handshake)
    alice
        .to_peer(b"Hello Bob!", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Bob responds to Alice (uses existing session)
    bob.to_peer(b"Hello Alice!", Some(&alice_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Verify messages
    let bob_msgs = bob_received.read().await;
    assert_eq!(bob_msgs.len(), 1);
    assert_eq!(bob_msgs[0], b"Hello Bob!");

    let alice_msgs = alice_received.read().await;
    assert_eq!(alice_msgs.len(), 1);
    assert_eq!(alice_msgs[0], b"Hello Alice!");
}

// =============================================================================
// Test 3: Session persistence - multiple messages over established session
// =============================================================================

/// After a session is established, multiple messages can be sent without re-handshaking.
#[tokio::test]
async fn test_session_persistence_multiple_messages() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    let bob_received: Arc<RwLock<Vec<Vec<u8>>>> = Arc::new(RwLock::new(Vec::new()));
    let bob_received_clone = bob_received.clone();
    bob.listen_for_general_messages(move |_sender, payload| {
        let received = bob_received_clone.clone();
        Box::pin(async move {
            received.write().await.push(payload);
            Ok(())
        })
    })
    .await;

    // Send first message (triggers handshake)
    alice
        .to_peer(b"Message 1", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Send additional messages (reuse session, no handshake)
    alice
        .to_peer(b"Message 2", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    alice
        .to_peer(b"Message 3", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Verify all messages received
    let msgs = bob_received.read().await;
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0], b"Message 1");
    assert_eq!(msgs[1], b"Message 2");
    assert_eq!(msgs[2], b"Message 3");

    // Verify only one session was created (no re-handshaking)
    let mgr = alice.session_manager().read().await;
    assert_eq!(
        mgr.len(),
        1,
        "Alice should have exactly one session with Bob"
    );
}

// =============================================================================
// Test 4: get_authenticated_session establishes session
// =============================================================================

/// Calling get_authenticated_session explicitly initiates the handshake
/// without sending a general message.
#[tokio::test]
async fn test_get_authenticated_session() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    // Explicitly get authenticated session (handshake only, no message)
    let session = alice
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    assert!(
        session.is_authenticated,
        "Session should be authenticated after handshake"
    );
    assert!(
        session.peer_identity_key.is_some(),
        "Session should have peer identity key"
    );
    assert_eq!(
        session.peer_identity_key.unwrap().to_hex(),
        bob_hex,
        "Peer identity key should match Bob's key"
    );
}

// =============================================================================
// Test 5: Invalid auth version is rejected
// =============================================================================

/// Sending a message with an invalid auth version should be rejected by the receiver.
#[tokio::test]
async fn test_invalid_auth_version_rejected() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    // Create Bob standalone (just need handle_incoming_message)
    let (bob_tx, _bob_rx) = mpsc::unbounded_channel::<AuthMessage>();
    let bob_transport = ChannelTransport::new(bob_tx);
    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let bob = Peer::new(PeerOptions {
        wallet: bob_wallet,
        transport: bob_transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    // Craft a message with an invalid version and deliver it directly
    let alice_pub = alice_key.public_key();
    let mut bad_msg = AuthMessage::new(MessageType::InitialRequest, alice_pub);
    bad_msg.version = "99.0".to_string();
    bad_msg.initial_nonce = Some("test".to_string());

    let result = bob.handle_incoming_message(bad_msg).await;
    assert!(result.is_err(), "Invalid auth version should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid auth version"),
        "Error should mention invalid version, got: {}",
        err_msg
    );
}

// =============================================================================
// Test 6: handle_incoming_message processes InitialRequest correctly
// =============================================================================

/// When Bob receives an InitialRequest via handle_incoming_message, he creates
/// a session and sends an InitialResponse back through the transport.
#[tokio::test]
async fn test_handle_initial_request_creates_session() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    // Create Bob with a channel transport so we can capture sent messages
    let (bob_tx, mut bob_rx) = mpsc::unbounded_channel::<AuthMessage>();
    let bob_transport = ChannelTransport::new(bob_tx);
    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let bob = Peer::new(PeerOptions {
        wallet: bob_wallet,
        transport: bob_transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    // Create an InitialRequest from Alice
    let alice_pub = alice_key.public_key();
    let mut initial_request = AuthMessage::new(MessageType::InitialRequest, alice_pub.clone());
    initial_request.initial_nonce = Some(bsv_sdk::primitives::to_base64(&[0xAA; 32]));

    // Deliver to Bob directly via handle_incoming_message
    bob.handle_incoming_message(initial_request).await.unwrap();

    // Bob should have created a session
    let mgr = bob.session_manager().read().await;
    let sessions: Vec<_> = mgr.iter().collect();
    assert!(
        !sessions.is_empty(),
        "Bob should have at least one session after processing InitialRequest"
    );

    // The session should have Alice's identity key
    let session = sessions[0];
    assert_eq!(
        session.peer_identity_key.as_ref().unwrap().to_hex(),
        alice_pub.to_hex()
    );
    assert!(session.is_authenticated);

    // Bob should have sent an InitialResponse via his transport
    let response = bob_rx.try_recv();
    assert!(response.is_ok(), "Bob should have sent an InitialResponse");
    assert_eq!(response.unwrap().message_type, MessageType::InitialResponse);
}

// =============================================================================
// Test 7: Listener registration and deregistration
// =============================================================================

/// Test that listener callbacks can be registered and deregistered.
#[tokio::test]
async fn test_listener_registration_and_deregistration() {
    let key = PrivateKey::random();
    let (tx, _rx) = mpsc::unbounded_channel::<AuthMessage>();
    let transport = ChannelTransport::new(tx);
    let wallet = ProtoWallet::new(Some(key.clone()));
    let peer = Peer::new(PeerOptions {
        wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    // Register general message listener
    let id1 = peer
        .listen_for_general_messages(|_sender, _payload| Box::pin(async { Ok(()) }))
        .await;
    assert!(id1 > 0);

    let id2 = peer
        .listen_for_general_messages(|_sender, _payload| Box::pin(async { Ok(()) }))
        .await;
    assert!(id2 > id1, "Second callback should have higher ID");

    // Deregister
    peer.stop_listening_for_general_messages(id1).await;

    // Register certificate listeners
    let cert_id = peer
        .listen_for_certificates_received(|_sender, _certs| Box::pin(async { Ok(()) }))
        .await;
    assert!(cert_id > 0);
    peer.stop_listening_for_certificates_received(cert_id).await;

    let req_id = peer
        .listen_for_certificates_requested(|_sender, _req| Box::pin(async { Ok(()) }))
        .await;
    assert!(req_id > 0);
    peer.stop_listening_for_certificates_requested(req_id).await;
}

// =============================================================================
// Test 8: Identity key consistency
// =============================================================================

/// The identity key returned by Peer should match the wallet's identity key,
/// and repeated calls should return the same cached value.
#[tokio::test]
async fn test_identity_key_consistency() {
    let key = PrivateKey::random();
    let expected_pub = key.public_key();
    let (tx, _rx) = mpsc::unbounded_channel::<AuthMessage>();
    let transport = ChannelTransport::new(tx);
    let wallet = ProtoWallet::new(Some(key.clone()));
    let peer = Peer::new(PeerOptions {
        wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    let identity = peer.get_identity_key().await.unwrap();
    assert_eq!(identity.to_hex(), expected_pub.to_hex());

    // Call again to test caching
    let identity2 = peer.get_identity_key().await.unwrap();
    assert_eq!(identity.to_hex(), identity2.to_hex());
}

// =============================================================================
// Test 9: Two separate handshakes with different peers
// =============================================================================

/// Alice can authenticate with both Bob and Carol independently,
/// establishing separate sessions.
#[tokio::test]
async fn test_multiple_peer_sessions() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();
    let carol_key = PrivateKey::random();

    // Alice <-> Bob
    let (alice_for_bob, bob) = create_simple_peers(&alice_key, &bob_key).await;

    // Alice <-> Carol (separate instance of alice with same key)
    let (alice_for_carol, carol) = create_simple_peers(&alice_key, &carol_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();
    let carol_hex = carol.get_identity_key().await.unwrap().to_hex();

    // Authenticate with Bob
    let session_bob = alice_for_bob
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();
    assert!(session_bob.is_authenticated);

    // Authenticate with Carol
    let session_carol = alice_for_carol
        .get_authenticated_session(Some(&carol_hex), Some(5000))
        .await
        .unwrap();
    assert!(session_carol.is_authenticated);

    // Both sessions are distinct
    assert_ne!(
        session_bob.session_nonce, session_carol.session_nonce,
        "Sessions with different peers should have different nonces"
    );
}

// =============================================================================
// Test 10: Certificate request callback is invoked
// =============================================================================

/// When Alice sends a certificate request to Bob (after auth), Bob's
/// certificate request callback should fire with the request details.
#[tokio::test]
async fn test_certificate_request_callback_invoked() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    // Set up Bob's certificate request callback
    let cert_request_received: Arc<RwLock<Option<RequestedCertificateSet>>> =
        Arc::new(RwLock::new(None));
    let cert_request_clone = cert_request_received.clone();
    bob.listen_for_certificates_requested(move |_sender, requested| {
        let cert_req = cert_request_clone.clone();
        Box::pin(async move {
            let mut r = cert_req.write().await;
            *r = Some(requested);
            Ok(())
        })
    })
    .await;

    // First authenticate
    alice
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    // Then request certificates
    let certifier_key = PrivateKey::random().public_key();
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier(certifier_key.to_hex());
    requested.add_type(
        bsv_sdk::primitives::to_base64(&[1u8; 32]),
        vec!["name".to_string(), "email".to_string()],
    );

    alice
        .request_certificates(requested.clone(), Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Verify Bob received the certificate request
    let received = cert_request_received.read().await;
    assert!(
        received.is_some(),
        "Bob should have received a certificate request"
    );
    let req = received.as_ref().unwrap();
    assert_eq!(req.certifiers.len(), 1);
    assert_eq!(req.certifiers[0], certifier_key.to_hex());
}

// =============================================================================
// Test 11: Certificate response flow
// =============================================================================

/// After authentication, Bob can send a certificate response to Alice,
/// and Alice's certificate received callback is invoked.
#[tokio::test]
async fn test_certificate_response_flow() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();
    let certifier_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();
    let alice_hex = alice.get_identity_key().await.unwrap().to_hex();

    // Set up Alice's certificate received callback
    let certs_received: Arc<RwLock<Vec<VerifiableCertificate>>> = Arc::new(RwLock::new(Vec::new()));
    let certs_clone = certs_received.clone();
    alice
        .listen_for_certificates_received(move |_sender, certs| {
            let received = certs_clone.clone();
            Box::pin(async move {
                let mut r = received.write().await;
                r.extend(certs);
                Ok(())
            })
        })
        .await;

    // Authenticate Alice with Bob
    alice
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    // Create a certificate for Bob (signed by certifier)
    let bob_pub = bob.get_identity_key().await.unwrap();
    let mut cert = Certificate::new([1u8; 32], [2u8; 32], bob_pub, certifier_key.public_key());
    cert.fields
        .insert("name".to_string(), b"encrypted_bob".to_vec());
    cert.sign(&certifier_key).unwrap();

    let keyring = HashMap::new();
    let verifiable = VerifiableCertificate::new(cert, keyring);

    // Bob sends certificate response to Alice
    bob.send_certificate_response(&alice_hex, vec![verifiable.clone()])
        .await
        .unwrap();

    settle().await;

    // Verify Alice received the certificate
    let received = certs_received.read().await;
    assert_eq!(
        received.len(),
        1,
        "Alice should have received one certificate"
    );
    assert_eq!(
        received[0].certificate.certifier.to_hex(),
        certifier_key.public_key().to_hex()
    );
}

// =============================================================================
// Test 12: General message callback with sender identity
// =============================================================================

/// Verify that the general message callback receives the correct sender identity key.
#[tokio::test]
async fn test_general_message_callback_sender_identity() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();
    let alice_identity = alice.get_identity_key().await.unwrap();

    // Bob listens and checks sender identity
    let sender_key_received: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let sender_clone = sender_key_received.clone();
    bob.listen_for_general_messages(move |sender, _payload| {
        let sender_key = sender_clone.clone();
        Box::pin(async move {
            let mut s = sender_key.write().await;
            *s = Some(sender.to_hex());
            Ok(())
        })
    })
    .await;

    // Alice sends to Bob
    alice
        .to_peer(b"Hello!", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    // Verify sender identity
    let sender = sender_key_received.read().await;
    assert_eq!(
        sender.as_deref(),
        Some(alice_identity.to_hex().as_str()),
        "Bob should see Alice as the sender"
    );
}

// =============================================================================
// Test 13: Empty payload message
// =============================================================================

/// Sending an empty payload should still work correctly through the auth flow.
#[tokio::test]
async fn test_empty_payload_message() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    let bob_received: Arc<RwLock<Option<Vec<u8>>>> = Arc::new(RwLock::new(None));
    let bob_clone = bob_received.clone();
    bob.listen_for_general_messages(move |_sender, payload| {
        let received = bob_clone.clone();
        Box::pin(async move {
            let mut r = received.write().await;
            *r = Some(payload);
            Ok(())
        })
    })
    .await;

    // Send empty payload
    alice
        .to_peer(b"", Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    let received = bob_received.read().await;
    assert_eq!(received.as_deref(), Some(b"".as_slice()));
}

// =============================================================================
// Test 14: Large payload message
// =============================================================================

/// Verify that large payloads are transmitted correctly through the auth flow.
#[tokio::test]
async fn test_large_payload_message() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

    let bob_received: Arc<RwLock<Option<Vec<u8>>>> = Arc::new(RwLock::new(None));
    let bob_clone = bob_received.clone();
    bob.listen_for_general_messages(move |_sender, payload| {
        let received = bob_clone.clone();
        Box::pin(async move {
            let mut r = received.write().await;
            *r = Some(payload);
            Ok(())
        })
    })
    .await;

    // Send large payload (100 KB)
    let large_data = vec![0xAB; 100_000];
    alice
        .to_peer(&large_data, Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    settle().await;

    let received = bob_received.read().await;
    assert!(received.is_some());
    assert_eq!(received.as_ref().unwrap().len(), 100_000);
    assert_eq!(received.as_ref().unwrap()[0], 0xAB);
}

// =============================================================================
// Test 15: Session nonce uniqueness
// =============================================================================

/// Each new handshake should produce a unique session nonce.
#[tokio::test]
async fn test_session_nonce_uniqueness() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    // First handshake
    let (alice1, bob1) = create_simple_peers(&alice_key, &bob_key).await;
    let bob_hex = bob1.get_identity_key().await.unwrap().to_hex();

    let session1 = alice1
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    // Second handshake (fresh peers)
    let (alice2, _bob2) = create_simple_peers(&alice_key, &bob_key).await;

    let session2 = alice2
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    assert_ne!(
        session1.session_nonce, session2.session_nonce,
        "Different handshakes should produce different session nonces"
    );
}

// =============================================================================
// Test 16: General message without session fails
// =============================================================================

/// Receiving a General message without an existing session should fail.
#[tokio::test]
async fn test_general_message_without_session_fails() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (bob_tx, _bob_rx) = mpsc::unbounded_channel::<AuthMessage>();
    let bob_transport = ChannelTransport::new(bob_tx);
    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let bob = Peer::new(PeerOptions {
        wallet: bob_wallet,
        transport: bob_transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    // Create a General message from Alice without prior handshake
    let alice_pub = alice_key.public_key();
    let mut msg = AuthMessage::new(MessageType::General, alice_pub);
    msg.nonce = Some("some-nonce".to_string());
    msg.payload = Some(b"Hello".to_vec());
    msg.signature = Some(vec![0x30, 0x44]); // Fake DER

    let result = bob.handle_incoming_message(msg).await;
    assert!(
        result.is_err(),
        "General message without a session should fail"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("No session") || err_msg.contains("session"),
        "Error should mention missing session, got: {}",
        err_msg
    );
}

// =============================================================================
// Test 17: Certificate request without existing session fails
// =============================================================================

/// Sending a certificate request without an existing session should fail.
#[tokio::test]
async fn test_certificate_request_without_session_fails() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (bob_tx, _bob_rx) = mpsc::unbounded_channel::<AuthMessage>();
    let bob_transport = ChannelTransport::new(bob_tx);
    let bob_wallet = ProtoWallet::new(Some(bob_key.clone()));
    let bob = Peer::new(PeerOptions {
        wallet: bob_wallet,
        transport: bob_transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("e2e-test".into()),
    });

    // Create a CertificateRequest from Alice without prior handshake
    let alice_pub = alice_key.public_key();
    let mut msg = AuthMessage::new(MessageType::CertificateRequest, alice_pub);
    msg.nonce = Some("some-nonce".to_string());
    msg.requested_certificates = Some(RequestedCertificateSet::new());
    msg.signature = Some(vec![0x30, 0x44]); // Fake

    let result = bob.handle_incoming_message(msg).await;
    assert!(
        result.is_err(),
        "Certificate request without a session should fail"
    );
}

// =============================================================================
// Test 18: Random key handshake stress test
// =============================================================================

/// Verify that randomly generated keys can complete the handshake successfully.
/// Runs 5 rounds to check for any timing or randomness issues.
#[tokio::test]
async fn test_random_key_handshake() {
    for i in 0..5 {
        let alice_key = PrivateKey::random();
        let bob_key = PrivateKey::random();

        let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

        let bob_hex = bob.get_identity_key().await.unwrap().to_hex();

        let session = alice
            .get_authenticated_session(Some(&bob_hex), Some(5000))
            .await
            .unwrap_or_else(|e| panic!("Round {}: handshake failed: {}", i, e));

        assert!(session.is_authenticated, "Round {}: not authenticated", i);
    }
}

// =============================================================================
// Test 19: Both peers have sessions after handshake
// =============================================================================

/// After a handshake initiated by Alice, both Alice and Bob should have
/// authenticated sessions referencing each other.
#[tokio::test]
async fn test_both_peers_have_sessions_after_handshake() {
    let alice_key = PrivateKey::random();
    let bob_key = PrivateKey::random();

    let (alice, bob) = create_simple_peers(&alice_key, &bob_key).await;

    let bob_identity = bob.get_identity_key().await.unwrap();
    let bob_hex = bob_identity.to_hex();
    let alice_identity = alice.get_identity_key().await.unwrap();
    let alice_hex = alice_identity.to_hex();

    // Alice initiates handshake
    alice
        .get_authenticated_session(Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    // Check Alice's session manager
    let alice_mgr = alice.session_manager().read().await;
    let alice_session = alice_mgr.get_session(&bob_hex);
    assert!(
        alice_session.is_some(),
        "Alice should have a session indexed by Bob's key"
    );
    assert!(alice_session.unwrap().is_authenticated);
    drop(alice_mgr);

    // Check Bob's session manager
    let bob_mgr = bob.session_manager().read().await;
    let bob_session = bob_mgr.get_session(&alice_hex);
    assert!(
        bob_session.is_some(),
        "Bob should have a session indexed by Alice's key"
    );
    assert!(bob_session.unwrap().is_authenticated);
}
