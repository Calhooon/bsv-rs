#![cfg(test)]
//! `Peer`'s unit tests, moved from `peer.rs` (#294).

use super::*;
use crate::auth::transports::MockTransport;
use crate::primitives::PrivateKey;
use crate::wallet::ProtoWallet;

fn make_peer() -> Peer<ProtoWallet, MockTransport> {
    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let transport = MockTransport::new();
    Peer::new(PeerOptions {
        wallet,
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    })
}

#[tokio::test]
async fn test_peer_creation() {
    let peer = make_peer();
    let identity = peer.get_identity_key().await.unwrap();
    assert_eq!(identity.to_compressed().len(), 33);
}

#[tokio::test]
async fn test_listener_registration() {
    let peer = make_peer();

    let id = peer
        .listen_for_general_messages(|_sender, _payload| Box::pin(async { Ok(()) }))
        .await;
    assert!(id > 0);

    peer.stop_listening_for_general_messages(id).await;
}

#[tokio::test]
async fn test_session_manager_access() {
    let peer = make_peer();
    let mgr = peer.session_manager.read().await;
    assert!(mgr.is_empty());
}

/// The validator both certificate paths call refuses an empty list and more
/// than 100 certificates in `validateCertificates`' words, before any
/// certificate is verified (`validateCertificates.ts:73-78`; #445). Through
/// the Peer the intake's bound is met earlier (`auth_peer_certificate_paths_445`).
#[tokio::test]
async fn the_shared_certificate_validator_bounds_the_list_before_verifying() {
    use crate::auth::certificates::{Certificate, VerifiableCertificate};

    let peer = make_peer();
    let sender = PrivateKey::random().public_key();
    let unsigned = VerifiableCertificate::new(
        Certificate::new([1; 32], [2; 32], sender.clone(), sender.clone()),
        Default::default(),
    );
    let mut message = AuthMessage::new(MessageType::CertificateResponse, sender);
    let refusal = |words: &str| Err(Error::AuthError(words.into()));
    message.set_certificates(Vec::new());
    assert_eq!(
        peer.validate_received_certificates(&message, None).await,
        refusal("No certificates were provided in the AuthMessage.")
    );
    message.set_certificates(vec![unsigned.clone(); 101]);
    assert_eq!(
        peer.validate_received_certificates(&message, None).await,
        refusal("AuthMessage cannot contain more than 100 certificates.")
    );
    message.set_certificates(vec![unsigned; 100]);
    assert_eq!(
        peer.validate_received_certificates(&message, None).await,
        refusal(
            "The signature for the certificate with serial number AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI= is invalid!"
        )
    );
}
