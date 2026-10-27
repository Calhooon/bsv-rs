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
