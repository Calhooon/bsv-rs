#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::auth::PeerSession;

fn recorded() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../tests/vectors/auth_peer_nonces_362_364.json"
    ))
    .unwrap()
}

#[test]
fn signed_nonce_capacity_fails_closed_and_session_removal_releases_claims_362() {
    let mut manager = SessionManager::new();
    manager
        .add_session(PeerSession::with_nonce("session".into()))
        .unwrap();
    for i in 0..MAX_MESSAGE_NONCES {
        assert!(manager
            .claim_message_nonce("session", &i.to_string())
            .unwrap());
    }
    assert_eq!(
        manager.claim_message_nonce("session", "overflow"),
        Err(Error::AuthError(
            recorded()["store"]["capacity"].as_str().unwrap().into()
        ))
    );
    assert_eq!(
        manager.claim_message_nonce("session", "0").unwrap(),
        recorded()["store"]["replayAtCapacity"]
    );
    manager.remove_by_nonce("session");
    manager
        .add_session(PeerSession::with_nonce("session".into()))
        .unwrap();
    assert_eq!(
        manager.claim_message_nonce("session", "0").unwrap(),
        recorded()["store"]["afterRemoval"]
    );
}

#[test]
fn initial_nonce_window_expires_and_evicts_the_oldest_for_an_identity_362() {
    let mut claims = NonceClaims::default();
    let v = &recorded()["store"];
    assert!(claims.claim_initial("alice", "first", 1000));
    assert_eq!(claims.claim_initial("alice", "first", 1000), v["duplicate"]);
    assert_eq!(
        claims.claim_initial("alice", "first", 1000 + IDLE_MS - 1),
        v["beforeExpiry"]
    );
    assert_eq!(
        claims.claim_initial("alice", "first", 1000 + IDLE_MS),
        v["atExpiry"]
    );
    for i in 0..MAX_INITIAL_PER_IDENTITY {
        assert!(claims.claim_initial("bob", &i.to_string(), 1000 + IDLE_MS));
    }
    assert!(claims.claim_initial("bob", "overflow", 1000 + IDLE_MS));
    assert_eq!(
        claims.claim_initial("bob", "0", 1000 + IDLE_MS),
        v["perIdentityEviction"]
    );
    assert_eq!(
        claims.initial_by_identity["bob"].len(),
        MAX_INITIAL_PER_IDENTITY
    );
    claims.prune_initial(1000 + 2 * IDLE_MS);
    assert!(claims.initial.is_empty());
    assert!(claims.initial_order.is_empty());
    assert!(claims.initial_by_identity.is_empty());
}

#[test]
fn initial_nonce_global_window_evicts_the_oldest_claim_362() {
    let mut claims = NonceClaims::default();
    for i in 0..MAX_INITIAL_NONCES {
        assert!(claims.claim_initial(&format!("peer{}", i / 256), &i.to_string(), 1000));
    }
    assert!(claims.claim_initial("newPeer", "newNonce", 1000));
    assert_eq!(
        claims.claim_initial("peer0", "0", 1000),
        recorded()["store"]["globalEviction"]
    );
    assert_eq!(claims.initial.len(), MAX_INITIAL_NONCES);
    assert_eq!(claims.initial_order.len(), MAX_INITIAL_NONCES);
}

#[test]
fn signed_claims_follow_the_session_idle_lifetime_and_initial_claims_survive_removal_362() {
    let mut manager = SessionManager::new();
    let session = PeerSession::with_nonce("session".into());
    manager.add_session(session.clone()).unwrap();
    assert!(manager.claim_message_nonce("session", "signed").unwrap());
    assert!(manager
        .claim_initial_request_nonce("alice", "initial")
        .unwrap());
    manager.remove_session(&session);
    assert!(!manager
        .claim_initial_request_nonce("alice", "initial")
        .unwrap());
    let mut old = PeerSession::with_nonce("old".into());
    old.last_update = current_time_ms() - IDLE_MS;
    manager.add_session(old).unwrap();
    assert_eq!(
        manager.claim_message_nonce("old", "signed"),
        Err(Error::AuthError("Session not found for nonce: old".into()))
    );
    assert!(!manager.has_session("old"));
    manager.clear();
    assert!(manager
        .claim_initial_request_nonce("alice", "initial")
        .unwrap());
}
