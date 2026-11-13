//! The three auth option records are built through `new`/`Default` and their
//! `with_` setters (#843d8a): `new`'s values, every setter, and `Default`
//! unchanged. Each setter takes its field's own type and sets that field
//! alone. Compile-RED on the base, where none of these doors exist.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used)] // Test assertions.

use bsv_rs::auth::transports::MockTransport;
use bsv_rs::auth::{AuthFetchOptions, PeerOptions, RequestedCertificateSet, SessionManager};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;

fn wallet() -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_bytes(&[7; 32]).unwrap()))
}

#[test]
fn peer_options_new_takes_the_reference_defaults_843d8a() {
    let options = PeerOptions::new(wallet(), MockTransport::new());
    assert_eq!(
        options.wallet.identity_key_hex(),
        wallet().identity_key_hex()
    );
    assert!(options.certificates_to_request.is_none());
    assert!(options.session_manager.is_none());
    // The reference's default (`Peer.ts:100` at ts-stack@edf6e03) and go-sdk's.
    assert!(options.auto_persist_last_session);
    assert!(options.originator.is_none());
}

#[test]
fn every_peer_options_setter_sets_its_field_843d8a() {
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier("02".to_string() + &"11".repeat(32));
    let mut sessions = SessionManager::new();
    sessions
        .add_session(bsv_rs::auth::PeerSession::with_nonce("n".into()))
        .unwrap();
    let options = PeerOptions::new(wallet(), MockTransport::new())
        .with_certificates_to_request(Some(requested.clone()))
        .with_session_manager(Some(sessions))
        .with_auto_persist_last_session(false)
        .with_originator(Some("app.example".into()));
    assert_eq!(
        options
            .certificates_to_request
            .as_ref()
            .map(|r| &r.certifiers),
        Some(&requested.certifiers)
    );
    assert_eq!(
        options.session_manager.as_ref().map(SessionManager::len),
        Some(1)
    );
    assert!(!options.auto_persist_last_session);
    assert_eq!(options.originator.as_deref(), Some("app.example"));
    // Each setter replaces, `None` included.
    let options = options
        .with_certificates_to_request(None)
        .with_session_manager(None)
        .with_auto_persist_last_session(true)
        .with_originator(None);
    assert!(options.certificates_to_request.is_none());
    assert!(options.session_manager.is_none());
    assert!(options.auto_persist_last_session);
    assert!(options.originator.is_none());
    // A Peer is built from it as before.
    let _peer = bsv_rs::auth::Peer::new(options);
}

#[test]
fn auth_fetch_options_default_is_unchanged_843d8a() {
    let options = AuthFetchOptions::default();
    assert!(options.method.is_none());
    assert!(options.headers.is_empty());
    assert!(options.body.is_none());
    assert!(options.retry_counter.is_none());
    assert!(options.payment_retry_attempts.is_none());
    assert!(options.labels.is_empty());
}

#[test]
fn every_auth_fetch_options_setter_sets_its_field_843d8a() {
    let headers: IndexMap<String, String> =
        [("content-type".to_string(), "application/json".to_string())]
            .into_iter()
            .collect();
    let options = AuthFetchOptions::default()
        .with_method(Some("POST".into()))
        .with_headers(headers.clone())
        .with_body(Some(vec![1, 2, 3]))
        .with_retry_counter(Some(4))
        .with_payment_retry_attempts(Some(5))
        .with_labels(vec!["app".into()]);
    assert_eq!(options.method.as_deref(), Some("POST"));
    assert_eq!(options.headers, headers);
    assert_eq!(options.body.as_deref(), Some(&[1u8, 2, 3][..]));
    assert_eq!(options.retry_counter, Some(4));
    assert_eq!(options.payment_retry_attempts, Some(5));
    assert_eq!(options.labels, ["app"]);
    let options = options
        .with_method(None)
        .with_headers(IndexMap::new())
        .with_body(None)
        .with_retry_counter(None)
        .with_payment_retry_attempts(None)
        .with_labels(vec![]);
    assert!(options.method.is_none());
    assert!(options.headers.is_empty());
    assert!(options.body.is_none());
    assert!(options.retry_counter.is_none());
    assert!(options.payment_retry_attempts.is_none());
    assert!(options.labels.is_empty());
}

#[cfg(feature = "websocket")]
#[test]
fn websocket_transport_options_new_and_its_setter_843d8a() {
    use bsv_rs::auth::{WebSocketTransport, WebSocketTransportOptions};
    let options = WebSocketTransportOptions::new("wss://ws.invalid/socket");
    assert_eq!(options.base_url, "wss://ws.invalid/socket");
    assert!(options.read_deadline_secs.is_none());
    let options = WebSocketTransportOptions::new(String::from("ws://ws.invalid"))
        .with_read_deadline_secs(Some(7));
    assert_eq!(options.base_url, "ws://ws.invalid");
    assert_eq!(options.read_deadline_secs, Some(7));
    // The transport reads them as before: 7, and 30 for `None`.
    let transport = WebSocketTransport::new(options.clone()).unwrap();
    assert_eq!(transport.read_deadline_secs(), 7);
    let transport = WebSocketTransport::new(options.with_read_deadline_secs(None)).unwrap();
    assert_eq!(transport.read_deadline_secs(), 30);
}
