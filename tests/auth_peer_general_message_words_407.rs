//! #407's proposed normalization contradicts both pinned reference Peers.
//! A throwing wallet's error propagates; only `valid: false` reaches the
//! Peer's own words. The Node 22 recorder exercises both, including malformed
//! bytes. Rust reconstructs the signed messages with its own nonce writer
//! because the reference's nonce HMAC inputs differ (the documented #353 gap).
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/peer_wallet_407.rs"]
mod wallet;

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    create_nonce, AuthMessage, MessageType, Peer, PeerOptions, PeerSession, SessionManager,
    AUTH_PROTOCOL_ID,
};
use bsv_rs::primitives::{to_base64, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use wallet::TestWallet;

const VECTOR: &str = include_str!("vectors/auth_peer_general_message_words_407.json");
const REFERENCES: [&str; 2] = ["ts-stack@edf6e03", "ts-sdk@9e3ede6b"];
type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;

struct Wire(Callback);

#[async_trait]
impl Transport for Wire {
    async fn send(&self, _: &AuthMessage) -> Result<()> {
        panic!("a received general message must not send a message")
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.0.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.0.lock().unwrap() = None;
    }
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn key(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

fn sign(signer: u8, nonce: &str, ours: &str) -> Vec<u8> {
    ProtoWallet::new(Some(key(signer)))
        .create_signature(CreateSignatureArgs {
            data: Some(vec![1, 2, 3]),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: format!("{nonce} {ours}"),
            counterparty: Some(Counterparty::Other(key(41).public_key())),
            ..Default::default()
        })
        .unwrap()
        .signature
}

/// Seed an authenticated session, then use the callback installed by `start`
/// (or `start_server`). Every nonce and signature is made by the real wallet.
async fn deliver(case: &str, wallet: TestWallet, server: bool) -> (Result<()>, usize) {
    let ours = create_nonce(&wallet, None, Some("test")).await.unwrap();
    let mut session = PeerSession::with_nonce(ours.clone());
    session.is_authenticated = true;
    session.peer_identity_key = Some(key(42).public_key());
    let mut manager = SessionManager::new();
    manager.add_session(session).unwrap();
    let callback: Callback = Arc::default();
    let peer = Arc::new(Peer::new(PeerOptions {
        wallet,
        transport: Wire(callback.clone()),
        certificates_to_request: None,
        session_manager: Some(manager),
        auto_persist_last_session: false,
        originator: Some("test".into()),
    }));
    let calls = Arc::new(AtomicUsize::new(0));
    let log = calls.clone();
    peer.listen_for_general_messages(move |sender, payload| {
        assert_eq!(sender, key(42).public_key());
        assert_eq!(payload, [1, 2, 3]);
        log.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    })
    .await;
    if server {
        peer.start_server();
    } else {
        peer.start();
    }
    let nonce = to_base64(&[7; 32]);
    let mut message = AuthMessage::new(MessageType::General, key(42).public_key());
    message.signature = Some(if case == "malformed" {
        serde_json::from_value(vector()["malformed"].clone()).unwrap()
    } else {
        sign(if case == "other_key" { 43 } else { 42 }, &nonce, &ours)
    });
    message.payload = Some(vec![1, 2, 3]);
    message.nonce = Some(nonce);
    message.your_nonce = Some(ours);
    let pending = callback.lock().unwrap().as_ref().unwrap()(message);
    (pending.await, calls.load(Ordering::SeqCst))
}

fn assert_reference(verdict: Result<()>, case: &str, kind: &str, calls: usize) {
    let rendered = verdict.as_ref().err().map(ToString::to_string);
    let words = match verdict {
        Ok(()) => Value::Null,
        Err(Error::WalletError(words)) if kind == "proto" => Value::String(words),
        Err(Error::AuthError(words)) if kind == "answering" => Value::String(words),
        Err(other) => panic!("unexpected refusal: {other:?}"),
    };
    for reference in REFERENCES {
        let expected = &vector()["references"][reference]["cases"][case][kind];
        assert_eq!(words, expected["error"], "{reference}: {case}/{kind}");
        let prefix = if kind == "proto" {
            "wallet error"
        } else {
            "authentication error"
        };
        assert_eq!(
            rendered,
            expected["error"]
                .as_str()
                .map(|text| format!("{prefix}: {text}"))
        );
        assert_eq!(calls, expected["delivered"].as_u64().unwrap() as usize);
    }
}

#[tokio::test]
async fn another_keys_general_signature_throws_the_wallet_words_before_the_peer_words() {
    for server in [false, true] {
        let (result, calls) = deliver("other_key", TestWallet::new(key(41), false), server).await;
        assert_reference(result, "other_key", "proto", calls);
    }
}

#[tokio::test]
async fn unparseable_general_signature_throws_before_the_peer_words_and_delivers_nothing() {
    for server in [false, true] {
        let (result, calls) = deliver("malformed", TestWallet::new(key(41), false), server).await;
        // The wallet's parser words are a pre-existing difference, not a
        // `valid: false` result. The two reference versions also differ here.
        assert_eq!(
            result,
            Err(Error::InvalidSignature("Expected sequence tag 0x30".into()))
        );
        assert_eq!(calls, 0);
        let fixture = vector();
        assert_eq!(
            fixture["references"][REFERENCES[0]]["cases"]["malformed"]["proto"]["error"],
            "The signature parameter must be a canonical DER-encoded ECDSA signature"
        );
        assert_eq!(
            fixture["references"][REFERENCES[1]]["cases"]["malformed"]["proto"]["error"],
            "Signature DER must start with 0x30"
        );
    }
}

#[tokio::test]
async fn false_for_either_bad_signature_uses_the_verified_identity_in_the_peer_words() {
    for case in ["other_key", "malformed"] {
        for server in [false, true] {
            let (result, calls) = deliver(case, TestWallet::new(key(41), true), server).await;
            assert_reference(result, case, "answering", calls);
        }
    }
}

#[tokio::test]
async fn honest_general_signatures_reach_the_listener_with_either_wallet() {
    for answering in [false, true] {
        let kind = if answering { "answering" } else { "proto" };
        let (result, calls) = deliver("honest", TestWallet::new(key(41), answering), false).await;
        assert_reference(result, "honest", kind, calls);
    }
}

#[tokio::test]
async fn a_wallet_operational_error_is_not_relabelled_as_an_invalid_general_signature() {
    let mut wallet = TestWallet::new(key(41), false);
    let error = Error::WalletError("wallet unavailable".into());
    wallet.failure = Some(error.clone());
    let (result, calls) = deliver("honest", wallet, false).await;
    assert_eq!(result, Err(error));
    assert_eq!(calls, 0);
}
