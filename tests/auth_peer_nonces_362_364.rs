//! #362-364: two real Peers, manual in-process delivery, reference-recorded words.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/peer_wallet_362_364.rs"]
mod wallet;

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    create_nonce, AuthMessage, MasterCertificate, MessageType, Peer, PeerOptions, PeerSession,
    RequestedCertificateSet, VerifiableCertificate, AUTH_PROTOCOL_ID,
};
use bsv_rs::primitives::{to_base64, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::mpsc;
use wallet::TestWallet;

const VECTOR: &str = include_str!("vectors/auth_peer_nonces_362_364.json");
type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;
struct Wire {
    out: mpsc::UnboundedSender<AuthMessage>,
    callback: Callback,
}
#[async_trait]
impl Transport for Wire {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.out.send(message.clone()).unwrap();
        Ok(())
    }
    fn set_callback(&self, cb: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(cb);
    }
    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}
struct End {
    peer: Peer<TestWallet, Wire>,
    callback: Callback,
    sent: mpsc::UnboundedReceiver<AuthMessage>,
    gate: Arc<wallet::Gate>,
}
impl End {
    async fn deliver(&self, message: AuthMessage) -> Result<()> {
        deliver(&self.callback, message).await
    }
    async fn session(&self, identity: u8) -> PeerSession {
        self.peer
            .session_manager()
            .read()
            .await
            .get_session(&key(identity).public_key().to_hex())
            .unwrap()
            .clone()
    }
}
async fn deliver(callback: &Callback, message: AuthMessage) -> Result<()> {
    let future = callback.lock().unwrap().as_ref().unwrap()(message);
    future.await
}
fn key(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}
fn policy() -> RequestedCertificateSet {
    let mut p = RequestedCertificateSet::new();
    p.add_certifier(key(42).public_key().to_hex());
    p.add_type(to_base64(&[1; 32]), vec!["name".into()]);
    p
}
fn end(n: u8, required: bool) -> End {
    let wallet = TestWallet::new(key(n), true);
    let gate = wallet.gate.clone();
    let (out, sent) = mpsc::unbounded_channel();
    let callback = Callback::default();
    let peer = Peer::new(PeerOptions {
        wallet,
        transport: Wire {
            out,
            callback: callback.clone(),
        },
        certificates_to_request: required.then(policy),
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    });
    peer.start();
    End {
        peer,
        callback,
        sent,
        gate,
    }
}
struct Pair {
    a: End,
    b: End,
    request: AuthMessage,
    response: AuthMessage,
}
async fn pair(required: bool) -> Pair {
    let mut a = end(41, required);
    let mut b = end(42, false);
    let identity = key(42).public_key().to_hex();
    let callback = a.callback.clone();
    let (session, messages) = tokio::join!(
        a.peer
            .get_authenticated_session(Some(&identity), Some(2000)),
        async {
            let request = a.sent.recv().await.unwrap();
            b.deliver(request.clone()).await.unwrap();
            let response = b.sent.recv().await.unwrap();
            deliver(&callback, response.clone()).await.unwrap();
            (request, response)
        }
    );
    session.unwrap();
    Pair {
        a,
        b,
        request: messages.0,
        response: messages.1,
    }
}
async fn certificate() -> VerifiableCertificate {
    let signer = key(42);
    let wallet = ProtoWallet::new(Some(signer.clone()));
    let master = MasterCertificate::issue_for_subject(
        &wallet,
        &signer,
        signer.public_key(),
        [("name".into(), "Alice".into())].into(),
        [1; 32],
        Some([2; 32]),
        Some("test"),
    )
    .await
    .unwrap();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &wallet,
        &signer.public_key(),
        &key(41).public_key(),
        &master.certificate.fields,
        &["name".into()],
        &master.master_keyring,
        &[2; 32],
        None,
        None,
        Some("test"),
    )
    .await
    .unwrap();
    VerifiableCertificate::new(master.certificate, keyring)
}
async fn message(p: &mut Pair, kind: MessageType) -> AuthMessage {
    let identity = key(41).public_key().to_hex();
    match kind {
        MessageType::InitialRequest => return p.request.clone(),
        MessageType::InitialResponse => return p.response.clone(),
        MessageType::CertificateRequest => {
            p.b.peer
                .request_certificates(policy(), Some(&identity), None)
                .await
                .unwrap()
        }
        MessageType::CertificateResponse => {
            p.b.peer
                .send_certificate_response(&identity, vec![certificate().await])
                .await
                .unwrap()
        }
        MessageType::General => {
            p.b.peer
                .to_peer(&[1, 2, 3], Some(&identity), None)
                .await
                .unwrap()
        }
    }
    p.b.sent.recv().await.unwrap()
}
fn words(id: &str, nonce: &str) -> String {
    let v: Value = serde_json::from_str(VECTOR).unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()["error"]
        .as_str()
        .unwrap()
        .replace("<nonce>", nonce)
}
fn assert_ref(result: Result<()>, id: &str, nonce: &str) {
    assert_eq!(result, Err(Error::AuthError(words(id, nonce))), "{id}");
}
async fn replay(kind: MessageType) {
    let mut p = pair(kind == MessageType::CertificateResponse).await;
    let m = message(&mut p, kind).await;
    let target = if kind == MessageType::InitialRequest {
        &p.b
    } else {
        &p.a
    };
    if !kind.is_handshake() {
        target.deliver(m.clone()).await.unwrap();
    }
    assert_ref(target.deliver(m).await, &format!("replay_{kind}"), "");
}
#[tokio::test]
async fn initial_request_nonce_is_claimed_362() {
    replay(MessageType::InitialRequest).await;
}
#[tokio::test]
async fn initial_response_replay_is_refused_362() {
    replay(MessageType::InitialResponse).await;
}
#[tokio::test]
async fn certificate_request_replay_is_refused_362() {
    replay(MessageType::CertificateRequest).await;
}
#[tokio::test]
async fn certificate_response_replay_is_refused_362() {
    replay(MessageType::CertificateResponse).await;
}
#[tokio::test]
async fn general_message_replay_is_refused_362() {
    replay(MessageType::General).await;
}

fn resign(message: &mut AuthMessage, our_nonce: &str) {
    message.signature = Some(
        ProtoWallet::new(Some(key(42)))
            .create_signature(CreateSignatureArgs {
                data: Some(message.signing_data()),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id: message.get_key_id(Some(our_nonce)),
                counterparty: Some(Counterparty::Other(key(41).public_key())),
                ..Default::default()
            })
            .unwrap()
            .signature,
    );
}
async fn certificate_fault(kind: MessageType, fault: &str) {
    let mut p = pair(kind == MessageType::CertificateResponse).await;
    let mut m = message(&mut p, kind).await;
    match fault {
        "wrong_your_nonce" => m.your_nonce = Some(to_base64(&[0; 48])),
        "unknown_session" => {
            m.your_nonce = Some(
                create_nonce(&TestWallet::new(key(41), true), None, Some("test"))
                    .await
                    .unwrap(),
            )
        }
        "identity_mismatch" => m.identity_key = key(43).public_key(),
        "invalid_signature" => m.signature = Some(vec![48, 6, 2, 1, 1, 2, 1, 1]),
        "missing_nonce" => {
            m.nonce = None;
            resign(
                &mut m,
                p.a.session(42).await.session_nonce.as_deref().unwrap(),
            );
        }
        "listener_error" => {
            if kind == MessageType::CertificateRequest {
                p.a.peer
                    .listen_for_certificates_requested(|_, _| {
                        Box::pin(async {
                            Err(Error::AuthError("certificate listener failed".into()))
                        })
                    })
                    .await;
            } else {
                p.a.peer
                    .listen_for_certificates_received(|_, _| {
                        Box::pin(async {
                            Err(Error::AuthError("certificate listener failed".into()))
                        })
                    })
                    .await;
            }
        }
        _ => unreachable!(),
    }
    let nonce = m.your_nonce.clone().unwrap();
    let actual = p.a.deliver(m).await;
    if fault == "missing_nonce" {
        // #445 closes the earlier handler-only gap; keep the old vector intact.
        let vector: Value =
            serde_json::from_str(include_str!("vectors/auth_peer_certificate_paths_445.json"))
                .unwrap();
        let id = format!("nonce_intake_{kind}_nonce_missing");
        let row = vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap();
        assert_eq!(
            actual,
            Err(Error::AuthError(row["error"].as_str().unwrap().into()))
        );
    } else {
        assert_ref(actual, &format!("{kind}_{fault}"), &nonce);
    }
}
#[tokio::test]
async fn certificate_request_verifies_your_nonce_and_session_363() {
    for fault in [
        "wrong_your_nonce",
        "unknown_session",
        "identity_mismatch",
        "invalid_signature",
        "missing_nonce",
    ] {
        certificate_fault(MessageType::CertificateRequest, fault).await;
    }
}
#[tokio::test]
async fn certificate_response_verifies_your_nonce_and_session_363() {
    for fault in [
        "wrong_your_nonce",
        "unknown_session",
        "identity_mismatch",
        "invalid_signature",
        "missing_nonce",
    ] {
        certificate_fault(MessageType::CertificateResponse, fault).await;
    }
}
#[tokio::test]
async fn certificate_request_listener_error_is_the_message_error_363() {
    certificate_fault(MessageType::CertificateRequest, "listener_error").await;
}
#[tokio::test]
async fn certificate_response_listener_error_is_the_message_error_363() {
    certificate_fault(MessageType::CertificateResponse, "listener_error").await;
}
#[tokio::test]
async fn certificate_response_makes_only_its_nonce_session_ready_364() {
    let mut p = pair(true).await;
    let m = message(&mut p, MessageType::CertificateResponse).await;
    assert!(!p.a.session(42).await.is_ready());
    let mut other = p.a.session(42).await;
    other.session_nonce = Some("another session for the same identity".into());
    other.last_update += 1000;
    p.a.peer
        .session_manager()
        .write()
        .await
        .add_session(other.clone())
        .unwrap();
    p.a.deliver(m).await.unwrap();
    let manager = p.a.peer.session_manager().read().await;
    assert!(manager
        .get_session(p.response.your_nonce.as_deref().unwrap())
        .unwrap()
        .is_ready());
    assert!(!manager
        .get_session(other.session_nonce.as_deref().unwrap())
        .unwrap()
        .is_ready());
}
#[tokio::test]
async fn general_message_waits_for_pending_certificate_validation_364() {
    let reference: Value = serde_json::from_str(VECTOR).unwrap();
    let reference = reference["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "pending_validation")
        .unwrap();
    let mut p = pair(true).await;
    let response = message(&mut p, MessageType::CertificateResponse).await;
    let general = message(&mut p, MessageType::General).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    p.a.peer
        .listen_for_general_messages(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .await;
    p.a.gate.enabled.store(true, Ordering::SeqCst);
    let validation = p.a.deliver(response);
    let mut validation = Box::pin(validation);
    tokio::select! {
        result = &mut validation => panic!("validation did not block: {result:?}"),
        permit = p.a.gate.entered.acquire() => permit.unwrap().forget(),
    }
    let mut delivery = Box::pin(p.a.deliver(general));
    tokio::select! {
        result = &mut delivery => panic!("general message passed pending validation: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(30)) => {}
    }
    assert_eq!(
        calls.load(Ordering::SeqCst) as u64,
        reference["before"]["calls"].as_u64().unwrap()
    );
    p.a.gate.release.add_permits(1);
    let (validated, delivered) = tokio::join!(validation, delivery);
    validated.unwrap();
    delivered.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst) as u64,
        reference["after"]["calls"].as_u64().unwrap()
    );
    assert_eq!(
        p.a.session(42).await.is_ready(),
        reference["after"]["ready"].as_bool().unwrap()
    );
}
#[tokio::test]
async fn general_message_validation_timeout_uses_reference_words_364() {
    let mut p = pair(true).await;
    let m = message(&mut p, MessageType::General).await;
    let second = message(&mut p, MessageType::General).await;
    let (first_result, second_result) = tokio::join!(p.a.deliver(m.clone()), p.a.deliver(second));
    assert_ref(first_result, "validation_timeout", "");
    assert_ref(second_result, "validation_timeout", "");
    assert_ref(p.a.deliver(m).await, "replay_general", "");
}

#[tokio::test]
async fn concurrent_general_replay_is_delivered_once_362() {
    let mut p = pair(false).await;
    let m = message(&mut p, MessageType::General).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    p.a.peer
        .listen_for_general_messages(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        })
        .await;
    let (a, b) = tokio::join!(p.a.deliver(m.clone()), p.a.deliver(m));
    assert!(a.is_ok() ^ b.is_ok());
    assert_ref(a.and(b), "replay_general", "");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_signature_does_not_claim_a_nonce_and_claims_span_message_kinds_362() {
    let mut p = pair(false).await;
    let request = message(&mut p, MessageType::CertificateRequest).await;
    let mut bad = request.clone();
    bad.signature = Some(vec![48, 6, 2, 1, 1, 2, 1, 1]);
    assert_ref(
        p.a.deliver(bad).await,
        "certificateRequest_invalid_signature",
        "",
    );
    p.a.deliver(request.clone()).await.unwrap();
    let mut general = message(&mut p, MessageType::General).await;
    general.nonce = request.nonce;
    resign(
        &mut general,
        p.a.session(42).await.session_nonce.as_deref().unwrap(),
    );
    assert_ref(p.a.deliver(general).await, "replay_general", "");
}

#[tokio::test]
async fn certificate_exchange_makes_session_ready_364() {
    let mut p = pair(true).await;
    assert!(!p.a.session(42).await.is_ready());
    let response = message(&mut p, MessageType::CertificateResponse).await;
    p.a.deliver(response).await.unwrap();
    assert!(p.a.session(42).await.is_ready());
}
