//! The initial response exchanges both peers' certificate policies and proofs.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/peer_wallet_362_364.rs"]
mod wallet;

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    AuthMessage, MasterCertificate, MessageType, Peer, PeerOptions, PeerSession,
    RequestedCertificateSet, VerifiableCertificate,
};
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use wallet::TestWallet;

const VECTOR: &str = include_str!("vectors/auth_peer_nonces_362_364.json");
type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;

struct Wire {
    sent: mpsc::UnboundedSender<AuthMessage>,
    callback: Callback,
}

#[async_trait]
impl Transport for Wire {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Exercise the wire representation as well as the installed start callback.
        let text = serde_json::to_string(message).unwrap();
        self.sent
            .send(serde_json::from_str(&text).unwrap())
            .unwrap();
        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

struct End {
    peer: Peer<TestWallet, Wire>,
    callback: Callback,
    sent: mpsc::UnboundedReceiver<AuthMessage>,
}

fn key(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

fn policy() -> RequestedCertificateSet {
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier(key(42).public_key().to_hex());
    requested.add_type(to_base64(&[1; 32]), vec!["name".into()]);
    requested
}

async fn master(subject: u8, certifier: u8, cert_type: u8, field: &str) -> MasterCertificate {
    MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(key(certifier))),
        &key(certifier),
        key(subject).public_key(),
        [(field.into(), "Alice".into())].into(),
        [cert_type; 32],
        Some([2; 32]),
        Some("test"),
    )
    .await
    .unwrap()
}

async fn end(n: u8, required: bool, holds_certificate: bool) -> End {
    let mut wallet = TestWallet::new(key(n), true);
    if holds_certificate {
        wallet.certificates.push(master(n, 42, 1, "name").await);
    }
    let (sent, received) = mpsc::unbounded_channel();
    let callback = Callback::default();
    let peer = Peer::new(PeerOptions {
        wallet,
        transport: Wire {
            sent,
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
        sent: received,
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .expect("in-process certificate exchange exceeded two seconds")
}

async fn deliver(callback: &Callback, message: AuthMessage) -> Result<()> {
    let future = callback.lock().unwrap().as_ref().unwrap()(message);
    bounded(future).await
}

async fn handshake(
    a: &mut End,
    b: &mut End,
    replacement: Option<VerifiableCertificate>,
) -> (Result<PeerSession>, Result<()>, AuthMessage) {
    let identity = key(42).public_key().to_hex();
    let (session, (delivery, response)) = bounded(async {
        tokio::join!(
            a.peer
                .get_authenticated_session(Some(&identity), Some(1500)),
            async {
                let request = a.sent.recv().await.unwrap();
                deliver(&b.callback, request).await.unwrap();
                let mut response = b.sent.recv().await.unwrap();
                if let Some(certificate) = replacement {
                    response.set_certificates(vec![certificate]);
                }
                let delivery = deliver(&a.callback, response.clone()).await;
                (delivery, response)
            }
        )
    })
    .await;
    (session, delivery, response)
}

fn reference(id: &str) -> Value {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap()
        .clone()
}

fn assert_response_fields(response: &AuthMessage, id: &str) {
    let text = serde_json::to_string(response).unwrap();
    let object: indexmap::IndexMap<String, Value> = serde_json::from_str(&text).unwrap();
    let fields: Vec<_> = object.keys().collect();
    assert_eq!(
        serde_json::to_value(fields).unwrap(),
        reference(id)["response_fields"]
    );
    let mut signed = from_base64(response.your_nonce.as_deref().unwrap()).unwrap();
    signed.extend(from_base64(response.initial_nonce.as_deref().unwrap()).unwrap());
    assert_eq!(response.signing_data(), signed);
    assert!(response.nonce.is_none());
}

async fn assert_general_delivered(sender: &mut End, receiver: &End, recipient: u8) {
    let (delivered, mut received) = mpsc::unbounded_channel();
    receiver
        .peer
        .listen_for_general_messages(move |identity, payload| {
            delivered.send((identity, payload)).unwrap();
            Box::pin(async { Ok(()) })
        })
        .await;
    sender
        .peer
        .to_peer(
            b"certificate exchange complete",
            Some(&key(recipient).public_key().to_hex()),
            None,
        )
        .await
        .unwrap();
    deliver(
        &receiver.callback,
        bounded(sender.sent.recv()).await.unwrap(),
    )
    .await
    .unwrap();
    let (identity, payload) = bounded(received.recv()).await.unwrap();
    assert_eq!(identity, sender.peer.get_identity_key().await.unwrap());
    assert_eq!(payload, b"certificate exchange complete");
}

#[tokio::test]
async fn a_responder_with_a_certificate_policy_receives_the_initiators_general_message() {
    let mut a = end(41, false, true).await;
    let mut b = end(42, true, false).await;
    let (session, delivery, response) = handshake(&mut a, &mut b, None).await;
    session.unwrap();
    delivery.unwrap();
    assert_response_fields(&response, "initial_responder_policy");
    assert_eq!(
        serde_json::to_value(response.requested_certificates).unwrap(),
        reference("initial_responder_policy")["requested"]
    );
    let answer = bounded(a.sent.recv()).await.unwrap();
    assert_eq!(answer.message_type, MessageType::CertificateResponse);
    assert_eq!(answer.certificates.as_ref().unwrap().len(), 1);
    deliver(&b.callback, answer).await.unwrap();
    assert_general_delivered(&mut a, &b, 42).await;
}

#[tokio::test]
async fn an_initiator_with_a_certificate_policy_becomes_ready_from_the_initial_response() {
    let mut a = end(41, true, false).await;
    let mut b = end(42, false, true).await;
    let (session, delivery, response) = handshake(&mut a, &mut b, None).await;
    delivery.unwrap();
    assert!(session.unwrap().is_ready());
    assert_response_fields(&response, "initial_initiator_policy");
    assert_eq!(response.certificates.as_ref().unwrap().len(), 1);
    assert!(
        b.sent.try_recv().is_err(),
        "certificates belong in the initial response"
    );
    assert_general_delivered(&mut b, &a, 41).await;
}

async fn outside_certificate(fault: &str) -> VerifiableCertificate {
    let certifier = if fault == "certifier" { 43 } else { 42 };
    let cert_type = if fault == "type" { 3 } else { 1 };
    let field = if fault == "field" { "email" } else { "name" };
    let master = master(42, certifier, cert_type, field).await;
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(key(42))),
        &key(certifier).public_key(),
        &key(41).public_key(),
        &master.certificate.fields,
        &[field.into()],
        &master.master_keyring,
        &master.certificate.serial_number,
        None,
        None,
        Some("test"),
    )
    .await
    .unwrap();
    VerifiableCertificate::new(master.certificate, keyring)
}

#[tokio::test]
async fn an_initial_response_certificate_outside_the_policy_is_refused_in_the_references_words() {
    for fault in ["certifier", "type", "field"] {
        let mut a = end(41, true, true).await;
        let mut b = end(42, true, false).await;
        let (session, delivery, _) =
            handshake(&mut a, &mut b, Some(outside_certificate(fault).await)).await;
        let expected = reference(&format!("initial_response_unrequested_{fault}"))["error"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(delivery, Err(Error::AuthError(expected.clone())), "{fault}");
        assert_eq!(session.unwrap_err(), Error::AuthError(expected), "{fault}");
        assert!(
            a.sent.try_recv().is_err(),
            "a rejected certificate must stop the answer"
        );
    }
}

#[tokio::test]
async fn initial_response_certificates_are_validated_before_the_request_listener_runs() {
    let mut a = end(41, true, true).await;
    let mut b = end(42, true, true).await;
    let events = Arc::new(Mutex::new(Vec::new()));
    let received = events.clone();
    let manager = a.peer.session_manager().clone();
    a.peer
        .listen_for_certificates_received(move |sender, certificates| {
            let manager = manager.clone();
            let received = received.clone();
            Box::pin(async move {
                assert_eq!(certificates.len(), 1);
                assert!(manager
                    .read()
                    .await
                    .get_session(&sender.to_hex())
                    .unwrap()
                    .is_ready());
                received.lock().unwrap().push("validated");
                Ok(())
            })
        })
        .await;
    let requested = events.clone();
    a.peer
        .listen_for_certificates_requested(move |_, request| {
            assert_eq!(request.certifiers, policy().certifiers);
            requested.lock().unwrap().push("requested");
            Box::pin(async { Ok(()) })
        })
        .await;
    let (session, delivery, _) = handshake(&mut a, &mut b, None).await;
    delivery.unwrap();
    assert!(session.unwrap().is_ready());
    assert_eq!(
        serde_json::to_value(events.lock().unwrap().clone()).unwrap(),
        reference("initial_response_listener_order")["events"]
    );
    assert!(
        a.sent.try_recv().is_err(),
        "a request listener owns the response"
    );
}

#[tokio::test]
async fn an_initial_request_listener_replaces_automatic_certificate_selection() {
    let mut a = end(41, true, false).await;
    let mut b = end(42, false, true).await;
    let (observed, mut observations) = mpsc::unbounded_channel();
    b.peer
        .listen_for_certificates_requested(move |sender, request| {
            observed.send((sender, request)).unwrap();
            Box::pin(async { Ok(()) })
        })
        .await;
    let (session, delivery, response) = handshake(&mut a, &mut b, None).await;
    delivery.unwrap();
    assert!(!session.unwrap().is_ready());
    let (sender, request) = bounded(observations.recv()).await.unwrap();
    assert_eq!(sender, key(41).public_key());
    assert_eq!(request.certifiers, policy().certifiers);
    assert!(response.certificates.is_none());
    assert!(b.sent.try_recv().is_err());
}

#[tokio::test]
async fn an_initial_response_listener_error_stops_the_certificate_answer() {
    let mut a = end(41, true, true).await;
    let mut b = end(42, true, true).await;
    a.peer
        .listen_for_certificates_received(|_, _| {
            Box::pin(async {
                Err(Error::AuthError(
                    "initial certificate listener failed".into(),
                ))
            })
        })
        .await;
    let (session, delivery, response) = handshake(&mut a, &mut b, None).await;
    let expected = Error::AuthError("initial certificate listener failed".into());
    assert_eq!(delivery, Err(expected.clone()));
    assert_eq!(session.unwrap_err(), expected);
    assert!(a.sent.try_recv().is_err());
    // Observer failure does not undo successful certificate validation.
    // The waiting handshake removes its failed session after receiving the error.
    assert!(response.certificates.is_some());
}
