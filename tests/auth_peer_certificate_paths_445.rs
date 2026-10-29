//! The Peer's two certificate paths refuse in the reference's words, with its
//! 100-certificate bound; the empty certificates array; a handshake nonce
//! that is not canonical base64 (#445). Every expected text is the
//! reference's, recorded under Node 22 by
//! `support/auth_peer_certificate_paths_445.mjs` from `ts-stack@edf6e03`.
//! Two Peers over in-process transports whose deliveries go through the
//! callback `start` installs; no port.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/peer_wallet_362_364.rs"]
mod wallet;

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    AuthMessage, MasterCertificate, MessageType, Peer, PeerOptions, PeerSession,
    RequestedCertificateSet, VerifiableCertificate, AUTH_PROTOCOL_ID,
};
use bsv_rs::primitives::{to_base64, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use wallet::TestWallet;

const VECTOR: &str = include_str!("vectors/auth_peer_certificate_paths_445.json");
type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;

struct Wire {
    sent: mpsc::UnboundedSender<AuthMessage>,
    callback: Callback,
}

#[async_trait]
impl Transport for Wire {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
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
    gate: Arc<wallet::Gate>,
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

fn end(n: u8, required: bool) -> End {
    end_with_policy(n, required.then(policy))
}

fn end_with_policy(n: u8, policy: Option<RequestedCertificateSet>) -> End {
    let (sent, received) = mpsc::unbounded_channel();
    let callback = Callback::default();
    let wallet = TestWallet::new(key(n), true);
    let gate = wallet.gate.clone();
    let peer = Peer::new(PeerOptions {
        wallet,
        transport: Wire {
            sent,
            callback: callback.clone(),
        },
        certificates_to_request: policy,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    });
    peer.start();
    End {
        peer,
        callback,
        sent: received,
        gate,
    }
}

async fn bounded<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("in-process certificate exchange exceeded twenty seconds")
}

async fn deliver(callback: &Callback, message: AuthMessage) -> Result<()> {
    let future = callback.lock().unwrap().as_ref().unwrap()(message);
    bounded(future).await
}

/// a (41, its policy as `required`) authenticates with b (42, no policy, no
/// certificate); `change` rewrites b's initial response before a reads it.
async fn handshake(
    a: &mut End,
    b: &mut End,
    change: impl FnOnce(&mut AuthMessage),
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
                change(&mut response);
                let delivery = deliver(&a.callback, response.clone()).await;
                (delivery, response)
            }
        )
    })
    .await;
    (session, delivery, response)
}

/// A certificate of `subject` by `certifier`, revealing its one field to 41,
/// its keyring made by the subject's wallet, as the recorder's `shown`.
async fn shown(
    subject: u8,
    certifier: u8,
    cert_type: u8,
    field: &str,
    serial: u8,
) -> VerifiableCertificate {
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(key(certifier))),
        &key(certifier),
        key(subject).public_key(),
        [(field.into(), "Alice".into())].into(),
        [cert_type; 32],
        Some([serial; 32]),
        Some("test"),
    )
    .await
    .unwrap();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(key(subject))),
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

async fn requested_certificate() -> VerifiableCertificate {
    shown(42, 42, 1, "name", 2).await
}

/// The requested certificate under the signature of serial 3's.
async fn wrongly_signed() -> VerifiableCertificate {
    let mut certificate = requested_certificate().await;
    let other = shown(42, 42, 1, "name", 3).await;
    certificate
        .certificate
        .set_signature(other.certificate.signature.clone());
    certificate
}

fn rows() -> Vec<Value> {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    vector["cases"].as_array().unwrap().clone()
}

fn reference(id: &str) -> Value {
    rows().into_iter().find(|row| row["id"] == id).unwrap()
}

fn reference_error(id: &str) -> Result<()> {
    match reference(id)["error"].as_str() {
        Some(words) => Err(Error::AuthError(words.to_owned())),
        None => Ok(()),
    }
}

/// a requires the policy and has received no certificate; b answers with
/// `certificates`, signed by b's Peer.
async fn certificate_response(certificates: Vec<VerifiableCertificate>) -> (End, Result<()>) {
    let mut a = end(41, true);
    let mut b = end(42, false);
    let (session, delivery, _) = handshake(&mut a, &mut b, |_| {}).await;
    delivery.unwrap();
    assert!(!session.unwrap().is_ready());
    b.peer
        .send_certificate_response(
            &key(41).public_key().to_hex(),
            if certificates.len() > 100 {
                Vec::new()
            } else {
                certificates.clone()
            },
        )
        .await
        .unwrap();
    let mut response = bounded(b.sent.recv()).await.unwrap();
    if certificates.len() > 100 {
        response.set_certificates(certificates);
        resign(&mut response);
    }
    let delivery = deliver(&a.callback, response).await;
    (a, delivery)
}

#[tokio::test]
async fn a_certificate_response_is_refused_in_the_references_words() {
    for fault in ["subject", "signature", "certifier", "type", "field"] {
        let certificate = match fault {
            "subject" => shown(43, 42, 1, "name", 2).await,
            "signature" => wrongly_signed().await,
            "certifier" => shown(42, 43, 1, "name", 2).await,
            "type" => shown(42, 42, 3, "name", 2).await,
            _ => shown(42, 42, 1, "email", 2).await,
        };
        let (a, delivery) = certificate_response(vec![certificate]).await;
        let id = format!("certificate_response_{fault}");
        assert_eq!(delivery, reference_error(&id), "{fault}");
        let manager = a.peer.session_manager().read().await;
        let session = manager.get_session(&key(42).public_key().to_hex()).unwrap();
        assert!(!session.is_ready(), "{fault}");
    }
}

#[tokio::test]
async fn more_than_100_certificates_are_refused_before_any_is_verified_on_both_paths() {
    // 100 accepted on the certificate-response path, the session ready
    let hundred = vec![requested_certificate().await; 100];
    let (a, delivery) = certificate_response(hundred).await;
    assert_eq!(delivery, reference_error("certificate_response_100_intake"));
    let manager = a.peer.session_manager().read().await;
    assert!(manager
        .get_session(&key(42).public_key().to_hex())
        .unwrap()
        .is_ready());
    drop(manager);

    // 101, index 0 wrongly signed: the bound's words, not the signature's
    let mut over = vec![requested_certificate().await; 100];
    over.insert(0, wrongly_signed().await);
    let (_, delivery) = certificate_response(over.clone()).await;
    assert_eq!(delivery, reference_error("certificate_response_101_intake"));

    let mut a = end(41, true);
    let mut b = end(42, false);
    let (session, delivery, _) =
        handshake(&mut a, &mut b, |response| response.set_certificates(over)).await;
    assert_eq!(delivery, reference_error("initial_response_101_intake"));
    // Refused at intake, before the handler that releases the waiting
    // handshake: it ends at its deadline, never authenticated
    assert_eq!(
        session.map(|_| ()),
        Err(Error::AuthError("Handshake timeout".into()))
    );
}

#[tokio::test]
async fn an_initial_response_with_no_matching_certificate_carries_an_empty_array() {
    let row = reference("initial_response_empty_certificates");
    let mut a = end(41, true);
    let mut b = end(42, false);
    let (calls, mut received) = mpsc::unbounded_channel();
    a.peer
        .listen_for_certificates_received(move |_, certificates| {
            calls.send(certificates.len()).unwrap();
            Box::pin(async { Ok(()) })
        })
        .await;
    let (session, delivery, response) = handshake(&mut a, &mut b, |_| {}).await;
    assert_eq!(
        delivery,
        reference_error("initial_response_empty_certificates")
    );

    // The responder's selection ran and matched nothing: `certificates: []`
    let text = serde_json::to_string(&response).unwrap();
    let object: indexmap::IndexMap<String, Value> = serde_json::from_str(&text).unwrap();
    let fields: Vec<_> = object.keys().collect();
    assert_eq!(
        serde_json::to_value(fields).unwrap(),
        row["response_fields"]
    );
    assert_eq!(object["certificates"], row["certificates"]);

    // Read back as the reference reads it: authenticated, not ready, no
    // listener called, nothing answered
    let session = session.unwrap();
    assert!(session.is_authenticated);
    assert_eq!(Value::Bool(session.is_ready()), row["ready"]);
    assert_eq!(row["certificates_received_calls"], 0);
    assert!(received.try_recv().is_err());
    assert_eq!(row["automatic_answers"], 0);
    assert!(a.sent.try_recv().is_err());
}

#[tokio::test]
async fn a_handshake_nonce_that_is_not_canonical_base64_is_refused_at_intake() {
    let cases: Vec<Value> = rows()
        .into_iter()
        .filter(|row| row["id"] == "initial_request_nonce" || row["id"] == "initial_response_nonce")
        .collect();
    assert_eq!(cases.len(), 6);
    // Why at intake: the reference's signer decodes with Node's
    // `Buffer.from(_, 'base64')`, which reads `not base64!` as six bytes,
    // where this crate's decoder refused it and signed nothing for it.
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(
        vector["decodings"][0]["buffer_from"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(bsv_rs::primitives::from_base64("not base64!").is_err());
    for row in cases {
        let nonce = row["nonce"].as_str().unwrap().to_owned();
        let expected = Err(Error::AuthError(row["error"].as_str().unwrap().to_owned()));
        let mut a = end(41, false);
        let mut b = end(42, false);
        let identity = key(42).public_key().to_hex();
        if row["id"] == "initial_request_nonce" {
            let handshake = a.peer.get_authenticated_session(Some(&identity), Some(200));
            let forge = async {
                let mut request = a.sent.recv().await.unwrap();
                request.initial_nonce = Some(nonce.clone());
                deliver(&b.callback, request).await
            };
            let (_, delivery) = bounded(async { tokio::join!(handshake, forge) }).await;
            assert_eq!(delivery, expected, "initialRequest {nonce}");
            assert_eq!(
                b.sent.try_recv().is_ok(),
                expected.is_ok(),
                "answered {nonce}"
            );
        } else {
            let (_, delivery, _) = handshake(&mut a, &mut b, |response| {
                response.initial_nonce = Some(nonce.clone());
            })
            .await;
            assert_eq!(delivery, expected, "initialResponse {nonce}");
        }
    }
}

fn resign(message: &mut AuthMessage) {
    let signer = if message.identity_key == key(41).public_key() {
        41
    } else {
        42
    };
    message.signature = Some(
        ProtoWallet::new(Some(key(signer)))
            .create_signature(CreateSignatureArgs {
                data: Some(message.signing_data()),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id: message.get_key_id(message.your_nonce.as_deref()),
                counterparty: Some(Counterparty::Other(
                    key(if signer == 41 { 42 } else { 41 }).public_key(),
                )),
                ..Default::default()
            })
            .unwrap()
            .signature,
    );
}

#[tokio::test]
async fn every_nonce_is_required_canonical_and_has_the_reference_length_at_intake() {
    let mut a = end(41, false);
    let mut b = end(42, false);
    let (_, delivery, response) = handshake(&mut a, &mut b, |_| {}).await;
    delivery.unwrap();
    let mut failures = Vec::new();
    let cases: Vec<_> = rows()
        .into_iter()
        .filter(|r| r["id"].as_str().unwrap().starts_with("nonce_intake_"))
        .collect();
    assert_eq!(cases.len(), 88);
    for row in cases {
        let kind = MessageType::from_str(row["message_type"].as_str().unwrap()).unwrap();
        let mut message = AuthMessage::new(kind, key(42).public_key());
        message.nonce = Some(to_base64(&[7; 32]));
        message.initial_nonce = response.initial_nonce.clone();
        message.your_nonce = response.your_nonce.clone();
        message.payload = Some(vec![1]);
        if kind == MessageType::CertificateRequest {
            message.set_requested_certificates(policy());
        }
        if kind == MessageType::CertificateResponse {
            message.set_certificates(Vec::new());
        }
        let value = row["value"].as_str().map(str::to_owned);
        match row["field"].as_str().unwrap() {
            "nonce" => message.nonce = value,
            "initialNonce" => message.initial_nonce = value,
            "yourNonce" => message.your_nonce = value,
            _ => unreachable!(),
        }
        resign(&mut message);
        let actual = deliver(&a.callback, message).await;
        let expected = Err(Error::AuthError(row["error"].as_str().unwrap().into()));
        if actual != expected {
            failures.push(format!("{}: {actual:?}, expected {expected:?}", row["id"]));
        }
    }
    for (id, missing_nonce, over_limit) in [
        ("certificate_request_missing_nonce_and_policy", true, false),
        ("certificate_request_missing_policy", false, false),
        (
            "certificate_request_bound_before_missing_policy",
            true,
            true,
        ),
    ] {
        let mut message = AuthMessage::new(MessageType::CertificateRequest, key(42).public_key());
        message.nonce = (!missing_nonce).then(|| to_base64(&[7; 32]));
        message.initial_nonce = response.initial_nonce.clone();
        message.your_nonce = response.your_nonce.clone();
        if over_limit {
            message.set_certificates(vec![requested_certificate().await; 101]);
        }
        let actual = deliver(&a.callback, message).await;
        let expected = reference_error(id);
        if actual != expected {
            failures.push(format!("{id}: {actual:?}, expected {expected:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn a_certificate_response_without_a_policy_is_refused_before_listeners() {
    for count in [0, 1] {
        let mut a = end(41, false);
        let mut b = end(42, false);
        handshake(&mut a, &mut b, |_| {}).await.1.unwrap();
        let (calls, mut received) = mpsc::unbounded_channel();
        a.peer
            .listen_for_certificates_received(move |_, certificates| {
                calls.send(certificates.len()).unwrap();
                Box::pin(async { Ok(()) })
            })
            .await;
        b.peer
            .send_certificate_response(
                &key(41).public_key().to_hex(),
                vec![requested_certificate().await; count],
            )
            .await
            .unwrap();
        let message = b.sent.recv().await.unwrap();
        let id = format!("no_policy_response_{count}");
        assert_eq!(
            deliver(&a.callback, message).await,
            reference_error(&id),
            "{id}"
        );
        let calls = usize::from(received.try_recv().is_ok());
        assert_eq!(
            calls,
            reference(&id)["certificates_received_calls"]
                .as_u64()
                .unwrap() as usize
        );
    }
}

#[tokio::test]
async fn certificate_rejections_follow_the_reference_await_stages_on_both_paths() {
    let mut failures = Vec::new();
    for label in [
        "signature_subject",
        "signature_certifier",
        "signature_keyring",
        "subject_subject",
        "signature_signature",
    ] {
        for reverse in [false, true] {
            let (a, b) = match label {
                "signature_subject" => (wrongly_signed().await, shown(43, 42, 1, "name", 2).await),
                "signature_certifier" => {
                    (wrongly_signed().await, shown(42, 43, 1, "name", 2).await)
                }
                "signature_keyring" => {
                    let mut bad = requested_certificate().await;
                    bad.keyring.insert("name".into(), "AB==".into());
                    (wrongly_signed().await, bad)
                }
                "subject_subject" => (
                    shown(43, 42, 1, "name", 2).await,
                    shown(44, 42, 1, "name", 2).await,
                ),
                _ => {
                    let mut bad = shown(42, 42, 1, "name", 4).await;
                    bad.certificate.set_signature(
                        shown(42, 42, 1, "name", 9)
                            .await
                            .certificate
                            .signature
                            .clone(),
                    );
                    (wrongly_signed().await, bad)
                }
            };
            let mut certificates = vec![a, b];
            if reverse {
                certificates.reverse();
            }
            let suffix = if reverse { "reverse" } else { "forward" };
            let mut a = end(41, true);
            let mut b = end(42, false);
            let (_, actual, _) = handshake(&mut a, &mut b, |response| {
                response.set_certificates(certificates.clone());
                resign(response);
            })
            .await;
            let id = format!("order_initial_{label}_{suffix}");
            if actual != reference_error(&id) {
                failures.push(format!(
                    "{id}: {actual:?}, expected {:?}",
                    reference_error(&id)
                ));
            }
            if label != "signature_certifier" {
                let (_, actual) = certificate_response(certificates).await;
                let id = format!("order_response_{label}_{suffix}");
                if actual != reference_error(&id) {
                    failures.push(format!(
                        "{id}: {actual:?}, expected {:?}",
                        reference_error(&id)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

async fn two_revealed_fields() -> VerifiableCertificate {
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(key(42))),
        &key(42),
        key(42).public_key(),
        [
            ("name".into(), "Alice".into()),
            ("email".into(), "alice@example.invalid".into()),
        ]
        .into(),
        [1; 32],
        Some([2; 32]),
        Some("test"),
    )
    .await
    .unwrap();
    let ring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(key(42))),
        &key(42).public_key(),
        &key(41).public_key(),
        &master.certificate.fields,
        &["name".into(), "email".into()],
        &master.master_keyring,
        &master.certificate.serial_number,
        None,
        None,
        Some("test"),
    )
    .await
    .unwrap();
    VerifiableCertificate::new(master.certificate, ring)
}

#[tokio::test]
async fn decryption_rejections_follow_the_wallet_await_on_both_paths() {
    for reverse in [false, true] {
        let mut after_wallet = two_revealed_fields().await;
        after_wallet.keyring.insert("email".into(), "AB==".into());
        let mut before_wallet = requested_certificate().await;
        before_wallet.keyring.insert("name".into(), "AB==".into());
        let certificates = if reverse {
            vec![before_wallet, after_wallet]
        } else {
            vec![after_wallet, before_wallet]
        };
        let suffix = if reverse { "reverse" } else { "forward" };
        for initial in [true, false] {
            let mut requested = policy();
            requested
                .types
                .get_mut(&to_base64(&[1; 32]))
                .unwrap()
                .push("email".into());
            let mut a = end_with_policy(41, Some(requested));
            let mut b = end(42, false);
            let path = if initial { "initial" } else { "response" };
            let id = format!("order_{path}_decryption_await_{suffix}");
            let actual = if initial {
                handshake(&mut a, &mut b, |response| {
                    response.set_certificates(certificates.clone());
                    resign(response);
                })
                .await
                .1
            } else {
                handshake(&mut a, &mut b, |_| {}).await.1.unwrap();
                b.peer
                    .send_certificate_response(&key(41).public_key().to_hex(), certificates.clone())
                    .await
                    .unwrap();
                deliver(&a.callback, b.sent.recv().await.unwrap()).await
            };
            assert_eq!(
                actual,
                Err(Error::CertificateValidationError(
                    reference(&id)["error"].as_str().unwrap().into()
                )),
                "{id}"
            );
        }
    }
}

#[tokio::test]
async fn the_sender_refuses_101_certificates_before_a_session_or_send() {
    let mut failures = Vec::new();
    for count in [0, 100, 101] {
        let mut a = end(41, false);
        let mut b = end(42, false);
        handshake(&mut a, &mut b, |_| {}).await.1.unwrap();
        let actual = b
            .peer
            .send_certificate_response(
                &key(41).public_key().to_hex(),
                vec![requested_certificate().await; count],
            )
            .await;
        let id = format!("sender_bound_{count}");
        if actual != reference_error(&id) {
            failures.push(format!(
                "{id}: {actual:?}, expected {:?}",
                reference_error(&id)
            ));
        }
        let sent = usize::from(b.sent.try_recv().is_ok());
        if sent != reference(&id)["sent"].as_u64().unwrap() as usize {
            failures.push(format!("{id}: sent {sent}"));
        }
    }
    let mut b = end(42, false);
    let actual = b
        .peer
        .send_certificate_response(
            &key(41).public_key().to_hex(),
            vec![requested_certificate().await; 101],
        )
        .await;
    let expected = reference_error("sender_bound_101_without_session");
    if actual != expected {
        failures.push(format!(
            "without session: {actual:?}, expected {expected:?}"
        ));
    }
    assert!(b.sent.try_recv().is_err());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn empty_subset_and_extra_keyrings_keep_the_reference_verdicts() {
    let mut failures = Vec::new();
    for kind in ["empty", "subset", "extra"] {
        let mut requested = policy();
        if kind != "extra" {
            requested
                .types
                .get_mut(&to_base64(&[1; 32]))
                .unwrap()
                .push("email".into());
        }
        let mut a = end_with_policy(41, Some(requested));
        let mut b = end(42, false);
        handshake(&mut a, &mut b, |_| {}).await.1.unwrap();
        let master = MasterCertificate::issue_for_subject(
            &ProtoWallet::new(Some(key(42))),
            &key(42),
            key(42).public_key(),
            [
                ("name".into(), "Alice".into()),
                ("email".into(), "alice@example.invalid".into()),
            ]
            .into(),
            [1; 32],
            Some([2; 32]),
            Some("test"),
        )
        .await
        .unwrap();
        let reveal = if kind == "empty" {
            Vec::new()
        } else if kind == "subset" {
            vec!["name".into()]
        } else {
            vec!["name".into(), "email".into()]
        };
        let ring = if reveal.is_empty() {
            Default::default()
        } else {
            MasterCertificate::create_keyring_for_verifier(
                &ProtoWallet::new(Some(key(42))),
                &key(42).public_key(),
                &key(41).public_key(),
                &master.certificate.fields,
                &reveal,
                &master.master_keyring,
                &master.certificate.serial_number,
                None,
                None,
                Some("test"),
            )
            .await
            .unwrap()
        };
        b.peer
            .send_certificate_response(
                &key(41).public_key().to_hex(),
                vec![VerifiableCertificate::new(master.certificate, ring)],
            )
            .await
            .unwrap();
        let message = b.sent.recv().await.unwrap();
        let actual = deliver(&a.callback, message).await;
        let expected = reference_error(&format!("keyring_{kind}"));
        if actual != expected {
            failures.push(format!("{kind}: {actual:?}, expected {expected:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn certificate_decryption_runs_concurrently_before_either_wallet_answer() {
    let mut a = end(41, true);
    let mut b = end(42, false);
    handshake(&mut a, &mut b, |_| {}).await.1.unwrap();
    a.gate
        .enabled
        .store(true, std::sync::atomic::Ordering::SeqCst);
    b.peer
        .send_certificate_response(
            &key(41).public_key().to_hex(),
            vec![requested_certificate().await; 2],
        )
        .await
        .unwrap();
    let message = b.sent.recv().await.unwrap();
    let release = async {
        let both =
            tokio::time::timeout(Duration::from_secs(1), a.gate.entered.acquire_many(2)).await;
        let concurrent = both.is_ok();
        if let Ok(permits) = both {
            permits.unwrap().forget();
        }
        a.gate.release.add_permits(2);
        concurrent
    };
    let (delivery, concurrent) = tokio::join!(deliver(&a.callback, message), release);
    delivery.unwrap();
    assert!(
        concurrent,
        "both certificates must reach the wallet before either answer"
    );
}
