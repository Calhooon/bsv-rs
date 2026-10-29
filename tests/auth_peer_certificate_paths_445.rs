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
    AuthMessage, MasterCertificate, Peer, PeerOptions, PeerSession, RequestedCertificateSet,
    VerifiableCertificate,
};
use bsv_rs::primitives::{to_base64, PrivateKey};
use bsv_rs::wallet::ProtoWallet;
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
    let (sent, received) = mpsc::unbounded_channel();
    let callback = Callback::default();
    let peer = Peer::new(PeerOptions {
        wallet: TestWallet::new(key(n), true),
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
        .send_certificate_response(&key(41).public_key().to_hex(), certificates)
        .await
        .unwrap();
    let response = bounded(b.sent.recv()).await.unwrap();
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

/// The reference refuses a handshake nonce of the right text but not 48
/// bytes (`must encode exactly 48 bytes.`); this crate still accepts the
/// 32-byte legacy nonce (0.3.6), a stated difference.
const STATED_LENGTH: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

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
        let expected = match nonce.as_str() {
            STATED_LENGTH => Ok(()),
            _ => Err(Error::AuthError(row["error"].as_str().unwrap().to_owned())),
        };
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
            if nonce == STATED_LENGTH {
                // Past the intake, the signature over the 48-byte nonce fails
                assert!(delivery.is_err());
            } else {
                assert_eq!(delivery, expected, "initialResponse {nonce}");
            }
        }
    }
}
