//! `Peer` refuses a malformed requested certificate set where the reference
//! does (#294): on its own policy before it signs or sends it
//! (`ts-stack@edf6e03` `packages/sdk/src/auth/Peer.ts:158`, `:332`, `:434`)
//! and on a received message's `requestedCertificates` before any handler
//! (`snapshotAuthMessage`, `Peer.ts:767`, through
//! `AuthMessageValidation.ts:345-346`, `:367`), in the words of
//! `assertRequestedCertificateSet` (`AuthMessageValidation.ts:107-162`).
//! Until #294 this crate's `Peer` called no validator: it signed and sent a
//! certificateRequest the reference refuses, and handed a received one to
//! its listener unchecked.
//!
//! The witness is `tests/vectors/auth_requested_set_validation_294.json`,
//! written by `tests/support/requested_set_validation_294.mjs` under Node
//! v22.18.0: for a 31-byte, a 33-byte, a non-base64 and an integer-like type
//! ID, and a 32-byte one, the reference `Peer`'s verdict as a constructor's
//! policy, as `requestCertificates`' argument after a handshake, and on a
//! signed certificateRequest carrying it (whose text this crate's `Peer`
//! reads here).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    assert_requested_certificate_set, create_nonce, AuthMessage, MessageType, Peer, PeerOptions,
    PeerSession, RequestedCertificateSet, SessionManager,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const VECTOR: &str = include_str!("vectors/auth_requested_set_validation_294.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn key(vector: &Value, name: &str) -> PrivateKey {
    PrivateKey::from_hex(vector["keys"][name].as_str().unwrap()).unwrap()
}

fn case<'a>(vector: &'a Value, name: &str) -> &'a Value {
    vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap()
}

/// The four policies the reference refuses
const REFUSED: [&str; 4] = [
    "type_id_of_31_bytes",
    "type_id_of_33_bytes",
    "type_id_not_base64",
    "type_id_integer_like",
];

/// A case's policy in the order it was written (`given_types`), as a caller
/// of this crate builds it
fn policy(vector: &Value, case: &Value) -> RequestedCertificateSet {
    let mut set = RequestedCertificateSet::new();
    set.add_certifier(key(vector, "certifier").public_key().to_hex());
    for type_id in case["given_types"].as_array().unwrap() {
        set.add_type(type_id.as_str().unwrap().to_string(), vec!["name".into()]);
    }
    set
}

fn auth_error(words: &Value) -> Error {
    Error::AuthError(words.as_str().unwrap().to_string())
}

type Log = Arc<Mutex<Vec<AuthMessage>>>;

/// One end of a pair: records what it sends and routes it to the other end
struct LoggedTransport {
    sent: Log,
    to: mpsc::UnboundedSender<AuthMessage>,
    callback: Arc<Mutex<Option<Box<TransportCallback>>>>,
}

#[async_trait]
impl Transport for LoggedTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        let _ = self.to.send(message.clone());
        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

type TestPeer = Arc<Peer<ProtoWallet, LoggedTransport>>;

struct End {
    peer: TestPeer,
    sent: Log,
    /// The errors its routing task's `handle_incoming_message` returned
    errors: Arc<Mutex<Vec<Error>>>,
    /// The policies its certificate-request listener received
    requested: Arc<Mutex<Vec<RequestedCertificateSet>>>,
    /// The callback `start` registered on its transport
    callback: Arc<Mutex<Option<Box<TransportCallback>>>>,
}

async fn end(
    key: &PrivateKey,
    policy: Option<RequestedCertificateSet>,
    sessions: Option<SessionManager>,
    to: mpsc::UnboundedSender<AuthMessage>,
) -> End {
    let sent: Log = Arc::default();
    let callback: Arc<Mutex<Option<Box<TransportCallback>>>> = Arc::default();
    let peer = Arc::new(Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(key.clone())),
        transport: LoggedTransport {
            sent: sent.clone(),
            to,
            callback: callback.clone(),
        },
        certificates_to_request: policy,
        session_manager: sessions,
        auto_persist_last_session: false,
        originator: Some("test-294".into()),
    }));
    let requested: Arc<Mutex<Vec<RequestedCertificateSet>>> = Arc::default();
    let into = requested.clone();
    peer.listen_for_certificates_requested(move |_sender, set| {
        into.lock().unwrap().push(set);
        Box::pin(async { Ok(()) })
    })
    .await;
    End {
        peer,
        sent,
        errors: Arc::default(),
        requested,
        callback,
    }
}

/// Feeds every message for `end` to its `handle_incoming_message`
fn route(end: &End, mut inbox: mpsc::UnboundedReceiver<AuthMessage>) {
    let peer = end.peer.clone();
    let errors = end.errors.clone();
    tokio::spawn(async move {
        while let Some(message) = inbox.recv().await {
            if let Err(e) = peer.handle_incoming_message(message).await {
                errors.lock().unwrap().push(e);
            }
        }
    });
}

/// A requester and a holder over a loopback, each with its own policy
async fn pair(
    requester_policy: Option<RequestedCertificateSet>,
    holder_policy: Option<RequestedCertificateSet>,
) -> (End, End) {
    let v = vector();
    let (to_holder, holder_inbox) = mpsc::unbounded_channel();
    let (to_requester, requester_inbox) = mpsc::unbounded_channel();
    let requester = end(&key(&v, "requester"), requester_policy, None, to_holder).await;
    let holder = end(&key(&v, "verifier"), holder_policy, None, to_requester).await;
    route(&requester, requester_inbox);
    route(&holder, holder_inbox);
    (requester, holder)
}

async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

fn holder_hex() -> String {
    key(&vector(), "verifier").public_key().to_hex()
}

#[test]
fn the_validator_refuses_each_malformed_type_id_in_the_references_words_294() {
    let v = vector();
    for name in REFUSED {
        let c = case(&v, name);
        assert_eq!(
            assert_requested_certificate_set(&policy(&v, c)),
            Err(auth_error(&c["constructor"]["error"])),
            "{name}"
        );
    }
    let c = case(&v, "type_id_of_32_bytes");
    assert!(c["constructor"]["error"].is_null());
    assert_eq!(assert_requested_certificate_set(&policy(&v, c)), Ok(()));
    // The reference's default policy, `{ certifiers: [], types: {} }`
    assert_eq!(
        assert_requested_certificate_set(&RequestedCertificateSet::new()),
        Ok(())
    );
}

#[tokio::test]
async fn request_certificates_refuses_a_malformed_type_id_before_signing_294() {
    let v = vector();
    for name in REFUSED {
        let c = case(&v, name);
        let (requester, holder) = pair(None, None).await;
        requester
            .peer
            .get_authenticated_session(Some(&holder_hex()), Some(5000))
            .await
            .unwrap();
        settle().await;
        let before = requester.sent.lock().unwrap().len();

        let verdict = requester
            .peer
            .request_certificates(policy(&v, c), Some(&holder_hex()), Some(5000))
            .await;
        settle().await;

        assert_eq!(verdict, Err(auth_error(&c["sender"]["error"])), "{name}");
        // The reference made no signature and sent nothing
        assert_eq!(c["sender"]["signatures_made"], 0, "{name}");
        assert_eq!(
            c["sender"]["messages_sent"],
            serde_json::json!([]),
            "{name}"
        );
        assert_eq!(requester.sent.lock().unwrap().len(), before, "{name}");
        assert!(holder.requested.lock().unwrap().is_empty(), "{name}");
    }
}

#[tokio::test]
async fn request_certificates_signs_and_sends_a_32_byte_type_id_294() {
    let v = vector();
    let c = case(&v, "type_id_of_32_bytes");
    let (requester, holder) = pair(None, None).await;
    requester
        .peer
        .get_authenticated_session(Some(&holder_hex()), Some(5000))
        .await
        .unwrap();
    settle().await;
    let before = requester.sent.lock().unwrap().len();

    requester
        .peer
        .request_certificates(policy(&v, c), Some(&holder_hex()), Some(5000))
        .await
        .unwrap();
    settle().await;

    assert_eq!(
        c["sender"]["messages_sent"],
        serde_json::json!(["certificateRequest"])
    );
    let sent = requester.sent.lock().unwrap();
    assert_eq!(sent.len(), before + 1);
    assert_eq!(sent[before].message_type, MessageType::CertificateRequest);
    assert!(sent[before].signature.is_some());
    let received = holder.requested.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        serde_json::to_string(&received[0]).unwrap(),
        c["sender"]["holder_received_policy_text"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_peer_whose_own_policy_has_a_malformed_type_id_sends_no_initial_request_294() {
    let v = vector();
    for name in REFUSED {
        let c = case(&v, name);
        // The reference refuses the policy at construction (`Peer.ts:158`);
        // this crate's `Peer::new` cannot fail, so the first snapshot does
        let (requester, holder) = pair(Some(policy(&v, c)), None).await;
        let verdict = requester
            .peer
            .get_authenticated_session(Some(&holder_hex()), Some(500))
            .await;
        settle().await;
        assert_eq!(
            verdict.map(|_| ()),
            Err(auth_error(&c["constructor"]["error"])),
            "{name}"
        );
        assert!(requester.sent.lock().unwrap().is_empty(), "{name}");
        assert!(holder.sent.lock().unwrap().is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_peer_whose_own_policy_has_a_malformed_type_id_signs_no_initial_response_294() {
    let v = vector();
    for name in REFUSED {
        let c = case(&v, name);
        let (requester, holder) = pair(None, Some(policy(&v, c))).await;
        let verdict = requester
            .peer
            .get_authenticated_session(Some(&holder_hex()), Some(300))
            .await;
        settle().await;
        assert!(verdict.is_err(), "{name}");
        assert_eq!(
            *holder.errors.lock().unwrap(),
            [auth_error(&c["constructor"]["error"])],
            "{name}"
        );
        assert!(holder.sent.lock().unwrap().is_empty(), "{name}");
    }
}

/// A verifier holding the reference requester's session, as the script's
/// receiver does
async fn verifier_for(case: &Value) -> End {
    let v = vector();
    let receiver = &case["receiver"];
    let mut session = PeerSession::with_nonce(receiver["session_nonce"].as_str().unwrap().into());
    session.peer_nonce = Some(receiver["requester_session_nonce"].as_str().unwrap().into());
    session.peer_identity_key = Some(key(&v, "requester").public_key());
    session.is_authenticated = true;
    let mut sessions = SessionManager::new();
    sessions.add_session(session).unwrap();
    let (to, _inbox) = mpsc::unbounded_channel();
    end(&key(&v, "verifier"), None, Some(sessions), to).await
}

fn received_message(receiver: &Value) -> AuthMessage {
    serde_json::from_str(receiver["message_text"].as_str().unwrap()).unwrap()
}

/// #363 verifies the receiver's wallet nonce. Keep the recorded policy text,
/// but remake the nonce and its signature: the two SDKs' nonce HMACs differ.
async fn locally_signed_message(verifier: &End, receiver: &Value) -> AuthMessage {
    let v = vector();
    let wallet = ProtoWallet::new(Some(key(&v, "verifier")));
    let nonce = create_nonce(&wallet, None, Some("test-294")).await.unwrap();
    let mut message = received_message(receiver);
    let mut sessions = verifier.peer.session_manager().write().await;
    let mut session = sessions
        .get_session(message.your_nonce.as_deref().unwrap())
        .unwrap()
        .clone();
    sessions.remove_session(&session);
    session.session_nonce = Some(nonce.clone());
    sessions.add_session(session).unwrap();
    drop(sessions);
    message.your_nonce = Some(nonce.clone());
    message.signature = Some(
        ProtoWallet::new(Some(key(&v, "requester")))
            .create_signature(CreateSignatureArgs {
                data: Some(message.signing_data()),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
                key_id: message.get_key_id(Some(&nonce)),
                counterparty: Some(Counterparty::Other(key(&v, "verifier").public_key())),
                ..Default::default()
            })
            .unwrap()
            .signature,
    );
    message
}

#[tokio::test]
async fn a_received_certificate_request_with_a_malformed_type_id_is_refused_before_the_handler_294()
{
    let v = vector();
    for name in REFUSED {
        let c = case(&v, name);
        let receiver = &c["receiver"];
        assert_eq!(receiver["signatures_checked"], 0, "{name}");
        assert!(
            receiver["listener_received_policy_text"].is_null(),
            "{name}"
        );

        // The server path
        let verifier = verifier_for(c).await;
        assert_eq!(
            verifier
                .peer
                .handle_incoming_message(received_message(receiver))
                .await,
            Err(auth_error(&receiver["error"])),
            "{name}"
        );
        assert!(verifier.requested.lock().unwrap().is_empty(), "{name}");

        // The client path (`start`)
        let verifier = verifier_for(c).await;
        verifier.peer.start();
        let verdict = {
            let callback = verifier.callback.lock().unwrap();
            callback.as_ref().unwrap()(received_message(receiver))
        }
        .await;
        assert_eq!(verdict, Err(auth_error(&receiver["error"])), "{name}");
        assert!(verifier.requested.lock().unwrap().is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_received_certificate_request_with_a_32_byte_type_id_reaches_the_handler_294() {
    let v = vector();
    let c = case(&v, "type_id_of_32_bytes");
    let receiver = &c["receiver"];
    assert!(receiver["error"].is_null());
    assert_eq!(receiver["signatures_checked"], 1);

    let verifier = verifier_for(c).await;
    let message = locally_signed_message(&verifier, receiver).await;
    verifier
        .peer
        .handle_incoming_message(message)
        .await
        .unwrap();
    let requested = verifier.requested.lock().unwrap();
    assert_eq!(requested.len(), 1);
    assert_eq!(
        serde_json::to_string(&requested[0]).unwrap(),
        receiver["listener_received_policy_text"].as_str().unwrap()
    );
}

#[tokio::test]
async fn a_received_certificate_request_without_requested_certificates_is_refused_294() {
    let v = vector();
    let receiver = &v["absent_requested_certificates"]["receiver"];
    assert_eq!(receiver["signatures_checked"], 0);
    let message = received_message(receiver);
    assert!(message.requested_certificates.is_none());
    let mut case = case(&v, "type_id_of_32_bytes").clone();
    case["receiver"] = receiver.clone();
    let verifier = verifier_for(&case).await;
    assert_eq!(
        verifier.peer.handle_incoming_message(message).await,
        Err(auth_error(&receiver["error"]))
    );
}

#[test]
fn an_integer_like_type_id_is_signed_by_neither_side_294() {
    let v = vector();
    let c = case(&v, "type_id_integer_like");
    // Written second; the reference's object moves it first (#288's note)
    assert_eq!(c["given_types"][1], "42");
    let text = c["policy_text"].as_str().unwrap();
    assert!(
        text.find("\"42\"").unwrap() < text.find("AQEB").unwrap(),
        "{text}"
    );
    let set = policy(&v, c);
    assert_eq!(set.types.keys().nth(1).map(String::as_str), Some("42"));
    // Neither order reaches a signature: both sides refuse the key
    assert_eq!(
        assert_requested_certificate_set(&set),
        Err(auth_error(&c["sender"]["error"]))
    );
    let read: RequestedCertificateSet = serde_json::from_str(text).unwrap();
    assert_eq!(
        assert_requested_certificate_set(&read),
        Err(auth_error(&c["receiver"]["error"]))
    );
}
