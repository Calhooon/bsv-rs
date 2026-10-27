//! `Peer::start`'s client path verifies the initial response and general
//! messages as the reference's `Peer` does (#353): the nonce it echoes, its
//! session, the pinned identity and the signature (`ts-stack@edf6e03`
//! `Peer.ts:886-930`), and a general message's `yourNonce`, session, sender,
//! signature and nonce (`:1270-1314`). Until 0.9 `start` marked a session
//! authenticated on any initial response and handed any general message to
//! the listeners.
//!
//! The witnesses are `tests/vectors/auth_peer_client_verifies_353.json`,
//! written by `tests/support/auth_peer_client_verifies_353.mjs` under Node
//! v22.18.0: a reference client `Peer` (scalar 41) pinned to its server
//! (scalar 42) given an initial response forged at one field by the script,
//! or, after an honest handshake, a general message forged at one field, each
//! verdict recorded with the client on a `ProtoWallet` (`proto`, its verify
//! calls throw on a miss) and on a wallet answering `{ valid: false }`
//! (`answering`, the Peer's own words reached). Each case runs here over an
//! in-process transport whose deliveries go through the callback `start`
//! installs; the verdicts are the reference's, save the three in `STATED`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{create_nonce, AuthMessage, MessageType, Peer, PeerOptions, AUTH_PROTOCOL_ID};
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey};
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const VECTOR: &str = include_str!("vectors/auth_peer_client_verifies_353.json");

/// The verdicts whose words differ from the reference's, each with this
/// crate's: the reference's nonce check asks its wallet's `verifyHmac`, which
/// a `ProtoWallet` throws on (`verifyNonce.ts:44-53`), where this crate's
/// `verify_nonce` recomputes the HMAC (`createHmac`, for the 32-byte legacy
/// nonces) and reaches the Peer's words; the reference's message snapshot
/// refuses a general message without a nonce before its `Peer` reads it
/// (`snapshotAuthMessage`, `Peer.ts:767`), where this crate has no snapshot
/// and the Peer's own check refuses it. Each is a refusal on both sides.
const STATED: [(&str, &str, &str); 4] = [
    (
        "initial_response_wrong_nonce",
        "proto",
        "Initial response nonce verification failed from peer: 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
    ),
    (
        "general_wrong_your_nonce",
        "proto",
        "Unable to verify nonce for general message from: 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
    ),
    ("general_no_nonce", "proto", "General message nonce is required."),
    ("general_no_nonce", "answering", "General message nonce is required."),
];

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn scalar(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

fn client_key() -> PrivateKey {
    scalar(41)
}

fn server_key() -> PrivateKey {
    scalar(42)
}

fn mallory_key() -> PrivateKey {
    scalar(43)
}

// ---------------------------------------------------------------------------
// A ProtoWallet, or one that answers a verify miss with `valid: false`
// ---------------------------------------------------------------------------

struct TestWallet {
    inner: ProtoWallet,
    answering: bool,
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! test_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait]
        impl WalletInterface for TestWallet {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

            async fn verify_hmac(&self, args: VerifyHmacArgs, o: Option<&str>) -> Result<VerifyHmacResult> {
                match WalletInterface::verify_hmac(&self.inner, args, o).await {
                    Err(_) if self.answering => Ok(VerifyHmacResult { valid: false }),
                    other => other,
                }
            }
            async fn verify_signature(
                &self,
                args: VerifySignatureArgs,
                o: Option<&str>,
            ) -> Result<VerifySignatureResult> {
                match WalletInterface::verify_signature(&self.inner, args, o).await {
                    Err(_) if self.answering => Ok(VerifySignatureResult { valid: false }),
                    other => other,
                }
            }
            async fn is_authenticated(&self, o: Option<&str>) -> Result<AuthenticatedResult> {
                WalletInterface::is_authenticated(&self.inner, o).await
            }
            async fn wait_for_authentication(&self, o: Option<&str>) -> Result<AuthenticatedResult> {
                WalletInterface::wait_for_authentication(&self.inner, o).await
            }
            async fn get_height(&self, o: Option<&str>) -> Result<GetHeightResult> {
                WalletInterface::get_height(&self.inner, o).await
            }
            async fn get_network(&self, o: Option<&str>) -> Result<GetNetworkResult> {
                WalletInterface::get_network(&self.inner, o).await
            }
            async fn get_version(&self, o: Option<&str>) -> Result<GetVersionResult> {
                WalletInterface::get_version(&self.inner, o).await
            }
        }
    };
}

test_wallet! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

fn wallet(key: &PrivateKey, kind: &str) -> TestWallet {
    TestWallet {
        inner: ProtoWallet::new(Some(key.clone())),
        answering: kind == "answering",
    }
}

// ---------------------------------------------------------------------------
// An in-process transport: what a peer sends lands in `sent`; what it is
// given goes through the callback `start` installed
// ---------------------------------------------------------------------------

type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;

struct Wire {
    out: mpsc::UnboundedSender<AuthMessage>,
    callback: Callback,
}

#[async_trait]
impl Transport for Wire {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.out
            .send(message.clone())
            .map_err(|e| Error::AuthError(format!("closed: {e}")))
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

/// Hands `message` to the callback `start` installed; its verdict
async fn deliver(callback: &Callback, message: AuthMessage) -> Result<()> {
    let verdict = {
        let callback = callback.lock().unwrap();
        callback.as_ref().expect("the peer is started")(message)
    };
    verdict.await
}

struct End {
    peer: Arc<Peer<TestWallet, Wire>>,
    callback: Callback,
    sent: Option<mpsc::UnboundedReceiver<AuthMessage>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// A peer on `start` (or, for `server`, `start_server`), its listener
/// recording each payload
async fn end(wallet: TestWallet, server: bool) -> End {
    let (out, sent) = mpsc::unbounded_channel();
    let callback: Callback = Arc::new(Mutex::new(None));
    let peer = Arc::new(Peer::new(PeerOptions {
        wallet,
        transport: Wire {
            out,
            callback: callback.clone(),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    }));
    if server {
        peer.start_server();
    } else {
        peer.start();
    }
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    peer.listen_for_general_messages(move |_, payload| {
        log.lock().unwrap().push(payload);
        Box::pin(async { Ok(()) })
    })
    .await;
    End {
        peer,
        callback,
        sent: Some(sent),
        received,
    }
}

/// Carries each message `from` sends to `to`'s callback
fn route(from: &mut End, to: &End) {
    let mut sent = from.sent.take().unwrap();
    let callback = to.callback.clone();
    tokio::spawn(async move {
        while let Some(message) = sent.recv().await {
            let _ = deliver(&callback, message).await;
        }
    });
}

/// A client (on `start`) and a server, each routed to the other, the server
/// on `start_server` unless `both_on_start`
async fn pair(kind: &str, both_on_start: bool) -> (End, End) {
    let mut client = end(wallet(&client_key(), kind), false).await;
    let mut server = end(wallet(&server_key(), "proto"), !both_on_start).await;
    route(&mut client, &server);
    route(&mut server, &client);
    (client, server)
}

fn sign(signer: &PrivateKey, key_id: &str, data: &[u8]) -> Vec<u8> {
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(data.to_vec()),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: key_id.to_string(),
            counterparty: Some(Counterparty::Other(client_key().public_key())),
            ..Default::default()
        })
        .unwrap()
        .signature
}

async fn nonce_of(key: &PrivateKey) -> String {
    create_nonce(&ProtoWallet::new(Some(key.clone())), None, Some("test"))
        .await
        .unwrap()
}

/// An initial response from `responder` to the client's `your_nonce`, signed
/// under `key_id` (the honest one when `None`)
async fn initial_response(
    responder: &PrivateKey,
    your_nonce: &str,
    key_id: Option<String>,
) -> AuthMessage {
    let responder_nonce = nonce_of(responder).await;
    let mut data = from_base64(your_nonce).unwrap();
    data.extend(from_base64(&responder_nonce).unwrap());
    let key_id = key_id.unwrap_or_else(|| format!("{your_nonce} {responder_nonce}"));
    let mut message = AuthMessage::new(MessageType::InitialResponse, responder.public_key());
    message.initial_nonce = Some(responder_nonce);
    message.your_nonce = Some(your_nonce.to_string());
    message.signature = Some(sign(responder, &key_id, &data));
    message
}

fn words(verdict: &Result<()>) -> Value {
    match verdict {
        Ok(()) => Value::Null,
        Err(Error::AuthError(words) | Error::WalletError(words)) => Value::String(words.clone()),
        Err(other) => Value::String(format!("not a refusal: {other:?}")),
    }
}

/// The reference's verdict, or this crate's stated one
fn expected(case: &str, kind: &str) -> Value {
    STATED
        .iter()
        .find(|(c, k, _)| *c == case && *k == kind)
        .map(|(_, _, words)| Value::String(words.to_string()))
        .unwrap_or_else(|| vector()["cases"][case][kind].clone())
}

/// The client asks for a session pinned to the server and is given the
/// response `case` forges; the verdict, and the handshake's result
async fn initial_case(
    case: &str,
    kind: &str,
) -> (Result<()>, Result<bsv_rs::auth::PeerSession>, End) {
    let mut client = end(wallet(&client_key(), kind), false).await;
    let peer = client.peer.clone();
    let pinned = server_key().public_key().to_hex();
    let handshake = tokio::spawn(async move {
        peer.get_authenticated_session(Some(&pinned), Some(500))
            .await
    });
    let request = client.sent.as_mut().unwrap().recv().await.unwrap();
    assert_eq!(request.message_type, MessageType::InitialRequest);
    let ours = request.initial_nonce.unwrap();
    let response = match case {
        "initial_response_honest" => initial_response(&server_key(), &ours, None).await,
        "initial_response_wrong_signature" => {
            initial_response(&server_key(), &ours, Some(format!("{ours} not-the-nonce"))).await
        }
        "initial_response_another_identity" => initial_response(&mallory_key(), &ours, None).await,
        "initial_response_wrong_nonce" => {
            initial_response(&server_key(), &nonce_of(&server_key()).await, None).await
        }
        _ => unreachable!(),
    };
    let verdict = deliver(&client.callback, response).await;
    (verdict, handshake.await.unwrap(), client)
}

/// After an honest handshake with the server, the client is given the
/// general message `case` forges from it; the verdict
async fn general_case(case: &str, kind: &str) -> (Result<()>, End) {
    let (client, _server) = pair(kind, false).await;
    let server_hex = server_key().public_key().to_hex();
    let session = client
        .peer
        .get_authenticated_session(Some(&server_hex), Some(5000))
        .await
        .unwrap();
    let ours = session.session_nonce.unwrap();
    let nonce = to_base64(&[7u8; 32]);
    let payload = vec![1u8, 2, 3];
    let mut message = AuthMessage::new(MessageType::General, server_key().public_key());
    message.nonce = Some(nonce.clone());
    message.your_nonce = Some(ours.clone());
    message.payload = Some(payload.clone());
    let honest = sign(&server_key(), &format!("{nonce} {ours}"), &payload);
    let by_mallory = sign(&mallory_key(), &format!("{nonce} {ours}"), &payload);
    message.signature = Some(honest);
    match case {
        "general_honest" => {}
        "general_wrong_your_nonce" => message.your_nonce = Some(nonce_of(&server_key()).await),
        "general_no_nonce" => {
            message.nonce = None;
            message.signature = Some(sign(&server_key(), &format!(" {ours}"), &payload));
        }
        "general_wrong_signature" => message.signature = Some(by_mallory),
        "general_another_identity" => {
            message.identity_key = mallory_key().public_key();
            message.signature = Some(by_mallory);
        }
        _ => unreachable!(),
    }
    let verdict = deliver(&client.callback, message).await;
    (verdict, client)
}

async fn authenticated_sessions(end: &End) -> usize {
    let sessions = end.peer.session_manager().read().await;
    sessions.iter().filter(|s| s.is_authenticated).count()
}

#[test]
fn the_vector_is_the_reference_at_edf6e03_with_the_fixed_keys() {
    let v = vector();
    assert!(v["source"].as_str().unwrap().contains("ts-stack@edf6e03"));
    for (name, n) in [("client", 41), ("server", 42), ("mallory", 43)] {
        assert_eq!(v["keys"][name], n);
        assert_eq!(
            v["identities"][name].as_str().unwrap(),
            scalar(n).public_key().to_hex()
        );
    }
    assert_eq!(v["cases"].as_object().unwrap().len(), 9);
    // The stated words are refusals where the reference refuses too
    for (case, kind, _) in STATED {
        assert!(v["cases"][case][kind].is_string(), "{case} {kind}");
    }
}

#[tokio::test]
async fn a_forged_initial_response_is_refused_by_a_client_on_start_353() {
    for case in [
        "initial_response_wrong_signature",
        "initial_response_another_identity",
        "initial_response_wrong_nonce",
    ] {
        for kind in ["proto", "answering"] {
            let (verdict, handshake, client) = initial_case(case, kind).await;
            assert_eq!(words(&verdict), expected(case, kind), "{case} {kind}");
            assert!(handshake.is_err(), "{case} {kind}: {handshake:?}");
            assert_eq!(authenticated_sessions(&client).await, 0, "{case} {kind}");
            // The refusal reaches the waiting handshake, save where yourNonce
            // names none of ours (it times out, as the reference's does)
            let words_given = handshake.unwrap_err().to_string();
            if case == "initial_response_wrong_nonce" {
                assert!(
                    words_given.contains("timeout"),
                    "{case} {kind}: {words_given}"
                );
            } else {
                let refusal = verdict.unwrap_err().to_string();
                assert_eq!(words_given, refusal, "{case} {kind}");
            }
        }
    }
}

#[tokio::test]
async fn an_honest_initial_response_authenticates_the_pinned_session_353() {
    for kind in ["proto", "answering"] {
        let (verdict, handshake, client) = initial_case("initial_response_honest", kind).await;
        assert_eq!(words(&verdict), expected("initial_response_honest", kind));
        let session = handshake.unwrap();
        assert!(session.is_authenticated);
        assert_eq!(session.peer_identity_key, Some(server_key().public_key()));
        assert_eq!(authenticated_sessions(&client).await, 1);
    }
}

#[tokio::test]
async fn a_forged_general_message_is_refused_by_a_client_on_start_353() {
    for case in [
        "general_wrong_your_nonce",
        "general_no_nonce",
        "general_wrong_signature",
        "general_another_identity",
    ] {
        for kind in ["proto", "answering"] {
            let (verdict, client) = general_case(case, kind).await;
            assert_eq!(words(&verdict), expected(case, kind), "{case} {kind}");
            assert!(client.received.lock().unwrap().is_empty(), "{case} {kind}");
        }
    }
}

#[tokio::test]
async fn an_honest_general_message_reaches_the_listener_353() {
    for kind in ["proto", "answering"] {
        let (verdict, client) = general_case("general_honest", kind).await;
        assert_eq!(words(&verdict), expected("general_honest", kind));
        assert_eq!(*client.received.lock().unwrap(), vec![vec![1u8, 2, 3]]);
    }
}

#[tokio::test]
async fn a_handshake_pinned_to_one_identity_refuses_another_353() {
    // The server answers honestly, but the client asked for mallory
    let (client, _server) = pair("proto", false).await;
    let mallory = mallory_key().public_key().to_hex();
    let refused = client
        .peer
        .get_authenticated_session(Some(&mallory), Some(2000))
        .await;
    assert_eq!(
        refused.unwrap_err(),
        Error::AuthError(
            "initialResponse identity does not match the requested peer identity.".into()
        )
    );
    assert_eq!(authenticated_sessions(&client).await, 0);
    // The failed handshake's session is gone, as the reference removes it
    assert!(client.peer.session_manager().read().await.is_empty());
}

#[tokio::test]
async fn two_peers_on_start_handshake_and_exchange_messages_353() {
    // Both on `start`: the server answers the initial request on the one path
    let (client, server) = pair("proto", true).await;
    let server_hex = server_key().public_key().to_hex();
    let client_hex = client_key().public_key().to_hex();
    for round in 0u8..3 {
        client
            .peer
            .to_peer(&[round], Some(&server_hex), Some(5000))
            .await
            .unwrap();
        server
            .peer
            .to_peer(&[round + 10], Some(&client_hex), Some(5000))
            .await
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        *server.received.lock().unwrap(),
        vec![vec![0u8], vec![1], vec![2]]
    );
    assert_eq!(
        *client.received.lock().unwrap(),
        vec![vec![10u8], vec![11], vec![12]]
    );
    assert_eq!(authenticated_sessions(&client).await, 1);
    assert_eq!(authenticated_sessions(&server).await, 1);
}

#[tokio::test]
async fn a_handshake_named_by_a_string_that_is_no_identity_key_is_refused_353() {
    let (client, _server) = pair("proto", false).await;
    assert!(matches!(
        client
            .peer
            .get_authenticated_session(Some("not-a-key"), Some(500))
            .await,
        Err(Error::InvalidPublicKey(_) | Error::InvalidHex(_))
    ));
    assert!(client.peer.session_manager().read().await.is_empty());
}

// ---------------------------------------------------------------------------
// A dropped Peer is freed: the callback `start` installs in the transport
// holds no strong reference back to it (the #353 review's F1)
// ---------------------------------------------------------------------------

/// A transport holding a marker: the marker's count says whether the
/// transport (and the callback in it) outlived its Peer
struct Held {
    _marker: Arc<()>,
    callback: Mutex<Option<Box<TransportCallback>>>,
}

#[async_trait]
impl Transport for Held {
    async fn send(&self, _message: &AuthMessage) -> Result<()> {
        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

fn held_peer(marker: &Arc<()>) -> Peer<ProtoWallet, Held> {
    Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(client_key())),
        transport: Held {
            _marker: marker.clone(),
            callback: Mutex::new(None),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    })
}

#[test]
fn a_dropped_peer_on_start_frees_its_transport_353() {
    let marker = Arc::new(());
    let peer = held_peer(&marker);
    peer.start();
    assert_eq!(Arc::strong_count(&marker), 2);
    drop(peer);
    assert_eq!(
        Arc::strong_count(&marker),
        1,
        "the transport outlives its Peer"
    );
}

#[test]
fn a_dropped_peer_on_start_server_frees_its_transport_353() {
    let marker = Arc::new(());
    let peer = Arc::new(held_peer(&marker));
    peer.start_server();
    drop(peer);
    assert_eq!(
        Arc::strong_count(&marker),
        1,
        "the transport outlives its Peer"
    );
}
