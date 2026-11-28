//! The client receive path set up by [`Peer::start`] verifies a received
//! message before it reaches a listener or completes a handshake.
//!
//! Before this fix, `start` installed a callback that dispatched by message
//! type and handed `General`, `CertificateRequest` and `CertificateResponse`
//! messages to their listeners — and completed the handshake from an
//! `InitialResponse` — WITHOUT checking the signature, the session, the
//! identity or the nonce. A counterparty or a transport-position attacker
//! could hand a client forged "authenticated" content attributed to the peer
//! identity the client meant to authenticate. `start` now routes every
//! incoming message through the one verifying path both roles share, so a
//! forged message is refused and never reaches the caller; an honest, correctly
//! signed message is delivered unchanged.
//!
//! All transports (`SimplifiedFetchTransport`, the WebSocket and Socket.IO
//! transports, `MockTransport`) deliver only through the callback `start`
//! installs, so the Peer-level verification exercised here closes the path on
//! every transport. These tests are hermetic: no network, no port; the forging
//! side builds its `AuthMessage`s with this crate's own types, and the honest
//! side is two real peers over an in-memory transport.

#![cfg(all(test, feature = "auth"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::types::{AuthMessage, MessageType, PeerSession};
use bsv_rs::auth::{Peer, PeerOptions, AUTH_PROTOCOL_ID};
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

type CbSlot = Arc<Mutex<Option<Box<TransportCallback>>>>;

/// A one-sided transport: the test injects a crafted message into the Peer's
/// own callback (exactly what any transport, or a man in the middle, hands the
/// Peer), and records what the Peer sends.
#[derive(Clone)]
struct ProbeTransport {
    cb: CbSlot,
    sent: Arc<Mutex<Vec<AuthMessage>>>,
}

impl ProbeTransport {
    fn new() -> Self {
        Self {
            cb: Arc::new(Mutex::new(None)),
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn deliver(&self, msg: AuthMessage) -> Result<()> {
        let fut = { self.cb.lock().unwrap().as_ref().map(|cb| cb(msg)) };
        match fut {
            Some(f) => f.await,
            None => Ok(()),
        }
    }
}

#[async_trait]
impl Transport for ProbeTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.cb.lock().unwrap() = Some(callback);
    }
    fn clear_callback(&self) {
        *self.cb.lock().unwrap() = None;
    }
}

/// A loopback half: `send` delivers to the other peer's callback (spawned, so a
/// reentrant handshake does not deadlock) and records the message.
struct Loopback {
    inbound: CbSlot,
    outbound: CbSlot,
    sent: Arc<Mutex<Vec<AuthMessage>>>,
}

#[async_trait]
impl Transport for Loopback {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        let fut = {
            self.outbound
                .lock()
                .unwrap()
                .as_ref()
                .map(|cb| cb(message.clone()))
        };
        if let Some(f) = fut {
            tokio::spawn(f);
        }
        Ok(())
    }
    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.inbound.lock().unwrap() = Some(callback);
    }
    fn clear_callback(&self) {
        *self.inbound.lock().unwrap() = None;
    }
}

fn client_peer(sk: PrivateKey, transport: ProbeTransport) -> Peer<ProtoWallet, ProbeTransport> {
    Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(sk)),
        transport,
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("peer-start-verify".into()),
    })
}

fn general(
    identity: PublicKey,
    payload: &[u8],
    nonce: Option<&str>,
    your_nonce: Option<&str>,
    sig: Option<Vec<u8>>,
) -> AuthMessage {
    let mut m = AuthMessage::new(MessageType::General, identity);
    m.payload = Some(payload.to_vec());
    m.nonce = nonce.map(str::to_string);
    m.your_nonce = your_nonce.map(str::to_string);
    m.signature = sig;
    m
}

// A DER-looking but meaningless signature (two 32-byte integers of 1s and 2s).
fn garbage_sig() -> Vec<u8> {
    let mut v = vec![0x30, 0x44, 0x02, 0x20];
    v.extend_from_slice(&[1u8; 32]);
    v.extend_from_slice(&[0x02, 0x20]);
    v.extend_from_slice(&[2u8; 32]);
    v
}

/// Register a General listener on `peer` and return its fire counter.
async fn count_general<T: Transport + 'static>(peer: &Peer<ProtoWallet, T>) -> Arc<AtomicUsize> {
    let fired = Arc::new(AtomicUsize::new(0));
    let f = fired.clone();
    peer.listen_for_general_messages(move |_sender, _payload| {
        let f = f.clone();
        Box::pin(async move {
            f.fetch_add(1, SeqCst);
            Ok(())
        })
    })
    .await;
    fired
}

async fn deliver_forged_general(msg: AuthMessage) -> (usize, bool) {
    let probe = ProbeTransport::new();
    let peer = client_peer(PrivateKey::random(), probe.clone());
    peer.start();
    let fired = count_general(&peer).await;
    let r = probe.deliver(msg).await;
    (fired.load(SeqCst), r.is_err())
}

#[tokio::test]
async fn start_refuses_a_general_message_with_no_signature() {
    let server = PrivateKey::random().public_key();
    let (fired, refused) = deliver_forged_general(general(
        server,
        b"forged",
        Some("YmJiYg=="),
        Some("Y2NjYw=="),
        None,
    ))
    .await;
    assert_eq!(fired, 0, "unsigned General must not reach the listener");
    assert!(refused, "unsigned General must be refused");
}

#[tokio::test]
async fn start_refuses_a_general_message_with_a_garbage_signature() {
    let server = PrivateKey::random().public_key();
    let (fired, refused) = deliver_forged_general(general(
        server,
        b"forged",
        Some("YmJiYg=="),
        Some("Y2NjYw=="),
        Some(garbage_sig()),
    ))
    .await;
    assert_eq!(fired, 0, "a garbage signature must not reach the listener");
    assert!(refused);
}

#[tokio::test]
async fn start_refuses_a_general_message_signed_by_another_key() {
    let attacker = PrivateKey::random().public_key();
    let (fired, refused) = deliver_forged_general(general(
        attacker,
        b"forged",
        Some("YmJiYg=="),
        Some("Y2NjYw=="),
        Some(garbage_sig()),
    ))
    .await;
    assert_eq!(
        fired, 0,
        "a message from an unrelated key must not reach the listener"
    );
    assert!(refused);
}

#[tokio::test]
async fn start_refuses_a_general_message_with_a_foreign_your_nonce() {
    // your_nonce is a nonce this peer never issued: verification fails first.
    let server = PrivateKey::random().public_key();
    let (fired, refused) = deliver_forged_general(general(
        server,
        b"forged",
        Some("YmJiYg=="),
        Some("Zm9yZWlnbg=="),
        Some(garbage_sig()),
    ))
    .await;
    assert_eq!(fired, 0, "a foreign your_nonce must not reach the listener");
    assert!(refused);
}

#[tokio::test]
async fn start_refuses_a_general_message_without_any_session() {
    // A first message, no nonces at all, before any handshake.
    let server = PrivateKey::random().public_key();
    let (fired, refused) =
        deliver_forged_general(general(server, b"forged", None, None, None)).await;
    assert_eq!(
        fired, 0,
        "a General before any handshake must not reach the listener"
    );
    assert!(refused);
}

#[tokio::test]
async fn start_refuses_a_forged_general_replayed_twice() {
    // A forged message delivered twice reaches the listener zero times (the
    // pre-fix path delivered it both times).
    let probe = ProbeTransport::new();
    let peer = client_peer(PrivateKey::random(), probe.clone());
    peer.start();
    let fired = count_general(&peer).await;
    let server = PrivateKey::random().public_key();
    let msg = general(
        server,
        b"forged",
        Some("YmJiYg=="),
        Some("Y2NjYw=="),
        Some(garbage_sig()),
    );
    let _ = probe.deliver(msg.clone()).await;
    let _ = probe.deliver(msg).await;
    assert_eq!(
        fired.load(SeqCst),
        0,
        "a replayed forged General must not reach the listener"
    );
}

#[tokio::test]
async fn start_refuses_a_forged_certificate_request() {
    let probe = ProbeTransport::new();
    let peer = client_peer(PrivateKey::random(), probe.clone());
    peer.start();
    let fired = Arc::new(AtomicUsize::new(0));
    let f = fired.clone();
    peer.listen_for_certificates_requested(move |_sender, _requested| {
        let f = f.clone();
        Box::pin(async move {
            f.fetch_add(1, SeqCst);
            Ok(())
        })
    })
    .await;
    let server = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::CertificateRequest, server);
    msg.your_nonce = Some("Y2NjYw==".into());
    msg.signature = Some(garbage_sig());
    let r = probe.deliver(msg).await;
    assert_eq!(
        fired.load(SeqCst),
        0,
        "a forged certificate request must not reach the listener"
    );
    assert!(r.is_err());
}

#[tokio::test]
async fn start_refuses_a_forged_certificate_response() {
    let probe = ProbeTransport::new();
    let peer = client_peer(PrivateKey::random(), probe.clone());
    peer.start();
    let fired = Arc::new(AtomicUsize::new(0));
    let f = fired.clone();
    peer.listen_for_certificates_received(move |_sender, _certs| {
        let f = f.clone();
        Box::pin(async move {
            f.fetch_add(1, SeqCst);
            Ok(())
        })
    })
    .await;
    let server = PrivateKey::random().public_key();
    let mut msg = AuthMessage::new(MessageType::CertificateResponse, server);
    msg.your_nonce = Some("Y2NjYw==".into());
    msg.signature = Some(garbage_sig());
    let r = probe.deliver(msg).await;
    assert_eq!(
        fired.load(SeqCst),
        0,
        "a forged certificate response must not reach the listener"
    );
    assert!(r.is_err());
}

#[tokio::test]
async fn start_refuses_a_forged_initial_response_so_the_handshake_does_not_complete() {
    let probe = ProbeTransport::new();
    let peer = client_peer(PrivateKey::random(), probe.clone());
    peer.start();
    let server = PrivateKey::random().public_key();
    let server_hex = server.to_hex();

    // Drive the handshake: wait for the InitialRequest, then inject a forged
    // InitialResponse carrying our real (echoed) nonce but a garbage signature.
    let probe2 = probe.clone();
    let server2 = server.clone();
    let drive = async move {
        let mut echoed = None;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if let Some(ir) = probe2
                .sent
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.message_type == MessageType::InitialRequest)
                .cloned()
            {
                echoed = ir.initial_nonce.clone();
                break;
            }
        }
        let echoed = echoed.expect("the client must have sent an InitialRequest");
        let mut resp = AuthMessage::new(MessageType::InitialResponse, server2);
        resp.your_nonce = Some(echoed);
        resp.nonce = Some("YXR0YWNrZXItbm9uY2U=".into());
        resp.initial_nonce = Some("YXR0YWNrZXItbm9uY2U=".into());
        resp.signature = Some(garbage_sig());
        let _ = probe2.deliver(resp).await;
    };

    let send = peer.to_peer(b"hi", Some(&server_hex), Some(1500));
    let (res, _) = tokio::join!(send, drive);
    assert!(
        res.is_err(),
        "a forged InitialResponse must not complete an authenticated session"
    );
}

// ---- The honest control and the one deliberately-unported 0.9 behaviour ----

/// Build two peers wired to each other by an in-memory loopback, start both,
/// and register a General listener on B. Returns (peerA, peerB_identity_hex,
/// B_fire_counter, A_sent_messages, B_inbound_callback_slot).
async fn honest_pair() -> (
    Peer<ProtoWallet, Loopback>,
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<AuthMessage>>>,
    CbSlot,
) {
    let a_cb: CbSlot = Arc::new(Mutex::new(None));
    let b_cb: CbSlot = Arc::new(Mutex::new(None));
    let a_sent = Arc::new(Mutex::new(Vec::new()));
    let b_sent = Arc::new(Mutex::new(Vec::new()));

    let a = Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(PrivateKey::random())),
        transport: Loopback {
            inbound: a_cb.clone(),
            outbound: b_cb.clone(),
            sent: a_sent.clone(),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("peer-start-verify-a".into()),
    });
    let b_sk = PrivateKey::random();
    let b_hex = b_sk.public_key().to_hex();
    // B is the responder: a server-role peer, as on 0.8.13 a responder had to
    // be (a `start()` peer ignored InitialRequest). This is the honest topology
    // that must behave the same before and after the fix.
    let b = Arc::new(Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(b_sk)),
        transport: Loopback {
            inbound: b_cb.clone(),
            outbound: a_cb.clone(),
            sent: b_sent,
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("peer-start-verify-b".into()),
    }));
    a.start();
    b.start_server();
    let fired = Arc::new(AtomicUsize::new(0));
    let f = fired.clone();
    b.listen_for_general_messages(move |_s, _p| {
        let f = f.clone();
        Box::pin(async move {
            f.fetch_add(1, SeqCst);
            Ok(())
        })
    })
    .await;
    // B owns its transport strongly; it must outlive the spawned deliveries, so
    // leak the Arc for the test's lifetime.
    Box::leak(Box::new(b));
    (a, b_hex, fired, a_sent, b_cb)
}

#[tokio::test]
async fn two_honest_peers_still_exchange_a_general_message() {
    let (a, b_hex, fired, _sent, _b_cb) = honest_pair().await;
    a.to_peer(b"hello", Some(&b_hex), Some(3000))
        .await
        .expect("an honest handshake and General must succeed");
    // Let the spawned General delivery reach B.
    for _ in 0..100 {
        if fired.load(SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        fired.load(SeqCst),
        1,
        "an honest signed General must be delivered once"
    );
}

/// S4 note: the 0.9 line also claims each message nonce once (replay refusal,
/// #445). That is a distinct, lower-severity, higher-bar matter (it needs a
/// *validly captured* signed message, not a forgery) and is NOT part of the
/// unsigned-content-trusted class this fix closes; it is deliberately not
/// ported here. This test pins the resulting stable-line behaviour: a validly
/// signed General, replayed verbatim, is still delivered a second time. Had the
/// 0.9 nonce claim travelled with this port, the second delivery would be
/// refused and this assertion would read `2 -> 1`.
#[tokio::test]
async fn a_validly_signed_general_replayed_is_redelivered_without_the_0_9_nonce_claim() {
    let (a, b_hex, fired, a_sent, b_cb) = honest_pair().await;
    a.to_peer(b"hello", Some(&b_hex), Some(3000)).await.unwrap();
    for _ in 0..100 {
        if fired.load(SeqCst) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(fired.load(SeqCst), 1);

    // Replay the exact signed General A sent to B, as a transport or a man in
    // the middle could, by delivering it to B's callback a second time.
    let signed = a_sent
        .lock()
        .unwrap()
        .iter()
        .find(|m| m.message_type == MessageType::General)
        .cloned()
        .expect("A must have sent a signed General");
    let fut = { b_cb.lock().unwrap().as_ref().map(|cb| cb(signed)) };
    let _ = fut.expect("B has a callback").await;
    assert_eq!(
        fired.load(SeqCst),
        2,
        "the 0.9 replay nonce-claim is deliberately not ported on the stable line"
    );
}

// ---------------------------------------------------------------------------
// Isolating regression tests for the two identity checks (and the general
// signature) on a REAL authenticated session.
//
// The forged-* tests above inject a message into a client that never completed
// a handshake, so each is refused at the echoed-nonce / session-lookup stage
// (verify_own_nonce, get_session) BEFORE the identity and signature checks are
// reached. The three tests here first establish a real authenticated client
// session, then exercise ONE check each, so a future edit that drops that one
// check is caught instead of passing silently (CLAUDE.md rule 2). They pin the
// two properties the port must guarantee (the #353 client path), isolated:
//   * a General whose claimed identity is not the session's authenticated peer
//     never reaches the listener (the general identity check);
//   * a handshake asked toward one identity is refused when the response proves
//     another, and no session is stored (the handshake identity pinning);
//   * a General on a live session that is not signed by its peer is refused
//     (the general signature check).
// ---------------------------------------------------------------------------

/// A fixed private key, as the reference vectors use (scalar `n`).
fn scalar(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

/// A valid General signature by `signer`, over `payload`, bound to the
/// receiver's session (`key_id = "{message_nonce} {session_nonce}"`,
/// counterparty = the receiver), as `sign_message` and `verify_message_signature`
/// compute it. The signer need not be the session's peer: the receiver's
/// signature check passes for any key that actually signed, so this lets a test
/// isolate the *identity* check from the *signature* check.
fn sign_general(
    signer: &PrivateKey,
    message_nonce: &str,
    session_nonce: &str,
    payload: &[u8],
    receiver: PublicKey,
) -> Vec<u8> {
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(payload.to_vec()),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: format!("{message_nonce} {session_nonce}"),
            counterparty: Some(Counterparty::Other(receiver)),
        })
        .unwrap()
        .signature
}

/// A started client (on `start`) and a started server (on `start_server`),
/// wired to each other by the in-memory loopback. Returns the client and its
/// inbound callback slot (where a transport, or a man in the middle, hands it a
/// message). The server is leaked for the test's lifetime, as it owns its
/// transport strongly.
fn start_client_and_server(
    client_sk: PrivateKey,
    server_sk: PrivateKey,
) -> (Peer<ProtoWallet, Loopback>, CbSlot) {
    let a_cb: CbSlot = Arc::new(Mutex::new(None));
    let b_cb: CbSlot = Arc::new(Mutex::new(None));
    let a = Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(client_sk)),
        transport: Loopback {
            inbound: a_cb.clone(),
            outbound: b_cb.clone(),
            sent: Arc::new(Mutex::new(Vec::new())),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("fold-client".into()),
    });
    let b = Arc::new(Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(server_sk)),
        transport: Loopback {
            inbound: b_cb.clone(),
            outbound: a_cb.clone(),
            sent: Arc::new(Mutex::new(Vec::new())),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("fold-server".into()),
    }));
    a.start();
    b.start_server();
    Box::leak(Box::new(b));
    (a, a_cb)
}

/// A client with a real authenticated session toward the honest server, a
/// General listener registered on it. Returns the client, its inbound callback
/// slot, the listener's fire counter and the client's own session nonce (the
/// `your_nonce` a message on this session carries).
async fn client_with_authenticated_session(
    client_sk: PrivateKey,
    server_sk: PrivateKey,
) -> (
    Peer<ProtoWallet, Loopback>,
    CbSlot,
    Arc<AtomicUsize>,
    String,
) {
    let server_hex = server_sk.public_key().to_hex();
    let (a, a_cb) = start_client_and_server(client_sk, server_sk);
    let fired = count_general(&a).await;
    let session = a
        .get_authenticated_session(Some(&server_hex), Some(3000))
        .await
        .expect("an honest handshake must succeed");
    let session_nonce = session.session_nonce.expect("the session has a nonce");
    (a, a_cb, fired, session_nonce)
}

/// Property 1: a General whose claimed identity is not the authenticated
/// session's peer never reaches the listener, even when it is validly signed by
/// the key it claims. Only the general identity check refuses it; dropping that
/// check lets the attacker's validly signed message through.
#[tokio::test]
async fn a_general_message_whose_identity_is_not_the_authenticated_session_peer_never_reaches_the_listener(
) {
    let (a, a_cb, fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let client_pub = scalar(41).public_key();
    let attacker = scalar(43); // not the session's peer (scalar 42)

    // A General on the client's own live session (its your_nonce), carrying the
    // attacker's identity and a signature the attacker really made: the
    // signature verifies, so only the identity check stands between it and the
    // listener.
    let message_nonce = to_base64(&[9u8; 32]);
    let payload = vec![1u8, 2, 3];
    let sig = sign_general(
        &attacker,
        &message_nonce,
        &session_nonce,
        &payload,
        client_pub,
    );
    let mut msg = AuthMessage::new(MessageType::General, attacker.public_key());
    msg.your_nonce = Some(session_nonce);
    msg.nonce = Some(message_nonce);
    msg.payload = Some(payload);
    msg.signature = Some(sig);

    let fut = { a_cb.lock().unwrap().as_ref().map(|cb| cb(msg)) };
    let verdict = fut.expect("the client is started").await;
    assert!(
        verdict.is_err(),
        "a General whose identity is not the session's peer must be refused"
    );
    assert_eq!(
        fired.load(SeqCst),
        0,
        "a General whose identity is not the session's peer must not reach the listener"
    );
    drop(a);
}

/// Property 2: a handshake asked toward one identity is refused when the honest
/// response proves another, and no authenticated session is stored. The
/// response's signature verifies (the server answers honestly); only the
/// pinned-identity check refuses it. Dropping either half of the pinning (the
/// pin at request, or the compare at response) lets the handshake complete
/// under whichever key answered.
#[tokio::test]
async fn a_handshake_requested_toward_one_identity_is_refused_when_the_initial_response_proves_another(
) {
    // The server honestly proves scalar 42; the client asks for scalar 43.
    let (a, _a_cb) = start_client_and_server(scalar(41), scalar(42));
    let wrong_hex = scalar(43).public_key().to_hex();

    let refused = a
        .get_authenticated_session(Some(&wrong_hex), Some(2000))
        .await;
    assert_eq!(
        refused.unwrap_err(),
        Error::AuthError(
            "initialResponse identity does not match the requested peer identity.".into()
        ),
        "a handshake must refuse a response that proves an identity other than the one asked for"
    );
    let mgr = a.session_manager().read().await;
    assert_eq!(
        mgr.iter().filter(|s| s.is_authenticated).count(),
        0,
        "no authenticated session may be stored after a refused handshake"
    );
    assert!(
        mgr.is_empty(),
        "the refused handshake's session must be removed, toward either key"
    );
    drop(mgr);
    drop(a);
}

/// The general signature check on a live session: a General that names the
/// session's real peer but is not signed by it is refused. Dropping the
/// signature check lets an unsigned/forged message through on an established
/// session (the forged-* tests above never reach this check, being refused at
/// the session-lookup stage first).
#[tokio::test]
async fn a_general_message_not_signed_by_the_session_peer_is_refused_on_a_live_session() {
    let (a, a_cb, fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let server_pub = scalar(42).public_key(); // the session's real peer

    let mut msg = AuthMessage::new(MessageType::General, server_pub);
    msg.your_nonce = Some(session_nonce);
    msg.nonce = Some(to_base64(&[8u8; 32]));
    msg.payload = Some(vec![4u8, 5, 6]);
    msg.signature = Some(garbage_sig()); // DER-shaped, not the peer's signature

    let fut = { a_cb.lock().unwrap().as_ref().map(|cb| cb(msg)) };
    let verdict = fut.expect("the client is started").await;
    assert!(
        verdict.is_err(),
        "a General not signed by the session's peer must be refused"
    );
    assert_eq!(
        fired.load(SeqCst),
        0,
        "a General not signed by the session's peer must not reach the listener"
    );
    drop(a);
}

// ---------------------------------------------------------------------------
// Isolating regression tests for the remaining receive-path refusal checks the
// #353 port adds (CLAUDE.md rule 2: a check no test guards is not guaranteed).
// Each reaches ONE check directly — on a real or a crafted session — and asserts
// the refusal it alone produces; with that one check removed the assertion
// fails, with any other check removed it still holds. The reference's
// session-nonce-present check is omitted from this crate: a stored session
// always carries its own nonce (`SessionManager::add_session` requires it), so
// that check's refusal branch can never fire — it is unreachable, not pinned.
// ---------------------------------------------------------------------------

/// A signature `signer` makes over `msg` using the message's own signing data
/// and key id, bound to `receiver` as counterparty — the way `sign_message` and
/// `verify_message_signature` compute it. `recv_session_nonce` is the receiver's
/// own session nonce (used for a General's key id; ignored for an
/// InitialResponse, whose key id is taken from the message's own nonces).
fn sign_msg(
    signer: &PrivateKey,
    msg: &AuthMessage,
    receiver: PublicKey,
    recv_session_nonce: Option<&str>,
) -> Vec<u8> {
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(msg.signing_data()),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: msg.get_key_id(recv_session_nonce),
            counterparty: Some(Counterparty::Other(receiver)),
        })
        .unwrap()
        .signature
}

/// Hand `msg` to the client's own inbound callback (what a transport, or a man
/// in the middle, hands it) and return the Peer's verdict.
async fn deliver(a_cb: &CbSlot, msg: AuthMessage) -> Result<()> {
    let fut = { a_cb.lock().unwrap().as_ref().map(|cb| cb(msg)) };
    fut.expect("the client is started").await
}

async fn authenticated_count<T: Transport + 'static>(peer: &Peer<ProtoWallet, T>) -> usize {
    peer.session_manager()
        .read()
        .await
        .iter()
        .filter(|s| s.is_authenticated)
        .count()
}

/// The general own-nonce check: a General on a session whose nonce this wallet
/// never issued is refused. The general's identity matches the session's peer
/// and its signature is valid, so only `verify_own_nonce(your_nonce)` stands
/// before the listener. Dropping it lets the message through.
#[tokio::test]
async fn a_general_message_on_a_session_whose_nonce_this_wallet_never_issued_is_refused() {
    let (a, a_cb) = start_client_and_server(scalar(41), scalar(42));
    let fired = count_general(&a).await;
    let client_pub = scalar(41).public_key();
    let peer = scalar(44);
    let forged_nonce = "a-nonce-this-wallet-never-issued".to_string();
    {
        let mut s = PeerSession::with_nonce(forged_nonce.clone());
        s.peer_identity_key = Some(peer.public_key());
        s.is_authenticated = true;
        a.session_manager().write().await.add_session(s).unwrap();
    }
    let message_nonce = to_base64(&[7u8; 32]);
    let payload = vec![1u8, 2, 3];
    let mut msg = AuthMessage::new(MessageType::General, peer.public_key());
    msg.your_nonce = Some(forged_nonce.clone());
    msg.nonce = Some(message_nonce);
    msg.payload = Some(payload);
    msg.signature = Some(sign_msg(&peer, &msg, client_pub, Some(&forged_nonce)));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "a General on a session whose nonce this wallet never issued must be refused"
    );
    assert_eq!(fired.load(SeqCst), 0, "it must not reach the listener");
    drop(a);
}

/// The general identity-established check: a General on a session with no
/// established peer identity is refused, even validly signed by the key it
/// claims. Only the `None` arm of the identity match stands; dropping it lets an
/// unknown key deliver on a session whose peer was never set.
#[tokio::test]
async fn a_general_message_on_a_session_with_no_established_peer_identity_is_refused() {
    let (a, a_cb, fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let client_pub = scalar(41).public_key();
    {
        let mut mgr = a.session_manager().write().await;
        let s = mgr
            .get_session_mut(&session_nonce)
            .expect("the authenticated session exists");
        s.peer_identity_key = None;
    }
    let attacker = scalar(45);
    let message_nonce = to_base64(&[6u8; 32]);
    let mut msg = AuthMessage::new(MessageType::General, attacker.public_key());
    msg.your_nonce = Some(session_nonce.clone());
    msg.nonce = Some(message_nonce);
    msg.payload = Some(vec![9u8]);
    msg.signature = Some(sign_msg(&attacker, &msg, client_pub, Some(&session_nonce)));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "a General on a session with no established peer identity must be refused"
    );
    assert_eq!(fired.load(SeqCst), 0, "it must not reach the listener");
    drop(a);
}

/// The general message-nonce-present check: a General validly signed by the
/// session's peer but carrying no message nonce is refused. Only the nonce
/// presence check stands (the signature is valid); dropping it lets a
/// nonce-less message reach the listener.
#[tokio::test]
async fn a_validly_signed_general_with_no_message_nonce_is_refused() {
    let (a, a_cb, fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let client_pub = scalar(41).public_key();
    let peer = scalar(42); // the session's real peer
    let mut msg = AuthMessage::new(MessageType::General, peer.public_key());
    msg.your_nonce = Some(session_nonce.clone());
    msg.nonce = None;
    msg.payload = Some(vec![3u8, 1, 4]);
    msg.signature = Some(sign_msg(&peer, &msg, client_pub, Some(&session_nonce)));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "a validly signed General with no message nonce must be refused"
    );
    assert_eq!(fired.load(SeqCst), 0, "it must not reach the listener");
    drop(a);
}

/// The handshake own-nonce check: an InitialResponse whose echoed nonce this
/// wallet never issued is refused. A session pinned to the responder is keyed by
/// that nonce, so the session-exists and identity checks would pass; only
/// `verify_own_nonce(your_nonce)` stands. Dropping it completes a handshake on a
/// nonce the wallet never sent.
#[tokio::test]
async fn an_initial_response_whose_echoed_nonce_this_wallet_never_issued_is_refused() {
    let (a, a_cb) = start_client_and_server(scalar(41), scalar(42));
    let client_pub = scalar(41).public_key();
    let responder = scalar(42);
    let forged_nonce = "an-echoed-nonce-this-wallet-never-issued".to_string();
    {
        let mut s = PeerSession::with_nonce(forged_nonce.clone());
        s.peer_identity_key = Some(responder.public_key());
        a.session_manager().write().await.add_session(s).unwrap();
    }
    let responder_nonce = to_base64(&[5u8; 32]);
    let mut msg = AuthMessage::new(MessageType::InitialResponse, responder.public_key());
    msg.your_nonce = Some(forged_nonce);
    msg.nonce = Some(responder_nonce.clone());
    msg.initial_nonce = Some(responder_nonce);
    msg.signature = Some(sign_msg(&responder, &msg, client_pub, None));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "an InitialResponse on a nonce this wallet never issued must be refused"
    );
    assert_eq!(
        authenticated_count(&a).await,
        0,
        "no session may be authenticated by it"
    );
    drop(a);
}

/// The handshake session-exists check: an InitialResponse whose echoed nonce is
/// a real one this wallet issued but whose session has gone is refused. The
/// own-nonce check passes and the signature is valid; only the session lookup
/// stands. Dropping it lets a response with no pending handshake be processed.
#[tokio::test]
async fn an_initial_response_whose_echoed_nonce_names_no_session_is_refused() {
    let (a, a_cb, _fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let client_pub = scalar(41).public_key();
    let responder = scalar(42);
    a.session_manager()
        .write()
        .await
        .remove_by_nonce(&session_nonce);
    let responder_nonce = to_base64(&[4u8; 32]);
    let mut msg = AuthMessage::new(MessageType::InitialResponse, responder.public_key());
    msg.your_nonce = Some(session_nonce);
    msg.nonce = Some(responder_nonce.clone());
    msg.initial_nonce = Some(responder_nonce);
    msg.signature = Some(sign_msg(&responder, &msg, client_pub, None));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "an InitialResponse whose echoed nonce names no session must be refused"
    );
    assert_eq!(authenticated_count(&a).await, 0);
    drop(a);
}

/// The handshake responder-nonce-present check: an InitialResponse validly
/// signed by the pinned responder but carrying no responder nonce is refused.
/// The own-nonce, session, identity and signature checks all pass; only the
/// responder-nonce presence check stands. Dropping it completes a handshake with
/// an empty peer nonce.
#[tokio::test]
async fn an_initial_response_with_no_responder_nonce_is_refused() {
    let (a, a_cb, _fired, session_nonce) =
        client_with_authenticated_session(scalar(41), scalar(42)).await;
    let client_pub = scalar(41).public_key();
    let responder = scalar(42); // the session's pinned peer
    let mut msg = AuthMessage::new(MessageType::InitialResponse, responder.public_key());
    msg.your_nonce = Some(session_nonce);
    msg.nonce = None;
    msg.initial_nonce = None;
    msg.signature = Some(sign_msg(&responder, &msg, client_pub, None));

    let verdict = deliver(&a_cb, msg).await;
    assert!(
        verdict.is_err(),
        "an InitialResponse with no responder nonce must be refused"
    );
    drop(a);
}
