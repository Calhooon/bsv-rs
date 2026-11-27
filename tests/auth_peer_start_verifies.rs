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
use bsv_rs::auth::types::{AuthMessage, MessageType};
use bsv_rs::auth::{Peer, PeerOptions};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Result;
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
async fn count_general(peer: &Peer<ProtoWallet, ProbeTransport>) -> Arc<AtomicUsize> {
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
