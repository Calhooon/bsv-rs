//! The app-event listener hands back this crate's receiver (#843d23, #843's
//! freeze plan, row 3): `install_app_event_listener` returned a
//! `futures::channel::mpsc::UnboundedReceiver<AppEvent>` until #843d23, so a
//! `futures` major was this crate's break; it returns `AppEventReceiver`,
//! read with `recv` and `try_recv`. No reference line: neither SDK has this
//! queue, and no wire byte moves.
//!
//! Two `Peer`s on `start`, each transport's sends handed to the other's
//! start callback by a routing task (the pattern of
//! `tests/auth_peer_client_verifies_353.rs`); the payload is
//! `build_envelope_payload`'s; no network, no port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "socketio")]

use async_trait::async_trait;
use bsv_rs::auth::transports::socketio::build_envelope_payload;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::{
    install_app_event_listener, AppEvent, AppEventReceiver, AuthMessage, Peer, PeerOptions,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::{Error, Result};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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

struct End {
    peer: Arc<Peer<ProtoWallet, Wire>>,
    callback: Callback,
    sent: Option<mpsc::UnboundedReceiver<AuthMessage>>,
}

fn key(n: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn end(scalar: u8) -> End {
    let (out, sent) = mpsc::unbounded_channel();
    let callback: Callback = Arc::new(Mutex::new(None));
    let peer = Arc::new(Peer::new(
        PeerOptions::new(
            ProtoWallet::new(Some(key(scalar))),
            Wire {
                out,
                callback: callback.clone(),
            },
        )
        .with_auto_persist_last_session(false)
        .with_originator(Some("test".into())),
    ));
    peer.start();
    End {
        peer,
        callback,
        sent: Some(sent),
    }
}

/// Carries each message `from` sends to `to`'s start callback
fn route(from: &mut End, to: &End) -> JoinHandle<()> {
    let mut sent = from.sent.take().unwrap();
    let callback = to.callback.clone();
    tokio::spawn(async move {
        while let Some(message) = sent.recv().await {
            let verdict = {
                let callback = callback.lock().unwrap();
                callback.as_ref().map(|callback| callback(message))
            };
            if let Some(verdict) = verdict {
                let _ = verdict.await;
            }
        }
    })
}

fn assert_send<T: Send>() {}

#[tokio::test]
async fn the_app_event_listener_hands_back_this_crates_receiver_843d23() {
    assert_send::<AppEventReceiver>();

    let mut alice = end(7);
    let mut bob = end(9);
    let to_bob = route(&mut alice, &bob);
    let to_alice = route(&mut bob, &alice);

    // The return type is this crate's: the binding names it, so the test
    // does not compile against a signature returning another crate's type.
    let (mut events, _id): (AppEventReceiver, u32) = install_app_event_listener(&bob.peer).await;
    assert_eq!(events.try_recv(), None, "nothing queued before a message");
    let printed = format!("{events:?}");
    assert!(printed.starts_with("AppEventReceiver"), "{printed}");

    let data = json!({ "amount": 42, "memo": "hello" });
    let payload = build_envelope_payload("payment", &data);
    let bob_hex = key(9).public_key().to_hex();
    alice
        .peer
        .to_peer(&payload, Some(&bob_hex), Some(5000))
        .await
        .unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("an event within five seconds")
        .expect("the listener is alive");
    assert_eq!(
        event,
        AppEvent {
            sender: key(7).public_key(),
            event_name: "payment".into(),
            data: data.clone(),
        }
    );
    assert_eq!(events.try_recv(), None, "one message, one event");

    // A second message queued, read without waiting once it has arrived
    alice
        .peer
        .to_peer(
            &build_envelope_payload("second", &json!(null)),
            Some(&bob_hex),
            Some(5000),
        )
        .await
        .unwrap();
    let mut second = None;
    for _ in 0..500 {
        second = events.try_recv();
        if second.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(second.map(|e| e.event_name), Some("second".to_string()));

    // The peer gone (its routing tasks, its callback slot, the Arc): the
    // listener's sender is dropped with its state and `recv` answers `None`.
    to_bob.abort();
    to_alice.abort();
    let _ = to_bob.await;
    let _ = to_alice.await;
    *bob.callback.lock().unwrap() = None;
    *alice.callback.lock().unwrap() = None;
    drop(bob);
    let closed = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("recv answers once the peer is gone");
    assert_eq!(closed, None);
    assert_eq!(events.try_recv(), None);
}

#[tokio::test]
async fn a_removed_listener_ends_the_receiver_after_its_queue_843d23() {
    let bob = end(9);
    let (mut events, id) = install_app_event_listener(&bob.peer).await;
    bob.peer.stop_listening_for_general_messages(id).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("recv answers once the listener is removed");
    assert_eq!(closed, None);
}
