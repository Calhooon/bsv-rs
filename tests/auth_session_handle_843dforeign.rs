//! `Peer::session_manager` hands out this crate's handle (#843dforeign, the
//! captain's ruling of 2026-11-12 on #843's foreign types): the door returned
//! `&Arc<tokio::sync::RwLock<SessionManager>>` until then, so a `tokio` major
//! was this crate's break; it returns `&SessionManagerHandle`, whose
//! `read().await` and `write().await` answer this crate's guards over the
//! `SessionManager`, and whose clone shares the store. The reference's `Peer`
//! exposes the store itself as a public property (`ts-stack@edf6e03`
//! `auth/Peer.ts:55`, `:163`; its doors `addSession`, `updateSession`,
//! `getSession`, `removeSession`, `hasSession`, `auth/SessionManager.ts:130,
//! 174,195,250,264`), go-sdk an unexported field (`auth/peer.go:54` at
//! `2ca481c`): neither hands out a lock. No wire byte moves.
//!
//! A `Peer` over `MockTransport`, never started: no task, no network, no port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::{
    MockTransport, Peer, PeerOptions, PeerSession, SessionManager, SessionManagerHandle,
    SessionManagerReadGuard, SessionManagerWriteGuard,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;

const NONCE: &str = "bm9uY2UtODQzZGZvcmVpZ24tc2Vzc2lvbi1ub25jZQ==";

fn key(n: u8) -> PrivateKey {
    let mut scalar = [0u8; 32];
    scalar[31] = n;
    PrivateKey::from_bytes(&scalar).unwrap()
}

fn peer() -> Peer<ProtoWallet, MockTransport> {
    Peer::new(PeerOptions::new(
        ProtoWallet::new(Some(key(7))),
        MockTransport::new(),
    ))
}

fn session(nonce: &str, peer_key: u8) -> PeerSession {
    let mut session = PeerSession::with_nonce(nonce.to_string());
    session.peer_identity_key = Some(key(peer_key).public_key());
    session.peer_nonce = Some(format!("peer-{nonce}"));
    session
}

#[tokio::test]
async fn the_door_hands_out_this_crates_handle_843dforeign() {
    let peer = peer();
    // The binding the door's type must satisfy: this crate's handle, by name
    let handle: &SessionManagerHandle = peer.session_manager();
    let read: SessionManagerReadGuard<'_> = handle.read().await;
    // The guard dereferences to the store: its doors by name
    let store: &SessionManager = &read;
    assert!(store.is_empty());
    assert!(!read.has_session(NONCE));
    drop(read);
    let mut write: SessionManagerWriteGuard<'_> = handle.write().await;
    let store: &mut SessionManager = &mut write;
    store.add_session(session(NONCE, 9)).unwrap();
    assert_eq!(write.len(), 1);
}

#[tokio::test]
async fn a_session_added_through_write_is_read_through_read_and_a_clone_843dforeign() {
    let peer = peer();
    let subject = key(9).public_key().to_hex();
    peer.session_manager()
        .write()
        .await
        .add_session(session(NONCE, 9))
        .unwrap();

    // Read back through the door, by nonce and by identity key
    {
        let manager = peer.session_manager().read().await;
        assert!(manager.has_session(NONCE));
        let held = manager
            .get_session(&subject)
            .expect("found by identity key");
        assert_eq!(held.session_nonce.as_deref(), Some(NONCE));
    }

    // A clone moved into a spawned task shares the store: it reads the
    // session, updates it and adds another; the door sees all of it
    let manager = peer.session_manager().clone();
    let task_subject = subject.clone();
    tokio::spawn(async move {
        assert!(manager.read().await.has_session(&task_subject));
        let mut store = manager.write().await;
        let mut updated = session(NONCE, 9);
        updated.is_authenticated = true;
        store.update_session(updated);
        store
            .add_session(session("c2Vjb25kLXNlc3Npb24=", 11))
            .unwrap();
    })
    .await
    .unwrap();
    {
        let manager = peer.session_manager().read().await;
        assert_eq!(manager.len(), 2);
        assert!(manager.get_session(NONCE).unwrap().is_authenticated);
        assert!(manager.has_session("c2Vjb25kLXNlc3Npb24="));
    }

    // Two readers at once, then a writer once they are gone; a removal
    // through the door is seen by a clone made before it
    let before = peer.session_manager().clone();
    let (first, second) = (peer.session_manager().read().await, before.read().await);
    assert_eq!((first.len(), second.len()), (2, 2));
    drop((first, second));
    let gone = session(NONCE, 9);
    peer.session_manager().write().await.remove_session(&gone);
    assert!(!before.read().await.has_session(NONCE));
    assert_eq!(before.read().await.len(), 1);
}

fn is_send<T: Send>(_: &T) {}
fn is_send_and_sync<T: Send + Sync>(_: &T) {}
fn is_clone<T: Clone>(_: &T) {}

#[tokio::test]
async fn the_handle_is_send_and_sync_and_its_guards_and_futures_are_send_843dforeign() {
    let peer = peer();
    let handle = peer.session_manager().clone();
    is_send_and_sync(&handle);
    is_clone(&handle);
    {
        let reading = handle.read();
        is_send(&reading);
        let guard = reading.await;
        is_send_and_sync(&guard);
    }
    {
        let writing = handle.write();
        is_send(&writing);
        let guard = writing.await;
        is_send_and_sync(&guard);
    }
    // A future that holds a guard across an await is `Send`: it is spawned
    let held = handle.clone();
    tokio::spawn(async move {
        let mut guard = held.write().await;
        tokio::task::yield_now().await;
        guard.add_session(session(NONCE, 9)).unwrap();
    })
    .await
    .unwrap();
    assert_eq!(handle.read().await.len(), 1);
}

#[tokio::test]
async fn no_debug_of_the_handle_or_its_guards_prints_a_nonce_or_an_identity_key_843dforeign() {
    let peer = peer();
    let subject = key(9).public_key().to_hex();
    peer.session_manager()
        .write()
        .await
        .add_session(session(NONCE, 9))
        .unwrap();
    let handle = peer.session_manager();

    let mut printed = vec![format!("{handle:?}"), format!("{handle:#?}")];
    {
        let guard = handle.read().await;
        printed.push(format!("{guard:?}"));
        printed.push(format!("{guard:#?}"));
    }
    {
        let guard = handle.write().await;
        printed.push(format!("{guard:?}"));
        printed.push(format!("{guard:#?}"));
    }
    assert_eq!(printed[0], "SessionManagerHandle { .. }");
    assert_eq!(printed[2], "SessionManagerReadGuard { .. }");
    assert_eq!(printed[4], "SessionManagerWriteGuard { .. }");
    for text in &printed {
        for secret in [NONCE, subject.as_str(), &subject[2..18], "peer-"] {
            assert!(!text.contains(secret), "`{text}` prints `{secret}`");
        }
    }
}
