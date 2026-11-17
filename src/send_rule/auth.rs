//! The `auth` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::auth::certificates::{MasterCertificate, VerifiableCertificate};
use crate::auth::clients::AuthFetch;
use crate::auth::session_handle::SessionManagerHandle;
use crate::auth::transports::{MockTransport, Transport};
use crate::auth::utils::{
    create_nonce, get_verifiable_certificates, validate_certificate, validate_certificates,
    verify_nonce,
};
use crate::auth::Peer;
use crate::primitives::{PrivateKey, PublicKey};
use crate::wallet::WalletInterface;
use crate::Result;
use core::future::Future;
use core::pin::Pin;
use indexmap::IndexMap;

/// The future a `Peer` listener returns, as the three `listen_for_*` doors
/// spell it.
type Listened = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

// src/auth/transports/http.rs
fn transport<V: Values, T: Transport + ?Sized>(v: &V) {
    let transport = v.any::<&T>();
    send(transport.send(v.any()));
}

// src/auth/transports/http.rs
fn mock_transport<V: Values>(v: &V) {
    let mock = v.any::<&MockTransport>();
    send(mock.queue_response(v.any()));
    send(mock.get_sent_messages());
    send(mock.clear_sent());
    send(mock.receive_message(v.any()));
}

// src/auth/peer.rs
fn peer<V: Values, W: WalletInterface + 'static, T: Transport + 'static>(v: &V) {
    let peer = v.any::<&Peer<W, T>>();
    send(peer.to_peer(v.any(), v.any(), v.any()));
    send(peer.get_authenticated_session(v.any(), v.any()));
    send(peer.request_certificates(v.any(), v.any(), v.any()));
    send(peer.send_certificate_response(v.any(), v.any()));
    send(peer.stop_listening_for_general_messages(v.any()));
    send(peer.stop_listening_for_certificates_received(v.any()));
    send(peer.stop_listening_for_certificates_requested(v.any()));
    send(peer.get_identity_key());
    send(peer.handle_incoming_message(v.any()));
}

// src/auth/peer.rs
fn peer_listeners<V: Values, W: WalletInterface + 'static, T: Transport + 'static>(v: &V) {
    let listening = v.any::<&Peer<W, T>>();
    let general = v.any::<fn(PublicKey, Vec<u8>) -> Listened>();
    send(listening.listen_for_general_messages(general));
    let received = v.any::<fn(PublicKey, Vec<VerifiableCertificate>) -> Listened>();
    send(listening.listen_for_certificates_received(received));
    let requested = v.any::<fn(PublicKey, crate::auth::RequestedCertificateSet) -> Listened>();
    send(listening.listen_for_certificates_requested(requested));
}

// src/auth/session_handle.rs
fn session_handle<V: Values>(v: &V) {
    let sessions = v.any::<&SessionManagerHandle>();
    send(sessions.read());
    send(sessions.write());
}

// src/auth/clients/auth_fetch.rs
fn auth_fetch<V: Values, W: WalletInterface + 'static, T: Transport + 'static>(v: &V) {
    let fetching = v.any::<&AuthFetch<W, T>>();
    send(fetching.fetch(v.any(), v.any()));
}

// src/auth/clients/state.rs
fn auth_fetch_certificates<V: Values, W: WalletInterface + 'static, T: Transport + 'static>(v: &V) {
    let requesting = v.any::<&AuthFetch<W, T>>();
    send(requesting.send_certificate_request(v.any(), v.any()));
}

// src/auth/certificates/master.rs
fn master_certificate<V: Values, W: WalletInterface>(v: &V) {
    let wallet = v.any::<&W>();
    send(MasterCertificate::create_certificate_fields(
        wallet,
        v.any::<&PublicKey>(),
        v.any::<IndexMap<String, String>>(),
        v.any::<Option<bool>>(),
        v.any(),
        v.any(),
    ));
    send(MasterCertificate::create_keyring_for_verifier(
        wallet,
        v.any::<&PublicKey>(),
        v.any::<&PublicKey>(),
        v.any::<&IndexMap<String, String>>(),
        v.any::<&[String]>(),
        v.any::<&IndexMap<String, String>>(),
        v.any::<&[u8; 32]>(),
        v.any::<Option<bool>>(),
        v.any(),
        v.any(),
    ));
    send(MasterCertificate::issue_for_subject(
        wallet,
        v.any::<&PrivateKey>(),
        v.any::<PublicKey>(),
        v.any::<IndexMap<String, String>>(),
        v.any::<[u8; 32]>(),
        v.any(),
        v.any(),
    ));
    let master = v.any::<&MasterCertificate>();
    send(master.decrypt_field(wallet, v.any(), v.any(), v.any(), v.any(), v.any()));
    send(master.decrypt_fields(wallet, v.any(), v.any(), v.any(), v.any()));
}

// src/auth/certificates/verifiable.rs
fn verifiable_certificate<V: Values, W: WalletInterface>(v: &V) {
    let wallet = v.any::<&W>();
    let held = v.any::<&VerifiableCertificate>();
    send(held.decrypt_field(wallet, v.any(), v.any(), v.any(), v.any()));
    let decrypting = v.any::<&mut VerifiableCertificate>();
    send(decrypting.decrypt_fields(wallet, v.any(), v.any(), v.any()));
}

// src/auth/utils/nonce.rs
fn nonce<V: Values, W: WalletInterface>(v: &V) {
    let wallet = v.any::<&W>();
    send(create_nonce(wallet, v.any(), v.any()));
    send(verify_nonce(v.any(), wallet, v.any(), v.any()));
}

// src/auth/utils/validation.rs
fn validation<V: Values, W: WalletInterface>(v: &V) {
    let wallet = v.any::<&W>();
    send(validate_certificates(wallet, v.any(), v.any(), v.any()));
    send(validate_certificate(
        wallet,
        v.any(),
        v.any(),
        v.any(),
        v.any(),
    ));
}

// src/auth/utils/verifiable.rs
fn verifiable<V: Values, W: WalletInterface>(v: &V) {
    let wallet = v.any::<&W>();
    send(get_verifiable_certificates(
        wallet,
        v.any(),
        v.any(),
        v.any(),
    ));
}

/// The Socket.IO transport's doors.
#[cfg(feature = "socketio")]
mod socketio {
    use super::super::{send, Values};
    use crate::auth::transports::socketio::{
        install_app_event_listener, run_dispatch, AppEventReceiver, SocketIoFrameSource,
        SocketIoSink,
    };
    use crate::auth::transports::Transport;
    use crate::auth::Peer;
    use crate::wallet::WalletInterface;

    // src/auth/transports/socketio/mod.rs
    fn frame_source<V: Values, F: SocketIoFrameSource + ?Sized>(v: &V) {
        let frames = v.any::<&mut F>();
        send(frames.recv_engineio());
    }

    // src/auth/transports/socketio/mod.rs
    fn dispatch<V: Values, F: SocketIoFrameSource, S: SocketIoSink>(v: &V) {
        send(run_dispatch(v.any::<F>(), v.any::<S>(), v.any()));
    }

    // src/auth/transports/socketio/mod.rs
    fn app_events<V: Values, W: WalletInterface + 'static, T: Transport + 'static>(v: &V) {
        let listened = v.any::<&Peer<W, T>>();
        send(install_app_event_listener(listened));
    }

    // src/auth/transports/socketio/app_event.rs
    fn app_event_receiver<V: Values>(v: &V) {
        let events = v.any::<&mut AppEventReceiver>();
        send(events.recv());
    }
}
