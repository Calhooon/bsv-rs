//! Socket.IO + BRC-103 transport for [`Peer`](crate::auth::Peer).
//!
//! [`SocketIoTransport`] implements [`Transport`] by driving the
//! BRC-103 `authMessage` event channel over a Socket.IO 5 / Engine.IO 4
//! connection. It is **substrate-agnostic**: rather than hard-coding a
//! particular WebSocket stack, it is generic over a minimal outbound
//! [`SocketIoSink`] (one method, `send_socketio`). Consumers plug in
//! whatever they like — `tokio-tungstenite` and `reqwest` on native,
//! `web_sys::WebSocket` and `worker::Fetch` on `wasm32`, the bsv-rs
//! [`WebSocketTransport`](crate::auth::WebSocketTransport) machinery, or
//! a test double. bsv-rs itself pulls in **no** new dependency for this
//! module, so enabling it can never break a `wasm32` build that uses
//! `auth` without it.
//!
//! The inbound side is symmetrical: [`run_dispatch`] is generic over a
//! [`SocketIoFrameSource`] (one async method, `recv_engineio`) so the
//! decode loop is decoupled from any concrete read half.
//!
//! # Wire shape (matches canonical TS `@bsv/authsocket-client`)
//!
//! **Outbound** — each [`AuthMessage`] is JSON-serialized and emitted as
//! a Socket.IO `EVENT` whose data array is `["authMessage", <json>]` on
//! the default namespace `/`. The canonical TS does
//! `socket.emit('authMessage', message)`; on the wire that is a single
//! Engine.IO `Message(4)` framing `42["authMessage",{<json>}]`. The byte
//! form is identical because `socket.io-client` serializes the JS object
//! via `JSON.stringify` exactly as `serde_json` serializes the Rust
//! [`AuthMessage`] (camelCase, per its `#[serde(rename_all = "camelCase")]`).
//!
//! **Inbound** — [`run_dispatch`] decodes Engine.IO `Message(4)` frames,
//! extracts the Socket.IO `EVENT` payload, matches `data[0] == "authMessage"`,
//! deserializes `data[1]` as an [`AuthMessage`], and invokes the
//! registered [`TransportCallback`]. Engine.IO `Ping` frames are
//! auto-replied with `Pong` through a caller-supplied [`SocketIoSink`]
//! clone so the relay's `pingTimeout` never fires mid-dispatch.
//!
//! # Application-event envelope
//!
//! Post-handshake [`MessageType::General`](crate::auth::MessageType::General)
//! payloads use the canonical `{eventName, data}` JSON envelope.
//! [`build_envelope_payload`] and [`parse_app_event_payload`] encode and
//! decode it byte-exactly against the TS canonical (`encodeEventPayload`);
//! [`AppEvent`] is the decoded form. See [`install_app_event_listener`] to
//! subscribe a [`Peer`](crate::auth::Peer) to a stream of decoded events.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::auth::transports::socketio::{SocketIoTransport, SocketIoSink, run_dispatch};
//! use bsv_rs::auth::transports::socketio::codec::SocketIoPacket;
//!
//! // 1. Implement the one-method sink over your WS substrate.
//! #[derive(Clone)]
//! struct MySink(/* your cloneable WS sender */);
//! impl SocketIoSink for MySink {
//!     fn send_socketio(&self, pkt: &SocketIoPacket) -> Result<(), String> {
//!         // self.0.send_text(&EngineIoPacket::Message(pkt.encode()).encode())
//!         Ok(())
//!     }
//! }
//!
//! // 2. Build the transport, hand it to a Peer.
//! let transport = SocketIoTransport::new(MySink(/* ... */));
//! let callback = transport.callback_handle();
//! let sink = transport.sink();
//! // peer = Peer::new(PeerOptions { transport: transport.clone(), .. });
//!
//! // 3. Spawn the inbound dispatch over your WS read half.
//! // tokio::spawn(run_dispatch(my_frame_source, sink, callback));
//! ```

pub mod codec;

use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::auth::transports::{Transport, TransportCallback};
use crate::auth::types::AuthMessage;
use crate::primitives::PublicKey;
use crate::Result;

use codec::{EngineIoPacket, SocketIoPacket};

/// Minimal outbound sink for the Socket.IO transport.
///
/// Implement this over whatever WebSocket substrate you use. The single
/// method serializes a [`SocketIoPacket`], wraps it in an Engine.IO
/// `Message(4)` frame, and writes it to the wire. A blanket helper is
/// not provided so implementors retain full control over framing and
/// back-pressure; most implementations are a one-liner:
///
/// ```rust,ignore
/// use bsv_rs::auth::transports::socketio::codec::EngineIoPacket;
/// fn send_socketio(&self, pkt: &SocketIoPacket) -> Result<(), String> {
///     self.ws.send_text(&EngineIoPacket::Message(pkt.encode()).encode())
/// }
/// ```
///
/// The error type is `String` (rather than [`crate::Error`]) so trivial
/// substrate adapters need no dependency on the SDK error enum; the
/// transport maps it into [`crate::Error::AuthError`] at the boundary.
///
/// Implementors must be `Send + Sync` so [`SocketIoTransport`] satisfies
/// the [`Transport`] bound and can be shared across the
/// [`Peer`](crate::auth::Peer) and the dispatch task.
pub trait SocketIoSink: Send + Sync {
    /// Encode `pkt` (wrapped in an Engine.IO `Message(4)`) and write it
    /// to the wire. Returns `Err` if the underlying transport is closed.
    fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String>;

    /// Encode and send a raw [`EngineIoPacket`]. Used by [`run_dispatch`]
    /// to reply to inbound `Ping` frames with `Pong`. The default
    /// implementation only supports wrapping Socket.IO packets via
    /// [`SocketIoSink::send_socketio`]; override to support bare
    /// Engine.IO control frames (most substrates expose a `send_text`).
    fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
        // Conservative default: only Message frames can be expressed via
        // `send_socketio`. Control frames (Ping/Pong) require an override.
        match pkt {
            EngineIoPacket::Message(payload) => {
                // Re-decode the inner Socket.IO packet and forward it.
                match SocketIoPacket::decode(payload) {
                    Ok(sio) => self.send_socketio(&sio),
                    Err(e) => Err(format!("send_engineio default: {e}")),
                }
            }
            other => Err(format!(
                "send_engineio default impl cannot send {other:?}; override SocketIoSink::send_engineio"
            )),
        }
    }
}

/// An inbound frame source for [`run_dispatch`].
///
/// Implement this over the read half of your WebSocket substrate. The
/// dispatch loop calls [`recv_engineio`](SocketIoFrameSource::recv_engineio)
/// repeatedly until it returns `Err` (connection closed).
#[async_trait]
pub trait SocketIoFrameSource: Send {
    /// Await and decode the next inbound Engine.IO frame. Returns `Err`
    /// when the underlying transport has closed; [`run_dispatch`] treats
    /// any `Err` as end-of-stream and exits cleanly.
    async fn recv_engineio(&mut self) -> std::result::Result<EngineIoPacket, String>;
}

/// [`Transport`] implementation over a Socket.IO `authMessage` event
/// channel, generic over an outbound [`SocketIoSink`].
///
/// Cheap to clone (a [`SocketIoSink`] handle plus an `Arc`); use one
/// clone per consumer — [`Peer`](crate::auth::Peer) consumes one, the
/// [`run_dispatch`] task another.
///
/// Construct via [`SocketIoTransport::new`]; register a callback via the
/// [`Transport::set_callback`] trait method (or indirectly by passing
/// this transport into [`Peer::new`](crate::auth::Peer::new) and calling
/// `Peer::start`). Use [`SocketIoTransport::callback_handle`] to obtain a
/// clone of the callback slot for the dispatch task.
#[derive(Clone)]
pub struct SocketIoTransport<S: SocketIoSink> {
    sink: S,
    callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
}

impl<S: SocketIoSink + std::fmt::Debug> std::fmt::Debug for SocketIoTransport<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketIoTransport")
            .field("sink", &self.sink)
            .finish_non_exhaustive()
    }
}

impl<S: SocketIoSink + Clone> SocketIoTransport<S> {
    /// Wrap a [`SocketIoSink`] as a BRC-103 `authMessage` transport. The
    /// callback slot starts empty; either call [`Transport::set_callback`]
    /// directly or call `Peer::start` after passing this into
    /// `Peer::new` to populate it.
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            callback: Arc::new(StdMutex::new(None)),
        }
    }

    /// Return a clone of the callback slot. The [`run_dispatch`] task
    /// holds one of these so it can find the registered callback for
    /// each inbound [`AuthMessage`]. Cloning the `Arc` does NOT clone the
    /// callback itself — the registered `Box<TransportCallback>` lives
    /// behind the shared `Mutex`.
    pub fn callback_handle(&self) -> Arc<StdMutex<Option<Box<TransportCallback>>>> {
        self.callback.clone()
    }

    /// A clone of the outbound sink. Useful for the dispatch loop, which
    /// needs to write `Pong` replies on inbound `Ping` frames.
    pub fn sink(&self) -> S {
        self.sink.clone()
    }
}

#[async_trait]
impl<S: SocketIoSink + Clone + 'static> Transport for SocketIoTransport<S> {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Serialize the AuthMessage as the second arg of an
        // `["authMessage", <msg>]` Socket.IO EVENT on the default
        // namespace. The byte form is identical to the canonical TS
        // `socket.emit('authMessage', message)` because socket.io-client
        // serializes via `JSON.stringify` exactly as `serde_json` does
        // the camelCase `AuthMessage`.
        let json = serde_json::to_value(message).map_err(|e| {
            crate::Error::AuthError(format!("SocketIoTransport::send: serialize: {e}"))
        })?;
        let pkt = SocketIoPacket::Event {
            nsp: "/".to_string(),
            ack_id: None,
            data: vec![Value::String("authMessage".to_string()), json],
        };
        self.sink
            .send_socketio(&pkt)
            .map_err(|e| crate::Error::AuthError(format!("SocketIoTransport::send: ws: {e}")))
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        // `StdMutex` is safe here — it serializes the dispatch task vs.
        // `Peer::start`. Poisoning is theoretical; if it happens we
        // silently drop the registration, matching
        // `SimplifiedFetchTransport`.
        if let Ok(mut cb) = self.callback.lock() {
            *cb = Some(callback);
        }
    }

    fn clear_callback(&self) {
        if let Ok(mut cb) = self.callback.lock() {
            *cb = None;
        }
    }
}

// ============================================================================
// Inbound dispatch loop
// ============================================================================

/// Background dispatch task body. Reads Engine.IO frames from a
/// [`SocketIoFrameSource`] in a loop and:
///
/// - Replies to inbound Engine.IO `Ping` with `Pong` via the provided
///   [`SocketIoSink`] so the relay heartbeat never fires.
/// - On Engine.IO `Message(4)` carrying a Socket.IO `EVENT` whose
///   `data[0]` is `"authMessage"`, deserializes `data[1]` as an
///   [`AuthMessage`] and invokes the registered [`TransportCallback`]
///   (typically the one `Peer::start` installs) so `Peer`'s session
///   manager stays consistent.
/// - Exits the loop on `recv_engineio` error (WS closed).
///
/// Drives one BRC-103 channel; spawn one of these per WebSocket. On
/// native this future is `Send` when the `frames`/`sink`/callback `Arc`
/// are `Send`, so it can run under `tokio::spawn`; on `wasm32` spawn it
/// with `wasm_bindgen_futures::spawn_local`.
pub async fn run_dispatch<F, S>(
    mut frames: F,
    sink: S,
    callback: Arc<StdMutex<Option<Box<TransportCallback>>>>,
) where
    F: SocketIoFrameSource,
    S: SocketIoSink,
{
    loop {
        let frame = match frames.recv_engineio().await {
            Ok(f) => f,
            Err(_) => break, // WS closed — exit dispatch.
        };
        match frame {
            EngineIoPacket::Ping(payload) => {
                let _ = sink.send_engineio(&EngineIoPacket::Pong(payload));
            }
            EngineIoPacket::Message(payload) => {
                let sio = match SocketIoPacket::decode(&payload) {
                    Ok(p) => p,
                    Err(_) => continue, // ignore malformed Socket.IO frames
                };
                if let SocketIoPacket::Event { data, .. } = sio {
                    if data.len() >= 2 && data[0].as_str() == Some("authMessage") {
                        let auth_msg: AuthMessage = match serde_json::from_value(data[1].clone()) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };

                        // Synchronously invoke the callback under the lock
                        // to produce the future; drop the lock before
                        // awaiting. Same pattern as
                        // `SimplifiedFetchTransport::invoke_callback`.
                        let fut_opt = {
                            match callback.lock() {
                                Ok(guard) => guard.as_ref().map(|cb| cb(auth_msg)),
                                Err(_) => None, // poisoned — drop the message
                            }
                        };
                        if let Some(fut) = fut_opt {
                            let _ = fut.await;
                        }
                    }
                }
            }
            _ => { /* Open/Close/Pong/Upgrade/Noop — ignore */ }
        }
    }
}

// ============================================================================
// Application-event envelope layer
// ============================================================================

/// One application-level event decoded from a post-BRC-103-handshake
/// [`MessageType::General`](crate::auth::MessageType::General) payload.
///
/// The payload shape is the canonical `{eventName, data}` JSON envelope
/// used by `@bsv/authsocket-client`'s `encodeEventPayload` — byte-identical
/// between the TS canonical and this Rust client.
#[derive(Debug, Clone, PartialEq)]
pub struct AppEvent {
    /// The signing identity from the inbound General's `identity_key`
    /// field — typically the server's identity key, but typed as
    /// [`PublicKey`] so the same shape generalizes to peer-to-peer events.
    pub sender: PublicKey,
    /// The `eventName` field from the payload JSON. Empty string when the
    /// payload was missing the field (still surfaced so callers can
    /// observe malformed traffic instead of silently dropping it).
    pub event_name: String,
    /// The `data` field from the payload JSON. Type varies by event;
    /// left as [`Value`] so callers parse the per-event shape themselves.
    pub data: Value,
}

/// Install an inbound listener that decodes every post-BRC-103 General
/// message payload as the canonical `{eventName, data}` envelope and
/// forwards it on an unbounded `mpsc` channel.
///
/// The returned `Receiver` is the caller's queue of inbound application
/// events; the `u32` is the `Peer::listen_for_general_messages` callback
/// id (pass it to `Peer::stop_listening_for_general_messages` on teardown
/// if needed).
///
/// Requires `Peer::start()` to have been called on the same
/// [`Peer`](crate::auth::Peer) so the start-callback routes inbound
/// Generals to the `general_message_callbacks` map this helper subscribes to.
pub async fn install_app_event_listener<W, T>(
    peer: &crate::auth::Peer<W, T>,
) -> (futures::channel::mpsc::UnboundedReceiver<AppEvent>, u32)
where
    W: crate::wallet::WalletInterface + 'static,
    T: Transport + 'static,
{
    let (tx, rx) = futures::channel::mpsc::unbounded::<AppEvent>();
    let id = peer
        .listen_for_general_messages(move |sender, payload| {
            let tx = tx.clone();
            Box::pin(async move {
                let (event_name, data) = parse_app_event_payload(&payload);
                let _ = tx.unbounded_send(AppEvent {
                    sender,
                    event_name,
                    data,
                });
                Ok(())
            })
        })
        .await;
    (rx, id)
}

/// Parse a `{eventName, data}` JSON envelope from a General message's
/// `payload` bytes. Returns `("", Value::Null)` on parse failure so
/// callers can observe malformed traffic without panicking.
pub fn parse_app_event_payload(payload: &[u8]) -> (String, Value) {
    match serde_json::from_slice::<Value>(payload) {
        Ok(json) => {
            let event_name = json
                .get("eventName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let data = json.get("data").cloned().unwrap_or(Value::Null);
            (event_name, data)
        }
        Err(_) => (String::new(), Value::Null),
    }
}

/// Build the canonical `{eventName, data}` envelope as UTF-8 JSON bytes.
///
/// Byte-identical to the TS canonical `encodeEventPayload`:
///
/// ```ts
/// private encodeEventPayload(eventName: string, data: any): number[] {
///     const obj = { eventName, data }
///     return Utils.toArray(JSON.stringify(obj), 'utf8')
/// }
/// ```
///
/// **Critical wire-compat detail**: JS `JSON.stringify` emits keys in
/// object-literal **insertion order** (`{"eventName":...,"data":...}`).
/// `serde_json::json!({...})` is `BTreeMap`-backed and would serialize
/// **alphabetically** (`{"data":...,"eventName":...}`) unless the
/// `preserve_order` feature is enabled. To match canonical TS without a
/// crate-wide feature flip, this uses a typed `Envelope` struct, which
/// serializes fields in **declaration order** (`eventName` first, `data`
/// second). Verified by the byte-exact vector tests in this module.
pub fn build_envelope_payload(event_name: &str, data: &Value) -> Vec<u8> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        #[serde(rename = "eventName")]
        event_name: &'a str,
        data: &'a Value,
    }
    let envelope = Envelope { event_name, data };
    serde_json::to_vec(&envelope).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::MessageType;
    use crate::primitives::PrivateKey;
    use serde_json::json;

    // ---------- authMessage EVENT framing (byte-exact) ----------

    /// A trivial sink that records the last encoded Engine.IO frame so a
    /// test can assert the exact wire bytes produced by `Transport::send`.
    #[derive(Clone, Default)]
    struct CapturingSink {
        last: Arc<StdMutex<Option<String>>>,
    }

    impl SocketIoSink for CapturingSink {
        fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
            let frame = EngineIoPacket::Message(pkt.encode()).encode();
            *self.last.lock().unwrap() = Some(frame);
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_emits_authmessage_event_on_default_namespace() {
        let sink = CapturingSink::default();
        let transport = SocketIoTransport::new(sink.clone());

        // A deterministic identity key so we can pin the wire bytes.
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap()
        .public_key();
        let msg = AuthMessage::new(MessageType::InitialRequest, key.clone());

        transport.send(&msg).await.unwrap();

        let frame = sink.last.lock().unwrap().clone().unwrap();
        // Engine.IO Message(4) + Socket.IO EVENT(2) on default ns.
        assert!(
            frame.starts_with("42[\"authMessage\","),
            "unexpected frame prefix: {frame}"
        );

        // Decode back through both layers and confirm the round-trip.
        let eio = EngineIoPacket::decode(&frame).unwrap();
        let payload = match eio {
            EngineIoPacket::Message(p) => p,
            other => panic!("expected Message, got {other:?}"),
        };
        let sio = SocketIoPacket::decode(&payload).unwrap();
        match sio {
            SocketIoPacket::Event { nsp, ack_id, data } => {
                assert_eq!(nsp, "/");
                assert_eq!(ack_id, None);
                assert_eq!(data[0], json!("authMessage"));
                let decoded: AuthMessage = serde_json::from_value(data[1].clone()).unwrap();
                assert_eq!(decoded.message_type, MessageType::InitialRequest);
                assert_eq!(decoded.identity_key.to_hex(), key.to_hex());
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_authmessage_event_array_head_is_authmessage_literal() {
        // Pin the exact event-name literal the canonical TS emits:
        // `socket.emit('authMessage', message)` → data[0] == "authMessage".
        let sink = CapturingSink::default();
        let transport = SocketIoTransport::new(sink.clone());
        let key = PrivateKey::random().public_key();
        let msg = AuthMessage::new(MessageType::General, key);
        transport.send(&msg).await.unwrap();

        let frame = sink.last.lock().unwrap().clone().unwrap();
        let payload = match EngineIoPacket::decode(&frame).unwrap() {
            EngineIoPacket::Message(p) => p,
            other => panic!("expected Message, got {other:?}"),
        };
        match SocketIoPacket::decode(&payload).unwrap() {
            SocketIoPacket::Event { data, .. } => {
                assert_eq!(data[0].as_str(), Some("authMessage"));
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    // ---------- {eventName, data} envelope (byte-exact vectors) ----------

    #[test]
    fn parse_app_event_decodes_joinroom_envelope() {
        let payload = br#"{"eventName":"joinRoom","data":"02abc...xyz-payment_inbox"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "joinRoom");
        assert_eq!(data, json!("02abc...xyz-payment_inbox"));
    }

    #[test]
    fn parse_app_event_decodes_sendmessage_envelope() {
        let payload = br#"{"eventName":"sendMessage","data":{"roomId":"02abc-test","message":{"messageId":"h34","body":"hello"}}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "sendMessage");
        assert_eq!(
            data,
            json!({"roomId":"02abc-test","message":{"messageId":"h34","body":"hello"}})
        );
    }

    #[test]
    fn parse_app_event_decodes_sendmessageack_with_room_suffix() {
        let payload = br#"{"eventName":"sendMessageAck-02abc-h34-test","data":{"status":"success","messageId":"h34"}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "sendMessageAck-02abc-h34-test");
        assert_eq!(data["status"], json!("success"));
        assert_eq!(data["messageId"], json!("h34"));
    }

    #[test]
    fn parse_app_event_handles_empty_data() {
        let payload = br#"{"eventName":"authenticated","data":{}}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "authenticated");
        assert_eq!(data, json!({}));
    }

    #[test]
    fn parse_app_event_returns_empty_on_malformed_json() {
        let payload = b"this is not json";
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_returns_empty_on_missing_fields() {
        let payload = br#"{"foo":"bar"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_handles_event_name_only() {
        let payload = br#"{"eventName":"someEvent"}"#;
        let (event_name, data) = parse_app_event_payload(payload);
        assert_eq!(event_name, "someEvent");
        assert_eq!(data, Value::Null);
    }

    #[test]
    fn parse_app_event_byte_exact_against_ts_emit_vector() {
        let canonical_ts_bytes: &[u8] = b"{\"eventName\":\"sendMessage\",\"data\":{\"roomId\":\"abc-test\",\"message\":{\"messageId\":\"v1\",\"body\":\"hi\"}}}";
        let (event_name, data) = parse_app_event_payload(canonical_ts_bytes);
        assert_eq!(event_name, "sendMessage");
        assert_eq!(data["roomId"], json!("abc-test"));
        assert_eq!(data["message"]["messageId"], json!("v1"));
        assert_eq!(data["message"]["body"], json!("hi"));
    }

    #[test]
    fn build_envelope_payload_joinroom_byte_exact() {
        let bytes = build_envelope_payload("joinRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"joinRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_sendmessage_byte_exact() {
        // The wrapper's contract: `{"eventName":"<name>","data":<data verbatim>}`
        // with the OUTER keys in `eventName`-then-`data` declaration order
        // (the canonical JS `JSON.stringify({ eventName, data })` order).
        // The nested `data` object is serialized by `serde_json` verbatim;
        // we compose the expected vector from that serialization so the
        // assertion is independent of whether `serde_json`'s
        // `preserve_order` feature is active in the dependency graph.
        let data = json!({"roomId": "abc-test", "message": {"messageId": "v1", "body": "hi"}});
        let bytes = build_envelope_payload("sendMessage", &data);

        let mut expected = b"{\"eventName\":\"sendMessage\",\"data\":".to_vec();
        expected.extend_from_slice(&serde_json::to_vec(&data).unwrap());
        expected.push(b'}');

        assert_eq!(bytes, expected);
        // And the outer `eventName` key MUST come first (declaration order).
        assert!(bytes.starts_with(b"{\"eventName\":\"sendMessage\",\"data\":"));
    }

    #[test]
    fn build_envelope_payload_leaveroom_byte_exact() {
        let bytes = build_envelope_payload("leaveRoom", &json!("02abc-test_inbox"));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"leaveRoom\",\"data\":\"02abc-test_inbox\"}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_empty_data_object() {
        let bytes = build_envelope_payload("authenticated", &json!({}));
        assert_eq!(
            bytes.as_slice(),
            b"{\"eventName\":\"authenticated\",\"data\":{}}".as_slice(),
        );
    }

    #[test]
    fn build_envelope_payload_round_trips_through_parser() {
        let cases: Vec<(&str, Value)> = vec![
            ("joinRoom", json!("02abc-room")),
            (
                "sendMessage",
                json!({"roomId": "02abc-room", "message": {"messageId": "m1", "body": "hi"}}),
            ),
            ("leaveRoom", json!("02abc-room")),
            ("authenticated", json!({})),
            ("sendMessageAck-02abc-room", json!({"status": "success"})),
        ];
        for (name, data) in cases {
            let bytes = build_envelope_payload(name, &data);
            let (decoded_name, decoded_data) = parse_app_event_payload(&bytes);
            assert_eq!(decoded_name, name, "event_name round-trip for {name}");
            assert_eq!(decoded_data, data, "data round-trip for {name}");
        }
    }

    // ---------- inbound dispatch ----------

    #[tokio::test]
    async fn dispatch_routes_authmessage_event_to_callback() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A frame source that yields one authMessage EVENT then closes.
        struct OneShotFrames {
            frame: Option<EngineIoPacket>,
        }
        #[async_trait]
        impl SocketIoFrameSource for OneShotFrames {
            async fn recv_engineio(&mut self) -> std::result::Result<EngineIoPacket, String> {
                self.frame.take().ok_or_else(|| "closed".to_string())
            }
        }

        // Build the inbound frame: an authMessage EVENT carrying a General.
        let key = PrivateKey::random().public_key();
        let msg = AuthMessage::new(MessageType::General, key);
        let json = serde_json::to_value(&msg).unwrap();
        let sio = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: None,
            data: vec![json!("authMessage"), json],
        };
        let frame = EngineIoPacket::Message(sio.encode());

        let count = Arc::new(AtomicUsize::new(0));
        let count_cb = count.clone();
        let callback: Arc<StdMutex<Option<Box<TransportCallback>>>> =
            Arc::new(StdMutex::new(Some(Box::new(move |_m: AuthMessage| {
                let count_cb = count_cb.clone();
                Box::pin(async move {
                    count_cb.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            }))));

        let sink = CapturingSink::default();
        run_dispatch(OneShotFrames { frame: Some(frame) }, sink, callback).await;

        assert_eq!(count.load(Ordering::SeqCst), 1, "callback should fire once");
    }

    #[tokio::test]
    async fn dispatch_replies_pong_to_ping() {
        // A frame source that yields one Ping then closes.
        struct PingThenClose {
            frame: Option<EngineIoPacket>,
        }
        #[async_trait]
        impl SocketIoFrameSource for PingThenClose {
            async fn recv_engineio(&mut self) -> std::result::Result<EngineIoPacket, String> {
                self.frame.take().ok_or_else(|| "closed".to_string())
            }
        }

        // A sink that records every engineio frame it is asked to send.
        #[derive(Clone, Default)]
        struct PongSink {
            sent: Arc<StdMutex<Vec<String>>>,
        }
        impl SocketIoSink for PongSink {
            fn send_socketio(&self, pkt: &SocketIoPacket) -> std::result::Result<(), String> {
                self.sent
                    .lock()
                    .unwrap()
                    .push(EngineIoPacket::Message(pkt.encode()).encode());
                Ok(())
            }
            fn send_engineio(&self, pkt: &EngineIoPacket) -> std::result::Result<(), String> {
                self.sent.lock().unwrap().push(pkt.encode());
                Ok(())
            }
        }

        let sink = PongSink::default();
        let callback: Arc<StdMutex<Option<Box<TransportCallback>>>> = Arc::new(StdMutex::new(None));
        run_dispatch(
            PingThenClose {
                frame: Some(EngineIoPacket::Ping(String::new())),
            },
            sink.clone(),
            callback,
        )
        .await;

        let sent = sink.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "exactly one pong should be sent");
        assert_eq!(sent[0], "3", "pong frame for a bare ping is `3`");
    }
}
