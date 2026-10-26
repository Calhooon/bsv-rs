//! The Socket.IO transport passes an `AuthMessage`'s text through (#280): a
//! certificateRequest's and a certificateResponse's signatures cover their
//! JSON text as transmitted, and a `serde_json::Value` sorts object keys,
//! so the send writes the message's serialized text through
//! `SocketIoSink::send_socketio_text` and the dispatch reads the event
//! argument's text.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "socketio")]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bsv_rs::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
use bsv_rs::auth::transports::socketio::{
    run_dispatch, SocketIoFrameSource, SocketIoSink, SocketIoTransport,
};
use bsv_rs::auth::transports::TransportCallback;
use bsv_rs::auth::{AuthMessage, Transport};
use bsv_rs::primitives::PrivateKey;

/// A certificateRequest whose `requestedCertificates` text no sort gives:
/// three types in reverse order
fn unsorted_certificate_request() -> (AuthMessage, String) {
    let key = PrivateKey::from_hex(&"0a".repeat(32)).unwrap().public_key();
    let text = r#"{"certifiers":[],"types":{"cc":["z","y"],"bb":["x"],"aa":["w"]}}"#;
    let message = format!(
        r#"{{"version":"0.1","messageType":"certificateRequest","identityKey":"{}","nonce":"AA==","requestedCertificates":{text},"signature":[48]}}"#,
        key.to_hex()
    );
    (serde_json::from_str(&message).unwrap(), text.to_string())
}

/// A sink writing the text it is given; its `Value` path refused
#[derive(Clone, Default)]
struct TextSink {
    last: Arc<Mutex<Option<String>>>,
}

impl SocketIoSink for TextSink {
    fn send_socketio(&self, _pkt: &SocketIoPacket) -> Result<(), String> {
        Err("the text path is expected".into())
    }

    fn send_socketio_text(&self, packet: &str) -> Result<(), String> {
        *self.last.lock().unwrap() = Some(EngineIoPacket::Message(packet.into()).encode());
        Ok(())
    }
}

#[tokio::test]
async fn send_writes_the_signed_text_as_serialized() {
    let (message, text) = unsorted_certificate_request();
    let sink = TextSink::default();
    SocketIoTransport::new(sink.clone())
        .send(&message)
        .await
        .unwrap();
    let frame = sink.last.lock().unwrap().clone().unwrap();
    assert_eq!(
        frame,
        format!(
            "42[\"authMessage\",{}]",
            serde_json::to_string(&message).unwrap()
        )
    );
    assert!(frame.contains(&format!(r#""requestedCertificates":{text}"#)));
}

#[tokio::test]
async fn dispatch_reads_the_signed_text_as_transmitted() {
    struct OneShotFrames {
        frame: Option<EngineIoPacket>,
    }
    #[async_trait]
    impl SocketIoFrameSource for OneShotFrames {
        async fn recv_engineio(&mut self) -> Result<EngineIoPacket, String> {
            self.frame.take().ok_or_else(|| "closed".to_string())
        }
    }

    let (message, text) = unsorted_certificate_request();
    let frame = EngineIoPacket::Message(format!(
        "2[\"authMessage\",{}]",
        serde_json::to_string(&message).unwrap()
    ));
    let signed = Arc::new(Mutex::new(None));
    let signed_cb = signed.clone();
    let callback: Arc<Mutex<Option<Box<TransportCallback>>>> =
        Arc::new(Mutex::new(Some(Box::new(move |m: AuthMessage| {
            *signed_cb.lock().unwrap() = Some(m.signing_data());
            Box::pin(async { Ok(()) })
                as std::pin::Pin<Box<dyn std::future::Future<Output = bsv_rs::Result<()>> + Send>>
        }))));
    run_dispatch(
        OneShotFrames { frame: Some(frame) },
        TextSink::default(),
        callback,
    )
    .await;
    assert_eq!(
        String::from_utf8(signed.lock().unwrap().clone().unwrap()).unwrap(),
        text
    );
}
