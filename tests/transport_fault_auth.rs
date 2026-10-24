//! The auth transports' transport fault (Calhooon/bsv-rs#87): a connection
//! error, a timeout, and a handshake answered 429, 502, 503 or 504 are
//! `Error::TransportFault` with their class, never `AuthError(String)`; a
//! refusal in the far side's word (any other status) stays `AuthError`. The
//! Socket.IO transport's sink failure is a fault that may have been received.
//!
//! Run with: `cargo test --features "auth,http" --test transport_fault_auth`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "auth", feature = "http"))]

use std::io::Read;
use std::net::TcpListener;
use std::time::Duration;

use bsv_rs::auth::transports::HttpRequest;
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::{Error, TransportFault};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn handshake() -> AuthMessage {
    AuthMessage::new(
        MessageType::InitialRequest,
        PrivateKey::random().public_key(),
    )
}

fn general() -> AuthMessage {
    let mut message = AuthMessage::new(MessageType::General, PrivateKey::random().public_key());
    let request = HttpRequest {
        request_id: [7; 32],
        method: "POST".into(),
        path: "/sendMessage".into(),
        search: String::new(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: b"{}".to_vec(),
    };
    message.payload = Some(request.to_payload());
    message
}

async fn handshake_answered(answer: ResponseTemplate) -> Error {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    SimplifiedFetchTransport::new(&server.uri())
        .send(&handshake())
        .await
        .expect_err("the handshake fails")
}

fn assert_fault(err: &Error, fault: TransportFault, status: Option<u16>) {
    match err {
        Error::TransportFault {
            fault: got,
            status: got_status,
            ..
        } => {
            assert_eq!(*got, fault, "{err:?}");
            assert_eq!(*got_status, status, "{err:?}");
        }
        other => panic!("expected TransportFault, got {other:?}"),
    }
    assert_eq!(err.transport_fault(), Some(fault));
}

#[tokio::test]
async fn a_refused_connection_is_never_sent_on_both_paths() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let transport = SimplifiedFetchTransport::new(&format!("http://127.0.0.1:{port}"));
    for message in [handshake(), general()] {
        let err = transport.send(&message).await.unwrap_err();
        assert_fault(&err, TransportFault::NeverSent, None);
    }
}

#[tokio::test]
async fn a_connection_lost_after_the_request_was_written_may_have_been_received() {
    // The peer takes the request and closes with it unread: the kernel resets
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut one = [0u8; 1];
            let _ = stream.read(&mut one);
            drop(stream);
        }
    });
    let transport = SimplifiedFetchTransport::new(&format!("http://{addr}"));
    for message in [handshake(), general()] {
        let err = transport.send(&message).await.unwrap_err();
        assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
    }
    peer.join().unwrap();
}

/// The transport's client times out at 30 s (`SimplifiedFetchTransport::new`
/// takes no client), so this test waits that long.
#[tokio::test]
async fn a_timeout_after_the_request_was_written_may_have_been_received() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(40)))
        .mount(&server)
        .await;
    let err = SimplifiedFetchTransport::new(&server.uri())
        .send(&handshake())
        .await
        .unwrap_err();
    assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait() {
    let err = handshake_answered(
        ResponseTemplate::new(429)
            .insert_header("Retry-After", "5")
            .set_body_raw("Too Many Requests", "text/plain"),
    )
    .await;
    let fault = TransportFault::RateLimited {
        retry_after_ms: Some(5000),
    };
    assert_fault(&err, fault, Some(429));
}

#[tokio::test]
async fn a_bare_503_may_have_been_received() {
    let err = handshake_answered(ResponseTemplate::new(503)).await;
    assert_fault(&err, TransportFault::MayHaveBeenReceived, Some(503));
    assert_eq!(
        err.to_string(),
        "transport fault MAY_HAVE_BEEN_RECEIVED: Auth endpoint returned 503 Service Unavailable: "
    );
}

#[tokio::test]
async fn a_503_with_a_busy_code_is_still_a_transport_fault() {
    // The auth handshake has no busy word: the status alone promises nothing
    let err = handshake_answered(
        ResponseTemplate::new(503).set_body_json(serde_json::json!({"code": "STORE_BUSY"})),
    )
    .await;
    assert_fault(&err, TransportFault::MayHaveBeenReceived, Some(503));
}

#[tokio::test]
async fn any_other_status_stays_the_auth_error() {
    let err = handshake_answered(ResponseTemplate::new(401).set_body_string("no")).await;
    assert_eq!(
        err,
        Error::AuthError("Auth endpoint returned 401 Unauthorized: no".into())
    );
    assert_eq!(err.transport_fault(), None);
}

/// A body cut after the request was written (the reviewer's probe on #87):
/// reqwest reads it as a decode error whose source is not `serde_json`'s.
#[cfg(not(target_arch = "wasm32"))]
mod body_cut {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stub that reads each whole request, answers `200` with
    /// `Content-Length: 200`, sends twelve bytes of the body and closes: the
    /// body cut after the request was written. wiremock cannot cut a body.
    async fn cut_body_stub() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request_read(&request) {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 200\r\n\r\n0123456789ab",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        format!("http://{addr}")
    }

    /// Whether `request` holds its head and the body its `Content-Length`
    /// names.
    fn request_read(request: &[u8]) -> bool {
        let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        request.len() >= end + 4 + length
    }

    #[tokio::test]
    async fn a_body_cut_after_the_request_was_written_may_have_been_received() {
        let transport = SimplifiedFetchTransport::new(&cut_body_stub().await);
        for message in [handshake(), general()] {
            let err = transport.send(&message).await.unwrap_err();
            assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
        }
    }
}

#[cfg(feature = "socketio")]
mod socketio {
    use super::*;
    use bsv_rs::auth::transports::socketio::codec::SocketIoPacket;
    use bsv_rs::auth::transports::{SocketIoSink, SocketIoTransport};

    #[derive(Clone)]
    struct ClosedSink;

    impl SocketIoSink for ClosedSink {
        fn send_socketio(&self, _: &SocketIoPacket) -> Result<(), String> {
            Err("closed".into())
        }
    }

    #[tokio::test]
    async fn a_sink_failure_may_have_been_received() {
        let err = SocketIoTransport::new(ClosedSink)
            .send(&handshake())
            .await
            .unwrap_err();
        assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
    }
}
