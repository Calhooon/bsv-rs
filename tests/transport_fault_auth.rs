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

#[path = "support/body_stub.rs"]
mod body_stub;

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

async fn handshake_answered(answer: ResponseTemplate) -> (Error, String) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    let error = SimplifiedFetchTransport::new(&server.uri())
        .send(&handshake())
        .await
        .expect_err("the handshake fails");
    (error, server.uri())
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

/// A client of one second's timeout (`with_client`), the fault read where
/// the transport's own 30 s client would read it: the class is the error's,
/// not the clock's (speed loop two, #670; until then the test waited the
/// 30 s of `SimplifiedFetchTransport::new`).
#[tokio::test]
async fn a_timeout_after_the_request_was_written_may_have_been_received() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .expect(1)
        .mount(&server)
        .await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let err = SimplifiedFetchTransport::with_client(&server.uri(), client)
        .send(&handshake())
        .await
        .unwrap_err();
    assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait() {
    let (err, _) = handshake_answered(
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
    let (err, origin) = handshake_answered(ResponseTemplate::new(503)).await;
    assert_fault(&err, TransportFault::MayHaveBeenReceived, Some(503));
    assert_eq!(
        err.to_string(),
        format!("transport fault MAY_HAVE_BEEN_RECEIVED: Received HTTP 503 Service Unavailable from {origin}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers)")
    );
}

#[tokio::test]
async fn a_503_with_a_busy_code_is_still_a_transport_fault() {
    // The auth handshake has no busy word: the status alone promises nothing
    let (err, _) = handshake_answered(
        ResponseTemplate::new(503).set_body_json(serde_json::json!({"code": "STORE_BUSY"})),
    )
    .await;
    assert_fault(&err, TransportFault::MayHaveBeenReceived, Some(503));
}

#[tokio::test]
async fn any_other_status_stays_the_auth_error() {
    let (err, origin) = handshake_answered(ResponseTemplate::new(401).set_body_string("no")).await;
    assert_eq!(
        err,
        Error::AuthError(format!("Received HTTP 401 Unauthorized from {origin}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers) - body preview: no"))
    );
    assert_eq!(err.transport_fault(), None);
}

/// #98: the head arrives, twelve bytes of the body, and nothing more. The
/// client's timeout (`with_client`, as the timeout cell's) ends the call on
/// both paths, in the class the timeout cell answers, after one request each,
/// counted once the stub's reads ended.
#[tokio::test]
async fn a_body_that_never_ends_is_bounded_by_the_timeout_and_may_have_been_received_98() {
    let stub = body_stub::BodyStub::stalled().await;
    for (path, message) in [("handshake", handshake()), ("general", general())] {
        let message = &message;
        let url = &stub.url;
        let err = stub
            .stalled_once(path, || async move {
                let client = reqwest::Client::builder()
                    .timeout(body_stub::DOOR_TIMEOUT)
                    .build()
                    .unwrap();
                let transport = SimplifiedFetchTransport::with_client(url, client);
                transport.send(message).await
            })
            .await
            .unwrap_err();
        assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
    }
    assert_eq!(stub.settled().await, 2, "one request a call");
}

/// #98: a handshake answered `200` with a body that is not the message's
/// JSON is the transport's refusal in its own class, `AuthError`, never a
/// panic and never a transport fault: the far side answered. The general
/// path reads no JSON (its answer is the BRC-104 headers and a byte body).
#[tokio::test]
async fn a_handshake_answer_that_is_not_the_messages_json_is_an_auth_error_never_a_fault_98() {
    for body in [
        "",
        "not json",
        "{\"version\":",
        "{\"version\":\"0.1\",\"messageType\":\"initialResponse\"",
        "[]",
        "{}",
        "null",
        "\u{feff}",
        "{\"identityKey\":7}",
    ] {
        let (err, _) =
            handshake_answered(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
                .await;
        assert!(matches!(err, Error::AuthError(_)), "{body:?}: {err:?}");
        assert_eq!(err.transport_fault(), None, "{body:?}");
    }
}

/// A body cut after the request was written (the reviewer's probe on #87):
/// reqwest reads it as a decode error whose source is not `serde_json`'s.
#[cfg(not(target_arch = "wasm32"))]
mod body_cut {
    use super::*;

    #[tokio::test]
    async fn a_body_cut_after_the_request_was_written_may_have_been_received() {
        let stub = body_stub::BodyStub::cut().await;
        let transport = SimplifiedFetchTransport::new(&stub.url);
        for message in [handshake(), general()] {
            let err = transport.send(&message).await.unwrap_err();
            assert_fault(&err, TransportFault::MayHaveBeenReceived, None);
        }
        assert_eq!(stub.requests(), 2, "one request a call");
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
