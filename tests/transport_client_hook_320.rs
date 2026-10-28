//! The HTTP auth transport's client (bsv-rs#320): `SimplifiedFetchTransport`
//! takes a caller's `reqwest::Client` (`with_client`, the reference's
//! `fetchClient`, `ts-stack@edf6e03`
//! `packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:64-67`), and
//! an answer with a redirect status is refused on both paths, never followed,
//! as the reference's `redirect: 'error'` refuses it (`:128`, `:212`). Before
//! #320 the transport's client followed up to ten hops and replayed the
//! signed request to the second host.
//!
//! Run with: `cargo test --features "auth,http" --test transport_client_hook_320`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "auth", feature = "http"))]

use bsv_rs::auth::transports::HttpRequest;
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn handshake() -> AuthMessage {
    AuthMessage::new(
        MessageType::InitialRequest,
        PrivateKey::random().public_key(),
    )
}

fn general() -> AuthMessage {
    let mut message = AuthMessage::new(MessageType::General, PrivateKey::random().public_key());
    message.signature = Some(vec![0x30, 0x00]);
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

/// The named host, answering `status` at `at` with a `Location` on `elsewhere`.
async fn redirecting(status: u16, verb: &str, at: &str, elsewhere: &MockServer) -> MockServer {
    let named = MockServer::start().await;
    Mock::given(method(verb))
        .and(path(at))
        .respond_with(
            ResponseTemplate::new(status)
                .insert_header("Location", format!("{}{}", elsewhere.uri(), at).as_str()),
        )
        .expect(1)
        .mount(&named)
        .await;
    named
}

/// The host a redirect points at, answering anything `401` so a followed hop
/// is seen by its text.
async fn elsewhere() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string("replayed"))
        .mount(&server)
        .await;
    server
}

fn redirect_refused(named: &MockServer, at: &str) -> Error {
    Error::AuthError(format!(
        "Network error while sending authenticated request to {}{}: fetch failed",
        named.uri(),
        at,
    ))
}

#[tokio::test]
async fn a_handshake_answered_with_a_redirect_is_refused_and_not_replayed() {
    for status in [301, 302, 303, 307, 308] {
        let other = elsewhere().await;
        let named = redirecting(status, "POST", "/.well-known/auth", &other).await;
        let err = SimplifiedFetchTransport::new(&named.uri())
            .send(&handshake())
            .await
            .unwrap_err();
        assert_eq!(
            err,
            redirect_refused(&named, "/.well-known/auth"),
            "{status}"
        );
        assert_eq!(err.transport_fault(), None, "the named host's answer");
        assert!(
            other.received_requests().await.unwrap().is_empty(),
            "{status}"
        );
    }
}

#[tokio::test]
async fn a_general_message_answered_with_a_redirect_is_refused_and_not_replayed() {
    for status in [302, 307] {
        let other = elsewhere().await;
        let named = redirecting(status, "POST", "/sendMessage", &other).await;
        let err = SimplifiedFetchTransport::new(&named.uri())
            .send(&general())
            .await
            .unwrap_err();
        assert_eq!(err, redirect_refused(&named, "/sendMessage"), "{status}");
        assert!(
            other.received_requests().await.unwrap().is_empty(),
            "{status}"
        );
    }
}

#[tokio::test]
async fn a_client_supplied_through_with_client_is_the_one_used() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .and(header("x-caller-client", "320"))
        .respond_with(ResponseTemplate::new(401).set_body_string("marked"))
        .expect(1)
        .mount(&server)
        .await;
    let mut marker = reqwest::header::HeaderMap::new();
    marker.insert("x-caller-client", "320".parse().unwrap());
    let client = reqwest::Client::builder()
        .default_headers(marker)
        .build()
        .unwrap();
    let transport = SimplifiedFetchTransport::with_client(&format!("{}/", server.uri()), client);
    assert_eq!(transport.base_url(), server.uri());
    let err = transport.send(&handshake()).await.unwrap_err();
    assert_eq!(
        err,
        Error::AuthError(format!(
            "Received HTTP 401 Unauthorized from {}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers) - body preview: marked",
            server.uri()
        ))
    );
}

#[tokio::test]
async fn a_supplied_client_that_follows_redirects_carries_its_own_policy() {
    // The caller's policy is the caller's: a client that follows has followed
    // before the transport reads the answer
    let other = elsewhere().await;
    let named = redirecting(307, "POST", "/.well-known/auth", &other).await;
    let err = SimplifiedFetchTransport::with_client(&named.uri(), reqwest::Client::new())
        .send(&handshake())
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::AuthError(format!(
            "Received HTTP 401 Unauthorized from {}/.well-known/auth without valid BSV authentication (response lacked required BSV auth headers) - body preview: replayed",
            named.uri()
        ))
    );
    assert_eq!(other.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_supplied_client_that_does_not_follow_is_refused_by_the_transport() {
    let other = elsewhere().await;
    let named = redirecting(302, "POST", "/sendMessage", &other).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let err = SimplifiedFetchTransport::with_client(&named.uri(), client)
        .send(&general())
        .await
        .unwrap_err();
    assert_eq!(err, redirect_refused(&named, "/sendMessage"));
    assert!(other.received_requests().await.unwrap().is_empty());
}
