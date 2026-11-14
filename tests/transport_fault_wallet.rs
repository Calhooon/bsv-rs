//! The wallet substrates' transport fault (Calhooon/bsv-rs#87). Both HTTP
//! substrates answer `Error::WalletTransport` for a connection error, a
//! timeout and a 502, 503 or 504 without the wallet's word (0.8.2's #73 for
//! `HttpWalletJson`, carried to `HttpWalletWire`, which answered
//! `WalletError`); a 429 without a busy code is `Error::TransportFault`,
//! rate limited, with its wait; busy stays the body's word.
//!
//! Run with: `cargo test --features "wallet,http" --test transport_fault_wallet`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use std::net::TcpListener;
use std::time::Duration;

use bsv_rs::wallet::substrates::{HttpWalletJson, HttpWalletWire};
use bsv_rs::wallet::wire::{WalletCall, WalletWire};
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::{Error, TransportFault};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/body_stub.rs"]
mod body_stub;

fn create_action_args() -> CreateActionArgs {
    CreateActionArgs {
        description: "a served createAction".into(),
        input_beef: None,
        inputs: None,
        outputs: None,
        lock_time: None,
        version: None,
        labels: None,
        options: None,
    }
}

fn client(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder().timeout(timeout).build().unwrap()
}

/// `createAction` through the JSON substrate against `url`.
async fn json_at(url: &str, timeout: Duration) -> Error {
    let json = HttpWalletJson::with_client(
        client(timeout),
        Some("app.example.com".into()),
        Some(url.to_string()),
    )
    .expect("the substrate is configured");
    json.create_action(create_action_args(), Some("app.example.com"))
        .await
        .expect_err("the JSON substrate fails")
}

/// `createAction` through the wire substrate against `url`.
async fn wire_at(url: &str, timeout: Duration) -> Error {
    let wire = HttpWalletWire::with_client(client(timeout), None, Some(url.to_string()))
        .expect("the substrate is configured");
    wire.transmit_to_wallet(&[WalletCall::CreateAction as u8, 0, 1, 2, 3])
        .await
        .expect_err("the wire substrate fails")
}

/// `createAction` through both substrates against `url`.
async fn both_at(url: &str, timeout: Duration) -> [(&'static str, Error); 2] {
    let json_err = json_at(url, timeout).await;
    let wire_err = wire_at(url, timeout).await;
    [("json", json_err), ("wire", wire_err)]
}

async fn both_answered(answer: ResponseTemplate) -> [(&'static str, Error); 2] {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(answer)
        .expect(2)
        .mount(&server)
        .await;
    both_at(&server.uri(), Duration::from_secs(30)).await
}

fn assert_transport(name: &str, err: &Error, status: Option<u16>) {
    match err {
        Error::WalletTransport { status: got, .. } => assert_eq!(*got, status, "{name}"),
        other => panic!("{name}: expected WalletTransport, got {other:?}"),
    }
    assert_eq!(
        err.transport_fault(),
        Some(TransportFault::MayHaveBeenReceived),
        "{name}"
    );
}

#[tokio::test]
async fn a_refused_connection_is_a_wallet_transport_fault_on_both_substrates() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}");
    for (name, err) in both_at(&url, Duration::from_secs(30)).await {
        assert_transport(name, &err, None);
    }
}

#[tokio::test]
async fn a_timeout_after_the_request_was_written_is_a_wallet_transport_fault() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .expect(2)
        .mount(&server)
        .await;
    for (name, err) in both_at(&server.uri(), Duration::from_millis(300)).await {
        assert_transport(name, &err, None);
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_429_without_a_busy_code_is_rate_limited_with_its_wait() {
    let answers = both_answered(
        ResponseTemplate::new(429)
            .insert_header("Retry-After", "5")
            .set_body_raw("Too Many Requests", "text/plain"),
    )
    .await;
    let fault = TransportFault::RateLimited {
        retry_after_ms: Some(5000),
    };
    for (name, err) in answers {
        match &err {
            Error::TransportFault {
                fault: got, status, ..
            } => {
                assert_eq!(*got, fault, "{name}");
                assert_eq!(*status, Some(429), "{name}");
            }
            other => panic!("{name}: expected TransportFault, got {other:?}"),
        }
        assert_eq!(err.transport_fault(), Some(fault), "{name}");
    }
}

#[tokio::test]
async fn a_503_without_a_busy_code_is_a_wallet_transport_fault() {
    for (name, err) in both_answered(ResponseTemplate::new(503)).await {
        assert_transport(name, &err, Some(503));
    }
}

#[tokio::test]
async fn store_busy_on_a_503_is_wallet_busy_where_the_substrate_reads_one() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "5")
                .set_body_json(serde_json::json!({ "code": "STORE_BUSY", "message": "busy" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let json = HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
        .expect("the substrate is configured");
    let err = json
        .create_action(create_action_args(), Some("app.example.com"))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "busy".into(),
            retry_after_ms: Some(5000),
        }
    );
    assert_eq!(err.transport_fault(), None, "busy is not a transport fault");
}

/// #98: the head arrives, twelve bytes of the body, and nothing more. The
/// client's timeout (`with_client`, as the timeout cell's) ends the call on
/// each substrate, in the class the timeout cell answers, after one request.
/// Each substrate is held by itself (the fold of #98): its own call waited
/// out its own timeout and made its own one request, so one that answered at
/// once beside one that waited is refused.
#[tokio::test]
async fn a_body_that_never_ends_is_bounded_by_the_timeout_and_a_wallet_transport_fault_98() {
    let stub = body_stub::BodyStub::stalled().await;
    let url = &stub.url;
    let json = stub
        .stalled_once("json", || json_at(url, body_stub::DOOR_TIMEOUT))
        .await;
    assert_transport("json", &json, None);
    let wire = stub
        .stalled_once("wire", || wire_at(url, body_stub::DOOR_TIMEOUT))
        .await;
    assert_transport("wire", &wire, None);
    assert_eq!(stub.settled().await, 2, "one request a call");
}

/// `createAction` through the JSON substrate against one answer, asked once.
async fn json_answered(answer: ResponseTemplate) -> Error {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
        .expect("the substrate is configured")
        .create_action(create_action_args(), Some("app.example.com"))
        .await
        .expect_err("the JSON substrate fails")
}

/// #98: the JSON substrate's answer whose body is not the result's JSON, at
/// a success status and at a refusal's, is the wallet's answer misread,
/// `WalletError`, never a panic and never a transport fault. The wire
/// substrate reads no JSON (its answer is a byte frame).
#[tokio::test]
async fn an_answer_that_is_not_the_results_json_is_a_wallet_error_never_a_fault_98() {
    for status in [200, 400, 500] {
        for body in ["", "{\"txid\":", "[]", "null", "{\"txid\":7}", "\u{feff}{"] {
            let err =
                json_answered(ResponseTemplate::new(status).set_body_raw(body, "application/json"))
                    .await;
            assert!(
                matches!(err, Error::WalletError(_)),
                "{status} {body:?}: {err:?}"
            );
            assert_eq!(err.transport_fault(), None, "{status} {body:?}");
        }
    }
}

/// A body cut after the request was written (the reviewer's probe on #87):
/// reqwest reads it as a decode error whose source is not `serde_json`'s.
#[cfg(not(target_arch = "wasm32"))]
mod body_cut {
    use super::*;

    #[tokio::test]
    async fn a_body_cut_after_the_request_was_written_is_a_wallet_transport_fault() {
        let stub = body_stub::BodyStub::cut().await;
        for (name, err) in both_at(&stub.url, Duration::from_secs(30)).await {
            assert_transport(name, &err, None);
        }
        assert_eq!(stub.requests(), 2, "one request a call");
    }

    /// The other half of the rule: a success body that is not the expected
    /// JSON is a decode error from `serde_json`, the wallet's answer.
    #[tokio::test]
    async fn a_success_body_that_is_not_json_stays_the_wallet_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/createAction"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .expect(1)
            .mount(&server)
            .await;
        let err = HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
            .expect("the substrate is configured")
            .create_action(create_action_args(), Some("app.example.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::WalletError(_)), "{err:?}");
        assert_eq!(err.transport_fault(), None);
    }
}
