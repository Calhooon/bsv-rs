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

/// `createAction` through both substrates against `url`.
async fn both_at(url: &str, timeout: Duration) -> [(&'static str, Error); 2] {
    let json = HttpWalletJson::with_client(client(timeout), None, Some(url.to_string()));
    let json_err = json
        .create_action(create_action_args(), "app.example.com")
        .await
        .expect_err("the JSON substrate fails");
    let wire = HttpWalletWire::with_client(client(timeout), None, Some(url.to_string()));
    let wire_err = wire
        .transmit_to_wallet(&[WalletCall::CreateAction as u8, 0, 1, 2, 3])
        .await
        .expect_err("the wire substrate fails");
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
        .mount(&server)
        .await;
    let json = HttpWalletJson::new(None, Some(server.uri()));
    let err = json
        .create_action(create_action_args(), "app.example.com")
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
