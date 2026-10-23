//! The HTTP JSON substrate's busy answer (Calhooon/bsv-wallet-cli#44): the
//! body's code `STORE_BUSY` or `ERR_SERVER_BUSY`, at any status, reads back as
//! `Error::WalletBusy`, `Retry-After` in delta-seconds as `retry_after_ms`, an
//! HTTP-date as `None`. A 502, 503 or 504 without that code (and without a
//! numeric wallet code), a refused or reset connection and a timeout read back
//! as `Error::WalletTransport` (Calhooon/bsv-rs#73), with no promise about what
//! the wallet did; every other answer keeps its `WalletError` text.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_busy_tests`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::Error;
use std::io::Read;
use std::net::TcpListener;
use std::time::Duration;
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

async fn create_action_against(answer: ResponseTemplate) -> Error {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(None, Some(server.uri()));
    wallet
        .create_action(create_action_args(), "app.example.com")
        .await
        .expect_err("the wallet answered an error")
}

#[test]
fn wallet_busy_displays_its_detail_and_compares_on_both_fields() {
    let busy = Error::WalletBusy {
        detail: "database is locked".into(),
        retry_after_ms: Some(1000),
    };
    assert_eq!(busy.to_string(), "wallet busy: database is locked");
    assert_ne!(
        busy,
        Error::WalletBusy {
            detail: "database is locked".into(),
            retry_after_ms: None,
        }
    );
    // Not the general wallet error: a host matches the variant, not a string
    assert!(!matches!(busy, Error::WalletError(_)));
}

#[tokio::test]
async fn the_producers_store_busy_body_is_wallet_busy_with_the_delay() {
    // bsv-wallet-cli's busy answer, byte for byte (handlers.rs, AppError)
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "1")
            .set_body_json(serde_json::json!({
                "code": "STORE_BUSY",
                "message": "Store busy: database is locked",
            })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "Store busy: database is locked".into(),
            retry_after_ms: Some(1000),
        }
    );
}

#[tokio::test]
async fn store_busy_on_a_500_is_wallet_busy() {
    let err = create_action_against(ResponseTemplate::new(500).set_body_json(serde_json::json!({
        "code": "STORE_BUSY",
        "message": "Store busy: sqlite code 5",
    })))
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "Store busy: sqlite code 5".into(),
            retry_after_ms: None,
        }
    );
}

#[tokio::test]
async fn the_ts_toolbox_err_server_busy_body_is_wallet_busy_with_its_description() {
    // ts-stack@edf6e03 wallet-toolbox `storage/remoting/edgePolicy.ts:668-672`
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "1")
            .set_body_json(serde_json::json!({
                "status": "error",
                "code": "ERR_SERVER_BUSY",
                "description": "The service is temporarily at capacity.",
            })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "The service is temporarily at capacity.".into(),
            retry_after_ms: Some(1000),
        }
    );
}

#[tokio::test]
async fn the_first_of_two_retry_after_headers_wins() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .append_header("Retry-After", "7")
            .append_header("Retry-After", "1")
            .set_body_json(serde_json::json!({ "code": "STORE_BUSY", "message": "busy" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "busy".into(),
            retry_after_ms: Some(7000),
        }
    );
}

#[tokio::test]
async fn a_busy_body_with_an_http_date_retry_after_has_no_delay() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
            .set_body_json(serde_json::json!({ "code": "STORE_BUSY", "message": "busy" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "busy".into(),
            retry_after_ms: None,
        }
    );
}

#[tokio::test]
async fn an_html_503_from_a_proxy_is_a_transport_fault() {
    // A proxy's 503 promises nothing about the wallet: the status is not the word
    let html = "<html><body><h1>503 Service Temporarily Unavailable</h1></body></html>";
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "1")
            .set_body_string(html),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletTransport {
            status: Some(503),
            detail: format!("HTTP 503 Service Unavailable for createAction: {}", html),
        }
    );
    assert!(!matches!(
        err,
        Error::WalletBusy { .. } | Error::WalletError(_)
    ));
}

#[tokio::test]
async fn a_bare_503_is_a_transport_fault() {
    let err = create_action_against(ResponseTemplate::new(503)).await;
    assert_eq!(
        err,
        Error::WalletTransport {
            status: Some(503),
            detail: "HTTP 503 Service Unavailable for createAction: ".into(),
        }
    );
}

#[tokio::test]
async fn a_503_with_a_message_and_no_code_is_a_transport_fault() {
    let err = create_action_against(
        ResponseTemplate::new(503).set_body_json(serde_json::json!({ "message": "busy" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletTransport {
            status: Some(503),
            detail: r#"HTTP 503 Service Unavailable for createAction: {"message":"busy"}"#.into(),
        }
    );
}

#[tokio::test]
async fn a_502_and_a_504_are_transport_faults() {
    let err =
        create_action_against(ResponseTemplate::new(502).set_body_string("bad gateway")).await;
    assert_eq!(
        err,
        Error::WalletTransport {
            status: Some(502),
            detail: "HTTP 502 Bad Gateway for createAction: bad gateway".into(),
        }
    );

    let err = create_action_against(ResponseTemplate::new(504)).await;
    assert_eq!(
        err,
        Error::WalletTransport {
            status: Some(504),
            detail: "HTTP 504 Gateway Timeout for createAction: ".into(),
        }
    );
}

#[tokio::test]
async fn store_busy_on_a_502_or_504_is_still_wallet_busy() {
    for status in [502, 504] {
        let err = create_action_against(
            ResponseTemplate::new(status)
                .set_body_json(serde_json::json!({ "code": "STORE_BUSY", "message": "busy" })),
        )
        .await;
        assert_eq!(
            err,
            Error::WalletBusy {
                detail: "busy".into(),
                retry_after_ms: None,
            }
        );
    }
}

#[tokio::test]
async fn a_refused_connection_is_a_transport_fault() {
    // A port bound and released: nothing listens there
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let wallet = HttpWalletJson::new(None, Some(format!("http://127.0.0.1:{}", port)));
    let err = wallet
        .create_action(create_action_args(), "app.example.com")
        .await
        .expect_err("nothing listens");
    match err {
        Error::WalletTransport { status, detail } => {
            assert_eq!(status, None);
            assert!(detail.starts_with("HTTP request failed: "), "{}", detail);
        }
        other => panic!("expected WalletTransport, got {:?}", other),
    }
}

#[tokio::test]
async fn a_connection_reset_before_an_answer_is_a_transport_fault() {
    // The peer takes the request and closes with it unread: the kernel resets
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut one = [0u8; 1];
        let _ = stream.read(&mut one);
        drop(stream);
    });
    let wallet = HttpWalletJson::new(None, Some(format!("http://{}", addr)));
    let err = wallet
        .create_action(create_action_args(), "app.example.com")
        .await
        .expect_err("the peer closed");
    peer.join().unwrap();
    match err {
        Error::WalletTransport { status, detail } => {
            assert_eq!(status, None);
            assert!(detail.starts_with("HTTP request failed: "), "{}", detail);
        }
        other => panic!("expected WalletTransport, got {:?}", other),
    }
}

#[tokio::test]
async fn a_timeout_is_a_transport_fault() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let wallet = HttpWalletJson::with_client(client, None, Some(server.uri()));
    let err = wallet
        .create_action(create_action_args(), "app.example.com")
        .await
        .expect_err("the answer came too late");
    match err {
        Error::WalletTransport { status, detail } => {
            assert_eq!(status, None);
            assert!(detail.starts_with("HTTP request failed: "), "{}", detail);
        }
        other => panic!("expected WalletTransport, got {:?}", other),
    }
}

#[test]
fn wallet_transport_displays_its_detail_and_is_neither_busy_nor_a_refusal() {
    let fault = Error::WalletTransport {
        status: Some(503),
        detail: "HTTP 503 Service Unavailable for createAction: ".into(),
    };
    assert_eq!(
        fault.to_string(),
        "wallet transport fault: HTTP 503 Service Unavailable for createAction: "
    );
    assert_ne!(
        fault,
        Error::WalletTransport {
            status: None,
            detail: "HTTP 503 Service Unavailable for createAction: ".into(),
        }
    );
    assert!(!matches!(
        fault,
        Error::WalletBusy { .. } | Error::WalletError(_)
    ));
}

#[tokio::test]
async fn a_503_with_a_numeric_code_keeps_the_coded_wallet_error() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .set_body_json(serde_json::json!({ "code": 1, "description": "writer held" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletError("wallet error (code 1): writer held".into())
    );
}

#[tokio::test]
async fn every_other_status_keeps_the_wallet_error_mapping() {
    let err = create_action_against(
        ResponseTemplate::new(400)
            .insert_header("Retry-After", "2")
            .set_body_json(serde_json::json!({ "code": 6, "description": "bad args" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletError("wallet error (code 6): bad args".into())
    );

    let err = create_action_against(
        ResponseTemplate::new(500)
            .set_body_json(serde_json::json!({ "code": 7, "description": "internal" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletError("wallet error (code 7): internal".into())
    );

    let err = create_action_against(ResponseTemplate::new(500).set_body_string("boom")).await;
    assert_eq!(
        err,
        Error::WalletError("HTTP 500 Internal Server Error for createAction: boom".into())
    );
}
