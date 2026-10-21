//! The HTTP JSON substrate's busy answer (Calhooon/bsv-wallet-cli#44): a 503
//! reads back as `Error::WalletBusy`, `Retry-After` in delta-seconds as
//! `retry_after_ms`, an HTTP-date as `None`; every other status keeps its
//! `WalletError` text.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_busy_tests`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::Error;
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
async fn a_503_with_retry_after_seconds_is_wallet_busy_with_the_delay() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "2")
            .set_body_json(serde_json::json!({ "message": "store busy: database is locked" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "store busy: database is locked".into(),
            retry_after_ms: Some(2000),
        }
    );
}

#[tokio::test]
async fn a_503_without_retry_after_is_wallet_busy_with_no_delay() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .set_body_json(serde_json::json!({ "code": 1, "description": "writer held" })),
    )
    .await;
    assert_eq!(
        err,
        Error::WalletBusy {
            detail: "(code 1) writer held".into(),
            retry_after_ms: None,
        }
    );
}

#[tokio::test]
async fn a_503_with_an_http_date_retry_after_is_wallet_busy_with_no_delay() {
    let err = create_action_against(
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
            .set_body_json(serde_json::json!({ "message": "busy" })),
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

    let err = create_action_against(ResponseTemplate::new(500).set_body_string("boom")).await;
    assert_eq!(
        err,
        Error::WalletError("HTTP 500 Internal Server Error for createAction: boom".into())
    );
}
