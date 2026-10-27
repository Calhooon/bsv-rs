//! The HTTP JSON substrate reads a wallet's error body as its class
//! (bsv-rs#137).
//!
//! The reference's error bodies at `ts-stack@edf6e03`: the SDK's
//! `WalletError.unknownToJson` (`packages/sdk/src/wallet/WalletError.ts:29-67`:
//! `isError`, `name`, `message`, and `code` 5, 6, 7 for its three `WERR_*`),
//! the wallet-toolbox's `toJson` (`packages/wallet/wallet-toolbox/src/sdk/WalletError.ts:143-151`:
//! `isError`, `name`, `message`; `WERR_errors.ts:110,136,225,278` add `code`
//! 6, 8, 7, 5) and its `asStatus` (`WalletError.ts:126-132`: `status`, `code`
//! the `WERR_*` name, `description`). The class is the body's `name`, else its
//! `code` (an SDK code 2 to 8, or a class's name); the words its `message`,
//! else its `description`. The reference's `HTTPWalletJSON` builds a typed
//! error from codes 5, 6, 7 alone and refuses a body whose `code` is no
//! integer (`HTTPWalletJSON.ts:199-206`, `:329-335`); this substrate reads
//! every class the table names (the CHANGELOG's parity note).
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_refusal_class`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::{Error, WalletRefusalClass};
use serde_json::{json, Value};
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

async fn create_action_against(status: u16, body: Value) -> Error {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/createAction"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;
    HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
        .expect("the substrate is configured")
        .create_action(create_action_args(), Some("app.example.com"))
        .await
        .expect_err("the wallet answered an error")
}

fn refusal(class: WalletRefusalClass, message: &str) -> Error {
    Error::WalletRefusal {
        class,
        message: message.into(),
    }
}

/// The toolbox's `toJson` of every class: `name` the class, `message` the
/// words, `code` where the class assigns one.
#[tokio::test]
async fn the_toolboxs_body_reads_as_its_class_by_name() {
    for class in WalletRefusalClass::ALL {
        let mut body = json!({
            "isError": true,
            "name": class.name(),
            "message": format!("refused as {class}"),
        });
        if let Some(code) = class.code() {
            body["code"] = json!(code);
        }
        let error = create_action_against(400, body).await;
        assert_eq!(
            error,
            refusal(class, &format!("refused as {class}")),
            "{class}"
        );
    }
}

/// The toolbox's `asStatus`: `code` the class's name, `description` the words.
#[tokio::test]
async fn the_toolboxs_status_body_reads_as_its_class_by_code_name() {
    let error = create_action_against(
        401,
        json!({
            "status": "error",
            "code": "WERR_UNAUTHORIZED",
            "description": "Access is denied due to an authorization error.",
        }),
    )
    .await;
    assert_eq!(
        error,
        refusal(
            WalletRefusalClass::Unauthorized,
            "Access is denied due to an authorization error."
        )
    );
}

/// The SDK's `unknownToJson` of `WERR_INSUFFICIENT_FUNDS` (`:47-50`), byte
/// for byte its fields.
#[tokio::test]
async fn the_sdks_insufficient_funds_body_reads_as_its_class() {
    let error = create_action_against(
        400,
        json!({
            "name": "WERR_INSUFFICIENT_FUNDS",
            "message": "Insufficient funds in the available inputs",
            "isError": true,
            "totalSatoshisNeeded": 1000,
            "moreSatoshisNeeded": 500,
            "code": 7,
        }),
    )
    .await;
    assert_eq!(
        error,
        refusal(
            WalletRefusalClass::InsufficientFunds,
            "Insufficient funds in the available inputs"
        )
    );
}

/// The collision: the toolbox's merkle-root body carries 8 and its name, the
/// name deciding; a bare 8 is the SDK's `abortRefused`.
#[tokio::test]
async fn a_code_8_is_the_merkle_root_by_name_and_abort_refused_alone() {
    let error = create_action_against(
        400,
        json!({ "isError": true, "name": "WERR_INVALID_MERKLE_ROOT", "message": "m", "code": 8 }),
    )
    .await;
    assert_eq!(error, refusal(WalletRefusalClass::InvalidMerkleRoot, "m"));

    let error =
        create_action_against(400, json!({ "isError": true, "message": "a", "code": 8 })).await;
    assert_eq!(error, refusal(WalletRefusalClass::AbortRefused, "a"));
}

/// A class's body with no words carries its name as the words; a name no
/// class carries falls to the numeric code, then to the old reading.
#[tokio::test]
async fn a_body_without_words_or_class_reads_as_before() {
    let error = create_action_against(500, json!({ "code": "WERR_INTERNAL" })).await;
    assert_eq!(
        error,
        refusal(WalletRefusalClass::Internal, "WERR_INTERNAL")
    );

    let error = create_action_against(
        400,
        json!({ "isError": true, "name": "Error", "message": "bad", "code": 6 }),
    )
    .await;
    assert_eq!(error, refusal(WalletRefusalClass::InvalidParameter, "bad"));

    let error = create_action_against(
        500,
        json!({ "name": "WERR_UNKNOWN", "code": 1, "description": "boom" }),
    )
    .await;
    assert_eq!(
        error,
        Error::WalletError("wallet error (code 1): boom".into())
    );

    let error =
        create_action_against(500, json!({ "name": "WERR_UNKNOWN", "message": "boom" })).await;
    assert!(
        matches!(&error, Error::WalletError(words) if words.starts_with("HTTP 500")),
        "{error:?}"
    );
}
