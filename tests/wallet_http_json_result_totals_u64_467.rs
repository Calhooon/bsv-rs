//! #467: replay R47 boundary verdicts recorded under Node 22, checking exact totals.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/wallet.rs"]
mod wallet;
#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use bsv_rs::wallet::{substrates::HttpWalletJson, wire::WalletCall};
use bsv_rs::Error;
use serde_json::Value;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn check(call: WalletCall, field: &str) {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_result_totals_u64_467.json")).unwrap();
    assert_eq!(vector["source"], "ts-stack@edf6e03");
    assert_eq!(vector["node"], "v22.18.0");
    assert_eq!(vector["cases"].as_array().unwrap().len(), 25);
    let server = MockServer::start().await;
    let client = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    let mut checked = 0;
    for case in vector["cases"].as_array().unwrap() {
        if case["call"] != call.method_name() {
            continue;
        }
        server.reset().await;
        Mock::given(method("POST"))
            .and(path(format!("/{}", call.method_name())))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(case["bodyText"].as_str().unwrap(), "application/json"),
            )
            .mount(&server)
            .await;
        let result = wallet::invoke(&client, call, case["args"].clone()).await;
        if case["reference"]["accepted"] == true {
            let body: Value = serde_json::from_str(case["bodyText"].as_str().unwrap()).unwrap();
            assert_eq!(result.unwrap()[field], body[field], "{}", case["name"]);
        } else {
            assert_eq!(
                result.unwrap_err(),
                Error::WalletError(case["reference"]["error"].as_str().unwrap().into()),
                "{}",
                case["name"]
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 5);
}

#[tokio::test]
async fn http_list_actions_total_u64_467() {
    check(WalletCall::ListActions, "totalActions").await;
}

#[tokio::test]
async fn http_list_outputs_total_u64_467() {
    check(WalletCall::ListOutputs, "totalOutputs").await;
}

#[tokio::test]
async fn http_list_certificates_total_u64_467() {
    check(WalletCall::ListCertificates, "totalCertificates").await;
}

#[tokio::test]
async fn http_discover_identity_total_u64_467() {
    check(WalletCall::DiscoverByIdentityKey, "totalCertificates").await;
}

#[tokio::test]
async fn http_discover_attributes_total_u64_467() {
    check(WalletCall::DiscoverByAttributes, "totalCertificates").await;
}
