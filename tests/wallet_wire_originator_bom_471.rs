//! #471: the header uses TextDecoder's one-leading-BOM rule before validation.
//! The #338 recorder captures both the decoded string and the wallet argument.
//! The three hostname cases are controls: validation already trims edge BOMs.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireReader, WireWriter};
use fixtures::wallet::Stub;
use serde_json::{json, Value};

async fn assert_processor(name: &str, decoded: &str, originator: Option<&str>) {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/originator_338.json")).unwrap();
    let cases = vector["processor"].as_array().unwrap();
    assert_eq!(cases.len(), 21, "recorded processor case census");
    let case = cases.iter().find(|case| case["name"] == name).unwrap();
    assert_eq!(case["decoded_originator"], decoded);

    let raw = case["originator"].as_str().unwrap().as_bytes();
    let mut request = WireWriter::new();
    request
        .write_u8(WalletCall::GetVersion.as_u8())
        .write_u8(u8::try_from(raw.len()).unwrap())
        .write_bytes(raw);
    assert_eq!(hex::encode(request.as_bytes()), case["request_hex"]);

    let wallet = Stub::new(json!({"version": "v-1.0.0"}));
    let response = WalletWireProcessor::new(wallet.clone())
        .process_message(request.as_bytes())
        .await
        .unwrap();
    let mut reader = WireReader::new(&response);
    let code = reader.read_u8().unwrap();
    let message = if code == 0 {
        None
    } else {
        Some(reader.read_string().unwrap())
    };
    assert_eq!(
        json!({"code": code, "message": message}),
        json!({"code": case["code"], "message": case["message"]}),
        "{name}: processor code and refusal words"
    );
    assert_eq!(hex::encode(response), case["response_hex"]);

    let observed = wallet.observed.lock().unwrap();
    let call = observed.as_ref().expect("the reference reached the wallet");
    assert_eq!(call["method"], "get_version");
    assert_eq!(call["originator"], json!(originator));
    // #329 represents the reference's empty string as Rust's None.
    let expected = if case["observed"] == json!([""]) {
        json!([null])
    } else {
        case["observed"].clone()
    };
    assert_eq!(json!([call["originator"]]), expected, "{name}");
}

#[tokio::test]
async fn bom_only_originator_471_is_absent() {
    assert_processor("bom-only", "", None).await;
}

#[tokio::test]
async fn leading_bom_before_hostname_471_is_removed_before_validation() {
    assert_processor("bom-before-host", "a.b", Some("a.b")).await;
}

#[tokio::test]
async fn second_bom_before_hostname_471_survives_decode_then_is_trimmed() {
    assert_processor("two-boms-before-host", "\u{feff}a.b", Some("a.b")).await;
}

#[tokio::test]
async fn trailing_bom_after_hostname_471_survives_decode_then_is_trimmed() {
    assert_processor("bom-after-host", "a.b\u{feff}", Some("a.b")).await;
}
