//! #338: the wire validates and normalizes its originator before dispatch or
//! transmission. Reference frames and words are recorded from ts-stack@edf6e03
//! under Node 22 by support/wire_linkage_calls_406.mjs and its originator helper.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{
    WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver, WireWriter,
};
use bsv_rs::{Error, WalletRefusalClass};
use fixtures::wallet::Stub;
use serde_json::{json, Value};
use std::sync::Mutex;

fn case(side: &str, name: &str) -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/originator_338.json")).unwrap();
    let cases = vector[side].as_array().unwrap();
    assert_eq!(cases.len(), 9, "{side}: recorded case census");
    cases
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
        .clone()
}

fn wallet() -> Stub {
    Stub::new(json!({"version": "v-1.0.0"}))
}

async fn assert_processor(case: Value) {
    let wallet = wallet();
    let expected = hex::decode(case["request_hex"].as_str().unwrap()).unwrap();
    let mut request = WireWriter::new();
    request
        .write_u8(WalletCall::GetVersion.as_u8())
        .write_u8(expected[1]);
    if expected.len() > 2 {
        request.write_bytes(case["originator"].as_str().unwrap().as_bytes());
    }
    assert_eq!(request.as_bytes(), expected);
    let response = WalletWireProcessor::new(wallet.clone())
        .process_message(request.as_bytes())
        .await
        .unwrap();
    assert_eq!(
        hex::encode(response),
        case["response_hex"],
        "{}",
        case["name"]
    );
    let observed = wallet.observed.lock().unwrap();
    let origins = match observed.as_ref() {
        Some(call) => json!([call["originator"]]),
        None => json!([]),
    };
    // #329 deliberately reads the reference's empty string as None.
    let expected = if case["observed"] == json!([""]) {
        json!([null])
    } else {
        case["observed"].clone()
    };
    assert_eq!(origins, expected, "{}: wallet originator", case["name"]);
}

struct RecordingWire {
    processor: WalletWireProcessor<Stub>,
    frames: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl WalletWire for RecordingWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> bsv_rs::Result<Vec<u8>> {
        self.frames.lock().unwrap().push(hex::encode(message));
        self.processor.process_message(message).await
    }
}

async fn assert_transceiver(case: Value, originator: Option<&str>) {
    let wallet = wallet();
    let client = WalletWireTransceiver::new(RecordingWire {
        processor: WalletWireProcessor::new(wallet.clone()),
        frames: Mutex::default(),
    });
    let result = client.get_version(originator).await;
    // Check the transport before the error: a wrapped length must never leave.
    assert_eq!(
        json!(*client.wire().frames.lock().unwrap()),
        case["frames"],
        "{}: frames written",
        case["name"]
    );
    if case["thrown"].is_null() {
        assert_eq!(result, Ok("v-1.0.0".into()));
    } else {
        assert_eq!(case["thrown"]["code"], 6);
        assert_eq!(case["thrown"]["name"], "WERR_INVALID_PARAMETER");
        assert_eq!(
            result,
            Err(Error::WalletRefusal {
                class: WalletRefusalClass::InvalidParameter,
                message: case["thrown"]["message"].as_str().unwrap().into(),
            })
        );
    }
    let observed = wallet.observed.lock().unwrap();
    let origins = match observed.as_ref() {
        Some(call) => json!([call["originator"]]),
        None => json!([]),
    };
    let expected = if case["observed"] == json!([""]) {
        json!([null])
    } else {
        case["observed"].clone()
    };
    assert_eq!(origins, expected, "{}: wallet originator", case["name"]);
}

#[tokio::test]
async fn processor_refuses_251_bytes_in_reference_words() {
    for name in ["length-251", "length-255", "multibyte-length-251"] {
        let case = case("processor", name);
        assert_eq!(case["code"], 1);
        assert_processor(case).await;
    }
}

#[tokio::test]
async fn processor_checks_length_before_reading_originator_bytes() {
    assert_processor(case("processor", "length-251-truncated")).await;
}

#[tokio::test]
async fn processor_accepts_250_bytes_and_normalizes_before_wallet_call() {
    let boundary = case("processor", "length-250-with-port");
    assert_eq!(boundary["originator"].as_str().unwrap().len(), 250);
    assert_processor(boundary).await;
    assert_processor(case("processor", "padded-host-with-port")).await;
}

#[tokio::test]
async fn processor_rejects_invalid_originator_with_reference_class() {
    for name in ["invalid-host", "blank"] {
        let case = case("processor", name);
        assert_eq!(case["code"], 6);
        assert_processor(case).await;
    }
}

#[tokio::test]
async fn transceiver_refuses_256_bytes_before_writing_any_frame() {
    for name in [
        "length-256",
        "length-251",
        "length-255",
        "multibyte-length-251",
    ] {
        let case = case("transceiver", name);
        let originator = case["originator"].as_str().unwrap().to_string();
        assert_transceiver(case, Some(&originator)).await;
    }
}

#[tokio::test]
async fn transceiver_validates_named_originators_before_writing_any_frame() {
    for name in ["invalid-host", "blank"] {
        let case = case("transceiver", name);
        let originator = case["originator"].as_str().unwrap().to_string();
        assert_transceiver(case, Some(&originator)).await;
    }
}

#[tokio::test]
async fn transceiver_writes_normalized_originator_with_checked_length() {
    for name in ["length-250-with-port", "padded-host-with-port"] {
        let case = case("transceiver", name);
        let originator = case["originator"].as_str().unwrap().to_string();
        assert_transceiver(case, Some(&originator)).await;
    }
}

#[tokio::test]
async fn empty_originators_remain_absent_on_wire() {
    assert_processor(case("processor", "empty")).await;
    for originator in [None, Some("")] {
        assert_transceiver(case("transceiver", "empty"), originator).await;
    }
}
