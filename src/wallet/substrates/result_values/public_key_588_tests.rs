//! #588: the HTTP JSON result validator's key check (`scalars::key`) against the
//! recorder's `result` outcomes (`tests/vectors/public_key_validation_579.json`,
//! `validateWalletResult('getPublicKey', ..)` at `ts-stack@edf6e03`), through the
//! getPublicKey dispatch and under another call's field name.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{bytes, scalars, validate_with_bytes};
use crate::Error;
use serde_json::{value::RawValue, Value};

fn cases() -> Vec<Value> {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../tests/vectors/public_key_validation_579.json"
    ))
    .unwrap();
    vector["cases"].as_array().unwrap().clone()
}

#[test]
fn the_result_key_check_is_the_result_validators_outcome_588() {
    let cases = cases();
    assert_eq!(cases.len(), 15);
    for case in &cases {
        let text = case["text"].as_str().unwrap();
        let recorded = &case["result"];
        let body = serde_json::json!({ "publicKey": text }).to_string();
        let through_dispatch = validate_with_bytes(
            "getPublicKey",
            body.as_bytes(),
            &Value::Null,
            "test",
            &bytes::Fields::default(),
        )
        .map(|_| ());
        let raw = RawValue::from_string(serde_json::to_string(text).unwrap()).unwrap();
        let verifier = scalars::key(Some(&raw), "listCertificates", "certificates[0].verifier");
        if recorded["ok"].as_bool().unwrap() {
            assert_eq!(through_dispatch, Ok(()), "{}", case["name"]);
            assert_eq!(verifier.unwrap(), text, "{}", case["name"]);
        } else {
            let message = recorded["message"].as_str().unwrap();
            assert_eq!(
                through_dispatch,
                Err(Error::WalletError(message.to_string())),
                "{}",
                case["name"]
            );
            let renamed = message.replace(
                "getPublicKey result publicKey",
                "listCertificates result certificates[0].verifier",
            );
            assert_eq!(
                verifier,
                Err(Error::WalletError(renamed)),
                "{}",
                case["name"]
            );
        }
    }
}
