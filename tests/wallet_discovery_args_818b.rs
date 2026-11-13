//! #818b (#905): the two discovery calls' argument validators,
//! `wallet::validate_discover_by_identity_key_args` and
//! `wallet::validate_discover_by_attributes_args`, are the reference's
//! `validateDiscoverByIdentityKeyArgs` and `validateDiscoverByAttributesArgs`
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:1535-1587`),
//! which its `WalletClient` and the toolbox wallet run before any lookup
//! (`WalletClient.ts:509`, `:524`; `wallet-toolbox/src/Wallet.ts:971`,
//! `:1029`). Against `vectors/identity_door_args_818b.json`'s `validator`
//! column (`support/identity_door_args_818b.mjs`, Node v22.18.0): every
//! refused cell refused as `WalletRefusal` of class `InvalidParameter`
//! (`WERR_INVALID_PARAMETER`, code 6) in the recorded words, every accepted
//! one accepted, the key the validated text names. Compile-RED on `5a87392e`
//! (neither validator exists).
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::wallet::{
    validate_discover_by_attributes_args, validate_discover_by_identity_key_args,
    DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs,
};
use bsv_rs::{Error, Result};
use indexmap::IndexMap;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_door_args_818b.json")).unwrap()
}

fn cases(prefix: &str) -> Vec<Value> {
    vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"].as_str().unwrap().starts_with(prefix))
        .cloned()
        .collect()
}

/// A case's attribute map in insertion order: its pairs, or for a map
/// recorded by its count, `f<i>` = `v` for each `i`.
fn attributes_of(case: &Value) -> IndexMap<String, String> {
    match &case["attributes"] {
        Value::Array(pairs) => pairs
            .iter()
            .map(|p| (p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()))
            .collect(),
        recorded => {
            assert_eq!(recorded["pattern"], "f<i>=v");
            assert!(recorded["extra"].is_null());
            (0..recorded["count"].as_u64().unwrap())
                .map(|i| (format!("f{i}"), "v".to_string()))
                .collect()
        }
    }
}

fn key_args(subject: &str, limit: Option<u32>) -> DiscoverByIdentityKeyArgs {
    DiscoverByIdentityKeyArgs {
        identity_key: subject.to_string(),
        limit,
        offset: None,
        seek_permission: None,
    }
}

fn attribute_args(
    attributes: IndexMap<String, String>,
    limit: Option<u32>,
) -> DiscoverByAttributesArgs {
    DiscoverByAttributesArgs {
        attributes,
        limit,
        offset: None,
        seek_permission: None,
    }
}

/// `got` against the recorded `outcome`: a refusal its class, code and
/// words; an acceptance `accepted(value)`.
fn agrees<T>(got: Result<T>, outcome: &Value, accepted: impl Fn(&T, &Value) -> bool) -> bool {
    match (got, outcome.get("refused")) {
        (Err(Error::WalletRefusal { class, message }), Some(refused)) => {
            refused["name"] == class.name()
                && refused["code"].as_u64() == class.code().map(u64::from)
                && refused["message"] == message.as_str()
        }
        (Ok(value), None) => accepted(&value, &outcome["accepted"]),
        _ => false,
    }
}

#[test]
fn an_identity_key_the_reference_validator_refuses_is_refused_in_its_words_818b() {
    let cases = cases("key_");
    assert_eq!(cases.len(), 17);
    let mut differ = Vec::new();
    for case in &cases {
        let got = validate_discover_by_identity_key_args(&key_args(
            case["subject"].as_str().unwrap(),
            None,
        ));
        let shown = format!("{got:?}");
        if !agrees(got, &case["validator"], |key, accepted| {
            key.to_hex() == *accepted
        }) {
            differ.push(format!("{}: {shown}; {}", case["name"], case["validator"]));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

#[test]
fn an_attribute_map_the_reference_validator_refuses_is_refused_in_its_words_818b() {
    let mut cases = Vec::new();
    for prefix in ["attributes_", "name_", "value_", "unsafe_", "two_faults_"] {
        cases.extend(self::cases(prefix));
    }
    assert_eq!(cases.len(), 5 + 7 + 6 + 4 + 3);
    let mut differ = Vec::new();
    for case in &cases {
        let got = validate_discover_by_attributes_args(&attribute_args(attributes_of(case), None));
        let shown = format!("{got:?}");
        if !agrees(got, &case["validator"], |_, accepted| *accepted == true) {
            differ.push(format!("{}: {shown}; {}", case["name"], case["validator"]));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// Of two faults the reference names the one `Object.keys` walks earlier: an
/// array-index name ahead of the names inserted before it.
#[test]
fn of_two_faults_the_one_object_keys_walks_first_is_named_818b() {
    for name in [
        "two_faults_index_value_then_name",
        "two_faults_index_value_long_then_value",
    ] {
        let case = cases(name).pop().unwrap();
        let message = case["validator"]["refused"]["message"].as_str().unwrap();
        assert!(message.starts_with("The attributes."), "{name}: {message}");
        let got = validate_discover_by_attributes_args(&attribute_args(attributes_of(&case), None));
        assert_eq!(got.unwrap_err().to_string(), message, "{name}");
    }
}

#[test]
fn a_limit_outside_1_to_10000_is_refused_by_both_validators_818b() {
    let cases = cases("limit_");
    assert_eq!(cases.len(), 4);
    for case in &cases {
        let limit = Some(u32::try_from(case["limit"].as_u64().unwrap()).unwrap());
        let by_key = validate_discover_by_identity_key_args(&key_args(
            case["subject"].as_str().unwrap(),
            limit,
        ));
        assert!(
            agrees(by_key, &case["validator"], |_, _| true),
            "{}: {}",
            case["name"],
            case["validator"]
        );
        let email = IndexMap::from([("email".to_string(), "bob".to_string())]);
        let by_attributes = validate_discover_by_attributes_args(&attribute_args(email, limit));
        assert!(
            agrees(by_attributes, &case["validator_attributes"], |_, _| true),
            "{}: {}",
            case["name"],
            case["validator_attributes"]
        );
    }
}

/// `Wallet.ts:1012` compares the subject with the key the validator returns,
/// trimmed and lower-cased: the recorded key is the one this validator names.
#[test]
fn the_validated_key_of_a_padded_or_upper_case_text_is_the_subjects_818b() {
    let vector = vector();
    let subjects = vector["subjects"].as_array().unwrap();
    assert_eq!(subjects.len(), 2);
    for cell in subjects {
        let key = validate_discover_by_identity_key_args(&key_args(
            cell["subject"].as_str().unwrap(),
            None,
        ))
        .unwrap();
        assert_eq!(key.to_hex(), cell["validated"].as_str().unwrap());
        assert_eq!(cell["validated"], cell["certificate_subject"]);
        assert_eq!(cell["kept"], 1);
    }
}

/// Every recorded case is judged by one of the tests above.
#[test]
fn every_recorded_case_is_judged_818b() {
    assert_eq!(vector()["cases"].as_array().unwrap().len(), 17 + 25 + 4);
}
