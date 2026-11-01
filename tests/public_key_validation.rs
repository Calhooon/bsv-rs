//! #579: the reference's two public-key validators as public helpers, against
//! `vectors/public_key_validation_579.json` (`ts-stack@edf6e03` under Node
//! v22.18.0, `support/public_key_validation_579.mjs`): the wallet's
//! `validatePublicKey` (`validationHelpers.ts:185-191`) as
//! `wallet::validate_public_key`, and the auth identity key's
//! `assertAuthIdentityKey` (`AuthMessageValidation.ts:81-90`) as
//! `auth::assert_auth_identity_key`. Each accepted key equals
//! `PublicKey::from_hex` of the same text; each lenient form #498's reader
//! accepts is refused by both in the reference's words.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::auth::assert_auth_identity_key;
use bsv_rs::primitives::PublicKey;
use bsv_rs::wallet::validate_public_key;
use bsv_rs::{Error, WalletRefusalClass};
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/public_key_validation_579.json");

fn cases() -> Vec<Value> {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(vector["reference"], "ts-stack@edf6e03");
    vector["cases"].as_array().unwrap().clone()
}

fn case(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
}

fn wallet_refusal(message: &str) -> Error {
    Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: message.to_string(),
    }
}

/// The wallet helper's outcome against the recorded one, the parameter named
/// as the recorder named it.
fn assert_wallet(case: &Value) {
    let text = case["text"].as_str().unwrap();
    let recorded = &case["wallet"];
    let outcome = validate_public_key(text, "identityKey");
    if recorded["ok"].as_bool().unwrap() {
        let key = outcome.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(key.to_hex(), recorded["returned"].as_str().unwrap());
        assert_eq!(key, PublicKey::from_hex(text.trim()).unwrap());
    } else {
        assert_eq!(
            outcome.unwrap_err(),
            wallet_refusal(recorded["message"].as_str().unwrap()),
            "{}",
            case["name"]
        );
    }
}

fn assert_auth(case: &Value) {
    let text = case["text"].as_str().unwrap();
    let recorded = &case["auth"];
    let outcome = assert_auth_identity_key(text);
    if recorded["ok"].as_bool().unwrap() {
        let key = outcome.unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(key.to_hex(), text);
        assert_eq!(key, PublicKey::from_hex(text).unwrap());
    } else {
        assert_eq!(
            outcome.unwrap_err(),
            Error::AuthError(recorded["message"].as_str().unwrap().to_string()),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_canonical_compressed_key_is_the_lenient_readers_key_579() {
    for name in ["compressed", "compressed_other_parity"] {
        let case = case(name);
        let text = case["text"].as_str().unwrap();
        let expected = PublicKey::from_hex(text).unwrap();
        assert_eq!(validate_public_key(text, "identityKey").unwrap(), expected);
        assert_eq!(assert_auth_identity_key(text).unwrap(), expected);
    }
}

#[test]
fn every_lenient_form_the_498_reader_accepts_is_refused_in_the_reference_words_579() {
    for name in [
        "odd_length_498",
        "uncompressed_498",
        "hybrid_498",
        "x_above_p_498",
    ] {
        let case = case(name);
        let text = case["text"].as_str().unwrap();
        assert!(PublicKey::from_hex(text).is_ok(), "{name}: #498 reads it");
        assert!(validate_public_key(text, "identityKey").is_err(), "{name}");
        assert!(assert_auth_identity_key(text).is_err(), "{name}");
        assert_wallet(&case);
        assert_auth(&case);
    }
}

#[test]
fn the_auth_identity_key_rule_refuses_the_case_and_space_the_wallet_rule_reads_579() {
    let compressed = case("compressed");
    for name in ["upper_case", "surrounding_space"] {
        let case = case(name);
        let text = case["text"].as_str().unwrap();
        let expected = PublicKey::from_hex(compressed["text"].as_str().unwrap()).unwrap();
        assert_eq!(validate_public_key(text, "identityKey").unwrap(), expected);
        assert_eq!(
            assert_auth_identity_key(text).unwrap_err(),
            Error::AuthError(
                "Authentication identityKey must be a canonical compressed public key.".into()
            )
        );
    }
}

#[test]
fn the_parameter_name_is_the_callers_579() {
    assert_eq!(
        validate_public_key("0234", "counterparty").unwrap_err(),
        wallet_refusal("The counterparty parameter must be at least 66 length.")
    );
}

#[test]
fn every_recorded_case_is_the_references_outcome_579() {
    let cases = cases();
    assert_eq!(cases.len(), 15);
    for case in &cases {
        assert_wallet(case);
        assert_auth(case);
    }
}
