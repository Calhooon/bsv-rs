//! #420's five ProtoWallet validators and encoded-counterparty intake.
//! Recorded by support/wallet_proto_args_415.mjs --remaining under Node 22.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/wallet_proto_args_420.rs"]
mod replay;

use bsv_rs::{Error, WalletRefusalClass};
use serde_json::Value;

fn cases() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/wallet_proto_args_420.json")).unwrap();
    let all = fixture["cases"].as_array().unwrap();
    let typed = all
        .iter()
        .filter(|c| c.get("unrepresentable").is_some())
        .count();
    let replayable: Vec<_> = all
        .iter()
        .filter(|c| c.get("unrepresentable").is_none())
        .cloned()
        .collect();
    assert_eq!(
        (replayable.len(), typed),
        (148, 109),
        "recorded case split changed"
    );
    replayable
}

fn assert_case(case: &Value) {
    let result = replay::invoke(case);
    if case["expected"]["code"] == 6 {
        let error = Error::WalletRefusal {
            class: WalletRefusalClass::InvalidParameter,
            message: case["expected"]["error"].as_str().unwrap().into(),
        };
        assert_eq!(result, Err(error), "{} / {}", case["method"], case["name"]);
    } else if case["expected"].get("error").is_some() {
        // Empty or wrong-key ciphertext passes validation and fails in the cipher.
        assert!(result.is_err(), "{}", case["name"]);
        assert!(!matches!(result, Err(Error::WalletRefusal { .. })));
    } else {
        assert_eq!(
            result.unwrap(),
            case["expected"]["observed"],
            "{} / {}",
            case["method"],
            case["name"]
        );
    }
}

fn assert_refusal(words: &str) {
    let selected: Vec<_> = cases()
        .into_iter()
        .filter(|c| c["expected"]["error"] == words)
        .collect();
    assert!(!selected.is_empty(), "missing recorded refusal {words}");
    for case in selected {
        assert_case(&case);
    }
}

macro_rules! refusal {
    ($test:ident, $words:literal) => {
        #[test]
        fn $test() {
            assert_refusal($words);
        }
    };
}

refusal!(
    short_protocol_before_crypto_and_on_identity,
    "The protocolID[1] parameter must be at least 5 length."
);
refusal!(
    long_protocol_counts_raw_utf8_before_crypto_and_on_identity,
    "The protocolID[1] parameter must be no more than 400 length."
);
refusal!(
    empty_key_before_crypto_and_on_identity,
    "The keyID parameter must be at least 1 length."
);
refusal!(
    long_key_counts_utf8_before_crypto_and_on_identity,
    "The keyID parameter must be no more than 800 length."
);
refusal!(
    short_reason_even_without_privilege_including_both_linkage_adapters,
    "The privilegedReason parameter must be at least 5 length."
);
refusal!(
    long_reason_counts_utf8_including_both_linkage_adapters,
    "The privilegedReason parameter must be no more than 50 length."
);
refusal!(
    privilege_requires_reason_including_identity_and_both_linkage_adapters,
    "The privilegedReason parameter must be a value when 'privileged' is true"
);
refusal!(
    get_public_key_missing_protocol_uses_reference_words,
    "The protocolID parameter must be a [securityLevel, protocolName] tuple"
);
refusal!(
    get_public_key_missing_key_uses_reference_words,
    "The keyID parameter must be a string"
);
refusal!(
    oversized_plaintext_is_refused_before_encryption,
    "The plaintext parameter must be at most 268435456 bytes"
);
refusal!(
    oversized_ciphertext_is_refused_before_decryption,
    "The ciphertext parameter must be at most 268435456 bytes"
);
refusal!(
    counterparty_odd_hex_before_parsing_uses_reference_words,
    "The counterparty parameter must be even length, not 1."
);
refusal!(
    counterparty_non_hex_before_parsing_uses_reference_words,
    "The counterparty parameter must be hexadecimal string."
);
refusal!(
    counterparty_short_hex_before_parsing_uses_reference_words,
    "The counterparty parameter must be at least 66 length."
);
#[test]
fn uncompressed_encoded_counterparty_is_refused_before_parsing() {
    let witnesses: Vec<_> = cases()
        .into_iter()
        .filter(|case| case["name"].as_str().unwrap().contains("uncompressed"))
        .collect();
    assert_eq!(witnesses.len(), 9, "encoded-counterparty sites changed");
    for case in witnesses {
        assert_case(&case);
    }
    assert_refusal("The counterparty parameter must be no more than 66 length.");
}
refusal!(
    counterparty_off_curve_and_wrong_prefix_use_reference_words,
    "The counterparty parameter must be a valid compressed secp256k1 public key"
);

#[test]
fn multiple_invalid_fields_follow_the_reference_order() {
    for case in cases()
        .iter()
        .filter(|c| c["name"].as_str().unwrap().starts_with("order_"))
    {
        assert_case(case);
    }
}

#[test]
fn valid_boundaries_and_reference_ciphertexts_replay() {
    for case in cases().iter().filter(|c| c["expected"]["code"] != 6) {
        assert_case(case);
    }
}

#[test]
fn inherent_linkage_entry_points_share_the_same_validation_and_allow_internal_430_byte_protocols() {
    for case in cases()
        .iter()
        .filter(|c| c["method"].as_str().unwrap().starts_with("reveal"))
    {
        let mut case = case.clone();
        // The inherent structs have no privilege fields. Exercise every other
        // representable case, including the 400-byte public protocol boundary.
        if case["args"].get("privileged").is_some()
            || case["args"].get("privilegedReason").is_some()
        {
            continue;
        }
        case["inherent"] = true.into();
        assert_case(&case);
    }
}
