//! #498: `PublicKey::from_hex` reads the key strings the reference reads.
//!
//! `vectors/public_key_forms_498.json` is `PublicKey.fromString` at
//! `ts-stack@edf6e03` under Node 22, written by
//! `support/public_key_forms_498.mjs`. The keeper's word (2026-10-30 05:1xZ):
//! accept as the reference does, the question upstream; strictness returns on
//! the upstream's answer, and `PublicKey::from_bytes` is the strict reading.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{from_hex, PublicKey};
use bsv_rs::Error;
use serde_json::Value;

fn cases() -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/public_key_forms_498.json")).unwrap();
    assert_eq!(recorded["node"], "v22.18.0");
    recorded["cases"].as_array().unwrap().clone()
}

fn named(prefix: &str) -> Vec<Value> {
    let selected: Vec<_> = cases()
        .into_iter()
        .filter(|case| case["name"].as_str().unwrap().starts_with(prefix))
        .collect();
    assert!(!selected.is_empty(), "no case named {prefix}*");
    selected
}

/// The reference accepted the case: so does `from_hex`, to the same point,
/// written back in the strict forms.
fn assert_accepted(case: &Value) {
    let name = case["name"].as_str().unwrap();
    assert_eq!(case["accepted"], true, "{name}: the reference accepts it");
    let key = PublicKey::from_hex(case["input"].as_str().unwrap())
        .unwrap_or_else(|error| panic!("{name}: refused here: {error}"));
    assert_eq!(key.to_hex(), case["point"]["compressed"], "{name}");
    assert_eq!(
        key.to_hex_uncompressed(),
        case["point"]["uncompressed"],
        "{name}"
    );
    // The round trip of a lenient form is the strict form.
    assert_eq!(PublicKey::from_hex(&key.to_hex()).unwrap(), key, "{name}");
    assert_eq!(
        PublicKey::from_bytes(&key.to_compressed()).unwrap(),
        key,
        "{name}"
    );
}

/// The reference refused the case: so does `from_hex`, in this crate's class.
fn assert_refused(case: &Value) {
    let name = case["name"].as_str().unwrap();
    assert_eq!(case["accepted"], false, "{name}: the reference refuses it");
    let error = PublicKey::from_hex(case["input"].as_str().unwrap()).unwrap_err();
    match case["error"].as_str().unwrap() {
        "Invalid hex string" => assert!(matches!(error, Error::InvalidHex(_)), "{name}: {error}"),
        "Unknown point format" | "Point string value is wrong length" | "Invalid point" => {
            assert!(
                matches!(error, Error::InvalidPublicKey(_)),
                "{name}: {error}"
            )
        }
        other => panic!("{name}: unrecorded reference words {other}"),
    }
}

#[test]
fn every_recorded_verdict_is_the_reference_498() {
    let cases = cases();
    assert_eq!(cases.len(), 39);
    let accepted = cases.iter().filter(|case| case["accepted"] == true).count();
    assert_eq!(accepted, 19, "19 accepted, 20 refused");
    for case in &cases {
        if case["accepted"] == true {
            assert_accepted(case);
        } else {
            assert_refused(case);
        }
    }
}

#[test]
fn an_odd_length_key_is_read_with_a_leading_zero_498() {
    // RED before #498: `Odd number of digits`. Strictness returns on the
    // upstream's answer.
    for case in named("odd_length_") {
        if case["accepted"] == true {
            assert_accepted(&case);
        } else {
            assert_refused(&case);
        }
    }
}

#[test]
fn a_hybrid_key_is_read_when_its_prefix_names_y_parity_498() {
    // RED before #498: `elliptic curve point encoding error`. Strictness
    // returns on the upstream's answer.
    for case in named("hybrid_") {
        if case["accepted"] == true {
            assert_accepted(&case);
        } else {
            assert_eq!(case["error"], "Point string value is wrong length");
            assert_refused(&case);
        }
    }
}

#[test]
fn a_coordinate_at_or_above_p_is_reduced_498() {
    // RED before #498: `Point not on curve` (compressed) and k256's encoding
    // error (uncompressed, hybrid). Strictness returns on the upstream's answer.
    for prefix in ["x_above_p_", "x_equal_p_", "y_above_p_"] {
        for case in named(prefix) {
            if case["accepted"] == true {
                assert_accepted(&case);
            } else {
                assert_refused(&case);
            }
        }
    }
}

#[test]
fn the_reference_writes_an_unreduced_coordinate_back_498() {
    // The reference keeps an uncompressed or hybrid coordinate as written and
    // its `toString` writes it so, the compressed prefix taken from y's
    // unreduced parity; this crate holds the reduced point and writes it. Five
    // cases, recorded as the reference's own outputs.
    let differing: Vec<_> = cases()
        .into_iter()
        .filter(|case| {
            case["accepted"] == true && case["reference_compressed"] != case["point"]["compressed"]
        })
        .map(|case| case["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        differing,
        [
            "x_above_p_uncompressed",
            "x_above_p_hybrid_even",
            "x_above_p_hybrid_odd",
            "y_above_p_uncompressed",
            "y_above_p_hybrid_even",
        ]
    );
}

#[test]
fn the_strict_reader_still_refuses_the_lenient_forms_498() {
    // `from_bytes` keeps the strict reading (the BRC-100 PubKeyHex and SEC 1
    // forms), so the strictness can return to `from_hex` on the upstream's answer.
    for case in cases() {
        let input = case["input"].as_str().unwrap();
        if case["accepted"] != true || input.len() % 2 == 1 {
            continue;
        }
        let bytes = from_hex(input).unwrap();
        let strict = PublicKey::from_bytes(&bytes);
        let canonical = matches!(bytes[0], 2..=4) && strict.is_ok();
        let expected = !case["name"].as_str().unwrap().starts_with("hybrid")
            && !case["name"].as_str().unwrap().contains("above_p");
        assert_eq!(canonical, expected, "{}", case["name"]);
    }
}
