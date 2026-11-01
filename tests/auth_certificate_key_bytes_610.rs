//! #610: `auth::certificates::certificate_key_bytes` is the reference's
//! `Certificate.toBinary` on a subject or certifier text (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/certificates/Certificate.ts:240-254`): the 33 bytes
//! it writes for every text it accepts, its words for every text it refuses,
//! against `tests/vectors/certificate_key_bytes_610.json` (46 cases) and the
//! `to_binary` outcomes of `tests/vectors/certificate_to_binary_key_585.json`
//! (16 cases), with no case enumerated apart.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::auth::certificates::certificate_key_bytes;
use bsv_rs::Error;

fn cases(vector: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(vector).unwrap();
    assert_eq!(v["reference"], "ts-stack@edf6e03");
    assert_eq!(v["node"], "v22.18.0");
    v["cases"].as_array().unwrap().clone()
}

/// Every case's outcome here is the reference's, bytes or words.
fn assert_reference_outcomes(cases: &[serde_json::Value]) -> (usize, usize) {
    let (mut written, mut refused) = (0, 0);
    for case in cases {
        let field = case["field"].as_str().unwrap();
        let label = format!("{field} {}", case["name"].as_str().unwrap());
        let read = certificate_key_bytes(case["text"].as_str().unwrap(), field);
        let to_binary = &case["to_binary"];
        if to_binary["ok"].as_bool().unwrap() {
            let bytes = read.unwrap_or_else(|e| panic!("{label}: refused, {e}"));
            assert_eq!(
                hex::encode(bytes),
                to_binary["key"].as_str().unwrap(),
                "{label}"
            );
            written += 1;
        } else {
            let message = to_binary["message"].as_str().unwrap();
            assert_eq!(
                read,
                Err(Error::CertificateValidationError(message.into())),
                "{label}"
            );
            refused += 1;
        }
    }
    (written, refused)
}

#[test]
fn the_key_bytes_are_the_reference_to_binary_bytes_or_its_words_610() {
    let cases = cases(include_str!("vectors/certificate_key_bytes_610.json"));
    assert_eq!(cases.len(), 46);
    // Per field: compressed, the other prefix, upper and mixed case, an x
    // above p and the largest x written; seventeen texts refused.
    assert_eq!(assert_reference_outcomes(&cases), (12, 34));
}

#[test]
fn an_x_above_the_field_prime_is_written_unreduced_as_the_reference_writes_it_610() {
    for case in cases(include_str!("vectors/certificate_key_bytes_610.json")) {
        let name = case["name"].as_str().unwrap();
        if name != "x_above_p" && name != "x_max" {
            continue;
        }
        let text = case["text"].as_str().unwrap();
        let bytes = certificate_key_bytes(text, case["field"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(bytes), text, "{name}");
        // The strict key reading refuses those bytes (#183), as the identity
        // parsers' reader does.
        assert!(bsv_rs::PublicKey::from_bytes(&bytes).is_err(), "{name}");
    }
}

#[test]
fn the_585_vector_to_binary_outcomes_are_the_helpers_with_none_apart_610() {
    let cases = cases(include_str!("vectors/certificate_to_binary_key_585.json"));
    assert_eq!(cases.len(), 16);
    assert_eq!(assert_reference_outcomes(&cases), (6, 10));
}
