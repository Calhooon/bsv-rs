//! #543: `decode_and_verify_registry_token`, the reference's
//! `decodeAndVerifyRegistryToken` (`ts-stack@edf6e03`
//! `registryTokenValidation.ts:57-64`), reads the reference's three
//! definition tokens to its fields and refuses this crate's pre-#543 tokens
//! and the ten one-change tokens of each type in the words the reference's
//! threw, and judges the operator's key text as the reference's
//! `verifySignature` judges its counterparty
//! (`tests/vectors/registry_token_fields_543.json`).
#![cfg(feature = "registry")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/registry_token_fields_543.rs"]
mod token_fields;

use bsv_rs::registry::decode_and_verify_registry_token;
use bsv_rs::Error;

#[test]
fn the_reference_tokens_decode_to_the_reference_fields_543() {
    for case in token_fields::cases("tokens") {
        let decoded = decode_and_verify_registry_token(
            token_fields::definition_type(&case),
            &token_fields::script(&case),
        )
        .unwrap();
        let expected: Vec<String> =
            serde_json::from_value(case["verdict"]["fields"].clone()).unwrap();
        assert_eq!(decoded, expected, "{}", case["definition_type"]);
    }
}

#[test]
fn refused_tokens_are_refused_in_the_reference_words_543() {
    let mut cases = token_fields::cases("base_tokens");
    cases.extend(token_fields::cases("refusals"));
    assert_eq!(cases.len(), 33);
    for case in cases {
        let words = case["verdict"]["words"].as_str().unwrap();
        assert_eq!(
            decode_and_verify_registry_token(
                token_fields::definition_type(&case),
                &token_fields::script(&case),
            ),
            Err(Error::RegistryError(words.to_string())),
            "{}",
            case
        );
    }
}

#[test]
fn the_operator_key_and_signature_refusals_are_the_reference_words_through_registry_error_543() {
    let kinds = [
        ("operator_not_hex", "Invalid hex string"),
        ("operator_unknown_format", "Unknown point format"),
        ("operator_not_a_point", "Invalid point"),
        (
            "signature_not_der",
            "The signature parameter must be a canonical DER-encoded ECDSA signature",
        ),
    ];
    let cases = token_fields::cases("refusals");
    for (kind, words) in kinds {
        let mut seen = 0;
        for case in cases.iter().filter(|case| case["kind"] == kind) {
            assert_eq!(case["verdict"]["words"], words, "{}", case["name"]);
            assert_eq!(
                decode_and_verify_registry_token(
                    token_fields::definition_type(case),
                    &token_fields::script(case),
                ),
                Err(Error::RegistryError(words.to_string())),
                "{}",
                case["name"]
            );
            seen += 1;
        }
        assert_eq!(seen, 3, "{kind}");
    }
}

/// The operator's text is the counterparty of the reference's
/// `verifySignature` (`registryTokenValidation.ts:45-51`), checked as
/// `validatePublicKey` checks it (`validationHelpers.ts:185-196`, `:522-534`):
/// each token signed by the operator's wallet over its own text and locked
/// with the key derived for it, so the text is the one difference.
#[test]
fn the_operator_text_is_checked_as_the_reference_counterparty_543() {
    let cases = token_fields::cases("counterparties");
    assert_eq!(cases.len(), 15);
    let mut accepted = 0;
    for case in &cases {
        let decoded = decode_and_verify_registry_token(
            token_fields::definition_type(case),
            &token_fields::script(case),
        );
        if case["verdict"]["ok"] == true {
            let expected: Vec<String> =
                serde_json::from_value(case["verdict"]["fields"].clone()).unwrap();
            assert_eq!(decoded, Ok(expected), "{}", case["name"]);
            accepted += 1;
        } else {
            let words = case["verdict"]["words"].as_str().unwrap();
            assert_eq!(
                decoded,
                Err(Error::RegistryError(words.to_string())),
                "{}",
                case["name"]
            );
        }
    }
    // The upper-case text alone: `validateHexString` lowercases it (`:533`).
    assert_eq!(accepted, 3);
}

/// A `05` prefix on the locking key is refused in `Point.fromDER`'s words
/// (`Point.ts:303-325`), where k256 reads it as a compact point.
#[test]
fn a_05_locking_key_is_refused_in_the_reference_words_543() {
    let cases = token_fields::cases("refusals");
    let cases: Vec<_> = cases
        .iter()
        .filter(|case| case["kind"] == "locking_key_05")
        .collect();
    assert_eq!(cases.len(), 3);
    for case in cases {
        assert_eq!(case["verdict"]["words"], "Unknown point format");
        assert_eq!(
            decode_and_verify_registry_token(
                token_fields::definition_type(case),
                &token_fields::script(case),
            ),
            Err(Error::RegistryError("Unknown point format".into())),
            "{}",
            case["name"]
        );
    }
}

/// The operator's text before the signature and as written: a bad operator
/// beside a non-DER signature is refused in the counterparty's words
/// (`validationHelpers.ts:1797` before `:1799-1802`), and an operator in
/// whitespace in `PublicKey.fromString`'s (`registryTokenValidation.ts:36`),
/// read before `validateHexString`'s trim (`:524`) could apply.
#[test]
fn the_operator_is_judged_before_the_signature_and_untrimmed_543() {
    let cases = token_fields::cases("operator_orders");
    assert_eq!(cases.len(), 12);
    for case in &cases {
        let words = case["verdict"]["words"].as_str().unwrap();
        assert_eq!(
            decode_and_verify_registry_token(
                token_fields::definition_type(case),
                &token_fields::script(case),
            ),
            Err(Error::RegistryError(words.to_string())),
            "{}",
            case["name"]
        );
    }
}
