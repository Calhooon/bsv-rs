#![cfg(test)]
//! #498's second fold: the payment's counterparty, the 402's
//! `x-bsv-auth-identity-key` header, is read as the reference's wallet
//! validates it (since #582 through `wallet::validate_public_key`, #579;
//! `validateCounterparty`,
//! `ts-stack@edf6e03` `validationHelpers.ts:185-196`, the header handed over at
//! `AuthFetch.ts:735-738,873-878`). Through `AuthFetch` the header is the
//! authenticated sender's compressed hex (`response.rs`), and a fallback answer
//! carrying any `x-bsv` header is refused (`AuthFetch.ts:693-697`), so the
//! lenient forms reach this site only through `pay_and_retry` directly.

use super::*;
use crate::auth::transports::MockTransport;
use crate::primitives::PrivateKey;
use crate::wallet::ProtoWallet;
use indexmap::IndexMap;

/// The 402 a server answers, its identity key the case's.
fn payment_required(identity_key: &str) -> Response {
    let mut headers = IndexMap::new();
    for (name, value) in [
        ("x-bsv-auth-identity-key", identity_key),
        ("x-bsv-payment-derivation-prefix", "cHJlZml4"),
        ("x-bsv-payment-satoshis-required", "7"),
        ("x-bsv-payment-version", "1.0"),
    ] {
        headers.insert(name.to_owned(), value.to_owned());
    }
    Response {
        status: 402,
        headers,
        body: Vec::new(),
    }
}

#[tokio::test]
async fn a_lenient_payment_identity_key_is_refused_before_the_wallet_498() {
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/public_key_forms_498.json"
    ))
    .unwrap();
    for name in [
        "hybrid_even",
        "odd_length_compressed_even",
        "x_above_p_compressed_even",
    ] {
        let case = recorded["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let input = case["input"].as_str().unwrap();
        assert!(
            PublicKey::from_hex(input).is_ok(),
            "{name}: from_hex reads it"
        );
        // In `validatePublicKey`'s words since #582
        let refusal = crate::wallet::validate_public_key(input, "counterparty").unwrap_err();
        let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(&format!("{:064x}", 41)).unwrap()));
        let fetch = AuthFetch::with_transport_factory(wallet, None, None, |_| MockTransport::new());
        let result = fetch
            .pay_and_retry(
                "https://payment-498.invalid/resource",
                AuthFetchOptions::default(),
                payment_required(input),
                None,
                RetryBudget::new(None),
            )
            .await;
        assert_eq!(result.unwrap_err(), refusal, "{name}");
    }
}

/// #582: the reference's wallet refuses an uncompressed counterparty
/// (`validatePublicKey`, `validationHelpers.ts:185-191`: 66 characters);
/// read strictly (`from_strict_hex`) it reached the wallet until #582. The
/// verdict is the 579 recorder's, its parameter renamed.
#[tokio::test]
async fn an_uncompressed_payment_identity_key_is_refused_before_the_wallet_582() {
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/public_key_validation_579.json"
    ))
    .unwrap();
    let parameter = recorded["wallet_parameter"].as_str().unwrap();
    let case = recorded["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "uncompressed_498")
        .unwrap();
    assert_eq!(case["wallet"]["ok"], false, "the reference refuses it");
    let words = case["wallet"]["message"]
        .as_str()
        .unwrap()
        .replace(&format!("The {parameter} "), "The counterparty ");
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(&format!("{:064x}", 41)).unwrap()));
    let fetch = AuthFetch::with_transport_factory(wallet, None, None, |_| MockTransport::new());
    let result = fetch
        .pay_and_retry(
            "https://payment-582.invalid/resource",
            AuthFetchOptions::default(),
            payment_required(case["text"].as_str().unwrap()),
            None,
            RetryBudget::new(None),
        )
        .await;
    match result {
        Err(crate::Error::WalletRefusal { message, .. }) => assert_eq!(message, words),
        other => panic!("an uncompressed counterparty: {other:?}"),
    }
}
