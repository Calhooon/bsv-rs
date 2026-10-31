#![cfg(test)]
//! #498's second fold: the payment's counterparty, the 402's
//! `x-bsv-auth-identity-key` header, is read strictly (`from_strict_hex`), as
//! the reference's wallet validates it (`validateCounterparty`,
//! `ts-stack@edf6e03` `validationHelpers.ts:185-196`, the header handed over at
//! `AuthFetch.ts:735-738,873-878`). Through `AuthFetch` the header is the
//! authenticated sender's compressed hex (`response.rs`), and a fallback answer
//! carrying any `x-bsv` header is refused (`AuthFetch.ts:693-697`), so the
//! lenient forms reach this site only through `pay_and_retry` directly.

use super::*;
use crate::auth::transports::MockTransport;
use crate::primitives::{from_hex, PrivateKey};
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
        let refusal = from_hex(input)
            .and_then(|bytes| PublicKey::from_bytes(&bytes))
            .unwrap_err();
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
