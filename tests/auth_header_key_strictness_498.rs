//! #498's second fold: `SimplifiedFetchTransport` reads a general answer's
//! `x-bsv-auth-identity-key` header strictly (`from_strict_hex`: the hex
//! decoded, then `PublicKey::from_bytes`), as it did before #498, though
//! `from_hex` reads the reference's lenient key strings: the header is the
//! message's `identityKey` (`ts-stack@edf6e03` `SimplifiedFetchTransport.ts:346`),
//! refused by `assertAuthIdentityKey` (`AuthMessageValidation.ts:344`, `:81-89`:
//! `02`/`03` and 64 lower-case hex digits, the canonical key). The payment's
//! reading of the same header is pinned in
//! `src/auth/clients/payment_key_strictness_498_tests.rs`.
//!
//! The three forms are `tests/vectors/public_key_forms_498.json`'s: a hybrid
//! key, an odd-length key and a compressed x at p+1, each one `from_hex`
//! accepts; each is refused in `assertAuthIdentityKey`'s words since #582
//! (`bsv_rs::auth::assert_auth_identity_key`, #579), where the strict reading
//! also read an upper-case header the reference refuses (the `_582` test).
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.

use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::HttpRequest;
use bsv_rs::auth::{
    assert_auth_identity_key, AuthMessage, MessageType, SimplifiedFetchTransport, Transport,
};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::{Error, Result};
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LENIENT: [&str; 3] = [
    "hybrid_even",
    "odd_length_compressed_even",
    "x_above_p_compressed_even",
];

/// The named case's input, which `from_hex` accepts, and the reference's
/// refusal of it (`assertAuthIdentityKey`, #582).
fn lenient(name: &str) -> (String, Error) {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/public_key_forms_498.json")).unwrap();
    let case = recorded["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("the vector has no case {name}"));
    assert_eq!(
        case["accepted"], true,
        "{name}: the reference's parser reads it"
    );
    let input = case["input"].as_str().unwrap().to_owned();
    assert!(
        PublicKey::from_hex(&input).is_ok(),
        "{name}: from_hex reads it"
    );
    let refusal = assert_auth_identity_key(&input).unwrap_err();
    (input, refusal)
}

/// A general answer with every auth header, its identity key the case's.
async fn general_answer(identity_key: &str) -> (Result<()>, Vec<AuthMessage>) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/resource"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-bsv-auth-version", "0.1")
                .insert_header("x-bsv-auth-identity-key", identity_key)
                .insert_header("x-bsv-auth-signature", "3006020101020101")
                .set_body_string("ok"),
        )
        .mount(&server)
        .await;
    let transport = SimplifiedFetchTransport::new(&server.uri());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |message| {
        sink.lock().unwrap().push(message);
        Box::pin(async { Ok(()) })
    }));
    let mut message = AuthMessage::new(MessageType::General, PrivateKey::random().public_key());
    message.payload = Some(
        HttpRequest {
            request_id: [7; 32],
            method: "POST".into(),
            path: "/resource".into(),
            search: String::new(),
            headers: vec![],
            body: vec![],
        }
        .to_payload(),
    );
    let result = transport.send(&message).await;
    let seen = seen.lock().unwrap().clone();
    (result, seen)
}

#[tokio::test]
async fn a_general_answer_with_a_lenient_identity_key_header_is_refused_498() {
    // The control: the canonical key reaches the callback as the sender.
    let canonical = PrivateKey::from_hex(&format!("{:064x}", 7))
        .unwrap()
        .public_key();
    let (result, seen) = general_answer(&canonical.to_hex()).await;
    result.unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].identity_key, canonical);
    for name in LENIENT {
        let (input, refusal) = lenient(name);
        let (result, seen) = general_answer(&input).await;
        assert_eq!(result.unwrap_err(), refusal, "{name}");
        assert!(seen.is_empty(), "{name}: no message from a lenient sender");
    }
}

/// The reference refuses an upper-case `x-bsv-auth-identity-key`
/// (`AuthMessageValidation.ts:81-90`, applied at `:344` to the header folded
/// into the message, `SimplifiedFetchTransport.ts:346`); read strictly
/// (`from_strict_hex`), it reached the callback as the sender until #582.
#[tokio::test]
async fn a_general_answer_with_an_upper_case_identity_key_header_is_refused_582() {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/public_key_validation_579.json")).unwrap();
    let case = recorded["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "upper_case")
        .unwrap();
    assert_eq!(case["auth"]["ok"], false, "the reference refuses it");
    let words = case["auth"]["message"].as_str().unwrap();
    let (result, seen) = general_answer(case["text"].as_str().unwrap()).await;
    assert_eq!(result.unwrap_err(), Error::AuthError(words.into()));
    assert!(seen.is_empty(), "no message from an upper-case sender");
}
