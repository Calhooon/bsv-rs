//! `SimplifiedFetchTransport` refuses a general answer without valid BSV
//! authentication (#354): an answer missing any of `x-bsv-auth-version`,
//! `x-bsv-auth-identity-key`, `x-bsv-auth-signature` (absent, or blank) is
//! `Error::AuthError` in the reference's words, the missing headers named in
//! its order, before the body becomes a message (`ts-stack@edf6e03`
//! `SimplifiedFetchTransport.ts:220-232`, `:464-494`, the preview `:512-579`).
//! Through 0.9.0-beta.1 such an answer reached the callback as a message whose
//! sender was the client's own identity key. The named host answered, so it is
//! never a `TransportFault`.
//!
//! The witness is `tests/vectors/transport_unsigned_response_354.json`,
//! recorded by `tests/support/transport_unsigned_response_354.mjs` under Node
//! v22.18.0 against a local `node:http` server; each case here is served by
//! its own wiremock server, `{url}` its origin.
//!
//! Run with: `cargo test --features "auth,http" --test transport_unsigned_response_354`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "auth", feature = "http"))]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::{HttpRequest, HttpResponse};
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_hex, PrivateKey, PublicKey};
use bsv_rs::Error;
use serde::Deserialize;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
struct Witness {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    status: u16,
    headers: BTreeMap<String, String>,
    body_hex: String,
    refusal: Option<String>,
    reached_on_data: bool,
}

fn witness() -> Vec<Case> {
    let data = std::fs::read_to_string("tests/vectors/transport_unsigned_response_354.json")
        .expect("read the #354 witness");
    serde_json::from_str::<Witness>(&data)
        .expect("parse the #354 witness")
        .cases
}

fn case(name: &str) -> Case {
    witness()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("the witness has no case {name}"))
}

/// The recorder's message: POST `/{name}` with a JSON body.
fn general(name: &str) -> AuthMessage {
    let mut message = AuthMessage::new(MessageType::General, PrivateKey::random().public_key());
    let request = HttpRequest {
        request_id: [7; 32],
        method: "POST".into(),
        path: format!("/{name}"),
        search: String::new(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: b"{}".to_vec(),
    };
    message.payload = Some(request.to_payload());
    message
}

/// Serves the case on its own wiremock server and sends the recorder's
/// message through the transport: the send's result, the messages the
/// callback saw, and the server's origin.
async fn sent(case: &Case) -> (bsv_rs::Result<()>, Vec<AuthMessage>, String) {
    let server = MockServer::start().await;
    let mut answer =
        ResponseTemplate::new(case.status).set_body_bytes(from_hex(&case.body_hex).unwrap());
    for (name, value) in &case.headers {
        answer = answer.insert_header(name.as_str(), value.as_str());
    }
    Mock::given(method("POST"))
        .and(path(format!("/{}", case.name)))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    let transport = SimplifiedFetchTransport::new(&server.uri());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |message| {
        sink.lock().unwrap().push(message);
        Box::pin(async { Ok(()) })
    }));
    let result = transport.send(&general(&case.name)).await;
    let seen = seen.lock().unwrap().clone();
    (result, seen, server.uri())
}

/// The case refused in the recorded words, its origin this server's, and
/// nothing handed to the callback.
async fn assert_refused_as_recorded(case: &Case) -> Error {
    let recorded = case.refusal.as_deref().expect("a refused case");
    let (result, seen, origin) = sent(case).await;
    let err = result.expect_err(&case.name);
    assert_eq!(
        err,
        Error::AuthError(recorded.replace("{url}", &origin)),
        "{}",
        case.name
    );
    assert!(
        seen.is_empty(),
        "{}: no message from an unsigned answer",
        case.name
    );
    err
}

#[tokio::test]
async fn a_200_with_a_body_and_no_auth_headers_is_refused_in_the_references_words() {
    let case = case("no_auth_headers_json");
    let (result, seen, origin) = sent(&case).await;
    assert_eq!(
        result.unwrap_err(),
        Error::AuthError(format!(
            "Received HTTP 200 OK from {origin}/no_auth_headers_json without valid BSV \
             authentication (missing headers: x-bsv-auth-version, x-bsv-auth-identity-key, \
             x-bsv-auth-signature) - body preview: {{\"ok\":true}}"
        ))
    );
    assert!(seen.is_empty(), "the client's own key is never the sender");
    assert_refused_as_recorded(&case).await;
}

#[tokio::test]
async fn a_200_with_two_of_the_three_headers_is_refused_naming_the_missing_one() {
    for (name, missing) in [
        ("signature_missing", "x-bsv-auth-signature"),
        ("identity_key_missing", "x-bsv-auth-identity-key"),
        ("version_blank", "x-bsv-auth-version"),
    ] {
        let case = case(name);
        let err = assert_refused_as_recorded(&case).await;
        assert!(
            err.to_string()
                .contains(&format!("(missing headers: {missing})")),
            "{name}: {err}"
        );
    }
}

#[tokio::test]
async fn every_unsigned_case_the_reference_refused_is_refused_in_its_words() {
    let cases = witness();
    assert_eq!(cases.len(), 14, "the witness's census");
    let mut refused = 0;
    for case in cases.iter().filter(|c| c.refusal.is_some()) {
        assert!(!case.reached_on_data, "{}", case.name);
        assert_refused_as_recorded(case).await;
        refused += 1;
    }
    assert_eq!(refused, 13);
}

#[tokio::test]
async fn the_refusal_is_the_named_hosts_answer_not_a_transport_fault() {
    for name in ["no_auth_headers_json", "unavailable_no_content_type"] {
        let err = assert_refused_as_recorded(&case(name)).await;
        assert!(matches!(err, Error::AuthError(_)), "{name}: {err:?}");
        assert_eq!(err.transport_fault(), None, "{name}");
    }
}

#[tokio::test]
async fn a_response_with_the_three_headers_is_read_as_before() {
    let case = case("all_three_present");
    assert_eq!(case.refusal, None);
    assert!(case.reached_on_data);
    let (result, seen, _) = sent(&case).await;
    result.expect("a signed answer is read");
    assert_eq!(seen.len(), 1);
    let message = &seen[0];
    assert_eq!(message.message_type, MessageType::General);
    assert_eq!(
        message.identity_key,
        PublicKey::from_hex(&case.headers["x-bsv-auth-identity-key"]).unwrap()
    );
    assert_eq!(
        message.signature.as_deref(),
        Some(
            from_hex(&case.headers["x-bsv-auth-signature"])
                .unwrap()
                .as_slice()
        )
    );
    let response = HttpResponse::from_payload(message.payload.as_deref().unwrap()).unwrap();
    assert_eq!(response.request_id, [7; 32]);
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"signed");
}
