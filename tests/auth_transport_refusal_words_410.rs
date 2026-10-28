//! #410: replay the reference transport's refusal words, recorded under
//! Node 22.18.0 with fake fetch (native fetch + MockAgent for redirects).
//! All HTTP here uses wiremock's ephemeral listeners, never a default URL.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::HttpRequest;
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::{Error, TransportFault};
use serde::Deserialize;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
struct Witness {
    references: Vec<Reference>,
}

#[derive(Deserialize)]
struct Reference {
    reference: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    #[serde(default)]
    general: bool,
    #[serde(default)]
    redirect: bool,
    status: u16,
    headers: BTreeMap<String, String>,
    body_hex: String,
    error: Option<Vec<RecordedError>>,
    reached_on_data: bool,
    requested_certificates_padding: Option<usize>,
    delivered: Option<Delivery>,
}

#[derive(Deserialize)]
struct Delivery {
    message_type: String,
    signature: Vec<u8>,
    requested_certificates: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RecordedError {
    name: String,
    message: String,
}

fn references() -> Vec<Reference> {
    serde_json::from_str::<Witness>(include_str!(
        "vectors/auth_transport_refusal_words_410.json"
    ))
    .unwrap()
    .references
}

fn message(general: bool) -> AuthMessage {
    let mut message = AuthMessage::new(
        MessageType::InitialRequest,
        PrivateKey::from_hex(&format!("{:064x}", 42))
            .unwrap()
            .public_key(),
    );
    if general {
        message.message_type = MessageType::General;
        message.signature = Some(vec![48, 0]);
        message.payload = Some(
            HttpRequest {
                request_id: [7; 32],
                method: "POST".into(),
                path: "/sendMessage".into(),
                search: String::new(),
                headers: vec![],
                body: vec![],
            }
            .to_payload(),
        );
    }
    message
}

async fn exchange(case: &Case) -> (bsv_rs::Result<()>, Vec<AuthMessage>, String) {
    let server = MockServer::start().await;
    let at = if case.general {
        "/sendMessage"
    } else {
        "/.well-known/auth"
    };
    let mut answer =
        ResponseTemplate::new(case.status).set_body_bytes(from_hex(&case.body_hex).unwrap());
    for (name, value) in &case.headers {
        // Fetch's Headers holds ByteStrings: U+00E9 is one Latin-1 byte,
        // not the two bytes of its UTF-8 encoding.
        let bytes: Vec<u8> = value
            .chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap())
            .collect();
        answer = answer.insert_header(
            name.as_str(),
            reqwest::header::HeaderValue::from_bytes(&bytes).unwrap(),
        );
    }
    if let Some(padding) = case.requested_certificates_padding {
        let value = format!(
            "{{\"certifiers\":[],\"types\":{{{}}}}}",
            " ".repeat(padding)
        );
        assert_eq!(value.len(), 262145);
        answer = answer.insert_header("x-bsv-auth-requested-certificates", value);
    }
    if case.redirect {
        answer = answer.insert_header("location", format!("{}/never-replayed", server.uri()));
    }
    Mock::given(method("POST"))
        .and(path(at))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/never-replayed"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let transport = SimplifiedFetchTransport::new(&server.uri());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |message| {
        sink.lock().unwrap().push(message);
        Box::pin(async { Ok(()) })
    }));
    let result = transport.send(&message(case.general)).await;
    let messages = std::mem::take(&mut *seen.lock().unwrap());
    (result, messages, server.uri())
}

async fn replay(case: &Case) -> (Error, String) {
    let (result, messages, origin) = exchange(case).await;
    assert!(messages.is_empty(), "{} reached the callback", case.name);
    (result.expect_err(&case.name), origin)
}

async fn assert_words(case: &Case) {
    let (error, origin) = replay(case).await;
    let expected = case.error.as_ref().unwrap()[0]
        .message
        .replace("{url}", &origin);
    let fault = match case.status {
        429 => Some(TransportFault::RateLimited {
            retry_after_ms: Some(7000),
        }),
        503 => Some(TransportFault::MayHaveBeenReceived),
        _ => None,
    };
    assert_eq!(error.transport_fault(), fault, "{}", case.name);
    match error {
        Error::AuthError(text) | Error::TransportFault { detail: text, .. } => {
            assert_eq!(text, expected, "{}", case.name);
        }
        other => panic!("{}: unexpected error {other:?}", case.name),
    }
    assert!(!case.reached_on_data);
}

#[tokio::test]
async fn issue_410_a_404_handshake_uses_the_reference_status_url_and_header_message() {
    for reference in references() {
        for case in reference
            .cases
            .iter()
            .filter(|case| case.name.starts_with("handshake_404"))
        {
            assert_words(case).await;
        }
    }
}

#[tokio::test]
async fn issue_410_a_non_auth_body_uses_nodes_unwrapped_json_error() {
    for reference in references() {
        assert_words(
            reference
                .cases
                .iter()
                .find(|case| case.name == "body_0")
                .unwrap(),
        )
        .await;
    }
}

#[tokio::test]
async fn issue_410_well_formed_non_auth_json_keeps_the_documented_typed_refusal() {
    for reference in references() {
        let case = reference
            .cases
            .iter()
            .find(|case| case.name == "schema_non_auth")
            .unwrap();
        assert!(case.error.is_none() && case.reached_on_data);
        let (error, _) = replay(case).await;
        assert_eq!(error, Error::AuthError(
            "Failed to parse auth response: missing field `version` at line 1 column 11 - body: {\"ok\":true}".into()
        ));
    }
}

#[tokio::test]
async fn issue_410_a_307_uses_the_fetch_wrapper_without_replaying_the_request() {
    let reference = references().remove(0);
    assert_eq!(reference.reference, "ts-stack@edf6e03");
    for case in reference.cases.iter().filter(|case| case.redirect) {
        let chain = case.error.as_ref().unwrap();
        assert_eq!(
            (&*chain[1].name, &*chain[1].message),
            ("TypeError", "fetch failed")
        );
        assert_eq!(
            (&*chain[2].name, &*chain[2].message),
            ("Error", "unexpected redirect")
        );
        assert_words(case).await;
    }
    let older = references().remove(1);
    assert_eq!(older.reference, "ts-sdk@9e3ede6b");
    for case in older.cases.iter().filter(|case| case.redirect) {
        assert!(
            case.error.is_none() && case.reached_on_data,
            "the older reference follows"
        );
    }
}

#[tokio::test]
async fn issue_410_malformed_headers_use_the_header_wrapper_even_on_a_general_reply() {
    for reference in references() {
        for case in reference
            .cases
            .iter()
            .filter(|case| case.name.starts_with("header_"))
        {
            assert_words(case).await;
        }
    }
}

#[tokio::test]
async fn issue_410_handshake_status_words_preserve_transport_fault_classes() {
    for case in references()
        .remove(0)
        .cases
        .iter()
        .filter(|case| matches!(case.status, 401 | 429 | 503))
    {
        assert_words(case).await;
    }
}

#[tokio::test]
async fn issue_410_replays_every_recorded_json_syntax_error() {
    let mut mismatches = Vec::new();
    for case in references()
        .remove(0)
        .cases
        .iter()
        .filter(|case| case.name.starts_with("body_"))
    {
        let (error, _) = replay(case).await;
        let expected = &case.error.as_ref().unwrap()[0].message;
        if error != Error::AuthError(expected.clone()) {
            mismatches.push(format!(
                "{}: got {error:?}; expected {expected:?}",
                case.name
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

async fn assert_depth_words(depth: usize) {
    for reference in references() {
        let cases: Vec<_> = reference
            .cases
            .iter()
            .filter(|case| case.name.starts_with(&format!("depth_{depth}_")))
            .collect();
        assert_eq!(cases.len(), 4);
        for case in cases {
            assert_words(case).await;
        }
    }
}

#[tokio::test]
async fn issue_410_json_syntax_at_depth_127_uses_the_reference_words() {
    assert_depth_words(127).await;
}

#[tokio::test]
async fn issue_410_json_syntax_at_depth_200_uses_the_reference_words() {
    assert_depth_words(200).await;
}

#[tokio::test]
async fn issue_410_oversized_certificate_header_is_a_documented_divergence() {
    for reference in references() {
        let case = reference
            .cases
            .iter()
            .find(|c| c.name == "mapping_oversized")
            .unwrap();
        if reference.reference == "ts-stack@edf6e03" {
            assert_eq!(case.error.as_ref().unwrap()[0].message,
                "Failed to parse x-bsv-auth-requested-certificates returned by {url}/sendMessage: [oversized]. header exceeds its byte limit");
            assert!(!case.reached_on_data);
        } else {
            assert!(case.error.is_none() && case.reached_on_data);
            assert_eq!(
                case.delivered.as_ref().unwrap().requested_certificates,
                Some(serde_json::json!({"certifiers": [], "types": {}}))
            );
        }
        let (result, messages, _) = exchange(case).await;
        result.unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0]
            .requested_certificates
            .as_ref()
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn issue_410_base64_signature_is_a_documented_divergence() {
    let reference = references().remove(0);
    let case = reference
        .cases
        .iter()
        .find(|c| c.name == "mapping_signature")
        .unwrap();
    assert_eq!(case.error.as_ref().unwrap()[0].message,
        "Failed to parse x-bsv-auth-signature returned by {url}/sendMessage: [invalid]. signature must be bounded even-length hexadecimal");
    assert!(!case.reached_on_data);
    let (result, messages, _) = exchange(case).await;
    result.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].signature, Some(vec![48, 0]));
}

#[tokio::test]
async fn issue_410_certificate_request_type_is_a_documented_divergence() {
    for reference in references() {
        let case = reference
            .cases
            .iter()
            .find(|c| c.name == "mapping_certificate_request")
            .unwrap();
        assert!(case.error.is_none() && case.reached_on_data);
        let delivered = case.delivered.as_ref().unwrap();
        assert_eq!(delivered.message_type, "certificateRequest");
        assert_eq!(delivered.signature, vec![48, 6, 2, 1, 1, 2, 1, 1]);
        let (result, messages, _) = exchange(case).await;
        result.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_type, MessageType::General);
    }
}
