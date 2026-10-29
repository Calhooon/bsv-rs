//! #366: the #354 recorder's actual handshake refusals, Node 22.18.0 at
//! ts-stack@edf6e03. Every exchange uses a wiremock ephemeral port.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::{Error, TransportFault};
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

fn cases() -> Vec<Case> {
    let witness: Witness =
        serde_json::from_str(include_str!("vectors/transport_handshake_refusal_366.json")).unwrap();
    assert_eq!(witness.cases.len(), 16);
    witness.cases
}

async fn exchange(case: &Case) -> (bsv_rs::Result<()>, Vec<AuthMessage>, String) {
    let server = MockServer::start().await;
    let mut response =
        ResponseTemplate::new(case.status).set_body_bytes(from_hex(&case.body_hex).unwrap());
    for (name, value) in &case.headers {
        response = response.insert_header(name.as_str(), value.as_str());
    }
    Mock::given(method("POST"))
        .and(path(format!("/{}/.well-known/auth", case.name)))
        .respond_with(response)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(path("/never-replayed"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let transport = SimplifiedFetchTransport::new(&format!("{}/{}", server.uri(), case.name));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |message| {
        sink.lock().unwrap().push(message);
        Box::pin(async { Ok(()) })
    }));
    let message = AuthMessage::new(
        MessageType::InitialRequest,
        PrivateKey::from_hex(&format!("{:064x}", 7))
            .unwrap()
            .public_key(),
    );
    let result = transport.send(&message).await;
    let messages = std::mem::take(&mut *seen.lock().unwrap());
    server.verify().await;
    (result, messages, server.uri())
}

fn expected_fault(case: &Case) -> Option<TransportFault> {
    match case.status {
        429 | 503 if case.headers.contains_key("retry-after") => {
            Some(TransportFault::RateLimited {
                retry_after_ms: Some(case.headers["retry-after"].parse::<u64>().unwrap() * 1000),
            })
        }
        429 => Some(TransportFault::RateLimited {
            retry_after_ms: None,
        }),
        502..=504 => Some(TransportFault::MayHaveBeenReceived),
        _ => None,
    }
}

async fn assert_refusal(case: &Case) {
    let (result, messages, origin) = exchange(case).await;
    assert!(!case.reached_on_data, "{}", case.name);
    assert!(messages.is_empty(), "{} reached the callback", case.name);
    let error = result.expect_err(&case.name);
    let expected = case.refusal.as_ref().unwrap().replace("{url}", &origin);
    assert_eq!(
        error.transport_fault(),
        expected_fault(case),
        "{}",
        case.name
    );
    match error {
        Error::AuthError(text) => {
            assert!(expected_fault(case).is_none(), "{}", case.name);
            assert_eq!(text, expected, "{}", case.name);
        }
        Error::TransportFault { status, detail, .. } => {
            assert_eq!(status, Some(case.status), "{}", case.name);
            assert_eq!(detail, expected, "{}", case.name);
        }
        other => panic!("{}: unexpected {other:?}", case.name),
    }
}

#[tokio::test]
async fn issue_366_handshake_host_refusals_use_status_url_and_body_preview() {
    let cases: Vec<_> = cases()
        .into_iter()
        .filter(|case| case.status >= 300 && case.status != 307 && expected_fault(case).is_none())
        .collect();
    assert_eq!(cases.len(), 7);
    for case in cases {
        assert_refusal(&case).await;
    }
}

#[tokio::test]
async fn issue_366_handshake_gateway_and_limiter_refusals_keep_transport_fault_classes() {
    let cases: Vec<_> = cases()
        .into_iter()
        .filter(|case| expected_fault(case).is_some())
        .collect();
    assert_eq!(cases.len(), 6);
    for case in cases {
        assert_refusal(&case).await;
    }
}

#[tokio::test]
async fn issue_366_handshake_success_does_not_require_response_authentication_headers() {
    let cases: Vec<_> = cases()
        .into_iter()
        .filter(|case| case.status < 300)
        .collect();
    assert_eq!(cases.len(), 2);
    for case in cases {
        assert!(case.refusal.is_none() && case.reached_on_data);
        let (result, messages, _) = exchange(&case).await;
        result.unwrap();
        assert_eq!(messages.len(), 1, "{}", case.name);
        assert_eq!(messages[0].message_type, MessageType::InitialResponse);
    }
}

#[tokio::test]
async fn issue_366_handshake_redirect_uses_fetch_refusal_without_replaying() {
    let case = cases().into_iter().find(|case| case.status == 307).unwrap();
    assert_refusal(&case).await;
}
