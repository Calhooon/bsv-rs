//! `SimplifiedFetchTransport` refuses a general answer without valid BSV
//! authentication (#354): an answer missing any of `x-bsv-auth-version`,
//! `x-bsv-auth-identity-key`, `x-bsv-auth-signature` (absent, or blank) is
//! `Error::AuthError` in the reference's words, the missing headers named in
//! its order, before the body becomes a message (`ts-stack@edf6e03`
//! `SimplifiedFetchTransport.ts:220-232`, `:464-494`, the preview `:512-579`).
//! Through 0.9.0-beta.1 such an answer reached the callback as a message whose
//! sender was the client's own identity key. An unsigned 429, 502, 503 or 504
//! is a gateway's or a limiter's, a `TransportFault` of #87's class with the
//! refusal's words its detail; any other status is the named host's answer,
//! `AuthError`. The reason phrase is the status line's own (fetch's
//! `statusText`), the canonical one when the line carries that one.
//!
//! The witness is `tests/vectors/transport_unsigned_response_354.json`,
//! recorded by `tests/support/transport_unsigned_response_354.mjs` under Node
//! v22.18.0 against a local `node:http` server; each case here is served by
//! its own server, `{url}` its origin: wiremock, or, for a case with its own
//! reason phrase (wiremock writes the canonical one), a loopback listener
//! that writes the status line as recorded.
//!
//! Run with: `cargo test --features "auth,http" --test transport_unsigned_response_354`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "auth", feature = "http"))]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::{HttpRequest, HttpResponse};
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_hex, PrivateKey, PublicKey};
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
    reason: Option<String>,
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

/// Serves the case on its own wiremock server, its origin.
async fn wiremock_origin(case: &Case) -> (MockServer, String) {
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
    let origin = server.uri();
    (server, origin)
}

/// Serves the case once on a loopback listener that writes the status line
/// with the case's reason phrase, its characters as the Latin-1 bytes node
/// writes; its origin.
fn status_line_origin(case: &Case, reason: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut answer = format!("HTTP/1.1 {} ", case.status)
        .into_bytes()
        .into_iter()
        .chain(reason.chars().map(|c| u8::try_from(u32::from(c)).unwrap()))
        .collect::<Vec<u8>>();
    let body = from_hex(&case.body_hex).unwrap();
    let mut head = String::from("\r\n");
    for (name, value) in &case.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    answer.extend_from_slice(head.as_bytes());
    answer.extend_from_slice(&body);
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        // The request's head and its two-byte body (`{}`)
        while !request.windows(4).any(|w| w == b"\r\n\r\n") || !request.ends_with(b"{}") {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "the request ended early");
            request.extend_from_slice(&chunk[..read]);
        }
        stream.write_all(&answer).unwrap();
    });
    origin
}

/// Serves the case on its own server and sends the recorder's message
/// through the transport: the send's result, the messages the callback saw,
/// and the server's origin.
async fn sent(case: &Case) -> (bsv_rs::Result<()>, Vec<AuthMessage>, String) {
    let (_server, origin) = match &case.reason {
        Some(reason) => (None, status_line_origin(case, reason)),
        None => {
            let (server, origin) = wiremock_origin(case).await;
            (Some(server), origin)
        }
    };
    let transport = SimplifiedFetchTransport::new(&origin);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |message| {
        sink.lock().unwrap().push(message);
        Box::pin(async { Ok(()) })
    }));
    let result = transport.send(&general(&case.name)).await;
    let seen = seen.lock().unwrap().clone();
    (result, seen, origin)
}

/// The one recorded refusal read otherwise here (the parity note): a reason
/// phrase with a byte above `0x7e`, which fetch reads as UTF-8 (`0xe9` alone
/// one U+FFFD) and hyper's parser (httparse 1.10, `parse_reason`) as empty,
/// so the status stands alone; the case's words as recorded, then as read.
const READ_OTHERWISE: [(&str, &str, &str); 1] = [(
    "latin1_reason_phrase",
    "Received HTTP 401 Caf\u{fffd} from ",
    "Received HTTP 401 from ",
)];

/// The class #87 gives an unsigned answer's status: a fault for a 429, 502,
/// 503 or 504 (the cases' `Retry-After` 7 and 3 seconds), else none.
fn fault_of(name: &str) -> Option<TransportFault> {
    match name {
        "rate_limited_retry_after" => Some(TransportFault::RateLimited {
            retry_after_ms: Some(7000),
        }),
        "unavailable_retry_after" => Some(TransportFault::RateLimited {
            retry_after_ms: Some(3000),
        }),
        "bad_gateway" | "unavailable_no_content_type" | "gateway_timeout" => {
            Some(TransportFault::MayHaveBeenReceived)
        }
        _ => None,
    }
}

/// The case refused in the recorded words, its origin this server's, and
/// nothing handed to the callback.
async fn assert_refused_as_recorded(case: &Case) -> Error {
    let recorded = case.refusal.as_deref().expect("a refused case");
    let (result, seen, origin) = sent(case).await;
    let err = result.expect_err(&case.name);
    let mut words = recorded.replace("{url}", &origin);
    for (name, as_recorded, as_read) in READ_OTHERWISE {
        if name == case.name {
            assert!(words.contains(as_recorded), "{name}: {words}");
            words = words.replace(as_recorded, as_read);
        }
    }
    let expected = match fault_of(&case.name) {
        Some(fault) => Error::TransportFault {
            fault,
            status: Some(case.status),
            detail: words,
        },
        None => Error::AuthError(words),
    };
    assert_eq!(err, expected, "{}", case.name);
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
    assert_eq!(cases.len(), 22, "the witness's census");
    let mut refused = 0;
    for case in cases.iter().filter(|c| c.refusal.is_some()) {
        assert!(!case.reached_on_data, "{}", case.name);
        assert_refused_as_recorded(case).await;
        refused += 1;
    }
    assert_eq!(refused, 20);
}

#[tokio::test]
async fn an_unsigned_answer_of_another_status_is_the_named_hosts_auth_error() {
    for name in [
        "no_auth_headers_json",
        "unauthorized_text",
        "custom_reason_phrase",
    ] {
        let err = assert_refused_as_recorded(&case(name)).await;
        assert!(matches!(err, Error::AuthError(_)), "{name}: {err:?}");
        assert_eq!(err.transport_fault(), None, "{name}");
    }
}

#[tokio::test]
async fn an_unsigned_429_502_503_or_504_is_a_transport_fault_in_the_refusals_words() {
    for (name, status, fault) in [
        (
            "rate_limited_retry_after",
            429,
            TransportFault::RateLimited {
                retry_after_ms: Some(7000),
            },
        ),
        ("bad_gateway", 502, TransportFault::MayHaveBeenReceived),
        (
            "unavailable_no_content_type",
            503,
            TransportFault::MayHaveBeenReceived,
        ),
        (
            "unavailable_retry_after",
            503,
            TransportFault::RateLimited {
                retry_after_ms: Some(3000),
            },
        ),
        ("gateway_timeout", 504, TransportFault::MayHaveBeenReceived),
    ] {
        let case = case(name);
        assert_eq!(case.status, status, "{name}");
        let err = assert_refused_as_recorded(&case).await;
        assert_eq!(err.transport_fault(), Some(fault), "{name}: {err:?}");
        match &err {
            Error::TransportFault {
                status: got,
                detail,
                ..
            } => {
                assert_eq!(*got, Some(status), "{name}");
                assert!(
                    detail.starts_with(&format!("Received HTTP {status} ")),
                    "{name}: {detail}"
                );
            }
            other => panic!("{name}: {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_reason_phrase_is_the_status_lines_own_else_the_canonical_one() {
    for (name, description) in [
        ("custom_reason_phrase", "200 Fine By Me"),
        ("blank_reason_phrase", "401"),
        ("latin1_reason_phrase", "401"),
        ("no_auth_headers_json", "200 OK"),
        ("unauthorized_text", "401 Unauthorized"),
    ] {
        let err = assert_refused_as_recorded(&case(name)).await;
        assert!(
            err.to_string()
                .contains(&format!("Received HTTP {description} from ")),
            "{name}: {err}"
        );
    }
}

#[tokio::test]
async fn a_signed_503_is_read_as_the_named_hosts_answer() {
    let case = case("signed_unavailable");
    assert_eq!(case.refusal, None);
    assert!(case.reached_on_data);
    let (result, seen, _) = sent(&case).await;
    result.expect("a signed 503 is read");
    assert_eq!(seen.len(), 1);
    let response = HttpResponse::from_payload(seen[0].payload.as_deref().unwrap()).unwrap();
    assert_eq!(response.status, 503);
    assert_eq!(response.body, b"signed");
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
