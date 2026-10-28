//! The reference's configurable body defaults, on fixed and chunked HTTP.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::{headers, HttpRequest};
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn message(handshake: bool) -> AuthMessage {
    let key = PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap();
    let mut message = AuthMessage::new(MessageType::InitialRequest, key.public_key());
    if !handshake {
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

fn body(handshake: bool, size: usize) -> Vec<u8> {
    if !handshake {
        return vec![b'a'; size];
    }
    let mut body = serde_json::to_vec(&message(true)).unwrap();
    body.resize(size, b' ');
    body
}

async fn replay(case: &Value, chunked: bool) {
    let handshake = case["handshake"].as_bool().unwrap_or(false);
    let server = MockServer::start().await;
    let at = if handshake {
        "/.well-known/auth"
    } else {
        "/sendMessage"
    };
    let mut response = ResponseTemplate::new(200)
        .set_body_bytes(body(
            handshake,
            case["body_bytes"].as_u64().unwrap() as usize,
        ))
        .insert_header(headers::VERSION, "0.1")
        .insert_header(headers::IDENTITY_KEY, message(true).identity_key.to_hex())
        .insert_header(headers::SIGNATURE, "3006020101020101");
    if chunked {
        response = response.insert_header("transfer-encoding", "chunked");
    }
    Mock::given(method("POST"))
        .and(path(at))
        .respond_with(response)
        .expect(1)
        .mount(&server)
        .await;
    let transport = SimplifiedFetchTransport::new(&server.uri());
    let transport = if handshake {
        transport.with_max_handshake_response_bytes(
            case["options"]["maxHandshakeResponseBytes"]
                .as_u64()
                .unwrap() as usize,
        )
    } else {
        transport
            .with_max_response_bytes(case["options"]["maxResponseBytes"].as_u64().unwrap() as usize)
    }
    .unwrap();
    let seen = Arc::new(Mutex::new(0));
    let sink = seen.clone();
    transport.set_callback(Box::new(move |_| {
        *sink.lock().unwrap() += 1;
        Box::pin(async { Ok(()) })
    }));
    let result = transport.send(&message(handshake)).await;
    if let Some(error) = case["error"]["message"].as_str() {
        assert_eq!(
            result,
            Err(Error::AuthError(error.replace("{url}", &server.uri()))),
            "{}, chunked={chunked}",
            case["name"]
        );
        assert_eq!(*seen.lock().unwrap(), 0);
    } else {
        result.unwrap();
        assert_eq!(*seen.lock().unwrap(), 1);
    }
}

fn reference() -> Value {
    let witness: Value =
        serde_json::from_str(include_str!("vectors/auth_transport_bounds_416.json")).unwrap();
    witness["references"][0].clone()
}

#[tokio::test]
async fn issue_416_configured_body_limits_apply_with_and_without_content_length() {
    for case in reference()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["family"] == "options")
    {
        replay(case, false).await;
        replay(case, true).await;
    }
}

#[test]
fn issue_416_body_limits_require_positive_safe_integers_in_the_reference_words() {
    for case in reference()["option_errors"].as_array().unwrap() {
        // Construction performs no I/O; the reserved host is never contacted.
        let transport = SimplifiedFetchTransport::new("https://transport-416.invalid");
        let value = case["value"].as_u64().unwrap() as usize;
        let result = if case["name"] == "maxResponseBytes" {
            transport.with_max_response_bytes(value)
        } else {
            transport.with_max_handshake_response_bytes(value)
        };
        assert_eq!(
            result.unwrap_err(),
            Error::AuthError(case["message"].as_str().unwrap().into())
        );
    }
}
