//! #416 fold: HTTP certificate requests reach the actual Peer callback and
//! signature verifier after a signed handshake on wiremock's ephemeral port.
//! The reference records its request handler separately from the newer Peer's
//! initialNonce intake refusal; see the fixture's explicit scope and changelog.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bsv_rs::auth::transports::{headers, HttpRequest, HttpResponse, TransportCallback};
use bsv_rs::auth::{
    AuthMessage, MessageType, Peer, PeerOptions, RequestedCertificateSet, SimplifiedFetchTransport,
    Transport, AUTH_PROTOCOL_ID,
};
use bsv_rs::primitives::{from_base64, to_base64, to_hex, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn witness(name: &str) -> Value {
    let data: Value = serde_json::from_str(include_str!(
        "vectors/auth_http_certificate_request_416.json"
    ))
    .unwrap();
    assert_eq!(data["node"], "v22.18.0");
    assert_eq!(data["references"][0]["reference"], "ts-stack@edf6e03");
    assert_eq!(data["references"][1]["reference"], "ts-sdk@9e3ede6b");
    let find = |reference: &Value| {
        reference["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap()
            .clone()
    };
    let newer = find(&data["references"][0]);
    let older = find(&data["references"][1]);
    for key in [
        "header",
        "signed",
        "signed_text",
        "verified_text",
        "error",
        "requests",
        "general_deliveries",
    ] {
        assert_eq!(newer[key], older[key], "{name}: {key}");
    }
    assert_eq!(
        newer["intake_error"],
        "certificateRequest.initialNonce must be canonical base64."
    );
    assert!(older["intake_error"].is_null());
    newer
}

fn key(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

fn sign(data: Vec<u8>, key_id: String) -> Vec<u8> {
    ProtoWallet::new(Some(key(42)))
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(key(41).public_key())),
            ..Default::default()
        })
        .unwrap()
        .signature
}

async fn server(case: &Value) -> MockServer {
    let mock = MockServer::start().await;
    let client_nonce = Arc::new(Mutex::new(String::new()));
    let kept = client_nonce.clone();
    let server_nonce = to_base64(&[11; 48]);
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(move |request: &Request| {
            let initial: AuthMessage = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(initial.message_type, MessageType::InitialRequest);
            let nonce = initial.initial_nonce.unwrap();
            *kept.lock().unwrap() = nonce.clone();
            let mut data = from_base64(&nonce).unwrap();
            data.extend(from_base64(&server_nonce).unwrap());
            let mut response = AuthMessage::new(MessageType::InitialResponse, key(42).public_key());
            response.initial_nonce = Some(server_nonce.clone());
            response.your_nonce = Some(nonce.clone());
            response.signature = Some(sign(data, format!("{nonce} {server_nonce}")));
            ResponseTemplate::new(200).set_body_json(response)
        })
        .expect(1)
        .mount(&mock)
        .await;

    let case = case.clone();
    Mock::given(method("POST"))
        .and(path("/request"))
        .respond_with(move |request: &Request| {
            let nonce = to_base64(&[9; 32]);
            let client_nonce = client_nonce.lock().unwrap().clone();
            let request_id = request.headers[headers::REQUEST_ID].to_str().unwrap();
            let header = case["header"].as_str().unwrap();
            let data = match case["signed"].as_str().unwrap() {
                "payload" => HttpResponse {
                    request_id: from_base64(request_id).unwrap().try_into().unwrap(),
                    status: 200,
                    headers: vec![],
                    body: b"hi".to_vec(),
                }
                .to_payload(),
                "header" | "stringified" => {
                    case["signed_text"].as_str().unwrap().as_bytes().to_vec()
                }
                signed => panic!("unrecorded preimage: {signed}"),
            };
            ResponseTemplate::new(200)
                .insert_header(headers::VERSION, "0.1")
                .insert_header(headers::IDENTITY_KEY, key(42).public_key().to_hex())
                .insert_header(headers::MESSAGE_TYPE, "certificateRequest")
                .insert_header(headers::REQUESTED_CERTIFICATES, header)
                .insert_header(headers::NONCE, nonce.as_str())
                .insert_header(headers::YOUR_NONCE, client_nonce.as_str())
                .insert_header(headers::REQUEST_ID, request_id)
                .insert_header(
                    headers::SIGNATURE,
                    to_hex(&sign(data, format!("{nonce} {client_nonce}"))),
                )
                .set_body_string("hi")
        })
        .expect(1)
        .mount(&mock)
        .await;
    mock
}

/// Observe what the real HTTP transport hands to Peer::start; forward intact.
struct ObservedTransport {
    inner: SimplifiedFetchTransport,
    seen: Arc<Mutex<Vec<AuthMessage>>>,
}

#[async_trait]
impl Transport for ObservedTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.inner.send(message).await
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        let seen = self.seen.clone();
        self.inner.set_callback(Box::new(move |message| {
            seen.lock().unwrap().push(message.clone());
            callback(message)
        }));
    }

    fn clear_callback(&self) {
        self.inner.clear_callback();
    }
}

struct Exchange {
    result: Result<()>,
    messages: Vec<AuthMessage>,
    requests: Vec<RequestedCertificateSet>,
    general: Vec<Vec<u8>>,
}

async fn exchange(case: &Value) -> Exchange {
    let server = server(case).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let peer = Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(key(41))),
        transport: ObservedTransport {
            inner: SimplifiedFetchTransport::new(&server.uri()),
            seen: seen.clone(),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: None,
    });
    let requests = Arc::new(Mutex::new(Vec::new()));
    let sink = requests.clone();
    peer.listen_for_certificates_requested(move |identity, requested| {
        assert_eq!(identity, key(42).public_key());
        sink.lock().unwrap().push(requested);
        Box::pin(async { Ok(()) })
    })
    .await;
    let general = Arc::new(Mutex::new(Vec::new()));
    let sink = general.clone();
    peer.listen_for_general_messages(move |_, payload| {
        sink.lock().unwrap().push(payload);
        Box::pin(async { Ok(()) })
    })
    .await;
    peer.start();
    let payload = HttpRequest {
        request_id: [7; 32],
        method: "POST".into(),
        path: "/request".into(),
        search: String::new(),
        headers: vec![],
        body: vec![],
    }
    .to_payload();
    let result = peer
        .to_peer(&payload, Some(&key(42).public_key().to_hex()), Some(5000))
        .await;
    server.verify().await;
    let messages = seen.lock().unwrap().clone();
    let requests = requests.lock().unwrap().clone();
    let general = general.lock().unwrap().clone();
    Exchange {
        result,
        messages,
        requests,
        general,
    }
}

async fn accepted(name: &str) {
    let case = witness(name);
    assert!(case["error"].is_null());
    assert_eq!(case["verified_text"], case["header"]);
    let observed = exchange(&case).await;
    assert_eq!(observed.result, Ok(()), "{name}");
    assert_eq!(observed.messages.len(), 2);
    let message = &observed.messages[1];
    assert_eq!(message.message_type, MessageType::CertificateRequest);
    let text = case["header"].as_str().unwrap();
    assert_eq!(
        message.requested_certificates_text.as_ref().unwrap().get(),
        text
    );
    assert_eq!(message.signing_data(), text.as_bytes());
    let expected: RequestedCertificateSet = serde_json::from_str(text).unwrap();
    assert_eq!(
        serde_json::to_value(observed.requests).unwrap(),
        serde_json::to_value(vec![expected]).unwrap()
    );
    assert!(observed.general.is_empty());
}

#[tokio::test]
async fn issue_416_http_certificate_header_keeps_property_order_for_the_peer_signature() {
    accepted("property_order").await;
}

#[tokio::test]
async fn issue_416_http_certificate_header_keeps_extra_properties_for_the_peer_signature() {
    accepted("extra_property").await;
}

#[tokio::test]
async fn issue_416_http_certificate_request_refuses_a_general_payload_signature() {
    let case = witness("general_payload_signature");
    assert_eq!(case["error"], "Signature is not valid");
    let observed = exchange(&case).await;
    // Valid for the HTTP payload, invalid for the requested-certificate text.
    // Before #416 the transport retyped it General and Peer accepted it.
    assert_eq!(
        observed.result,
        Err(Error::WalletError(case["error"].as_str().unwrap().into()))
    );
    assert_eq!(
        observed.messages[1].message_type,
        MessageType::CertificateRequest
    );
    assert!(observed.requests.is_empty());
    assert!(observed.general.is_empty());
}

// Behavior pins, not a changed verdict: #280 preserves the signed text received.
// The other side's verdict and actual preimage are read from the Node recorder.
async fn raw_text_divergence(name: &str, raw_signature: bool) {
    let case = witness(name);
    let header = case["header"].as_str().unwrap();
    let stringified = case["verified_text"].as_str().unwrap();
    assert_ne!(header, stringified);
    assert_eq!(
        serde_json::from_str::<Value>(header).unwrap(),
        serde_json::from_str::<Value>(stringified).unwrap()
    );
    if name.starts_with("spaced_") {
        assert!(header.contains(' '));
        assert!(!stringified.contains(' '));
    } else {
        assert!(header.contains(r"\u0074ypes"));
        assert!(stringified.contains("\"types\""));
        assert!(!stringified.contains(r"\u0074"));
    }
    assert_eq!(
        case["signed"],
        if raw_signature {
            "header"
        } else {
            "stringified"
        }
    );
    assert_eq!(
        case["signed_text"],
        if raw_signature { header } else { stringified }
    );
    let reference_verifies = case["error"].is_null();
    assert_eq!(reference_verifies, !raw_signature);
    if !reference_verifies {
        assert_eq!(case["error"], "Signature is not valid");
    }
    assert_eq!(
        case["requests"].as_array().unwrap().len(),
        usize::from(reference_verifies)
    );
    assert_eq!(case["general_deliveries"], 0);

    let observed = exchange(&case).await;
    assert_eq!(observed.messages.len(), 2);
    let message = &observed.messages[1];
    assert_eq!(message.message_type, MessageType::CertificateRequest);
    assert_eq!(
        message.requested_certificates_text.as_ref().unwrap().get(),
        header
    );
    assert_eq!(message.signing_data(), header.as_bytes());
    if raw_signature {
        assert_eq!(observed.result, Ok(()), "{name}");
        let requested: RequestedCertificateSet = serde_json::from_str(header).unwrap();
        assert_eq!(
            serde_json::to_value(observed.requests).unwrap(),
            serde_json::to_value(vec![requested]).unwrap()
        );
    } else {
        assert_eq!(
            observed.result,
            Err(Error::WalletError("Signature is not valid".into())),
            "{name}"
        );
        assert!(observed.requests.is_empty());
    }
    assert!(observed.general.is_empty());
}

#[tokio::test]
async fn issue_416_h3_whitespace_header_signed_raw_verifies() {
    raw_text_divergence("spaced_header_signature", true).await;
}

#[tokio::test]
async fn issue_416_h3b_whitespace_header_signed_stringified_is_refused() {
    raw_text_divergence("spaced_stringified_signature", false).await;
}

#[tokio::test]
async fn issue_416_h5_escaped_header_signed_raw_verifies() {
    raw_text_divergence("escaped_header_signature", true).await;
}

#[tokio::test]
async fn issue_416_h5b_escaped_header_signed_stringified_is_refused() {
    raw_text_divergence("escaped_stringified_signature", false).await;
}
