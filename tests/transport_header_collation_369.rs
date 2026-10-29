//! #369: signed response payloads recorded from the actual transport under
//! Node 22.18.0 / ICU 77.1, plus the lowercase BRC-104 collation measurement.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use bsv_rs::auth::transports::{HttpRequest, HttpResponse};
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_hex, sha256, to_hex, PrivateKey};
use serde::Deserialize;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
struct Witness {
    measurement: Measurement,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Measurement {
    alphabet: String,
    suffix_lengths: Vec<usize>,
    count: usize,
    byte_order_sha256: String,
    locale_order_sha256: String,
    differing_positions: usize,
    raw_byte_order: Vec<String>,
    raw_locale_order: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    subset: String,
    status: u16,
    headers: Vec<(String, String)>,
    body_hex: String,
    included_headers: Vec<(String, String)>,
    payload_hex: String,
}

fn witness() -> Witness {
    serde_json::from_str(include_str!("vectors/transport_header_collation_369.json")).unwrap()
}

async fn assert_payload(case: &Case) {
    let server = MockServer::start().await;
    let mut response =
        ResponseTemplate::new(case.status).set_body_bytes(from_hex(&case.body_hex).unwrap());
    for (name, value) in &case.headers {
        response = response.insert_header(name.as_str(), value.as_str());
    }
    Mock::given(method("POST"))
        .and(path("/headers"))
        .respond_with(response)
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
    let mut message = AuthMessage::new(MessageType::General, PrivateKey::random().public_key());
    message.payload = Some(
        HttpRequest {
            request_id: [7; 32],
            method: "POST".into(),
            path: "/headers".into(),
            search: String::new(),
            headers: vec![],
            body: vec![],
        }
        .to_payload(),
    );
    transport.send(&message).await.unwrap();
    let messages = seen.lock().unwrap();
    assert_eq!(messages.len(), 1, "{}", case.name);
    let payload = messages[0].payload.as_ref().unwrap();
    let response = HttpResponse::from_payload(payload).unwrap();
    assert_eq!(response.headers, case.included_headers, "{}", case.name);
    assert_eq!(to_hex(payload), case.payload_hex, "{}", case.name);
}

#[test]
fn issue_369_lowercase_brc104_byte_order_matches_the_node_measurement() {
    let measurement = witness().measurement;
    assert_eq!(
        measurement.alphabet,
        "-0123456789abcdefghijklmnopqrstuvwxyz"
    );
    assert_eq!(measurement.suffix_lengths, [0, 1, 2]);
    let mut names = vec!["x-bsv-".to_owned()];
    for a in measurement.alphabet.chars() {
        names.push(format!("x-bsv-{a}"));
        for b in measurement.alphabet.chars() {
            names.push(format!("x-bsv-{a}{b}"));
        }
    }
    names.sort();
    assert_eq!(names.len(), measurement.count);
    assert_eq!(measurement.count, 1407);
    let digest = to_hex(&sha256(format!("{}\n", names.join("\n")).as_bytes()));
    assert_eq!(digest, measurement.byte_order_sha256);
    assert_eq!(digest, measurement.locale_order_sha256);
    assert_eq!(measurement.differing_positions, 0);
    assert_ne!(measurement.raw_byte_order, measurement.raw_locale_order);
}

#[tokio::test]
async fn issue_369_brc104_response_names_are_lowercased_filtered_and_signed_in_reference_order() {
    let cases: Vec<_> = witness()
        .cases
        .into_iter()
        .filter(|case| case.subset == "brc104")
        .collect();
    assert_eq!(cases.len(), 2);
    for case in cases {
        assert_payload(&case).await;
    }
}

#[tokio::test]
async fn issue_369_wider_http_token_names_use_locale_order_in_the_signed_payload() {
    let case = witness()
        .cases
        .into_iter()
        .find(|case| case.subset == "http_token")
        .unwrap();
    let mut byte_order = case.included_headers.clone();
    byte_order.sort_by(|a, b| a.0.cmp(&b.0));
    assert_ne!(byte_order, case.included_headers);
    assert_payload(&case).await;
}
