//! #423 certificate queue and the #416 HTTP intake distinction.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.
#[path = "support/auth_fetch_423/mod.rs"]
mod support;
use bsv_rs::auth::MessageType;
use support::{vector, words, Environment};

#[tokio::test]
async fn certificate_exchange_during_handshake_precedes_general_request_423() {
    let env = Environment::new("certificate_handshake").await;
    let start = std::time::Instant::now();
    let response = env.fetch().await.unwrap();
    env.assert_response(&response);
    assert!(start.elapsed() >= std::time::Duration::from_millis(500));
    let sent = env.sent.lock().unwrap();
    assert_eq!(
        sent.iter().map(|m| m.message_type).collect::<Vec<_>>(),
        [
            MessageType::InitialRequest,
            MessageType::CertificateResponse,
            MessageType::General
        ]
    );
    let reference = env.row["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["messageType"] == "certificateResponse")
        .unwrap();
    assert_eq!(
        serde_json::to_value(sent[1].certificates.as_ref().unwrap()).unwrap(),
        reference["certificates"]
    );
    drop(sent);
    env.assert_frames();
}

#[tokio::test]
async fn http_certificate_request_keeps_the_pinned_intake_refusal_423() {
    let env = Environment::new("certificate_http").await;
    assert_eq!(words(env.fetch().await), env.row["error"]);
    env.assert_frames();
}

#[tokio::test]
async fn certificate_handler_and_explicit_retry_match_the_reference_423() {
    let mut env = Environment::new("certificate_handler").await;
    env.client = env.client.with_response_timeout_ms(800);
    assert_eq!(words(env.fetch().await), env.row["error"]);
    let retry = env.fetch().await.unwrap();
    assert_eq!(
        retry.status,
        env.row["explicit_retry"]["status"].as_u64().unwrap() as u16
    );
    assert_eq!(
        hex::encode(retry.body),
        env.row["explicit_retry"]["body_hex"]
    );
    env.assert_frames();
    let sent = env.sent.lock().unwrap();
    let certs = sent
        .iter()
        .find(|m| m.message_type == MessageType::CertificateResponse)
        .unwrap();
    let reference = env.row["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["messageType"] == "certificateResponse")
        .unwrap();
    assert_eq!(
        serde_json::to_value(certs.certificates.as_ref().unwrap()).unwrap(),
        reference["certificates"]
    );
}

#[tokio::test]
async fn requesting_receiving_and_consuming_certificates_423() {
    let env = Environment::new("receive_certificates").await;
    let policy = serde_json::from_value(vector()["policy"].clone()).unwrap();
    let certificates = env
        .client
        .send_certificate_request(&env.url(), policy)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(certificates).unwrap(),
        env.row["result_certificates"]
    );
    let received = env.client.consume_received_certificates();
    assert!(!received.is_empty());
    for certificate in received {
        assert_eq!(
            serde_json::to_value(certificate).unwrap(),
            env.row["result_certificates"][0]
        );
    }
    assert!(env.client.consume_received_certificates().is_empty());
    let sent = env.sent.lock().unwrap();
    assert!(sent
        .iter()
        .any(|m| m.message_type == MessageType::CertificateRequest));
}
