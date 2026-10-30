//! #423: real AuthFetch → Peer → HTTP exchanges replayed from Node 22.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.
#[path = "support/auth_fetch_423/mod.rs"]
mod support;
use support::{words, Environment};

#[tokio::test]
async fn plain_request_and_matching_response_423() {
    let env = Environment::new("plain").await;
    let response = env.fetch().await.unwrap();
    env.assert_response(&response);
    assert!(response.ok());
    assert_eq!(response.header("X-BSV-ANSWER"), Some("yes"));
    env.assert_frames();
    let requests = env.mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let request = &requests[1];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/resource");
    assert_eq!(request.url.query(), Some("q=1"));
    assert_eq!(request.headers["content-type"], "application/json");
    assert_eq!(request.headers["authorization"], "test-token");
    assert_eq!(request.body, b"{}");
    for name in [
        "version",
        "identity-key",
        "nonce",
        "your-nonce",
        "signature",
        "request-id",
    ] {
        assert!(request.headers.contains_key(format!("x-bsv-auth-{name}")));
    }
}

#[tokio::test]
async fn mismatched_request_id_waits_for_the_recorded_timeout_423() {
    let mut env = Environment::new("mismatch").await;
    env.client = env.client.with_response_timeout_ms(100);
    assert_eq!(words(env.fetch().await), env.row["error"]);
    env.assert_frames();
    assert_eq!(env.mock.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn deadline_covers_a_fetch_that_never_answers_423() {
    let mut env = Environment::new("timeout").await;
    env.client = env.client.with_response_timeout_ms(100);
    assert_eq!(words(env.fetch().await), env.row["error"]);
    env.assert_frames();
}

#[tokio::test]
async fn retry_counter_zero_refuses_before_a_request_423() {
    let env = Environment::new("counter_zero").await;
    assert_eq!(words(env.fetch().await), env.row["error"]);
    assert!(env.mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn unsupported_and_auth_headers_use_the_reference_words_423() {
    for name in ["unsupported_header", "forbidden_header"] {
        let env = Environment::new(name).await;
        assert_eq!(words(env.fetch().await), env.row["error"]);
        assert!(env.mock.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn binary_request_body_keeps_its_recorded_bytes_423() {
    let env = Environment::new("body_bytes").await;
    env.assert_response(&env.fetch().await.unwrap());
    env.assert_frames();
    let requests = env.mock.received_requests().await.unwrap();
    assert_eq!(requests[1].body, [0, 128, 255]);
}

#[tokio::test]
async fn a_body_needs_content_type_and_text_needs_utf8_423() {
    for name in ["body_missing_type", "body_invalid_utf8"] {
        let env = Environment::new(name).await;
        assert_eq!(words(env.fetch().await), env.row["error"]);
        assert_eq!(
            env.mock.received_requests().await.unwrap().len(),
            1,
            "only the handshake precedes the body refusal"
        );
    }
}
