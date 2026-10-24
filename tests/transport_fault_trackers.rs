//! The chain trackers' transport fault (Calhooon/bsv-rs#87): a provider's
//! fault is an error, never a verdict (no `Ok(false)`). `ChainTrackerError` is
//! exhaustive, so it carries no typed class until the owner's word; the class
//! and the wait are stated in its detail, the status read before the body.
//!
//! Run with: `cargo test --features "full,http" --test transport_fault_trackers`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "transaction", feature = "http"))]

use std::net::TcpListener;
use std::time::Duration;

use bsv_rs::transaction::{
    BlockHeadersServiceConfig, BlockHeadersServiceTracker, ChainTracker, ChainTrackerError,
    WhatsOnChainTracker, WocNetwork,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const ROOT: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

fn trackers(url: &str, timeout_ms: u64) -> Vec<(&'static str, Box<dyn ChainTracker>)> {
    vec![
        (
            "WhatsOnChain",
            Box::new(WhatsOnChainTracker::with_base_url(url, WocNetwork::Mainnet)),
        ),
        (
            "BlockHeadersService",
            Box::new(BlockHeadersServiceTracker::with_config(
                BlockHeadersServiceConfig {
                    base_url: url.to_string(),
                    auth_token: None,
                    timeout_ms,
                },
            )),
        ),
    ]
}

/// Both questions of every tracker against `url`: the root's verdict and the
/// height. Each must be an error.
async fn errors_at(url: &str, timeout_ms: u64) -> Vec<(String, ChainTrackerError)> {
    let mut errors = Vec::new();
    for (name, tracker) in trackers(url, timeout_ms) {
        let verdict = tracker.is_valid_root_for_height(ROOT, 700_000).await;
        errors.push((
            format!("{name} root"),
            verdict.expect_err("a fault is never a verdict"),
        ));
        let height = tracker.current_height().await;
        errors.push((
            format!("{name} height"),
            height.expect_err("a fault is an error"),
        ));
    }
    errors
}

async fn answered(answer: ResponseTemplate) -> Vec<(String, ChainTrackerError)> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(answer)
        .mount(&server)
        .await;
    errors_at(&server.uri(), 30_000).await
}

#[tokio::test]
async fn a_refused_connection_is_a_network_error_never_sent() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    for (name, err) in errors_at(&format!("http://127.0.0.1:{port}"), 30_000).await {
        match err {
            ChainTrackerError::NetworkError(detail) => {
                assert!(detail.ends_with(" (NEVER_SENT)"), "{name}: {detail}");
            }
            other => panic!("{name}: expected NetworkError, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_timeout_is_a_network_error_that_may_have_been_received() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    // WhatsOnChainTracker has no timeout of its own: only the headers service
    let tracker = BlockHeadersServiceTracker::with_config(BlockHeadersServiceConfig {
        base_url: server.uri(),
        auth_token: None,
        timeout_ms: 300,
    });
    for err in [
        tracker
            .is_valid_root_for_height(ROOT, 700_000)
            .await
            .unwrap_err(),
        tracker.current_height().await.unwrap_err(),
    ] {
        match err {
            ChainTrackerError::NetworkError(detail) => {
                assert!(detail.ends_with(" (MAY_HAVE_BEEN_RECEIVED)"), "{detail}");
            }
            other => panic!("expected NetworkError, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn a_429_with_retry_after_states_the_rate_limit_and_its_wait() {
    let errors = answered(
        ResponseTemplate::new(429)
            .insert_header("Retry-After", "5")
            .set_body_raw("Too Many Requests", "text/plain"),
    )
    .await;
    for (name, err) in errors {
        assert_eq!(
            err,
            ChainTrackerError::InvalidResponse(
                "HTTP 429 Too Many Requests (RATE_LIMITED, retry_after_ms 5000)".into()
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_bare_503_states_the_transport_fault() {
    for (name, err) in answered(ResponseTemplate::new(503)).await {
        assert_eq!(
            err,
            ChainTrackerError::InvalidResponse(
                "HTTP 503 Service Unavailable (MAY_HAVE_BEEN_RECEIVED)".into()
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_500_stays_the_providers_answer() {
    for (name, err) in answered(ResponseTemplate::new(500)).await {
        assert_eq!(
            err,
            ChainTrackerError::InvalidResponse("HTTP 500 Internal Server Error".into()),
            "{name}"
        );
    }
}

/// A body cut after the request was written (the reviewer's probe on #87):
/// reqwest reads it as a decode error whose source is not `serde_json`'s.
#[cfg(not(target_arch = "wasm32"))]
mod body_cut {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A stub that reads each whole request, answers `200` with
    /// `Content-Length: 200`, sends twelve bytes of the body and closes: the
    /// body cut after the request was written. wiremock cannot cut a body.
    async fn cut_body_stub() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request_read(&request) {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Content-Length: 200\r\n\r\n0123456789ab",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        format!("http://{addr}")
    }

    /// Whether `request` holds its head and the body its `Content-Length`
    /// names.
    fn request_read(request: &[u8]) -> bool {
        let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        request.len() >= end + 4 + length
    }

    #[tokio::test]
    async fn a_body_cut_is_a_network_error_that_may_have_been_received() {
        for (name, err) in errors_at(&cut_body_stub().await, 30_000).await {
            match err {
                ChainTrackerError::NetworkError(detail) => {
                    assert!(
                        detail.ends_with(" (MAY_HAVE_BEEN_RECEIVED)"),
                        "{name}: {detail}"
                    );
                }
                other => panic!("{name}: expected NetworkError, got {other:?}"),
            }
        }
    }
}
