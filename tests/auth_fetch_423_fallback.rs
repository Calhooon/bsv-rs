//! The fallback's own words, exercised after a transport requests fallback.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.
#[path = "support/auth_fetch_423/mod.rs"]
mod support;
use async_trait::async_trait;
use bsv_rs::auth::transports::TransportCallback;
use bsv_rs::auth::{AuthFetch, AuthFetchOptions, AuthMessage, Transport};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::{Error, Result};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Refusal;
#[async_trait]
impl Transport for Refusal {
    async fn send(&self, _: &AuthMessage) -> Result<()> {
        Err(Error::AuthError(
            "HTTP server failed to authenticate".into(),
        ))
    }
    fn set_callback(&self, _: Box<TransportCallback>) {}
    fn clear_callback(&self) {}
}

#[tokio::test]
async fn fallback_validates_claims_and_status_with_recorded_words_423() {
    for (name, status, claim) in [
        ("fallback_direct", 200, false),
        ("fallback_direct_claim", 200, true),
        ("fallback_direct_status", 503, false),
    ] {
        let row = support::row(name);
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status).set_body_string("fallback");
        if claim {
            response = response.insert_header("x-bsv-pretend", "yes");
        }
        Mock::given(wiremock::matchers::path("/resource"))
            .respond_with(response)
            .mount(&server)
            .await;
        let client = AuthFetch::with_transport_factory(
            ProtoWallet::new(Some(support::key(41))),
            None,
            None,
            |_| Refusal,
        );
        let result = client
            .fetch(
                &format!("{}/resource?q=1", server.uri()),
                AuthFetchOptions::default(),
            )
            .await;
        if row.get("error").is_some() {
            assert_eq!(support::words(result), row["error"]);
        } else {
            let response = result.unwrap();
            assert_eq!(
                response.status,
                row["result"]["status"].as_u64().unwrap() as u16
            );
            assert_eq!(hex::encode(response.body), row["result"]["body_hex"]);
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

async fn fallback_body_bound(chunked: bool) {
    const LIMIT: usize = 8;
    for size in [LIMIT, LIMIT + 1] {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(200).set_body_bytes(vec![b'x'; size]);
        if chunked {
            response = response.insert_header("transfer-encoding", "chunked");
        }
        Mock::given(wiremock::matchers::path("/resource"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let client = AuthFetch::with_transport_factory(
            ProtoWallet::new(Some(support::key(41))),
            None,
            None,
            |_| Refusal,
        )
        .with_max_response_bytes(LIMIT)
        .unwrap();
        let url = format!("{}/resource", server.uri());
        let result = client.fetch(&url, AuthFetchOptions::default()).await;
        if size == LIMIT {
            assert_eq!(result.unwrap().body, vec![b'x'; LIMIT]);
        } else {
            assert_eq!(
                result,
                Err(Error::AuthError(format!(
                    "Unauthenticated response from {url} exceeds {LIMIT} bytes"
                )))
            );
        }
    }
}

#[tokio::test]
async fn fallback_refuses_one_byte_over_its_limit_with_content_length_423() {
    fallback_body_bound(false).await;
}

#[tokio::test]
async fn fallback_refuses_one_byte_over_its_limit_without_content_length_423() {
    fallback_body_bound(true).await;
}

#[tokio::test]
async fn recorded_fallback_handshake_refusal_is_not_a_plain_fetch_423() {
    let row = support::row("fallback");
    // The recorder's `new Response('{}', { status: 404 })` has no statusText.
    // Wiremock supplies "Not Found", so serve the recorded empty reason phrase.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let serve = async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut buffer = [0; 1024];
            let length = stream.read(&mut buffer).await.unwrap();
            assert!(length > 0);
            request.extend_from_slice(&buffer[..length]);
        }
        assert!(request.starts_with(b"POST /.well-known/auth HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 404 \r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .await
            .unwrap();
    };
    let client = AuthFetch::new(ProtoWallet::new(Some(support::key(41))), None, None);
    let url = format!("{origin}/resource");
    let (result, ()) = tokio::join!(client.fetch(&url, support::options(&row)), serve);
    assert_eq!(
        support::words(result),
        row["error"]
            .as_str()
            .unwrap()
            .replace("https://auth-fetch-423.invalid", &origin)
    );
}
