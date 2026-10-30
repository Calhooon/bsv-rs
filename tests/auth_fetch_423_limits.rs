//! Client body limits reach the native transport and the Peer payload boundary.
#![cfg(all(feature = "auth", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/auth_fetch_423/mod.rs"]
mod support;

use bsv_rs::auth::transports::{HttpRequest, TransportCallback};
use bsv_rs::auth::{AuthFetch, AuthFetchOptions};
use bsv_rs::auth::{AuthMessage, MessageType, Transport};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use bsv_rs::Result;
use std::sync::Mutex;
use support::Environment;

fn native_client(injected: bool, limit: usize) -> AuthFetch<ProtoWallet> {
    let wallet = ProtoWallet::new(Some(support::key(41)));
    let client = if injected {
        AuthFetch::with_client(wallet, None, None, reqwest::Client::new())
    } else {
        AuthFetch::new(wallet, None, None)
    };
    client.with_max_response_bytes(limit).unwrap()
}

#[tokio::test]
async fn a_small_client_limit_refuses_at_the_transport_before_parsing_423() {
    for injected in [false, true] {
        let env = Environment::new("plain").await;
        let client = native_client(injected, 5);
        assert_eq!(
            client.fetch(&env.url(), AuthFetchOptions::default()).await,
            Err(Error::AuthError(format!(
                "Authenticated response from {} exceeds 5 bytes",
                env.url()
            )))
        );
        assert_eq!(env.mock.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn a_raised_client_limit_reads_a_signed_body_above_16_mib_423() {
    let size = 16 * 1024 * 1024 + 1;
    for injected in [false, true] {
        let env = Environment::with_response_body("plain", Some(vec![b'x'; size])).await;
        let client = native_client(injected, size);
        let response = client
            .fetch(&env.url(), AuthFetchOptions::default())
            .await
            .unwrap();
        assert_eq!(response.body.len(), size);
        assert!(response.body.iter().all(|byte| *byte == b'x'));
        assert_eq!(env.mock.received_requests().await.unwrap().len(), 2);
    }
}

#[tokio::test]
async fn a_matching_id_commits_identity_even_when_status_parsing_refuses_423() {
    let env = Environment::with_response_status("plain", 600).await;
    let client = native_client(false, 16 * 1024 * 1024);
    let expected = Err(Error::AuthError(
        "Authenticated response contains an invalid HTTP status code.".into(),
    ));
    assert_eq!(
        client.fetch(&env.url(), AuthFetchOptions::default()).await,
        expected
    );
    wiremock::Mock::given(wiremock::matchers::path("/resource"))
        .respond_with(wiremock::ResponseTemplate::new(401))
        .with_priority(1)
        .up_to_n_times(1)
        .expect(1)
        .mount(&env.mock)
        .await;
    // The matched identity makes this 401 stale: reauthenticate, then parse the
    // next signed response. Without it the unsigned 401 escapes immediately.
    assert_eq!(
        client.fetch(&env.url(), AuthFetchOptions::default()).await,
        expected
    );
    assert_eq!(env.mock.received_requests().await.unwrap().len(), 5);
}

struct PayloadTransport {
    incoming: Option<usize>,
    callback: Mutex<Option<Box<TransportCallback>>>,
}

#[async_trait::async_trait]
impl Transport for PayloadTransport {
    async fn send(&self, _: &AuthMessage) -> Result<()> {
        let Some(size) = self.incoming else {
            return Err(Error::AuthError("reached transport".into()));
        };
        let mut response = AuthMessage::new(MessageType::General, support::key(42).public_key());
        response.payload = Some(vec![0; size]);
        let future = self.callback.lock().unwrap().as_ref().unwrap()(response);
        future.await
    }
    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }
    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

#[tokio::test]
async fn custom_transport_payloads_are_bounded_before_peer_intake_423() {
    for limit in [1, 17 * 1024 * 1024] {
        let maximum = (16 * 1024 * 1024).max(limit + 512 * 1024);
        for size in [maximum, maximum + 1] {
            let client = AuthFetch::with_transport_factory(
                ProtoWallet::new(Some(support::key(41))),
                None,
                None,
                move |_| PayloadTransport {
                    incoming: Some(size),
                    callback: Mutex::new(None),
                },
            )
            .with_max_response_bytes(limit)
            .unwrap();
            let error = support::words(
                client
                    .fetch(
                        "https://payload-423.invalid/resource",
                        AuthFetchOptions::default(),
                    )
                    .await,
            );
            if size == maximum {
                assert_eq!(error, "general.nonce must be canonical base64.");
            } else {
                assert_eq!(error, "Authentication message array exceeds its limit.");
            }
        }
    }
}

#[tokio::test]
async fn request_payloads_are_bounded_before_the_peer_copies_them_423() {
    let maximum = 16 * 1024 * 1024;
    let headers = vec![("content-type".into(), "application/octet-stream".into())];
    let overhead = HttpRequest {
        request_id: [0; 32],
        method: "POST".into(),
        path: "/resource".into(),
        search: String::new(),
        headers: headers.clone(),
        body: vec![0],
    }
    .to_payload()
    .len()
        - 1
        + 4; // Five-byte body length at the tested size.
    for size in [maximum, maximum + 1] {
        let client = AuthFetch::with_transport_factory(
            ProtoWallet::new(Some(support::key(41))),
            None,
            None,
            |_| PayloadTransport {
                incoming: None,
                callback: Mutex::new(None),
            },
        )
        .with_max_response_bytes(1)
        .unwrap();
        let options = AuthFetchOptions {
            method: Some("POST".into()),
            headers: headers.clone().into_iter().collect(),
            body: Some(vec![0; size - overhead]),
            ..Default::default()
        };
        let error = support::words(
            client
                .fetch("https://payload-423.invalid/resource", options)
                .await,
        );
        if size == maximum {
            assert_eq!(error, "reached transport");
        } else {
            assert_eq!(
                error,
                format!("general.payload must be a dense byte array of at most {maximum} bytes.")
            );
        }
    }
}
