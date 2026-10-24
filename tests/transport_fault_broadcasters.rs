//! The broadcasters' transport fault (Calhooon/bsv-rs#87): a failure says
//! whether the request was sent. A connection never made is `NEVER_SENT` (the
//! caller may release its inputs); a timeout or a fault after the body was
//! written is `MAY_HAVE_BEEN_RECEIVED` (the caller holds them); a 429, and a
//! 503 with `Retry-After`, is `RATE_LIMITED` with the wait in `more`, never a
//! verdict on the transaction. The status is read before the body.
//!
//! Witnesses: #65 (W-SDK-1, a timeout after the body was written read as
//! `NETWORK_ERROR`) and #66 (W-SDK-2, a 429 read as `PARSE_ERROR`, its wait
//! lost), each through ARC, Teranode and WhatsOnChain.
//!
//! Run with: `cargo test --features "full,http" --test transport_fault_broadcasters`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "transaction", feature = "http"))]

use std::net::TcpListener;
use std::time::Duration;

use bsv_rs::transaction::{
    ArcBroadcaster, ArcConfig, BroadcastFailure, Broadcaster, TeranodeBroadcaster, TeranodeConfig,
    Transaction, TransactionOutput, TransportFault, WhatsOnChainBroadcaster, WocBroadcastConfig,
    WocBroadcastNetwork,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The Go SDK vector transaction `tests/broadcaster_http_tests.rs` uses.
const TEST_TX_HEX: &str = "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000";

#[derive(Clone, Copy, Debug)]
enum Service {
    Arc,
    Teranode,
    WhatsOnChain,
}

const SERVICES: [Service; 3] = [Service::Arc, Service::Teranode, Service::WhatsOnChain];

impl Service {
    fn path(self) -> &'static str {
        match self {
            Service::Arc | Service::Teranode => "/v1/tx",
            Service::WhatsOnChain => "/v1/bsv/main/tx/raw",
        }
    }

    fn broadcaster(self, url: &str, timeout_ms: u64) -> Box<dyn Broadcaster> {
        let url = url.to_string();
        match self {
            Service::Arc => Box::new(ArcBroadcaster::with_config(ArcConfig {
                url,
                api_key: None,
                timeout_ms,
            })),
            Service::Teranode => Box::new(TeranodeBroadcaster::with_config(TeranodeConfig {
                url,
                api_key: None,
                timeout_ms,
            })),
            Service::WhatsOnChain => {
                Box::new(WhatsOnChainBroadcaster::with_config(WocBroadcastConfig {
                    network: WocBroadcastNetwork::Mainnet,
                    api_key: None,
                    timeout_ms,
                    base_url: Some(url),
                }))
            }
        }
    }
}

/// The vector transaction with a source transaction on its input, so that
/// Teranode's Extended Format serializes it.
fn transaction() -> Transaction {
    let mut tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
    let mut source = Transaction::new();
    for _ in 0..=tx.inputs[0].source_output_index {
        source
            .add_output(TransactionOutput::new(
                1_000_000,
                bsv_rs::script::LockingScript::from_hex(
                    "76a914000000000000000000000000000000000000000088ac",
                )
                .unwrap(),
            ))
            .unwrap();
    }
    tx.inputs[0].source_transaction = Some(Box::new(source));
    tx
}

async fn broadcast_to(service: Service, url: &str, timeout_ms: u64) -> BroadcastFailure {
    service
        .broadcaster(url, timeout_ms)
        .broadcast(&transaction())
        .await
        .expect_err("the broadcast fails")
}

async fn answered(service: Service, answer: ResponseTemplate) -> BroadcastFailure {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(service.path()))
        .respond_with(answer)
        .expect(1)
        .mount(&server)
        .await;
    broadcast_to(service, &server.uri(), 30_000).await
}

fn assert_fault(service: Service, failure: &BroadcastFailure, fault: TransportFault) {
    assert_eq!(failure.code, fault.code(), "{service:?}: {failure:?}");
    assert_eq!(failure.transport_fault(), Some(fault), "{service:?}");
    assert_eq!(
        failure.txid.as_deref(),
        Some(transaction().id().as_str()),
        "{service:?}: the failure names the transaction"
    );
}

#[tokio::test]
async fn a_refused_connection_is_never_sent() {
    // A port bound and released: nothing listens there
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    for service in SERVICES {
        let failure = broadcast_to(service, &format!("http://127.0.0.1:{port}"), 30_000).await;
        assert_fault(service, &failure, TransportFault::NeverSent);
        assert_eq!(failure.code, "NEVER_SENT");
        assert!(failure.more.is_none(), "{service:?}");
    }
}

/// #65, W-SDK-1 step 1: the stub takes the transaction and never answers in
/// time. The request was written, so the caller must hold the inputs.
#[tokio::test]
async fn a_timeout_after_the_body_was_written_may_have_been_received() {
    for service in SERVICES {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(service.path()))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let failure = broadcast_to(service, &server.uri(), 300).await;
        assert_fault(service, &failure, TransportFault::MayHaveBeenReceived);
        assert_eq!(failure.code, "MAY_HAVE_BEEN_RECEIVED");
        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            1,
            "{service:?}: the stub received the request"
        );
        assert!(
            !received[0].body.is_empty(),
            "{service:?}: with the transaction"
        );
    }
}

/// #66, W-SDK-2: a 429 with a `text/plain` body and `Retry-After: 5`. The
/// status is read before the body, and the wait is kept.
#[tokio::test]
async fn a_429_with_retry_after_and_a_text_body_is_rate_limited_with_its_wait() {
    for service in SERVICES {
        let failure = answered(
            service,
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "5")
                .set_body_raw("Too Many Requests", "text/plain"),
        )
        .await;
        let fault = TransportFault::RateLimited {
            retry_after_ms: Some(5000),
        };
        assert_fault(service, &failure, fault);
        assert_eq!(failure.code, "RATE_LIMITED");
        assert_eq!(
            failure.more,
            Some(json!({"status": 429, "retry_after_ms": 5000})),
            "{service:?}"
        );
        assert_eq!(failure.description, "Too Many Requests", "{service:?}");
    }
}

#[tokio::test]
async fn a_429_without_retry_after_is_rate_limited_with_no_wait() {
    for service in SERVICES {
        let failure = answered(service, ResponseTemplate::new(429)).await;
        let fault = TransportFault::RateLimited {
            retry_after_ms: None,
        };
        assert_fault(service, &failure, fault);
        assert_eq!(
            failure.more,
            Some(json!({"status": 429, "retry_after_ms": null})),
            "{service:?}"
        );
    }
}

#[tokio::test]
async fn a_bare_503_may_have_been_received() {
    for service in SERVICES {
        let failure = answered(service, ResponseTemplate::new(503)).await;
        assert_fault(service, &failure, TransportFault::MayHaveBeenReceived);
        assert_eq!(failure.more, Some(json!({"status": 503})), "{service:?}");
        assert_eq!(
            failure.description, "HTTP 503 Service Unavailable",
            "{service:?}"
        );
    }
}

#[tokio::test]
async fn a_502_and_a_504_may_have_been_received_whatever_the_body() {
    for service in SERVICES {
        for status in [502, 504] {
            let failure = answered(
                service,
                ResponseTemplate::new(status).set_body_json(json!({"status": status})),
            )
            .await;
            assert_fault(service, &failure, TransportFault::MayHaveBeenReceived);
            assert_eq!(failure.more, Some(json!({"status": status})));
        }
    }
}

#[tokio::test]
async fn a_503_with_retry_after_is_rate_limited() {
    for service in SERVICES {
        let failure = answered(
            service,
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "2")
                .set_body_string("down for a moment"),
        )
        .await;
        let fault = TransportFault::RateLimited {
            retry_after_ms: Some(2000),
        };
        assert_fault(service, &failure, fault);
    }
}

/// #65's S2 half holds: an answered 500 is the service's word, not a fault.
#[tokio::test]
async fn a_500_is_the_services_answer_not_a_fault() {
    let failure = answered(Service::Arc, ResponseTemplate::new(500)).await;
    assert_eq!(failure.code, "PARSE_ERROR");
    assert_eq!(failure.transport_fault(), None);
    for service in [Service::Teranode, Service::WhatsOnChain] {
        let failure = answered(service, ResponseTemplate::new(500)).await;
        assert_eq!(failure.code, "500", "{service:?}");
        assert_eq!(failure.transport_fault(), None);
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
    async fn a_body_cut_after_the_body_was_written_may_have_been_received() {
        let url = cut_body_stub().await;
        for service in SERVICES {
            let failure = broadcast_to(service, &url, 30_000).await;
            assert_fault(service, &failure, TransportFault::MayHaveBeenReceived);
            assert!(failure.more.is_none(), "{service:?}");
        }
    }
}
