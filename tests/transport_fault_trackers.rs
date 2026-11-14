//! The chain trackers' transport fault (Calhooon/bsv-rs#87): a provider's
//! fault is an error, never a verdict (no `Ok(false)`):
//! `ChainTrackerError::TransportFault` with its class, its wait and the
//! answer's status, read before the body; `Transaction::verify` carries it to
//! `Error::TransportFault`.
//!
//! Run with: `cargo test --features "full,http" --test transport_fault_trackers`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "transaction", feature = "http"))]

use std::net::TcpListener;
use std::time::Duration;

use bsv_rs::transaction::{
    BlockHeadersServiceConfig, BlockHeadersServiceTracker, ChainTracker, ChainTrackerError,
    TransportFault, WhatsOnChainTracker, WocNetwork,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/body_stub.rs"]
mod body_stub;

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

/// The four questions' paths: WhatsOnChain's root and height, the headers
/// service's root and height.
const QUESTIONS: [&str; 4] = [
    "/block/700000/header",
    "/chain/info",
    "/api/v1/chain/header/700000",
    "/api/v1/chain/tip",
];

/// `answer` at each of `paths`, each asked once and no more (#98).
async fn serving(paths: &[&str], answer: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    for question in paths {
        Mock::given(method("GET"))
            .and(path(*question))
            .respond_with(answer.clone())
            .expect(1)
            .mount(&server)
            .await;
    }
    server
}

async fn answered(answer: ResponseTemplate) -> Vec<(String, ChainTrackerError)> {
    let server = serving(&QUESTIONS, answer).await;
    errors_at(&server.uri(), 30_000).await
}

/// The typed fault an error must be: its class and status, and its detail
/// the transport's words with no class appended.
fn assert_fault(name: &str, err: &ChainTrackerError, class: TransportFault, code: Option<u16>) {
    match err {
        ChainTrackerError::TransportFault {
            fault,
            status,
            detail,
        } => {
            assert_eq!((*fault, *status), (class, code), "{name}: {detail}");
            assert!(!detail.contains(class.code()), "{name}: {detail}");
        }
        other => panic!("{name}: expected TransportFault, got {other:?}"),
    }
    assert_eq!(err.transport_fault(), Some(class), "{name}");
}

fn closed_port_url() -> String {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn a_refused_connection_is_a_transport_fault_never_sent() {
    for (name, err) in errors_at(&closed_port_url(), 30_000).await {
        assert_fault(&name, &err, TransportFault::NeverSent, None);
    }
}

#[tokio::test]
async fn a_timeout_is_a_transport_fault_that_may_have_been_received() {
    let server = serving(
        &QUESTIONS[2..],
        ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
    )
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
        assert_fault("timeout", &err, TransportFault::MayHaveBeenReceived, None);
    }
}

#[tokio::test]
async fn a_429_with_retry_after_is_rate_limited_with_its_wait() {
    let errors = answered(
        ResponseTemplate::new(429)
            .insert_header("Retry-After", "5")
            .set_body_raw("Too Many Requests", "text/plain"),
    )
    .await;
    for (name, err) in errors {
        assert_eq!(
            err,
            ChainTrackerError::TransportFault {
                fault: TransportFault::RateLimited {
                    retry_after_ms: Some(5000)
                },
                status: Some(429),
                detail: "HTTP 429 Too Many Requests".into(),
            },
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_bare_503_is_a_transport_fault_that_may_have_been_received() {
    for (name, err) in answered(ResponseTemplate::new(503)).await {
        assert_eq!(
            err,
            ChainTrackerError::TransportFault {
                fault: TransportFault::MayHaveBeenReceived,
                status: Some(503),
                detail: "HTTP 503 Service Unavailable".into(),
            },
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
        assert_eq!(err.transport_fault(), None, "{name}");
    }
}

/// #98: the head arrives, twelve bytes of the body, and nothing more. The
/// headers service's `timeout_ms` ends both questions, in the class the
/// timeout cell answers, after one request each, counted once the stub's
/// reads ended; the door is the one that cell holds.
#[tokio::test]
async fn a_body_that_never_ends_is_bounded_by_the_timeout_and_may_have_been_received_98() {
    let stub = body_stub::BodyStub::stalled().await;
    let tracker = || {
        BlockHeadersServiceTracker::with_config(BlockHeadersServiceConfig {
            base_url: stub.url.clone(),
            auth_token: None,
            timeout_ms: body_stub::DOOR_TIMEOUT.as_millis() as u64,
        })
    };
    let root = stub
        .stalled_once("root", || async {
            tracker().is_valid_root_for_height(ROOT, 700_000).await
        })
        .await
        .expect_err("a fault is never a verdict");
    let height = stub
        .stalled_once("height", || async { tracker().current_height().await })
        .await
        .expect_err("a fault is an error");
    for err in [root, height] {
        assert_fault("stalled", &err, TransportFault::MayHaveBeenReceived, None);
    }
    assert_eq!(stub.settled().await, 2, "one request a call");
}

/// The two bodies that are not JSON at all: an error on both sides at every
/// question (the reference's client throws at its `JSON.parse`,
/// `transaction/http/FetchHttpClient.ts:75-80` at `ts-stack@edf6e03`).
const NOT_JSON: [&str; 2] = ["not json", "{\"merkleroot\":"];

/// The five bodies the reference's client reads as a value (the empty body
/// as the text `''`) that is no answer to the question: beside each, what
/// both of the reference's trackers answer on the root question, and what
/// this crate answers there.
const NO_ANSWER: [(&str, &str, &str); 5] = [
    ("", "false", "InvalidResponse"),
    ("[]", "false", "InvalidResponse"),
    ("null", "false", "InvalidResponse"),
    ("{}", "false", "InvalidResponse"),
    (
        "{\"merkleroot\":7,\"blocks\":\"x\",\"height\":-1}",
        "false",
        "InvalidResponse",
    ),
];

/// Every tracker's two answers to `body` served `200` at the four questions.
async fn json_answered(body: &str) -> Vec<(String, ChainTrackerError)> {
    let errors = answered(ResponseTemplate::new(200).set_body_raw(body, "application/json")).await;
    assert_eq!(errors.len(), 4);
    errors
}

fn assert_invalid_response(name: &str, body: &str, err: &ChainTrackerError) {
    assert!(
        matches!(err, ChainTrackerError::InvalidResponse(_)),
        "{name} {body:?}: {err:?}"
    );
    assert_eq!(err.transport_fault(), None, "{name} {body:?}");
}

/// #98: an answer `200` whose body is not the question's JSON is the
/// provider's answer misread, `InvalidResponse`, never a panic and never a
/// transport fault class. These are the cells where the reference answers an
/// error too: the height question at both trackers for all seven bodies, and
/// the root question at both trackers for the two bodies that are not JSON.
/// The root question's other ten cells are the next test's.
#[tokio::test]
async fn an_answer_that_is_not_the_questions_json_is_an_invalid_response_never_a_fault_98() {
    let mut cells = 0;
    for body in NOT_JSON {
        for (name, err) in json_answered(body).await {
            assert_invalid_response(&name, body, &err);
            cells += 1;
        }
    }
    for (body, _, _) in NO_ANSWER {
        for (name, err) in json_answered(body).await {
            if name.ends_with(" height") {
                assert_invalid_response(&name, body, &err);
                cells += 1;
            }
        }
    }
    assert_eq!(cells, 2 * 4 + 5 * 2, "the cells both sides refuse");
}

/// #98, a stated difference (the captain's ruling on the three reads of pull
/// request #990): on the root question, for the five bodies of [`NO_ANSWER`],
/// both of the reference's trackers answer `false`, a verdict
/// (`ts-stack@edf6e03` `transaction/chaintrackers/WhatsOnChain.ts:183-186`,
/// `responseMerkleRoot(response.data) === query.root`;
/// `BlockHeadersService.ts:131-171,247-248`, `isConfirmedResponse`), and this
/// crate answers the typed refusal `InvalidResponse` at both of its trackers:
/// ten cells, two trackers by five bodies. A malformed answer from a tracker
/// is a fault a caller may retry or route elsewhere, never evidence about
/// the root (#87's typed-fault contract); both sides refuse the root. The
/// test holds this crate's answer and names the reference's beside it; a
/// change of either column is this table's to make.
#[tokio::test]
async fn a_body_that_is_no_answer_to_the_root_question_is_an_invalid_response_where_the_reference_answers_false_stated_98(
) {
    let mut cells = Vec::new();
    for (body, reference, here) in NO_ANSWER {
        assert_eq!(
            (reference, here),
            ("false", "InvalidResponse"),
            "{body:?}: the stated pair"
        );
        for (name, err) in json_answered(body).await {
            if name.ends_with(" root") {
                assert_invalid_response(&name, body, &err);
                cells.push((name, body));
            }
        }
    }
    assert_eq!(cells.len(), 10, "two trackers, five bodies: {cells:?}");
    for tracker in ["WhatsOnChain root", "BlockHeadersService root"] {
        assert_eq!(cells.iter().filter(|(name, _)| name == tracker).count(), 5);
    }
}

/// `Transaction::verify` asks the tracker for a proven transaction's root;
/// a fault there is the crate's `Error::TransportFault`, its class read by
/// `Error::transport_fault()`, never a `TransactionError` text.
#[cfg(feature = "wallet")]
#[tokio::test]
async fn a_trackers_transport_fault_reaches_the_crate_error_typed() {
    use bsv_rs::script::LockingScript;
    use bsv_rs::transaction::{MerklePath, Transaction, TransactionInput, TransactionOutput};

    let mut tx = Transaction::new();
    tx.inputs_mut()
        .push(TransactionInput::new("aa".repeat(32), 0));
    let op_true = LockingScript::from_binary(&[0x51]).unwrap();
    tx.outputs_mut().push(TransactionOutput::new(1000, op_true));
    tx.merkle_path = Some(MerklePath::from_coinbase_txid(&tx.id(), 800_000));

    let tracker = WhatsOnChainTracker::with_base_url(&closed_port_url(), WocNetwork::Mainnet);
    let err = tx.verify(&tracker, None, None).await.unwrap_err();
    assert_eq!(
        err.transport_fault(),
        Some(TransportFault::NeverSent),
        "{err:?}"
    );
    match err {
        bsv_rs::Error::TransportFault { status, .. } => assert_eq!(status, None),
        other => panic!("expected Error::TransportFault, got {other:?}"),
    }
}

/// A body cut after the request was written (the reviewer's probe on #87):
/// reqwest reads it as a decode error whose source is not `serde_json`'s.
#[cfg(not(target_arch = "wasm32"))]
mod body_cut {
    use super::*;

    #[tokio::test]
    async fn a_body_cut_is_a_transport_fault_that_may_have_been_received() {
        let stub = body_stub::BodyStub::cut().await;
        for (name, err) in errors_at(&stub.url, 30_000).await {
            assert_fault(&name, &err, TransportFault::MayHaveBeenReceived, None);
        }
        assert_eq!(stub.requests(), 4, "one request a call");
    }
}
