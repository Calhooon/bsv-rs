//! #768: the JSON lookup parse refuses what the reference's normalizer
//! refuses. `ts-stack@edf6e03`'s HTTPS facilitator runs `normalizeLookupAnswer`
//! on the parsed body and throws when it reads nothing
//! (`packages/sdk/src/overlay-tools/LookupResolver.ts:865-866`):
//!
//! ```text
//! const normalizedAnswer = normalizeLookupAnswer(answer)
//! if (normalizedAnswer == null) throw new Error('Malformed lookup response')
//! ```
//!
//! and `normalizeOutputListAnswer` (`:389-406`) reads an output list only
//! from an object whose `type` is the string `output-list` and whose
//! `outputs` is an array of items `normalizeLookupOutput` admits (`:327-357`:
//! `beef` a non-empty byte array, `outputIndex` an integer from 0 to
//! `0xffffffff`). The resolver's accounting (`:2379-2406`) records the
//! thrown error as the host's failure. Until #768 this crate read a body that
//! is not an object, a missing or non-string `type`, a missing or non-array
//! `outputs` as an empty output list, and dropped a malformed item, each a
//! host success since #760. The reputation tracker is one global keyed by URL
//! and each test reads its host's counts before and after; each test also
//! takes a server of its own (`MockServer::builder().start()`, not the pool
//! of `MockServer::start()`), since three failures on one reused host put it
//! in the tracker's backoff and the next test's query is refused.
#![cfg(all(feature = "overlay", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    get_overlay_host_reputation_tracker, HttpsOverlayLookupFacilitator, LookupAnswer,
    LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVICE: &str = "ls_lookup_normalizer_768";

async fn host_answering(body: serde_json::Value) -> MockServer {
    // A server of its own: `MockServer::start` draws from wiremock's pool, so
    // a reused port would carry an earlier test's failures into the
    // tracker's backoff and refuse this test's query.
    let server = MockServer::builder().start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn http_resolver(host: &str) -> LookupResolver {
    LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(HttpsOverlayLookupFacilitator::new(true))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            SERVICE.to_string(),
            vec![host.to_string()],
        )])),
        ..Default::default()
    })
}

fn question() -> LookupQuestion {
    LookupQuestion::new(SERVICE, json!({}))
}

/// The host's recorded failures and successes so far.
fn counts(host: &str) -> (u64, u64) {
    get_overlay_host_reputation_tracker()
        .snapshot(host)
        .map_or((0, 0), |e| (e.total_failures, e.total_successes))
}

/// The facilitator refuses `body` in the reference's words naming `member`,
/// and the resolver records one failure and no success for its host.
async fn refused_and_recorded(body: serde_json::Value, member: &str) {
    let server = host_answering(body.clone()).await;
    let host = server.uri();
    let (failures, successes) = counts(&host);
    let answer = HttpsOverlayLookupFacilitator::new(true)
        .lookup(&host, &question(), None)
        .await;
    match &answer {
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("Malformed lookup response: "),
                "{body}: {text}"
            );
            assert!(text.contains(member), "{body}: {text}");
        }
        Ok(other) => panic!("{body} was read: {other:?}"),
    }
    http_resolver(&host).query(&question(), None).await.unwrap();
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(&host)
        .unwrap_or_else(|| panic!("{body}: the malformed answer is recorded"));
    assert_eq!(entry.total_failures, failures + 1, "{body}: {entry:?}");
    assert_eq!(entry.total_successes, successes, "{body}: {entry:?}");
    assert!(
        entry
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("Malformed lookup response"),
        "{body}: {entry:?}"
    );
}

#[tokio::test]
async fn an_empty_object_is_malformed_and_recorded_768() {
    refused_and_recorded(json!({}), "type").await;
}

#[tokio::test]
async fn an_array_body_is_malformed_and_recorded_768() {
    refused_and_recorded(json!([]), "not a JSON object").await;
}

#[tokio::test]
async fn a_string_body_is_malformed_and_recorded_768() {
    refused_and_recorded(json!("x"), "not a JSON object").await;
}

#[tokio::test]
async fn a_null_body_is_malformed_and_recorded_768() {
    refused_and_recorded(json!(null), "not a JSON object").await;
}

#[tokio::test]
async fn a_number_body_is_malformed_and_recorded_768() {
    refused_and_recorded(json!(5), "not a JSON object").await;
}

#[tokio::test]
async fn a_numeric_type_is_malformed_and_recorded_768() {
    refused_and_recorded(json!({ "type": 5 }), "type").await;
}

#[tokio::test]
async fn an_output_list_without_outputs_is_malformed_and_recorded_768() {
    refused_and_recorded(json!({ "type": "output-list" }), "outputs").await;
}

#[tokio::test]
async fn an_output_list_whose_outputs_is_a_string_is_malformed_and_recorded_768() {
    refused_and_recorded(json!({ "type": "output-list", "outputs": "x" }), "outputs").await;
}

#[tokio::test]
async fn an_item_without_an_output_index_is_malformed_and_recorded_768() {
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [{ "beef": [1] }] }),
        "output 0 outputIndex",
    )
    .await;
}

#[tokio::test]
async fn a_malformed_item_beside_a_good_one_refuses_the_answer_768() {
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [
            { "beef": [1, 2], "outputIndex": 0 },
            { "outputIndex": 1 }
        ] }),
        "output 1 beef",
    )
    .await;
}

#[tokio::test]
async fn a_hex_text_beef_is_no_byte_array_768() {
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [{ "beef": "0102", "outputIndex": 0 }] }),
        "output 0 beef",
    )
    .await;
}

#[tokio::test]
async fn an_empty_beef_is_malformed_768() {
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [{ "beef": [], "outputIndex": 0 }] }),
        "output 0 beef",
    )
    .await;
}

#[tokio::test]
async fn a_context_or_txid_of_the_wrong_kind_is_malformed_768() {
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [
            { "beef": [1], "outputIndex": 0, "context": null }
        ] }),
        "output 0 context",
    )
    .await;
    refused_and_recorded(
        json!({ "type": "output-list", "outputs": [
            { "beef": [1], "outputIndex": 0, "txid": "ab" }
        ] }),
        "output 0 txid",
    )
    .await;
}

#[tokio::test]
async fn a_well_formed_empty_list_stays_a_success_768() {
    let server = host_answering(json!({ "type": "output-list", "outputs": [] })).await;
    let host = server.uri();
    let (failures, successes) = counts(&host);
    let answer = http_resolver(&host).query(&question(), None).await.unwrap();
    assert!(
        matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
        "{answer:?}"
    );
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(&host)
        .expect("an output list is a recorded success");
    assert_eq!(entry.total_successes, successes + 1, "{entry:?}");
    assert_eq!(entry.total_failures, failures, "{entry:?}");
}

#[tokio::test]
async fn the_items_the_normalizer_repairs_are_read_768() {
    // The historical object form of `beef` and `context` (`{}` an empty
    // context), an integral float index and a 64-hex txid: each admitted by
    // `normalizeBRC100ByteFields` then `normalizeLookupOutput`.
    let txid = "ab".repeat(32);
    let server = host_answering(json!({ "type": "output-list", "outputs": [
        { "beef": { "0": 7, "1": 8 }, "outputIndex": 1.0, "context": {}, "txid": txid }
    ] }))
    .await;
    let answer = HttpsOverlayLookupFacilitator::new(true)
        .lookup(&server.uri(), &question(), None)
        .await
        .unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].beef, vec![7, 8]);
    assert_eq!(outputs[0].output_index, 1);
    assert_eq!(outputs[0].context, Some(vec![]));
}
