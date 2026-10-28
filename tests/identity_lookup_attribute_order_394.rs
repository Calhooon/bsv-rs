//! The identity lookup's attributes are sent in insertion order (#394, the
//! keeper's word of 2026-10-28 04:5xZ under the owner's ruling (c)): the
//! reference holds them in a `Record` and writes them through
//! `JSON.stringify` (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:667`), which keeps that
//! order; a `serde_json::Value` sorts its keys, so `resolve_by_attributes`
//! sends the `IndexMap`'s text through the facilitator's `lookup_ordered`
//! (#394's fold), `LookupQuestion` unchanged. Every other lookup body keeps its
//! bytes: `query` before `service`, the query as its `Value` writes it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "identity", feature = "http"))]

use bsv_rs::identity::{IdentityClient, DEFAULT_SOCIALCERT_CERTIFIER};
use bsv_rs::overlay::{
    HttpsOverlayLookupFacilitator, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, OverlayLookupFacilitator,
};
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A lookup host that answers every question with no outputs.
async fn lookup_host() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "type": "output-list", "outputs": [] })),
        )
        .mount(&server)
        .await;
    server
}

/// The bodies the host received, as text.
async fn bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect()
}

/// `resolve_by_attributes` against `server` as the one `ls_identity` host.
async fn resolve(server: &MockServer, attributes: IndexMap<String, String>) {
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(HttpsOverlayLookupFacilitator::new(true))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec![server.uri()],
        )])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let found = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    assert!(found.is_empty());
}

#[tokio::test]
async fn resolve_by_attributes_sends_its_attributes_in_insertion_order() {
    let server = lookup_host().await;
    let attributes = IndexMap::from([
        ("zeta".to_string(), "z".to_string()),
        ("alpha".to_string(), "a".to_string()),
    ]);
    resolve(&server, attributes).await;
    assert_eq!(
        bodies(&server).await,
        [format!(
            r#"{{"query":{{"attributes":{{"zeta":"z","alpha":"a"}},"certifiers":["{DEFAULT_SOCIALCERT_CERTIFIER}"]}},"service":"ls_identity"}}"#
        )]
    );
}

#[tokio::test]
async fn a_single_attribute_is_still_sent_as_the_any_matcher() {
    let server = lookup_host().await;
    resolve(&server, IndexMap::from([("email".into(), "x".into())])).await;
    assert_eq!(
        bodies(&server).await,
        [format!(
            r#"{{"query":{{"attributes":{{"any":"x"}},"certifiers":["{DEFAULT_SOCIALCERT_CERTIFIER}"]}},"service":"ls_identity"}}"#
        )]
    );
}

#[tokio::test]
async fn a_question_built_from_a_value_keeps_the_body_it_always_had() {
    let server = lookup_host().await;
    let query = serde_json::json!({ "zeta": 1, "alpha": { "y": 2, "b": 3 } });
    let question = LookupQuestion::new("ls_test", query.clone());
    HttpsOverlayLookupFacilitator::new(true)
        .lookup(&server.uri(), &question, None)
        .await
        .unwrap();
    // The body before #394's fold: `json!` of both members, keys sorted.
    let before = serde_json::json!({ "service": "ls_test", "query": query });
    assert_eq!(bodies(&server).await, [before.to_string()]);
}

#[tokio::test]
async fn the_https_facilitator_sends_the_query_text_it_is_given() {
    let server = lookup_host().await;
    let question = LookupQuestion::new("ls_test", serde_json::json!({ "zeta": 1, "alpha": 2 }));
    let text = RawValue::from_string(r#"{"zeta":1,"alpha":2}"#.into()).unwrap();
    HttpsOverlayLookupFacilitator::new(true)
        .lookup_ordered(&server.uri(), &question, Some(&text), None)
        .await
        .unwrap();
    assert_eq!(
        bodies(&server).await,
        [r#"{"query":{"zeta":1,"alpha":2},"service":"ls_test"}"#]
    );
}

/// A facilitator that records each question and answers no outputs; it
/// keeps the trait's default `lookup_ordered`.
#[derive(Default)]
struct Recording(Mutex<Vec<LookupQuestion>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.0.lock().unwrap().push(question.clone());
        Ok(LookupAnswer::OutputList { outputs: vec![] })
    }
}

#[tokio::test]
async fn a_facilitator_with_the_default_is_asked_through_lookup() {
    let recording = Arc::new(Recording::default());
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(recording.clone()),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://identity-lookup.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([
        ("zeta".to_string(), "z".to_string()),
        ("alpha".to_string(), "a".to_string()),
    ]);
    client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let asked = recording.0.lock().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].service, "ls_identity");
    assert_eq!(
        asked[0].query,
        serde_json::json!({
            "attributes": { "zeta": "z", "alpha": "a" },
            "certifiers": [DEFAULT_SOCIALCERT_CERTIFIER],
        })
    );
}
