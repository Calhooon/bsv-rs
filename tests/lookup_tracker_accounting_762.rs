//! #762: the two residues beside #760's row. A SLAP tracker's question is the
//! reference's tracked call, as a host's is (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:1974`,
//! `lookupSlapTrackerHosts` calling `lookupHostWithTracking`), so its answer
//! is accounted by `completeTrackedLookup` (`:2379-2406`): an output list a
//! success, a freeform answer neutral, anything the normalizer cannot read a
//! failure (`Malformed lookup response`). And the normalizer reads a freeform
//! answer only with an own `result` member (`:430-433`):
//!
//! ```text
//! if (answer == null || answer.type !== 'freeform' || !Object.hasOwn(answer, 'result')) {
//!   return undefined
//! }
//! ```
//!
//! Until #762 the SLAP path recorded nothing for a formula answer from a
//! tracker, and the HTTP facilitator read `{"type":"freeform"}` as
//! `Freeform { result: Null }`. Each test names its own tracker or `wiremock`
//! host, as the tracker is one global keyed by URL.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    get_overlay_host_reputation_tracker, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, OverlayLookupFacilitator,
};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const SERVICE: &str = "ls_tracker_accounting_762";

/// #760's scripted facilitator, recording the service of each question.
struct Recording {
    asked: Arc<Mutex<Vec<String>>>,
    script: Mutex<VecDeque<bsv_rs::Result<LookupAnswer>>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.asked.lock().unwrap().push(question.service.clone());
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(LookupAnswer::OutputList { outputs: vec![] }))
    }
}

/// A resolver whose one SLAP tracker is `tracker`, no host overrides.
fn tracker_resolver(
    tracker: &str,
    script: Vec<bsv_rs::Result<LookupAnswer>>,
) -> (LookupResolver, Arc<Mutex<Vec<String>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording {
            asked: asked.clone(),
            script: Mutex::new(script.into()),
        })),
        slap_trackers: Some(vec![tracker.to_string()]),
        ..Default::default()
    });
    (resolver, asked)
}

fn formula() -> bsv_rs::Result<LookupAnswer> {
    Ok(LookupAnswer::Formula { formulas: vec![] })
}

#[tokio::test]
async fn three_formula_answers_from_a_slap_tracker_back_it_off_762() {
    let tracker = "https://formula-tracker-762.invalid";
    let (resolver, asked) = tracker_resolver(tracker, vec![formula(), formula(), formula()]);
    for n in 1..=3 {
        let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
        assert!(hosts.is_empty(), "discovery {n}: {hosts:?}");
    }
    let entry = get_overlay_host_reputation_tracker()
        .snapshot(tracker)
        .expect("a formula answer from a tracker is recorded");
    assert_eq!(entry.consecutive_failures, 3);
    assert_eq!(entry.last_error.as_deref(), Some("Invalid lookup response"));
    // The third failure is past the two of grace: the tracker is backed off,
    // and the next discovery does not ask it (`find_competent_hosts` skips a
    // tracker in backoff, answering no hosts).
    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert!(hosts.is_empty());
    assert_eq!(
        asked.lock().unwrap().len(),
        3,
        "the backed-off tracker was asked"
    );
    assert_eq!(asked.lock().unwrap()[0], "ls_slap");
}

#[tokio::test]
async fn a_slap_tracker_that_only_ever_answered_freeform_has_no_record_762() {
    let tracker = "https://freeform-tracker-762.invalid";
    let freeform = || {
        Ok(LookupAnswer::Freeform {
            result: json!({ "neutral": true }),
        })
    };
    let (resolver, asked) = tracker_resolver(tracker, vec![freeform(), freeform()]);
    for n in 1..=2 {
        let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
        assert!(hosts.is_empty(), "discovery {n}: {hosts:?}");
    }
    assert_eq!(asked.lock().unwrap().len(), 2);
    assert!(
        get_overlay_host_reputation_tracker()
            .snapshot(tracker)
            .is_none(),
        "a freeform-only tracker must leave no tracker record"
    );
}

#[cfg(feature = "http")]
mod http_answers {
    use super::*;
    use bsv_rs::overlay::HttpsOverlayLookupFacilitator;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn host_answering(body: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
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

    #[tokio::test]
    async fn a_freeform_answer_without_a_result_member_is_malformed_and_recorded_762() {
        let server = host_answering(json!({ "type": "freeform" })).await;
        let host = server.uri();
        let answer = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), None)
            .await;
        match &answer {
            Err(e) => assert!(e.to_string().contains("Malformed lookup response"), "{e}"),
            Ok(other) => panic!("a freeform answer without result was read: {other:?}"),
        }
        // Through the resolver: the facilitator's error is the host's failure.
        http_resolver(&host).query(&question(), None).await.unwrap();
        let entry = get_overlay_host_reputation_tracker()
            .snapshot(&host)
            .expect("the malformed answer is recorded");
        assert_eq!(entry.total_failures, 1);
        assert_eq!(entry.total_successes, 0);
        assert!(
            entry
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("Malformed lookup response"),
            "{entry:?}"
        );
    }

    #[tokio::test]
    async fn a_freeform_answer_with_a_null_result_is_an_answer_762() {
        let server = host_answering(json!({ "type": "freeform", "result": null })).await;
        let host = server.uri();
        let answer = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), None)
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::Freeform { result } if result.is_null()),
            "{answer:?}"
        );
        let answer = http_resolver(&host).query(&question(), None).await.unwrap();
        assert!(
            matches!(&answer, LookupAnswer::Freeform { result } if result.is_null()),
            "{answer:?}"
        );
        assert!(
            get_overlay_host_reputation_tracker()
                .snapshot(&host)
                .is_none(),
            "a freeform answer is neutral"
        );
    }
}
