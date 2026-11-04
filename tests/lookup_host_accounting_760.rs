//! #760: the lookup resolver's host accounting is the reference's. Any
//! output list, the empty one included, records a success, and a freeform
//! answer records nothing (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:2395-2402`):
//!
//! ```text
//! if (isOutputListAnswer(normalizedAnswer)) {
//!   this.hostReputation.recordSuccess(host, Date.now() - startedAt)
//!   return normalizedAnswer
//! }
//! // A valid freeform response is neutral: it proves this request reached the
//! // service, but it must not erase an availability backoff established by a
//! // concurrent failing request and cannot contribute to output aggregation.
//! if (isFreeformAnswer(normalizedAnswer)) return normalizedAnswer
//! ```
//!
//! and `ts-sdk@9e3ede6` `src/overlay-tools/LookupResolver.ts:518-528`
//! (`answer.type === 'output-list' && Array.isArray((answer).outputs)`, then
//! `recordSuccess`). Until #760 an empty output list was a failure here
//! ("Invalid lookup response") and a freeform answer a success, so three
//! empty answers backed a host off for every resolver in the process (the
//! tracker is one global keyed by host URL, two failures of grace). Each test
//! names its own `.invalid` host, as the tracker is shared by the binary.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    get_overlay_host_reputation_tracker, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, OverlayLookupFacilitator,
};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const SERVICE: &str = "ls_host_accounting_760";

/// A facilitator recording each question's query, as #752's does, and
/// answering from its script (an empty output list once the script is spent).
struct Recording {
    asked: Arc<Mutex<Vec<Value>>>,
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
        self.asked.lock().unwrap().push(question.query.clone());
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(LookupAnswer::OutputList { outputs: vec![] }))
    }
}

fn resolver(
    host: &str,
    script: Vec<bsv_rs::Result<LookupAnswer>>,
) -> (LookupResolver, Arc<Mutex<Vec<Value>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording {
            asked: asked.clone(),
            script: Mutex::new(script.into()),
        })),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            SERVICE.to_string(),
            vec![host.to_string()],
        )])),
        ..Default::default()
    });
    (resolver, asked)
}

fn question(n: u32) -> LookupQuestion {
    LookupQuestion::new(SERVICE, json!({ "n": n }))
}

fn failure() -> bsv_rs::Result<LookupAnswer> {
    Err(bsv_rs::Error::OverlayError("scripted host failure".into()))
}

#[tokio::test]
async fn four_empty_output_lists_from_one_host_leave_it_answering_760() {
    let (resolver, asked) = resolver("https://empty-answers-760.invalid", vec![]);
    for n in 1..=4 {
        match resolver.query(&question(n), None).await {
            Ok(LookupAnswer::OutputList { outputs }) => assert!(outputs.is_empty()),
            other => panic!("lookup {n}: {other:?}"),
        }
    }
    let asked = asked.lock().unwrap().clone();
    assert_eq!(
        asked,
        (1..=4).map(|n| json!({ "n": n })).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_freeform_answer_after_two_failures_keeps_the_backoff_coming_760() {
    let freeform = Ok(LookupAnswer::Freeform {
        result: json!({ "neutral": true }),
    });
    let script = vec![failure(), failure(), freeform, failure()];
    let (resolver, asked) = resolver("https://freeform-neutral-760.invalid", script);
    for n in 1..=3 {
        resolver.query(&question(n), None).await.unwrap();
    }
    // The third failure in a row: past the two of grace, the host backs off.
    resolver.query(&question(4), None).await.unwrap();
    let refused = resolver.query(&question(5), None).await.unwrap_err();
    assert!(
        refused.to_string().contains(&format!(
            "All competent hosts for {SERVICE} are backing off"
        )),
        "{refused}"
    );
    assert_eq!(asked.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn a_host_that_only_ever_answered_freeform_has_no_tracker_record_760() {
    // The #761 strength read's line: a freeform answer is neutral, so a host
    // that never answered anything else has no record at all, neither a
    // success nor a failure nor a latency sample.
    let host = "https://freeform-only-760.invalid";
    let freeform = || {
        Ok(LookupAnswer::Freeform {
            result: json!({ "neutral": true }),
        })
    };
    let (resolver, asked) = resolver(host, vec![freeform(), freeform()]);
    for n in 1..=2 {
        resolver
            .query(&question(n), None)
            .await
            .unwrap_or_else(|e| panic!("lookup {n}: {e}"));
    }
    assert_eq!(asked.lock().unwrap().len(), 2);
    assert!(
        get_overlay_host_reputation_tracker()
            .snapshot(host)
            .is_none(),
        "a freeform-only host must leave no tracker record"
    );
}
