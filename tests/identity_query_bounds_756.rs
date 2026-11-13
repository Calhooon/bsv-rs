//! #756: `IdentityClient::query` refuses, before the network, a question the
//! reference overlay refuses whole, in the overlay's own words
//! (`ts-stack@edf6e03`
//! `packages/overlays/topics/src/identity/IdentityLookupService.ts:83-123`,
//! `packages/overlays/topics/src/shared/queryValidation.ts`). Until #756 such
//! a question was sent, the overlay's refusal came back from the resolver as
//! an empty answer and the host's reputation was charged for the caller's
//! input. Hardening, not parity: `query` has no reference counterpart; the
//! reference's SDK client hands its two lookups' arguments to its wallet,
//! whose door refuses a bad key or map before any lookup
//! (`IdentityClient.ts:569`, `:614`; `validationHelpers.ts:1535-1587`), the
//! check the other doors make here since #818b (`identity_door_args_818b.rs`).
//!
//! Against `vectors/identity_query_bounds_756.json` (recorded by
//! `support/identity_query_bounds_756.mjs`: the reference's
//! `IdentityLookupService.lookup` over a stub storage manager, Node v22.18.0):
//! each case is the question `query` sends for an `IdentityQuery`; a refused
//! one is refused here in the recorded message with nothing sent, an admitted
//! one is sent. #752's recording facilitator over an injected `.invalid`
//! resolver answering an empty list; no network.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OverlayLookupFacilitator,
};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A facilitator recording each question's query.
struct Recording(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.0.lock().unwrap().push(question.query.clone());
        Ok(LookupAnswer::OutputList { outputs: vec![] })
    }
}

fn client() -> (IdentityClient<ProtoWallet>, Arc<Mutex<Vec<Value>>>) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording(asked.clone()))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    (
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver),
        asked,
    )
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_query_bounds_756.json")).unwrap()
}

/// The `IdentityQuery` whose question is the case's.
fn query_of(case: &Value) -> IdentityQuery {
    let text = |name: &str| case[name].as_str().map(str::to_string);
    let number = |name: &str| case[name].as_u64().map(|n| u32::try_from(n).unwrap());
    IdentityQuery {
        identity_key: text("subject"),
        attributes: case["attributes"].as_array().map(|pairs| {
            pairs
                .iter()
                .map(|p| (p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()))
                .collect::<IndexMap<String, String>>()
        }),
        certificate_type: text("certificateType"),
        certifier: text("certifier"),
        limit: number("limit"),
        offset: number("offset"),
    }
}

/// Each case of `prefix`'s outcome here, the recording's: `Err` the words with
/// nothing sent, or `Ok` with one question sent; every disagreement with the
/// recording named.
async fn agree(prefix: &str) -> usize {
    let vector = vector();
    let cases: Vec<&Value> = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"].as_str().unwrap().starts_with(prefix))
        .collect();
    let mut differ = Vec::new();
    for case in &cases {
        let (client, asked) = client();
        let got = client.query(query_of(case)).await;
        let sent = asked.lock().unwrap().len();
        let name = &case["name"];
        let expected = case["outcome"]["refused"].as_str();
        match (expected, got) {
            (Some(words), Err(Error::IdentityError(message))) if message == words && sent == 0 => {}
            (None, Ok(_)) if sent == 1 => {}
            (_, got) => differ.push(format!("{name}: {got:?}, {sent} sent; {}", case["outcome"])),
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
    cases.len()
}

#[tokio::test]
async fn a_limit_outside_1_to_100_is_refused_in_the_overlays_words_756() {
    assert_eq!(agree("limit_").await, 4);
}

#[tokio::test]
async fn an_offset_above_100000_is_refused_in_the_overlays_words_756() {
    assert_eq!(agree("offset_").await, 3);
}

#[tokio::test]
async fn an_identity_key_the_overlay_refuses_is_refused_in_its_words_756() {
    assert_eq!(agree("key_").await, 12);
}

#[tokio::test]
async fn a_certifier_the_overlay_refuses_is_refused_in_its_words_756() {
    assert_eq!(agree("certifier_").await, 13);
}

#[tokio::test]
async fn a_type_the_overlay_refuses_is_refused_in_its_words_756() {
    assert_eq!(agree("type_").await, 9);
}

#[tokio::test]
async fn attributes_the_overlay_refuses_are_refused_in_its_words_756() {
    assert_eq!(agree("attributes_").await, 3);
    assert_eq!(agree("name_").await, 12);
    assert_eq!(agree("value_").await, 5);
}

#[tokio::test]
async fn of_two_faults_the_overlays_earlier_is_named_756() {
    assert_eq!(agree("two_faults_").await, 9);
}

/// Every case of the vector is one of the groups above.
#[test]
fn every_recorded_case_is_judged_756() {
    assert_eq!(
        vector()["cases"].as_array().unwrap().len(),
        4 + 3 + 12 + 13 + 9 + 3 + 12 + 5 + 9
    );
}

/// The type beside attributes: admitted by the overlay, which then searches
/// by the attributes alone (`IdentityLookupService.ts:132-135`); the question
/// is sent with both, and the local type filter still applies to the answer
/// (#746: an empty answer here, the filter pinned by
/// `identity_query_filters_746.rs`).
#[tokio::test]
async fn a_type_beside_attributes_is_sent_with_both_756() {
    let case = vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "type_beside_attributes")
        .cloned()
        .unwrap();
    assert_eq!(case["outcome"]["reached"], "findByAttribute");
    let (client, asked) = client();
    assert!(client.query(query_of(&case)).await.unwrap().is_empty());
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0]["certificateTypes"][0], case["certificateType"]);
    assert_eq!(asked[0]["attributes"]["email"], "bob");
    assert_eq!(asked[0]["identityKey"], case["subject"]);
}

/// The attributes judged in the order the overlay walks the text `query`
/// sends (#751's fold, the rule read): sent in insertion order, `JSON.parse`
/// holds an array-index name ahead (`IdentityLookupService.ts:113-125`), so of
/// `a.b` (a name fault) then `7` (a value fault) the value is named, as the
/// recording `two_faults_index_value_then_name` has it; the names walked as
/// inserted named the name.
#[tokio::test]
async fn an_index_name_is_judged_ahead_as_the_overlay_walks_it_751() {
    let case = vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "two_faults_index_value_then_name")
        .cloned()
        .unwrap();
    let (client, asked) = client();
    let got = client.query(query_of(&case)).await.unwrap_err();
    assert_eq!(
        got,
        Error::IdentityError(case["outcome"]["refused"].as_str().unwrap().into())
    );
    assert!(asked.lock().unwrap().is_empty());
}

/// #818: the other compressed tag. `requirePublicKey` admits `02` or `03`
/// (`queryValidation.ts:174`, `/^(?:02|03)[0-9a-fA-F]{64}$/`); until #818 no
/// recorded key or certifier was tagged `03`, so a check admitting `02` alone
/// passed every test. The two recorded cases (`03` and G's x, a point of
/// either parity) reach the overlay's storage, and are sent here.
#[tokio::test]
async fn a_key_tagged_03_is_admitted_818() {
    let vector = vector();
    for (name, reached, member) in [
        ("key_prefix_03", "findByIdentityKey", "subject"),
        ("certifier_prefix_03", "findByCertifier", "certifier"),
    ] {
        let case = vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no case {name}"));
        assert!(case[member].as_str().unwrap().starts_with("03"), "{name}");
        assert_eq!(case["outcome"]["reached"], reached, "{name}");
        let (client, asked) = client();
        let got = client.query(query_of(case)).await;
        assert!(
            matches!(got, Ok(ref kept) if kept.is_empty()),
            "{name}: {got:?}"
        );
        assert_eq!(asked.lock().unwrap().len(), 1, "{name}: the question sent");
    }
}
