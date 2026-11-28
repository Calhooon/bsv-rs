//! A freeform answer from one queried host does not decide a lookup's result.
//!
//! On the stable line before this fix, `LookupResolver::query` returned the
//! earliest `Freeform` answer over the aggregated output list, so one host
//! answering freeform could substitute its own JSON as the lookup result or
//! suppress the honest hosts' aggregated `OutputList` (a lookup returns
//! nothing; a SHIP discovery finds no interested host, so a broadcast fails).
//! No path of the reference's `query` returns a freeform answer
//! (`ts-stack@edf6e03` `LookupResolver.ts:1369-1375`, `:1445-1450`): a
//! freeform host is counted and never answered. These tests assert the fixed
//! behaviour — `query` answers the merged output list in every case — and so
//! fail on the pre-fix stable code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code
#![cfg(feature = "overlay")]

use async_trait::async_trait;
use bsv_rs::overlay::{
    create_signed_overlay_admin_token, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, NetworkPreset, OutputListItem, OverlayLookupFacilitator, Protocol,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::Result;
use std::collections::HashMap;
use std::sync::Arc;

/// A facilitator that answers each queried host with a pre-set answer, keyed
/// by the host string the resolver passes it.
struct ByHost {
    answers: HashMap<String, LookupAnswer>,
}

#[async_trait(?Send)]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        Ok(self
            .answers
            .get(url)
            .cloned()
            .unwrap_or_else(LookupAnswer::empty_output_list))
    }
}

fn freeform() -> LookupAnswer {
    LookupAnswer::Freeform {
        result: serde_json::json!({ "attacker": "controls this" }),
    }
}

/// One output carrying a parseable BEEF (so `query` keeps it), locked by the
/// given script.
fn output_of(script: &LockingScript) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script.clone()))
        .unwrap();
    OutputListItem {
        beef: tx.to_beef(true).unwrap(),
        output_index: 0,
        context: None,
    }
}

fn resolver_over(service: &str, answers: HashMap<String, LookupAnswer>) -> LookupResolver {
    let hosts: Vec<String> = answers.keys().cloned().collect();
    LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(ByHost { answers })),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(service.to_string(), hosts)])),
        ..Default::default()
    })
}

/// `query`, one host, freeform: the untrusted JSON is no longer handed back as
/// the lookup result; the answer is the (empty) merged output list.
#[tokio::test]
async fn a_lone_freeform_answer_is_not_returned_as_the_lookup_result() {
    let answers = HashMap::from([("http://host-a".to_string(), freeform())]);
    let resolver = resolver_over("ls_test", answers);
    let q = LookupQuestion::new("ls_test", serde_json::json!({}));

    let answer = resolver.query(&q, Some(30_000)).await.unwrap();

    assert!(
        matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
        "a freeform answer must not be returned as the result, got {answer:?}"
    );
}

/// `query`, two hosts: an honest host's aggregated outputs are not discarded
/// because another host answered freeform.
#[tokio::test]
async fn an_honest_hosts_outputs_are_not_discarded_by_a_freeform_host() {
    let script = LockingScript::from_hex("51").unwrap(); // OP_1, any parseable script
    let answers = HashMap::from([
        ("http://host-a".to_string(), freeform()),
        (
            "http://host-b".to_string(),
            LookupAnswer::OutputList {
                outputs: vec![output_of(&script)],
            },
        ),
    ]);
    let resolver = resolver_over("ls_test", answers);
    let q = LookupQuestion::new("ls_test", serde_json::json!({}));

    let answer = resolver.query(&q, Some(30_000)).await.unwrap();

    match answer {
        LookupAnswer::OutputList { outputs } => {
            assert_eq!(
                outputs.len(),
                1,
                "the honest host's one output must survive the freeform host"
            );
        }
        other => panic!("expected the honest output list, got {other:?}"),
    }
}

/// SHIP discovery (downstream of `query`): a freeform `ls_ship` host beside an
/// honestly advertising one no longer suppresses the advertised host.
#[tokio::test]
async fn ship_discovery_keeps_an_advertising_host_beside_a_freeform_host() {
    const HOST: &str = "https://advertised.invalid";
    let identity = PrivateKey::random();
    // A valid, signed SHIP advertisement for the broadcaster's topic.
    let token = create_signed_overlay_admin_token(&identity, Protocol::Ship, HOST, "tm_kvstore");

    let answers = HashMap::from([
        ("http://host-a".to_string(), freeform()),
        (
            "http://host-b".to_string(),
            LookupAnswer::OutputList {
                outputs: vec![output_of(&token)],
            },
        ),
    ]);
    let lookup = resolver_over("ls_ship", answers);
    let broadcaster = TopicBroadcaster::new(
        vec!["tm_kvstore".to_string()],
        TopicBroadcasterConfig {
            network_preset: NetworkPreset::Mainnet,
            resolver: Some(Arc::new(lookup)),
            ..Default::default()
        },
    )
    .unwrap();

    let hosts: Vec<String> = broadcaster
        .find_interested_hosts()
        .await
        .unwrap()
        .into_keys()
        .collect();

    assert!(
        hosts.iter().any(|h| h == HOST),
        "the advertised host must be found despite a freeform host, got {hosts:?}"
    );
}
