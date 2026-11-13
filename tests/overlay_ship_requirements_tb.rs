//! Lane fix-tb-acks: the topic broadcaster's acknowledgment requirements as
//! the reference has them (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//!
//! ```text
//! 182: function snapshotAcknowledgmentRequirement(value, topics, label) {
//! 187:   if (value === 'all' || value === 'any') return value
//! 188:   const required = canonicalTopics(value, label, true)
//! 189:   if (required.some(topic => !topics.includes(topic))) {
//! 190:     throw new TypeError(`${label} may only reference topics included in this broadcast.`)
//! 511:     const hostAcknowledgments: Record<string, Set<string>> = Object.create(null)
//! 512:     for (const host of Object.keys(interestedHosts)) hostAcknowledgments[host] = new Set()
//! 572:         code: 'ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED',
//! 596:         code: 'ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED',
//! 615:         code: 'ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED',
//! ```
//!
//! The reference's verdicts are recorded in
//! `vectors/ship_requirements_tb_acks.json` by
//! `support/ship_requirements_tb_acks.mjs` (its own `TopicBroadcaster` on a
//! stub resolver and a scripted facilitator, Node v22.18.0): twenty
//! constructions and 120 broadcasts (two interested hosts by eight
//! behaviours under fifteen requirements). Here the recorded advertisements
//! travel through a real `LookupResolver` (the `ls_ship` host an `.invalid`
//! override, a scripted lookup facilitator) and the broadcast through a
//! scripted broadcast facilitator answering by the host's behaviour.
//! Nothing is dialled.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    AdmittanceInstructions, LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig,
    OutputListItem, OverlayBroadcastFacilitator, OverlayLookupFacilitator, RequireAck, Steak,
    TaggedBEEF, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::transaction::Transaction;
use bsv_rs::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

fn recorded() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| {
        serde_json::from_str(include_str!("vectors/ship_requirements_tb_acks.json")).unwrap()
    })
}

fn topics() -> Vec<String> {
    recorded()["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect()
}

/// A lookup facilitator answering every question with its one answer.
struct Scripted(LookupAnswer);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0.clone())
    }
}

/// A broadcast facilitator answering each host by its behaviour, as the
/// recorder's `BEHAVIOURS`, and counting what it is sent.
struct Behaving {
    behaviours: HashMap<String, String>,
    sent: Mutex<Vec<String>>,
}

fn instructions(admit: bool) -> AdmittanceInstructions {
    AdmittanceInstructions {
        outputs_to_admit: if admit { vec![0] } else { vec![] },
        coins_to_retain: vec![],
        coins_removed: None,
    }
}

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Behaving {
    async fn send(&self, url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        self.sent.lock().unwrap().push(url.to_string());
        let behaviour = self
            .behaviours
            .get(url)
            .map(String::as_str)
            .unwrap_or("fail");
        let each = |admit: &dyn Fn(&str) -> bool| -> Steak {
            tagged
                .topics
                .iter()
                .map(|t| (t.clone(), instructions(admit(t))))
                .collect()
        };
        match behaviour {
            "ack" => Ok(each(&|_| true)),
            "fail" => Err(Error::OverlayError("host refused".into())),
            "empty" => Ok(HashMap::new()),
            "idle" => Ok(each(&|_| false)),
            "alpha_only" => Ok(each(&|t| t == "tm_alpha")),
            "beta_only" => Ok(each(&|t| t == "tm_beta")),
            other => panic!("unknown behaviour {other}"),
        }
    }
}

/// A resolver whose `ls_ship` host (one of its own: the reputation tracker
/// is one global keyed by URL) answers the recorded advertisements.
fn resolver() -> Arc<LookupResolver> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let outputs = recorded()["advertisements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| OutputListItem {
            beef: hex::decode(a["beef"].as_str().unwrap()).unwrap(),
            output_index: 0,
            context: None,
            txid: None,
        })
        .collect();
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted(LookupAnswer::OutputList { outputs }))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![format!(
                "https://ls-ship-{n}.ship-requirements-tb-acks-rs.invalid"
            )],
        )])),
        ..Default::default()
    }))
}

/// A requirement in the reference's form: `'all'`, `'any'` or a list.
fn require_ack(v: &Value) -> RequireAck {
    match v {
        Value::String(s) if s == "all" => RequireAck::All,
        Value::String(s) if s == "any" => RequireAck::Any,
        Value::Array(list) => RequireAck::Some(
            list.iter()
                .map(|t| t.as_str().unwrap().to_string())
                .collect(),
        ),
        other => panic!("not a requirement: {other}"),
    }
}

/// The recorded requirement as this crate's configuration, an absent field
/// this crate's default (`None` for all hosts, the reference's `[]`; `All`
/// for any host, the reference's `'all'`).
fn config(requirement: &Value, facilitator: Arc<Behaving>) -> TopicBroadcasterConfig {
    let mut config = TopicBroadcasterConfig {
        resolver: Some(resolver()),
        facilitator: Some(facilitator),
        ..Default::default()
    };
    if let Some(all) = requirement.get("all") {
        config.require_ack_from_all_hosts = require_ack(all);
    }
    if let Some(any) = requirement.get("any") {
        config.require_ack_from_any_host = require_ack(any);
    }
    if let Some(specific) = requirement.get("specific") {
        config.require_ack_from_specific_hosts = specific
            .as_object()
            .unwrap()
            .iter()
            .map(|(host, r)| (host.clone(), require_ack(r)))
            .collect();
    }
    config
}

fn behaving(case: &Value) -> Arc<Behaving> {
    let hosts = &recorded()["hosts"];
    let behaviours = case["behaviours"]
        .as_object()
        .map(|b| {
            b.iter()
                .map(|(k, v)| {
                    (
                        hosts[k].as_str().unwrap().to_string(),
                        v.as_str().unwrap().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Arc::new(Behaving {
        behaviours,
        sent: Mutex::new(vec![]),
    })
}

/// A broadcast's verdict in the recording's terms: status, code,
/// description, message.
type Verdict = (String, Option<String>, Option<String>, Option<String>);

async fn broadcast(case: &Value) -> (Verdict, Vec<String>) {
    let facilitator = behaving(case);
    let b = TopicBroadcaster::new(topics(), config(&case["requirement"], facilitator.clone()))
        .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
    let subject = Transaction::from_beef(
        &hex::decode(recorded()["advertisements"][0]["beef"].as_str().unwrap()).unwrap(),
        None,
    )
    .unwrap();
    let verdict = match b.broadcast_tx(&subject).await {
        Ok(r) => ("success".into(), None, None, Some(r.message)),
        Err(f) => ("error".into(), Some(f.code), Some(f.description), None),
    };
    let mut sent = facilitator.sent.lock().unwrap().clone();
    sent.sort();
    (verdict, sent)
}

fn recorded_verdict(case: &Value) -> Verdict {
    let s = |k: &str| case[k].as_str().map(str::to_string);
    (
        s("status").unwrap(),
        s("code"),
        s("description"),
        s("message"),
    )
}

fn broadcasts() -> &'static Vec<Value> {
    let b = recorded()["broadcasts"].as_array().unwrap();
    assert_eq!(b.len(), 120);
    b
}

/// Rule 1: a requirement naming a topic outside the broadcast's (or not a
/// bounded list of unique canonical names) refuses `new` in the reference's
/// words, for the all-host, the any-host and each specific host's
/// requirement, in the reference's order; nothing can be sent.
#[tokio::test]
async fn a_requirement_naming_a_topic_outside_the_broadcast_refuses_new_tb_acks() {
    let cases = recorded()["construction"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let facilitator = behaving(case);
        let ours = TopicBroadcaster::new(topics(), config(&case["requirement"], facilitator))
            .map(|_| ())
            .map_err(|e| e.to_string());
        let theirs = match case["constructor_refusal"].as_str() {
            Some(words) => Err(Error::OverlayError(words.into()).to_string()),
            None => Ok(()),
        };
        assert_eq!(ours, theirs, "{name}");
    }
}

/// Rule 1's side effect: under a requirement naming another topic, the base
/// sent the transaction to every host, then reported it failed; here
/// nothing is built, so nothing is sent.
#[tokio::test]
async fn nothing_is_sent_under_a_requirement_the_reference_refuses_tb_acks() {
    for requirement in [
        serde_json::json!({ "all": ["tm_other"] }),
        serde_json::json!({ "any": ["tm_other"] }),
        serde_json::json!({ "specific": { recorded()["hosts"]["a"].as_str().unwrap(): ["tm_other"] } }),
    ] {
        let case = serde_json::json!({ "behaviours": { "a": "ack", "b": "ack" } });
        let facilitator = behaving(&case);
        let built = TopicBroadcaster::new(topics(), config(&requirement, facilitator.clone()));
        let subject = Transaction::from_beef(
            &hex::decode(recorded()["advertisements"][0]["beef"].as_str().unwrap()).unwrap(),
            None,
        )
        .unwrap();
        if let Ok(b) = built {
            let _ = b.broadcast_tx(&subject).await;
        }
        assert_eq!(
            facilitator.sent.lock().unwrap().clone(),
            Vec::<String>::new(),
            "{requirement}"
        );
    }
}

/// Rule 2: every interested host is seeded with an empty set, so a host
/// that failed (`fail`) or answered no topic (`empty`) acknowledged nothing
/// under each requirement: the verdict (success or not) is the reference's
/// on every broadcast where a host failed.
#[tokio::test]
async fn a_failed_host_acknowledges_nothing_under_every_requirement_tb_acks() {
    let mut judged = 0;
    for case in broadcasts() {
        let b = &case["behaviours"];
        if !(b["a"] == "fail" || b["b"] == "fail" || b["b"] == "empty") {
            continue;
        }
        judged += 1;
        let ((status, ..), sent) = broadcast(case).await;
        assert_eq!(status, case["status"].as_str().unwrap(), "{}", case["name"]);
        assert_eq!(sent.len(), 2, "{}", case["name"]);
    }
    assert_eq!(judged, 45);
}

/// The any-host requirement's topic list asks one host for every listed
/// topic (`#resolveAnyHostRequirement`, `:584`, `require: 'all'`): one host
/// acknowledging alpha and the other beta fails `['tm_alpha', 'tm_beta']`.
#[tokio::test]
async fn an_any_host_topic_list_asks_one_host_for_every_topic_tb_acks() {
    let case = broadcasts()
        .iter()
        .find(|c| c["name"] == "alpha_only_beta_only__any_host_both")
        .unwrap();
    assert_eq!(case["code"], "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED");
    assert_eq!(broadcast(case).await.0, recorded_verdict(case));
}

/// Rule 3: the failed requirement's code and description are the
/// reference's, by which requirement failed, in the reference's order
/// (all hosts, any host, specific hosts); and every other verdict, success
/// message included, the reference's: all 120 broadcasts.
#[tokio::test]
async fn the_failed_requirement_carries_the_references_code_and_description_tb_acks() {
    // One failure of each requirement, each a failure on the base too, so
    // the code and the description alone decide.
    for (name, code) in [
        (
            "idle_idle__all_hosts_all",
            "ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED",
        ),
        (
            "idle_idle__any_host_any",
            "ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED",
        ),
        (
            "ack_ack__specific_c_empty",
            "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED",
        ),
    ] {
        let case = broadcasts().iter().find(|c| c["name"] == name).unwrap();
        assert_eq!(case["code"], code, "{name}");
        assert_eq!(broadcast(case).await.0, recorded_verdict(case), "{name}");
    }
    let mut codes = HashMap::<String, usize>::new();
    for case in broadcasts() {
        let (ours, _) = broadcast(case).await;
        assert_eq!(ours, recorded_verdict(case), "{}", case["name"]);
        if let Some(code) = &ours.1 {
            *codes.entry(code.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        codes,
        HashMap::from([
            ("ERR_REQUIRE_ACK_FROM_ALL_HOSTS_FAILED".to_string(), 20),
            ("ERR_REQUIRE_ACK_FROM_ANY_HOST_FAILED".to_string(), 9),
            ("ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED".to_string(), 23),
            ("ERR_ALL_HOSTS_REJECTED".to_string(), 15),
        ])
    );
}

// =============================================================================
// #815: the broadcast topics themselves, as the reference's constructor
// reads them (`SHIPBroadcaster.ts:420`, `this.topics =
// canonicalTopics(topics, 'Broadcast topics')`; `:156-179`: not an array,
// empty or over 64 `<label> must be a bounded array of canonical topic
// names.`, a name failing `/^(?=.{1,50}$)tm_[a-z]+(?:_[a-z]+)*$/` (`:171`)
// or seen before `<label> must contain unique canonical tm_ topic names.`),
// ahead of the requirements. Recorded as `broadcast_topics`.
// =============================================================================

fn broadcast_topic_case(name: &str) -> &'static Value {
    recorded()["broadcast_topics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
}

/// `new` over the case's own topics and requirement, against the recording.
fn assert_broadcast_topics_case(name: &str) {
    let case = broadcast_topic_case(name);
    let topics: Vec<String> = case["topics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    let facilitator = behaving(case);
    let ours = TopicBroadcaster::new(topics, config(&case["requirement"], facilitator))
        .map(|_| ())
        .map_err(|e| e.to_string());
    let theirs = match case["constructor_refusal"].as_str() {
        Some(words) => Err(Error::OverlayError(words.into()).to_string()),
        None => Ok(()),
    };
    assert_eq!(ours, theirs, "{name}");
}

#[test]
fn a_non_canonical_broadcast_topic_is_refused_at_new_815() {
    for name in [
        "not_canonical_upper_case",
        "not_canonical_prefix",
        "not_canonical_digit",
        "not_canonical_trailing_underscore",
        "not_canonical_double_underscore",
        "not_canonical_bare_prefix",
        "not_canonical_after_a_canonical_one",
        // The issue's line: a requirement naming `tm_Foo` is refused at the
        // broadcast topics, ahead of the requirement, as there.
        "not_canonical_named_by_a_requirement_too",
        // The empty list in the reference's words (until #815 `At least one
        // topic is required for broadcast.`).
        "empty",
    ] {
        assert_broadcast_topics_case(name);
    }
    assert_eq!(
        broadcast_topic_case("not_canonical_upper_case")["constructor_refusal"],
        "Broadcast topics must contain unique canonical tm_ topic names."
    );
}

#[test]
fn sixty_five_broadcast_topics_are_refused_815() {
    assert_broadcast_topics_case("sixty_four");
    assert_broadcast_topics_case("sixty_five");
    assert_eq!(
        broadcast_topic_case("sixty_five")["constructor_refusal"],
        "Broadcast topics must be a bounded array of canonical topic names."
    );
}

#[test]
fn a_repeated_broadcast_topic_is_refused_815() {
    assert_broadcast_topics_case("repeated");
    assert_eq!(
        broadcast_topic_case("repeated")["constructor_refusal"],
        "Broadcast topics must contain unique canonical tm_ topic names."
    );
}

#[test]
fn fifty_characters_pass_and_fifty_one_are_refused_815() {
    assert_broadcast_topics_case("fifty_characters");
    assert_broadcast_topics_case("fifty_one_characters");
    assert_eq!(
        broadcast_topic_case("fifty_characters")["constructed"],
        true
    );
}

/// Every recorded broadcast-topics case, counted.
#[test]
fn every_recorded_broadcast_topics_case_is_the_references_815() {
    let cases = recorded()["broadcast_topics"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        assert_broadcast_topics_case(case["name"].as_str().unwrap());
    }
}

/// The pin the tb-acks reads asked for: a requirement list of exactly 64
/// topics is taken (`canonicalTopics`' `value.length > MAX_SHIP_TOPICS`,
/// `:159`; the `>` of `requirements.rs`), 65 refused in the requirement's
/// words.
#[test]
fn a_requirement_list_of_exactly_64_topics_is_taken_815() {
    assert_broadcast_topics_case("sixty_four_required_by_all_hosts");
    assert_eq!(
        broadcast_topic_case("sixty_four_required_by_all_hosts")["constructed"],
        true
    );
    assert_broadcast_topics_case("sixty_five_required_of_sixty_four");
}

/// The pin the tb-acks reads asked for: an interested specific host whose
/// requirement is `RequireAck::None` (no reference form; its `continue`
/// for a requirement that is neither `'all'`, `'any'` nor a list,
/// `:674-677`) is passed over once it is in the map: host `b`, interested
/// and acknowledging nothing (`idle`), passes under `None` and fails under
/// `All` (`ack_idle__specific_b_all` is recorded a failure).
#[tokio::test]
async fn a_specific_host_with_no_requirement_is_passed_over_815() {
    let b_host = recorded()["hosts"]["b"].as_str().unwrap().to_string();
    let subject = Transaction::from_beef(
        &hex::decode(recorded()["advertisements"][0]["beef"].as_str().unwrap()).unwrap(),
        None,
    )
    .unwrap();
    for (requirement, passes) in [(RequireAck::None, true), (RequireAck::All, false)] {
        let facilitator =
            behaving(&serde_json::json!({ "behaviours": { "a": "ack", "b": "idle" } }));
        let mut cfg = config(&serde_json::json!({ "any": [] }), facilitator);
        cfg.require_ack_from_specific_hosts =
            HashMap::from([(b_host.clone(), requirement.clone())]);
        let b = TopicBroadcaster::new(topics(), cfg).unwrap();
        let verdict = b.broadcast_tx(&subject).await;
        assert_eq!(verdict.is_ok(), passes, "{requirement:?}: {verdict:?}");
        if !passes {
            assert_eq!(
                verdict.unwrap_err().code,
                "ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED"
            );
        }
    }
}
