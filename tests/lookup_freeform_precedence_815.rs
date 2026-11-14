//! #815: a freeform answer from one host no longer blanks a lookup;
//! `LookupResolver::query` answers the merged output list, as the reference
//! does.
//!
//! The reference counts a freeform host and answers the output list
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts`):
//!
//! ```text
//! 1085:  recordFreeformAnswer(): void {
//! 1086:    if (!this.closed) this.freeformHosts++
//! 1087:  }
//! 1123:  snapshot(isFinal: boolean): LookupAnswerProgress {
//! 1124:    return {
//! 1125:      type: 'output-list',
//! 1126:      outputs: Array.from(this.outputsMap.values()),
//! 1135:      freeformHosts: this.freeformHosts,
//! 1501:    if (isOutputListAnswer(answer)) {
//! 1502:      session.recordOutputAnswer(answer)
//! 1510:      return
//! 1511:    }
//! 1512:    session.recordFreeformAnswer()
//! 1374:    return (await this.queryDetailed(question, timeout, options)).answer
//! 1445:    return {
//! 1446:      answer: {
//! 1447:        type: 'output-list',
//! 1448:        outputs: progress.outputs
//! 1449:      },
//! ```
//!
//! and `query` (`:1369-1375`) returns `queryDetailed`'s `answer`: no path of
//! the reference's `query` returns a freeform answer. A freeform answer is
//! neutral for its host's reputation (`:2399-2402`). Until #815 this crate
//! returned the earliest freeform answer over the aggregate, so one host
//! answering freeform blanked the output lists every other host gave.
//!
//! The shapes and the reference's answers are
//! `vectors/lookup_freeform_precedence_815.json`, recorded by
//! `support/lookup_freeform_precedence_815.mjs` under Node v22.18.0 against
//! the reference's own `LookupResolver` with a scripted facilitator; the
//! BEEFs are this crate's writer's (the ignored emitter below). Every host is
//! an `.invalid` name answered by the scripted facilitator, never dialled;
//! each test runs its shapes on hosts of its own (the reputation tracker is
//! one global keyed by URL).
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    get_overlay_host_reputation_tracker, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::to_hex;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const SERVICE: &str = "ls_freeform_815";

/// Transaction `name` (`A` or `B`): one made-up input and one `OP_TRUE`
/// output whose amount tells them apart, proven by a block of its own (a
/// lone leaf at offset 0), written by this crate's BEEF writer.
fn beef_of(name: &str) -> (Vec<u8>, String) {
    let satoshis = if name == "A" { 1 } else { 2 };
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("15".repeat(32).parse().unwrap(), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(
        satoshis,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let mut beef = Beef::new();
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let index = beef.merge_bump(MerklePath::new(815 + satoshis as u32, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    (beef.to_binary().expect("the BEEF is writable"), tx.id())
}

/// The shapes the recorder drives: each host's answer in rank order, a
/// freeform result or an output list (an output naming its transaction,
/// index, hint and context bytes).
fn shapes() -> Value {
    let o = |tx: &str, hint: Option<&str>, context: u8| json!({ "tx": tx, "outputIndex": 0, "hint": hint, "context": [context] });
    let free = |role: &str, result: Value| json!({ "role": role, "freeform": result });
    let list = |role: &str, outputs: Vec<Value>| json!({ "role": role, "outputs": outputs });
    json!([
        { "name": "freeform_then_list", "hosts": [
            free("free", json!({ "note": "freeform" })),
            list("list", vec![o("A", Some("A"), 1)]) ] },
        { "name": "list_then_freeform", "hosts": [
            list("list", vec![o("A", Some("A"), 1)]),
            free("free", json!({ "note": "freeform" })) ] },
        { "name": "every_host_freeform", "hosts": [
            free("free", json!({ "note": "one" })),
            free("free_2", json!("two")) ] },
        { "name": "lone_freeform", "hosts": [
            free("free", json!(null)) ] },
        { "name": "freeform_and_empty_list", "hosts": [
            free("free", json!({ "note": "freeform" })),
            list("empty", vec![]) ] },
        { "name": "list_freeform_list", "hosts": [
            list("list", vec![o("A", Some("A"), 1)]),
            free("free", json!([1, 2, 3])),
            list("list_2", vec![o("B", None, 2), o("A", Some("A"), 3)]) ] },
        { "name": "freeform_liar_honest", "hosts": [
            free("free", json!({ "note": "freeform" })),
            list("liar", vec![o("A", Some("B"), 4)]),
            list("honest", vec![o("A", Some("A"), 5)]) ] },
    ])
}

/// Prints the recorder's input: the two BEEFs and txids and the shapes.
/// `cargo test --features overlay --test lookup_freeform_precedence_815 emit -- --ignored --nocapture`
#[test]
#[ignore]
fn emit_the_recorders_input_815() {
    let (a, a_txid) = beef_of("A");
    let (b, b_txid) = beef_of("B");
    let input = json!({
        "beefs": { "A": to_hex(&a), "B": to_hex(&b) },
        "txids": { "A": a_txid, "B": b_txid },
        "shapes": shapes(),
    });
    println!("{}", serde_json::to_string_pretty(&input).unwrap());
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/lookup_freeform_precedence_815.json")).unwrap()
}

fn shape(name: &str) -> Value {
    vector()["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no shape {name}"))
        .clone()
}

/// The output a shape's entry describes, its BEEF this crate's writer's.
fn item(entry: &Value) -> OutputListItem {
    OutputListItem {
        beef: beef_of(entry["tx"].as_str().unwrap()).0,
        output_index: entry["outputIndex"].as_u64().unwrap() as u32,
        context: entry["context"]
            .as_array()
            .map(|c| c.iter().map(|b| b.as_u64().unwrap() as u8).collect()),
        txid: entry["hint"].as_str().map(|h| beef_of(h).1),
    }
}

/// A facilitator answering each host with its scripted answer.
struct ByHost(HashMap<String, LookupAnswer>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self
            .0
            .get(url)
            .cloned()
            .unwrap_or(LookupAnswer::OutputList { outputs: vec![] }))
    }
}

/// Each run's hosts are its own: the reputation tracker is one global keyed
/// by URL, and a test run three times must not see its earlier runs.
static RUN: AtomicUsize = AtomicUsize::new(0);

/// The shape's hosts (role, URL) in rank order and the resolver over them.
fn resolver_of(shape: &Value, test: &str) -> (Vec<(String, String)>, LookupResolver) {
    let run = RUN.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = shape["name"].as_str().unwrap();
    let mut answers = HashMap::new();
    let hosts: Vec<(String, String)> = shape["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let role = h["role"].as_str().unwrap().to_string();
            let url =
                format!("https://{role}-{name}-{test}-{pid}-{run}-815.invalid").replace('_', "-");
            let answer = match h.get("freeform") {
                Some(result) => LookupAnswer::Freeform {
                    result: result.clone(),
                },
                None => LookupAnswer::OutputList {
                    outputs: h["outputs"].as_array().unwrap().iter().map(item).collect(),
                },
            };
            answers.insert(url.clone(), answer);
            (role, url)
        })
        .collect();
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(ByHost(answers)) as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            SERVICE.to_string(),
            hosts.iter().map(|(_, url)| url.clone()).collect(),
        )])),
        ..Default::default()
    });
    (hosts, resolver)
}

fn question() -> LookupQuestion {
    LookupQuestion::new(SERVICE, json!({}))
}

/// The answer as the vector writes it: its type and each output's
/// transaction, index, hint and context.
fn described(answer: &LookupAnswer) -> Value {
    match answer {
        LookupAnswer::OutputList { outputs } => {
            let name_of_beef = |beef: &[u8]| {
                ["A", "B"]
                    .into_iter()
                    .find(|n| beef_of(n).0 == beef)
                    .unwrap()
            };
            let name_of_txid = |txid: &str| {
                ["A", "B"]
                    .into_iter()
                    .find(|n| beef_of(n).1 == txid)
                    .unwrap()
            };
            json!({
                "type": "output-list",
                "outputs": outputs.iter().map(|o| json!({
                    "tx": name_of_beef(&o.beef),
                    "outputIndex": o.output_index,
                    "hint": o.txid.as_deref().map(name_of_txid),
                    "context": o.context,
                })).collect::<Vec<_>>(),
            })
        }
        other => json!({ "type": format!("{:?}", other.answer_type()) }),
    }
}

/// The reference's answer for a shape, in the form [`described`] writes.
fn reference(shape: &Value) -> Value {
    let r = &shape["reference"];
    assert_eq!(r["type"], "output-list", "{}", shape["name"]);
    assert_eq!(r["query_type"], "output-list", "{}", shape["name"]);
    json!({ "type": r["type"], "outputs": r["outputs"] })
}

/// Replays `name` and asserts this crate's answer is the reference's.
async fn replays(name: &str, test: &str) -> (Vec<(String, String)>, LookupResolver) {
    let shape = shape(name);
    let (hosts, resolver) = resolver_of(&shape, test);
    let answer = resolver.query(&question(), None).await.unwrap();
    assert_eq!(described(&answer), reference(&shape), "{name}");
    (hosts, resolver)
}

#[tokio::test]
async fn a_freeform_host_beside_an_output_list_answers_the_list_in_either_order_815() {
    for name in ["freeform_then_list", "list_then_freeform"] {
        replays(name, "either-order").await;
    }
}

#[tokio::test]
async fn every_host_freeform_answers_the_empty_output_list_815() {
    for name in ["every_host_freeform", "lone_freeform"] {
        let (_, _) = replays(name, "every-freeform").await;
        assert_eq!(shape(name)["reference"]["outputs"], json!([]), "{name}");
    }
}

#[tokio::test]
async fn a_freeform_host_beside_an_empty_list_answers_the_empty_list_815() {
    replays("freeform_and_empty_list", "beside-empty").await;
}

#[tokio::test]
async fn a_freeform_host_among_three_leaves_the_other_hosts_merge_815() {
    replays("list_freeform_list", "among-three").await;
}

/// #796's merge runs unchanged on the lists kept: the honest copy displaces
/// the lying one and the lie is counted, the freeform host beside them
/// changing nothing.
#[tokio::test]
async fn a_freeform_host_keeps_the_hint_merge_and_its_count_815() {
    let shape = shape("freeform_liar_honest");
    let (_, resolver) = resolver_of(&shape, "hint-merge");
    let answer = resolver.query(&question(), None).await.unwrap();
    assert_eq!(described(&answer), reference(&shape));
    assert_eq!(resolver.txid_hint_contradictions(), 1);
}

/// A freeform answer is neutral for its host (`:2399-2402`): no success and
/// no failure, where an output list (empty or not) is a success; each
/// host's counts the reference's tracker's on every shape.
#[tokio::test]
async fn a_freeform_host_records_neither_success_nor_failure_on_every_shape_815() {
    let recorded = vector();
    let shapes = recorded["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 7);
    for shape in shapes {
        let name = shape["name"].as_str().unwrap();
        let (hosts, resolver) = resolver_of(shape, "reputation");
        let answer = resolver.query(&question(), None).await.unwrap();
        assert_eq!(described(&answer), reference(shape), "{name}");
        for (role, url) in &hosts {
            let ours = get_overlay_host_reputation_tracker()
                .snapshot(url)
                .map_or((0, 0), |e| (e.total_successes, e.total_failures));
            let theirs = &shape["reference"]["reputation"][role];
            assert_eq!(json!([ours.0, ours.1]), *theirs, "{name}: {role}");
        }
        let freeform = shape["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|h| h.get("freeform").is_some())
            .count() as u64;
        assert_eq!(
            shape["reference"]["freeformHosts"],
            json!(freeform),
            "{name}"
        );
    }
}
