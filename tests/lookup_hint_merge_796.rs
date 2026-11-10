//! #796: the resolver's merge never lets a lookup output whose `txid` hint
//! disagrees with its BEEF's subject shadow an agreeing copy of the same
//! output, and counts every disagreeing one it receives.
//!
//! The reference drops a disagreeing output at its merge
//! (`ts-stack@edf6e03` `packages/sdk/src/overlay-tools/LookupResolver.ts`):
//!
//! ```text
//! 1104:       const txId = this.options.resolveTxId(output, now)
//! 1105:       if (txId === null) continue
//! 1106:       const key = `${txId}.${output.outputIndex}`
//! 1107:       if (this.outputsMap.has(key)) continue
//! 2229:       if (output.txid !== undefined && output.txid.toLowerCase() !== memo.txId) return null
//! 2235:       if (output.txid !== undefined && output.txid.toLowerCase() !== txId) return null
//! ```
//!
//! so wherever an agreeing copy of a key arrives, its answer holds that copy.
//! This crate keeps a disagreeing output whose BEEF parses and counts it
//! (`LookupResolver::txid_hint_contradictions`), by the owner's word on #735
//! (2026-11-04 13:5xZ: carried and counted, never refused); until #796 a
//! lying host ranked ahead of an honest one had its copy kept and the honest
//! copy discarded as the duplicate. Since #796 an agreeing (or hintless) copy
//! displaces a held disagreeing one and stands where it arrived, so this
//! crate's answer less its kept lying outputs is the reference's copies, and
//! its order while the hosts answer in rank order (this crate merges in rank
//! order after every host answers, the reference each answer as it
//! completes, `:1501-1502` into `:1065-1072`: a liar ranked ahead answering
//! after the honest host puts the reference's order otherwise; older than
//! #796); where every copy disagrees, the reference returns none and this
//! crate the earliest, hint as given, every lying copy counted (`STATED`). The drop records nothing against the host, as the
//! reference's merge calls no reputation method (`:1101-1115`; the success
//! recorded for any output list at `:2395-2397`). Go at `2ca481c` has no hint
//! (`overlay/lookup/types.go:19-22`) and keeps a later copy
//! (`overlay/lookup/resolver.go:131-138`). Upstream: ts-stack #1482.
//!
//! The shapes and the reference's answers are `vectors/lookup_hint_merge_796.json`,
//! recorded by `support/lookup_hint_merge_796.mjs` under Node v22.18.0 against the
//! reference's own `LookupResolver` with a scripted facilitator; the
//! BEEFs are this crate's writer's (the ignored emitter below). Every host
//! is an `.invalid` name answered by the scripted facilitator, never dialled;
//! each test runs its shape on hosts of its own (the reputation tracker is
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
use std::sync::Arc;

const SERVICE: &str = "ls_hint_merge_796";

/// The shapes whose answer differs from the reference's, by the owner's
/// word on #735: a key only lying copies carry is kept (the earliest, hint
/// as given) and every lying copy counted, where the reference drops them
/// and answers no output.
const STATED: &[&str] = &["lone_liar", "liar_liar"];

/// Transaction `name` (`A`, `B` or `C`): one made-up input and one `OP_TRUE`
/// output whose amount tells them apart, proven by a block of its own (a
/// lone leaf at offset 0), written by this crate's BEEF writer. `C` is never
/// an output's transaction, only a second lie's hint (`liar_liar`).
fn beef_of(name: &str) -> (Vec<u8>, String) {
    let satoshis = match name {
        "A" => 1,
        "B" => 2,
        _ => 3,
    };
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(
        satoshis,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let mut beef = Beef::new();
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let index = beef.merge_bump(MerklePath::new(900 + satoshis as u32, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    (beef.to_binary().expect("the BEEF is writable"), tx.id())
}

/// The shapes the recorder drives: each host's answer in rank order, an
/// output naming its transaction, index, hint (`"A"`, `"B"`, `"C"`,
/// `"A_upper"` or absent) and context bytes. The last four (the reads of
/// 2026-11-09) pin each stated rule of the merge against a one-line
/// mutation: two liars (the earliest kept, both counted), two agreeing
/// copies (the earlier kept), and one displacement per key.
fn shapes() -> Value {
    let o = |tx: &str, hint: Option<&str>, context: u8| json!({ "tx": tx, "outputIndex": 0, "hint": hint, "context": [context] });
    json!([
        { "name": "liar_then_honest", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] },
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] } ] },
        { "name": "honest_then_liar", "hosts": [
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] },
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] } ] },
        { "name": "replaced_keeps_place", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1), o("B", Some("B"), 3)] },
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] } ] },
        { "name": "lone_liar", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] } ] },
        { "name": "upper_and_absent", "hosts": [
            { "role": "honest", "outputs": [o("A", Some("A_upper"), 2), o("B", None, 3)] } ] },
        { "name": "absent_replaces_liar", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] },
            { "role": "hintless", "outputs": [o("A", None, 4)] } ] },
        { "name": "liar_liar", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] },
            { "role": "liar_2", "outputs": [o("A", Some("C"), 5)] } ] },
        { "name": "honest_honest", "hosts": [
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] },
            { "role": "honest_2", "outputs": [o("A", Some("A"), 6)] } ] },
        { "name": "liar_liar_honest", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] },
            { "role": "liar_2", "outputs": [o("A", Some("C"), 5)] },
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] } ] },
        { "name": "liar_honest_honest", "hosts": [
            { "role": "liar", "outputs": [o("A", Some("B"), 1)] },
            { "role": "honest", "outputs": [o("A", Some("A"), 2)] },
            { "role": "honest_2", "outputs": [o("A", Some("A"), 6)] } ] },
    ])
}

/// Prints the recorder's input: the three BEEFs and txids and the shapes.
/// `cargo test --features overlay --test lookup_hint_merge_796 -- --ignored --nocapture`
#[test]
#[ignore]
fn emit_the_recorders_input_796() {
    let (a, a_txid) = beef_of("A");
    let (b, b_txid) = beef_of("B");
    let (c, c_txid) = beef_of("C");
    let input = json!({
        "beefs": { "A": to_hex(&a), "B": to_hex(&b), "C": to_hex(&c) },
        "txids": { "A": a_txid, "B": b_txid, "C": c_txid },
        "shapes": shapes(),
    });
    println!("{}", serde_json::to_string_pretty(&input).unwrap());
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/lookup_hint_merge_796.json")).unwrap()
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

fn txid(tx: &str) -> String {
    beef_of(tx).1
}

fn hint_text(hint: &Value) -> Option<String> {
    hint.as_str().map(|h| match h {
        "A_upper" => txid("A").to_uppercase(),
        other => txid(other),
    })
}

/// The output a shape's entry describes, its BEEF this crate's writer's.
fn item(entry: &Value) -> OutputListItem {
    OutputListItem {
        beef: beef_of(entry["tx"].as_str().unwrap()).0,
        output_index: entry["outputIndex"].as_u64().unwrap() as u32,
        context: entry["context"]
            .as_array()
            .map(|c| c.iter().map(|b| b.as_u64().unwrap() as u8).collect()),
        txid: hint_text(&entry["hint"]),
    }
}

/// A facilitator answering each host with its scripted outputs.
struct ByHost(HashMap<String, Vec<OutputListItem>>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.get(url).cloned().unwrap_or_default(),
        })
    }
}

fn host_url(shape: &str, role: &str, tag: &str) -> String {
    format!("https://{role}-{shape}-{tag}-796.invalid").replace('_', "-")
}

/// Runs `name` on hosts of its own (`tag`): the answer's outputs and the
/// resolver's count.
async fn run(name: &str, tag: &str) -> (Vec<OutputListItem>, u64, Vec<String>) {
    let shape = shape(name);
    let mut answers = HashMap::new();
    let mut hosts = Vec::new();
    for host in shape["hosts"].as_array().unwrap() {
        let url = host_url(name, host["role"].as_str().unwrap(), tag);
        let outputs = host["outputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(item)
            .collect();
        answers.insert(url.clone(), outputs);
        hosts.push(url);
    }
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(ByHost(answers))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(SERVICE.to_string(), hosts.clone())])),
        ..Default::default()
    });
    let answer = resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("{name}: not an output list");
    };
    (outputs, resolver.txid_hint_contradictions(), hosts)
}

/// An output as the tests compare it: transaction, index, hint, context.
type Described = (String, u32, Option<String>, Option<Vec<u8>>);

fn described(outputs: &[OutputListItem]) -> Vec<Described> {
    outputs
        .iter()
        .map(|o| {
            let tx = if o.beef == beef_of("A").0 { "A" } else { "B" };
            (
                tx.to_string(),
                o.output_index,
                o.txid.clone(),
                o.context.clone(),
            )
        })
        .collect()
}

/// The reference's recorded answer for a shape, in the same description.
fn reference(name: &str) -> Vec<Described> {
    shape(name)["reference"]["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let output = item(o);
            (
                o["tx"].as_str().unwrap().to_string(),
                output.output_index,
                output.txid,
                output.context,
            )
        })
        .collect()
}

#[test]
fn the_recorded_beefs_are_this_crates_writers_796() {
    let v = vector();
    for tx in ["A", "B", "C"] {
        let (beef, id) = beef_of(tx);
        assert_eq!(v["beefs"][tx].as_str().unwrap(), to_hex(&beef), "{tx}");
        assert_eq!(v["txids"][tx].as_str().unwrap(), id, "{tx}");
    }
}

#[tokio::test]
async fn a_lying_hint_ahead_of_an_honest_copy_does_not_shadow_it_796() {
    let (outputs, count, _) = run("liar_then_honest", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("A")), Some(vec![2]))]
    );
    assert_eq!(count, 1);
}

#[tokio::test]
async fn an_honest_copy_ahead_of_a_lying_copy_is_kept_796() {
    let (outputs, count, _) = run("honest_then_liar", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("A")), Some(vec![2]))]
    );
    assert_eq!(count, 1);
}

/// The agreeing copy displaces the liar and stands where it arrived, after
/// the liar's `B`, as the reference's answer is `[B, A honest]` (it drops
/// the lying `A` and keys the honest one when it arrives,
/// `LookupResolver.ts:1106-1112`), while the hosts answer in rank order.
#[tokio::test]
async fn an_agreeing_copy_displaces_a_liar_and_stands_where_it_arrived_796() {
    let (outputs, count, _) = run("replaced_keeps_place", "named").await;
    assert_eq!(
        described(&outputs),
        vec![
            ("B".into(), 0, Some(txid("B")), Some(vec![3])),
            ("A".into(), 0, Some(txid("A")), Some(vec![2])),
        ]
    );
    assert_eq!(described(&outputs), reference("replaced_keeps_place"));
    assert_eq!(count, 1);
}

#[tokio::test]
async fn a_lone_lying_hint_is_kept_and_counted_never_refused_796() {
    let (outputs, count, _) = run("lone_liar", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("B")), Some(vec![1]))]
    );
    assert_eq!(count, 1);
    // The stated cell: the reference drops it and answers nothing.
    assert!(reference("lone_liar").is_empty());
}

#[tokio::test]
async fn an_agreeing_hint_in_upper_case_and_an_absent_hint_are_no_contradiction_796() {
    let (outputs, count, _) = run("upper_and_absent", "named").await;
    assert_eq!(
        described(&outputs),
        vec![
            ("A".into(), 0, Some(txid("A").to_uppercase()), Some(vec![2])),
            ("B".into(), 0, None, Some(vec![3])),
        ]
    );
    assert_eq!(count, 0);
    let (outputs, count, _) = run("absent_replaces_liar", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, None, Some(vec![4]))]
    );
    assert_eq!(count, 1);
}

/// Two liars, different lies (a stated cell): the earliest kept, hint as
/// given, both counted; the reference answers nothing.
#[tokio::test]
async fn two_lying_copies_keep_the_earliest_and_count_both_796() {
    let (outputs, count, _) = run("liar_liar", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("B")), Some(vec![1]))]
    );
    assert_eq!(count, 2);
    assert!(reference("liar_liar").is_empty());
}

/// Two agreeing copies: the earlier stays, by both (`:1107`).
#[tokio::test]
async fn an_earlier_agreeing_copy_stays_against_a_later_one_796() {
    let (outputs, count, _) = run("honest_honest", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("A")), Some(vec![2]))]
    );
    assert_eq!(described(&outputs), reference("honest_honest"));
    assert_eq!(count, 0);
}

/// Two liars then an agreeing copy: the agreeing copy displaces the held
/// liar, both lies counted.
#[tokio::test]
async fn an_agreeing_copy_displaces_the_held_liar_after_two_lies_796() {
    let (outputs, count, _) = run("liar_liar_honest", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("A")), Some(vec![2]))]
    );
    assert_eq!(described(&outputs), reference("liar_liar_honest"));
    assert_eq!(count, 2);
}

/// A liar then two agreeing copies: one displacement per key, the earlier
/// agreeing copy stands.
#[tokio::test]
async fn a_key_is_displaced_once_the_earlier_agreeing_copy_standing_796() {
    let (outputs, count, _) = run("liar_honest_honest", "named").await;
    assert_eq!(
        described(&outputs),
        vec![("A".into(), 0, Some(txid("A")), Some(vec![2]))]
    );
    assert_eq!(described(&outputs), reference("liar_honest_honest"));
    assert_eq!(count, 1);
}

#[tokio::test]
async fn a_lying_hint_records_nothing_against_its_host_796() {
    let (_, count, hosts) = run("liar_then_honest", "reputation").await;
    assert_eq!(count, 1);
    let tracker = get_overlay_host_reputation_tracker();
    for host in hosts {
        let entry = tracker.snapshot(&host).unwrap();
        assert_eq!(
            (entry.total_successes, entry.total_failures),
            (1, 0),
            "{host}"
        );
    }
}

#[tokio::test]
async fn every_shape_is_the_references_answer_save_the_stated_796() {
    for s in vector()["shapes"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        let (outputs, _, _) = run(name, "all").await;
        if STATED.contains(&name) {
            assert!(reference(name).is_empty(), "{name}: the reference's answer");
            assert_eq!(outputs.len(), 1, "{name}: kept here");
        } else {
            assert_eq!(described(&outputs), reference(name), "{name}");
        }
    }
}
