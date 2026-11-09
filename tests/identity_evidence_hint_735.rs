//! #735: the lookup output's `txid` hint. The reference's HTTPS facilitator
//! keeps a JSON answer's `txid` member as given (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResolver.ts:356`) and sets a binary
//! aggregated answer's outputs' from their outpoints (`:905-936`); the
//! toolbox hands the whole output to the evidence check
//! (`packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:602`),
//! whose `loadEvidenceTransaction` refuses a hint that, lower-cased, is not
//! the subject's txid (`packages/sdk/src/transaction/TransactionEvidence.ts:123-124`):
//!
//! ```text
//! if (hint !== undefined && (typeof hint !== 'string' || hint.toLowerCase() !== txid)) {
//!   throw new TransactionEvidenceError('invalid-evidence')
//! }
//! ```
//!
//! This crate carries the hint (`OutputListItem::txid`) and compares it the
//! same way, but by the owner's word of 2026-11-04 13:5xZ reads the proven
//! subject and counts the contradiction as the host's fault
//! (`IdentityClient::txid_hint_contradictions`), where the reference skips
//! the output (the stated divergence, ts-stack #1482). Against
//! `tests/vectors/identity_evidence_hint_735.json`
//! (`tests/support/identity_evidence_hint_735.mjs`, Node v22.18.0): #730's
//! `proven_parent_absent_grandparent` BEEF rebuilt by this crate's writer
//! (`tests/support/identity_evidence_730.rs`) to the recorded bytes, served
//! by a `wiremock` host as the reference's facilitator was served it, through
//! `resolve_by_attributes` and `discover_certificates`.
//!
//! The fold (the reads of 2026-11-04 18:5xZ): a binary aggregated answer's
//! outputs each carry the Atomic BEEF of their own outpoint's txid, one per
//! distinct txid, as the reference's `extractAtomicOutputs` builds them
//! (`LookupResolver.ts:905-936`, `beefObj.toBinaryAtomic(x.txid)`), against
//! the vector's `binary_cases`: one BEEF of two transactions (the shape
//! above merged with #737's `second_name_11` BEEF by this crate's
//! `merge_beef`, to the recorded bytes) under two outpoints, each output's
//! bytes the reference's and its hint its own subject, both read and nothing
//! counted.
#![cfg(all(feature = "identity", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_730.rs"]
mod build;

use bsv_rs::identity::IdentityClient;
use bsv_rs::overlay::{
    HttpsOverlayLookupFacilitator, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::transaction::Beef;
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_evidence_hint_735.json")).unwrap()
}

fn case(name: &str) -> Value {
    vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

/// #730's shape, rebuilt by this crate's writer to the recorded bytes.
fn beef() -> Vec<u8> {
    let built = build::build("proven_parent_absent_grandparent", None);
    assert_eq!(
        to_hex(&built.beef),
        vector()["beef"].as_str().unwrap(),
        "this crate's writer and the recorded bytes"
    );
    built.beef
}

/// The JSON answer the reference's facilitator was served for `case`.
fn json_body(case: &Value) -> Value {
    let mut item = json!({ "beef": beef(), "outputIndex": 0 });
    if let Some(hint) = case["hint"].as_str() {
        item["txid"] = json!(hint);
    }
    json!({ "type": "output-list", "outputs": [item] })
}

/// The binary aggregated answer of the recorder: one outpoint naming the
/// subject (its hex's bytes, as `toHex(r.read(32))` reads them back), output
/// 0, no context, then the BEEF (`LookupResolver.ts:876-900`).
fn binary_body() -> Vec<u8> {
    let mut body = vec![1];
    body.extend(from_hex(vector()["subject_txid"].as_str().unwrap()).unwrap());
    body.extend([0, 0]);
    body.extend(beef());
    body
}

/// A host of its own (the reputation tracker is one global keyed by URL).
async fn host(response: ResponseTemplate) -> MockServer {
    let server = MockServer::builder().start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

fn resolver(host: &str) -> Arc<LookupResolver> {
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(HttpsOverlayLookupFacilitator::new(true))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec![host.to_string()],
        )])),
        ..Default::default()
    }))
}

/// How many identities and certificates the two parsers return, and how
/// many contradictions the client counted over both.
async fn read(response: ResponseTemplate) -> (usize, usize, u64) {
    let server = host(response).await;
    let client = IdentityClient::with_resolver(
        ProtoWallet::new(None),
        Default::default(),
        resolver(&server.uri()),
    );
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .unwrap();
    let subject: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    let certificates = client
        .discover_certificates(subject["subject"].as_str().unwrap())
        .await
        .unwrap();
    (
        identities.len(),
        certificates.len(),
        client.txid_hint_contradictions(),
    )
}

/// The facilitator's answer's one output, as this crate's reader keeps it.
async fn kept(response: ResponseTemplate) -> sdk::overlay::OutputListItem {
    let server = host(response).await;
    let question = LookupQuestion::new("ls_identity", json!({ "identityKey": "02" }));
    let answer = HttpsOverlayLookupFacilitator::new(true)
        .lookup(&server.uri(), &question, Some(5_000))
        .await
        .unwrap();
    let LookupAnswer::OutputList { mut outputs } = answer else {
        panic!("not an output list: {answer:?}");
    };
    assert_eq!(outputs.len(), 1);
    outputs.remove(0)
}

/// The JSON reader keeps a present `txid` as given, its case included, as the
/// reference's `normalizeLookupOutput` keeps it (`:356`), and none when absent.
#[tokio::test]
async fn the_json_reader_keeps_the_hint_as_given_735() {
    for name in [
        "no_hint",
        "hint_the_subject",
        "hint_the_subject_upper_case",
        "hint_the_grandparent",
        "hint_another_txid",
    ] {
        let c = case(name);
        let output = kept(ResponseTemplate::new(200).set_body_json(json_body(&c))).await;
        assert_eq!(output.txid.as_deref(), c["kept_hint"].as_str(), "{name}");
        assert_eq!(output.beef, beef(), "{name}");
    }
}

/// A binary aggregated answer's output carries its outpoint's txid, as the
/// reference's `extractAtomicOutputs` sets it (`:905-936`).
#[tokio::test]
async fn a_binary_answer_carries_the_outpoint_txid_735() {
    let c = case("binary_outpoint_names_the_subject");
    let response =
        || ResponseTemplate::new(200).set_body_raw(binary_body(), "application/octet-stream");
    let output = kept(response()).await;
    assert_eq!(output.txid.as_deref(), c["kept_hint"].as_str());
    // The fold: its bytes the reference's `toBinaryAtomic` of that txid.
    assert_eq!(to_hex(&output.beef), c["atomic_beef"].as_str().unwrap());
    assert_eq!(c["outcome"], "read");
    assert_eq!(read(response()).await, (1, 1, 0));
}

/// No hint, or one naming the subject in either case: read on both sides,
/// nothing counted.
#[tokio::test]
async fn an_agreeing_hint_or_none_is_read_and_not_counted_735() {
    for name in ["no_hint", "hint_the_subject", "hint_the_subject_upper_case"] {
        let c = case(name);
        assert_eq!(c["outcome"], "read", "{name}: the reference's verdict");
        assert_eq!(c["selected_txid"], vector()["subject_txid"], "{name}");
        let got = read(ResponseTemplate::new(200).set_body_json(json_body(&c))).await;
        assert_eq!(got, (1, 1, 0), "{name}");
    }
}

/// A hint naming another transaction (the BEEF's own grandparent, or one it
/// does not hold): the reference refuses the evidence (`invalid-evidence`)
/// and `parseResults` skips the output; this crate reads the proven subject
/// and counts the contradiction once per parse (the stated divergence, the
/// owner's word of 2026-11-04 13:5xZ, ts-stack #1482).
#[tokio::test]
async fn a_disagreeing_hint_is_read_and_counted_where_the_reference_skips_it_735() {
    for name in ["hint_the_grandparent", "hint_another_txid"] {
        let c = case(name);
        assert_eq!(c["outcome"], "skipped", "{name}: the reference's verdict");
        assert_eq!(c["selected_txid"], "refused: invalid-evidence", "{name}");
        let got = read(ResponseTemplate::new(200).set_body_json(json_body(&c))).await;
        assert_eq!(got, (1, 1, 2), "{name}");
    }
}

fn binary_case(name: &str) -> Value {
    vector()["binary_cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no binary case {name}"))
        .clone()
}

/// The fold's BEEF of two transactions: #730's shape merged with #737's
/// `second_name_11` BEEF (a proven transaction whose output 0 is a second
/// token of the subject), by this crate's `merge_beef` and writer to the
/// bytes the reference's `mergeBeef` and `toBinary` wrote.
fn two_transactions_beef() -> Vec<u8> {
    let v737: Value =
        serde_json::from_str(include_str!("vectors/identity_resolve_737.json")).unwrap();
    let second = v737["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "refused_first_then_token")
        .unwrap()["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["builder"] == "second_name_11")
        .unwrap()["beef"]
        .as_str()
        .unwrap()
        .to_string();
    let mut both = Beef::from_binary(&beef()).unwrap();
    both.merge_beef(&Beef::from_binary(&from_hex(&second).unwrap()).unwrap());
    let bytes = both.to_binary();
    assert_eq!(
        to_hex(&bytes),
        vector()["two_transactions_beef"].as_str().unwrap(),
        "this crate's merge and writer and the recorded bytes"
    );
    bytes
}

/// The aggregated answer the recorder served for `case`: its outpoints (no
/// context), then `beef` (`LookupResolver.ts:876-900`).
fn aggregated_body(case: &Value, beef: &[u8]) -> Vec<u8> {
    let outpoints = case["outpoints"].as_array().unwrap();
    let mut body = vec![outpoints.len() as u8];
    for outpoint in outpoints {
        body.extend(from_hex(outpoint["txid"].as_str().unwrap()).unwrap());
        body.extend([outpoint["outputIndex"].as_u64().unwrap() as u8, 0]);
    }
    body.extend(beef);
    body
}

fn binary(body: Vec<u8>) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body, "application/octet-stream")
}

/// The facilitator's answer to `response`: its outputs, or its refusal.
async fn answered(response: ResponseTemplate) -> sdk::Result<Vec<sdk::overlay::OutputListItem>> {
    let server = host(response).await;
    let question = LookupQuestion::new("ls_identity", json!({ "identityKey": "02" }));
    let answer = HttpsOverlayLookupFacilitator::new(true)
        .lookup(&server.uri(), &question, Some(5_000))
        .await?;
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("not an output list: {answer:?}");
    };
    Ok(outputs)
}

/// A binary answer over a BEEF of two transactions: each output carries the
/// reference's `toBinaryAtomic` of its own outpoint's txid, byte for byte,
/// and that txid as its hint, in either order of the outpoints; the same
/// outpoint twice the same bytes twice (`LookupResolver.ts:905-936`). Until
/// the fold each output carried the whole BEEF.
#[tokio::test]
async fn a_binary_answers_outputs_each_carry_their_own_txids_atomic_beef_735() {
    let beef = two_transactions_beef();
    for name in [
        "binary_two_transactions",
        "binary_two_transactions_reversed",
        "binary_one_outpoint_twice",
    ] {
        let c = binary_case(name);
        let outputs = answered(binary(aggregated_body(&c, &beef))).await.unwrap();
        let recorded = c["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), recorded.len(), "{name}");
        for (i, (output, r)) in outputs.iter().zip(recorded).enumerate() {
            assert_eq!(
                to_hex(&output.beef),
                r["atomic_beef"].as_str().unwrap(),
                "{name} output {i}: the reference's atomic bytes"
            );
            assert_eq!(
                output.txid.as_deref(),
                r["kept_hint"].as_str(),
                "{name} {i}"
            );
            assert_eq!(
                r["atomic_txid"], r["kept_hint"],
                "{name} {i}: the recording"
            );
            assert_eq!(
                r["selected_txid"], r["kept_hint"],
                "{name} {i}: the recording"
            );
            assert_eq!(
                u64::from(output.output_index),
                r["output_index"].as_u64().unwrap(),
                "{name} {i}"
            );
        }
    }
}

/// Two outpoints of two transactions sharing index 0, through the resolver
/// and both parsers: both read, as the reference's `parseResults` reads
/// both, and no contradiction counted, each hint naming its own BEEF's
/// subject. On the base both outputs carried the whole BEEF: the resolver's
/// dedup (the BEEF's txid and the index) kept one, read from the BEEF's last
/// transaction, and an honest host's other hint was counted.
#[tokio::test]
async fn two_transactions_of_a_binary_answer_are_both_read_and_no_hint_counted_735() {
    let beef = two_transactions_beef();
    for name in [
        "binary_two_transactions",
        "binary_two_transactions_reversed",
    ] {
        let c = binary_case(name);
        assert_eq!(c["read"], 2, "{name}: the reference's parseResults");
        let got = read(binary(aggregated_body(&c, &beef))).await;
        assert_eq!(got, (2, 2, 0), "{name}");
    }
    // One outpoint named twice: one output after the dedup, on both sides.
    let c = binary_case("binary_one_outpoint_twice");
    assert_eq!(c["read"], 1, "the reference's parseResults");
    let got = read(binary(aggregated_body(&c, &beef))).await;
    assert_eq!(got, (1, 1, 0));
}

/// What the reference's facilitator refuses whole, refused whole: an
/// outpoint naming a txid the BEEF does not hold (`toBinaryAtomic`'s words
/// under this crate's prefix) and an answer of no outpoint and no BEEF
/// (`Beef.fromBinary` on nothing; this crate's parser's words).
#[tokio::test]
async fn a_binary_answer_the_reference_refuses_whole_is_refused_whole_735() {
    let beef = two_transactions_beef();
    let c = binary_case("binary_outpoint_names_an_absent_txid");
    let recorded = c["error"].as_str().unwrap();
    assert_eq!(
        recorded,
        format!("{} does not exist in this Beef", "33".repeat(32))
    );
    let refused = answered(binary(aggregated_body(&c, &beef)))
        .await
        .unwrap_err();
    assert!(
        refused.to_string().ends_with(recorded),
        "{refused}: the reference's words"
    );

    let c = binary_case("binary_no_outpoint_no_beef");
    assert!(c["error"].is_string(), "the reference refuses it");
    assert!(answered(binary(aggregated_body(&c, &[]))).await.is_err());
}
