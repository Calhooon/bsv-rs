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
