//! #736: the evidence check's bounds graph-wide, one parent written twice,
//! and the `limit` error at every discovery door, against
//! `tests/vectors/identity_evidence_736.json`
//! (`tests/support/identity_evidence_736.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`
//! `parseEvidence` and the toolbox's `parseResults`): each BEEF rebuilt by
//! this crate's writer (`tests/support/identity_evidence_736.rs`) to the
//! recorded SHA-256 and served through both parsers (`resolve_by_attributes`,
//! `discover_certificates`) on an in-process facilitator on an `.invalid`
//! host, answered as `parseResults` answered it: the inputs bound a running
//! sum over the unconfirmed graph (`:166-171`), a proven parent's scripts
//! counted toward the script-bytes bound (`:168`), one parent raw then
//! txid-only skipped (`:143`, the later entry the index's,
//! `Beef.#rebuildTxIndexes`, `Beef.ts:516-524`) and txid-only then raw read.
//! Then the five discovery functions, each refused in the reference's words
//! (`identity error: Transaction evidence: limit`, `identityUtils.ts:630-634`
//! rethrowing) on the #730 vector's `transactions_over_bound` BEEF and this
//! vector's `graph_inputs_over_bound`. The check's codes and lines are the
//! unit pins of `src/identity/evidence_736_tests.rs`.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_736.rs"]
mod build;
#[path = "support/identity_evidence_730.rs"]
mod build_730;

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::wallet::ProtoWallet;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// The words every door answers a `limit` with.
const LIMIT: &str = "identity error: Transaction evidence: limit";

/// The subject of the reference's token (#553's vector).
fn subject() -> String {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    v["subject"].as_str().unwrap().to_string()
}

/// A facilitator answering every question with one output.
struct Answering(OutputListItem);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![self.0.clone()],
        })
    }
}

/// A client whose `ls_identity` lookups answer `beef` at output 0.
fn client(beef: Vec<u8>) -> IdentityClient<ProtoWallet> {
    let output = OutputListItem {
        beef,
        output_index: 0,
        context: None,
        txid: None,
    };
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(output))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver)
}

/// The attributes `resolve_by_attributes` asks for.
fn attributes() -> IndexMap<String, String> {
    IndexMap::from([("email".to_string(), "alice@example.com".to_string())])
}

/// How many identities and certificates the two parsers return for `beef`,
/// each asked on its own client, or the words of each refusal.
async fn read(beef: Vec<u8>) -> (Result<usize, String>, Result<usize, String>) {
    let identities = client(beef.clone())
        .resolve_by_attributes(attributes(), false)
        .await
        .map(|v| v.len())
        .map_err(|e| e.to_string());
    let certificates = client(beef)
        .discover_certificates(&subject())
        .await
        .map(|v| v.len())
        .map_err(|e| e.to_string());
    (identities, certificates)
}

/// The shape `name`, rebuilt to the recorded bytes: its BEEF and the
/// discovery's recorded answer (`parseResults`' outcome), per parser.
fn shape(name: &str) -> (Vec<u8>, Result<usize, String>) {
    let case = build::case(name);
    let built = build::build(name, case["size"].as_u64().map(|n| n as usize));
    assert_eq!(
        to_hex(&sha256(&built.beef)),
        case["beef_sha256"].as_str().unwrap(),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    let expected = match case["outcome"].as_str().unwrap() {
        "read" => Ok(1),
        "skipped" => Ok(0),
        words => Err(format!(
            "identity error: {}",
            words.strip_prefix("refused: ").unwrap()
        )),
    };
    (built.beef, expected)
}

/// Each shape answered by both parsers as the reference's discovery answers
/// it, every disagreement named.
async fn agrees(names: &[&str]) {
    let mut differ = Vec::new();
    for name in names {
        let (beef, expected) = shape(name);
        let got = read(beef).await;
        if got != (expected.clone(), expected.clone()) {
            differ.push(format!("{name}: {got:?}, expected {expected:?} at both"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// 2048 inputs at the unproven subject and 2049 at its unproven parent: 4097
/// over the graph refuses the discovery (`:170-171`); 2048 and 2048 read.
#[tokio::test]
async fn the_inputs_bound_counts_the_whole_unconfirmed_graph_736() {
    agrees(&["graph_inputs_over_bound", "graph_inputs_at_bound"]).await;
}

/// The subject's scripts 131072 bytes and its PROVEN parent's 131073: the
/// parent's count (`graphScriptBytes` over every visited transaction,
/// `:168`), 262145 refusing the discovery; 131072 and 131072 read.
#[tokio::test]
async fn a_proven_parent_s_scripts_count_toward_the_script_bytes_bound_736() {
    agrees(&[
        "graph_script_bytes_over_bound",
        "graph_script_bytes_at_bound",
    ])
    .await;
}

/// One parent written raw then txid-only: the later entry, txid-only, is the
/// index's, the subject's input has no source (`:143`), skipped; txid-only
/// then raw: the raw entry links it, read.
#[tokio::test]
async fn a_parent_written_raw_and_txid_only_is_judged_by_its_later_entry_736() {
    agrees(&["parent_raw_then_txid_only", "parent_txid_only_then_raw"]).await;
}

/// The limit BEEFs every door is asked with: #730's 257 transactions
/// (`:117`) and this vector's 4097 inputs over the graph (`:170-171`).
fn limit_beefs() -> Vec<(&'static str, Vec<u8>)> {
    let name = "transactions_over_bound";
    let v = build_730::vector();
    let case = v["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap();
    assert_eq!(case["outcome"], "refused: Transaction evidence: limit");
    let over_730 = build_730::build(name, case["size"].as_u64().map(|n| n as usize));
    assert_eq!(
        to_hex(&sha256(&over_730.beef)),
        case["beef_sha256"].as_str().unwrap()
    );
    let (over_736, expected) = shape("graph_inputs_over_bound");
    assert_eq!(expected, Err(LIMIT.to_string()));
    vec![
        ("transactions_over_bound_730", over_730.beef),
        ("graph_inputs_over_bound", over_736),
    ]
}

/// Each limit BEEF through `door`, every answer other than the reference's
/// words named.
async fn every_limit_refuses<F, Fut>(door: F)
where
    F: Fn(IdentityClient<ProtoWallet>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut differ = Vec::new();
    for (name, beef) in limit_beefs() {
        let got = door(client(beef)).await;
        if got != Err(LIMIT.to_string()) {
            differ.push(format!("{name}: {got:?}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// `resolve_by_identity_key`, contacts not consulted: the answer's one
/// output's evidence refuses the resolution (every output parsed since
/// #737; a limit after an admitted output is `identity_resolve_737`'s pin).
#[tokio::test]
async fn resolve_by_identity_key_refuses_a_limit_in_the_reference_words_736() {
    every_limit_refuses(|c| async move {
        c.resolve_by_identity_key(&subject(), false)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
}

/// `resolve_by_attributes`, the door #730's `read()` reached on its limit
/// shapes (its `?` stopping there).
#[tokio::test]
async fn resolve_by_attributes_refuses_a_limit_in_the_reference_words_736() {
    every_limit_refuses(|c| async move {
        c.resolve_by_attributes(attributes(), false)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
}

/// `discover_certificates`, which #730's `read()` reached only on shapes
/// `resolve_by_attributes` let through.
#[tokio::test]
async fn discover_certificates_refuses_a_limit_in_the_reference_words_736() {
    every_limit_refuses(|c| async move {
        c.discover_certificates(&subject())
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
}

/// `discover_certificates_by_type`.
#[tokio::test]
async fn discover_certificates_by_type_refuses_a_limit_in_the_reference_words_736() {
    every_limit_refuses(|c| async move {
        c.discover_certificates_by_type(&subject(), "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=")
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
}

/// `query`.
#[tokio::test]
async fn query_refuses_a_limit_in_the_reference_words_736() {
    every_limit_refuses(|c| async move {
        c.query(IdentityQuery::by_identity_key(subject()))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await;
}
