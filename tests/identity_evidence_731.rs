//! #731: an Atomic subject written twice at the discovery door, against
//! `tests/vectors/identity_evidence_731.json`
//! (`tests/support/identity_evidence_731.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`
//! `parseEvidence` and the toolbox's `parseResults`): each BEEF (an Atomic
//! prefix naming X, X written raw and txid-only in both orders, X proven by
//! its own BUMP or unproven over a proven parent) rebuilt by this crate's
//! writer (`tests/support/identity_evidence_731.rs`) to the recorded SHA-256
//! and served through both parsers (`resolve_by_attributes`,
//! `discover_certificates`) on #748's in-process facilitator on an `.invalid`
//! host, answered as `parseResults` answered it: raw then txid-only skipped
//! (the later entry the index's, `Beef.ts:516-524`; `findAtomicTransaction`
//! undefined, `:120-121`), txid-only then raw read. The skip shapes are
//! GREEN at this door whatever `evidence.rs` does: `LookupResolver` runs
//! `Transaction::from_beef(&output.beef, None)` before any parser
//! (`src/overlay/lookup_resolver.rs:465`, `get_or_cache_tx_id`, called from
//! `src/overlay/lookup_resolver/query.rs:145`; the same index) and drops the
//! output there, as the reference's `resolveTxIdForOutput` does
//! (`LookupResolver.ts:2232-2239`). The parser's own verdict, code and line
//! are the unit pin of `src/identity/evidence_731_tests.rs` (#728's lesson).
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_731.rs"]
mod build;

use bsv_rs::identity::IdentityClient;
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

/// How many identities and certificates the two parsers return for `beef`,
/// each asked on its own client, or the words of each refusal.
async fn read(beef: Vec<u8>) -> (Result<usize, String>, Result<usize, String>) {
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client(beef.clone())
        .resolve_by_attributes(attributes, false)
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

/// `name` rebuilt to the recorded bytes and answered by both parsers as the
/// reference's discovery answered it.
async fn answers_as_recorded(name: &str) {
    let case = build::case(name);
    let built = build::build(name);
    assert_eq!(
        to_hex(&sha256(&built.beef)),
        case["beef_sha256"].as_str().unwrap(),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    assert_eq!(
        built.subject,
        case["subject_txid"].as_str().unwrap(),
        "{name}"
    );
    let expected = match case["outcome"].as_str().unwrap() {
        "read" => Ok(1),
        "skipped" => Ok(0),
        other => panic!("{name}: unexpected outcome {other}"),
    };
    assert_eq!(
        read(built.beef).await,
        (expected.clone(), expected),
        "{name}: (resolve_by_attributes, discover_certificates)"
    );
}

/// The vector's count: four shapes.
#[test]
fn the_vector_holds_four_shapes_731() {
    assert_eq!(build::names().len(), 4);
}

/// X proven, raw then txid-only: skipped (GREEN at this door by the
/// resolver's `from_beef`, the parser's skip the unit pin's).
#[tokio::test]
async fn an_atomic_subject_written_raw_then_txid_only_is_skipped_at_the_door_731() {
    answers_as_recorded("proven_subject_raw_then_txid_only").await;
}

/// X proven, txid-only then raw: read.
#[tokio::test]
async fn an_atomic_subject_written_txid_only_then_raw_is_read_at_the_door_731() {
    answers_as_recorded("proven_subject_txid_only_then_raw").await;
}

/// X unproven over a proven parent, raw then txid-only: skipped (GREEN at
/// this door by the resolver's `from_beef`).
#[tokio::test]
async fn an_unproven_atomic_subject_written_raw_then_txid_only_is_skipped_at_the_door_731() {
    answers_as_recorded("unproven_subject_raw_then_txid_only").await;
}

/// X unproven over a proven parent, txid-only then raw: read.
#[tokio::test]
async fn an_unproven_atomic_subject_written_txid_only_then_raw_is_read_at_the_door_731() {
    answers_as_recorded("unproven_subject_txid_only_then_raw").await;
}
