//! #748: the evidence walk's visited set at the discovery door, against
//! `tests/vectors/identity_evidence_748.json`
//! (`tests/support/identity_evidence_748.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`
//! `parseEvidence` and the toolbox's `parseResults`): each BEEF rebuilt by
//! this crate's writer (`tests/support/identity_evidence_748.rs`) to the
//! recorded SHA-256 and served through both parsers (`resolve_by_attributes`,
//! `discover_certificates`) on #741's in-process facilitator on an
//! `.invalid` host, answered as `parseResults` answered it. Both shapes reach
//! one grandparent G twice (the subject spends P1:0 and P2:0, P1 spends G:0
//! and P2 G:1) and both read: an unproven G over a proven GG, walked once
//! (`:164-166`), where a walk without the visited set spends GG:0 twice and
//! skips the output (`:149`); a proven G of 4092 inputs, summed once to
//! 4096, where a walk without the set sums 8188 and refuses the discovery
//! (`limit`, `:170-171`). The code and line are the unit pin of
//! `src/identity/evidence_748_tests.rs`.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_748.rs"]
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
        words => Err(format!(
            "identity error: {}",
            words.strip_prefix("refused: ").unwrap()
        )),
    };
    assert_eq!(
        read(built.beef).await,
        (expected.clone(), expected),
        "{name}: (resolve_by_attributes, discover_certificates)"
    );
}

/// An unproven G spent by both unproven parents, over a proven GG: walked
/// once, GG:0 spent once, read; without the visited set GG:0 is spent twice
/// (`:149`) and the output skipped.
#[tokio::test]
async fn a_grandparent_shared_by_two_unproven_paths_is_walked_once_748() {
    answers_as_recorded("shared_unproven_grandparent").await;
}

/// A proven G of 4092 inputs reached through both parents: 4096 inputs
/// summed once, read; without the visited set 8188 refuses the discovery
/// (`:170-171`).
#[tokio::test]
async fn a_proven_grandparent_reached_twice_is_summed_once_748() {
    answers_as_recorded("proven_grandparent_reached_twice").await;
}
