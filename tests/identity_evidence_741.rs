//! #741: the evidence check's inputs bound over two unproven branches at the
//! discovery door, against `tests/vectors/identity_evidence_741.json`
//! (`tests/support/identity_evidence_741.mjs`, Node v22.18.0,
//! `ts-stack@edf6e03` `packages/sdk/src/transaction/TransactionEvidence.ts`
//! `parseEvidence` and the toolbox's `parseResults`): each BEEF rebuilt by
//! this crate's writer (`tests/support/identity_evidence_741.rs`) to the
//! recorded SHA-256 and served through both parsers (`resolve_by_attributes`,
//! `discover_certificates`) on #736's in-process facilitator on an
//! `.invalid` host, answered as `parseResults` answered it: a subject of 2
//! inputs, unproven parents of 2047 and 2048 inputs, one proven grandparent
//! with none, 4097 over the graph refusing the discovery in the reference's
//! words (`:170-171`, `identityUtils.ts:630-634` rethrowing); 2047 and 2047,
//! 4096, read. Along either path alone the sum is at most 2050: a walk
//! summing each branch alone reads both. The code and line are the unit pin
//! of `src/identity/evidence_741_tests.rs`.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_741.rs"]
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

/// 2 inputs at the subject, 2047 at P1 and 2048 at P2: 4097 over the graph
/// refuses the discovery (`:170-171`); 2047 and 2047 read. Each shape
/// answered by both parsers as the reference's discovery answers it, every
/// disagreement named.
#[tokio::test]
async fn the_inputs_bound_sums_over_two_unproven_branches_741() {
    let mut differ = Vec::new();
    for name in ["two_branches_over_bound", "two_branches_at_bound"] {
        let case = build::case(name);
        let built = build::build(name);
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
        let got = read(built.beef).await;
        if got != (expected.clone(), expected.clone()) {
            differ.push(format!("{name}: {got:?}, expected {expected:?} at both"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}
