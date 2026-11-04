//! #730: the identity parsers run the reference's evidence check before
//! they read a lookup output (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/TransactionEvidence.ts:93-201`, reached by
//! the toolbox's discovery through `IdentityEvidenceVerifier.parse`,
//! `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:600-634`):
//! an `invalid-evidence` refusal skips the output, a `limit` refuses the
//! discovery in the reference's words, as its verifier rethrows it
//! (`:630-634`, `Wallet.ts:950-955`). Against
//! `tests/vectors/identity_evidence_730.json`
//! (`tests/support/identity_evidence_730.mjs`, Node v22.18.0): each BEEF
//! rebuilt by this crate's writer (`tests/support/identity_evidence_730.rs`)
//! to the recorded SHA-256, its subject's output 0 the reference's own
//! revelation token, and served through both parsers
//! (`resolve_by_attributes`, `discover_certificates`) on an in-process
//! facilitator on an `.invalid` host, each answered as `parseResults`
//! answered it. The check's codes and lines are the unit pins of
//! `src/identity/evidence_730_tests.rs`.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_730.rs"]
mod build;

use bsv_rs::identity::IdentityClient;
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::transaction::{Beef, Kind};
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

/// How many identities and certificates the two parsers return for `beef`,
/// or the words of the refusal.
async fn read(beef: Vec<u8>) -> Result<(usize, usize), String> {
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
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);
    let attributes = IndexMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .map_err(|e| e.to_string())?;
    let certificates = client
        .discover_certificates(&subject())
        .await
        .map_err(|e| e.to_string())?;
    Ok((identities.len(), certificates.len()))
}

/// The shape `name`, rebuilt to the recorded bytes: its BEEF and the
/// discovery's recorded answer (`parseResults`' outcome).
fn shape(name: &str) -> (Vec<u8>, Result<(usize, usize), String>, Value) {
    let v = build::vector();
    let case = v["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no shape {name}"))
        .clone();
    let built = build::build(name, case["size"].as_u64().map(|n| n as usize));
    assert_eq!(
        to_hex(&sha256(&built.beef)),
        case["beef_sha256"].as_str().unwrap(),
        "{name}: this crate's writer and the reference's recorded bytes"
    );
    let expected = match case["outcome"].as_str().unwrap() {
        "read" => Ok((1, 1)),
        "skipped" => Ok((0, 0)),
        words => Err(format!(
            "identity error: {}",
            words.strip_prefix("refused: ").unwrap()
        )),
    };
    (built.beef, expected, case)
}

/// Each shape answered as the reference's discovery answers it, every
/// disagreement named.
async fn agrees(names: &[&str]) {
    let mut differ = Vec::new();
    for name in names {
        let (beef, expected, case) = shape(name);
        let got = read(beef).await;
        if got != expected {
            differ.push(format!(
                "{name} ({}): {got:?}, expected {expected:?}",
                case["check"]
            ));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// Two unproven parents spend the proven grandparent's output 0 and the
/// subject spends both: the reference's walk refuses the second spend of
/// one outpoint (`TransactionEvidence.ts:149`), `invalid-evidence`, and the
/// output is skipped.
#[tokio::test]
async fn a_second_spend_of_one_outpoint_in_the_graph_is_skipped_730() {
    agrees(&["second_spend_in_graph"]).await;
}

/// An unproven subject with no inputs (`:174`): skipped.
#[tokio::test]
async fn an_unproven_transaction_without_inputs_is_skipped_730() {
    agrees(&["unproven_no_inputs"]).await;
}

/// A proven subject of 4096 inputs read, of 4097 the discovery refused
/// (`limits.inputs`, `:170-171`); its scripts at 262144 bytes read, at
/// 262145 refused (`limits.scriptBytes`).
#[tokio::test]
async fn the_inputs_and_script_bytes_limits_refuse_the_discovery_past_their_bounds_730() {
    agrees(&[
        "inputs_at_bound",
        "inputs_over_bound",
        "script_bytes_at_bound",
        "script_bytes_over_bound",
    ])
    .await;
}

/// An Atomic BEEF of 256 transactions read, of 257 refused
/// (`limits.transactions`, `:117`); of 1048576 bytes read, of 1048577
/// refused (`limits.candidateBytes`, `:101`), the extra entries outside the
/// subject's graph.
#[tokio::test]
async fn the_transactions_and_candidate_bytes_limits_refuse_the_discovery_past_their_bounds_730() {
    agrees(&[
        "transactions_at_bound",
        "transactions_over_bound",
        "candidate_bytes_at_bound",
        "candidate_bytes_over_bound",
    ])
    .await;
}

/// A proven parent ends its branch (`:173`): its own parent absent, the
/// subject is read on both sides. An agreement.
#[tokio::test]
async fn a_proven_parent_ends_the_walk_with_its_parent_absent_730() {
    agrees(&["proven_parent_absent_grandparent"]).await;
}

/// #728's shape 4 with the grandparent present raw and proven by its own
/// BUMP, the parent's entry still naming a BUMP of another txid: the
/// reference links the grandparent (`Beef.ts:649-666`, the BUMP found by
/// txid) and stops at its proof (`TransactionEvidence.ts:173`), reading the
/// subject; `parseEvidence` asks no BUMP index of its leaf. This crate reads
/// it too: the guard of #730's design, the check at this door the walk and
/// not `Beef::verify_structure`, which refuses the BEEF `TxidNotInBump`
/// (as the streaming reader's `check_bump_index` does).
#[tokio::test]
async fn a_parent_whose_bump_names_another_txid_is_read_when_its_parent_is_proven_730() {
    let name = "bump_names_another_txid_grandparent_proven";
    let (beef, expected, case) = shape(name);
    assert_eq!(expected, Ok((1, 1)), "the reference reads it");
    assert_eq!(case["selected_txid"], case["subject_txid"]);
    let mut parsed = Beef::from_binary(&beef).unwrap();
    assert_eq!(parsed.verify_structure(), Err(Kind::TxidNotInBump));
    assert_eq!(read(beef).await, expected, "this crate");
}
