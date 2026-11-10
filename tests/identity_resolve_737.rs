//! #737: `resolve_by_identity_key` reads every output of the `ls_identity`
//! lookup answer before it answers, as the reference's wallet walks them
//! (`ts-stack@edf6e03` `packages/wallet/wallet-toolbox/src/Wallet.ts:950-1016`,
//! through `parseResults`, `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:671-707`:
//! each output parsed in order, a skipped one dropped, a `limit` anywhere
//! rethrown), keeps only the asked subject's certificates
//! (`filterCertificatesByIdentityKey`, `identityUtils.ts:247-255`, called at
//! `Wallet.ts:1012`), where it read `outputs[0]` alone; and, since the list
//! (the owner's word of 2026-11-04 13:5xZ), returns every one's identity in
//! the trust step's order (`transformVerifiableCertificatesWithTrust`,
//! `identityUtils.ts:313-382`: one per type, serial number and certifier,
//! the most trusted ahead, ties in the answer's order), where it returned
//! the earliest. Against `tests/vectors/identity_resolve_737.json`
//! (`tests/support/identity_resolve_737.mjs`, Node v22.18.0): each answer
//! rebuilt by this crate's writer to the recorded SHA-256 and served on an
//! in-process facilitator on an `.invalid` host, the identities answered as
//! the reference's `resolveByIdentityKey` answers them
//! (`packages/sdk/src/identity/IdentityClient.ts:559-591`), keys and names in
//! order; and the certificates `parseResults` admits (their count and serial
//! numbers) read by this crate's `query` over the same parser, every shape.
//! One shape is stated: two certifiers at unequal trust, which the reference
//! wallet's trust settings order and this crate, holding none, does not.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs as sdk;

#[path = "support/identity_evidence_730.rs"]
mod build;

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_hex, sha256, to_base64, to_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::ProtoWallet;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_resolve_737.json")).unwrap()
}

/// #553's token named `name`.
fn token_of(name: &str) -> LockingScript {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

/// A proven transaction spending `<byte>`x32:0 with an empty unlocking
/// script, one 1-satoshi output locked by `lock`, its BUMP a lone leaf at
/// offset 0 at 900: the recorder's `proven(spending(..))`.
fn proven_spend(byte: &str, lock: LockingScript) -> Vec<u8> {
    let mut input = TransactionInput::new(byte.repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, lock)).unwrap();
    let path = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(path);
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    beef.to_binary().expect("the BEEF is writable")
}

/// A token the recorder issued, under the vector's `tokens`.
fn issued(name: &str) -> LockingScript {
    LockingScript::from_hex(vector()["tokens"][name].as_str().unwrap()).unwrap()
}

/// The recorder's `overBound`: 256 txid-only entries and a proven subject
/// spending `<byte>`x32:0 into #553's token, under an Atomic BEEF prefix.
fn over_bound(byte: &str, n: usize) -> Vec<u8> {
    let mut input = TransactionInput::new(byte.repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut subject = Transaction::new();
    subject.add_input(input).unwrap();
    subject
        .add_output(TransactionOutput::new(1, token_of("reference")))
        .unwrap();
    let mut beef = Beef::new();
    for i in 1..=n {
        beef.merge_txid_only(format!("{i:064x}"));
    }
    let path = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, subject.id())]]).unwrap();
    let index = beef.merge_bump(path);
    beef.merge_raw_tx(subject.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    let mut writer = Writer::new();
    writer.write_u32_le(0x0101_0101);
    let mut txid = from_hex(&subject.id()).unwrap();
    txid.reverse();
    writer.write_bytes(&txid);
    writer.write_bytes(&beef.to_binary().expect("the BEEF is writable"));
    writer.into_bytes()
}

/// The recorder's builder `name` at `size`.
fn built(name: &str, size: Option<usize>) -> Vec<u8> {
    match name {
        "reference_11" => proven_spend("11", token_of("reference")),
        "reference_55" => proven_spend("55", token_of("reference")),
        "second_certificate_55" => proven_spend("55", token_of("fields_at_bound")),
        "other_subject_77" => proven_spend("77", issued("other_subject")),
        "second_name_11" => proven_spend("11", issued("second_name")),
        "other_certifier_33" => proven_spend("33", issued("other_certifier")),
        "op_true_66" => proven_spend("66", LockingScript::from_hex("51").unwrap()),
        "transactions_over_bound_88" => over_bound("88", size.unwrap()),
        "unproven_no_inputs" | "transactions_over_bound" => build::build(name, size).beef,
        other => panic!("no builder {other}"),
    }
}

/// A facilitator answering every question with its outputs.
struct Answering(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.clone(),
        })
    }
}

/// The identities' keys and names in order, or the words of the refusal.
type Answer = Result<Vec<(String, String)>, String>;

/// The certificates admitted (their serial numbers in order), or the words
/// of the refusal.
type Admitted = Result<Vec<String>, String>;

/// A client whose resolver answers every question with `outputs`, each
/// output at its recorded index.
fn client(outputs: Vec<(Vec<u8>, u32)>) -> IdentityClient<ProtoWallet> {
    let outputs = outputs
        .into_iter()
        .map(|(beef, output_index)| OutputListItem {
            beef,
            output_index,
            context: None,
            txid: None,
        })
        .collect();
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(outputs))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver)
}

/// `resolve_by_identity_key`'s answer on `outputs`.
async fn resolve(outputs: Vec<(Vec<u8>, u32)>, key: &str) -> Answer {
    client(outputs)
        .resolve_by_identity_key(key, false)
        .await
        .map(|found| {
            found
                .into_iter()
                .map(|identity| (identity.identity_key, identity.name))
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// The certificates this crate's parser admits on `outputs`, read through
/// `query` with a question that carries no filter, which walks every output
/// with the parser `resolve_by_identity_key` uses and keeps every subject,
/// as `parseResults` does (since #746 a question naming a key keeps only
/// that subject's).
async fn admitted(outputs: Vec<(Vec<u8>, u32)>) -> Admitted {
    client(outputs)
        .query(IdentityQuery::default())
        .await
        .map(|results| {
            results
                .iter()
                .flat_map(|r| r.certificates.iter())
                .map(|c| to_base64(c.serial_number()))
                .collect()
        })
        .map_err(|e| e.to_string())
}

/// The shape `name`: its outputs rebuilt to the recorded bytes at their
/// recorded indices, the reference's identities in order (or its refusal)
/// and the recorded case.
fn shape(name: &str) -> (Vec<(Vec<u8>, u32)>, Answer, Value) {
    let v = vector();
    let case = v["shapes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no shape {name}"))
        .clone();
    let outputs = case["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            let bytes = built(
                o["builder"].as_str().unwrap(),
                o["size"].as_u64().map(|n| n as usize),
            );
            assert_eq!(
                to_hex(&sha256(&bytes)),
                o["beef_sha256"].as_str().unwrap(),
                "{name}: this crate's writer and the reference's recorded bytes"
            );
            (bytes, o["output_index"].as_u64().unwrap() as u32)
        })
        .collect();
    let outcome = case["outcome"].as_str().unwrap();
    let expected = if let Some(words) = outcome.strip_prefix("refused: ") {
        Err(format!("identity error: {words}"))
    } else {
        let texts = |member: &str| -> Vec<String> {
            case[member]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect()
        };
        let list: Vec<(String, String)> = texts("identity_subjects")
            .into_iter()
            .zip(texts("identity_names"))
            .collect();
        assert_eq!(case["identities"], list.len(), "{name}: the recorded count");
        Ok(list)
    };
    (outputs, expected, case)
}

/// The certificates `parseResults` admitted on the shape (the count and
/// serial numbers), or its refusal, as recorded.
fn recorded_admitted(case: &Value) -> Admitted {
    match case["outcome"].as_str().unwrap().strip_prefix("refused: ") {
        Some(words) => {
            assert!(case["certificates"].is_null() && case["serial_numbers"].is_null());
            Err(format!("identity error: {words}"))
        }
        None => {
            let serials: Vec<String> = case["serial_numbers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();
            assert_eq!(case["certificates"], serials.len());
            Ok(serials)
        }
    }
}

/// Each shape answered with the reference's identities in its order, and
/// its admitted certificates the reference's, every disagreement named.
async fn agrees(names: &[&str]) {
    let key = vector()["subject"].as_str().unwrap().to_string();
    let mut differ = Vec::new();
    for name in names {
        let (outputs, expected, case) = shape(name);
        let got = resolve(outputs.clone(), &key).await;
        if got != expected {
            differ.push(format!(
                "{name} ({}): {got:?}, expected {expected:?}",
                case["check"]
            ));
        }
        let (got, expected) = (admitted(outputs).await, recorded_admitted(&case));
        if got != expected {
            differ.push(format!("{name} admitted: {got:?}, expected {expected:?}"));
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// Shape (i): a first output the evidence check refuses
/// (`TransactionEvidence.ts:174`) or that carries no identity token
/// (`decodeIdentityOutput` null, `identityUtils.ts:609-610`), the token second:
/// the reference drops the first and reads the second; this crate read
/// `outputs[0]` alone and answered `None`. The refused output carries
/// alice's token and the second another of the subject's (carol, another
/// serial number), so an evidence skip that broke would answer alice.
#[tokio::test]
async fn a_skipped_first_output_is_passed_over_for_the_token_after_it_737() {
    let (_, expected, _) = shape("refused_first_then_token");
    assert_eq!(
        expected.unwrap()[0].1,
        "carol@example.com",
        "the second output's token, not the refused one's"
    );
    agrees(&["refused_first_then_token", "non_identity_first_then_token"]).await;
}

/// Shape (iv): another subject's certificate (the scalar 10's, signed by
/// it) alone, before the asked one's, and after a skipped output: the
/// reference reads it and drops it by subject (`identityUtils.ts:247-255`,
/// `Wallet.ts:1012`), answering the asked identity or none; this crate
/// answered the other subject's (`Ok(Some(bob))` at `a3f5fd03`).
#[tokio::test]
async fn another_subjects_certificate_is_not_the_asked_identity_737() {
    agrees(&[
        "other_subject_alone",
        "other_subject_then_asked",
        "skipped_then_other_subject_then_asked",
    ])
    .await;
}

/// The token first (a skipped output after it), one certificate at two
/// outpoints (one identity, the trust step keeping one per type, serial
/// number and certifier, `identityUtils.ts:360-361`, ported) and one
/// outpoint twice (read once, `:699-702`; the resolver's dedup here): one
/// identity on both sides.
#[tokio::test]
async fn the_token_first_and_one_certificate_twice_resolve_to_its_identity_737() {
    agrees(&[
        "token_then_refused",
        "one_certificate_two_outpoints",
        "same_output_twice",
    ])
    .await;
}

/// Shape (iii): a first output over `limits.transactions` (257
/// transactions, `TransactionEvidence.ts:117`), the token second: the
/// reference rethrows (`identityUtils.ts:630-634`) and the discovery is
/// refused in its words, `Transaction evidence: limit`; so here.
#[tokio::test]
async fn a_limit_on_the_first_output_refuses_the_resolution_737() {
    agrees(&["limit_first_then_token"]).await;
}

/// Shape (iii) after the token: an admitted output, then one over
/// `limits.transactions` (its subject spending `88`x32:0, another txid):
/// `parseResults` parses every output before it answers and rethrows the
/// limit (`identityUtils.ts:630-634,671-707`, `Wallet.ts:950-955`); this
/// crate answered the token's identity at once (`Ok(Some(..))` at `a3f5fd03`).
#[tokio::test]
async fn a_limit_after_an_admitted_output_refuses_the_resolution_737() {
    agrees(&["token_then_limit"]).await;
}

/// Shape (ii): two admitted certificates of the subject, both identities
/// in the answer's order (`IdentityClient.ts:568-571`, `DisplayableIdentity[]`),
/// where this crate returned the earliest (`Option`, until the list).
#[tokio::test]
async fn two_certificates_resolve_to_both_identities_in_order_737() {
    let (_, expected, _) = shape("two_certificates");
    assert_eq!(expected.unwrap().len(), 2, "the reference returns both");
    agrees(&["two_certificates"]).await;
}

/// Shape (v), the list's three outputs: the subject's certificate by the
/// certifier 7, a skipped output, its certificate by the certifier 8, both
/// trusted at one level: both identities, the answer's order (the trust
/// step's stable sort, `identityUtils.ts:378`, at equal trust).
#[tokio::test]
async fn two_certifiers_around_a_skipped_output_resolve_in_the_answers_order_737() {
    let (_, expected, case) = shape("two_certifiers_around_a_skipped_output");
    assert_eq!(case["outputs"].as_array().unwrap().len(), 3);
    let names: Vec<String> = expected.unwrap().into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, ["alice@example.com", "dave@example.com"]);
    agrees(&["two_certifiers_around_a_skipped_output"]).await;
}

/// One output, one identity; no output, and another subject's certificate
/// alone, the empty list, as the reference's `parseIdentities` of no
/// certificate (`IdentityClient.ts:568-571`), where this crate answered
/// `Ok(None)`.
#[tokio::test]
async fn one_output_is_a_one_element_list_and_none_the_empty_list_737() {
    agrees(&["token_alone", "no_outputs", "other_subject_alone"]).await;
}

/// The stated difference: the same answer with the certifier 8 trusted at 2
/// and the certifier 7 at 1. The reference wallet's trust sort puts the
/// certifier 8's identity ahead (`identityUtils.ts:378`, its trust settings,
/// `Wallet.ts:990,1010-1013`); this crate holds no trust settings (each
/// certificate's `certifier_info.trust` one constant), so its order is the
/// answer's, the reference's reversed.
#[tokio::test]
async fn two_certifiers_at_unequal_trust_keep_the_answers_order_stated_737() {
    let (outputs, expected, case) = shape("two_certifiers_trust_ordered");
    assert!(case["trust_levels"].is_object(), "the recorded settings");
    let key = vector()["subject"].as_str().unwrap().to_string();
    let mut reversed = expected.unwrap();
    let names: Vec<&str> = reversed.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(
        names,
        ["dave@example.com", "alice@example.com"],
        "the reference"
    );
    reversed.reverse();
    assert_eq!(resolve(outputs, &key).await, Ok(reversed), "this crate");
}
