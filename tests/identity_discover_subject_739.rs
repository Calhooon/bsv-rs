//! #739: `discover_certificates` and `discover_certificates_by_type`, this
//! crate's own by-key discovery doors, keep only certificates whose subject
//! is the asked key, where they returned another subject's, so an overlay
//! host answering a by-key discovery with another subject's certificate was
//! shown as that key's. The reference has no counterpart door; the rule
//! carried over is the one `resolve_by_identity_key` takes from its
//! discovery (`filterCertificatesByIdentityKey`, `ts-stack@edf6e03`
//! `packages/wallet/wallet-toolbox/src/utility/identityUtils.ts:247-255`,
//! called at `Wallet.ts:1012`, #737), and the witness is
//! `tests/vectors/identity_resolve_737.json`'s reference verdict on the same
//! shapes (`tests/support/identity_resolve_737.mjs`, Node v22.18.0): another
//! subject's certificate alone, no identity; the other subject then the
//! asked one, the asked one alone. Each answer rebuilt by this crate's
//! writer to the recorded SHA-256 and served on an in-process facilitator on
//! an `.invalid` host.
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
use bsv_rs::primitives::{from_hex, sha256, to_hex, Writer};
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
    let mut input = TransactionInput::new(byte.repeat(32).parse().unwrap(), 0);
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
    let mut input = TransactionInput::new(byte.repeat(32).parse().unwrap(), 0);
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

/// The shape `name`'s outputs, rebuilt to the recorded bytes at their
/// recorded indices, and the subjects of the identities the reference
/// returns on it.
fn shape(name: &str) -> (Vec<(Vec<u8>, u32)>, Vec<String>) {
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
    let subjects = case["identity_subjects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    (outputs, subjects)
}

/// The asked key, upper-cased when `upper` (the comparison is lower-cased).
fn asked(upper: bool) -> String {
    let key = vector()["subject"].as_str().unwrap().to_string();
    if upper {
        key.to_uppercase()
    } else {
        key
    }
}

/// The subjects of the certificates `discover_certificates` returns.
async fn discover(outputs: Vec<(Vec<u8>, u32)>, key: &str) -> Vec<String> {
    let found = client(outputs).discover_certificates(key).await.unwrap();
    found.iter().map(|c| c.subject().to_hex()).collect()
}

/// The subjects of the certificates `discover_certificates_by_type` returns.
async fn discover_by_type(outputs: Vec<(Vec<u8>, u32)>, key: &str) -> Vec<String> {
    let found = client(outputs)
        .discover_certificates_by_type(key, &format!("{}AQE=", "AQEB".repeat(10)))
        .await
        .unwrap();
    found.iter().map(|c| c.subject().to_hex()).collect()
}

/// `discover_certificates` on shape (iv): another subject's certificate
/// alone is no certificate of the asked key (`Ok(vec![])`, the reference's
/// 0 identities on `other_subject_alone`), and after it the asked one's is
/// returned alone (`other_subject_then_asked`, the reference's one
/// identity); the base returned the other subject's certificate on both.
/// The key asked upper-cased answers the same.
#[tokio::test]
async fn discover_certificates_keeps_only_the_asked_subjects_certificates_739() {
    for name in [
        "other_subject_alone",
        "other_subject_then_asked",
        "skipped_then_other_subject_then_asked",
    ] {
        let (outputs, expected) = shape(name);
        for upper in [false, true] {
            assert_eq!(
                discover(outputs.clone(), &asked(upper)).await,
                expected,
                "{name}, upper-cased {upper}"
            );
        }
    }
}

/// `discover_certificates_by_type` on the same shapes, the same rule.
#[tokio::test]
async fn discover_certificates_by_type_keeps_only_the_asked_subjects_certificates_739() {
    for name in [
        "other_subject_alone",
        "other_subject_then_asked",
        "skipped_then_other_subject_then_asked",
    ] {
        let (outputs, expected) = shape(name);
        for upper in [false, true] {
            assert_eq!(
                discover_by_type(outputs.clone(), &asked(upper)).await,
                expected,
                "{name}, upper-cased {upper}"
            );
        }
    }
}

/// The control: the asked subject's own certificates, every one returned
/// (two certificates of the subject, the reference's two identities), so
/// the filter drops nothing of the asked key's.
#[tokio::test]
async fn the_asked_subjects_own_certificates_are_all_returned_739() {
    let (outputs, expected) = shape("two_certificates");
    assert_eq!(expected.len(), 2);
    assert_eq!(discover(outputs.clone(), &asked(false)).await, expected);
    assert_eq!(discover_by_type(outputs, &asked(true)).await, expected);
}
