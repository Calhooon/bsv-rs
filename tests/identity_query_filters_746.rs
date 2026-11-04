//! #746: `IdentityClient::query` keeps only the certificates its question
//! asked for. The subject (`identity_key`), the type (`certificate_type`) and
//! the certifier (`certifier`) are sent in the `ls_identity` query and were
//! never checked on the certificates read, so a host answering with another
//! subject's, type's or certifier's certificate was believed, as the two
//! `discover_*` doors believed it before #739 and #744. The door has no
//! reference counterpart (`IdentityClient.ts`'s lookups at `ts-stack@edf6e03`
//! are `resolveByIdentityKey` and `resolveByAttributes`): this crate's own
//! rule, hardening. The subject is compared lower-cased on both sides (the
//! rule of the by-key doors, #737, #739), the type as its canonical base64
//! text exactly (#744), the certifier as the certificate's key in lower-case
//! hex against the asked text lower-cased; a field the question does not
//! carry filters nothing.
//!
//! The asked token is #737's (#553's `reference` case: the subject 9, the
//! certifier 7, type `AQEB..AQE=`); the other subject's is #737's recorded
//! `other_subject` token (the scalar 10's); the other type's and the other
//! certifier's are the reference record re-typed or re-certified by the
//! scalar 8, re-signed and revealed by the subject 9, built by this crate's
//! writer.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{to_base64, to_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// The type #553's reference certificate carries.
const ASKED: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn record_553() -> Value {
    serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap()
}

fn vector_737() -> Value {
    serde_json::from_str(include_str!("vectors/identity_resolve_737.json")).unwrap()
}

fn scalar(n: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn hex_of(key: &PrivateKey) -> String {
    to_hex(&key.public_key().to_compressed())
}

/// #737's token: #553's `reference` case, the reference's own bytes.
fn reference_token() -> LockingScript {
    let v = record_553();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "reference")
        .unwrap();
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

/// #737's recorded `other_subject` token (the scalar 10's certificate).
fn other_subject_token() -> LockingScript {
    LockingScript::from_hex(vector_737()["tokens"]["other_subject"].as_str().unwrap()).unwrap()
}

/// The reference record re-typed to `cert_type`, signed by `certifier` as
/// its certifier, and revealed by the subject 9 (#744's `retyped_token`
/// with the certifier a parameter).
fn reissued(cert_type: [u8; 32], certifier: &PrivateKey) -> LockingScript {
    let subject = scalar(9);
    let mut record: Value = serde_json::from_str(record_553()["reference_text"].as_str().unwrap())
        .expect("the reference record");
    let keyring = record.as_object_mut().unwrap().remove("keyring").unwrap();
    let mut certificate: Certificate = serde_json::from_value(record).unwrap();
    certificate.cert_type = cert_type;
    certificate.subject = subject.public_key();
    certificate.certifier = certifier.public_key();
    certificate.signature = None;
    certificate.sign(certifier).unwrap();
    let mut json = serde_json::to_value(&certificate).unwrap();
    json["keyring"] = keyring;
    assert_eq!(json["type"], to_base64(&cert_type));
    revelation(&subject, &serde_json::to_vec(&json).unwrap())
}

/// The subject's signed revelation of `json`.
fn revelation(subject: &PrivateKey, json: &[u8]) -> LockingScript {
    let wallet = ProtoWallet::new(Some(subject.clone()));
    let protocol = Protocol::new(SecurityLevel::App, "identity");
    let key = wallet
        .get_public_key(GetPublicKeyArgs {
            protocol_id: Some(protocol.clone()),
            key_id: Some("1".into()),
            counterparty: Some(Counterparty::Anyone),
            for_self: Some(true),
            ..Default::default()
        })
        .unwrap()
        .public_key;
    let signature = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(json.to_vec()),
            protocol_id: protocol,
            key_id: "1".into(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    PushDrop::new(
        PublicKey::from_hex(&key).unwrap(),
        vec![json.to_vec(), signature],
    )
    .lock()
}

/// One lookup output: a proven transaction spending `<byte>`x32:0 into
/// `lock` (#737's `proven_spend`).
fn output(byte: &str, lock: LockingScript) -> OutputListItem {
    let mut input = TransactionInput::new(byte.repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, lock)).unwrap();
    let path = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(path);
    beef.merge_raw_tx(tx.to_binary(), Some(index));
    OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
        txid: None,
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

fn client(outputs: Vec<OutputListItem>) -> IdentityClient<ProtoWallet> {
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

/// Each certificate `query` keeps on `outputs`: its subject, type and
/// certifier, in order.
async fn kept(
    outputs: Vec<OutputListItem>,
    question: IdentityQuery,
) -> Vec<(String, String, String)> {
    client(outputs)
        .query(question)
        .await
        .unwrap()
        .iter()
        .flat_map(|r| r.certificates.iter())
        .map(|c| {
            (
                c.subject().to_hex(),
                c.type_base64(),
                c.certifier().to_hex(),
            )
        })
        .collect()
}

/// The asked token's certificate: the subject 9, the asked type, the
/// certifier 7.
fn asked() -> (String, String, String) {
    (hex_of(&scalar(9)), ASKED.to_string(), hex_of(&scalar(7)))
}

#[tokio::test]
async fn a_query_by_key_keeps_only_the_asked_subjects_certificates_746() {
    let key = hex_of(&scalar(9));
    assert_eq!(key, vector_737()["subject"].as_str().unwrap());
    let other = hex_of(&scalar(10));
    // #737's `other_subject_then_asked` shape
    let outputs = || {
        vec![
            output("77", other_subject_token()),
            output("11", reference_token()),
        ]
    };

    // Both admitted by the parser: a question with no filter keeps both
    let all = kept(outputs(), IdentityQuery::default()).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].0, other);
    assert_eq!(all[1], asked());

    // The asked key, lower- and upper-cased: the asked subject's alone
    assert_eq!(
        kept(outputs(), IdentityQuery::by_identity_key(&key)).await,
        vec![asked()]
    );
    assert_eq!(
        kept(
            outputs(),
            IdentityQuery::by_identity_key(key.to_uppercase())
        )
        .await,
        vec![asked()]
    );
    // Another subject's alone answers nothing
    assert!(kept(
        vec![output("77", other_subject_token())],
        IdentityQuery::by_identity_key(&key)
    )
    .await
    .is_empty());
}

#[tokio::test]
async fn a_query_by_type_keeps_only_the_asked_types_certificates_746() {
    let other = to_base64(&[3u8; 32]);
    let outputs = || {
        vec![
            output("11", reference_token()),
            output("22", reissued([3u8; 32], &scalar(7))),
        ]
    };
    let by_type = |cert_type: &str| IdentityQuery {
        certificate_type: Some(cert_type.to_string()),
        ..Default::default()
    };

    let all = kept(outputs(), IdentityQuery::default()).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[1].1, other);

    // The asked type's alone, either way round
    assert_eq!(kept(outputs(), by_type(ASKED)).await, vec![asked()]);
    let types: Vec<String> = kept(outputs(), by_type(&other))
        .await
        .into_iter()
        .map(|c| c.1)
        .collect();
    assert_eq!(types, vec![other.clone()]);
    // The canonical text exactly: the asked type unpadded matches nothing
    assert!(kept(outputs(), by_type(ASKED.trim_end_matches('=')))
        .await
        .is_empty());
}

#[tokio::test]
async fn a_query_by_certifier_keeps_only_the_asked_certifiers_certificates_746() {
    let seven = hex_of(&scalar(7));
    let eight = hex_of(&scalar(8));
    let outputs = || {
        vec![
            output("33", reissued([1u8; 32], &scalar(8))),
            output("11", reference_token()),
        ]
    };
    let by_certifier = |certifier: &str| IdentityQuery::default().with_certifier(certifier);

    let all = kept(outputs(), IdentityQuery::default()).await;
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].2, eight);

    // The asked certifier's alone, lower- and upper-cased, either way round
    assert_eq!(kept(outputs(), by_certifier(&seven)).await, vec![asked()]);
    assert_eq!(
        kept(outputs(), by_certifier(&seven.to_uppercase())).await,
        vec![asked()]
    );
    let certifiers: Vec<String> = kept(outputs(), by_certifier(&eight))
        .await
        .into_iter()
        .map(|c| c.2)
        .collect();
    assert_eq!(certifiers, vec![eight]);
}

/// The four certificates of one answer: the asked one, another subject's,
/// another type's, another certifier's.
fn four() -> Vec<OutputListItem> {
    vec![
        output("77", other_subject_token()),
        output("22", reissued([3u8; 32], &scalar(7))),
        output("33", reissued([1u8; 32], &scalar(8))),
        output("11", reference_token()),
    ]
}

/// Every filter at once: of the four, the asked certificate alone.
#[tokio::test]
async fn every_filter_together_keeps_the_asked_certificate_alone_746() {
    let question = IdentityQuery {
        identity_key: Some(hex_of(&scalar(9))),
        certificate_type: Some(ASKED.to_string()),
        certifier: Some(hex_of(&scalar(7))),
        ..Default::default()
    };
    assert_eq!(kept(four(), question).await, vec![asked()]);
}

/// A question with no filter keeps every admitted certificate, in the
/// answer's order (GREEN before #746 too: the walk unchanged; the seam
/// `tests/identity_resolve_737.rs`'s `admitted` reads through).
#[tokio::test]
async fn a_question_with_no_filter_keeps_every_admitted_certificate_746() {
    let all = kept(four(), IdentityQuery::default()).await;
    let ten = hex_of(&scalar(10));
    let (nine, seven, eight) = (hex_of(&scalar(9)), hex_of(&scalar(7)), hex_of(&scalar(8)));
    assert_eq!(
        all,
        vec![
            (ten, ASKED.to_string(), seven.clone()),
            (nine.clone(), to_base64(&[3u8; 32]), seven.clone()),
            (nine.clone(), ASKED.to_string(), eight),
            (nine, ASKED.to_string(), seven),
        ]
    );
}
