//! #751: an attribute question keeps only the certificates matching it, as
//! the reference wallet's `discoverByAttributes` re-binds its answer
//! (`ts-stack@edf6e03` `packages/wallet/wallet-toolbox/src/Wallet.ts:1069-1082`,
//! `filterCertificatesByAttributes`, `utility/identityUtils.ts:140-293`).
//! Until #751 `IdentityClient::query` sent `attributes` to `ls_identity` and
//! checked none on the answer, and `resolve_by_attributes` kept every
//! certificate admitted, so a host could answer an attribute question with
//! any certificate the parser admits. The matcher reads the decrypted fields
//! (the anyone wallet's), so a certificate whose revealed field does not
//! decrypt carries none and matches nothing.
//!
//! The tokens are #737's (#553's `reference` case: the subject 9 revealing
//! `email` `alice@example.com`; the recorded `second_name`, the subject 9
//! revealing `carol@example.com`) and one built here by this crate's writer:
//! the reference record with its keyring value replaced by bytes that decrypt
//! to nothing, re-revealed by the subject 9. The matcher's own table is the
//! unit module `src/identity/client_attributes_751_tests.rs`. Injected
//! `.invalid` resolver; no network.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
};
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

fn record_553() -> Value {
    serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap()
}

/// #553's `reference` token: alice's email, revealed by the subject 9.
fn alice() -> LockingScript {
    let v = record_553();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "reference")
        .unwrap();
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

/// #737's recorded `second_name` token: carol's email, the subject 9.
fn carol() -> LockingScript {
    let v: Value = serde_json::from_str(include_str!("vectors/identity_resolve_737.json")).unwrap();
    LockingScript::from_hex(v["tokens"]["second_name"].as_str().unwrap()).unwrap()
}

fn scalar(n: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
}

/// The reference record (alice's) with its keyring value 80 bytes of `07`,
/// which the anyone wallet cannot decrypt, revealed by the subject 9.
fn undecryptable() -> LockingScript {
    let mut record: Value =
        serde_json::from_str(record_553()["reference_text"].as_str().unwrap()).unwrap();
    record["keyring"]["email"] = Value::String(to_base64(&[7u8; 80]));
    let json = serde_json::to_vec(&record).unwrap();
    let subject = scalar(9);
    let wallet = ProtoWallet::new(Some(subject));
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
            data: Some(json.clone()),
            protocol_id: protocol,
            key_id: "1".into(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    PushDrop::new(PublicKey::from_hex(&key).unwrap(), vec![json, signature]).lock()
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
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    OutputListItem {
        beef: beef.to_binary().expect("the BEEF is writable"),
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

/// The answer of three: alice's, carol's, the undecryptable one.
fn three() -> Vec<OutputListItem> {
    vec![
        output("01", alice()),
        output("02", carol()),
        output("03", undecryptable()),
    ]
}

/// Each kept certificate's decrypted email (`""` for none), in order.
async fn emails(question: IdentityQuery) -> Vec<String> {
    client(three())
        .query(question)
        .await
        .unwrap()
        .into_iter()
        .map(|result| result.identity.name)
        .collect()
}

fn email(value: &str) -> IndexMap<String, String> {
    IndexMap::from([("email".to_string(), value.to_string())])
}

/// Without attributes nothing is matched: the three certificates read, the
/// undecryptable one under the parser's default name (green on the base).
#[tokio::test]
async fn a_question_without_attributes_keeps_every_certificate_751() {
    let names = emails(IdentityQuery::default()).await;
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(names[..2], ["alice@example.com", "carol@example.com"]);
}

#[tokio::test]
async fn a_host_answering_an_attribute_question_with_another_certificate_is_not_believed_at_query_751(
) {
    assert_eq!(
        emails(IdentityQuery::by_attributes(email("alice@example.com"))).await,
        ["alice@example.com"]
    );
    assert_eq!(
        emails(IdentityQuery::by_attributes(email("carol example"))).await,
        ["carol@example.com"]
    );
    // A value no certificate carries, and the reference's `any`
    assert!(emails(IdentityQuery::by_attributes(email("dave")))
        .await
        .is_empty());
    let any = IndexMap::from([("any".to_string(), "carol".to_string())]);
    assert_eq!(
        emails(IdentityQuery::by_attributes(any)).await,
        ["carol@example.com"]
    );
}

/// Only blank values: nothing usable, nothing kept (`identityUtils.ts:291`).
#[tokio::test]
async fn an_attribute_question_with_nothing_usable_keeps_nothing_751() {
    assert!(emails(IdentityQuery::by_attributes(email("   ")))
        .await
        .is_empty());
}

/// The undecryptable certificate carries no field and matches no attribute,
/// whichever value is asked, the reference record's own included.
#[tokio::test]
async fn an_undecryptable_certificate_is_dropped_from_an_attribute_question_751() {
    let kept = client(vec![output("03", undecryptable())])
        .query(IdentityQuery::by_attributes(email("alice@example.com")))
        .await
        .unwrap();
    assert!(kept.is_empty(), "{} kept", kept.len());
    let any = IndexMap::from([("any".to_string(), "alice".to_string())]);
    let kept = client(vec![output("03", undecryptable())])
        .query(IdentityQuery::by_attributes(any))
        .await
        .unwrap();
    assert!(kept.is_empty(), "{} kept", kept.len());
}

/// `resolve_by_attributes` sends a lone attribute as `any` and judges the
/// answer by the same search (`alice`: alice's kept, carol's and the
/// undecryptable one dropped); two attributes judged by name; an empty map
/// keeps nothing.
#[tokio::test]
async fn a_host_answering_an_attribute_question_with_another_certificate_is_not_believed_at_resolve_751(
) {
    let names = |list: Vec<bsv_rs::identity::DisplayableIdentity>| {
        list.into_iter().map(|i| i.name).collect::<Vec<_>>()
    };
    let lone = client(three())
        .resolve_by_attributes(email("alice"), false)
        .await
        .unwrap();
    assert_eq!(names(lone), ["alice@example.com"]);
    // The `any` search is the overlay's text search, by tokens: carol's
    // `example` and `com` match a lone `alice@example.com` there and here
    let tokens = client(three())
        .resolve_by_attributes(email("alice@example.com"), false)
        .await
        .unwrap();
    assert_eq!(names(tokens), ["alice@example.com", "carol@example.com"]);
    let two = IndexMap::from([
        ("email".to_string(), "carol@example.com".to_string()),
        ("name".to_string(), "carol".to_string()),
    ]);
    // `name` is not revealed: no certificate carries it decrypted
    assert!(client(three())
        .resolve_by_attributes(two, false)
        .await
        .unwrap()
        .is_empty());
    assert!(client(three())
        .resolve_by_attributes(IndexMap::new(), false)
        .await
        .unwrap()
        .is_empty());
}

/// The type beside attributes (#756's pin): the overlay searches by the
/// attributes alone (`IdentityLookupService.ts:132-135`), and the answer is
/// still filtered here by the type and by the attributes: alice's certificate
/// (type `AQEB..AQE=`) kept under its type and dropped under another.
#[tokio::test]
async fn a_type_beside_attributes_filters_by_both_751() {
    let mut question = IdentityQuery::by_attributes(email("example"));
    question.certificate_type = Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into());
    assert_eq!(
        emails(question.clone()).await,
        ["alice@example.com", "carol@example.com"]
    );
    question.certificate_type = Some("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into());
    assert!(emails(question).await.is_empty());
}
