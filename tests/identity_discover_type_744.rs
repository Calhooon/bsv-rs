//! #744: `discover_certificates_by_type` keeps only the certificates whose
//! type is the asked one. The type is sent in the `ls_identity` query and
//! was never checked on the certificates read, so a host answering a by-type
//! discovery with another type's certificate was believed. The door has no
//! reference counterpart (`DiscoverByIdentityKeyArgs` carries no type at
//! `ts-stack@edf6e03`): this crate's own rule, hardening. The comparison is
//! the certificate's canonical base64 text (`type_base64`) against the asked
//! text, exactly: a token's type is canonical base64 of 32 bytes (#553), so
//! its re-encoding is the token's own text.
//!
//! The asked-type token is #737's (#553's `reference` case, the subject 9,
//! the certifier 7, type `AQEB..AQE=`); the other-type token is the same
//! record re-typed, re-signed by the certifier 7 and revealed by the subject
//! 9, built by this crate's writer.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::identity::IdentityClient;
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

fn scalar(n: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
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

/// The reference record re-typed to `cert_type`, re-signed by the certifier
/// 7, and revealed by `subject` (#544's signed revelation, as the
/// reference's `publiclyRevealAttributes` locks it, `IdentityClient.ts:502-509`).
fn retyped_token(cert_type: [u8; 32], subject: &PrivateKey) -> LockingScript {
    let mut record: Value = serde_json::from_str(record_553()["reference_text"].as_str().unwrap())
        .expect("the reference record");
    let keyring = record.as_object_mut().unwrap().remove("keyring").unwrap();
    let mut certificate: Certificate = serde_json::from_value(record).unwrap();
    certificate.cert_type = cert_type;
    certificate.subject = subject.public_key();
    certificate.signature = None;
    certificate.sign(&scalar(7)).unwrap();
    let mut json = serde_json::to_value(&certificate).unwrap();
    json["keyring"] = keyring;
    assert_eq!(json["type"], to_base64(&cert_type));
    revelation(subject, &serde_json::to_vec(&json).unwrap())
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

/// The types of the certificates the by-type door returns, in order.
async fn by_type(outputs: Vec<OutputListItem>, key: &str, asked: &str) -> Vec<String> {
    client(outputs)
        .discover_certificates_by_type(key, asked)
        .await
        .unwrap()
        .iter()
        .map(|c| c.type_base64())
        .collect()
}

#[tokio::test]
async fn a_by_type_discovery_keeps_only_the_asked_types_certificates_744() {
    let subject = scalar(9);
    let key = to_hex(&subject.public_key().to_compressed());
    assert_eq!(key, record_553()["subject"].as_str().unwrap());
    let other = to_base64(&[3u8; 32]);
    let outputs = || {
        vec![
            output("11", reference_token()),
            output("22", retyped_token([3u8; 32], &subject)),
        ]
    };

    // Both certificates are admitted by the parsers: the door that asks no
    // type returns both, unchanged.
    let all: Vec<String> = client(outputs())
        .discover_certificates(&key)
        .await
        .unwrap()
        .iter()
        .map(|c| c.type_base64())
        .collect();
    assert_eq!(all, vec![ASKED.to_string(), other.clone()]);

    // The by-type door returns the asked type's alone, either way round.
    assert_eq!(
        by_type(outputs(), &key, ASKED).await,
        vec![ASKED.to_string()]
    );
    assert_eq!(by_type(outputs(), &key, &other).await, vec![other.clone()]);
    // Another type alone answers nothing.
    assert!(by_type(
        vec![output("22", retyped_token([3u8; 32], &subject))],
        &key,
        ASKED
    )
    .await
    .is_empty());
}

/// The comparison is the canonical text, exactly: the asked type written
/// unpadded (a text no token carries, #553) matches nothing.
#[tokio::test]
async fn the_asked_type_is_compared_as_its_canonical_text_744() {
    let key = record_553()["subject"].as_str().unwrap().to_string();
    let unpadded = ASKED.trim_end_matches('=');
    assert!(
        by_type(vec![output("11", reference_token())], &key, unpadded)
            .await
            .is_empty()
    );
}

/// The asked type under another subject's certificate (#742's subject filter
/// beside this type filter): the by-type door returns the asked key's
/// certificate of the asked type alone, the foreign subject's dropped by the
/// subject filter and the foreign type's by the type filter.
#[tokio::test]
async fn the_asked_type_under_another_subject_is_dropped_beside_the_type_filter_744() {
    let subject = scalar(9);
    let key = to_hex(&subject.public_key().to_compressed());
    let foreign = scalar(5);
    let foreign_key = to_hex(&foreign.public_key().to_compressed());
    assert_ne!(foreign_key, key);
    let read = |outputs: Vec<OutputListItem>| {
        let key = key.clone();
        async move {
            client(outputs)
                .discover_certificates_by_type(&key, ASKED)
                .await
                .unwrap()
                .iter()
                .map(|c| (c.subject().to_hex(), c.type_base64()))
                .collect::<Vec<_>>()
        }
    };
    let asked_alone = vec![(key.clone(), ASKED.to_string())];

    // The asked type under the foreign subject, then the asked key's: the
    // subject filter alone drops the foreign one
    let foreign_subject = || output("33", retyped_token([1u8; 32], &foreign));
    assert_eq!(
        read(vec![foreign_subject(), output("11", reference_token())]).await,
        asked_alone,
        "the foreign subject's certificate of the asked type"
    );
    // The foreign subject's alone answers nothing
    assert!(read(vec![foreign_subject()]).await.is_empty());

    // With the asked key's certificate of another type beside them: the
    // asked key's and type's certificate alone
    assert_eq!(
        read(vec![
            foreign_subject(),
            output("11", reference_token()),
            output("22", retyped_token([3u8; 32], &subject)),
        ])
        .await,
        asked_alone,
        "the foreign subject's and the foreign type's certificates"
    );
}
