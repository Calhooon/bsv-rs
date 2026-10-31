//! The auth and identity certificate maps keep the order they were given in,
//! one order through the crate after the wallet's (#394, after #385; the
//! keeper's word of 2026-10-28 04:1xZ under the owner's ruling (c)): at
//! `ts-stack@edf6e03` a certificate's fields and keyrings are a JavaScript
//! `Record` wherever they appear, which keeps insertion order
//! (`packages/sdk/src/auth/certificates/Certificate.ts:179`, `:203`, `:510`;
//! `VerifiableCertificate.ts:87`, `:110`); the reference checks a
//! certificate's bounds in that order (`snapshotCertificateFields` walks
//! `Reflect.ownKeys`, `Certificate.ts:44-84`; `snapshotStringRecord`,
//! `MasterCertificate.ts:31-61`; `decryptFields`, `VerifiableCertificate.ts:160`)
//! and sorts the names by `localeCompare` only to write them
//! (`Certificate.ts:282`), so the signed preimage is the same whatever the
//! order.
//!
//! The maps are built with `collect()` and `insert`, so the file compiles
//! against the `HashMap` shape before #394 and the `IndexMap` shape after it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::auth::certificates::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{to_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::types::Outpoint;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
};
use bsv_rs::Error;
use std::sync::Arc;

/// Eight names out of every sorted order (a map without one keeps them in
/// this order once in 40,320).
const NAMES: [&str; 8] = [
    "zeta", "alpha", "mike", "bravo", "yankee", "charlie", "xray", "delta",
];

/// The names as `localeCompare` sorts them, the signed order.
fn signed_order() -> Vec<&'static str> {
    let mut names = NAMES.to_vec();
    names.sort_unstable();
    names
}

/// The keys of the object member `member` of a JSON text, in the text's order.
fn keys_in_text(text: &str, member: &str) -> Vec<String> {
    let start = text.find(&format!("\"{member}\":{{")).unwrap() + member.len() + 4;
    let body = &text[start..start + text[start..].find('}').unwrap()];
    body.split(',')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .split(':')
                .next()
                .unwrap()
                .trim_matches('"')
                .to_string()
        })
        .collect()
}

fn names_of<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    keys.map(String::as_str).collect()
}

/// A certificate signed over the eight fields, set in `NAMES`' order.
fn signed_certificate() -> (Certificate, PrivateKey) {
    let certifier = PrivateKey::from_bytes(&[41u8; 32]).unwrap();
    let subject = PrivateKey::from_bytes(&[43u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([4; 32], [5; 32], subject, certifier.public_key());
    cert.revocation_outpoint = Some(Outpoint::new([9; 32], 1));
    for name in NAMES {
        cert.set_field(name, "QQ==");
    }
    cert.sign(&certifier).unwrap();
    (cert, certifier)
}

#[test]
fn a_certificate_keeps_its_fields_in_insertion_order_through_its_json_and_the_verifier() {
    let (cert, _) = signed_certificate();
    assert_eq!(names_of(cert.field_names().into_iter()), NAMES);

    let text = serde_json::to_string(&cert).unwrap();
    assert_eq!(keys_in_text(&text, "fields"), NAMES);

    let read: Certificate = serde_json::from_str(&text).unwrap();
    assert_eq!(names_of(read.field_names().into_iter()), NAMES);
    assert_eq!(read.verify(), Ok(true));
    assert_eq!(names_of(read.to_wallet_certificate().fields.keys()), NAMES);
}

#[test]
fn the_binary_form_writes_the_signed_order_and_reads_back_the_order_it_carries() {
    let (cert, _) = signed_certificate();
    let read = Certificate::from_binary(&cert.to_binary(true).unwrap()).unwrap();
    assert_eq!(names_of(read.field_names().into_iter()), signed_order());
    assert_eq!(read.verify(), Ok(true));
    assert_eq!(
        keys_in_text(&serde_json::to_string(&read).unwrap(), "fields"),
        signed_order()
    );
}

/// An issuer's unsigned frame with the fields in `NAMES`' order, not the
/// signed one (another writer's, Go's byte order or a hand's).
fn frame_in_names_order(cert: &Certificate) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&cert.cert_type);
    bytes.extend_from_slice(&cert.serial_number);
    bytes.extend_from_slice(&cert.subject.to_compressed());
    bytes.extend_from_slice(&cert.certifier.to_compressed());
    bytes.extend_from_slice(&[9; 32]);
    bytes.push(1);
    bytes.push(NAMES.len() as u8);
    for name in NAMES {
        bytes.push(name.len() as u8);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(4);
        bytes.extend_from_slice(b"QQ==");
    }
    bytes
}

#[test]
fn a_frame_read_keeps_the_order_its_issuer_wrote() {
    let (cert, _) = signed_certificate();
    let frame = frame_in_names_order(&cert);
    let read = Certificate::from_binary(&frame).unwrap();
    assert_eq!(names_of(read.field_names().into_iter()), NAMES);
    assert_eq!(read.to_binary(false).unwrap(), frame);
}

#[test]
fn a_verifiable_certificate_keeps_its_keyring_in_insertion_order_through_its_json() {
    let (cert, _) = signed_certificate();
    let mut verifiable = VerifiableCertificate::new(cert, Default::default());
    for name in NAMES {
        verifiable
            .keyring
            .insert(name.to_string(), "Qg==".to_string());
    }
    assert_eq!(names_of(verifiable.revealable_fields().into_iter()), NAMES);

    let text = serde_json::to_string(&verifiable).unwrap();
    assert_eq!(keys_in_text(&text, "fields"), NAMES);
    assert_eq!(keys_in_text(&text, "keyring"), NAMES);
    let read: VerifiableCertificate = serde_json::from_str(&text).unwrap();
    assert_eq!(names_of(read.keyring.keys()), NAMES);
    assert_eq!(names_of(read.certificate.fields.keys()), NAMES);
    assert_eq!(read.verify(), Ok(true));
}

#[tokio::test]
async fn issuance_and_selective_disclosure_keep_the_order_given() {
    let certifier = PrivateKey::from_bytes(&[47u8; 32]).unwrap();
    let subject = PrivateKey::from_bytes(&[53u8; 32]).unwrap();
    let verifier = PrivateKey::from_bytes(&[59u8; 32]).unwrap();
    let plain = NAMES
        .iter()
        .map(|name| (name.to_string(), format!("{name} value")))
        .collect();
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier,
        subject.public_key(),
        plain,
        [6; 32],
        Some([7; 32]),
        None,
    )
    .await
    .unwrap();
    assert_eq!(names_of(master.certificate.fields.keys()), NAMES);
    assert_eq!(names_of(master.master_keyring.keys()), NAMES);

    let subject_wallet = ProtoWallet::new(Some(subject.clone()));
    let decrypted = master
        .decrypt_fields(&subject_wallet, &certifier.public_key(), None, None, None)
        .await
        .unwrap();
    assert_eq!(names_of(decrypted.keys()), NAMES);

    let reveal: Vec<String> = ["xray", "bravo", "zeta"].map(String::from).to_vec();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier.public_key(),
        &verifier.public_key(),
        &master.certificate.fields,
        &reveal,
        &master.master_keyring,
        &master.certificate.serial_number,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        names_of(keyring.keys()),
        reveal.iter().map(String::as_str).collect::<Vec<_>>()
    );

    let mut verifiable = VerifiableCertificate::new(master.certificate.clone(), keyring);
    let revealed = verifiable
        .decrypt_fields(&ProtoWallet::new(Some(verifier)), None, None, None)
        .await
        .unwrap();
    assert_eq!(
        names_of(revealed.keys()),
        reveal.iter().map(String::as_str).collect::<Vec<_>>()
    );
}

fn refusal(error: Error) -> String {
    match error {
        Error::CertificateValidationError(words) => words,
        other => panic!("not a certificate refusal: {other:?}"),
    }
}

#[test]
fn to_binary_names_the_first_oversized_value_in_insertion_order() {
    let key = PrivateKey::from_bytes(&[61u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([1; 32], [2; 32], key.clone(), key);
    let oversized = "A".repeat(1024 * 1024 + 4);
    cert.set_field("zeta", oversized.clone());
    cert.set_field("alpha", oversized);
    assert_eq!(
        refusal(cert.to_binary(false).unwrap_err()),
        "Certificate field zeta exceeds the maximum of 1048576 bytes"
    );
}

#[test]
fn to_binary_names_the_first_unsafe_name_in_insertion_order() {
    let key = PrivateKey::from_bytes(&[61u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([1; 32], [2; 32], key.clone(), key);
    cert.set_field("prototype", "QQ==");
    cert.set_field("__proto__", "QQ==");
    assert_eq!(
        refusal(cert.to_binary(false).unwrap_err()),
        "Unsafe certificate field name: prototype"
    );
}

#[test]
fn a_master_certificate_names_the_first_field_without_a_keyring_entry_in_insertion_order() {
    let key = PrivateKey::from_bytes(&[67u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([1; 32], [2; 32], key.clone(), key);
    cert.set_field("zeta", "QQ==");
    cert.set_field("alpha", "QQ==");
    assert_eq!(
        refusal(MasterCertificate::new(cert, Default::default()).unwrap_err()),
        "Master keyring must contain a value for every field. Missing or empty key for field: \"zeta\"."
    );
}

#[tokio::test]
async fn a_keyring_for_a_verifier_names_the_first_non_canonical_field_in_insertion_order() {
    let subject = PrivateKey::from_bytes(&[71u8; 32]).unwrap();
    let fields = [("zeta", "not base64"), ("alpha", "not base64")]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let error = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(subject.clone())),
        &subject.public_key(),
        &subject.public_key(),
        &fields,
        &[],
        &Default::default(),
        &[7; 32],
        None,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        refusal(error),
        "Certificate field zeta must use canonical base64 encoding"
    );
}

#[tokio::test]
async fn a_verifier_names_the_first_bad_keyring_entry_in_the_keyring_order() {
    let (cert, _) = signed_certificate();
    let mut verifiable = VerifiableCertificate::new(cert, Default::default());
    verifiable
        .keyring
        .insert("zeta".to_string(), "!!".to_string());
    verifiable
        .keyring
        .insert("alpha".to_string(), "!!".to_string());
    let error = verifiable
        .decrypt_fields(&ProtoWallet::anyone(), None, None, None)
        .await
        .unwrap_err();
    assert_eq!(
        refusal(error),
        "Failed to decrypt selectively revealed certificate fields using keyring: Certificate keyring field zeta must use canonical base64 encoding"
    );
}

#[tokio::test]
async fn certificate_fields_name_the_first_oversized_plaintext_in_insertion_order() {
    let certifier = PrivateKey::from_bytes(&[73u8; 32]).unwrap();
    let oversized = "A".repeat(64 * 1024 + 1);
    let plain = [("zeta", &oversized), ("alpha", &oversized)]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect();
    let error = MasterCertificate::create_certificate_fields(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier.public_key(),
        plain,
        None,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        refusal(error),
        "Certificate plaintext field zeta exceeds the maximum of 65536 bytes"
    );
}

/// Answers every lookup with the outputs it holds.
struct Outputs(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Outputs {
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

/// The subject's signed revelation of `json` (#544), as the reference's
/// `publiclyRevealAttributes` locks it (`IdentityClient.ts:502-509`:
/// `PushDrop.lock([json], [1, 'identity'], '1', 'anyone', true, true)`).
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

/// One output whose PushDrop carries `json`, a certificate's text.
fn published(json: &str) -> OutputListItem {
    // The subject's (key 43's) signed revelation (#544).
    let locking = revelation(
        &PrivateKey::from_bytes(&[43u8; 32]).unwrap(),
        json.as_bytes(),
    );
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, locking)).unwrap();
    let mut beef = Beef::new();
    beef.merge_transaction(tx);
    OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
    }
}

#[tokio::test]
async fn a_published_token_keeps_its_fields_and_keyring_in_the_order_of_its_text() {
    let (cert, _) = signed_certificate();
    let object = |value: &str| {
        NAMES
            .iter()
            .map(|name| format!("\"{name}\":\"{value}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    let json = format!(
        "{{\"type\":\"{}\",\"serialNumber\":\"{}\",\"subject\":\"{}\",\"certifier\":\"{}\",\
         \"revocationOutpoint\":\"{}.1\",\"fields\":{{{}}},\"signature\":\"{}\",\"keyring\":{{{}}}}}",
        cert.type_base64(),
        cert.serial_number_base64(),
        cert.subject.to_hex(),
        cert.certifier.to_hex(),
        to_hex(&[9; 32]),
        object("QQ=="),
        to_hex(cert.signature.as_ref().unwrap()),
        object("Qg=="),
    );
    let mut host_overrides = std::collections::HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["https://identity-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Outputs(vec![published(&json)]))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);

    let found = client
        .discover_certificates(&cert.subject.to_hex())
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "the token's certificate verifies");
    assert_eq!(names_of(found[0].certificate.fields.keys()), NAMES);
    assert_eq!(names_of(found[0].keyring.keys()), NAMES);
}

#[test]
fn an_identity_query_writes_its_attributes_in_insertion_order() {
    let attributes = NAMES
        .iter()
        .map(|name| (name.to_string(), "x".to_string()))
        .collect();
    let text = serde_json::to_string(&IdentityQuery::by_attributes(attributes)).unwrap();
    assert_eq!(keys_in_text(&text, "attributes"), NAMES);
}
