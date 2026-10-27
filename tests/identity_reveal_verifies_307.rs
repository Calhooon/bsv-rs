//! `publicly_reveal_attributes` checks the certificate's fields and the
//! names to reveal, then verifies the master certificate, before it calls
//! the wallet, as the reference's `publiclyRevealAttributes` does
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:420-467`;
//! #307), and after proveCertificate refuses a keyring whose names or values
//! the reference refuses (`:478-499`) and publishes the values trimmed. The
//! reference's verdicts on thirty-eight witnesses
//! (`vectors/identity_reveal_verifies_307.json`, Node v22.18.0,
//! `tests/support/identity_reveal_verifies_307.mjs`) are this crate's: the
//! same words and class, the same wallet calls before a refusal,
//! createAction reached where the reference reaches it with the keyring it
//! publishes. A wallet that counts its calls answers proveCertificate with
//! a keyring of the names asked (or the witness's) and createAction with no
//! transaction, so nothing is broadcast: the reference throws there, and
//! since #310 this crate does too, in its words (`:537`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::error::WalletRefusalClass;
use bsv_rs::identity::{BroadcastResult, IdentityClient, IdentityClientConfig};
use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde::Deserialize;
use std::collections::HashMap;

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

#[derive(Deserialize)]
struct Vector {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Witness {
    name: String,
    certificate: WalletCertificate,
    fields_to_reveal: Vec<String>,
    refusal: Option<String>,
    #[serde(rename = "wallet_calls")]
    wallet_calls: usize,
    /// The keyring the wallet answers, when not the names asked.
    #[serde(default)]
    keyring: Option<HashMap<String, String>>,
    /// The refusal's class, `Error` or `WERR_INVALID_PARAMETER`.
    #[serde(default, rename = "refusal_name")]
    refusal_name: Option<String>,
    /// The keyring the PushDrop carries, when createAction was reached.
    #[serde(default, rename = "published_keyring")]
    published_keyring: Option<HashMap<String, String>>,
}

fn vector() -> Vector {
    let text = include_str!("vectors/identity_reveal_verifies_307.json");
    serde_json::from_str(text).unwrap()
}

fn witness(name: &str) -> Witness {
    let found = vector().witnesses.into_iter().find(|w| w.name == name);
    found.unwrap_or_else(|| panic!("no witness {name}"))
}

/// The client's answer to one witness and the wallet's calls before it.
async fn reveal(
    wallet: &Counting,
    certificate: WalletCertificate,
    fields: Vec<String>,
) -> bsv_rs::Result<BroadcastResult> {
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    client.publicly_reveal_attributes(certificate, fields).await
}

/// The keyring of the certificate JSON the PushDrop of the createAction carries.
fn published_keyring(wallet: &Counting) -> serde_json::Value {
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let outputs = created.outputs.unwrap();
    let script = LockingScript::from_binary(&outputs[0].locking_script).unwrap();
    let published: serde_json::Value =
        serde_json::from_slice(&PushDrop::decode(&script).unwrap().fields[0]).unwrap();
    published["keyring"].clone()
}

/// The refusal in the witness's words and class: `WERR_INVALID_PARAMETER`
/// is the `InvalidParameter` refusal, `Error` the client's own.
fn assert_refusal(result: &bsv_rs::Result<BroadcastResult>, w: &Witness, words: &str) {
    match (w.refusal_name.as_deref(), result) {
        (Some("WERR_INVALID_PARAMETER"), Err(Error::WalletRefusal { class, message })) => {
            assert_eq!(*class, WalletRefusalClass::InvalidParameter, "{}", w.name);
            assert_eq!(message, words, "{}", w.name);
        }
        (None | Some("Error"), Err(Error::IdentityError(found))) => {
            assert_eq!(found, words, "{}", w.name)
        }
        (_, other) => panic!("{}: expected {words:?}, got {other:?}", w.name),
    }
}

/// createAction reached and its empty answer refused in the reference's
/// words (`IdentityClient.ts:537`, #310), as the reference's script saw it.
fn assert_reached_create_action(
    result: &bsv_rs::Result<BroadcastResult>,
    wallet: &Counting,
    name: &str,
) {
    match result {
        Err(Error::IdentityError(found)) => {
            assert_eq!(
                found, "Public reveal failed: failed to create action!",
                "{name}"
            )
        }
        other => panic!("{name}: expected createAction's empty answer refused, got {other:?}"),
    }
    assert_eq!(wallet.calls().last(), Some(&"create_action"), "{name}");
}

fn assert_refused_before_the_wallet(
    result: bsv_rs::Result<BroadcastResult>,
    wallet: &Counting,
    words: &str,
) {
    match result {
        Err(Error::IdentityError(found)) => assert_eq!(found, words),
        other => panic!("expected the refusal {words:?}, got {other:?}"),
    }
    assert_eq!(
        wallet.calls(),
        Vec::<&str>::new(),
        "a wallet call before {words:?}"
    );
}

#[tokio::test]
async fn every_reference_verdict_on_the_reveal_is_this_crates() {
    let witnesses = vector().witnesses;
    assert_eq!(witnesses.len(), 38);
    for w in witnesses {
        let mut wallet = Counting::new();
        wallet.keyring = w.keyring.clone();
        let result = reveal(&wallet, w.certificate.clone(), w.fields_to_reveal.clone()).await;
        match &w.refusal {
            Some(words) => {
                assert_refusal(&result, &w, words);
                assert_eq!(
                    wallet.calls().len(),
                    w.wallet_calls,
                    "{}: {:?}",
                    w.name,
                    wallet.calls()
                );
            }
            None => {
                assert_reached_create_action(&result, &wallet, &w.name);
                assert_eq!(wallet.calls().len() - 1, w.wallet_calls, "{}", w.name);
                if let Some(keyring) = &w.published_keyring {
                    let expected = serde_json::to_value(keyring).unwrap();
                    assert_eq!(published_keyring(&wallet), expected, "{}", w.name);
                }
            }
        }
    }
}

#[tokio::test]
async fn an_unsigned_master_certificate_is_refused_before_any_wallet_call() {
    let w = witness("unsigned");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    let words = "Public reveal failed: Certificate verification failed!";
    assert_refused_before_the_wallet(result, &wallet, words);
}

#[tokio::test]
async fn a_wrongly_signed_master_certificate_is_refused_before_any_wallet_call() {
    for name in ["other_key", "field_changed", "not_der", "empty_subject"] {
        let w = witness(name);
        let wallet = Counting::new();
        let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
        let words = "Public reveal failed: Certificate verification failed!";
        assert_refused_before_the_wallet(result, &wallet, words);
    }
}

#[tokio::test]
async fn a_name_is_judged_before_the_signature_as_the_reference_orders_them() {
    let w = witness("unsigned_absent_name");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    let words = "Public reveal failed: requested field is not present in the certificate!";
    assert_refused_before_the_wallet(result, &wallet, words);
}

#[tokio::test]
async fn a_signed_master_certificate_is_published_as_before() {
    let w = witness("signed");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate.clone(), w.fields_to_reveal).await;
    assert_reached_create_action(&result, &wallet, "signed");
    let calls = wallet.calls();
    assert_eq!(
        calls,
        [
            "prove_certificate",
            "get_public_key",
            "create_signature",
            "create_action"
        ]
    );
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let outputs = created.outputs.unwrap();
    let script = LockingScript::from_binary(&outputs[0].locking_script).unwrap();
    let published: serde_json::Value =
        serde_json::from_slice(&PushDrop::decode(&script).unwrap().fields[0]).unwrap();
    assert_eq!(published["signature"], w.certificate.signature.as_str());
    assert_eq!(published["keyring"], serde_json::json!({ "email": "AAAA" }));
}

/// The keyring witness `name` through the client: its refusal and the
/// wallet's one call before it, or the keyring published.
async fn keyring_witness(name: &str) -> (Witness, Counting, bsv_rs::Result<BroadcastResult>) {
    let w = witness(name);
    let mut wallet = Counting::new();
    wallet.keyring = w.keyring.clone();
    let result = reveal(&wallet, w.certificate.clone(), w.fields_to_reveal.clone()).await;
    (w, wallet, result)
}

#[tokio::test]
async fn an_unsafe_keyring_name_is_refused_in_the_reference_words() {
    for name in ["keyring_unsafe_proto", "keyring_unsafe_constructor"] {
        let (w, wallet, result) = keyring_witness(name).await;
        let words =
            "Invalid display identity: proof result keyringForVerifier contains an unsafe field";
        assert_eq!(w.refusal.as_deref(), Some(words), "{name}");
        assert_refusal(&result, &w, words);
        assert_eq!(wallet.calls(), ["prove_certificate"], "{name}");
    }
}

#[tokio::test]
async fn a_keyring_value_not_base64_or_over_2048_bytes_is_refused_as_the_reference_refuses_it() {
    for (name, must_be) in [
        ("keyring_not_base64", "valid base64 string"),
        ("keyring_empty", "valid base64 string"),
        ("keyring_padding_inside", "valid base64 string"),
        ("keyring_nel_kept", "valid base64 string"),
        ("keyring_oversized", "no more than 2048 bytes"),
    ] {
        let (w, wallet, result) = keyring_witness(name).await;
        let words = format!("The keyringForVerifier.email parameter must be {must_be}");
        assert_eq!(w.refusal.as_deref(), Some(words.as_str()), "{name}");
        assert_refusal(&result, &w, &words);
        assert_eq!(wallet.calls(), ["prove_certificate"], "{name}");
    }
}

#[tokio::test]
async fn a_keyring_value_is_published_trimmed_as_the_reference_publishes_it() {
    for name in [
        "keyring_trimmed",
        "keyring_bom_trimmed",
        "keyring_both_fields_trimmed",
        "keyring_at_bound",
    ] {
        let (w, wallet, result) = keyring_witness(name).await;
        assert_reached_create_action(&result, &wallet, name);
        let expected = serde_json::to_value(w.published_keyring.unwrap()).unwrap();
        assert_eq!(published_keyring(&wallet), expected, "{name}");
    }
}

#[tokio::test]
async fn a_keyring_for_another_field_is_refused_before_create_action() {
    let w = witness("signed");
    let mut wallet = Counting::new();
    wallet.keyring = Some(HashMap::from([
        ("email".to_string(), "AAAA".to_string()),
        ("name".to_string(), "AAAA".to_string()),
    ]));
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    match result {
        Err(Error::IdentityError(found)) => assert_eq!(
            found,
            "Public reveal failed: wallet returned a keyring for unrequested fields!"
        ),
        other => panic!("expected the keyring refusal, got {other:?}"),
    }
    assert_eq!(wallet.calls(), ["prove_certificate"]);
}

#[test]
fn the_vectors_signature_is_this_crates_own() {
    let w = witness("signed");
    let mut json = serde_json::to_value(&w.certificate).unwrap();
    json.as_object_mut().unwrap().remove("signature");
    let mut certificate: Certificate = serde_json::from_value(json).unwrap();
    let mut scalar = [0u8; 32];
    scalar[31] = 7; // the script's `new PrivateKey(7)`
    certificate
        .sign(&PrivateKey::from_bytes(&scalar).unwrap())
        .unwrap();
    assert_eq!(
        to_hex(certificate.signature.as_ref().unwrap()),
        w.certificate.signature
    );
}
