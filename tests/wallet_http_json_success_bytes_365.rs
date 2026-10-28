//! `HttpWalletJson` reads every byte field of a wallet's 200 answer as the
//! reference's `HTTPWalletJSON` does (#365; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:322-341`): the
//! body through `normalizeBRC100WalletByteFields` (`BRC100ByteEncoding.ts`),
//! then `validateWalletResult`'s `bytes`, against
//! `http_json_success_bytes_365.json` (110 bodies, Node v22.18.0,
//! `tests/support/http_json_success_bytes_365.mjs`), each body's text
//! served through wiremock as the reference was served it: the twelve byte
//! fields of nine calls (ciphertext, plaintext, hmac, signature, both
//! linkages' two, listOutputs' `BEEF`, createAction's `tx` and
//! `signableTransaction.tx`, signAction's `tx`) as an array, in the
//! historical object form and with every byte `1.0`, read to the
//! reference's bytes; with a first byte of `256`, `-1` or `1.5` in either
//! form refused in the reference's words; ciphertext's object form with
//! the integer text `-0` read as its byte 0, as `isByte` reads it; a
//! `signableTransaction` object without its `tx` refused in `bytes`' words
//! (`WalletResultValidation.ts:1271-1272`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::primitives::{to_hex, PublicKey};
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    call: String,
    args: Value,
    field: String,
    form: String,
    body_text: String,
    reference: Value,
}

fn cases() -> Vec<Case> {
    let vector: Vector =
        serde_json::from_str(include_str!("vectors/http_json_success_bytes_365.json")).unwrap();
    vector.cases
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "tests three six five")
}

fn key(args: &Value, name: &str) -> PublicKey {
    PublicKey::from_hex(args[name].as_str().unwrap()).unwrap()
}

/// The case's field as this crate's substrate answers it: its bytes as hex,
/// or the error.
async fn answer(c: &Case) -> Result<String, Error> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", c.call)))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(c.body_text.clone(), "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
    let bytes: Vec<u8> = match (c.call.as_str(), c.field.as_str()) {
        ("encrypt", _) => {
            let args = EncryptArgs {
                plaintext: vec![1, 2, 3],
                protocol_id: protocol(),
                key_id: "1".into(),
                ..Default::default()
            };
            wallet.encrypt(args, None).await?.ciphertext
        }
        ("decrypt", _) => {
            let args = DecryptArgs {
                ciphertext: vec![1, 2, 3],
                protocol_id: protocol(),
                key_id: "1".into(),
                ..Default::default()
            };
            wallet.decrypt(args, None).await?.plaintext
        }
        ("createHmac", _) => {
            let args = CreateHmacArgs {
                data: vec![1, 2, 3],
                protocol_id: protocol(),
                key_id: "1".into(),
                ..Default::default()
            };
            wallet.create_hmac(args, None).await?.hmac.to_vec()
        }
        ("createSignature", _) => {
            let args = CreateSignatureArgs {
                data: Some(vec![1, 2, 3]),
                protocol_id: protocol(),
                key_id: "1".into(),
                ..Default::default()
            };
            wallet.create_signature(args, None).await?.signature
        }
        ("revealCounterpartyKeyLinkage", field) => {
            let args = RevealCounterpartyKeyLinkageArgs {
                counterparty: key(&c.args, "counterparty"),
                verifier: key(&c.args, "verifier"),
                privileged: None,
                privileged_reason: None,
            };
            let linkage = wallet.reveal_counterparty_key_linkage(args, None).await?;
            linkage_field(linkage.linkage, field)
        }
        ("revealSpecificKeyLinkage", field) => {
            let args = RevealSpecificKeyLinkageArgs {
                counterparty: Counterparty::Other(key(&c.args, "counterparty")),
                verifier: key(&c.args, "verifier"),
                protocol_id: protocol(),
                key_id: "1".into(),
                privileged: None,
                privileged_reason: None,
            };
            let linkage = wallet.reveal_specific_key_linkage(args, None).await?;
            linkage_field(linkage.linkage, field)
        }
        ("listOutputs", _) => wallet.list_outputs(args(c), None).await?.beef.unwrap(),
        ("createAction", "tx") => wallet.create_action(args(c), None).await?.tx.unwrap(),
        ("createAction", "signableTransaction.tx") => {
            let result = wallet.create_action(args(c), None).await?;
            result.signable_transaction.unwrap().tx
        }
        ("signAction", _) => wallet.sign_action(args(c), None).await?.tx.unwrap(),
        other => panic!("{}: no call {other:?}", c.name),
    };
    Ok(to_hex(&bytes))
}

/// The case's args as this crate reads the reference's.
fn args<T: DeserializeOwned>(c: &Case) -> T {
    serde_json::from_value(c.args.clone()).unwrap()
}

fn linkage_field(linkage: KeyLinkageResult, field: &str) -> Vec<u8> {
    match field {
        "encryptedLinkage" => linkage.encrypted_linkage,
        "encryptedLinkageProof" => linkage.encrypted_linkage_proof,
        other => panic!("no linkage field {other}"),
    }
}

/// Every body read to the reference's outcome: the field's bytes where it
/// answered, its words where it threw.
#[tokio::test]
async fn every_success_byte_field_is_read_as_the_reference_reads_it() {
    let cases = cases();
    assert_eq!(cases.len(), 110);
    let mut mismatches = Vec::new();
    for c in &cases {
        let ours = answer(c).await;
        let agrees = match (&ours, &c.reference) {
            (Ok(hex), reference) => reference["answered"].as_str() == Some(hex),
            (Err(Error::WalletError(words)), reference) => {
                reference["error"].as_str() == Some(words)
            }
            _ => false,
        };
        if !agrees {
            mismatches.push(format!("{}: {ours:?} vs {}", c.name, c.reference));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

/// The twelve fields of nine calls, each in nine forms or ten: the
/// reference reads three and refuses six, ciphertext's `-0` a fourth read,
/// signableTransaction.tx's absence a seventh refused.
#[test]
fn the_vector_names_each_field_in_every_form_and_the_reference_reads_three() {
    let mut forms: BTreeMap<(String, String), Vec<(String, bool)>> = BTreeMap::new();
    for c in cases() {
        let answered = c.reference.get("answered").is_some();
        let entry = forms.entry((c.call, c.field)).or_default();
        entry.push((c.form, answered));
    }
    assert_eq!(forms.len(), 12);
    for ((call, field), seen) in &forms {
        let read: Vec<&str> = (seen.iter())
            .filter(|(_, answered)| *answered)
            .map(|(form, _)| form.as_str())
            .collect();
        let mut expected = vec!["array", "object", "integral_floats"];
        if field == "ciphertext" {
            expected.push("object_minus_0");
        }
        let refused = if field == "signableTransaction.tx" {
            7
        } else {
            6
        };
        assert_eq!(read, expected, "{call} {field}");
        assert_eq!(seen.len(), expected.len() + refused, "{call} {field}");
    }
}

/// The integer text `-0` crosses as written (the #339 re-review's unpinned
/// case): the object form `{"0":-0,..}` is the byte 0.
#[tokio::test]
async fn the_integer_text_minus_zero_in_the_object_form_is_the_byte_zero() {
    let c = cases()
        .into_iter()
        .find(|c| c.name == "encrypt_ciphertext_object_minus_0")
        .unwrap();
    assert!(c.body_text.starts_with(r#"{"ciphertext":{"0":-0,"1":1,"#));
    assert_eq!(answer(&c).await.unwrap(), "0001027f80feff");
}

/// A `signableTransaction` object without its `tx` is refused in `bytes`'
/// words, as the reference's `actionBeefTransaction(signable.tx, ..)`
/// refuses it (`WalletResultValidation.ts:1271-1272`, `:897`), not in
/// `serde_json`'s `missing field` (the #365 cold review's required change).
#[tokio::test]
async fn a_signable_transaction_without_its_tx_is_refused_in_the_references_words() {
    let c = cases()
        .into_iter()
        .find(|c| c.name == "createAction_signableTransaction_tx_absent")
        .unwrap();
    assert_eq!(
        c.body_text,
        r#"{"signableTransaction":{"reference":"UlJSUlJSUlI="}}"#
    );
    let words = "Invalid createAction result signableTransaction.tx: expected an array of bytes";
    assert_eq!(c.reference["error"], words);
    assert_eq!(answer(&c).await, Err(Error::WalletError(words.into())));
}
