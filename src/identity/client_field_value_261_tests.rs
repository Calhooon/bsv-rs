//! The identity client's intake of a certificate published for anyone (#261):
//! the reference's JSON (`{...certificate, keyring}`, `ts-stack@edf6e03`
//! `IdentityClient.ts:503`) carries each field as its base64 text and the
//! signature as hex; both parsers hold the text's bytes as BRC-52 signs them
//! (`brcs@5119a9b` `peer-to-peer/0052.md:97`), so the reference-issued
//! certificate of `tests/vectors/certificate_field_value_261.json` verifies
//! here and decrypts with the anyone keyring to the reference's plaintexts.

use super::*;
use crate::overlay::OutputListItem;
use crate::script::templates::PushDrop;
use crate::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};

fn reference_issued() -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/certificate_field_value_261.json"
    ))
    .unwrap();
    v["reference_issued"].clone()
}

/// One output whose PushDrop carries the certificate's JSON with the anyone
/// keyring, as the reference's `publiclyRevealAttributes` publishes it.
fn published(r: &serde_json::Value) -> OutputListItem {
    let mut json = r["certificate"].clone();
    json["keyring"] = r["anyone_keyring"].clone();
    let locking = PushDrop::new(
        PrivateKey::from_bytes(&[3u8; 32]).unwrap().public_key(),
        vec![serde_json::to_vec(&json).unwrap()],
    )
    .lock();
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

fn plaintexts(r: &serde_json::Value) -> HashMap<String, String> {
    serde_json::from_value(r["plaintexts"].clone()).unwrap()
}

#[tokio::test]
async fn a_reference_issued_certificate_published_for_anyone_parses_verifies_and_decrypts() {
    let r = reference_issued();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());

    let parsed = client
        .parse_output_to_certificate(&published(&r))
        .await
        .unwrap()
        .expect("the reference's certificate verifies here");
    assert_eq!(
        to_hex(&parsed.certificate.signing_hash()),
        r["preimage_sha256"].as_str().unwrap()
    );
    for (name, text) in r["certificate"]["fields"].as_object().unwrap() {
        assert_eq!(
            parsed.certificate.fields[name],
            text.as_str().unwrap().as_bytes()
        );
    }
    assert_eq!(parsed.decrypted_fields, plaintexts(&r));
}

#[tokio::test]
async fn a_reference_issued_certificate_published_for_anyone_parses_to_a_verifying_certificate() {
    let r = reference_issued();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());

    let mut cert = client
        .parse_output_to_verifiable_certificate(&published(&r))
        .await
        .unwrap()
        .expect("the reference's certificate verifies here");
    assert!(cert.verify().unwrap());
    let subject = cert.certificate.subject.clone();
    let decrypted = cert
        .decrypt_fields(&ProtoWallet::anyone(), &subject, None, None, "test")
        .await
        .unwrap();
    assert_eq!(decrypted, plaintexts(&r));
}
