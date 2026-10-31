#![cfg(test)]
//! The identity client's intake of a certificate published for anyone (#261):
//! the reference's JSON (`{...certificate, keyring}`, `ts-stack@edf6e03`
//! `IdentityClient.ts:503`) carries each field as its base64 text and the
//! signature as hex; both parsers hold the text as BRC-52 signs them
//! (`brcs@5119a9b` `peer-to-peer/0052.md:97`), so the reference-issued
//! certificate of `tests/vectors/certificate_field_value_261.json` verifies
//! here and decrypts with the anyone keyring to the reference's plaintexts.
//!
//! And a revocation outpoint written as the txid alone (#268): the
//! reference's default issuance writes that form (`MasterCertificate.ts:442`)
//! and reads it as index 0 (`:112-123`, `Certificate.ts:261-262`); both
//! parsers read it so, and a certificate signed over `<txid>.0` verifies.

use super::*;
use crate::overlay::OutputListItem;
use crate::primitives::to_hex;
use crate::script::templates::PushDrop;
use crate::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};
use crate::wallet::types::Outpoint;

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
    publish(&json)
}

/// One output whose PushDrop carries `json`.
fn publish(json: &serde_json::Value) -> OutputListItem {
    let locking = PushDrop::new(
        PrivateKey::from_bytes(&[3u8; 32]).unwrap().public_key(),
        vec![serde_json::to_vec(json).unwrap()],
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

fn plaintexts(r: &serde_json::Value) -> IndexMap<String, String> {
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
        to_hex(&parsed.certificate.signing_hash().unwrap()),
        r["preimage_sha256"].as_str().unwrap()
    );
    for (name, text) in r["certificate"]["fields"].as_object().unwrap() {
        assert_eq!(&parsed.certificate.fields[name], text.as_str().unwrap());
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
    let decrypted = cert
        .decrypt_fields(&ProtoWallet::anyone(), None, None, Some("test"))
        .await
        .unwrap();
    assert_eq!(decrypted, plaintexts(&r));
}

/// A lookup host that answers every question with the outputs it holds.
struct Outputs(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl crate::overlay::OverlayLookupFacilitator for Outputs {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.clone(),
        })
    }
}

#[tokio::test]
async fn a_malformed_signature_skips_its_output_and_the_resolution_goes_on() {
    let r = reference_issued();
    // The signature in base64 where the reference's JSON carries hex.
    let mut malformed = r["certificate"].clone();
    malformed["keyring"] = r["anyone_keyring"].clone();
    let signature = from_hex(malformed["signature"].as_str().unwrap()).unwrap();
    malformed["signature"] = crate::primitives::to_base64(&signature).into();

    let mut host_overrides = std::collections::HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["http://identity-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Outputs(vec![publish(&malformed), published(&r)]))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let client =
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver);

    let attributes = IndexMap::from([("email".to_string(), "x".to_string())]);
    let identities = client
        .resolve_by_attributes(attributes, false)
        .await
        .expect("a malformed output is skipped, never the resolution's error");
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].identity_key,
        r["certificate"]["subject"].as_str().unwrap()
    );
}

/// A certificate signed over `<ab..ab>.0`, published with its outpoint
/// written as the txid alone and an empty keyring.
fn published_with_txid_alone() -> (Certificate, OutputListItem) {
    let certifier = PrivateKey::from_bytes(&[31u8; 32]).unwrap();
    let subject = PrivateKey::from_bytes(&[37u8; 32]).unwrap().public_key();
    let txid = "ab".repeat(32);
    let mut cert = Certificate::new([6; 32], [7; 32], subject, certifier.public_key());
    cert.revocation_outpoint = Some(Outpoint::from_string(&format!("{txid}.0")).unwrap());
    cert.set_field("name", "QWxpY2U=");
    cert.sign(&certifier).unwrap();

    let mut json = serde_json::to_value(&cert).unwrap();
    json["revocationOutpoint"] = txid.into();
    json["keyring"] = serde_json::json!({});
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
    let output = OutputListItem {
        beef: beef.to_binary(),
        output_index: 0,
        context: None,
    };
    (cert, output)
}

#[tokio::test]
async fn a_published_txid_alone_revocation_outpoint_parses_as_index_zero() {
    let (cert, output) = published_with_txid_alone();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    let parsed = client
        .parse_output_to_certificate(&output)
        .await
        .unwrap()
        .expect("the certificate verifies");
    assert_eq!(
        parsed.certificate.revocation_outpoint,
        cert.revocation_outpoint
    );
}

#[tokio::test]
async fn a_published_txid_alone_revocation_outpoint_parses_to_a_verifying_certificate() {
    let (cert, output) = published_with_txid_alone();
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    let parsed = client
        .parse_output_to_verifiable_certificate(&output)
        .await
        .unwrap()
        .expect("the certificate verifies");
    assert_eq!(parsed.revocation_outpoint, cert.revocation_outpoint);
    assert!(parsed.verify().unwrap());
}

/// #498's re-review: a published certificate's subject and certifier are read
/// strictly, though `PublicKey::from_hex` reads the reference's lenient forms.
/// The reference's `Certificate.verify` refuses a key that is not `02`/`03`
/// and 64 hex digits at its `toBinary` (`ts-stack@edf6e03`
/// `Certificate.ts:240-254`, `:425-440`), so it skips the output
/// (`IdentityClient.ts:823`); read leniently, a hybrid or odd-length form
/// reduced to the signed key's point and verified here.
#[tokio::test]
async fn a_published_certificate_key_in_a_lenient_form_is_skipped_498() {
    let certifier = PrivateKey::from_bytes(&[31u8; 32]).unwrap();
    let subject = PrivateKey::from_bytes(&[37u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([6; 32], [7; 32], subject, certifier.public_key());
    cert.revocation_outpoint =
        Some(Outpoint::from_string(&format!("{}.0", "ab".repeat(32))).unwrap());
    cert.set_field("name", "QWxpY2U=");
    cert.sign(&certifier).unwrap();
    let mut json = serde_json::to_value(&cert).unwrap();
    json["keyring"] = serde_json::json!({});
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    assert!(client
        .parse_output_to_verifiable_certificate(&publish(&json))
        .await
        .unwrap()
        .is_some());

    for member in ["subject", "certifier"] {
        let key = PublicKey::from_hex(json[member].as_str().unwrap()).unwrap();
        let uncompressed = to_hex(&key.to_uncompressed());
        let odd = u8::from_str_radix(&uncompressed[128..], 16).unwrap() & 1 == 1;
        let hybrid = format!("{}{}", if odd { "07" } else { "06" }, &uncompressed[2..]);
        for form in [hybrid, key.to_hex()[1..].to_string()] {
            assert_eq!(PublicKey::from_hex(&form).unwrap(), key);
            let mut lenient = json.clone();
            lenient[member] = form.clone().into();
            let output = publish(&lenient);
            assert!(
                client
                    .parse_output_to_verifiable_certificate(&output)
                    .await
                    .unwrap()
                    .is_none(),
                "{member} {form}: verified leniently"
            );
            assert!(
                !matches!(
                    client.parse_output_to_certificate(&output).await,
                    Ok(Some(_))
                ),
                "{member} {form}: parsed leniently"
            );
        }
    }
}
