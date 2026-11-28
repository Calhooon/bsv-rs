//! bsv-rs#1118s: the identity resolve doors show a certifier's vouching
//! badge only where a check of this crate stands behind it — the record's
//! certifier is the one certifier key this crate anchors on
//! (`DEFAULT_SOCIALCERT_CERTIFIER`) AND the certificate verifies as that
//! key's. Every other record is handed over with no vouching label (the
//! neutral `DefaultIdentityValues` badge, `CertifierInfo` trust 0). The
//! anchor is the signature check, not a field the record's author writes.
//!
//! Hermetic (Rule 4): an in-process `ls_identity` resolver on an `.invalid`
//! host (never dialled, a unique tag per client so the process-wide host
//! reputation is not shared), every token built by this crate's own writers.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_token_1118e.rs"]
mod support;

use bsv_rs::auth::{Certificate, VerifiableCertificate};
use bsv_rs::identity::{
    CertifierInfo, DefaultIdentityValues, DisplayableIdentity, IdentityCertificate, IdentityClient,
    IdentityClientConfig, IdentityQuery, KnownCertificateType, DEFAULT_SOCIALCERT_CERTIFIER,
};
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, EncryptArgs, KeyDeriver, ProtoWallet, Protocol,
    SecurityLevel,
};
use std::collections::HashMap;

// ---- the token writer (this crate's own) -------------------------------

const XCERT: &str = "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=";

fn protocol() -> Protocol {
    Protocol::from_tuple((1, "identity")).unwrap()
}

fn lock_key(subject: &PublicKey) -> PublicKey {
    KeyDeriver::new(None)
        .derive_public_key(
            &protocol(),
            "1",
            &Counterparty::Other(subject.clone()),
            false,
        )
        .unwrap()
}

fn subject_signature(subject: &PrivateKey, field0: &[u8]) -> Vec<u8> {
    ProtoWallet::new(Some(subject.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(field0.to_vec()),
            hash_to_directly_sign: None,
            protocol_id: protocol(),
            key_id: "1".to_string(),
            counterparty: Some(Counterparty::Anyone),
        })
        .unwrap()
        .signature
}

fn anyone_pub() -> PublicKey {
    let mut b = [0u8; 32];
    b[31] = 1;
    PrivateKey::from_bytes(&b).unwrap().public_key()
}

fn anyone_keyring_entry(
    subject: &PrivateKey,
    serial: &[u8; 32],
    field: &str,
    value: &str,
) -> Vec<u8> {
    let proto = Protocol::new(SecurityLevel::Counterparty, "certificate field encryption");
    let key_id = format!("{} {}", to_base64(serial), field);
    ProtoWallet::new(Some(subject.clone()))
        .encrypt(EncryptArgs {
            plaintext: value.as_bytes().to_vec(),
            protocol_id: proto,
            key_id,
            counterparty: Some(Counterparty::Other(anyone_pub())),
        })
        .unwrap()
        .ciphertext
}

/// A self-authored XCert revelation: `subject` is the party, certified by the
/// party's own `certifier` key (not SocialCert), its `user_name` field
/// readable by anyone. `certifier_in_json`, when set, overrides the certifier
/// hex WRITTEN into the certificate JSON while the signature stays
/// `certifier`'s — used to show that naming the anchored key without its
/// signature is refused. Built by this crate's own writers.
fn self_authored_token(
    subject: &PrivateKey,
    certifier: &PrivateKey,
    user_name: &str,
    certifier_in_json: Option<&str>,
) -> LockingScript {
    let cert_type: [u8; 32] = from_base64(XCERT).unwrap().try_into().unwrap();
    let serial = [2u8; 32];
    let mut cert = Certificate::new(
        cert_type,
        serial,
        subject.public_key(),
        certifier.public_key(),
    );
    cert.set_field("userName".to_string(), b"master-encrypted".to_vec());
    cert.sign(certifier).unwrap();
    assert!(cert.verify().unwrap());
    let keyring_entry = anyone_keyring_entry(subject, &serial, "userName", user_name);
    let mut fields = serde_json::Map::new();
    fields.insert(
        "userName".to_string(),
        serde_json::json!(to_base64(b"master-encrypted")),
    );
    let mut keyring = serde_json::Map::new();
    keyring.insert(
        "userName".to_string(),
        serde_json::json!(to_base64(&keyring_entry)),
    );
    let certifier_hex = certifier_in_json
        .map(|s| s.to_string())
        .unwrap_or_else(|| certifier.public_key().to_hex());
    let json = serde_json::json!({
        "type": to_base64(&cert_type),
        "serialNumber": to_base64(&serial),
        "subject": subject.public_key().to_hex(),
        "certifier": certifier_hex,
        "fields": fields,
        "signature": to_base64(cert.signature.as_ref().unwrap()),
        "keyring": keyring,
    });
    let field0 = serde_json::to_vec(&json).unwrap();
    let field1 = subject_signature(subject, &field0);
    PushDrop::new(lock_key(&subject.public_key()), vec![field0, field1]).lock()
}

fn client(tag: &str, outputs: Vec<bsv_rs::overlay::OutputListItem>) -> IdentityClient<ProtoWallet> {
    IdentityClient::with_resolver(
        ProtoWallet::new(None),
        IdentityClientConfig::default(),
        support::answering("ls_identity", tag, outputs),
    )
}

fn no_vouching(id: &DisplayableIdentity) {
    let hay = format!(
        "{} | {} | {}",
        id.badge_label, id.badge_icon_url, id.badge_click_url
    )
    .to_lowercase();
    assert!(
        !hay.contains("socialcert"),
        "a record from an unanchored certifier must carry no SocialCert badge, got: {hay}"
    );
}

// ---- the doors: an unanchored record carries no vouching badge ---------

#[tokio::test]
async fn an_unanchored_record_carries_no_vouching_badge_at_every_door() {
    let party = PrivateKey::random();
    let party_cert_key = PrivateKey::random();
    assert_ne!(
        party_cert_key.public_key().to_hex(),
        DEFAULT_SOCIALCERT_CERTIFIER
    );
    let party_hex = party.public_key().to_hex();
    let script = self_authored_token(&party, &party_cert_key, "Alice Victim", None);

    // resolve_by_identity_key
    let c = client("key", vec![support::output_of(script.clone())]);
    let id = c
        .resolve_by_identity_key(&party_hex, false)
        .await
        .unwrap()
        .expect("the record is read");
    assert_eq!(id.identity_key, party_hex);
    no_vouching(&id);

    // query
    let c = client("query", vec![support::output_of(script.clone())]);
    let results = c.query(IdentityQuery::default()).await.unwrap();
    assert_eq!(results.len(), 1);
    no_vouching(&results[0].identity);
    assert_ne!(
        results[0].certificates[0].certifier().to_hex(),
        DEFAULT_SOCIALCERT_CERTIFIER
    );

    // resolve_by_attributes
    let c = client("attr", vec![support::output_of(script)]);
    let attrs = HashMap::from([("userName".to_string(), "Alice Victim".to_string())]);
    let found = c.resolve_by_attributes(attrs, false).await.unwrap();
    assert_eq!(found.len(), 1);
    no_vouching(&found[0]);
}

// ---- an attribute search about someone else is not vouched -------------

#[tokio::test]
async fn an_attribute_search_is_not_answered_with_a_vouched_record() {
    let party = PrivateKey::random();
    let party_cert_key = PrivateKey::random();
    // The party chose a name a caller might search; that caller is handed the
    // party's key, which must not wear a trusted-authority badge.
    let script = self_authored_token(&party, &party_cert_key, "Someone Else", None);
    let c = client("else", vec![support::output_of(script)]);
    let attrs = HashMap::from([("userName".to_string(), "Someone Else".to_string())]);
    let found = c.resolve_by_attributes(attrs, false).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].identity_key, party.public_key().to_hex());
    no_vouching(&found[0]);
}

// ---- condition (b): the anchor is a check, not a field -----------------

#[tokio::test]
async fn a_certifier_name_written_into_a_record_is_not_a_vouching_check() {
    // The party writes the anchored authority's NAME into the field it
    // controls (the readable userName). The badge still carries no vouching.
    let party = PrivateKey::random();
    let party_cert_key = PrivateKey::random();
    let script = self_authored_token(&party, &party_cert_key, "SocialCert", None);
    let c = client("name", vec![support::output_of(script)]);
    let id = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap()
        .expect("the record is read");
    no_vouching(&id);
}

#[tokio::test]
async fn a_record_naming_the_known_certifier_key_without_its_signature_is_refused() {
    // The party writes the anchored certifier's KEY into the certificate's
    // certifier field, but cannot sign as it: the signature check drops it,
    // so no door hands it to a caller at all.
    let party = PrivateKey::random();
    let party_cert_key = PrivateKey::random();
    let script = self_authored_token(
        &party,
        &party_cert_key,
        "Alice Victim",
        Some(DEFAULT_SOCIALCERT_CERTIFIER),
    );
    let c = client("forgekey", vec![support::output_of(script)]);
    let got = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert!(
        got.is_none(),
        "a record naming the known certifier without its signature is refused"
    );
}

// ---- the honest case must NOT move: an anchored record keeps its badge --

#[tokio::test]
async fn a_record_the_known_certifier_signed_keeps_its_badge() {
    // The anchored branch (the record's certifier IS the known key) is the
    // byte-for-byte pre-fix badge. It cannot be reached through a door
    // without the known certifier's private key, so it is pinned at the
    // badge builder with the anchored certifier info set as Step 9 sets it.
    let cert_type: [u8; 32] = from_base64(KnownCertificateType::XCert.type_id())
        .unwrap()
        .try_into()
        .unwrap();
    let subject = PrivateKey::random();
    let known = PublicKey::from_hex(DEFAULT_SOCIALCERT_CERTIFIER).unwrap();
    let certificate = Certificate::new(cert_type, [3u8; 32], subject.public_key(), known);
    let verifiable = VerifiableCertificate::new(certificate, HashMap::new());
    let mut decrypted = HashMap::new();
    decrypted.insert("userName".to_string(), "alice_x".to_string());
    let anchored = IdentityCertificate {
        certificate: verifiable,
        certifier_info: CertifierInfo {
            name: "SocialCert".to_string(),
            icon_url: "https://socialcert.net/favicon.ico".to_string(),
            description: "Social identity verification".to_string(),
            trust: 5,
        },
        publicly_revealed_keyring: HashMap::new(),
        decrypted_fields: decrypted,
    };
    let shown = IdentityClient::<ProtoWallet>::parse_identity(&anchored);
    assert_eq!(shown.badge_label, "X account certified by SocialCert");
    assert_eq!(shown.badge_icon_url, "https://socialcert.net/favicon.ico");
    assert_eq!(shown.badge_click_url, "https://socialcert.net");
    assert_eq!(shown.name, "alice_x");
}

// ---- the click URL of an unanchored record points nowhere trusted ------

#[tokio::test]
async fn an_unanchored_record_click_url_does_not_point_to_a_trusted_authority() {
    let party = PrivateKey::random();
    let party_cert_key = PrivateKey::random();
    let script = self_authored_token(&party, &party_cert_key, "Alice Victim", None);
    let c = client("click", vec![support::output_of(script)]);
    let id = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap()
        .expect("the record is read");
    assert!(!id.badge_click_url.contains("socialcert.net"));
    assert_eq!(id.badge_label, DefaultIdentityValues::BADGE_LABEL);
    assert_eq!(id.badge_click_url, DefaultIdentityValues::BADGE_CLICK_URL);
}

// ---- the vouching badge is minted at exactly one guarded place ---------

#[test]
fn the_vouching_badge_is_minted_at_one_guarded_place() {
    // The sole production site that mints the SocialCert vouching label is
    // `badge::certifier_info_for`; every door reaches it through that one call,
    // so a new door cannot hand out a vouching badge without the anchor check.
    let badge_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/identity/badge.rs"
    ));
    let badge_production = badge_src
        .split("#[cfg(test)]\nmod tests {")
        .next()
        .expect("badge.rs has a test module");
    let mints: Vec<_> = badge_production
        .match_indices("name: \"SocialCert\"")
        .collect();
    assert_eq!(
        mints.len(),
        1,
        "the SocialCert vouching label must be minted at exactly one production place"
    );
    // and that one site is guarded by the certifier anchor check.
    let before = &badge_production[..mints[0].0];
    let gate = before
        .rfind("DEFAULT_SOCIALCERT_CERTIFIER")
        .expect("the vouching mint must be gated by the certifier anchor");
    assert!(
        before[gate..].lines().count() <= 6,
        "the certifier anchor check must immediately gate the vouching mint"
    );
    // The door file never mints the vouching label itself: it only calls the
    // gated helper, so no door can re-introduce an un-anchored badge inline.
    let client_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/identity/client.rs"
    ));
    let client_production = client_src
        .split("#[cfg(test)]\nmod tests {")
        .next()
        .expect("client.rs has a test module");
    assert_eq!(
        client_production.matches("name: \"SocialCert\"").count(),
        0,
        "the door file must not mint the vouching label inline"
    );
}
