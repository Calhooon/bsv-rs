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

use bsv_rs::auth::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::identity::{
    CertifierInfo, DefaultIdentityValues, DisplayableIdentity, IdentityCertificate, IdentityClient,
    IdentityClientConfig, IdentityQuery, KnownCertificateType, DEFAULT_SOCIALCERT_CERTIFIER,
};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_base64, to_base64, to_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol};
use indexmap::IndexMap;
use std::sync::Arc;

// ---- the hermetic resolver ---------------------------------------------

struct Answering(Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _q: &LookupQuestion,
        _t: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: self.0.clone(),
        })
    }
}

fn client(tag: &str, outputs: Vec<OutputListItem>) -> IdentityClient<ProtoWallet> {
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(outputs))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(std::collections::HashMap::from([(
            "ls_identity".to_string(),
            vec![format!("https://ls_identity.{tag}-1118s.invalid")],
        )])),
        ..Default::default()
    }));
    IdentityClient::with_resolver(
        ProtoWallet::new(None),
        IdentityClientConfig::default(),
        resolver,
    )
}

/// A lookup output carrying `script` at index 0, proven by a block of its
/// own (a lone leaf at offset 0), so the parsers' evidence check admits it.
fn output_of(script: LockingScript) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let leaf = MerklePathLeaf::new_txid(0, tx.id());
    let mut beef = Beef::new();
    let index = beef.merge_bump(MerklePath::new(900, vec![vec![leaf]]).unwrap());
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    OutputListItem {
        beef: beef.to_binary().unwrap(),
        output_index: 0,
        context: None,
        txid: None,
    }
}

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
            protocol_id: protocol(),
            key_id: "1".to_string(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature
}

/// The "anyone" public key (private scalar 1), the verifier the identity
/// resolver decrypts fields as (`ProtoWallet::anyone()`).
fn anyone_pub() -> PublicKey {
    let mut b = [0u8; 32];
    b[31] = 1;
    PrivateKey::from_bytes(&b).unwrap().public_key()
}

/// A self-authored XCert revelation: `subject` is the party, certified by
/// the party's own `certifier` key (not SocialCert), its `user_name` field
/// readable by anyone. `certifier_in_json`, when set, overrides the
/// certifier hex WRITTEN into the certificate JSON while the signature stays
/// `certifier`'s — used to show that naming the anchored key without its
/// signature is refused. Built by this crate's own writers.
async fn self_authored_token(
    subject: &PrivateKey,
    certifier: &PrivateKey,
    user_name: &str,
    certifier_in_json: Option<&str>,
) -> LockingScript {
    let cert_type: [u8; 32] = from_base64(XCERT).unwrap().try_into().unwrap();
    let serial = [2u8; 32];
    let subject_pub = subject.public_key();
    let certifier_pub = certifier.public_key();
    let certifier_wallet = ProtoWallet::new(Some(certifier.clone()));
    let subject_wallet = ProtoWallet::new(Some(subject.clone()));
    let mut plain = IndexMap::new();
    plain.insert("userName".to_string(), user_name.to_string());
    let master = MasterCertificate::issue_for_subject(
        &certifier_wallet,
        certifier,
        subject_pub.clone(),
        plain,
        cert_type,
        Some(serial),
        None,
    )
    .await
    .unwrap();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &subject_wallet,
        &certifier_pub,
        &anyone_pub(),
        &master.certificate.fields,
        &["userName".to_string()],
        &master.master_keyring,
        &serial,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let certifier_hex = certifier_in_json
        .map(|s| s.to_string())
        .unwrap_or_else(|| certifier_pub.to_hex());
    let json = serde_json::json!({
        "type": to_base64(&cert_type),
        "serialNumber": to_base64(&serial),
        "subject": subject_pub.to_hex(),
        "certifier": certifier_hex,
        // issue_for_subject leaves no revocation outpoint; its signable is the
        // all-zeros sentinel, which this 64-zero string reads back as (#553).
        "revocationOutpoint": "0".repeat(64),
        "fields": master.certificate.fields,
        // the reference's WalletCertificate carries the signature as hex (#553)
        "signature": to_hex(master.certificate.signature.as_ref().unwrap()),
        "keyring": keyring,
    });
    let field0 = serde_json::to_vec(&json).unwrap();
    let field1 = subject_signature(subject, &field0);
    PushDrop::new(lock_key(&subject_pub), vec![field0, field1]).lock()
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
    let script = self_authored_token(&party, &party_cert_key, "Alice Victim", None).await;

    // resolve_by_identity_key
    let c = client("key", vec![output_of(script.clone())]);
    let ids = c.resolve_by_identity_key(&party_hex, false).await.unwrap();
    assert_eq!(ids.len(), 1, "the record is read");
    assert_eq!(ids[0].identity_key, party_hex);
    no_vouching(&ids[0]);

    // query
    let c = client("query", vec![output_of(script.clone())]);
    let results = c.query(IdentityQuery::default()).await.unwrap();
    assert_eq!(results.len(), 1);
    no_vouching(&results[0].identity);
    assert_ne!(
        results[0].certificates[0].certifier().to_hex(),
        DEFAULT_SOCIALCERT_CERTIFIER
    );

    // resolve_by_attributes
    let c = client("attr", vec![output_of(script)]);
    let attrs = IndexMap::from([("userName".to_string(), "Alice Victim".to_string())]);
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
    let script = self_authored_token(&party, &party_cert_key, "Someone Else", None).await;
    let c = client("else", vec![output_of(script)]);
    let attrs = IndexMap::from([("userName".to_string(), "Someone Else".to_string())]);
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
    let script = self_authored_token(&party, &party_cert_key, "SocialCert", None).await;
    let c = client("name", vec![output_of(script)]);
    let ids = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert_eq!(ids.len(), 1);
    no_vouching(&ids[0]);
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
    )
    .await;
    let c = client("forgekey", vec![output_of(script)]);
    let ids = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert!(
        ids.is_empty(),
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
    let verifiable = VerifiableCertificate::new(certificate, IndexMap::new());
    let mut decrypted = IndexMap::new();
    decrypted.insert("userName".to_string(), "alice_x".to_string());
    let anchored = IdentityCertificate {
        certificate: verifiable,
        certifier_info: CertifierInfo {
            name: "SocialCert".to_string(),
            icon_url: "https://socialcert.net/favicon.ico".to_string(),
            description: "Social identity verification".to_string(),
            trust: 5,
        },
        publicly_revealed_keyring: IndexMap::new(),
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
    let script = self_authored_token(&party, &party_cert_key, "Alice Victim", None).await;
    let c = client("click", vec![output_of(script)]);
    let ids = c
        .resolve_by_identity_key(&party.public_key().to_hex(), false)
        .await
        .unwrap();
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].badge_click_url.contains("socialcert.net"));
    assert_eq!(ids[0].badge_label, DefaultIdentityValues::BADGE_LABEL);
    assert_eq!(
        ids[0].badge_click_url,
        DefaultIdentityValues::BADGE_CLICK_URL
    );
}

// ---- the vouching badge is minted at exactly one guarded place ---------

#[test]
fn the_vouching_badge_is_minted_at_one_guarded_place() {
    // The sole production site that mints the SocialCert vouching label is
    // `badge::certifier_info_for`; every door reaches it through that one call,
    // so a new door cannot hand out a vouching badge without the anchor check.
    // A Windows checkout may hold these files with CRLF line ends; the splits
    // below are written with LF, so the text is read with LF line ends.
    let badge_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/identity/badge.rs"
    ))
    .replace("\r\n", "\n");
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
    ))
    .replace("\r\n", "\n");
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
