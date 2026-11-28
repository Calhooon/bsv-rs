//! bsv-rs#1118e: the identity client's two `ls_identity` parsers must read a
//! revelation token only when the subject authored it, so a party who does
//! not hold the subject's key cannot present another key's certificate from
//! an untrusted lookup host as a vouched-for identity.
//!
//! The reference reads a published identity token only after authenticating
//! it (`ts-stack@edf6e03` `IdentityClient.ts:773-815`,
//! `wallet-toolbox/identityUtils.ts:497-559`) and admitting its transaction
//! evidence (`TransactionEvidence.ts:93-201`, `identityUtils.ts:600-634`);
//! TS/Go delegate the whole resolve to the trusted wallet. The stable
//! Rust line re-implemented the resolve against the untrusted overlay and
//! read the first field of ANY token whose certifier self-signed, badging
//! it "certified by SocialCert, trust 5".
//!
//! Hermetic (crate Rule 4): an in-process resolver on an `.invalid` host,
//! every token built by this crate's own writers. These tests are RED on
//! `origin/main` (0.8.13): the forged and non-authenticated tokens are
//! returned there, badged as a trusted certifier. The honest-token tests
//! (C) pass on both lines: an honest subject-signed revelation keeps the
//! value 0.8.13 returned.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/identity_token_1118e.rs"]
mod support;

use bsv_rs::auth::Certificate;
use bsv_rs::identity::{IdentityClient, IdentityClientConfig, IdentityQuery};
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol};
use std::collections::HashMap;

/// The real SocialCert certifier key this crate hints to the overlay.
const SOCIALCERT: &str = "02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17";

fn protocol() -> Protocol {
    Protocol::from_tuple((1, "identity")).unwrap()
}

/// The key the reference's anyone wallet derives for the subject
/// (counterparty = subject), the key an authenticated token is locked with.
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

/// The subject's signature over `field0`, created as the reference's reveal
/// does (counterparty = anyone), so the anyone wallet verifies it with
/// counterparty = the subject.
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

/// The certificate JSON an identity token's first field is, its certifier
/// `certifier`, signed by it, no fields (the badge does not depend on them).
fn cert_json(subject: &PublicKey, certifier: &PrivateKey) -> Vec<u8> {
    let cert_type = [1u8; 32];
    let serial = [2u8; 32];
    let mut cert = Certificate::new(cert_type, serial, subject.clone(), certifier.public_key());
    cert.sign(certifier).unwrap();
    assert!(cert.verify().unwrap(), "the certifier's cert verifies");
    let empty: HashMap<String, String> = HashMap::new();
    let json = serde_json::json!({
        "type": to_base64(&cert_type),
        "serialNumber": to_base64(&serial),
        "subject": subject.to_hex(),
        "certifier": certifier.public_key().to_hex(),
        "fields": empty,
        "signature": to_base64(cert.signature.as_ref().unwrap()),
        "keyring": empty,
    });
    serde_json::to_vec(&json).unwrap()
}

/// An honest two-field revelation: the subject's locking key, the cert JSON,
/// and the subject's signature over it.
fn honest_token(subject: &PrivateKey, certifier: &PrivateKey) -> LockingScript {
    let field0 = cert_json(&subject.public_key(), certifier);
    let field1 = subject_signature(subject, &field0);
    PushDrop::new(lock_key(&subject.public_key()), vec![field0, field1]).lock()
}

fn client(
    resolver: std::sync::Arc<bsv_rs::overlay::LookupResolver>,
) -> IdentityClient<ProtoWallet> {
    IdentityClient::with_resolver(
        ProtoWallet::new(None),
        IdentityClientConfig::default(),
        resolver,
    )
}

// ===========================================================================
// A. The forged any-certifier token, refused at every production door (#544).
// ===========================================================================

/// A single attacker-locked field wrapping a certificate the attacker signed
/// as its own certifier (subject = the victim): the untrusted overlay's reply.
fn forged_token(attacker: &PrivateKey, victim: &PublicKey) -> LockingScript {
    let field0 = cert_json(victim, attacker);
    PushDrop::new(attacker.public_key(), vec![field0]).lock()
}

#[tokio::test]
async fn a_forged_any_certifier_token_is_refused_at_every_identity_door_1118e() {
    let attacker = PrivateKey::random();
    let victim = PrivateKey::random().public_key();
    let victim_hex = victim.to_hex();
    let out = support::output_of(forged_token(&attacker, &victim));

    let c = client(support::answering(
        "ls_identity",
        "a-key",
        vec![out.clone()],
    ));
    assert!(
        c.resolve_by_identity_key(&victim_hex, false)
            .await
            .unwrap()
            .is_none(),
        "resolve_by_identity_key must not badge a forged any-certifier token"
    );

    let c = client(support::answering(
        "ls_identity",
        "a-attr",
        vec![out.clone()],
    ));
    let attrs = HashMap::from([("email".to_string(), "alice@example.com".to_string())]);
    assert!(
        c.resolve_by_attributes(attrs, false)
            .await
            .unwrap()
            .is_empty(),
        "resolve_by_attributes must not badge a forged token"
    );

    let c = client(support::answering(
        "ls_identity",
        "a-query",
        vec![out.clone()],
    ));
    let q = IdentityQuery {
        identity_key: Some(victim_hex.clone()),
        ..Default::default()
    };
    assert!(
        c.query(q).await.unwrap().is_empty(),
        "query must not badge a forged token"
    );

    let c = client(support::answering(
        "ls_identity",
        "a-disc",
        vec![out.clone()],
    ));
    assert!(
        c.discover_certificates(&victim_hex)
            .await
            .unwrap()
            .is_empty(),
        "discover_certificates must not return a forged token's certificate"
    );

    let c = client(support::answering("ls_identity", "a-disct", vec![out]));
    assert!(
        c.discover_certificates_by_type(
            &victim_hex,
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        )
        .await
        .unwrap()
        .is_empty(),
        "discover_certificates_by_type must not return a forged token's certificate"
    );
}

// ===========================================================================
// B. The #544 matrix through BOTH parsers: only the subject's authenticated
//    two-field revelation is read; every one-change token is skipped.
// ===========================================================================

/// Identities and certificates the two parsers return for `script`.
async fn read_both(script: LockingScript, tag: &str, subject_hex: &str) -> (usize, usize) {
    let out = support::output_of(script);
    let c = client(support::answering("ls_identity", tag, vec![out.clone()]));
    let attrs = HashMap::from([("email".to_string(), "alice@example.com".to_string())]);
    let identities = c.resolve_by_attributes(attrs, false).await.unwrap();
    let c = client(support::answering("ls_identity", tag, vec![out]));
    let certificates = c.discover_certificates(subject_hex).await.unwrap();
    (identities.len(), certificates.len())
}

#[tokio::test]
async fn b_only_the_subjects_authenticated_token_is_read_1118e() {
    let subject = PrivateKey::random();
    let certifier = PrivateKey::random();
    let subject_hex = subject.public_key().to_hex();
    let field0 = cert_json(&subject.public_key(), &certifier);
    let field1 = subject_signature(&subject, &field0);

    // honest: the subject's locking key, its signature -> read.
    let honest = PushDrop::new(
        lock_key(&subject.public_key()),
        vec![field0.clone(), field1.clone()],
    )
    .lock();
    assert_eq!(
        read_both(honest, "b-ok", &subject_hex).await,
        (1, 1),
        "honest token read"
    );

    // wrong locking key (another key's derived key) -> skipped.
    let other = PrivateKey::random().public_key();
    let wrong_lock = PushDrop::new(lock_key(&other), vec![field0.clone(), field1.clone()]).lock();
    assert_eq!(
        read_both(wrong_lock, "b-lock", &subject_hex).await,
        (0, 0),
        "wrong lock key skipped"
    );

    // bad signature (not the subject's) -> skipped.
    let imposter = PrivateKey::random();
    let bad_sig = subject_signature(&imposter, &field0);
    let bad = PushDrop::new(
        lock_key(&subject.public_key()),
        vec![field0.clone(), bad_sig],
    )
    .lock();
    assert_eq!(
        read_both(bad, "b-sig", &subject_hex).await,
        (0, 0),
        "bad signature skipped"
    );

    // one field (no signature) -> skipped.
    let one = PushDrop::new(lock_key(&subject.public_key()), vec![field0.clone()]).lock();
    assert_eq!(
        read_both(one, "b-one", &subject_hex).await,
        (0, 0),
        "one-field token skipped"
    );

    // three fields -> skipped.
    let three = PushDrop::new(
        lock_key(&subject.public_key()),
        vec![field0.clone(), field1, b"extra".to_vec()],
    )
    .lock();
    assert_eq!(
        read_both(three, "b-three", &subject_hex).await,
        (0, 0),
        "three-field token skipped"
    );
}

// ===========================================================================
// C. S2: an honest subject-signed token is still read and still badged
//    "SocialCert, trust 5" (this value is unchanged from 0.8.13; it passes
//    on both lines).
// ===========================================================================

#[tokio::test]
async fn c_the_authenticated_token_is_read_and_badged_1118e() {
    let subject = PrivateKey::random();
    let certifier = PrivateKey::random();
    assert_ne!(
        certifier.public_key().to_hex(),
        SOCIALCERT,
        "the certifier is a test key"
    );
    let subject_hex = subject.public_key().to_hex();

    let out = support::output_of(honest_token(&subject, &certifier));
    let c = client(support::answering("ls_identity", "c-s2", vec![out]));

    let id = c
        .resolve_by_identity_key(&subject_hex, false)
        .await
        .unwrap()
        .expect("the subject's own authenticated revelation is read");
    assert_eq!(
        id.identity_key, subject_hex,
        "the subject is the queried key"
    );
    // The displayed badge value is unchanged from 0.8.13: a subject-authored
    // token keeps the "SocialCert" label.
    assert!(
        id.badge_label.contains("SocialCert"),
        "the residual badge still reads SocialCert: {}",
        id.badge_label
    );
    assert!(id.badge_icon_url.contains("socialcert.net"));
}

// ===========================================================================
// D. The evidence check (#730): a well-formed authenticated token in an
//    unproven transaction with no inputs is refused as invalid evidence.
// ===========================================================================

#[tokio::test]
async fn d_a_token_in_unproven_evidence_is_refused_1118e() {
    let subject = PrivateKey::random();
    let certifier = PrivateKey::random();
    let subject_hex = subject.public_key().to_hex();

    let out = support::unproven_output_of(honest_token(&subject, &certifier));
    let c = client(support::answering("ls_identity", "d-ev", vec![out]));
    assert!(
        c.resolve_by_identity_key(&subject_hex, false)
            .await
            .unwrap()
            .is_none(),
        "an unproven transaction with no inputs is not admitted as evidence"
    );
}
