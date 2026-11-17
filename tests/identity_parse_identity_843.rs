//! `IdentityClient::parse_identity` parses a wallet's discovery answer (#843).
//!
//! The reference's `IdentityClient.parseIdentity` takes the wallet's
//! `IdentityCertificate` (`IdentityClient.ts:1044`, the record of
//! `Wallet.interfaces.ts:877` at `ts-stack@edf6e03`; go-sdk's `parseIdentity`
//! the same, `identity/client.go:385` at `2ca481c`), so an entry of a
//! wallet's `discoverByIdentityKey` or `discoverByAttributes` answer goes to
//! it as it came. Until #843 this crate's `parse_identity` took a record of
//! the identity module's own, which no public door produced and no wallet
//! answer could be given as: the door went untested for it
//! (`tests/identity_tests.rs`). `identity::IdentityCertificate` and
//! `identity::IdentityCertifier` are the wallet's types since, re-exported,
//! and `identity::CertifierInfo` is gone.
//!
//! The answer below is a `discoverByIdentityKey` result in BRC-100's JSON
//! (the shape `tests/wallet_http_json_shapes_105.rs` pins); what each entry
//! displays as is typed from the reference's rules (`IdentityClient.ts`'s
//! type switch: an X certificate `:1077-1086`, an email certificate
//! `:1097-1104`), never computed from the code under test.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, KnownCertificateType};
use bsv_rs::wallet::{DiscoverCertificatesResult, ProtoWallet};
use serde_json::json;

const SUBJECT: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const CERTIFIER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

/// One entry of a wallet's discovery answer, in BRC-100's JSON.
fn entry(type_id: &str, decrypted: serde_json::Value) -> serde_json::Value {
    json!({
        "type": type_id,
        "subject": SUBJECT,
        "serialNumber": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "certifier": CERTIFIER,
        "revocationOutpoint": format!("{}.0", "ab".repeat(32)),
        "signature": "3006020101020101",
        "fields": { "userName": "ZW5jcnlwdGVk" },
        "certifierInfo": {
            "name": "SocialCert",
            "iconUrl": "https://socialcert.net/favicon.ico",
            "description": "Social identity verification",
            "trust": 5
        },
        "publiclyRevealedKeyring": { "userName": "a2V5" },
        "decryptedFields": decrypted
    })
}

fn answer(entries: Vec<serde_json::Value>) -> DiscoverCertificatesResult {
    serde_json::from_value(json!({
        "totalCertificates": entries.len(),
        "certificates": entries
    }))
    .unwrap()
}

#[test]
fn a_wallet_answer_is_parsed_843() {
    let result = answer(vec![
        entry(
            KnownCertificateType::XCert.type_id(),
            json!({ "userName": "alice", "profilePhoto": "https://example.com/alice.png" }),
        ),
        entry(
            KnownCertificateType::EmailCert.type_id(),
            json!({ "email": "alice@example.com" }),
        ),
    ]);
    let x = IdentityClient::<ProtoWallet>::parse_identity(&result.certificates[0]);
    assert_eq!(x.name, "alice");
    assert_eq!(x.avatar_url, "https://example.com/alice.png");
    assert_eq!(x.badge_label, "X account certified by SocialCert");
    assert_eq!(x.badge_icon_url, "https://socialcert.net/favicon.ico");
    assert_eq!(x.badge_click_url, "https://socialcert.net");
    assert_eq!(x.identity_key, SUBJECT);
    assert_eq!(x.abbreviated_key, "0279be667e...");

    let email = IdentityClient::<ProtoWallet>::parse_identity(&result.certificates[1]);
    assert_eq!(email.name, "alice@example.com");
    assert_eq!(
        email.avatar_url,
        "XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu"
    );
    assert_eq!(email.badge_label, "Email certified by SocialCert");
    assert_eq!(email.badge_icon_url, "https://socialcert.net/favicon.ico");
    assert_eq!(email.badge_click_url, "https://socialcert.net");
    assert_eq!(email.identity_key, SUBJECT);
}

/// The identity module's two names are the wallet's types: a record of one
/// path is a record of the other, with no conversion.
#[test]
fn the_identity_paths_name_the_wallets_types_843() {
    fn wallets(cert: bsv_rs::wallet::IdentityCertificate) -> bsv_rs::identity::IdentityCertificate {
        cert
    }
    fn certifiers(info: bsv_rs::wallet::IdentityCertifier) -> bsv_rs::identity::IdentityCertifier {
        info
    }
    let result = answer(vec![entry(
        KnownCertificateType::XCert.type_id(),
        json!({ "userName": "alice" }),
    )]);
    let cert = wallets(result.certificates[0].clone());
    assert_eq!(certifiers(cert.certifier_info.clone()).trust, 5);
    assert_eq!(cert.certificate.subject, SUBJECT);
}

/// The subject is the wallet's text as it came, so the abbreviation is cut
/// by character: a subject that is no key (any text a wallet answers) is
/// displayed, never a panic.
#[test]
fn a_subject_that_is_no_key_is_abbreviated_by_character_843() {
    let mut result = answer(vec![entry(
        KnownCertificateType::XCert.type_id(),
        json!({ "userName": "alice" }),
    )]);
    let cert = &mut result.certificates[0];
    cert.certificate.subject = "\u{e9}".repeat(12);
    let shown = IdentityClient::<ProtoWallet>::parse_identity(cert);
    assert_eq!(shown.identity_key, "\u{e9}".repeat(12));
    assert_eq!(shown.abbreviated_key, format!("{}...", "\u{e9}".repeat(10)));
    cert.certificate.subject = "02ab".to_string();
    let shown = IdentityClient::<ProtoWallet>::parse_identity(cert);
    assert_eq!(shown.abbreviated_key, "02ab");
}
