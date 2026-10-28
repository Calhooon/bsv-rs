//! A certificate issued here, its HMAC, and both keyrings verified by the
//! merged ts-stack PR 1423 at 9a2787b8c under Node 22 (#379).
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::{Certificate, MasterCertificate, VerifiableCertificate};
use bsv_rs::primitives::{from_hex, sha256_hmac, to_hex, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateHmacArgs, ProtoWallet, Protocol, SecurityLevel};
use indexmap::IndexMap;
use serde_json::{json, Value};

fn key(n: u8) -> PrivateKey {
    let mut bytes = [0; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn hmac_wallet() -> ProtoWallet {
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/wallet_hmac_key_379.json")).unwrap();
    ProtoWallet::new(Some(
        PrivateKey::from_hex(vectors["rootKey"].as_str().unwrap()).unwrap(),
    ))
}

fn hmac_args(data: Vec<u8>) -> CreateHmacArgs {
    CreateHmacArgs {
        data,
        protocol_id: Protocol::new(SecurityLevel::Counterparty, "hmac key vectors"),
        key_id: "k95".into(),
        counterparty: Some(Counterparty::Self_),
        ..Default::default()
    }
}

async fn issue() -> (
    MasterCertificate,
    IndexMap<String, String>,
    IndexMap<String, String>,
) {
    // field76's master encryption key and field0's verifier encryption key
    // each begin with zero. AES must retain those octets (BRC-2).
    let plaintexts: IndexMap<String, String> = [
        ("field76".into(), "master key starts with zero".into()),
        ("field0".into(), "verifier key starts with zero".into()),
    ]
    .into_iter()
    .collect();
    let certifier = key(43);
    let master = MasterCertificate::issue_for_subject(
        &ProtoWallet::new(Some(certifier.clone())),
        &certifier,
        key(47).public_key(),
        plaintexts.clone(),
        [8; 32],
        Some([9; 32]),
        Some("hmac-379.test"),
    )
    .await
    .unwrap();
    let keyring = MasterCertificate::create_keyring_for_verifier(
        &ProtoWallet::new(Some(key(47))),
        &certifier.public_key(),
        &key(41).public_key(),
        &master.fields,
        &plaintexts.keys().cloned().collect::<Vec<_>>(),
        &master.master_keyring,
        &master.serial_number,
        None,
        None,
        Some("hmac-379.test"),
    )
    .await
    .unwrap();
    (master, keyring, plaintexts)
}

#[tokio::test]
async fn a_fresh_certificate_issues_the_minimal_length_hmac() {
    let (master, _, _) = issue().await;
    let data = master.to_binary(true).unwrap();
    let vectors: Value =
        serde_json::from_str(include_str!("vectors/wallet_hmac_key_379.json")).unwrap();
    let key = from_hex(vectors["vectors"][1]["hmacKey"].as_str().unwrap()).unwrap();
    assert_eq!(
        hmac_wallet()
            .create_hmac(hmac_args(data.clone()))
            .unwrap()
            .hmac,
        sha256_hmac(&key, &data)
    );
}

#[tokio::test]
async fn the_reference_verifies_the_issued_certificate_and_decrypts_both_keyrings() {
    let v: Value =
        serde_json::from_str(include_str!("vectors/auth_hmac_issuance_379.json")).unwrap();
    assert_eq!(v["referenceCertificateValid"], true);
    assert_eq!(v["referenceHmacValid"], true);
    assert_eq!(v["referenceMasterPlaintexts"], v["plaintexts"]);
    assert_eq!(v["referenceVerifierPlaintexts"], v["plaintexts"]);
    assert!(v["encryptionKeys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["master"].as_str().unwrap().len() == 62));
    assert!(v["encryptionKeys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["verifier"].as_str().unwrap().len() == 62));
    let certificate =
        Certificate::from_binary(&from_hex(v["binaryHex"].as_str().unwrap()).unwrap()).unwrap();
    assert!(certificate.verify().unwrap());
    let master = MasterCertificate::new(
        certificate.clone(),
        serde_json::from_value(v["masterKeyring"].clone()).unwrap(),
    )
    .unwrap();
    let plaintexts: IndexMap<String, String> =
        serde_json::from_value(v["plaintexts"].clone()).unwrap();
    assert_eq!(
        master
            .decrypt_fields(
                &ProtoWallet::new(Some(key(47))),
                &key(43).public_key(),
                None,
                None,
                None
            )
            .await
            .unwrap(),
        plaintexts
    );
    let mut revealed = VerifiableCertificate::new(
        certificate,
        serde_json::from_value(v["verifierKeyring"].clone()).unwrap(),
    );
    assert_eq!(
        revealed
            .decrypt_fields(&ProtoWallet::new(Some(key(41))), None, None, None)
            .await
            .unwrap(),
        plaintexts
    );
}

/// The only writer of the Rust-issued input consumed by hmac_key_379.mjs.
/// Run with BSV_HMAC_ISSUED_OUTPUT set to a path outside the checkout.
#[tokio::test]
#[ignore]
async fn record_a_certificate_issued_here_for_the_reference() {
    let (master, keyring, plaintexts) = issue().await;
    let data = master.to_binary(true).unwrap();
    let hmac = hmac_wallet()
        .create_hmac(hmac_args(data.clone()))
        .unwrap()
        .hmac;
    let value = json!({
        "keys": {"certifier": 43, "subject": 47, "verifier": 41},
        "plaintexts": plaintexts,
        "binaryHex": to_hex(&data),
        "masterKeyring": master.master_keyring,
        "verifierKeyring": keyring,
        "hmac": to_hex(&hmac),
    });
    std::fs::write(
        std::env::var("BSV_HMAC_ISSUED_OUTPUT").unwrap(),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}
