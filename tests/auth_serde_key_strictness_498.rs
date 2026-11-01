//! #498's fold: serde's `PublicKey` reading and `KeyringRevealer` stay strict.
//!
//! `PublicKey::from_hex` reads the reference's `PublicKey.fromString` forms
//! (the keeper's word of 2026-10-30 05:1xZ); the argument paths read through
//! serde are the reference's validators, which are strict:
//! `assertAuthIdentityKey` (`ts-stack@edf6e03` `AuthMessageValidation.ts:81-89`),
//! `validateKeyringRevealer` -> `validatePublicKey` (`validationHelpers.ts:185-191,
//! 1243-1246`) and the certificate's `assertCompressedPublicKey`
//! (`Certificate.ts:240-245`). The inputs are the recorded lenient forms of
//! `vectors/public_key_forms_498.json`. Since #582 `KeyringRevealer` reads
//! through `wallet::validate_public_key` (#579), in its words.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::auth::types::{AuthMessage, PeerSession};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::types::{Certificate as WalletCertificate, KeyringRevealer};
use bsv_rs::wallet::KeyLinkageResult;
use serde_json::{json, Value};

/// The forms `from_hex` reads since #498 and `from_bytes` refuses: the odd
/// lengths, the hybrids and the coordinates at or above p.
fn lenient_forms() -> Vec<(String, String)> {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/public_key_forms_498.json")).unwrap();
    let forms: Vec<_> = recorded["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["accepted"] == true)
        .map(|case| {
            (
                case["name"].as_str().unwrap().to_string(),
                case["input"].as_str().unwrap().to_string(),
            )
        })
        .filter(|(name, _)| {
            ["odd_length_", "hybrid_", "x_above_p_", "y_above_p_"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
        })
        .collect();
    assert_eq!(forms.len(), 15, "the recorded lenient forms");
    // The three the review named are among them.
    for name in [
        "hybrid_even",
        "odd_length_compressed_even",
        "x_above_p_compressed_even",
    ] {
        assert!(forms.iter().any(|(n, _)| n == name), "{name}");
    }
    forms
}

fn auth_message(identity_key: &str) -> Value {
    json!({
        "version": "0.1",
        "messageType": "initialRequest",
        "identityKey": identity_key,
        "initialNonce": "dGVzdC1pbml0aWF0b3Itbm9uY2U=",
    })
}

#[test]
fn an_auth_message_identity_key_in_a_lenient_form_is_refused_498() {
    let control = PrivateKey::random().public_key().to_hex();
    serde_json::from_value::<AuthMessage>(auth_message(&control)).unwrap();
    for (name, input) in lenient_forms() {
        assert!(
            serde_json::from_value::<AuthMessage>(auth_message(&input)).is_err(),
            "{name}: an AuthMessage identityKey read leniently"
        );
    }
}

#[test]
fn a_keyring_revealer_in_a_lenient_form_is_refused_498() {
    let control = PrivateKey::random().public_key().to_hex();
    assert!(matches!(
        serde_json::from_value::<KeyringRevealer>(json!(control)),
        Ok(KeyringRevealer::PublicKey(_))
    ));
    for (name, input) in lenient_forms() {
        let error = serde_json::from_value::<KeyringRevealer>(json!(input))
            .err()
            .unwrap_or_else(|| panic!("{name}: a keyringRevealer read leniently"));
        // In `validatePublicKey`'s words since #582
        assert!(
            error
                .to_string()
                .starts_with("The keyringRevealer parameter must be "),
            "{name}: {error}"
        );
    }
}

/// #582: `validateKeyringRevealer` is `validatePublicKey` (`ts-stack@edf6e03`
/// `validationHelpers.ts:1243-1246,185-191`), which refuses an uncompressed
/// key and reads a space-padded one trimmed; the strict reading
/// (`from_strict_hex`) read the first and refused the second until #582. The
/// verdicts are the 579 recorder's, its parameter renamed.
#[test]
fn a_keyring_revealer_is_read_as_the_reference_validate_public_key_reads_it_582() {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/public_key_validation_579.json")).unwrap();
    let parameter = recorded["wallet_parameter"].as_str().unwrap();
    for name in ["uncompressed_498", "surrounding_space", "upper_case"] {
        let case = recorded["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .unwrap();
        let read = serde_json::from_value::<KeyringRevealer>(case["text"].clone());
        let wallet = &case["wallet"];
        if wallet["ok"] == true {
            match read {
                Ok(KeyringRevealer::PublicKey(key)) => {
                    assert_eq!(key.to_hex(), wallet["returned"].as_str().unwrap(), "{name}")
                }
                other => panic!("{name}: {other:?}"),
            }
        } else {
            let words = wallet["message"]
                .as_str()
                .unwrap()
                .replace(&format!("The {parameter} "), "The keyringRevealer ");
            assert_eq!(read.unwrap_err().to_string(), words, "{name}");
        }
    }
}

#[test]
fn a_certificate_subject_or_certifier_in_a_lenient_form_is_refused_498() {
    let key = PrivateKey::random().public_key();
    let json = serde_json::to_value(Certificate::new([1; 32], [2; 32], key.clone(), key)).unwrap();
    serde_json::from_value::<Certificate>(json.clone()).unwrap();
    for (name, input) in lenient_forms() {
        for member in ["subject", "certifier"] {
            let mut read = json.clone();
            read[member] = json!(input);
            assert!(
                serde_json::from_value::<Certificate>(read).is_err(),
                "{name}: a certificate {member} read leniently"
            );
        }
    }
}

/// Each `member` of `json` in every lenient form: refused by `T`'s reading,
/// the control `json` read.
fn refuses_each_member<T: serde::de::DeserializeOwned>(json: Value, members: &[&str], what: &str) {
    serde_json::from_value::<T>(json.clone()).unwrap();
    for (name, input) in lenient_forms() {
        for member in members {
            let mut read = json.clone();
            read[*member] = json!(input);
            assert!(
                serde_json::from_value::<T>(read).is_err(),
                "{name}: a {what} {member} read leniently"
            );
        }
    }
}

#[test]
fn a_key_linkage_result_key_in_a_lenient_form_is_refused_498() {
    let key = PrivateKey::random().public_key();
    let json = serde_json::to_value(KeyLinkageResult {
        encrypted_linkage: vec![1, 2],
        encrypted_linkage_proof: vec![3, 4],
        prover: key.clone(),
        verifier: key.clone(),
        counterparty: key,
    })
    .unwrap();
    refuses_each_member::<KeyLinkageResult>(
        json,
        &["prover", "verifier", "counterparty"],
        "KeyLinkageResult",
    );
}

#[test]
fn a_peer_session_identity_key_in_a_lenient_form_is_refused_498() {
    let mut session = PeerSession::with_nonce("bm9uY2U=".into());
    session.peer_identity_key = Some(PrivateKey::random().public_key());
    let json = serde_json::to_value(session).unwrap();
    refuses_each_member::<PeerSession>(json, &["peerIdentityKey"], "PeerSession");
}

#[test]
fn a_wallet_certificate_subject_or_certifier_in_a_lenient_form_is_refused_498() {
    let key = PrivateKey::random().public_key();
    let json = serde_json::to_value(WalletCertificate {
        certificate_type: "AQ==".into(),
        subject: key.clone(),
        serial_number: "Ag==".into(),
        certifier: key,
        revocation_outpoint: None,
        fields: Default::default(),
        signature: None,
    })
    .unwrap();
    refuses_each_member::<WalletCertificate>(json, &["subject", "certifier"], "wallet Certificate");
}
