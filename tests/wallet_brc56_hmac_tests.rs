//! Amended BRC-56 HMAC issuance and legacy verification (#148, #379).
//!
//! The six shared vectors are recorded from ts-stack PR 1423 at `9a2787b8c`
//! under Node 22 by `support/hmac_key_379.mjs`. Its `hmac` is standard and
//! `rejectedTag` is the pre-amendment 32-byte-key tag accepted here as legacy.
//! The default counts and names only that legacy acceptance; the strict
//! `MinimalLengthOnly` policy agrees with the reference and amended BRC.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_hex, sha256, to_hex, PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, HmacKeyEncoding, HmacVerifyPolicy, KeyDeriver, ProtoWallet,
    Protocol, SecurityLevel, VerifyHmacArgs,
};
use bsv_rs::Error;

/// The amended BRC-56 and PR 1423 root key, SHA-256 of the label below.
const ROOT_KEY: &str = "f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07";
const ROOT_LABEL: &str = "BRC-56 HMAC key test vectors: root";
/// Shared vector input: the root public key.
const ROOT_PUB: &str = "035818cd7cc614fea816c8b39eebe6e43cafc635451ec5a873f8757b418aaae91a";
/// Shared vector input: the counterparty public key, its private key SHA-256
/// of the label below.
const COUNTERPARTY_PUB: &str = "03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7";
const COUNTERPARTY_LABEL: &str = "BRC-56 HMAC key test vectors: counterparty";
/// Shared vector input: the protocol, `[2, "hmac key vectors"]`.
const PROTOCOL_NAME: &str = "hmac key vectors";
/// Shared vector input: the data, `4252432d353620484d41432074657374`.
const DATA: &[u8] = b"BRC-56 HMAC test";

/// Byte-for-byte values from the merged PR 1423 table, read by the recorder.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Row {
    counterparty: String,
    #[serde(rename = "keyID")]
    key_id: String,
    leading_zero_bytes: usize,
    hmac_key: String,
    #[serde(rename = "hmac")]
    tag: String,
    #[serde(rename = "rejectedTag")]
    legacy_tag: Option<String>,
}

fn rows() -> Vec<Row> {
    let value: serde_json::Value =
        serde_json::from_str(include_str!("vectors/wallet_hmac_key_379.json")).unwrap();
    serde_json::from_value(value["vectors"].clone()).unwrap()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, PROTOCOL_NAME)
}

fn root_key() -> PrivateKey {
    PrivateKey::from_hex(ROOT_KEY).unwrap()
}

fn counterparty(row: &Row) -> Counterparty {
    if row.counterparty != "self" {
        Counterparty::Other(PublicKey::from_hex(COUNTERPARTY_PUB).unwrap())
    } else {
        Counterparty::Self_
    }
}

fn tag(hex: &str) -> [u8; 32] {
    from_hex(hex).unwrap().try_into().unwrap()
}

fn args(row: &Row, hmac: [u8; 32]) -> VerifyHmacArgs {
    VerifyHmacArgs {
        data: DATA.to_vec(),
        hmac,
        protocol_id: protocol(),
        key_id: row.key_id.to_string(),
        counterparty: Some(counterparty(row)),
        ..Default::default()
    }
}

fn verify(wallet: &ProtoWallet, row: &Row, hmac: [u8; 32]) -> bsv_rs::Result<bool> {
    wallet.verify_hmac(args(row, hmac)).map(|r| r.valid)
}

fn strict() -> ProtoWallet {
    ProtoWallet::new(Some(root_key())).with_hmac_verify_policy(HmacVerifyPolicy::MinimalLengthOnly)
}

#[test]
fn the_brc56_inputs_derive_from_their_labels() {
    assert_eq!(to_hex(&sha256(ROOT_LABEL.as_bytes())), ROOT_KEY);
    assert_eq!(root_key().public_key().to_hex(), ROOT_PUB);
    let counterparty = PrivateKey::from_bytes(&sha256(COUNTERPARTY_LABEL.as_bytes())).unwrap();
    assert_eq!(counterparty.public_key().to_hex(), COUNTERPARTY_PUB);
    assert_eq!(to_hex(DATA), "4252432d353620484d41432074657374");
}

#[test]
fn the_six_minimal_hmac_keys_are_suffixes_of_fixed_width_aes_keys() {
    let deriver = KeyDeriver::new(Some(root_key()));
    for row in &rows() {
        let key = deriver
            .derive_symmetric_key(&protocol(), &row.key_id, &counterparty(row))
            .unwrap();
        assert_eq!(
            to_hex(&key.as_bytes()[row.leading_zero_bytes..]),
            row.hmac_key,
            "key {}",
            row.key_id
        );
        let zeros = key.as_bytes().iter().take_while(|b| **b == 0).count();
        assert_eq!(zeros, row.leading_zero_bytes, "key {}", row.key_id);
    }
}

#[test]
fn create_hmac_reproduces_the_six_brc56_tags() {
    let wallet = ProtoWallet::new(Some(root_key()));
    for row in &rows() {
        let created = wallet
            .create_hmac(CreateHmacArgs {
                data: DATA.to_vec(),
                protocol_id: protocol(),
                key_id: row.key_id.to_string(),
                counterparty: Some(counterparty(row)),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(to_hex(&created.hmac), row.tag, "key {}", row.key_id);
    }
}

#[test]
fn verify_hmac_accepts_the_six_standard_minimal_length_tags() {
    let wallet = ProtoWallet::new(Some(root_key()));
    for row in &rows() {
        assert_eq!(
            verify(&wallet, row, tag(&row.tag)),
            Ok(true),
            "key {}",
            row.key_id
        );
    }
    // The counterparty, verifying under the root's identity key, agrees.
    let other = PrivateKey::from_bytes(&sha256(COUNTERPARTY_LABEL.as_bytes())).unwrap();
    let other = ProtoWallet::new(Some(other));
    for row in rows().iter().filter(|r| r.counterparty != "self") {
        let valid = other
            .verify_hmac(VerifyHmacArgs {
                data: DATA.to_vec(),
                hmac: tag(&row.tag),
                protocol_id: protocol(),
                key_id: row.key_id.to_string(),
                counterparty: Some(Counterparty::Other(root_key().public_key())),
                ..Default::default()
            })
            .map(|r| r.valid);
        assert_eq!(valid, Ok(true), "key {}", row.key_id);
    }
}

#[test]
fn verify_hmac_accepts_both_encodings_of_the_six_brc56_tags() {
    // #1423's table both ways: each row's standard tag and, where the key
    // has a leading zero byte, its legacy 32-byte-key tag.
    let wallet = ProtoWallet::new(Some(root_key()));
    let mut accepted = 0;
    for row in &rows() {
        let standard = wallet.verify_hmac_encoding(args(row, tag(&row.tag)));
        assert_eq!(
            standard,
            Ok(HmacKeyEncoding::MinimalLength),
            "key {}",
            row.key_id
        );
        accepted += 1;
        if let Some(legacy) = row.legacy_tag.as_deref() {
            assert_eq!(
                verify(&wallet, row, tag(legacy)),
                Ok(true),
                "key {}",
                row.key_id
            );
            accepted += 1;
        }
    }
    assert_eq!(accepted, 10);
}

#[test]
fn a_legacy_32_byte_key_tag_is_accepted_named_and_counted() {
    let wallet = ProtoWallet::new(Some(root_key()));
    let mut named = 0;
    for row in rows().iter().filter(|r| r.leading_zero_bytes > 0) {
        let legacy = tag(row.legacy_tag.as_deref().unwrap());
        assert_eq!(
            wallet.verify_hmac_encoding(args(row, legacy)),
            Ok(HmacKeyEncoding::Legacy {
                leading_zero_bytes: row.leading_zero_bytes
            }),
            "key {}",
            row.key_id
        );
        named += 1;
        assert_eq!(
            wallet.legacy_hmac_acceptances(),
            named,
            "key {}",
            row.key_id
        );
    }
    assert_eq!(named, 4);
    // A standard tag is not counted; a clone shares the count.
    for row in &rows() {
        assert_eq!(
            verify(&wallet, row, tag(&row.tag)),
            Ok(true),
            "key {}",
            row.key_id
        );
    }
    let clone = wallet.clone();
    assert_eq!(
        verify(
            &clone,
            &rows()[1],
            tag(rows()[1].legacy_tag.as_deref().unwrap())
        ),
        Ok(true)
    );
    assert_eq!(wallet.legacy_hmac_acceptances(), 5);
}

#[test]
fn a_legacy_32_byte_key_tag_is_accepted_through_the_async_interface() {
    use bsv_rs::wallet::WalletInterface;
    let wallet = ProtoWallet::new(Some(root_key()));
    let row = &rows()[5];
    let result = futures::executor::block_on(WalletInterface::verify_hmac(
        &wallet,
        args(row, tag(row.legacy_tag.as_deref().unwrap())),
        Some("brc56.test"),
    ));
    assert!(result.unwrap().valid);
    assert_eq!(wallet.legacy_hmac_acceptances(), 1);
}

#[test]
fn the_strict_policy_refuses_a_legacy_32_byte_key_tag_by_name() {
    let wallet = strict();
    assert_eq!(
        wallet.hmac_verify_policy(),
        HmacVerifyPolicy::MinimalLengthOnly
    );
    assert_eq!(
        ProtoWallet::new(None).hmac_verify_policy(),
        HmacVerifyPolicy::BothEncodings
    );
    let mut refused = 0;
    for row in rows().iter().filter(|r| r.leading_zero_bytes > 0) {
        let legacy = tag(row.legacy_tag.as_deref().unwrap());
        let err = verify(&wallet, row, legacy).unwrap_err();
        assert_eq!(
            err,
            Error::HmacLegacyKey {
                leading_zero_bytes: row.leading_zero_bytes
            },
            "key {}",
            row.key_id
        );
        let text = err.to_string();
        assert!(text.contains("legacy 32-byte key"), "{text}");
        assert!(text.starts_with("HMAC is not valid"), "{text}");
        refused += 1;
    }
    assert_eq!(refused, 4);
    assert_eq!(wallet.legacy_hmac_acceptances(), 0);
    for row in &rows() {
        assert_eq!(
            verify(&wallet, row, tag(&row.tag)),
            Ok(true),
            "key {}",
            row.key_id
        );
    }
}

#[test]
fn the_strict_policy_refuses_by_name_through_the_async_interface() {
    use bsv_rs::wallet::WalletInterface;
    let row = &rows()[5];
    let result = futures::executor::block_on(WalletInterface::verify_hmac(
        &strict(),
        args(row, tag(row.legacy_tag.as_deref().unwrap())),
        Some("brc56.test"),
    ));
    assert_eq!(
        result.unwrap_err(),
        Error::HmacLegacyKey {
            leading_zero_bytes: 2
        }
    );
}

#[test]
fn a_key_with_no_leading_zero_has_one_encoding_and_no_refusal_path() {
    // For k0 and counterparty k0, the two encodings coincide:
    // the minimal-length key is the 32-byte key, so its tag is the accepted
    // one, named the standard key's, and there is nothing to refuse.
    for wallet in [ProtoWallet::new(Some(root_key())), strict()] {
        for row in rows().iter().filter(|r| r.leading_zero_bytes == 0) {
            assert_eq!(row.legacy_tag, None, "key {}", row.key_id);
            assert_eq!(
                wallet.verify_hmac_encoding(args(row, tag(&row.tag))),
                Ok(HmacKeyEncoding::MinimalLength),
                "key {}",
                row.key_id
            );
        }
        assert_eq!(wallet.legacy_hmac_acceptances(), 0);
    }
}

#[test]
fn a_tag_matching_neither_key_stays_hmac_is_not_valid() {
    let not_valid = Err(Error::WalletError("HMAC is not valid".to_string()));
    for wallet in [ProtoWallet::new(Some(root_key())), strict()] {
        for row in &rows() {
            for accepted in [Some(row.tag.as_str()), row.legacy_tag.as_deref()]
                .into_iter()
                .flatten()
            {
                let mut wrong = tag(accepted);
                wrong[31] ^= 1;
                assert_eq!(verify(&wallet, row, wrong), not_valid, "key {}", row.key_id);
            }
            // A row's legacy tag under another row's key is no acceptance either.
            let other =
                &rows()[(rows().iter().position(|r| r.key_id == row.key_id).unwrap() + 1) % 6];
            if let Some(legacy) = other.legacy_tag.as_deref() {
                assert_eq!(
                    verify(&wallet, row, tag(legacy)),
                    not_valid,
                    "key {}",
                    row.key_id
                );
            }
        }
        assert_eq!(wallet.legacy_hmac_acceptances(), 0);
    }
}
