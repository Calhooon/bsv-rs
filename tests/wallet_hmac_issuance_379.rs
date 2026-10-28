//! Issuance and naming regressions that also compile on the rebased #389
//! base, allowing an actual behavioral RED run rather than a missing-API error.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{from_hex, to_hex, PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, ProtoWallet, Protocol, SecurityLevel, VerifyHmacArgs,
    WalletInterface,
};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/wallet_hmac_key_379.json")).unwrap()
}

fn wallet() -> ProtoWallet {
    ProtoWallet::new(Some(
        PrivateKey::from_hex(vectors()["rootKey"].as_str().unwrap()).unwrap(),
    ))
}

fn args(row: &Value, tag: &str) -> VerifyHmacArgs {
    VerifyHmacArgs {
        protocol_id: Protocol::new(SecurityLevel::Counterparty, "hmac key vectors"),
        key_id: row["keyID"].as_str().unwrap().into(),
        counterparty: Some(if row["counterparty"] == "self" {
            Counterparty::Self_
        } else {
            Counterparty::Other(PublicKey::from_hex(row["counterparty"].as_str().unwrap()).unwrap())
        }),
        data: from_hex(vectors()["data"].as_str().unwrap()).unwrap(),
        hmac: from_hex(tag).unwrap().try_into().unwrap(),
        ..Default::default()
    }
}

#[test]
fn minimal_length_tags_are_named_as_the_standard() {
    for row in vectors()["vectors"].as_array().unwrap() {
        let result = wallet()
            .verify_hmac_encoding(args(row, row["hmac"].as_str().unwrap()))
            .unwrap();
        assert_eq!(format!("{result:?}"), "MinimalLength", "{}", row["keyID"]);
    }
}

#[test]
fn padded_key_tags_are_named_as_legacy() {
    for row in vectors()["vectors"].as_array().unwrap() {
        if let Some(tag) = row["rejectedTag"].as_str() {
            let result = wallet().verify_hmac_encoding(args(row, tag)).unwrap();
            assert_eq!(
                format!("{result:?}"),
                format!(
                    "Legacy {{ leading_zero_bytes: {} }}",
                    row["leadingZeroBytes"]
                )
            );
        }
    }
}

#[test]
fn an_issued_certificate_hmac_matches_the_reference_verifier() {
    let v: Value =
        serde_json::from_str(include_str!("vectors/auth_hmac_issuance_379.json")).unwrap();
    let result = wallet()
        .create_hmac(CreateHmacArgs {
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "hmac key vectors"),
            key_id: "k95".into(),
            counterparty: Some(Counterparty::Self_),
            data: from_hex(v["binaryHex"].as_str().unwrap()).unwrap(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(to_hex(&result.hmac), v["hmac"].as_str().unwrap());
    assert_eq!(v["referenceHmacValid"], true);
}

#[test]
fn the_async_issuer_uses_the_six_minimal_length_keys() {
    for row in vectors()["vectors"].as_array().unwrap() {
        let a = args(row, row["hmac"].as_str().unwrap());
        let result = futures::executor::block_on(WalletInterface::create_hmac(
            &wallet(),
            CreateHmacArgs {
                protocol_id: a.protocol_id,
                key_id: a.key_id,
                counterparty: a.counterparty,
                data: a.data,
                ..Default::default()
            },
            None,
        ))
        .unwrap();
        assert_eq!(to_hex(&result.hmac), row["hmac"].as_str().unwrap());
    }
}
