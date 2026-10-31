//! The result validator's keys stay strict under #498's `from_hex`:
//! `isValidCompressedPublicKey` refuses an x at or above p
//! (`Secp256k1Validation.ts:15-22`, `WalletResultValidation.ts:928-933` at
//! `ts-stack@edf6e03`), where `PublicKey.fromString` reduces it.
#![cfg(test)]

use super::{certificate, scalars};
use crate::primitives::{PrivateKey, PublicKey};
use serde_json::value::RawValue;

const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// p + 1: x = 1 once reduced, a point of the curve.
const X_ABOVE_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";

fn raw(text: String) -> Box<RawValue> {
    RawValue::from_string(text).unwrap()
}

#[test]
fn a_result_key_with_x_above_p_is_refused_though_from_hex_reads_it_498() {
    let above = format!("02{X_ABOVE_P}");
    assert!(PublicKey::from_hex(&above).is_ok());
    let refused = scalars::key(
        Some(&raw(format!("\"{above}\""))),
        "getPublicKey",
        "publicKey",
    );
    assert_eq!(
        refused.unwrap_err().to_string(),
        "wallet error: Invalid getPublicKey result publicKey: expected a valid compressed secp256k1 public key"
    );
    let accepted = scalars::key(
        Some(&raw(format!("\"02{GX}\""))),
        "getPublicKey",
        "publicKey",
    );
    assert_eq!(accepted.unwrap(), format!("02{GX}"));
}

#[test]
fn a_certificate_subject_with_x_above_p_is_refused_498() {
    let signature = PrivateKey::from_hex(&"11".repeat(32))
        .unwrap()
        .sign(&[7; 32])
        .unwrap()
        .to_der();
    let certificate = |subject: &str| {
        raw(format!(
            r#"{{"type":"{t}","serialNumber":"{t}","subject":"{subject}","certifier":"02{GX}","revocationOutpoint":"{z}.0","signature":"{s}","fields":{{}}}}"#,
            t = "A".repeat(43) + "=",
            z = "0".repeat(64),
            s = crate::primitives::to_hex(&signature),
        ))
    };
    let call = ("acquireCertificate", "certificate");
    assert!(certificate::validate(Some(&certificate(&format!("02{GX}"))), call.0, call.1).is_ok());
    let refused = certificate::validate(
        Some(&certificate(&format!("02{X_ABOVE_P}"))),
        call.0,
        call.1,
    );
    assert!(refused.is_err());
}
