#![cfg(test)]
//! The identity parsers' subject and certifier read as the reference's
//! `Certificate.toBinary` reads them (#585; `ts-stack@edf6e03`
//! `Certificate.ts:240-254`, run first by `verify`, `:425-427`), against
//! `tests/vectors/certificate_to_binary_key_585.json`: a certificate the
//! certifier 31 signed for the subject 37, published with its subject or
//! certifier in one of eight texts, read by each parser exactly when the
//! reference's `verify` answers `true` for that text.

use super::*;
use crate::auth::certificates::read_to_binary_key;

fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../tests/vectors/certificate_to_binary_key_585.json"
    ))
    .unwrap()
}

fn scalar(n: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    PrivateKey::from_bytes(&bytes).unwrap()
}

/// The vector's certificate signed here, its signature the reference's
/// (RFC 6979 on both sides), as published JSON with one keyring entry.
fn signed_json(v: &serde_json::Value) -> serde_json::Value {
    let mut cert = Certificate::new(
        [6; 32],
        [7; 32],
        scalar(37).public_key(),
        scalar(31).public_key(),
    );
    cert.revocation_outpoint =
        Some(Outpoint::from_string(v["revocation_outpoint"].as_str().unwrap()).unwrap());
    cert.set_field("name", v["fields"]["name"].as_str().unwrap());
    cert.sign(&scalar(31)).unwrap();
    let mut json = serde_json::to_value(&cert).unwrap();
    for member in ["type", "serialNumber", "subject", "certifier", "signature"] {
        let key = if member == "serialNumber" {
            "serial_number"
        } else {
            member
        };
        assert_eq!(
            json[member], v[key],
            "{member}: not the reference's certificate"
        );
    }
    json["keyring"] = serde_json::json!({ "name": "QWxpY2U=" });
    json
}

/// Each case's token, with the reference's `verify` verdict on its text.
fn cases() -> Vec<(String, OutputListItem, bool)> {
    let v = vector();
    let json = signed_json(&v);
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let field = case["field"].as_str().unwrap();
            let mut published = json.clone();
            published[field] = case["text"].clone();
            let label = format!("{field} {}", case["name"].as_str().unwrap());
            (
                label,
                publish_by(&published, &scalar(37)),
                case["verify"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn an_uncompressed_published_key_is_skipped_by_the_certificate_parser_585() {
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    for (label, output, verified) in cases() {
        let read = client.parse_output_to_certificate(&output).await.unwrap();
        assert_eq!(read.is_some(), verified, "{label}");
    }
}

#[tokio::test]
async fn an_uncompressed_published_key_is_skipped_by_the_verifiable_certificate_parser_585() {
    let client = IdentityClient::new(ProtoWallet::new(None), Default::default());
    for (label, output, verified) in cases() {
        let read = client
            .parse_output_to_verifiable_certificate(&output)
            .await
            .unwrap();
        assert_eq!(read.is_some(), verified, "{label}");
    }
}

/// The reader's words are `toBinary`'s; one case it refuses where `toBinary`
/// writes the bytes (#183's refusal; `verify` is `false` on both sides for
/// this certificate, signed over the canonical subject).
const REFUSED_HERE: [&str; 1] = ["x_above_p"];

#[test]
fn the_reader_refuses_in_the_reference_to_binary_words_585() {
    let v = vector();
    for case in v["cases"].as_array().unwrap() {
        let (field, name) = (
            case["field"].as_str().unwrap(),
            case["name"].as_str().unwrap(),
        );
        let read = read_to_binary_key(case["text"].as_str().unwrap(), field);
        let to_binary = &case["to_binary"];
        if REFUSED_HERE.contains(&name) {
            assert!(
                to_binary["ok"].as_bool().unwrap() && read.is_err(),
                "{field} {name}"
            );
        } else if to_binary["ok"].as_bool().unwrap() {
            assert_eq!(
                read.unwrap().to_hex(),
                to_binary["key"].as_str().unwrap(),
                "{field} {name}"
            );
        } else {
            let message = to_binary["message"].as_str().unwrap();
            assert_eq!(
                read,
                Err(crate::Error::CertificateValidationError(message.into())),
                "{field} {name}"
            );
        }
    }
}
