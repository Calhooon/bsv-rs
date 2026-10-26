#![cfg(test)]
//! The unit tests of `certificate.rs`, in their own file (the file-size ratchet).

use super::*;

#[test]
fn test_sign_and_verify() {
    let certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();

    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());

    cert.sign(&certifier).unwrap();
    assert!(cert.verify().unwrap());
}

#[test]
fn test_wrong_certifier_rejected() {
    let certifier = PrivateKey::random();
    let wrong_certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();

    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());

    // Trying to sign with wrong key should fail
    assert!(cert.sign(&wrong_certifier).is_err());
}

#[test]
fn test_binary_roundtrip() {
    let certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();

    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
    cert.set_field("name", "encrypted_value");
    cert.sign(&certifier).unwrap();

    let binary = cert.to_binary(true);
    let parsed = Certificate::from_binary(&binary).unwrap();

    assert_eq!(cert.cert_type, parsed.cert_type);
    assert_eq!(cert.serial_number, parsed.serial_number);
    assert_eq!(cert.subject, parsed.subject);
    assert_eq!(cert.certifier, parsed.certifier);
    assert_eq!(cert.fields, parsed.fields);
    assert!(parsed.verify().unwrap());
}

#[test]
fn test_binary_with_revocation_outpoint() {
    let certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();

    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
    cert.revocation_outpoint = Some(Outpoint::new([3u8; 32], 5));
    cert.sign(&certifier).unwrap();

    let binary = cert.to_binary(true);
    let parsed = Certificate::from_binary(&binary).unwrap();

    assert!(parsed.revocation_outpoint.is_some());
    let outpoint = parsed.revocation_outpoint.unwrap();
    assert_eq!(outpoint.txid, [3u8; 32]);
    assert_eq!(outpoint.vout, 5);
}

#[test]
fn test_json_roundtrip() {
    let certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();

    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
    cert.set_field("name", "encrypted_value");
    cert.sign(&certifier).unwrap();

    let json = serde_json::to_string(&cert).unwrap();
    let parsed: Certificate = serde_json::from_str(&json).unwrap();

    assert_eq!(cert.cert_type, parsed.cert_type);
    assert_eq!(cert.serial_number, parsed.serial_number);
    assert!(parsed.verify().unwrap());
}

#[test]
fn test_field_encryption_key_ids() {
    let serial = [42u8; 32];

    let master_key_id = Certificate::get_field_encryption_key_id_master("email");
    assert_eq!(master_key_id, "email");

    let verifiable_key_id = Certificate::get_field_encryption_key_id_verifiable("email", &serial);
    assert!(verifiable_key_id.contains("email"));
    assert!(verifiable_key_id.contains(&crate::primitives::to_base64(&serial)));
}

#[test]
fn a_revocation_outpoint_index_above_u32_max_is_refused_not_truncated_in_the_bound_refusals_form() {
    let certifier = PrivateKey::random();
    let subject = PrivateKey::random().public_key();
    let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
    cert.revocation_outpoint = Some(Outpoint::new([3u8; 32], u32::MAX));
    cert.sign(&certifier).unwrap();
    let binary = cert.to_binary(true);

    let parsed = Certificate::from_binary(&binary).unwrap();
    assert_eq!(
        parsed.revocation_outpoint,
        Some(Outpoint::new([3u8; 32], u32::MAX))
    );
    assert!(parsed.verify().unwrap());

    // type(32) serial(32) subject(33) certifier(33) txid(32), then the index
    let at = 32 + 32 + 33 + 33 + 32;
    let mut max = Vec::new();
    write_varint(&mut max, u32::MAX as u64);
    assert_eq!(&binary[at..at + 5], &max[..]);
    let mut over = binary[..at].to_vec();
    write_varint(&mut over, u32::MAX as u64 + 1);
    over.extend_from_slice(&binary[at + 5..]);

    let err = Certificate::from_binary(&over).unwrap_err();
    assert_eq!(
        err,
        Error::CertificateValidationError(
            "Invalid revocation outpoint index: expected an integer from 0 to 4294967295, received 4294967296"
                .to_string()
        )
    );
}
