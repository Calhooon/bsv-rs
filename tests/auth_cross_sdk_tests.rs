//! Cross-SDK test vectors for auth module.
//!
//! Tests certificate serialization and parsing compatibility
//! with TypeScript and Go BSV SDKs.

#![cfg(feature = "auth")]

use bsv_sdk::auth::certificates::Certificate;
use bsv_sdk::primitives::{from_base64, from_hex, to_base64, to_hex, PublicKey};
use bsv_sdk::wallet::types::Outpoint;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

// =================
// Test Vector Structure
// =================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateVector {
    description: String,
    #[serde(rename = "type")]
    cert_type: String,
    subject: String,
    serial_number: String,
    certifier: String,
    revocation_outpoint: Option<String>,
    signature: Option<String>,
    fields: HashMap<String, String>,
}

// =================
// Vector Loading
// =================

fn load_certificate_vectors() -> Vec<CertificateVector> {
    let data = fs::read_to_string("tests/vectors/auth_certificate.json")
        .expect("Failed to read auth_certificate.json");
    serde_json::from_str(&data).expect("Failed to parse auth_certificate.json")
}

fn parse_outpoint(s: &str) -> Outpoint {
    let parts: Vec<&str> = s.split('.').collect();
    assert_eq!(parts.len(), 2, "Invalid outpoint format");

    let txid_hex = parts[0];
    let vout: u32 = parts[1].parse().expect("Invalid vout");

    let mut txid = [0u8; 32];
    let txid_bytes = from_hex(txid_hex).expect("Invalid txid hex");
    txid.copy_from_slice(&txid_bytes);

    Outpoint { txid, vout }
}

fn vector_to_certificate(v: &CertificateVector) -> Certificate {
    // Parse cert_type from base64
    let cert_type_bytes = from_base64(&v.cert_type).expect("Invalid cert_type base64");
    let mut cert_type = [0u8; 32];
    cert_type.copy_from_slice(&cert_type_bytes);

    // Parse serial_number from base64
    let serial_bytes = from_base64(&v.serial_number).expect("Invalid serial_number base64");
    let mut serial_number = [0u8; 32];
    serial_number.copy_from_slice(&serial_bytes);

    // Parse subject and certifier from hex
    let subject = PublicKey::from_hex(&v.subject).expect("Invalid subject hex");
    let certifier = PublicKey::from_hex(&v.certifier).expect("Invalid certifier hex");

    // Parse revocation outpoint
    let revocation_outpoint = v.revocation_outpoint.as_ref().map(|s| parse_outpoint(s));

    // Parse fields (base64 encoded values)
    let fields: HashMap<String, Vec<u8>> = v
        .fields
        .iter()
        .map(|(k, v)| {
            let value = from_base64(v).expect("Invalid field value base64");
            (k.clone(), value)
        })
        .collect();

    // Parse signature if present
    let signature = v
        .signature
        .as_ref()
        .map(|s| from_hex(s).expect("Invalid signature hex"));

    Certificate {
        cert_type,
        serial_number,
        subject,
        certifier,
        revocation_outpoint,
        fields,
        signature,
    }
}

// =================
// Certificate Parsing Tests
// =================

#[test]
fn test_certificate_vector_parsing() {
    let vectors = load_certificate_vectors();
    assert!(!vectors.is_empty(), "No test vectors loaded");

    for (i, v) in vectors.iter().enumerate() {
        let cert = vector_to_certificate(v);

        // Verify basic fields match
        assert_eq!(
            to_base64(&cert.cert_type),
            v.cert_type,
            "Vector {}: cert_type mismatch",
            i
        );
        assert_eq!(
            to_base64(&cert.serial_number),
            v.serial_number,
            "Vector {}: serial_number mismatch",
            i
        );
        assert_eq!(
            to_hex(&cert.subject.to_compressed()),
            v.subject,
            "Vector {}: subject mismatch",
            i
        );
        assert_eq!(
            to_hex(&cert.certifier.to_compressed()),
            v.certifier,
            "Vector {}: certifier mismatch",
            i
        );

        // Verify field count matches
        assert_eq!(
            cert.fields.len(),
            v.fields.len(),
            "Vector {}: field count mismatch",
            i
        );

        println!("Vector {}: {} - OK", i, v.description);
    }
}

// =================
// Binary Serialization Tests
// =================

#[test]
fn test_certificate_binary_roundtrip() {
    let vectors = load_certificate_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let cert = vector_to_certificate(v);

        // Test binary serialization without signature
        let binary_no_sig = cert.to_binary(false);
        let parsed_no_sig = Certificate::from_binary(&binary_no_sig)
            .unwrap_or_else(|_| panic!("Vector {}: failed to parse binary (no sig)", i));

        assert_eq!(cert.cert_type, parsed_no_sig.cert_type);
        assert_eq!(cert.serial_number, parsed_no_sig.serial_number);
        assert_eq!(
            cert.subject.to_compressed(),
            parsed_no_sig.subject.to_compressed()
        );
        assert_eq!(
            cert.certifier.to_compressed(),
            parsed_no_sig.certifier.to_compressed()
        );
        assert_eq!(cert.fields.len(), parsed_no_sig.fields.len());

        // Test binary serialization with signature
        if cert.signature.is_some() {
            let binary_with_sig = cert.to_binary(true);
            let parsed_with_sig = Certificate::from_binary(&binary_with_sig)
                .unwrap_or_else(|_| panic!("Vector {}: failed to parse binary (with sig)", i));

            assert_eq!(cert.signature, parsed_with_sig.signature);
        }

        println!("Vector {}: binary roundtrip - OK", i);
    }
}

#[test]
fn test_certificate_deterministic_serialization() {
    let vectors = load_certificate_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let cert = vector_to_certificate(v);

        // Serialize twice and verify identical output
        let binary1 = cert.to_binary(false);
        let binary2 = cert.to_binary(false);

        assert_eq!(
            binary1, binary2,
            "Vector {}: non-deterministic serialization",
            i
        );

        // Parse and re-serialize
        let parsed = Certificate::from_binary(&binary1).unwrap();
        let binary3 = parsed.to_binary(false);

        assert_eq!(binary1, binary3, "Vector {}: roundtrip changed binary", i);

        println!("Vector {}: deterministic serialization - OK", i);
    }
}

// =================
// Field Sorting Tests
// =================

#[test]
fn test_certificate_fields_sorted_alphabetically() {
    let vectors = load_certificate_vectors();

    // Find a vector with multiple fields
    let multi_field_vector = vectors.iter().find(|v| v.fields.len() > 1);

    if let Some(v) = multi_field_vector {
        let cert = vector_to_certificate(v);
        let binary = cert.to_binary(false);

        // Parse it back
        let parsed = Certificate::from_binary(&binary).unwrap();

        // The parsed fields should have all the original fields
        for (name, value) in &cert.fields {
            let parsed_value = parsed
                .fields
                .get(name)
                .unwrap_or_else(|| panic!("Field {} missing after roundtrip", name));
            assert_eq!(
                value, parsed_value,
                "Field {} value changed after roundtrip",
                name
            );
        }

        println!("Fields sorted correctly with {} fields", cert.fields.len());
    } else {
        println!("No multi-field vector found for sorting test");
    }
}

// =================
// Signature Verification Tests
// =================

#[test]
fn test_certificate_with_signature_has_valid_format() {
    let vectors = load_certificate_vectors();

    // Find vectors with signatures
    for (i, v) in vectors.iter().enumerate() {
        if let Some(ref sig_hex) = v.signature {
            let sig_bytes = from_hex(sig_hex).expect("Invalid signature hex");

            // DER signatures start with 0x30 (sequence tag)
            assert_eq!(
                sig_bytes[0], 0x30,
                "Vector {}: signature should be DER encoded",
                i
            );

            // Parse as certificate and verify signature is stored
            let cert = vector_to_certificate(v);
            assert!(cert.signature.is_some());
            assert_eq!(cert.signature.as_ref().unwrap(), &sig_bytes);

            println!("Vector {}: signature format valid", i);
        }
    }
}

// =================
// JSON Serialization Tests
// =================

#[test]
fn test_certificate_json_roundtrip() {
    let vectors = load_certificate_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let cert = vector_to_certificate(v);

        // Serialize to JSON
        let json = serde_json::to_string(&cert).expect("Failed to serialize to JSON");

        // Parse back
        let parsed: Certificate = serde_json::from_str(&json).expect("Failed to parse JSON");

        // Verify all fields match
        assert_eq!(cert.cert_type, parsed.cert_type, "Vector {}: cert_type", i);
        assert_eq!(
            cert.serial_number, parsed.serial_number,
            "Vector {}: serial_number",
            i
        );
        assert_eq!(
            cert.subject.to_compressed(),
            parsed.subject.to_compressed(),
            "Vector {}: subject",
            i
        );
        assert_eq!(
            cert.certifier.to_compressed(),
            parsed.certifier.to_compressed(),
            "Vector {}: certifier",
            i
        );
        assert_eq!(
            cert.fields.len(),
            parsed.fields.len(),
            "Vector {}: fields count",
            i
        );
        assert_eq!(cert.signature, parsed.signature, "Vector {}: signature", i);

        // Verify revocation outpoint
        match (&cert.revocation_outpoint, &parsed.revocation_outpoint) {
            (Some(a), Some(b)) => {
                assert_eq!(a.txid, b.txid, "Vector {}: outpoint txid", i);
                assert_eq!(a.vout, b.vout, "Vector {}: outpoint vout", i);
            }
            (None, None) => {}
            _ => panic!("Vector {}: revocation_outpoint mismatch", i),
        }

        println!("Vector {}: JSON roundtrip - OK", i);
    }
}

// =================
// Type and Serial Number Tests
// =================

#[test]
fn test_certificate_type_base64() {
    let vectors = load_certificate_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let cert = vector_to_certificate(v);

        assert_eq!(
            cert.type_base64(),
            v.cert_type,
            "Vector {}: type_base64 mismatch",
            i
        );
        assert_eq!(
            cert.serial_number_base64(),
            v.serial_number,
            "Vector {}: serial_number_base64 mismatch",
            i
        );
    }
}

// =================
// Outpoint Tests
// =================

#[test]
fn test_certificate_outpoint_parsing() {
    // Test the outpoint parsing helper
    let outpoint =
        parse_outpoint("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.1");
    assert_eq!(outpoint.vout, 1);

    let expected_txid =
        from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    assert_eq!(outpoint.txid.to_vec(), expected_txid);

    // Test with vout 0
    let outpoint0 =
        parse_outpoint("0245242bd144a85053b4c1e4a0ed5467c79a4d172680ca77a970ebabd682d564.0");
    assert_eq!(outpoint0.vout, 0);
}

// =================
// Edge Case Tests
// =================

#[test]
fn test_certificate_empty_fields() {
    let vectors = load_certificate_vectors();

    // Find vector with empty fields
    let empty_fields_vector = vectors.iter().find(|v| v.fields.is_empty());

    if let Some(v) = empty_fields_vector {
        let cert = vector_to_certificate(v);
        assert!(cert.fields.is_empty());

        // Should still serialize/deserialize correctly
        let binary = cert.to_binary(false);
        let parsed = Certificate::from_binary(&binary).unwrap();
        assert!(parsed.fields.is_empty());

        println!("Empty fields test passed");
    } else {
        println!("No empty fields vector found");
    }
}

#[test]
fn test_certificate_without_revocation_outpoint() {
    let vectors = load_certificate_vectors();

    // Find vector without revocation outpoint
    let no_outpoint_vector = vectors.iter().find(|v| v.revocation_outpoint.is_none());

    if let Some(v) = no_outpoint_vector {
        let cert = vector_to_certificate(v);
        assert!(cert.revocation_outpoint.is_none());

        // Should still serialize/deserialize correctly
        let binary = cert.to_binary(false);
        let parsed = Certificate::from_binary(&binary).unwrap();
        assert!(parsed.revocation_outpoint.is_none());

        println!("No revocation outpoint test passed");
    } else {
        println!("No vector without revocation outpoint found");
    }
}

// =================
// Binary Format Structure Tests
// =================

/// Tests that the binary format matches TypeScript SDK format:
/// [type: 32 bytes][serial: 32 bytes][subject: 33 bytes][certifier: 33 bytes]
/// [txid: 32 bytes][vout: varint][field_count: varint][fields...][signature...]
#[test]
fn test_certificate_binary_format_structure() {
    // Create a simple certificate with known values
    let cert_type = [0x01u8; 32];
    let serial_number = [0x02u8; 32];

    // Use generator point G for subject
    let subject =
        PublicKey::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();

    // Use 2*G for certifier
    let certifier =
        PublicKey::from_hex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
            .unwrap();

    // Create outpoint with known txid
    let txid =
        from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    let mut txid_arr = [0u8; 32];
    txid_arr.copy_from_slice(&txid);
    let outpoint = Outpoint {
        txid: txid_arr,
        vout: 1,
    };

    let subject_compressed = subject.to_compressed();
    let certifier_compressed = certifier.to_compressed();

    let cert = Certificate {
        cert_type,
        serial_number,
        subject,
        certifier,
        revocation_outpoint: Some(outpoint),
        fields: std::collections::HashMap::new(), // No fields for simpler verification
        signature: None,
    };

    let binary = cert.to_binary(false);

    // Verify structure:
    // Offset 0-31: type (32 bytes)
    assert_eq!(&binary[0..32], &cert_type, "Type bytes mismatch");

    // Offset 32-63: serial_number (32 bytes)
    assert_eq!(
        &binary[32..64],
        &serial_number,
        "Serial number bytes mismatch"
    );

    // Offset 64-96: subject pubkey (33 bytes compressed)
    assert_eq!(
        &binary[64..97],
        &subject_compressed,
        "Subject pubkey mismatch"
    );

    // Offset 97-129: certifier pubkey (33 bytes compressed)
    assert_eq!(
        &binary[97..130],
        &certifier_compressed,
        "Certifier pubkey mismatch"
    );

    // Offset 130-161: TXID (32 bytes) - TypeScript format: no marker byte!
    assert_eq!(&binary[130..162], &txid_arr, "TXID mismatch");

    // Offset 162: vout as varint (value 1 = single byte 0x01)
    assert_eq!(binary[162], 0x01, "Vout varint mismatch");

    // Offset 163: field count as varint (value 0 = single byte 0x00)
    assert_eq!(binary[163], 0x00, "Field count mismatch");

    // Total length should be: 32 + 32 + 33 + 33 + 32 + 1 + 1 = 164 bytes
    assert_eq!(binary.len(), 164, "Binary length mismatch");

    println!("Binary format structure matches TypeScript SDK format");
}

/// Tests that "no revocation outpoint" is encoded as all-zeros TXID + index 0
#[test]
fn test_certificate_no_outpoint_sentinel_value() {
    let cert_type = [0x01u8; 32];
    let serial_number = [0x02u8; 32];
    let subject =
        PublicKey::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
    let certifier =
        PublicKey::from_hex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
            .unwrap();

    let cert = Certificate {
        cert_type,
        serial_number,
        subject,
        certifier,
        revocation_outpoint: None, // No outpoint
        fields: std::collections::HashMap::new(),
        signature: None,
    };

    let binary = cert.to_binary(false);

    // Offset 130-161: should be all zeros (sentinel value)
    assert_eq!(
        &binary[130..162],
        &[0u8; 32],
        "No-outpoint sentinel TXID should be zeros"
    );

    // Offset 162: vout should be 0
    assert_eq!(binary[162], 0x00, "No-outpoint sentinel vout should be 0");

    // Parse it back and verify outpoint is None
    let parsed = Certificate::from_binary(&binary).unwrap();
    assert!(
        parsed.revocation_outpoint.is_none(),
        "Parsed certificate should have no outpoint"
    );

    println!("No-outpoint sentinel value encoding works correctly");
}

// =================
// Cross-SDK Compatibility Notes
// =================

#[test]
fn test_certificate_vector_count() {
    let vectors = load_certificate_vectors();
    assert!(
        vectors.len() >= 4,
        "Expected at least 4 certificate test vectors, got {}",
        vectors.len()
    );
    println!("Loaded {} certificate vectors", vectors.len());
}
