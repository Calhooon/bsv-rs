//! Cross-SDK Wire Protocol Tests
//!
//! These tests validate that the Rust BSV SDK wire protocol is byte-for-byte
//! compatible with the Go SDK. Each test loads a JSON vector from
//! `tests/vectors/wallet_wire/` (from go-sdk/wallet/substrates/testdata/)
//! containing:
//!   - `json`: The structured arguments or result
//!   - `wire`: The canonical hex encoding
//!
//! Request wire format: call_code(1) + originator_len(1, always 0) + params
//! Response wire format: error_byte(1, always 0x00) + result_data
//!
//! Strategy: We use the Rust SDK's WalletWireProcessor to process Go-encoded
//! request messages, and verify that Rust can decode Go-encoded response data.
//! This proves cross-SDK interoperability at the byte level.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "wallet")]

use serde_json::Value;

/// Load a vector file and return (json_value, wire_bytes).
fn load_vector(filename: &str) -> (Value, Vec<u8>) {
    let path = format!(
        "{}/tests/vectors/wallet_wire/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let content =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
    let parsed: Value = serde_json::from_str(&content).unwrap();
    let wire_hex = parsed["wire"].as_str().unwrap();
    let wire_bytes = hex::decode(wire_hex).unwrap();
    (parsed["json"].clone(), wire_bytes)
}

/// Extract params from request frame (after call_code + originator).
fn extract_params(wire: &[u8]) -> &[u8] {
    assert!(wire.len() >= 2);
    let orig_len = wire[1] as usize;
    &wire[2 + orig_len..]
}

/// Extract result data from response frame (after error byte).
fn extract_result(wire: &[u8]) -> &[u8] {
    assert!(!wire.is_empty());
    assert_eq!(wire[0], 0x00, "expected success error byte");
    &wire[1..]
}

fn json_to_bytes(val: &Value) -> Vec<u8> {
    val.as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect()
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

use bsv_rs::wallet::wire::{WireReader, WireWriter};

// ============================================================================
// Call code verification
// ============================================================================

#[test]
fn test_all_call_codes_match_go_sdk() {
    use bsv_rs::wallet::wire::WalletCall;

    let expected: Vec<(u8, &str)> = vec![
        (1, "createAction"),
        (2, "signAction"),
        (3, "abortAction"),
        (4, "listActions"),
        (5, "internalizeAction"),
        (6, "listOutputs"),
        (7, "relinquishOutput"),
        (8, "getPublicKey"),
        (9, "revealCounterpartyKeyLinkage"),
        (10, "revealSpecificKeyLinkage"),
        (11, "encrypt"),
        (12, "decrypt"),
        (13, "createHmac"),
        (14, "verifyHmac"),
        (15, "createSignature"),
        (16, "verifySignature"),
        (17, "acquireCertificate"),
        (18, "listCertificates"),
        (19, "proveCertificate"),
        (20, "relinquishCertificate"),
        (21, "discoverByIdentityKey"),
        (22, "discoverByAttributes"),
        (23, "isAuthenticated"),
        (24, "waitForAuthentication"),
        (25, "getHeight"),
        (26, "getHeaderForHeight"),
        (27, "getNetwork"),
        (28, "getVersion"),
    ];

    for (code, name) in &expected {
        let call = WalletCall::try_from(*code).unwrap();
        assert_eq!(call.method_name(), *name, "call code {} mismatch", code);
    }
}

#[test]
fn test_all_request_call_codes() {
    let vectors: Vec<(&str, u8)> = vec![
        ("createAction-1-out-args.json", 1),
        ("signAction-simple-args.json", 2),
        ("abortAction-simple-args.json", 3),
        ("listActions-simple-args.json", 4),
        ("internalizeAction-simple-args.json", 5),
        ("listOutputs-simple-args.json", 6),
        ("relinquishOutput-simple-args.json", 7),
        ("getPublicKey-simple-args.json", 8),
        ("revealCounterpartyKeyLinkage-simple-args.json", 9),
        ("revealSpecificKeyLinkage-simple-args.json", 10),
        ("encrypt-simple-args.json", 11),
        ("decrypt-simple-args.json", 12),
        ("createHmac-simple-args.json", 13),
        ("verifyHmac-simple-args.json", 14),
        ("createSignature-simple-args.json", 15),
        ("verifySignature-simple-args.json", 16),
        ("acquireCertificate-simple-args.json", 17),
        ("acquireCertificate-issuance-args.json", 17),
        ("listCertificates-simple-args.json", 18),
        ("proveCertificate-simple-args.json", 19),
        ("relinquishCertificate-simple-args.json", 20),
        ("discoverByIdentityKey-simple-args.json", 21),
        ("discoverByAttributes-simple-args.json", 22),
        ("isAuthenticated-simple-args.json", 23),
        ("waitForAuthentication-simple-args.json", 24),
        ("getHeight-simple-args.json", 25),
        ("getHeaderForHeight-simple-args.json", 26),
    ];

    for (filename, expected_code) in &vectors {
        let (_, wire) = load_vector(filename);
        assert_eq!(wire[0], *expected_code, "wrong call code in {}", filename);
    }
}

#[test]
fn test_all_response_success_byte() {
    let result_files = vec![
        "createSignature-simple-result.json",
        "encrypt-simple-result.json",
        "decrypt-simple-result.json",
        "createHmac-simple-result.json",
        "verifyHmac-simple-result.json",
        "verifySignature-simple-result.json",
        "getPublicKey-simple-result.json",
        "getHeight-simple-result.json",
        "getHeaderForHeight-simple-result.json",
        "getNetwork-simple-result.json",
        "getVersion-simple-result.json",
        "isAuthenticated-simple-result.json",
        "waitForAuthentication-simple-result.json",
        "abortAction-simple-result.json",
        "listActions-simple-result.json",
        "listOutputs-simple-result.json",
        "listCertificates-simple-result.json",
        "listCertificates-full-result.json",
        "acquireCertificate-simple-result.json",
        "proveCertificate-simple-result.json",
        "relinquishCertificate-simple-result.json",
        "relinquishOutput-simple-result.json",
        "revealCounterpartyKeyLinkage-simple-result.json",
        "revealSpecificKeyLinkage-simple-result.json",
        "discoverByAttributes-simple-result.json",
        "discoverByIdentityKey-simple-result.json",
        "internalizeAction-simple-result.json",
    ];

    for filename in &result_files {
        let (_, wire) = load_vector(filename);
        assert_eq!(wire[0], 0x00, "expected success byte in {}", filename);
    }
}

// ============================================================================
// getPublicKey (call code 8)
// ============================================================================

#[test]
fn test_get_public_key_result_cross_sdk() {
    let (json, wire) = load_vector("getPublicKey-simple-result.json");
    let result_data = extract_result(&wire);
    let pubkey_hex = json["publicKey"].as_str().unwrap();
    let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
    assert_eq!(result_data, pubkey_bytes.as_slice());
}

// ============================================================================
// createSignature (call code 15) / result
// ============================================================================

#[test]
fn test_create_signature_result_cross_sdk() {
    let (json, wire) = load_vector("createSignature-simple-result.json");
    let result_data = extract_result(&wire);
    let sig_bytes = json_to_bytes(&json["signature"]);

    // Go encodes signature as raw bytes (no length prefix in result)
    assert_eq!(result_data, sig_bytes.as_slice());
}

// ============================================================================
// encrypt (call code 11) / result
// ============================================================================

#[test]
fn test_encrypt_result_cross_sdk() {
    let (json, wire) = load_vector("encrypt-simple-result.json");
    let result_data = extract_result(&wire);
    let ciphertext = json_to_bytes(&json["ciphertext"]);
    // Go encodes ciphertext as raw bytes (no length prefix in result)
    assert_eq!(result_data, ciphertext.as_slice());
}

// ============================================================================
// decrypt (call code 12) / result
// ============================================================================

#[test]
fn test_decrypt_result_cross_sdk() {
    let (json, wire) = load_vector("decrypt-simple-result.json");
    let result_data = extract_result(&wire);
    let plaintext = json_to_bytes(&json["plaintext"]);
    assert_eq!(result_data, plaintext.as_slice());
}

// ============================================================================
// createHmac (call code 13) / result
// ============================================================================

#[test]
fn test_create_hmac_result_cross_sdk() {
    let (json, wire) = load_vector("createHmac-simple-result.json");
    let result_data = extract_result(&wire);
    let hmac = json_to_bytes(&json["hmac"]);
    // Go encodes HMAC as raw 32 bytes (no length prefix)
    assert_eq!(result_data, hmac.as_slice());
}

// ============================================================================
// verifyHmac (call code 14) / result
// ============================================================================

#[test]
fn test_verify_hmac_result_cross_sdk() {
    let (_json, wire) = load_vector("verifyHmac-simple-result.json");
    let result_data = extract_result(&wire);
    // valid=true → empty result
    assert!(result_data.is_empty());
}

// ============================================================================
// verifySignature (call code 16) / result
// ============================================================================

#[test]
fn test_verify_signature_result_cross_sdk() {
    let (_json, wire) = load_vector("verifySignature-simple-result.json");
    let result_data = extract_result(&wire);
    assert!(result_data.is_empty());
}

// ============================================================================
// getHeight (call code 25)
// ============================================================================

#[test]
fn test_get_height_args_cross_sdk() {
    let (_json, wire) = load_vector("getHeight-simple-args.json");
    assert_eq!(wire[0], 25);
    let params = extract_params(&wire);
    assert!(params.is_empty());
}

#[test]
fn test_get_height_result_cross_sdk() {
    let (json, wire) = load_vector("getHeight-simple-result.json");
    let result_data = extract_result(&wire);
    let height = json["height"].as_u64().unwrap();

    let mut reader = WireReader::new(result_data);
    let decoded = reader.read_var_int().unwrap();
    assert_eq!(decoded, height);

    // Verify serialization
    let mut writer = WireWriter::new();
    writer.write_var_int(height);
    assert_eq!(writer.as_bytes(), result_data);
}

// ============================================================================
// getHeaderForHeight (call code 26)
// ============================================================================

#[test]
fn test_get_header_for_height_args_cross_sdk() {
    let (json, wire) = load_vector("getHeaderForHeight-simple-args.json");
    let params = extract_params(&wire);
    assert_eq!(wire[0], 26);

    let height = json["height"].as_u64().unwrap();
    let mut writer = WireWriter::new();
    writer.write_var_int(height);
    assert_eq!(writer.as_bytes(), params);
}

#[test]
fn test_get_header_for_height_result_cross_sdk() {
    let (json, wire) = load_vector("getHeaderForHeight-simple-result.json");
    let result_data = extract_result(&wire);
    let header_hex = json["header"].as_str().unwrap();
    let header_bytes = hex::decode(header_hex).unwrap();
    // 80-byte raw block header
    assert_eq!(result_data, header_bytes.as_slice());
    assert_eq!(result_data.len(), 80);
}

// ============================================================================
// getNetwork (call code 27) - result only
// ============================================================================

#[test]
fn test_get_network_result_cross_sdk() {
    let (json, wire) = load_vector("getNetwork-simple-result.json");
    let result_data = extract_result(&wire);
    let network = json["network"].as_str().unwrap();
    assert_eq!(network, "mainnet");
    // Go encodes mainnet as byte 0x00
    assert_eq!(result_data.len(), 1);
    assert_eq!(result_data[0], 0x00);
}

// ============================================================================
// getVersion (call code 28) - result only
// ============================================================================

#[test]
fn test_get_version_result_cross_sdk() {
    let (json, wire) = load_vector("getVersion-simple-result.json");
    let result_data = extract_result(&wire);
    let version = json["version"].as_str().unwrap();

    // Go encodes version as raw UTF-8 bytes (no length prefix)
    let decoded = std::str::from_utf8(result_data).unwrap();
    assert_eq!(decoded, version);

    let mut writer = WireWriter::new();
    writer.write_bytes(version.as_bytes());
    assert_eq!(writer.as_bytes(), result_data);
}

// ============================================================================
// isAuthenticated (call code 23)
// ============================================================================

#[test]
fn test_is_authenticated_args_cross_sdk() {
    let (_json, wire) = load_vector("isAuthenticated-simple-args.json");
    assert_eq!(wire[0], 23);
    assert!(extract_params(&wire).is_empty());
}

#[test]
fn test_is_authenticated_result_cross_sdk() {
    let (json, wire) = load_vector("isAuthenticated-simple-result.json");
    let result_data = extract_result(&wire);
    assert!(json["authenticated"].as_bool().unwrap());
    // authenticated=true → i8(1)
    assert_eq!(result_data, &[0x01]);
}

// ============================================================================
// waitForAuthentication (call code 24)
// ============================================================================

#[test]
fn test_wait_for_authentication_args_cross_sdk() {
    let (_json, wire) = load_vector("waitForAuthentication-simple-args.json");
    assert_eq!(wire[0], 24);
    assert!(extract_params(&wire).is_empty());
}

#[test]
fn test_wait_for_authentication_result_cross_sdk() {
    let (_json, wire) = load_vector("waitForAuthentication-simple-result.json");
    let result_data = extract_result(&wire);
    assert!(result_data.is_empty());
}

// ============================================================================
// abortAction (call code 3)
// ============================================================================

#[test]
fn test_abort_action_args_cross_sdk() {
    let (json, wire) = load_vector("abortAction-simple-args.json");
    let params = extract_params(&wire);
    assert_eq!(wire[0], 3);
    let reference_b64 = json["reference"].as_str().unwrap();
    let reference_bytes = base64_decode(reference_b64);
    assert_eq!(params, reference_bytes.as_slice());
}

#[test]
fn test_abort_action_result_cross_sdk() {
    let (_json, wire) = load_vector("abortAction-simple-result.json");
    assert!(extract_result(&wire).is_empty());
}

// ============================================================================
// relinquishOutput (call code 7)
// ============================================================================

#[test]
fn test_relinquish_output_args_cross_sdk() {
    let (json, wire) = load_vector("relinquishOutput-simple-args.json");
    let params = extract_params(&wire);
    assert_eq!(wire[0], 7);

    let mut writer = WireWriter::new();
    writer.write_string(json["basket"].as_str().unwrap());
    writer
        .write_outpoint_string(json["output"].as_str().unwrap())
        .unwrap();
    assert_eq!(writer.as_bytes(), params);
}

#[test]
fn test_relinquish_output_result_cross_sdk() {
    let (_json, wire) = load_vector("relinquishOutput-simple-result.json");
    assert!(extract_result(&wire).is_empty());
}

// ============================================================================
// relinquishCertificate (call code 20)
// ============================================================================

#[test]
fn test_relinquish_certificate_args_cross_sdk() {
    let (json, wire) = load_vector("relinquishCertificate-simple-args.json");
    let params = extract_params(&wire);
    assert_eq!(wire[0], 20);

    let mut writer = WireWriter::new();
    let type_bytes = base64_decode(json["type"].as_str().unwrap());
    writer.write_bytes(&type_bytes);
    let serial_bytes = base64_decode(json["serialNumber"].as_str().unwrap());
    writer.write_bytes(&serial_bytes);
    let certifier_bytes = hex::decode(json["certifier"].as_str().unwrap()).unwrap();
    writer.write_bytes(&certifier_bytes);

    assert_eq!(writer.as_bytes(), params);
}

#[test]
fn test_relinquish_certificate_result_cross_sdk() {
    let (_json, wire) = load_vector("relinquishCertificate-simple-result.json");
    assert!(extract_result(&wire).is_empty());
}

// ============================================================================
// internalizeAction (call code 5) / result
// ============================================================================

#[test]
fn test_internalize_action_result_cross_sdk() {
    let (_json, wire) = load_vector("internalizeAction-simple-result.json");
    assert!(extract_result(&wire).is_empty());
}

// ============================================================================
// proveCertificate result
// ============================================================================

#[test]
fn test_prove_certificate_result_cross_sdk() {
    let (json, wire) = load_vector("proveCertificate-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);
    let num_fields = reader.read_var_int().unwrap() as usize;
    let expected = json["keyringForVerifier"].as_object().unwrap();
    assert_eq!(num_fields, expected.len());

    for _ in 0..num_fields {
        let key = reader.read_string().unwrap();
        let value_len = reader.read_var_int().unwrap() as usize;
        let value_bytes = reader.read_bytes(value_len).unwrap();
        let value_b64 = base64_encode(value_bytes);
        assert_eq!(value_b64, expected[&key].as_str().unwrap());
    }
}

// ============================================================================
// acquireCertificate result - certificate binary format
// ============================================================================

#[test]
fn test_acquire_certificate_result_cross_sdk() {
    let (json, wire) = load_vector("acquireCertificate-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    // Go certificate format: type(32) → serial(32) → subject(33) → certifier(33) → outpoint → fields → signature(remaining)
    let type_bytes = reader.read_bytes(32).unwrap();
    assert_eq!(
        type_bytes,
        base64_decode(json["type"].as_str().unwrap()).as_slice()
    );

    let serial = reader.read_bytes(32).unwrap();
    assert_eq!(
        serial,
        base64_decode(json["serialNumber"].as_str().unwrap()).as_slice()
    );

    let subject = reader.read_bytes(33).unwrap();
    assert_eq!(
        subject,
        hex::decode(json["subject"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let certifier = reader.read_bytes(33).unwrap();
    assert_eq!(
        certifier,
        hex::decode(json["certifier"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let outpoint = reader.read_outpoint_string().unwrap();
    assert_eq!(outpoint, json["revocationOutpoint"].as_str().unwrap());

    // fields (string map, sorted, BEFORE signature)
    let fields = reader.read_string_map().unwrap();
    let expected_fields = json["fields"].as_object().unwrap();
    for (k, v) in expected_fields {
        assert_eq!(fields.get(k).unwrap(), v.as_str().unwrap());
    }

    // signature (remaining raw bytes, NO length prefix)
    let sig = reader.read_remaining();
    assert_eq!(
        sig,
        hex::decode(json["signature"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );
}

// ============================================================================
// listCertificates result - with keyring and verifier
// ============================================================================

#[test]
fn test_list_certificates_full_result_cross_sdk() {
    let (json, wire) = load_vector("listCertificates-full-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    // totalCertificates
    let total = reader.read_var_int().unwrap();
    assert_eq!(total, json["totalCertificates"].as_u64().unwrap());

    // Certificate binary (length-prefixed)
    let cert_len = reader.read_var_int().unwrap() as usize;
    assert!(cert_len > 0);
    let cert_bytes = reader.read_bytes(cert_len).unwrap();

    // Parse certificate: Go order: type(32) → serial(32) → subject(33) → certifier(33) → outpoint → fields → signature(remaining)
    let mut cert_reader = WireReader::new(cert_bytes);
    let cert = &json["certificates"][0];

    let type_bytes = cert_reader.read_bytes(32).unwrap();
    assert_eq!(
        type_bytes,
        base64_decode(cert["type"].as_str().unwrap()).as_slice()
    );

    let serial = cert_reader.read_bytes(32).unwrap();
    assert_eq!(
        serial,
        base64_decode(cert["serialNumber"].as_str().unwrap()).as_slice()
    );

    let subject = cert_reader.read_bytes(33).unwrap();
    assert_eq!(
        subject,
        hex::decode(cert["subject"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let certifier = cert_reader.read_bytes(33).unwrap();
    assert_eq!(
        certifier,
        hex::decode(cert["certifier"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let outpoint = cert_reader.read_outpoint_string().unwrap();
    assert_eq!(outpoint, cert["revocationOutpoint"].as_str().unwrap());

    let fields = cert_reader.read_string_map().unwrap();
    let expected_fields = cert["fields"].as_object().unwrap();
    for (k, v) in expected_fields {
        assert_eq!(fields.get(k).unwrap(), v.as_str().unwrap());
    }

    let sig = cert_reader.read_remaining();
    assert_eq!(
        sig,
        hex::decode(cert["signature"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // Keyring flag (1 = present)
    let keyring_flag = reader.read_i8().unwrap();
    assert_eq!(keyring_flag, 1);

    let num_keyring = reader.read_var_int().unwrap() as usize;
    let expected_keyring = cert["keyring"].as_object().unwrap();
    assert_eq!(num_keyring, expected_keyring.len());

    for _ in 0..num_keyring {
        let key = reader.read_string().unwrap();
        let value_len = reader.read_var_int().unwrap() as usize;
        let value_bytes = reader.read_bytes(value_len).unwrap();
        let value_b64 = base64_encode(value_bytes);
        assert_eq!(value_b64, expected_keyring[&key].as_str().unwrap());
    }

    // Verifier: Go encodes as varint(33) + raw 33-byte compressed pubkey
    let verifier_len = reader.read_var_int().unwrap() as usize;
    assert!(verifier_len > 0);
    let verifier_bytes = reader.read_bytes(verifier_len).unwrap();
    let expected_verifier = cert["verifier"].as_str().unwrap();
    if verifier_len == 33 {
        // Raw compressed pubkey bytes - compare as hex
        assert_eq!(hex::encode(verifier_bytes), expected_verifier);
    } else {
        // Hex string
        let verifier_str = std::str::from_utf8(verifier_bytes).unwrap();
        assert_eq!(verifier_str, expected_verifier);
    }
}

// ============================================================================
// revealCounterpartyKeyLinkage result
// ============================================================================

#[test]
fn test_reveal_counterparty_key_linkage_result_cross_sdk() {
    let (json, wire) = load_vector("revealCounterpartyKeyLinkage-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    // prover (33 bytes)
    let prover = reader.read_bytes(33).unwrap();
    assert_eq!(
        prover,
        hex::decode(json["prover"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // verifier (33 bytes)
    let verifier = reader.read_bytes(33).unwrap();
    assert_eq!(
        verifier,
        hex::decode(json["verifier"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // counterparty (33 bytes)
    let cp = reader.read_bytes(33).unwrap();
    assert_eq!(
        cp,
        hex::decode(json["counterparty"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // revelationTime (string)
    let time = reader.read_string().unwrap();
    assert_eq!(time, json["revelationTime"].as_str().unwrap());

    // encryptedLinkage (varint-len + bytes)
    let linkage_len = reader.read_var_int().unwrap() as usize;
    let linkage = reader.read_bytes(linkage_len).unwrap();
    assert_eq!(linkage, json_to_bytes(&json["encryptedLinkage"]).as_slice());

    // encryptedLinkageProof (varint-len + bytes)
    let proof_len = reader.read_var_int().unwrap() as usize;
    let proof = reader.read_bytes(proof_len).unwrap();
    assert_eq!(
        proof,
        json_to_bytes(&json["encryptedLinkageProof"]).as_slice()
    );
}

// ============================================================================
// revealSpecificKeyLinkage result
// ============================================================================

#[test]
fn test_reveal_specific_key_linkage_result_cross_sdk() {
    let (json, wire) = load_vector("revealSpecificKeyLinkage-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    // prover (33 bytes)
    let prover = reader.read_bytes(33).unwrap();
    assert_eq!(
        prover,
        hex::decode(json["prover"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // verifier (33 bytes)
    let verifier = reader.read_bytes(33).unwrap();
    assert_eq!(
        verifier,
        hex::decode(json["verifier"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // counterparty (33 bytes)
    let cp = reader.read_bytes(33).unwrap();
    assert_eq!(
        cp,
        hex::decode(json["counterparty"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // Protocol ID
    let level = reader.read_u8().unwrap();
    let name = reader.read_string().unwrap();
    assert_eq!(level, json["protocolID"][0].as_u64().unwrap() as u8);
    assert_eq!(name, json["protocolID"][1].as_str().unwrap());

    // Key ID
    let key_id = reader.read_string().unwrap();
    assert_eq!(key_id, json["keyID"].as_str().unwrap());

    // encryptedLinkage
    let linkage_len = reader.read_var_int().unwrap() as usize;
    let linkage = reader.read_bytes(linkage_len).unwrap();
    assert_eq!(linkage, json_to_bytes(&json["encryptedLinkage"]).as_slice());

    // encryptedLinkageProof
    let proof_len = reader.read_var_int().unwrap() as usize;
    let proof = reader.read_bytes(proof_len).unwrap();
    assert_eq!(
        proof,
        json_to_bytes(&json["encryptedLinkageProof"]).as_slice()
    );

    // proofType
    let proof_type = reader.read_u8().unwrap();
    assert_eq!(proof_type, json["proofType"].as_u64().unwrap() as u8);
}

// ============================================================================
// listActions result - deserialization
// ============================================================================

#[test]
fn test_list_actions_result_cross_sdk() {
    let (json, wire) = load_vector("listActions-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    let total = reader.read_var_int().unwrap();
    assert_eq!(total, json["totalActions"].as_u64().unwrap());

    // Parse one WalletAction
    let action = reader.read_wallet_action().unwrap();
    let expected = &json["actions"][0];

    assert_eq!(hex::encode(action.txid), expected["txid"].as_str().unwrap());
    assert_eq!(action.satoshis, expected["satoshis"].as_i64().unwrap());
    assert_eq!(
        action.is_outgoing,
        expected["isOutgoing"].as_bool().unwrap()
    );
    assert_eq!(
        action.description,
        expected["description"].as_str().unwrap()
    );
    assert_eq!(action.version, expected["version"].as_u64().unwrap() as u32);
    assert_eq!(
        action.lock_time,
        expected["lockTime"].as_u64().unwrap() as u32
    );

    // Outputs
    assert!(action.outputs.is_some());
    let outputs = action.outputs.unwrap();
    assert_eq!(outputs.len(), 1);
    let output = &outputs[0];
    let expected_output = &expected["outputs"][0];
    assert_eq!(
        output.satoshis,
        expected_output["satoshis"].as_u64().unwrap()
    );
    assert_eq!(
        output.spendable,
        expected_output["spendable"].as_bool().unwrap()
    );
    assert_eq!(
        output.output_index,
        expected_output["outputIndex"].as_u64().unwrap() as u32
    );
    assert_eq!(
        output.output_description,
        expected_output["outputDescription"].as_str().unwrap()
    );
    assert_eq!(output.basket, expected_output["basket"].as_str().unwrap());
}

// ============================================================================
// listOutputs result - deserialization
// ============================================================================

#[test]
fn test_list_outputs_result_cross_sdk() {
    let (json, wire) = load_vector("listOutputs-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    let total = reader.read_var_int().unwrap();
    assert_eq!(total, json["totalOutputs"].as_u64().unwrap());

    // BEEF (unsigned VarInt length + bytes, Go-compatible)
    let beef_len = reader.read_var_int().unwrap();
    let beef = reader.read_bytes(beef_len as usize).unwrap();
    assert_eq!(beef, json_to_bytes(&json["BEEF"]).as_slice());

    // First output
    let output = reader.read_wallet_output().unwrap();
    let expected = &json["outputs"][0];
    assert_eq!(output.satoshis, expected["satoshis"].as_u64().unwrap());
    assert_eq!(output.spendable, expected["spendable"].as_bool().unwrap());
}

// ============================================================================
// discoverByAttributes result - complex certificate with certifierInfo
// ============================================================================

#[test]
fn test_discover_by_attributes_result_cross_sdk() {
    let (json, wire) = load_vector("discoverByAttributes-simple-result.json");
    let result_data = extract_result(&wire);

    let mut reader = WireReader::new(result_data);

    let total = reader.read_var_int().unwrap();
    assert_eq!(total, json["totalCertificates"].as_u64().unwrap());
    assert_eq!(total, 1);

    // Certificate length + binary
    let cert_len = reader.read_var_int().unwrap() as usize;
    let cert_bytes = reader.read_bytes(cert_len).unwrap();
    let cert = &json["certificates"][0];

    // Parse certificate: Go order: type(32) → serial(32) → subject(33) → certifier(33) → outpoint → fields → signature(remaining)
    let mut cert_reader = WireReader::new(cert_bytes);
    let type_bytes = cert_reader.read_bytes(32).unwrap();
    assert_eq!(
        type_bytes,
        base64_decode(cert["type"].as_str().unwrap()).as_slice()
    );

    let serial = cert_reader.read_bytes(32).unwrap();
    assert_eq!(
        serial,
        base64_decode(cert["serialNumber"].as_str().unwrap()).as_slice()
    );

    let subject = cert_reader.read_bytes(33).unwrap();
    assert_eq!(
        subject,
        hex::decode(cert["subject"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let certifier = cert_reader.read_bytes(33).unwrap();
    assert_eq!(
        certifier,
        hex::decode(cert["certifier"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    let outpoint = cert_reader.read_outpoint_string().unwrap();
    assert_eq!(outpoint, cert["revocationOutpoint"].as_str().unwrap());

    let fields = cert_reader.read_string_map().unwrap();
    for (k, v) in cert["fields"].as_object().unwrap() {
        assert_eq!(fields.get(k).unwrap(), v.as_str().unwrap());
    }

    let sig = cert_reader.read_remaining();
    assert_eq!(
        sig,
        hex::decode(cert["signature"].as_str().unwrap())
            .unwrap()
            .as_slice()
    );

    // CertifierInfo
    let certifier_info = &cert["certifierInfo"];
    let name = reader.read_string().unwrap();
    assert_eq!(name, certifier_info["name"].as_str().unwrap());

    let icon_url = reader.read_optional_string().unwrap();
    assert_eq!(icon_url.as_deref(), certifier_info["iconUrl"].as_str());

    let description = reader.read_optional_string().unwrap();
    assert_eq!(
        description.as_deref(),
        certifier_info["description"].as_str()
    );

    let trust = reader.read_u8().unwrap();
    assert_eq!(trust, certifier_info["trust"].as_u64().unwrap() as u8);

    // Publicly revealed keyring
    let num_public = reader.read_var_int().unwrap() as usize;
    let expected_keyring = cert["publiclyRevealedKeyring"].as_object().unwrap();
    assert_eq!(num_public, expected_keyring.len());

    for _ in 0..num_public {
        let key = reader.read_string().unwrap();
        let value_len = reader.read_var_int().unwrap() as usize;
        let value_bytes = reader.read_bytes(value_len).unwrap();
        let value_b64 = base64_encode(value_bytes);
        assert_eq!(value_b64, expected_keyring[&key].as_str().unwrap());
    }

    // Decrypted fields
    let num_decrypted = reader.read_var_int().unwrap() as usize;
    let expected_decrypted = cert["decryptedFields"].as_object().unwrap();
    assert_eq!(num_decrypted, expected_decrypted.len());

    for _ in 0..num_decrypted {
        let key = reader.read_string().unwrap();
        let value = reader.read_string().unwrap();
        assert_eq!(value, expected_decrypted[&key].as_str().unwrap());
    }
}

// ============================================================================
// discoverByIdentityKey result
// ============================================================================

#[test]
fn test_discover_by_identity_key_result_cross_sdk() {
    let (json, wire) = load_vector("discoverByIdentityKey-simple-result.json");
    let result_data = extract_result(&wire);

    // Same format as discoverByAttributes
    let mut reader = WireReader::new(result_data);
    let total = reader.read_var_int().unwrap();
    assert_eq!(total, json["totalCertificates"].as_u64().unwrap());
}

// ============================================================================
// Full end-to-end: Process Go-encoded request through Rust processor
// ============================================================================

#[tokio::test]
async fn test_process_go_get_height_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    let (_, wire) = load_vector("getHeight-simple-args.json");

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    // Process Go-encoded request through Rust processor
    let response = processor.process_message(&wire).await.unwrap();

    // Should get a valid response (error byte 0 + varint height)
    assert_eq!(response[0], 0x00, "should be success");
    let mut reader = WireReader::new(&response[1..]);
    let height = reader.read_var_int().unwrap();
    // ProtoWallet returns 0 for height
    assert_eq!(height, 0);
}

#[tokio::test]
async fn test_process_go_is_authenticated_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    let (_, wire) = load_vector("isAuthenticated-simple-args.json");

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    let response = processor.process_message(&wire).await.unwrap();
    assert_eq!(response[0], 0x00);
    // ProtoWallet returns authenticated=true
    assert_eq!(response[1], 0x01);
}

#[tokio::test]
async fn test_process_go_get_network_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    // getNetwork has no args file, but we can construct a minimal request
    // call_code=27, originator_len=0
    let wire = vec![27u8, 0u8];

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    let response = processor.process_message(&wire).await.unwrap();
    assert_eq!(response[0], 0x00);
    // Processor returns mainnet
}

#[tokio::test]
async fn test_process_go_get_version_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    let wire = vec![28u8, 0u8]; // getVersion, empty originator

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    let response = processor.process_message(&wire).await.unwrap();
    assert_eq!(response[0], 0x00);
    // Go encodes version as raw UTF-8 bytes (no length prefix)
    let version = std::str::from_utf8(&response[1..]).unwrap();
    assert!(!version.is_empty());
}

#[tokio::test]
async fn test_process_go_get_public_key_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    let (_, wire) = load_vector("getPublicKey-simple-args.json");

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    let response = processor.process_message(&wire).await.unwrap();
    assert_eq!(response[0], 0x00, "getPublicKey should succeed");
    // Response should be 33-byte compressed public key
    assert_eq!(response.len(), 34); // error byte + 33 bytes
    assert!(
        response[1] == 0x02 || response[1] == 0x03,
        "should be compressed pubkey prefix"
    );
}

#[tokio::test]
async fn test_process_go_get_header_for_height_request() {
    use bsv_rs::primitives::PrivateKey;
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::ProtoWallet;

    let (_, wire) = load_vector("getHeaderForHeight-simple-args.json");

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    // ProtoWallet returns error for getHeaderForHeight
    let response = processor.process_message(&wire).await.unwrap();
    // Error byte should be non-zero (ProtoWallet doesn't support this)
    assert_ne!(response[0], 0x00);
}

// ============================================================================
// Every Go args vector decoded through the processor to its json (#191)
// ============================================================================

#[cfg(feature = "http")]
#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

/// Every `*-args.json` under `tests/vectors/wallet_wire/`, by call.
#[cfg(feature = "http")]
const ARGS_VECTORS: [&str; 27] = [
    "abortAction-simple-args.json",
    "acquireCertificate-issuance-args.json",
    "acquireCertificate-simple-args.json",
    "createAction-1-out-args.json",
    "createHmac-simple-args.json",
    "createSignature-simple-args.json",
    "decrypt-simple-args.json",
    "discoverByAttributes-simple-args.json",
    "discoverByIdentityKey-simple-args.json",
    "encrypt-simple-args.json",
    "getHeaderForHeight-simple-args.json",
    "getHeight-simple-args.json",
    "getPublicKey-simple-args.json",
    "internalizeAction-simple-args.json",
    "isAuthenticated-simple-args.json",
    "listActions-simple-args.json",
    "listCertificates-simple-args.json",
    "listOutputs-simple-args.json",
    "proveCertificate-simple-args.json",
    "relinquishCertificate-simple-args.json",
    "relinquishOutput-simple-args.json",
    "revealCounterpartyKeyLinkage-simple-args.json",
    "revealSpecificKeyLinkage-simple-args.json",
    "signAction-simple-args.json",
    "verifyHmac-simple-args.json",
    "verifySignature-simple-args.json",
    "waitForAuthentication-simple-args.json",
];

/// The args vectors the processor cannot decode to their json, with the
/// reason. A vector that leaves this list, or joins it, moves the count.
#[cfg(feature = "http")]
const PROCESSOR_ARGS_UNSUPPORTED: [(&str, &str); 21] = [
    (
        "abortAction-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "acquireCertificate-issuance-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "acquireCertificate-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "createAction-1-out-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "createHmac-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and CreateHmacArgs has no field for them: the flag 01 is read as the data's length",
    ),
    (
        "createSignature-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and CreateSignatureArgs has no field for them: the flag 01 is read as the data's, the reason as a length past the end",
    ),
    (
        "decrypt-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and DecryptArgs has no field for them: the flag 01 is read as the ciphertext's length",
    ),
    (
        "discoverByAttributes-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "discoverByIdentityKey-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "encrypt-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and EncryptArgs has no field for them: the flag 01 is read as the plaintext's length",
    ),
    (
        "getPublicKey-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and GetPublicKeyArgs has no field for them: the flag 01 is read as forSelf",
    ),
    (
        "internalizeAction-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listActions-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listCertificates-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listOutputs-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "proveCertificate-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "relinquishCertificate-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "relinquishOutput-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "signAction-simple-args.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "verifyHmac-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and VerifyHmacArgs has no field for them: the reason is read as the HMAC, a length past the end",
    ),
    (
        "verifySignature-simple-args.json",
        "the processor reads no privileged flag, reason or seekPermission of the key-related parameters (WalletWireProcessor.ts:2564-2583 at ts-stack@edf6e03), and VerifySignatureArgs has no field for them: the reason is read as the signature, a length past the end",
    ),
];

/// Sends a Go args vector through `WalletWireProcessor` to a wallet that
/// records what it is handed, and compares that to the vector's json: a field
/// absent on one side reads as null.
#[cfg(feature = "http")]
async fn processor_decodes_to_json(filename: &str) -> Result<(), String> {
    use bsv_rs::wallet::wire::WalletWireProcessor;
    let (json, wire) = load_vector(filename);
    let mut stub = fixtures::wallet::Stub::new(Value::Null);
    stub.error = Some(bsv_rs::Error::WalletError("observed".into()));
    let observed = stub.observed.clone();
    let response = WalletWireProcessor::new(stub)
        .process_message(&wire)
        .await
        .map_err(|e| format!("no response: {e}"))?;
    let Some(seen) = observed.lock().unwrap().take() else {
        let mut reader = WireReader::new(&response[1..]);
        return Err(format!(
            "the wallet was not called: {}",
            reader.read_string().unwrap_or_default()
        ));
    };
    let (seen, want) = (&seen["args"], json.as_object().unwrap());
    let mut names: Vec<&String> = want.keys().collect();
    names.extend(seen.as_object().into_iter().flat_map(|args| args.keys()));
    names.sort();
    names.dedup();
    for name in names {
        let (got, expected) = (&seen[name.as_str()], &json[name.as_str()]);
        if got != expected {
            return Err(format!("{name}: read {got}, the vector says {expected}"));
        }
    }
    Ok(())
}

/// The keeper's general form of #191's witness: `test_all_request_call_codes`
/// read each vector's call code alone, which is how the linkage frames passed.
#[cfg(feature = "http")]
#[tokio::test]
async fn every_go_args_vector_decodes_through_the_processor_to_its_json() {
    let mut on_disk: Vec<String> = std::fs::read_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/wallet_wire"
    ))
    .unwrap()
    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
    .filter(|name| name.ends_with("-args.json"))
    .collect();
    on_disk.sort();
    assert_eq!(on_disk, ARGS_VECTORS, "the table is every args vector");

    let mut failing = Vec::new();
    for filename in ARGS_VECTORS {
        if let Err(why) = processor_decodes_to_json(filename).await {
            println!("{filename}: {why}");
            failing.push(filename);
        }
    }
    let allowed: Vec<&str> = PROCESSOR_ARGS_UNSUPPORTED.iter().map(|(f, _)| *f).collect();
    assert_eq!(failing, allowed, "the vectors the processor cannot decode");
    assert_eq!(ARGS_VECTORS.len() - failing.len(), 6, "passing rows");
}

/// #191: Go's privileged revealCounterpartyKeyLinkage request (`09 00 01 0b
/// "test-reason"` then the two keys) reaches the wallet with its flag, its
/// reason and its keys, read in the reference's order.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_go_counterparty_linkage_request_reads_its_privileged_params_ahead_of_the_keys() {
    let (json, _) = load_vector("revealCounterpartyKeyLinkage-simple-args.json");
    assert_eq!(json["privileged"], true);
    assert_eq!(json["privilegedReason"], "test-reason");
    processor_decodes_to_json("revealCounterpartyKeyLinkage-simple-args.json")
        .await
        .unwrap();
}

/// #191, the same defect beside it: revealSpecificKeyLinkage's request is the
/// key-related parameters (protocol, key ID, counterparty, privileged, reason),
/// then the verifier.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_go_specific_linkage_request_reads_the_key_related_params_then_the_verifier() {
    processor_decodes_to_json("revealSpecificKeyLinkage-simple-args.json")
        .await
        .unwrap();
}

// ============================================================================
// Every Go result vector written through the processor to its wire (#194)
// ============================================================================

/// Every `*-result.json` under `tests/vectors/wallet_wire/`, by call.
#[cfg(feature = "http")]
const RESULT_VECTORS: [&str; 27] = [
    "abortAction-simple-result.json",
    "acquireCertificate-simple-result.json",
    "createHmac-simple-result.json",
    "createSignature-simple-result.json",
    "decrypt-simple-result.json",
    "discoverByAttributes-simple-result.json",
    "discoverByIdentityKey-simple-result.json",
    "encrypt-simple-result.json",
    "getHeaderForHeight-simple-result.json",
    "getHeight-simple-result.json",
    "getNetwork-simple-result.json",
    "getPublicKey-simple-result.json",
    "getVersion-simple-result.json",
    "internalizeAction-simple-result.json",
    "isAuthenticated-simple-result.json",
    "listActions-simple-result.json",
    "listCertificates-full-result.json",
    "listCertificates-simple-result.json",
    "listOutputs-simple-result.json",
    "proveCertificate-simple-result.json",
    "relinquishCertificate-simple-result.json",
    "relinquishOutput-simple-result.json",
    "revealCounterpartyKeyLinkage-simple-result.json",
    "revealSpecificKeyLinkage-simple-result.json",
    "verifyHmac-simple-result.json",
    "verifySignature-simple-result.json",
    "waitForAuthentication-simple-result.json",
];

/// The result vectors the processor cannot write as their wire, with the
/// reason. A vector that leaves this list, or joins it, moves the count (19
/// at #194; the seven result writers of #197 left it).
#[cfg(feature = "http")]
const PROCESSOR_RESULTS_UNSUPPORTED: [(&str, &str); 12] = [
    (
        "abortAction-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "acquireCertificate-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "discoverByAttributes-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "discoverByIdentityKey-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "internalizeAction-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listActions-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listCertificates-full-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listCertificates-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "listOutputs-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "proveCertificate-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "relinquishCertificate-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
    (
        "relinquishOutput-simple-result.json",
        "a processor refusal stub (docs/FIXTURES.md F1): the wallet is never called",
    ),
];

/// A Go result vector's json in the shape the fixture stub answers with: the
/// linkage results nest the keys and the bytes under `linkage` (the Rust
/// type's serde form), every other call's json is the stub's own.
#[cfg(feature = "http")]
fn stub_reply(call: &str, json: &Value) -> Value {
    let bytes = |name: &str| -> String {
        let list: Vec<u8> = serde_json::from_value(json[name].clone()).unwrap();
        hex::encode(list)
    };
    let linkage = || {
        serde_json::json!({"prover": json["prover"], "verifier": json["verifier"],
            "counterparty": json["counterparty"], "encryptedLinkage": bytes("encryptedLinkage"),
            "encryptedLinkageProof": bytes("encryptedLinkageProof")})
    };
    match call {
        "revealCounterpartyKeyLinkage" => {
            serde_json::json!({"linkage": linkage(), "revelationTime": json["revelationTime"]})
        }
        "revealSpecificKeyLinkage" => serde_json::json!({"linkage": linkage(),
            "protocol": {"securityLevel": json["protocolID"][0].to_string(),
                "protocolName": json["protocolID"][1]},
            "keyId": json["keyID"], "proofType": json["proofType"]}),
        _ => json.clone(),
    }
}

/// Sends the call's recorded request (`tests/fixtures/wire/<call>.json`, its
/// case 0: a frame the processor reads) to a wallet that answers with the
/// Go result vector's json, and compares the processor's whole response, the
/// error byte included, to the vector's wire.
#[cfg(feature = "http")]
async fn processor_writes_the_vector_wire(filename: &str) -> Result<(), String> {
    use bsv_rs::wallet::wire::WalletWireProcessor;
    use bsv_rs::wallet::Network;
    let call = filename.split('-').next().unwrap();
    let (json, wire) = load_vector(filename);
    let recording: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/tests/fixtures/wire/{call}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let request = hex::decode(
        recording["cases"][0]["expected"]["request_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let network = if json["network"] == "testnet" {
        Network::Testnet
    } else {
        Network::Mainnet
    };
    let version = json["version"]
        .as_str()
        .unwrap_or("fixture-0.0.0")
        .to_string();
    let stub = fixtures::wallet::Stub::new(stub_reply(call, &json));
    let observed = stub.observed.clone();
    // The stub's reply decoder panics on a json its type does not read: a
    // spawned task turns that into a row of the table.
    let response = tokio::spawn(async move {
        WalletWireProcessor::with_config(stub, network, &version)
            .process_message(&request)
            .await
    })
    .await
    .map_err(|_| "the vector's json is not the result type's".to_string())?
    .map_err(|e| format!("no response: {e}"))?;
    if observed.lock().unwrap().is_none() && !matches!(call, "getNetwork" | "getVersion") {
        let mut reader = WireReader::new(&response[1..]);
        return Err(format!(
            "the wallet was not called: {}",
            reader.read_string().unwrap_or_default()
        ));
    }
    if response != wire {
        return Err(format!(
            "wrote {}, the vector says {}",
            hex::encode(&response),
            hex::encode(&wire)
        ));
    }
    Ok(())
}

/// The general form of #194's witness: every Go result vector whose call the
/// processor answers, written through its result writer, is the vector's wire.
#[cfg(feature = "http")]
#[tokio::test]
async fn every_go_result_vector_is_the_processors_wire_for_its_json() {
    let mut on_disk: Vec<String> = std::fs::read_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/wallet_wire"
    ))
    .unwrap()
    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
    .filter(|name| name.ends_with("-result.json"))
    .collect();
    on_disk.sort();
    assert_eq!(on_disk, RESULT_VECTORS, "the table is every result vector");

    let mut failing = Vec::new();
    for filename in RESULT_VECTORS {
        if let Err(why) = processor_writes_the_vector_wire(filename).await {
            println!("{filename}: {why}");
            failing.push(filename);
        }
    }
    let allowed: Vec<&str> = PROCESSOR_RESULTS_UNSUPPORTED
        .iter()
        .map(|(f, _)| *f)
        .collect();
    assert_eq!(failing, allowed, "the vectors the processor cannot write");
    assert_eq!(RESULT_VECTORS.len() - failing.len(), 15, "passing rows");
}

/// #194: revealCounterpartyKeyLinkage's response is the error byte, the
/// prover, verifier and counterparty (33 bytes each), then revelationTime,
/// encryptedLinkage and encryptedLinkageProof, each behind its length.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_counterparty_linkage_response_writes_the_three_keys_ahead_of_everything() {
    processor_writes_the_vector_wire("revealCounterpartyKeyLinkage-simple-result.json")
        .await
        .unwrap();
}

/// #194: revealSpecificKeyLinkage's response is the error byte, the three
/// keys, the protocol, keyID, encryptedLinkage, encryptedLinkageProof, then
/// proofType as one byte.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_specific_linkage_response_writes_the_three_keys_ahead_of_everything() {
    processor_writes_the_vector_wire("revealSpecificKeyLinkage-simple-result.json")
        .await
        .unwrap();
}

// ============================================================================
// The seven result frames of #197, both sides
// ============================================================================

/// The four byte-array results and the three verdicts of #197.
#[cfg(feature = "http")]
const RESULT_BYTES_VECTORS: [&str; 7] = [
    "encrypt-simple-result.json",
    "decrypt-simple-result.json",
    "createHmac-simple-result.json",
    "createSignature-simple-result.json",
    "verifyHmac-simple-result.json",
    "verifySignature-simple-result.json",
    "waitForAuthentication-simple-result.json",
];

/// #197: encrypt, decrypt, createHmac and createSignature answer the error
/// byte then the bytes alone, no length ahead of them; verifyHmac,
/// verifySignature and waitForAuthentication answer the error byte alone.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_seven_result_writers_write_the_vectors_wire_byte_for_byte() {
    for filename in RESULT_BYTES_VECTORS {
        processor_writes_the_vector_wire(filename)
            .await
            .unwrap_or_else(|why| panic!("{filename}: {why}"));
    }
}

/// Answers every request with one recorded frame.
#[cfg(feature = "http")]
struct FrameWire(Vec<u8>);

#[cfg(feature = "http")]
#[async_trait::async_trait]
impl bsv_rs::wallet::wire::WalletWire for FrameWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, bsv_rs::Error> {
        Ok(self.0.clone())
    }
}

/// #197, the reader's side: this crate's transceiver reads each of the seven
/// Go result vectors' wire as the vector's json (the rest of the frame as the
/// bytes; an empty result as a true verdict).
#[cfg(feature = "http")]
#[tokio::test]
async fn the_transceiver_reads_the_seven_vectors_wire_as_their_json() {
    use bsv_rs::wallet::wire::WalletWireTransceiver;
    use bsv_rs::wallet::{
        CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, Protocol, SecurityLevel,
        VerifyHmacArgs, VerifySignatureArgs,
    };
    let protocol = || Protocol::new(SecurityLevel::App, "fixture keys");
    let key = || "fixture".to_string();
    for filename in RESULT_BYTES_VECTORS {
        let (json, wire) = load_vector(filename);
        let client = WalletWireTransceiver::new(FrameWire(wire));
        let read = match filename.split('-').next().unwrap() {
            "encrypt" => {
                let r = client
                    .encrypt(
                        EncryptArgs {
                            plaintext: vec![0],
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"ciphertext": r.ciphertext})
            }
            "decrypt" => {
                let r = client
                    .decrypt(
                        DecryptArgs {
                            ciphertext: vec![0],
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"plaintext": r.plaintext})
            }
            "createHmac" => {
                let r = client
                    .create_hmac(
                        CreateHmacArgs {
                            data: vec![0],
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"hmac": r.hmac.to_vec()})
            }
            "createSignature" => {
                let r = client
                    .create_signature(
                        CreateSignatureArgs {
                            data: Some(vec![0]),
                            hash_to_directly_sign: None,
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"signature": r.signature})
            }
            "verifyHmac" => {
                let r = client
                    .verify_hmac(
                        VerifyHmacArgs {
                            data: vec![0],
                            hmac: [0; 32],
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"valid": r.valid})
            }
            "verifySignature" => {
                let r = client
                    .verify_signature(
                        VerifySignatureArgs {
                            data: Some(vec![0]),
                            hash_to_directly_verify: None,
                            signature: vec![0],
                            protocol_id: protocol(),
                            key_id: key(),
                            counterparty: None,
                            for_self: None,
                        },
                        "",
                    )
                    .await
                    .unwrap();
                serde_json::json!({"valid": r.valid})
            }
            "waitForAuthentication" => {
                serde_json::json!({"authenticated": client.wait_for_authentication("").await.unwrap()})
            }
            other => unreachable!("{other}"),
        };
        assert_eq!(read, json, "{filename}");
    }
}

/// #197: a wallet's false verdict is the reference's error frame, never the
/// error byte alone (which the reference's transceiver, and this one, read as
/// true): `HMAC is not valid` (`WalletWireProcessor.ts:1520`), `Signature is
/// not valid` (`:1597`), `Wallet did not affirmatively authenticate` (`:1636-1638`).
#[cfg(feature = "http")]
#[tokio::test]
async fn a_false_verdict_is_answered_with_an_error_frame() {
    use bsv_rs::wallet::wire::WalletWireProcessor;
    for (call, reply, refusal) in [
        (
            "verifyHmac",
            serde_json::json!({"valid": false}),
            "HMAC is not valid",
        ),
        (
            "verifySignature",
            serde_json::json!({"valid": false}),
            "Signature is not valid",
        ),
        (
            "waitForAuthentication",
            serde_json::json!({"authenticated": false}),
            "Wallet did not affirmatively authenticate",
        ),
    ] {
        let recording: Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/tests/fixtures/wire/{call}.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let request = hex::decode(
            recording["cases"][1]["expected"]["request_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let stub = fixtures::wallet::Stub::new(reply);
        let observed = stub.observed.clone();
        let response = WalletWireProcessor::new(stub)
            .process_message(&request)
            .await
            .unwrap();
        assert!(
            observed.lock().unwrap().is_some(),
            "{call}: the wallet was called"
        );
        let mut expected = WireWriter::new();
        expected.write_u8(1);
        expected.write_string(&format!("wallet error: {refusal}"));
        expected.write_var_int(0);
        assert_eq!(
            hex::encode(&response),
            hex::encode(expected.as_bytes()),
            "{call}"
        );
    }
}
