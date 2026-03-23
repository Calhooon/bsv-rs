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

use bsv_sdk::wallet::wire::{WireReader, WireWriter};

// ============================================================================
// Call code verification
// ============================================================================

#[test]
fn test_all_call_codes_match_go_sdk() {
    use bsv_sdk::wallet::wire::WalletCall;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

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
    use bsv_sdk::primitives::PrivateKey;
    use bsv_sdk::wallet::wire::WalletWireProcessor;
    use bsv_sdk::wallet::ProtoWallet;

    let (_, wire) = load_vector("getHeaderForHeight-simple-args.json");

    let wallet = ProtoWallet::new(Some(PrivateKey::random()));
    let processor = WalletWireProcessor::new(wallet);

    // ProtoWallet returns error for getHeaderForHeight
    let response = processor.process_message(&wire).await.unwrap();
    // Error byte should be non-zero (ProtoWallet doesn't support this)
    assert_ne!(response[0], 0x00);
}
