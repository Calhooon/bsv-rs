//! `types.rs`'s unit tests, moved beside it for the file's line ceiling (#843d9); the module is still `tests`.
#![cfg(test)]

use super::*;

#[test]
fn test_security_level_conversion() {
    assert_eq!(SecurityLevel::from_u8(0), Some(SecurityLevel::Silent));
    assert_eq!(SecurityLevel::from_u8(1), Some(SecurityLevel::App));
    assert_eq!(SecurityLevel::from_u8(2), Some(SecurityLevel::Counterparty));
    assert_eq!(SecurityLevel::from_u8(3), None);

    assert_eq!(SecurityLevel::Silent.as_u8(), 0);
    assert_eq!(SecurityLevel::App.as_u8(), 1);
    assert_eq!(SecurityLevel::Counterparty.as_u8(), 2);
}

#[test]
fn test_protocol_from_tuple() {
    let proto = Protocol::from_tuple((1, "test protocol name")).unwrap();
    assert_eq!(proto.security_level, SecurityLevel::App);
    assert_eq!(proto.protocol_name, "test protocol name");

    let tuple = proto.to_tuple();
    assert_eq!(tuple, (1, "test protocol name"));
}

#[test]
fn test_outpoint_parsing() {
    let txid_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let outpoint_str = format!("{}.5", txid_hex);

    let outpoint = Outpoint::from_string(&outpoint_str).unwrap();
    assert_eq!(outpoint.vout, 5);
    assert_eq!(outpoint.txid[31], 1);

    assert_eq!(outpoint.to_string(), outpoint_str);
}

#[test]
fn test_outpoint_invalid_format() {
    assert!(Outpoint::from_string("invalid").is_err());
    assert!(Outpoint::from_string("txid").is_err());
    assert!(Outpoint::from_string("abc.1").is_err()); // txid too short
}

#[test]
fn test_validate_satoshis() {
    assert!(validate_satoshis(0, "test").is_ok());
    assert!(validate_satoshis(MAX_SATOSHIS, "test").is_ok());
    assert!(validate_satoshis(MAX_SATOSHIS + 1, "test").is_err());
}

#[test]
fn test_validate_description() {
    assert!(validate_description("hello", "test").is_ok());
    assert!(validate_description("a".repeat(50).as_str(), "test").is_ok());
    assert!(validate_description("tiny", "test").is_err()); // Too short
    assert!(validate_description("a".repeat(51).as_str(), "test").is_err());
    // Too long
}

#[test]
fn test_validate_key_id() {
    assert!(validate_key_id("a").is_ok());
    assert!(validate_key_id("a".repeat(800).as_str()).is_ok());
    assert!(validate_key_id("").is_err());
    assert!(validate_key_id("a".repeat(801).as_str()).is_err());
}

#[test]
fn test_validate_protocol_name() {
    assert!(validate_protocol_name("hello").is_ok());
    assert!(validate_protocol_name("test protocol 123").is_ok());
    assert!(validate_protocol_name("TEST SYSTEM").is_ok()); // Gets lowercased

    assert!(validate_protocol_name("tiny").is_err()); // Too short
    assert!(validate_protocol_name("hello  world").is_err()); // Double space
    assert!(validate_protocol_name("hello-world").is_err()); // Invalid char
    assert!(validate_protocol_name("test protocol").is_err()); // Ends with " protocol"
}

#[test]
fn test_counterparty_variants() {
    let cp_self = Counterparty::Self_;
    assert!(cp_self.is_self());
    assert!(!cp_self.is_anyone());
    assert!(cp_self.public_key().is_none());

    let cp_anyone = Counterparty::Anyone;
    assert!(!cp_anyone.is_self());
    assert!(cp_anyone.is_anyone());
    assert!(cp_anyone.public_key().is_none());
}

#[test]
fn test_hex_bytes_serialization() {
    // Test that Vec<u8> fields serialize as hex strings, not JSON arrays
    let output = CreateActionOutput {
        locking_script: vec![0x76, 0xa9, 0x14], // OP_DUP OP_HASH160 OP_PUSH20
        satoshis: 1000,
        output_description: "Test output description".to_string(),
        basket: None,
        custom_instructions: None,
        tags: None,
    };

    let json = serde_json::to_string(&output).unwrap();
    // Should contain hex string "76a914", not array [118, 169, 20]
    assert!(
        json.contains("\"76a914\""),
        "Expected hex string in JSON: {}",
        json
    );
    assert!(
        !json.contains("[118"),
        "Should not contain int array: {}",
        json
    );

    // Test deserialization from hex string
    let json_input = r#"{"lockingScript":"76a914","satoshis":1000,"outputDescription":"Test output description"}"#;
    let parsed: CreateActionOutput = serde_json::from_str(json_input).unwrap();
    assert_eq!(parsed.locking_script, vec![0x76, 0xa9, 0x14]);
}

#[test]
fn test_hex_bytes_option_serialization() {
    // Test that Option<Vec<u8>> fields serialize as hex strings when present
    let txid_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let outpoint = Outpoint::from_string(&format!("{}.0", txid_hex)).unwrap();

    let input_with_script = CreateActionInput {
        outpoint: outpoint.clone(),
        input_description: "Test input description".to_string(),
        unlocking_script: Some(vec![0x48, 0x30, 0x45]), // Signature prefix
        unlocking_script_length: None,
        sequence_number: None,
    };

    let json = serde_json::to_string(&input_with_script).unwrap();
    // Should contain hex string "483045", not array [72, 48, 69]
    assert!(
        json.contains("\"483045\""),
        "Expected hex string in JSON: {}",
        json
    );
    assert!(
        !json.contains("[72"),
        "Should not contain int array: {}",
        json
    );

    // Test that None serializes correctly (field should be absent)
    let input_without_script = CreateActionInput {
        outpoint,
        input_description: "Test input description".to_string(),
        unlocking_script: None,
        unlocking_script_length: None,
        sequence_number: None,
    };

    let json = serde_json::to_string(&input_without_script).unwrap();
    assert!(
        !json.contains("unlockingScript"),
        "Field should be absent when None: {}",
        json
    );

    // Test deserialization from hex string
    let json_input = format!(
        r#"{{"outpoint":"{}.0","inputDescription":"Test input description","unlockingScript":"483045"}}"#,
        txid_hex
    );
    let parsed: CreateActionInput = serde_json::from_str(&json_input).unwrap();
    assert_eq!(parsed.unlocking_script, Some(vec![0x48, 0x30, 0x45]));
}

#[test]
fn create_action_args_input_beef_is_a_byte_array() {
    // `inputBEEF`, an array of byte numbers, as BRC-100's `BEEF` (#105)
    let args = CreateActionArgs {
        description: "Test action description".to_string(),
        input_beef: Some(vec![0xBE, 0xEF, 0x00, 0x01]),
        inputs: None,
        outputs: None,
        lock_time: None,
        version: None,
        labels: None,
        options: None,
    };

    let json = serde_json::to_string(&args).unwrap();
    assert!(json.contains("\"inputBEEF\":[190,239,0,1]"), "{json}");

    let json_input = r#"{"description":"Test action description","inputBEEF":[190,239,0,1]}"#;
    let parsed: CreateActionArgs = serde_json::from_str(json_input).unwrap();
    // The hex string and the name this crate wrote until #105 are not it
    let hex = r#"{"description":"Test action description","inputBEEF":"beef0001"}"#;
    assert!(serde_json::from_str::<CreateActionArgs>(hex).is_err());
    assert_eq!(parsed.input_beef, Some(vec![0xBE, 0xEF, 0x00, 0x01]));
}

/// `FromStr` against the definition (#843d9): the list is held to the
/// definition by `VARIANT_NAMES`, which `non_exhaustive_enum!` writes from
/// it, and each listed mode's text reads back as itself.
#[test]
fn every_output_include_of_the_definition_reads_back_from_its_text_843d9() {
    let every = [
        OutputInclude::LockingScripts,
        OutputInclude::EntireTransactions,
    ];
    let names: Vec<String> = every.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(names, OutputInclude::VARIANT_NAMES);
    for include in every {
        assert_eq!(include.as_str().parse::<OutputInclude>().unwrap(), include);
    }
}
