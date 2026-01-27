//! Cross-SDK test vectors for overlay module.
//!
//! Tests admin token encoding/decoding and type serialization
//! for compatibility with TypeScript and Go BSV SDKs.

#![cfg(feature = "overlay")]

use bsv_sdk::overlay::{
    create_overlay_admin_token, decode_overlay_admin_token, AdmittanceInstructions, LookupAnswer,
    LookupQuestion, NetworkPreset, Protocol, TaggedBEEF,
};
use bsv_sdk::primitives::{from_hex, PublicKey};
use serde::Deserialize;
use std::fs;

// =================
// Test Vector Structures
// =================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminTokenVector {
    description: String,
    protocol: String,
    identity_key_hex: String,
    domain: String,
    topic_or_service: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverlayTypesVectors {
    lookup_questions: Vec<LookupQuestionVector>,
    lookup_answers: LookupAnswersVectors,
    admittance_instructions: Vec<AdmittanceInstructionsVector>,
    tagged_beef: Vec<TaggedBeefVector>,
    protocols: Vec<ProtocolVector>,
    network_presets: NetworkPresetsVectors,
}

#[derive(Debug, Deserialize)]
struct LookupQuestionVector {
    description: String,
    service: String,
    query: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookupAnswersVectors {
    output_list: serde_json::Value,
    freeform: serde_json::Value,
    formula: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmittanceInstructionsVector {
    description: String,
    outputs_to_admit: Vec<u32>,
    coins_to_retain: Vec<u32>,
    coins_removed: Option<Vec<u32>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaggedBeefVector {
    description: String,
    beef: String,
    topics: Vec<String>,
    off_chain_values: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProtocolVector {
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPresetsVectors {
    mainnet: NetworkPresetVector,
    testnet: NetworkPresetVector,
    local: NetworkPresetVector,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPresetVector {
    allow_http: bool,
    slap_tracker_count: usize,
}

// =================
// Vector Loading
// =================

fn load_admin_token_vectors() -> Vec<AdminTokenVector> {
    let data = fs::read_to_string("tests/vectors/overlay_admin_token.json")
        .expect("Failed to read overlay_admin_token.json");
    serde_json::from_str(&data).expect("Failed to parse overlay_admin_token.json")
}

fn load_overlay_types_vectors() -> OverlayTypesVectors {
    let data = fs::read_to_string("tests/vectors/overlay_types.json")
        .expect("Failed to read overlay_types.json");
    serde_json::from_str(&data).expect("Failed to parse overlay_types.json")
}

// =================
// Admin Token Tests
// =================

#[test]
fn test_admin_token_creation_and_decoding() {
    let vectors = load_admin_token_vectors();
    assert!(!vectors.is_empty(), "No admin token vectors loaded");

    for (i, v) in vectors.iter().enumerate() {
        // Parse protocol
        let protocol = Protocol::parse(&v.protocol)
            .unwrap_or_else(|| panic!("Vector {}: invalid protocol {}", i, v.protocol));

        // Parse identity key
        let identity_key = PublicKey::from_hex(&v.identity_key_hex)
            .unwrap_or_else(|e| panic!("Vector {}: invalid identity key: {}", i, e));

        // Create token
        let script =
            create_overlay_admin_token(protocol, &identity_key, &v.domain, &v.topic_or_service);

        // Decode token
        let decoded = decode_overlay_admin_token(&script)
            .unwrap_or_else(|e| panic!("Vector {}: failed to decode token: {}", i, e));

        // Verify fields match
        assert_eq!(
            decoded.protocol, protocol,
            "Vector {}: protocol mismatch",
            i
        );
        assert_eq!(
            decoded.identity_key.to_compressed(),
            identity_key.to_compressed(),
            "Vector {}: identity key mismatch",
            i
        );
        assert_eq!(decoded.domain, v.domain, "Vector {}: domain mismatch", i);
        assert_eq!(
            decoded.topic_or_service, v.topic_or_service,
            "Vector {}: topic/service mismatch",
            i
        );

        // Verify identity_key_hex method
        assert_eq!(
            decoded.identity_key_hex(),
            v.identity_key_hex,
            "Vector {}: identity_key_hex mismatch",
            i
        );

        println!("Vector {}: {} - OK", i, v.description);
    }
}

#[test]
fn test_admin_token_protocol_detection() {
    let vectors = load_admin_token_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let protocol = Protocol::parse(&v.protocol).unwrap();
        let identity_key = PublicKey::from_hex(&v.identity_key_hex).unwrap();

        let script =
            create_overlay_admin_token(protocol, &identity_key, &v.domain, &v.topic_or_service);

        // Test protocol detection
        let is_ship = bsv_sdk::overlay::is_ship_token(&script);
        let is_slap = bsv_sdk::overlay::is_slap_token(&script);
        let is_admin = bsv_sdk::overlay::is_overlay_admin_token(&script);

        assert!(is_admin, "Vector {}: should be admin token", i);

        match protocol {
            Protocol::Ship => {
                assert!(is_ship, "Vector {}: should be SHIP token", i);
                assert!(!is_slap, "Vector {}: should not be SLAP token", i);
            }
            Protocol::Slap => {
                assert!(is_slap, "Vector {}: should be SLAP token", i);
                assert!(!is_ship, "Vector {}: should not be SHIP token", i);
            }
        }
    }
}

#[test]
fn test_admin_token_deterministic_encoding() {
    let vectors = load_admin_token_vectors();

    for (i, v) in vectors.iter().enumerate() {
        let protocol = Protocol::parse(&v.protocol).unwrap();
        let identity_key = PublicKey::from_hex(&v.identity_key_hex).unwrap();

        // Create token twice
        let script1 =
            create_overlay_admin_token(protocol, &identity_key, &v.domain, &v.topic_or_service);
        let script2 =
            create_overlay_admin_token(protocol, &identity_key, &v.domain, &v.topic_or_service);

        // Should be identical
        assert_eq!(
            script1.to_binary(),
            script2.to_binary(),
            "Vector {}: non-deterministic encoding",
            i
        );
    }
}

// =================
// Protocol Tests
// =================

#[test]
fn test_protocol_parsing() {
    let vectors = load_overlay_types_vectors();

    for (i, v) in vectors.protocols.iter().enumerate() {
        let parsed = Protocol::parse(&v.input)
            .unwrap_or_else(|| panic!("Vector {}: failed to parse {}", i, v.input));

        assert_eq!(
            parsed.as_str(),
            v.expected,
            "Vector {}: expected {}, got {}",
            i,
            v.expected,
            parsed.as_str()
        );
    }
}

// =================
// Network Preset Tests
// =================

#[test]
fn test_network_presets() {
    let vectors = load_overlay_types_vectors();

    // Mainnet
    let mainnet = NetworkPreset::Mainnet;
    assert_eq!(
        mainnet.allow_http(),
        vectors.network_presets.mainnet.allow_http
    );
    assert!(mainnet.slap_trackers().len() >= vectors.network_presets.mainnet.slap_tracker_count);

    // Testnet
    let testnet = NetworkPreset::Testnet;
    assert_eq!(
        testnet.allow_http(),
        vectors.network_presets.testnet.allow_http
    );
    assert!(testnet.slap_trackers().len() >= vectors.network_presets.testnet.slap_tracker_count);

    // Local
    let local = NetworkPreset::Local;
    assert_eq!(local.allow_http(), vectors.network_presets.local.allow_http);
    assert!(local.slap_trackers().len() >= vectors.network_presets.local.slap_tracker_count);
}

// =================
// LookupQuestion Tests
// =================

#[test]
fn test_lookup_question_creation() {
    let vectors = load_overlay_types_vectors();

    for (i, v) in vectors.lookup_questions.iter().enumerate() {
        let question = LookupQuestion::new(v.service.clone(), v.query.clone());

        assert_eq!(
            question.service, v.service,
            "Vector {}: service mismatch",
            i
        );
        assert_eq!(question.query, v.query, "Vector {}: query mismatch", i);

        // Test JSON roundtrip
        let json = serde_json::to_string(&question).unwrap();
        let parsed: LookupQuestion = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.service, question.service);
        assert_eq!(parsed.query, question.query);

        println!("LookupQuestion {}: {} - OK", i, v.description);
    }
}

// =================
// LookupAnswer Tests
// =================

#[test]
fn test_lookup_answer_output_list_json() {
    let vectors = load_overlay_types_vectors();

    // Parse output-list answer from vector
    let answer: LookupAnswer =
        serde_json::from_value(vectors.lookup_answers.output_list.clone()).unwrap();

    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output_index, 0);
        assert_eq!(outputs[1].output_index, 1);
        assert!(outputs[1].context.is_some());
    } else {
        panic!("Expected OutputList variant");
    }
}

#[test]
fn test_lookup_answer_freeform_json() {
    let vectors = load_overlay_types_vectors();

    let answer: LookupAnswer =
        serde_json::from_value(vectors.lookup_answers.freeform.clone()).unwrap();

    if let LookupAnswer::Freeform { result } = answer {
        assert_eq!(result["status"], "ok");
    } else {
        panic!("Expected Freeform variant");
    }
}

#[test]
fn test_lookup_answer_formula_json() {
    let vectors = load_overlay_types_vectors();

    let answer: LookupAnswer =
        serde_json::from_value(vectors.lookup_answers.formula.clone()).unwrap();

    if let LookupAnswer::Formula { formulas } = answer {
        assert_eq!(formulas.len(), 1);
        assert_eq!(formulas[0].outpoint, "abc123def456.0");
        assert_eq!(formulas[0].history_fn, "getLatest");
    } else {
        panic!("Expected Formula variant");
    }
}

// =================
// AdmittanceInstructions Tests
// =================

#[test]
fn test_admittance_instructions_json() {
    let vectors = load_overlay_types_vectors();

    for (i, v) in vectors.admittance_instructions.iter().enumerate() {
        let instructions = AdmittanceInstructions {
            outputs_to_admit: v.outputs_to_admit.clone(),
            coins_to_retain: v.coins_to_retain.clone(),
            coins_removed: v.coins_removed.clone(),
        };

        // Test has_activity
        let expected_activity = !v.outputs_to_admit.is_empty()
            || !v.coins_to_retain.is_empty()
            || v.coins_removed.as_ref().is_some_and(|r| !r.is_empty());

        assert_eq!(
            instructions.has_activity(),
            expected_activity,
            "Vector {}: has_activity mismatch",
            i
        );

        // Test JSON roundtrip
        let json = serde_json::to_string(&instructions).unwrap();
        let parsed: AdmittanceInstructions = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.outputs_to_admit, instructions.outputs_to_admit);
        assert_eq!(parsed.coins_to_retain, instructions.coins_to_retain);

        println!("AdmittanceInstructions {}: {} - OK", i, v.description);
    }
}

// =================
// TaggedBEEF Tests
// =================

#[test]
fn test_tagged_beef_creation() {
    let vectors = load_overlay_types_vectors();

    for (i, v) in vectors.tagged_beef.iter().enumerate() {
        let beef_bytes = from_hex(&v.beef).unwrap();

        let tagged = if let Some(ref off_chain_hex) = v.off_chain_values {
            let off_chain = from_hex(off_chain_hex).unwrap();
            TaggedBEEF::with_off_chain_values(beef_bytes.clone(), v.topics.clone(), off_chain)
        } else {
            TaggedBEEF::new(beef_bytes.clone(), v.topics.clone())
        };

        assert_eq!(tagged.beef, beef_bytes, "Vector {}: beef mismatch", i);
        assert_eq!(tagged.topics, v.topics, "Vector {}: topics mismatch", i);

        if v.off_chain_values.is_some() {
            assert!(
                tagged.off_chain_values.is_some(),
                "Vector {}: expected off_chain_values",
                i
            );
        } else {
            assert!(
                tagged.off_chain_values.is_none(),
                "Vector {}: unexpected off_chain_values",
                i
            );
        }

        // Test JSON roundtrip
        let json = serde_json::to_string(&tagged).unwrap();
        let parsed: TaggedBEEF = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.beef, tagged.beef);
        assert_eq!(parsed.topics, tagged.topics);
        assert_eq!(parsed.off_chain_values, tagged.off_chain_values);

        println!("TaggedBEEF {}: {} - OK", i, v.description);
    }
}

// =================
// Vector Count Tests
// =================

#[test]
fn test_admin_token_vector_count() {
    let vectors = load_admin_token_vectors();
    assert!(
        vectors.len() >= 4,
        "Expected at least 4 admin token vectors"
    );
    println!("Loaded {} admin token vectors", vectors.len());
}

#[test]
fn test_overlay_types_vector_count() {
    let vectors = load_overlay_types_vectors();
    assert!(
        vectors.lookup_questions.len() >= 3,
        "Expected at least 3 lookup question vectors"
    );
    assert!(
        vectors.admittance_instructions.len() >= 4,
        "Expected at least 4 admittance instructions vectors"
    );
    assert!(
        vectors.tagged_beef.len() >= 3,
        "Expected at least 3 tagged BEEF vectors"
    );
    assert!(
        vectors.protocols.len() >= 6,
        "Expected at least 6 protocol vectors"
    );
    println!("Loaded overlay types vectors successfully");
}
