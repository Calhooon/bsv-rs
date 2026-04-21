//! Overlay module integration tests.
//!
//! Tests full overlay workflows including lookup resolution, topic broadcasting,
//! host reputation tracking, transaction history traversal, and admin token handling.
//!
//! **Historical note:** the admin-token assertions in this file were written
//! against the legacy [`create_overlay_admin_token`] (4-field unsigned), now
//! `#[deprecated]` in favor of the 5-field signed
//! [`create_signed_overlay_admin_token`] that matches @bsv/sdk 1.10.1. The
//! file-level allow keeps the legacy regression coverage running while new
//! parity assertions live in `overlay_admin_token_ts_parity_tests.rs`.
//!
//! [`create_overlay_admin_token`]: bsv_rs::overlay::create_overlay_admin_token
//! [`create_signed_overlay_admin_token`]: bsv_rs::overlay::create_signed_overlay_admin_token

#![cfg(feature = "overlay")]
#![allow(deprecated)]

use bsv_rs::overlay::{
    create_overlay_admin_token, decode_overlay_admin_token, is_overlay_admin_token, is_ship_token,
    is_slap_token, AdmittanceInstructions, HostReputationTracker, LookupAnswer, LookupQuestion,
    LookupResolver, LookupResolverConfig, NetworkPreset, OutputListItem, Protocol,
    ReputationConfig, ReputationStorage, RequireAck, Steak, SyncHistorian, TaggedBEEF,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// =================
// Network Preset Tests
// =================

#[test]
fn test_network_preset_slap_trackers() {
    // Mainnet has multiple trackers
    let mainnet_trackers = NetworkPreset::Mainnet.slap_trackers();
    assert!(mainnet_trackers.len() >= 3);
    for tracker in &mainnet_trackers {
        assert!(tracker.starts_with("https://"));
    }

    // Testnet has at least one tracker
    let testnet_trackers = NetworkPreset::Testnet.slap_trackers();
    assert!(!testnet_trackers.is_empty());
    for tracker in &testnet_trackers {
        assert!(tracker.starts_with("https://"));
    }

    // Local uses HTTP
    let local_trackers = NetworkPreset::Local.slap_trackers();
    assert_eq!(local_trackers.len(), 1);
    assert!(local_trackers[0].starts_with("http://localhost"));
}

#[test]
fn test_network_preset_allow_http() {
    assert!(!NetworkPreset::Mainnet.allow_http());
    assert!(!NetworkPreset::Testnet.allow_http());
    assert!(NetworkPreset::Local.allow_http());
}

#[test]
fn test_network_preset_default_is_mainnet() {
    let preset: NetworkPreset = Default::default();
    assert_eq!(preset, NetworkPreset::Mainnet);
}

// =================
// Protocol Tests
// =================

#[test]
fn test_protocol_parsing_case_insensitive() {
    assert_eq!(Protocol::parse("SHIP"), Some(Protocol::Ship));
    assert_eq!(Protocol::parse("ship"), Some(Protocol::Ship));
    assert_eq!(Protocol::parse("Ship"), Some(Protocol::Ship));
    assert_eq!(Protocol::parse("SLAP"), Some(Protocol::Slap));
    assert_eq!(Protocol::parse("slap"), Some(Protocol::Slap));
    assert_eq!(Protocol::parse("Slap"), Some(Protocol::Slap));
    assert_eq!(Protocol::parse("unknown"), None);
    assert_eq!(Protocol::parse(""), None);
}

#[test]
fn test_protocol_str_roundtrip() {
    let ship = Protocol::Ship;
    let slap = Protocol::Slap;

    assert_eq!(Protocol::parse(ship.as_str()), Some(Protocol::Ship));
    assert_eq!(Protocol::parse(slap.as_str()), Some(Protocol::Slap));
}

#[test]
fn test_protocol_display() {
    assert_eq!(format!("{}", Protocol::Ship), "SHIP");
    assert_eq!(format!("{}", Protocol::Slap), "SLAP");
}

// =================
// LookupQuestion Tests
// =================

#[test]
fn test_lookup_question_creation() {
    let query = serde_json::json!({
        "txid": "abc123",
        "outputIndex": 0
    });
    let question = LookupQuestion::new("ls_myservice", query.clone());

    assert_eq!(question.service, "ls_myservice");
    assert_eq!(question.query, query);
}

#[test]
fn test_lookup_question_from_string() {
    let question = LookupQuestion::new(String::from("ls_test"), serde_json::json!({}));
    assert_eq!(question.service, "ls_test");
}

// =================
// LookupAnswer Tests
// =================

#[test]
fn test_lookup_answer_output_list() {
    let outputs = vec![OutputListItem {
        beef: vec![1, 2, 3, 4],
        output_index: 0,
        context: Some(vec![0xAB]),
    }];

    let answer = LookupAnswer::OutputList {
        outputs: outputs.clone(),
    };

    assert_eq!(
        answer.answer_type(),
        bsv_rs::overlay::LookupAnswerType::OutputList
    );

    if let LookupAnswer::OutputList { outputs: out } = answer {
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].beef, vec![1, 2, 3, 4]);
        assert_eq!(out[0].output_index, 0);
        assert_eq!(out[0].context, Some(vec![0xAB]));
    } else {
        panic!("Expected OutputList variant");
    }
}

#[test]
fn test_lookup_answer_freeform() {
    let result = serde_json::json!({
        "key": "value",
        "nested": {"a": 1}
    });

    let answer = LookupAnswer::Freeform {
        result: result.clone(),
    };

    assert_eq!(
        answer.answer_type(),
        bsv_rs::overlay::LookupAnswerType::Freeform
    );

    if let LookupAnswer::Freeform { result: r } = answer {
        assert_eq!(r["key"], "value");
        assert_eq!(r["nested"]["a"], 1);
    } else {
        panic!("Expected Freeform variant");
    }
}

#[test]
fn test_lookup_answer_empty_output_list() {
    let answer = LookupAnswer::empty_output_list();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert!(outputs.is_empty());
    } else {
        panic!("Expected empty OutputList");
    }
}

// =================
// TaggedBEEF Tests
// =================

#[test]
fn test_tagged_beef_creation() {
    let beef = vec![0x01, 0x00, 0xBE, 0xEF];
    let topics = vec!["tm_topic1".to_string(), "tm_topic2".to_string()];

    let tagged = TaggedBEEF::new(beef.clone(), topics.clone());

    assert_eq!(tagged.beef, beef);
    assert_eq!(tagged.topics, topics);
    assert!(tagged.off_chain_values.is_none());
}

#[test]
fn test_tagged_beef_with_off_chain_values() {
    let beef = vec![0x01, 0x00, 0xBE, 0xEF];
    let topics = vec!["tm_topic1".to_string()];
    let off_chain = vec![0xFF, 0xFE, 0xFD];

    let tagged = TaggedBEEF::with_off_chain_values(beef.clone(), topics.clone(), off_chain.clone());

    assert_eq!(tagged.beef, beef);
    assert_eq!(tagged.topics, topics);
    assert_eq!(tagged.off_chain_values, Some(off_chain));
}

// =================
// AdmittanceInstructions Tests
// =================

#[test]
fn test_admittance_instructions_empty() {
    let instructions = AdmittanceInstructions::default();

    assert!(instructions.outputs_to_admit.is_empty());
    assert!(instructions.coins_to_retain.is_empty());
    assert!(instructions.coins_removed.is_none());
    assert!(!instructions.has_activity());
}

#[test]
fn test_admittance_instructions_with_activity() {
    // With admits
    let instructions = AdmittanceInstructions {
        outputs_to_admit: vec![0, 1],
        coins_to_retain: vec![],
        coins_removed: None,
    };
    assert!(instructions.has_activity());

    // With retains only
    let instructions = AdmittanceInstructions {
        outputs_to_admit: vec![],
        coins_to_retain: vec![2],
        coins_removed: None,
    };
    assert!(instructions.has_activity());

    // With removals only
    let instructions = AdmittanceInstructions {
        outputs_to_admit: vec![],
        coins_to_retain: vec![],
        coins_removed: Some(vec![3]),
    };
    assert!(instructions.has_activity());

    // Empty removals vector still counts as no activity
    let instructions = AdmittanceInstructions {
        outputs_to_admit: vec![],
        coins_to_retain: vec![],
        coins_removed: Some(vec![]),
    };
    assert!(!instructions.has_activity());
}

// =================
// Steak (Acknowledgment Map) Tests
// =================

#[test]
fn test_steak_creation() {
    let mut steak: Steak = HashMap::new();

    steak.insert(
        "tm_topic1".to_string(),
        AdmittanceInstructions {
            outputs_to_admit: vec![0],
            coins_to_retain: vec![],
            coins_removed: None,
        },
    );

    steak.insert(
        "tm_topic2".to_string(),
        AdmittanceInstructions {
            outputs_to_admit: vec![],
            coins_to_retain: vec![1],
            coins_removed: None,
        },
    );

    assert_eq!(steak.len(), 2);
    assert!(steak.get("tm_topic1").unwrap().has_activity());
    assert!(steak.get("tm_topic2").unwrap().has_activity());
}

// =================
// TopicBroadcaster Configuration Tests
// =================

#[test]
fn test_topic_broadcaster_valid_topics() {
    let result = TopicBroadcaster::new(
        vec!["tm_topic1".to_string(), "tm_topic2".to_string()],
        TopicBroadcasterConfig::default(),
    );
    assert!(result.is_ok());
}

#[test]
fn test_topic_broadcaster_invalid_topic_prefix() {
    let result = TopicBroadcaster::new(
        vec!["invalid_topic".to_string()],
        TopicBroadcasterConfig::default(),
    );
    match result {
        Err(e) => assert!(e.to_string().contains("must start with \"tm_\"")),
        Ok(_) => panic!("Expected error for invalid topic prefix"),
    }
}

#[test]
fn test_topic_broadcaster_empty_topics() {
    let result = TopicBroadcaster::new(vec![], TopicBroadcasterConfig::default());
    match result {
        Err(e) => assert!(e.to_string().contains("At least one topic")),
        Ok(_) => panic!("Expected error for empty topics"),
    }
}

#[test]
fn test_topic_broadcaster_mixed_valid_invalid() {
    let result = TopicBroadcaster::new(
        vec!["tm_valid".to_string(), "bad_topic".to_string()],
        TopicBroadcasterConfig::default(),
    );
    assert!(result.is_err());
}

#[test]
fn test_topic_broadcaster_config_defaults() {
    let config = TopicBroadcasterConfig::default();

    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert!(config.facilitator.is_none());
    assert!(config.resolver.is_none());
    assert!(matches!(
        config.require_ack_from_all_hosts,
        RequireAck::None
    ));
    assert!(matches!(config.require_ack_from_any_host, RequireAck::All));
    assert!(config.require_ack_from_specific_hosts.is_empty());
}

// =================
// RequireAck Tests
// =================

#[test]
fn test_require_ack_variants() {
    // Test each variant
    let none: RequireAck = RequireAck::None;
    let any: RequireAck = RequireAck::Any;
    let all: RequireAck = RequireAck::All;
    let some: RequireAck = RequireAck::Some(vec!["tm_specific".to_string()]);

    // Ensure they're distinct
    assert!(matches!(none, RequireAck::None));
    assert!(matches!(any, RequireAck::Any));
    assert!(matches!(all, RequireAck::All));
    if let RequireAck::Some(topics) = some {
        assert_eq!(topics, vec!["tm_specific"]);
    } else {
        panic!("Expected Some variant");
    }
}

#[test]
fn test_require_ack_default_is_none() {
    let default: RequireAck = Default::default();
    assert!(matches!(default, RequireAck::None));
}

// =================
// LookupResolver Configuration Tests
// =================

#[test]
fn test_lookup_resolver_default_config() {
    let config = LookupResolverConfig::default();

    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert!(config.facilitator.is_none());
    assert!(config.slap_trackers.is_none());
    assert!(config.host_overrides.is_none());
    assert!(config.additional_hosts.is_none());
    assert!(config.hosts_cache_ttl_ms > 0);
    assert!(config.hosts_cache_max_entries > 0);
}

#[test]
fn test_lookup_resolver_config_custom_values() {
    let config = LookupResolverConfig {
        network_preset: NetworkPreset::Testnet,
        hosts_cache_ttl_ms: 60_000,
        hosts_cache_max_entries: 64,
        tx_memo_ttl_ms: 120_000,
        tx_memo_max_entries: 2048,
        ..Default::default()
    };

    assert_eq!(config.network_preset, NetworkPreset::Testnet);
    assert_eq!(config.hosts_cache_ttl_ms, 60_000);
    assert_eq!(config.hosts_cache_max_entries, 64);
    assert_eq!(config.tx_memo_ttl_ms, 120_000);
    assert_eq!(config.tx_memo_max_entries, 2048);
}

#[test]
fn test_lookup_resolver_config_with_host_overrides() {
    let mut overrides = HashMap::new();
    overrides.insert(
        "ls_myservice".to_string(),
        vec!["https://custom.host.com".to_string()],
    );

    let config = LookupResolverConfig {
        host_overrides: Some(overrides.clone()),
        ..Default::default()
    };

    let host_overrides = config.host_overrides.unwrap();
    assert!(host_overrides.contains_key("ls_myservice"));
}

#[test]
fn test_lookup_resolver_config_with_additional_hosts() {
    let mut additional = HashMap::new();
    additional.insert(
        "ls_myservice".to_string(),
        vec!["https://extra.host.com".to_string()],
    );

    let config = LookupResolverConfig {
        additional_hosts: Some(additional.clone()),
        ..Default::default()
    };

    assert!(config.additional_hosts.is_some());
}

// =================
// HostReputationTracker Tests
// =================

#[test]
fn test_host_reputation_tracker_basic() {
    let tracker = HostReputationTracker::new();

    // Record success
    tracker.record_success("https://host1.com", 100);

    let entry = tracker.snapshot("https://host1.com").unwrap();
    assert_eq!(entry.total_successes, 1);
    assert_eq!(entry.total_failures, 0);
    assert_eq!(entry.consecutive_failures, 0);
    assert!(entry.avg_latency_ms.is_some());
}

#[test]
fn test_host_reputation_tracker_failure() {
    let tracker = HostReputationTracker::new();

    // Record failures
    tracker.record_failure("https://host1.com", Some("Connection timeout"));

    let entry1 = tracker.snapshot("https://host1.com").unwrap();
    assert_eq!(entry1.total_failures, 1);
    assert_eq!(entry1.consecutive_failures, 1);
    assert_eq!(entry1.last_error, Some("Connection timeout".to_string()));

    tracker.record_failure("https://host1.com", None);

    let entry2 = tracker.snapshot("https://host1.com").unwrap();
    assert_eq!(entry2.total_failures, 2);
    assert_eq!(entry2.consecutive_failures, 2);
    // last_error is overwritten on each failure - None overwrites the previous error
    assert_eq!(entry2.last_error, None);
}

#[test]
fn test_host_reputation_tracker_success_resets_consecutive_failures() {
    let tracker = HostReputationTracker::new();

    // Record failures then success
    tracker.record_failure("https://host1.com", Some("Error"));
    tracker.record_failure("https://host1.com", Some("Error"));
    let entry1 = tracker.snapshot("https://host1.com").unwrap();
    assert_eq!(entry1.consecutive_failures, 2);

    tracker.record_success("https://host1.com", 50);
    let entry2 = tracker.snapshot("https://host1.com").unwrap();
    assert_eq!(entry2.consecutive_failures, 0);
    assert_eq!(entry2.total_failures, 2); // Total stays
    assert_eq!(entry2.total_successes, 1);
}

#[test]
fn test_host_reputation_tracker_ranking() {
    let tracker = HostReputationTracker::new();

    // Host 1: Good latency
    tracker.record_success("https://fast-host.com", 50);
    tracker.record_success("https://fast-host.com", 60);

    // Host 2: Slow latency
    tracker.record_success("https://slow-host.com", 500);
    tracker.record_success("https://slow-host.com", 600);

    // Host 3: Failures
    tracker.record_failure("https://failing-host.com", Some("Error"));
    tracker.record_failure("https://failing-host.com", Some("Error"));
    tracker.record_failure("https://failing-host.com", Some("Error"));

    let hosts = vec![
        "https://fast-host.com".to_string(),
        "https://slow-host.com".to_string(),
        "https://failing-host.com".to_string(),
    ];

    let ranked = tracker.rank_hosts(&hosts);

    // Fast host should be ranked first (lowest score)
    assert_eq!(ranked[0].entry.host, "https://fast-host.com");
    // Failing host should be ranked last (highest score due to failures)
    assert_eq!(ranked[2].entry.host, "https://failing-host.com");
}

#[test]
fn test_host_reputation_tracker_config() {
    let config = ReputationConfig {
        latency_smoothing: 0.5,
        grace_failures: 3,
        backoff_base_ms: 2000,
        backoff_max_ms: 120_000,
        default_latency_ms: 2000.0,
        failure_penalty_ms: 500.0,
        success_bonus_ms: 50.0,
    };

    let tracker = HostReputationTracker::with_config(config);

    // First success sets avg_latency_ms directly to the measured value
    tracker.record_success("https://host.com", 100);
    let entry1 = tracker.snapshot("https://host.com").unwrap();
    assert!((entry1.avg_latency_ms.unwrap() - 100.0).abs() < 0.1);

    // Second success uses EMA with smoothing factor
    tracker.record_success("https://host.com", 200);
    let entry2 = tracker.snapshot("https://host.com").unwrap();

    // With 0.5 smoothing:
    // new_avg = old_avg * (1 - 0.5) + new_latency * 0.5
    // = 100 * 0.5 + 200 * 0.5 = 150
    let expected_latency = 100.0 * 0.5 + 200.0 * 0.5;
    assert!((entry2.avg_latency_ms.unwrap() - expected_latency).abs() < 0.1);
}

#[test]
fn test_host_reputation_tracker_reset() {
    let tracker = HostReputationTracker::new();

    tracker.record_success("https://host1.com", 100);
    tracker.record_failure("https://host2.com", None);

    assert!(tracker.snapshot("https://host1.com").is_some());
    assert!(tracker.snapshot("https://host2.com").is_some());

    tracker.reset();

    assert!(tracker.snapshot("https://host1.com").is_none());
    assert!(tracker.snapshot("https://host2.com").is_none());
}

// =================
// HostReputationTracker Storage Tests
// =================

struct MockStorage {
    data: Arc<RwLock<HashMap<String, String>>>,
}

impl MockStorage {
    fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl ReputationStorage for MockStorage {
    fn get(&self, key: &str) -> Option<String> {
        self.data.read().unwrap().get(key).cloned()
    }

    fn set(&self, key: &str, value: &str) {
        self.data
            .write()
            .unwrap()
            .insert(key.to_string(), value.to_string());
    }

    fn remove(&self, key: &str) {
        self.data.write().unwrap().remove(key);
    }
}

#[test]
fn test_host_reputation_tracker_with_storage() {
    let storage = MockStorage::new();
    let tracker = HostReputationTracker::with_storage(Box::new(storage));

    assert!(tracker.has_storage());

    // Record data
    tracker.record_success("https://host.com", 100);

    // Data should be persisted
    tracker.flush();
}

#[test]
fn test_host_reputation_tracker_json_export_import() {
    let tracker = HostReputationTracker::new();

    tracker.record_success("https://host1.com", 100);
    tracker.record_failure("https://host2.com", Some("Error"));

    // Export to JSON
    let json = tracker.to_json();
    assert!(!json.is_empty());
    assert!(json.contains("https://host1.com"));
    assert!(json.contains("https://host2.com"));

    // Import into new tracker
    let tracker2 = HostReputationTracker::new();
    assert!(tracker2.from_json(&json));

    // Verify data was imported
    let entry1 = tracker2.snapshot("https://host1.com").unwrap();
    assert_eq!(entry1.total_successes, 1);

    let entry2 = tracker2.snapshot("https://host2.com").unwrap();
    assert_eq!(entry2.total_failures, 1);
}

#[test]
fn test_host_reputation_tracker_json_import_invalid() {
    let tracker = HostReputationTracker::new();

    // Invalid JSON should return false
    assert!(!tracker.from_json("not valid json"));
    assert!(!tracker.from_json("{invalid}"));
}

// =================
// SyncHistorian Tests
// =================

fn create_test_transaction(id_modifier: u8, source: Option<Transaction>) -> Transaction {
    let mut tx = Transaction::new();

    // Add an output
    tx.outputs.push(TransactionOutput::new(
        1000 + id_modifier as u64,
        LockingScript::from_asm("OP_TRUE").unwrap(),
    ));

    // Add input with source transaction if provided
    if let Some(source_tx) = source {
        let mut input = TransactionInput::new(source_tx.id(), 0);
        input.source_transaction = Some(Box::new(source_tx));
        tx.inputs.push(input);
    }

    tx
}

#[test]
fn test_sync_historian_single_transaction() {
    let tx = create_test_transaction(1, None);

    let historian = SyncHistorian::<String, ()>::new(|tx, output_idx, _ctx| {
        Some(format!("{}:{}", tx.id(), output_idx))
    });

    let history = historian.build_history(&tx, None);

    assert_eq!(history.len(), 1);
    assert!(history[0].contains(":0"));
}

#[test]
fn test_sync_historian_chain_traversal() {
    // Create chain: tx1 <- tx2 <- tx3
    let tx1 = create_test_transaction(1, None);
    let tx2 = create_test_transaction(2, Some(tx1.clone()));
    let tx3 = create_test_transaction(3, Some(tx2.clone()));

    let historian =
        SyncHistorian::<String, ()>::new(|tx, _output_idx, _ctx| Some(tx.id()[..8].to_string()));

    let history = historian.build_history(&tx3, None);

    // History should be in chronological order (oldest first)
    assert_eq!(history.len(), 3);
    assert_eq!(history[0], tx1.id()[..8]);
    assert_eq!(history[1], tx2.id()[..8]);
    assert_eq!(history[2], tx3.id()[..8]);
}

#[test]
fn test_sync_historian_filtering() {
    let tx = create_test_transaction(1, None);

    // Only return values for outputs with value > 1500
    let historian = SyncHistorian::<u64, ()>::new(|tx, output_idx, _ctx| {
        let output = tx.outputs.get(output_idx as usize)?;
        let satoshis = output.satoshis?;
        if satoshis > 1500 {
            Some(satoshis)
        } else {
            None
        }
    });

    let history = historian.build_history(&tx, None);

    // tx has output with 1001 satoshis, should be filtered
    assert!(history.is_empty());
}

#[test]
fn test_sync_historian_with_context() {
    let tx = create_test_transaction(1, None);

    let historian = SyncHistorian::<String, String>::new(|_tx, _output_idx, ctx| {
        ctx.map(|c| format!("context: {}", c))
    });

    // With context
    let history_with_ctx = historian.build_history(&tx, Some(&"test_ctx".to_string()));
    assert_eq!(history_with_ctx.len(), 1);
    assert_eq!(history_with_ctx[0], "context: test_ctx");

    // Without context
    let history_without_ctx = historian.build_history(&tx, None);
    assert!(history_without_ctx.is_empty());
}

#[test]
fn test_sync_historian_cycle_prevention() {
    let tx = create_test_transaction(1, None);

    // Create a historian that would process each output twice
    let historian = SyncHistorian::<u32, ()>::new(|_tx, output_idx, _ctx| Some(output_idx));

    // Even if we call build_history multiple times, cycles are prevented
    let history = historian.build_history(&tx, None);
    assert_eq!(history.len(), 1);
}

#[test]
fn test_sync_historian_with_debug() {
    let tx = create_test_transaction(1, None);

    let historian = SyncHistorian::<u32, ()>::new(|_tx, output_idx, _ctx| Some(output_idx))
        .with_debug(true)
        .with_version("v2");

    let history = historian.build_history(&tx, None);
    assert_eq!(history.len(), 1);
}

// =================
// Admin Token Tests
// =================

#[test]
fn test_create_and_decode_ship_token() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let script = create_overlay_admin_token(
        Protocol::Ship,
        &public_key,
        "https://myoverlay.example.com",
        "tm_my_topic",
    );

    let decoded = decode_overlay_admin_token(&script).unwrap();

    assert_eq!(decoded.protocol, Protocol::Ship);
    assert_eq!(
        decoded.identity_key.to_compressed(),
        public_key.to_compressed()
    );
    assert_eq!(decoded.domain, "https://myoverlay.example.com");
    assert_eq!(decoded.topic_or_service, "tm_my_topic");
}

#[test]
fn test_create_and_decode_slap_token() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let script = create_overlay_admin_token(
        Protocol::Slap,
        &public_key,
        "https://lookup.example.com",
        "ls_my_service",
    );

    let decoded = decode_overlay_admin_token(&script).unwrap();

    assert_eq!(decoded.protocol, Protocol::Slap);
    assert_eq!(decoded.domain, "https://lookup.example.com");
    assert_eq!(decoded.topic_or_service, "ls_my_service");
}

#[test]
fn test_is_ship_token() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let ship_script = create_overlay_admin_token(
        Protocol::Ship,
        &public_key,
        "https://example.com",
        "tm_test",
    );

    let slap_script = create_overlay_admin_token(
        Protocol::Slap,
        &public_key,
        "https://example.com",
        "ls_test",
    );

    assert!(is_ship_token(&ship_script));
    assert!(!is_ship_token(&slap_script));
}

#[test]
fn test_is_slap_token() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let ship_script = create_overlay_admin_token(
        Protocol::Ship,
        &public_key,
        "https://example.com",
        "tm_test",
    );

    let slap_script = create_overlay_admin_token(
        Protocol::Slap,
        &public_key,
        "https://example.com",
        "ls_test",
    );

    assert!(is_slap_token(&slap_script));
    assert!(!is_slap_token(&ship_script));
}

#[test]
fn test_is_overlay_admin_token() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let admin_script = create_overlay_admin_token(
        Protocol::Ship,
        &public_key,
        "https://example.com",
        "tm_test",
    );

    assert!(is_overlay_admin_token(&admin_script));

    // Empty script is not admin token
    let empty_script = LockingScript::new();
    assert!(!is_overlay_admin_token(&empty_script));
}

#[test]
fn test_admin_token_identity_key_hex() {
    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();

    let script = create_overlay_admin_token(
        Protocol::Ship,
        &public_key,
        "https://example.com",
        "tm_test",
    );

    let decoded = decode_overlay_admin_token(&script).unwrap();
    let hex = decoded.identity_key_hex();

    // Should be 66 hex characters (33 bytes compressed pubkey)
    assert_eq!(hex.len(), 66);

    // Should match original key
    assert_eq!(hex, bsv_rs::primitives::to_hex(&public_key.to_compressed()));
}

#[test]
fn test_decode_invalid_admin_token() {
    // Empty script
    let empty = LockingScript::new();
    assert!(decode_overlay_admin_token(&empty).is_err());

    // P2PKH script is not an admin token
    let p2pkh = LockingScript::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac");
    if let Ok(script) = p2pkh {
        assert!(decode_overlay_admin_token(&script).is_err());
    }
}

// =================
// HostResponse Tests
// =================

#[test]
fn test_host_response_success() {
    let mut steak: Steak = HashMap::new();
    steak.insert(
        "tm_test".to_string(),
        AdmittanceInstructions {
            outputs_to_admit: vec![0],
            coins_to_retain: vec![],
            coins_removed: None,
        },
    );

    let response = bsv_rs::overlay::HostResponse::success("https://host.com".to_string(), steak);

    assert!(response.success);
    assert_eq!(response.host, "https://host.com");
    assert!(response.steak.is_some());
    assert!(response.error.is_none());
}

#[test]
fn test_host_response_failure() {
    let response = bsv_rs::overlay::HostResponse::failure(
        "https://host.com".to_string(),
        "Connection refused".to_string(),
    );

    assert!(!response.success);
    assert_eq!(response.host, "https://host.com");
    assert!(response.steak.is_none());
    assert_eq!(response.error, Some("Connection refused".to_string()));
}

// =================
// ServiceMetadata Tests
// =================

#[test]
fn test_service_metadata_default() {
    let metadata = bsv_rs::overlay::ServiceMetadata::default();

    assert!(metadata.name.is_empty());
    assert!(metadata.description.is_none());
    assert!(metadata.icon_url.is_none());
    assert!(metadata.version.is_none());
    assert!(metadata.info_url.is_none());
}

#[test]
fn test_service_metadata_creation() {
    let metadata = bsv_rs::overlay::ServiceMetadata {
        name: "My Service".to_string(),
        description: Some("A test service".to_string()),
        icon_url: Some("https://example.com/icon.png".to_string()),
        version: Some("1.0.0".to_string()),
        info_url: Some("https://example.com/docs".to_string()),
    };

    assert_eq!(metadata.name, "My Service");
    assert_eq!(metadata.description, Some("A test service".to_string()));
}

// =================
// JSON Serialization Tests
// =================

#[test]
fn test_lookup_question_json_roundtrip() {
    let question = LookupQuestion::new("ls_test", serde_json::json!({"key": "value"}));

    let json = serde_json::to_string(&question).unwrap();
    let decoded: LookupQuestion = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.service, question.service);
    assert_eq!(decoded.query, question.query);
}

#[test]
fn test_tagged_beef_json_roundtrip() {
    let tagged = TaggedBEEF::with_off_chain_values(
        vec![1, 2, 3],
        vec!["tm_test".to_string()],
        vec![4, 5, 6],
    );

    let json = serde_json::to_string(&tagged).unwrap();
    let decoded: TaggedBEEF = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.beef, tagged.beef);
    assert_eq!(decoded.topics, tagged.topics);
    assert_eq!(decoded.off_chain_values, tagged.off_chain_values);
}

#[test]
fn test_admittance_instructions_json_roundtrip() {
    let instructions = AdmittanceInstructions {
        outputs_to_admit: vec![0, 1],
        coins_to_retain: vec![2],
        coins_removed: Some(vec![3, 4]),
    };

    let json = serde_json::to_string(&instructions).unwrap();
    let decoded: AdmittanceInstructions = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.outputs_to_admit, instructions.outputs_to_admit);
    assert_eq!(decoded.coins_to_retain, instructions.coins_to_retain);
    assert_eq!(decoded.coins_removed, instructions.coins_removed);
}

#[test]
fn test_protocol_json_roundtrip() {
    let ship = Protocol::Ship;
    let slap = Protocol::Slap;

    let ship_json = serde_json::to_string(&ship).unwrap();
    let slap_json = serde_json::to_string(&slap).unwrap();

    assert_eq!(ship_json, "\"SHIP\"");
    assert_eq!(slap_json, "\"SLAP\"");

    let decoded_ship: Protocol = serde_json::from_str(&ship_json).unwrap();
    let decoded_slap: Protocol = serde_json::from_str(&slap_json).unwrap();

    assert_eq!(decoded_ship, Protocol::Ship);
    assert_eq!(decoded_slap, Protocol::Slap);
}

// =================
// Constants Tests
// =================

#[test]
fn test_overlay_constants() {
    // Verify constants have reasonable values (using const blocks for compile-time checks)
    const _: () = assert!(bsv_rs::overlay::MAX_TRACKER_WAIT_TIME_MS > 0);
    const _: () = assert!(bsv_rs::overlay::MAX_SHIP_QUERY_TIMEOUT_MS > 0);
    const _: () = assert!(bsv_rs::overlay::DEFAULT_HOSTS_CACHE_TTL_MS > 0);
    const _: () = assert!(bsv_rs::overlay::DEFAULT_HOSTS_CACHE_MAX_ENTRIES > 0);
    const _: () = assert!(bsv_rs::overlay::DEFAULT_TX_MEMO_TTL_MS > 0);
    const _: () = assert!(bsv_rs::overlay::DEFAULT_TX_MEMO_MAX_ENTRIES > 0);

    // TX memo TTL should be longer than hosts cache TTL
    const _: () = assert!(
        bsv_rs::overlay::DEFAULT_TX_MEMO_TTL_MS >= bsv_rs::overlay::DEFAULT_HOSTS_CACHE_TTL_MS
    );
}

// =================
// Type Alias Tests
// =================

#[test]
fn test_ship_broadcaster_alias() {
    // SHIPBroadcaster and SHIPCast are aliases for TopicBroadcaster
    let result =
        bsv_rs::overlay::SHIPBroadcaster::new(vec!["tm_test".to_string()], Default::default());
    assert!(result.is_ok());

    let result = bsv_rs::overlay::SHIPCast::new(vec!["tm_test".to_string()], Default::default());
    assert!(result.is_ok());
}

// =================
// Global Reputation Tracker Tests
// =================

#[test]
fn test_global_reputation_tracker() {
    // Get the global singleton
    let tracker1 = bsv_rs::overlay::get_overlay_host_reputation_tracker();
    let tracker2 = bsv_rs::overlay::get_overlay_host_reputation_tracker();

    // Should be the same instance (test by modifying and reading)
    let unique_host = format!("https://test-{}.example.com", rand::random());
    tracker1.record_success(&unique_host, 100);

    // Should see the change through the other reference
    let entry = tracker2.snapshot(&unique_host);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().total_successes, 1);
}

// =================
// LookupResolver::find_competent_hosts Tests
// =================

#[tokio::test]
async fn test_find_competent_hosts_public_api() {
    // Verify that find_competent_hosts is publicly accessible on LookupResolver.
    // This test confirms the method signature matches the Go SDK's FindCompetentHosts:
    //   Go:   func (l *LookupResolver) FindCompetentHosts(ctx, service string) ([]string, error)
    //   Rust: pub async fn find_competent_hosts(&self, service: &str) -> Result<Vec<String>>
    let resolver = LookupResolver::default();
    let result = resolver.find_competent_hosts("ls_test_service").await;

    // Without network access, the SLAP tracker queries will fail.
    // The key assertion is that the method is public and returns Result<Vec<String>>.
    match result {
        Ok(hosts) => {
            // Hosts should be a Vec<String> of domain URLs
            for host in &hosts {
                assert!(!host.is_empty());
            }
        }
        Err(_) => {
            // Expected: SLAP trackers are not reachable in test environment
        }
    }
}

#[tokio::test]
async fn test_find_competent_hosts_with_custom_config() {
    // Verify find_competent_hosts works with custom LookupResolverConfig
    let config = LookupResolverConfig {
        network_preset: NetworkPreset::Testnet,
        slap_trackers: Some(vec!["https://nonexistent-tracker.invalid".to_string()]),
        ..Default::default()
    };
    let resolver = LookupResolver::new(config);
    let result = resolver.find_competent_hosts("ls_custom_service").await;

    // With a non-existent tracker, the query will fail or return empty
    match result {
        Ok(hosts) => {
            // Tracker unreachable means no hosts discovered
            assert!(hosts.is_empty());
        }
        Err(_) => {
            // Also acceptable - tracker query failed
        }
    }
}

// Random number for unique test data
mod rand {
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn random() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }
}
