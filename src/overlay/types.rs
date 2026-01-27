//! Core types for overlay network operations.
//!
//! This module defines the fundamental types used throughout the overlay system
//! for SHIP (Submit Hierarchical Information Protocol) and SLAP (Service Lookup
//! Availability Protocol) operations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Overlay protocol type.
///
/// SHIP is used for broadcasting transactions to overlay topics.
/// SLAP is used for discovering and querying lookup services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// Submit Hierarchical Information Protocol - for broadcasting transactions.
    #[serde(rename = "SHIP")]
    Ship,
    /// Service Lookup Availability Protocol - for service discovery.
    #[serde(rename = "SLAP")]
    Slap,
}

impl Protocol {
    /// Get the protocol as a static string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ship => "SHIP",
            Self::Slap => "SLAP",
        }
    }

    /// Parse a protocol from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SHIP" => Some(Self::Ship),
            "SLAP" => Some(Self::Slap),
            _ => None,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Network preset for overlay services.
///
/// Determines which default endpoints and settings to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum NetworkPreset {
    /// BSV mainnet - production network.
    #[default]
    Mainnet,
    /// BSV testnet - testing network.
    Testnet,
    /// Local development network.
    Local,
}

impl NetworkPreset {
    /// Get default SLAP tracker URLs for this network.
    pub fn slap_trackers(&self) -> Vec<&'static str> {
        match self {
            Self::Mainnet => vec![
                "https://overlay-us-1.bsvb.tech",
                "https://overlay-eu-1.bsvb.tech",
                "https://overlay-ap-1.bsvb.tech",
                "https://users.bapp.dev",
            ],
            Self::Testnet => vec!["https://testnet-users.bapp.dev"],
            Self::Local => vec!["http://localhost:8080"],
        }
    }

    /// Whether HTTP (not HTTPS) is allowed for this network.
    pub fn allow_http(&self) -> bool {
        matches!(self, Self::Local)
    }
}

/// Question sent to a lookup service.
///
/// Contains the service identifier and a query payload that is
/// service-specific.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupQuestion {
    /// Service identifier (e.g., "ls_slap", "ls_ship", "ls_myservice").
    pub service: String,
    /// Service-specific query payload.
    pub query: serde_json::Value,
}

impl LookupQuestion {
    /// Create a new lookup question.
    pub fn new(service: impl Into<String>, query: serde_json::Value) -> Self {
        Self {
            service: service.into(),
            query,
        }
    }
}

/// Answer type from lookup service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupAnswerType {
    /// List of transaction outputs.
    OutputList,
    /// Freeform JSON response.
    Freeform,
    /// Formula-based response.
    Formula,
}

/// Single output in a lookup answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputListItem {
    /// BEEF-encoded transaction.
    pub beef: Vec<u8>,
    /// Output index within transaction.
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    /// Optional context data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u8>>,
}

/// Formula for computed lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupFormula {
    /// Transaction outpoint.
    pub outpoint: String,
    /// History function to apply.
    #[serde(rename = "historyFn")]
    pub history_fn: String,
}

/// Answer from a lookup service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LookupAnswer {
    /// List of transaction outputs.
    #[serde(rename = "output-list")]
    OutputList {
        /// The list of outputs.
        outputs: Vec<OutputListItem>,
    },
    /// Freeform JSON response.
    #[serde(rename = "freeform")]
    Freeform {
        /// The freeform result.
        result: serde_json::Value,
    },
    /// Formula-based response.
    #[serde(rename = "formula")]
    Formula {
        /// The list of formulas.
        formulas: Vec<LookupFormula>,
    },
}

impl LookupAnswer {
    /// Get the answer type.
    pub fn answer_type(&self) -> LookupAnswerType {
        match self {
            Self::OutputList { .. } => LookupAnswerType::OutputList,
            Self::Freeform { .. } => LookupAnswerType::Freeform,
            Self::Formula { .. } => LookupAnswerType::Formula,
        }
    }

    /// Create an empty output list answer.
    pub fn empty_output_list() -> Self {
        Self::OutputList {
            outputs: Vec::new(),
        }
    }
}

/// BEEF transaction tagged with topics.
///
/// Used when broadcasting transactions to overlay services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedBEEF {
    /// BEEF-encoded transaction.
    pub beef: Vec<u8>,
    /// Topics this transaction is published to.
    pub topics: Vec<String>,
    /// Optional off-chain values.
    #[serde(rename = "offChainValues", skip_serializing_if = "Option::is_none")]
    pub off_chain_values: Option<Vec<u8>>,
}

impl TaggedBEEF {
    /// Create a new tagged BEEF.
    pub fn new(beef: Vec<u8>, topics: Vec<String>) -> Self {
        Self {
            beef,
            topics,
            off_chain_values: None,
        }
    }

    /// Create a tagged BEEF with off-chain values.
    pub fn with_off_chain_values(beef: Vec<u8>, topics: Vec<String>, off_chain: Vec<u8>) -> Self {
        Self {
            beef,
            topics,
            off_chain_values: Some(off_chain),
        }
    }
}

/// Admittance instructions from overlay service.
///
/// Indicates which outputs were admitted and which coins were retained
/// or removed by the topic manager.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdmittanceInstructions {
    /// Output indices admitted to the overlay.
    #[serde(rename = "outputsToAdmit")]
    pub outputs_to_admit: Vec<u32>,
    /// Coin (output) indices to retain for historical record.
    #[serde(rename = "coinsToRetain")]
    pub coins_to_retain: Vec<u32>,
    /// Coin indices that were removed (spent).
    #[serde(rename = "coinsRemoved", skip_serializing_if = "Option::is_none")]
    pub coins_removed: Option<Vec<u32>>,
}

impl AdmittanceInstructions {
    /// Check if any activity was recorded (admits, retains, or removals).
    pub fn has_activity(&self) -> bool {
        !self.outputs_to_admit.is_empty()
            || !self.coins_to_retain.is_empty()
            || self.coins_removed.as_ref().is_some_and(|v| !v.is_empty())
    }
}

/// STEAK = Submitted Transaction Execution AcKnowledgment.
///
/// Maps topic name to admittance instructions, indicating how each topic
/// processed the submitted transaction.
pub type Steak = HashMap<String, AdmittanceInstructions>;

/// Response from a single host during broadcast.
#[derive(Debug, Clone)]
pub struct HostResponse {
    /// Host URL.
    pub host: String,
    /// Whether broadcast succeeded.
    pub success: bool,
    /// STEAK response (if successful).
    pub steak: Option<Steak>,
    /// Error message (if failed).
    pub error: Option<String>,
}

impl HostResponse {
    /// Create a successful response.
    pub fn success(host: String, steak: Steak) -> Self {
        Self {
            host,
            success: true,
            steak: Some(steak),
            error: None,
        }
    }

    /// Create a failed response.
    pub fn failure(host: String, error: String) -> Self {
        Self {
            host,
            success: false,
            steak: None,
            error: Some(error),
        }
    }
}

/// Metadata about an overlay service.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceMetadata {
    /// Service name.
    pub name: String,
    /// Service description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Icon URL.
    #[serde(rename = "iconUrl", skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    /// Service version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Additional info URL.
    #[serde(rename = "infoUrl", skip_serializing_if = "Option::is_none")]
    pub info_url: Option<String>,
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum time to wait for SLAP tracker response (milliseconds).
pub const MAX_TRACKER_WAIT_TIME_MS: u64 = 5000;

/// Maximum time for SHIP query (milliseconds).
pub const MAX_SHIP_QUERY_TIMEOUT_MS: u64 = 5000;

/// Default TTL for hosts cache (milliseconds) - 5 minutes.
pub const DEFAULT_HOSTS_CACHE_TTL_MS: u64 = 5 * 60 * 1000;

/// Default maximum entries in hosts cache.
pub const DEFAULT_HOSTS_CACHE_MAX_ENTRIES: usize = 128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_str_roundtrip() {
        assert_eq!(Protocol::parse("SHIP"), Some(Protocol::Ship));
        assert_eq!(Protocol::parse("SLAP"), Some(Protocol::Slap));
        assert_eq!(Protocol::parse("ship"), Some(Protocol::Ship));
        assert_eq!(Protocol::parse("other"), None);

        assert_eq!(Protocol::Ship.as_str(), "SHIP");
        assert_eq!(Protocol::Slap.as_str(), "SLAP");
    }

    #[test]
    fn test_network_preset_slap_trackers() {
        let mainnet = NetworkPreset::Mainnet.slap_trackers();
        assert!(mainnet.len() >= 1);
        assert!(mainnet[0].starts_with("https://"));

        let local = NetworkPreset::Local.slap_trackers();
        assert!(local[0].starts_with("http://"));
    }

    #[test]
    fn test_network_preset_allow_http() {
        assert!(!NetworkPreset::Mainnet.allow_http());
        assert!(!NetworkPreset::Testnet.allow_http());
        assert!(NetworkPreset::Local.allow_http());
    }

    #[test]
    fn test_lookup_question_new() {
        let q = LookupQuestion::new("ls_test", serde_json::json!({"key": "value"}));
        assert_eq!(q.service, "ls_test");
        assert_eq!(q.query["key"], "value");
    }

    #[test]
    fn test_lookup_answer_type() {
        let output_list = LookupAnswer::OutputList { outputs: vec![] };
        assert_eq!(output_list.answer_type(), LookupAnswerType::OutputList);

        let freeform = LookupAnswer::Freeform {
            result: serde_json::Value::Null,
        };
        assert_eq!(freeform.answer_type(), LookupAnswerType::Freeform);
    }

    #[test]
    fn test_tagged_beef() {
        let beef = TaggedBEEF::new(vec![1, 2, 3], vec!["tm_test".to_string()]);
        assert_eq!(beef.beef, vec![1, 2, 3]);
        assert_eq!(beef.topics, vec!["tm_test"]);
        assert!(beef.off_chain_values.is_none());

        let beef_with_off_chain = TaggedBEEF::with_off_chain_values(
            vec![1, 2, 3],
            vec!["tm_test".to_string()],
            vec![4, 5],
        );
        assert!(beef_with_off_chain.off_chain_values.is_some());
    }

    #[test]
    fn test_admittance_instructions_has_activity() {
        let empty = AdmittanceInstructions::default();
        assert!(!empty.has_activity());

        let with_admits = AdmittanceInstructions {
            outputs_to_admit: vec![0],
            ..Default::default()
        };
        assert!(with_admits.has_activity());

        let with_retains = AdmittanceInstructions {
            coins_to_retain: vec![0],
            ..Default::default()
        };
        assert!(with_retains.has_activity());
    }

    #[test]
    fn test_host_response() {
        let success = HostResponse::success("https://example.com".to_string(), HashMap::new());
        assert!(success.success);
        assert!(success.steak.is_some());
        assert!(success.error.is_none());

        let failure = HostResponse::failure(
            "https://example.com".to_string(),
            "Connection refused".to_string(),
        );
        assert!(!failure.success);
        assert!(failure.steak.is_none());
        assert!(failure.error.is_some());
    }
}
