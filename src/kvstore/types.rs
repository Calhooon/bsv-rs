//! Core types for KVStore module.
//!
//! This module provides the foundational types used throughout the kvstore module,
//! including configuration, entries, tokens, queries, and operation options.
//! These types are designed to be API-compatible with the TypeScript and Go BSV SDKs.

use serde::{Deserialize, Serialize};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for KVStore.
///
/// Controls protocol ID, service names, token amounts, topics, and encryption settings.
#[derive(Debug, Clone)]
pub struct KVStoreConfig {
    /// Protocol ID for key derivation (default: "kvstore").
    pub protocol_id: String,
    /// Service name for overlay lookup (default: "ls_kvstore").
    pub service_name: String,
    /// Token amount in satoshis (default: 1).
    pub token_amount: u64,
    /// Topics for broadcasting (default: ["tm_kvstore"]).
    pub topics: Vec<String>,
    /// Originator for wallet operations.
    pub originator: Option<String>,
    /// Whether to encrypt values (LocalKVStore only).
    pub encrypt: bool,
}

impl Default for KVStoreConfig {
    fn default() -> Self {
        Self {
            protocol_id: "kvstore".to_string(),
            service_name: "ls_kvstore".to_string(),
            token_amount: 1,
            topics: vec!["tm_kvstore".to_string()],
            originator: None,
            encrypt: true,
        }
    }
}

impl KVStoreConfig {
    /// Creates a new configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = protocol_id.into();
        self
    }

    /// Sets the service name.
    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    /// Sets the token amount.
    pub fn with_token_amount(mut self, amount: u64) -> Self {
        self.token_amount = amount;
        self
    }

    /// Sets the topics.
    pub fn with_topics(mut self, topics: Vec<String>) -> Self {
        self.topics = topics;
        self
    }

    /// Sets the originator.
    pub fn with_originator(mut self, originator: impl Into<String>) -> Self {
        self.originator = Some(originator.into());
        self
    }

    /// Sets whether to encrypt values.
    pub fn with_encrypt(mut self, encrypt: bool) -> Self {
        self.encrypt = encrypt;
        self
    }
}

// =============================================================================
// KVStoreToken
// =============================================================================

/// A token representing a KV entry on-chain.
///
/// Contains transaction reference data for the UTXO backing a key-value entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KVStoreToken {
    /// Transaction ID (hex string).
    pub txid: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Satoshi value of the output.
    pub satoshis: u64,
    /// BEEF data for SPV verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beef: Option<Vec<u8>>,
}

impl KVStoreToken {
    /// Creates a new token.
    pub fn new(txid: impl Into<String>, output_index: u32, satoshis: u64) -> Self {
        Self {
            txid: txid.into(),
            output_index,
            satoshis,
            beef: None,
        }
    }

    /// Creates a token with BEEF data.
    pub fn with_beef(mut self, beef: Vec<u8>) -> Self {
        self.beef = Some(beef);
        self
    }

    /// Returns the outpoint string in "txid.outputIndex" format.
    pub fn outpoint_string(&self) -> String {
        format!("{}.{}", self.txid, self.output_index)
    }
}

// =============================================================================
// KVStoreEntry
// =============================================================================

/// A key-value entry with metadata.
///
/// Represents a stored key-value pair along with controller info, protocol,
/// tags, and optional token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KVStoreEntry {
    /// The key.
    pub key: String,
    /// The value (decrypted if applicable).
    pub value: String,
    /// Controller public key (hex).
    pub controller: String,
    /// Protocol ID used.
    pub protocol_id: String,
    /// Tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Associated token (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<KVStoreToken>,
}

impl KVStoreEntry {
    /// Creates a new entry.
    pub fn new(
        key: impl Into<String>,
        value: impl Into<String>,
        controller: impl Into<String>,
        protocol_id: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            controller: controller.into(),
            protocol_id: protocol_id.into(),
            tags: Vec::new(),
            token: None,
        }
    }

    /// Sets tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Sets the token.
    pub fn with_token(mut self, token: KVStoreToken) -> Self {
        self.token = Some(token);
        self
    }
}

// =============================================================================
// KVStoreLookupResult
// =============================================================================

/// Result of a lookup operation from the overlay network.
///
/// Contains raw output data from an overlay query.
#[derive(Debug, Clone)]
pub struct KVStoreLookupResult {
    /// Transaction ID (hex).
    pub txid: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Output script (hex).
    pub output_script: String,
    /// Satoshi value of the output.
    pub satoshis: u64,
    /// BEEF data for SPV verification.
    pub beef: Option<Vec<u8>>,
}

impl KVStoreLookupResult {
    /// Creates a new lookup result.
    pub fn new(
        txid: impl Into<String>,
        output_index: u32,
        output_script: impl Into<String>,
        satoshis: u64,
    ) -> Self {
        Self {
            txid: txid.into(),
            output_index,
            output_script: output_script.into(),
            satoshis,
            beef: None,
        }
    }

    /// Sets the BEEF data.
    pub fn with_beef(mut self, beef: Vec<u8>) -> Self {
        self.beef = Some(beef);
        self
    }
}

// =============================================================================
// KVStoreQuery
// =============================================================================

/// Query parameters for finding entries.
///
/// Supports filtering by key, controller, protocol ID, and tags with
/// pagination and sorting options.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KVStoreQuery {
    /// Filter by key (exact match).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Filter by controller (hex pubkey).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// Filter by protocol ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_id: Option<String>,
    /// Filter by tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Tag query mode: "all" (default) or "any".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_query_mode: Option<String>,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of results to skip (pagination offset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip: Option<u32>,
    /// Sort order: "asc" or "desc".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,
}

impl KVStoreQuery {
    /// Creates a new empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by key.
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// Filter by controller.
    pub fn with_controller(mut self, controller: impl Into<String>) -> Self {
        self.controller = Some(controller.into());
        self
    }

    /// Filter by protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = Some(protocol_id.into());
        self
    }

    /// Filter by tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Set tag query mode ("all" or "any").
    pub fn with_tag_query_mode(mut self, mode: impl Into<String>) -> Self {
        self.tag_query_mode = Some(mode.into());
        self
    }

    /// Set result limit.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set pagination offset.
    pub fn with_skip(mut self, skip: u32) -> Self {
        self.skip = Some(skip);
        self
    }

    /// Set sort order ("asc" or "desc").
    pub fn with_sort_order(mut self, order: impl Into<String>) -> Self {
        self.sort_order = Some(order.into());
        self
    }

    /// Converts the query to a JSON Value for overlay lookup.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Object(Default::default()))
    }
}

// =============================================================================
// Operation Options
// =============================================================================

/// Options for get operations.
#[derive(Debug, Clone, Default)]
pub struct KVStoreGetOptions {
    /// Include full history chain.
    pub history: bool,
    /// Include token data in result.
    pub include_token: bool,
    /// Override service name.
    pub service_name: Option<String>,
}

impl KVStoreGetOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Include history.
    pub fn with_history(mut self, history: bool) -> Self {
        self.history = history;
        self
    }

    /// Include token data.
    pub fn with_include_token(mut self, include: bool) -> Self {
        self.include_token = include;
        self
    }

    /// Override service name.
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }
}

/// Options for set operations.
#[derive(Debug, Clone, Default)]
pub struct KVStoreSetOptions {
    /// Override protocol ID.
    pub protocol_id: Option<String>,
    /// Description for the operation.
    pub description: Option<String>,
    /// Token amount override.
    pub token_amount: Option<u64>,
    /// Tags to attach.
    pub tags: Option<Vec<String>>,
}

impl KVStoreSetOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = Some(protocol_id.into());
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Override token amount.
    pub fn with_token_amount(mut self, amount: u64) -> Self {
        self.token_amount = Some(amount);
        self
    }

    /// Set tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }
}

/// Options for remove operations.
#[derive(Debug, Clone, Default)]
pub struct KVStoreRemoveOptions {
    /// Override protocol ID.
    pub protocol_id: Option<String>,
    /// Description for the operation.
    pub description: Option<String>,
}

impl KVStoreRemoveOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = Some(protocol_id.into());
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

// =============================================================================
// Internal Types
// =============================================================================

/// Internal result from looking up a value in LocalKVStore.
#[derive(Debug, Clone)]
pub(crate) struct LookupValueResult {
    /// The decrypted/raw value.
    pub value: String,
    /// Outpoints for all outputs holding this key.
    pub outpoints: Vec<String>,
    /// Input BEEF data for spending.
    pub input_beef: Option<Vec<u8>>,
    /// The list outputs result.
    pub outputs: Vec<WalletOutput>,
    /// Whether the value exists.
    pub value_exists: bool,
}

impl LookupValueResult {
    /// Creates a result indicating the value doesn't exist.
    pub fn not_found(default_value: String) -> Self {
        Self {
            value: default_value,
            outpoints: Vec::new(),
            input_beef: None,
            outputs: Vec::new(),
            value_exists: false,
        }
    }

    /// Creates a result with a found value.
    pub fn found(
        value: String,
        outpoints: Vec<String>,
        input_beef: Option<Vec<u8>>,
        outputs: Vec<WalletOutput>,
    ) -> Self {
        Self {
            value,
            outpoints,
            input_beef,
            outputs,
            value_exists: true,
        }
    }
}

/// Simplified wallet output for internal use.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct WalletOutput {
    /// Outpoint string (txid.vout).
    pub outpoint: String,
    /// Satoshi value.
    pub satoshis: u64,
    /// Locking script (raw bytes).
    pub locking_script: Vec<u8>,
    /// Tags associated with the output.
    pub tags: Vec<String>,
}

// =============================================================================
// PushDrop Token Fields
// =============================================================================

/// Field indices in the KVStore PushDrop token.
///
/// KVStore entries use PushDrop tokens with the following field layout:
/// - Field 0: Protocol ID
/// - Field 1: Key
/// - Field 2: Value (encrypted if LocalKVStore)
/// - Field 3: Controller (public key, 33 bytes compressed)
/// - Field 4: Tags (JSON array, optional)
/// - Field 5: Signature (controller signs fields 0-4)
pub struct KvProtocolFields;

impl KvProtocolFields {
    /// Protocol ID field index.
    pub const PROTOCOL_ID: usize = 0;
    /// Key field index.
    pub const KEY: usize = 1;
    /// Value field index.
    pub const VALUE: usize = 2;
    /// Controller field index.
    pub const CONTROLLER: usize = 3;
    /// Tags field index.
    pub const TAGS: usize = 4;
    /// Signature field index.
    pub const SIGNATURE: usize = 5;

    /// Minimum number of fields in old format (no tags).
    pub const MIN_FIELDS_OLD: usize = 5;
    /// Number of fields in new format (with tags).
    pub const MIN_FIELDS_NEW: usize = 6;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kvstore_config_default() {
        let config = KVStoreConfig::default();
        assert_eq!(config.protocol_id, "kvstore");
        assert_eq!(config.service_name, "ls_kvstore");
        assert_eq!(config.token_amount, 1);
        assert_eq!(config.topics, vec!["tm_kvstore"]);
        assert!(config.originator.is_none());
        assert!(config.encrypt);
    }

    #[test]
    fn test_kvstore_config_builder() {
        let config = KVStoreConfig::new()
            .with_protocol_id("my_protocol")
            .with_service_name("ls_custom")
            .with_token_amount(100)
            .with_topics(vec!["tm_custom".to_string()])
            .with_originator("myapp")
            .with_encrypt(false);

        assert_eq!(config.protocol_id, "my_protocol");
        assert_eq!(config.service_name, "ls_custom");
        assert_eq!(config.token_amount, 100);
        assert_eq!(config.topics, vec!["tm_custom"]);
        assert_eq!(config.originator, Some("myapp".to_string()));
        assert!(!config.encrypt);
    }

    #[test]
    fn test_kvstore_token_serialization() {
        let token = KVStoreToken::new("abc123def456", 0, 1);

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("abc123def456"));
        assert!(json.contains("outputIndex"));

        let decoded: KVStoreToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.txid, "abc123def456");
        assert_eq!(decoded.output_index, 0);
        assert_eq!(decoded.satoshis, 1);
    }

    #[test]
    fn test_kvstore_token_with_beef() {
        let token = KVStoreToken::new("abc123", 0, 1).with_beef(vec![1, 2, 3, 4]);
        assert_eq!(token.beef, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn test_kvstore_token_outpoint_string() {
        let token = KVStoreToken::new("abc123", 5, 1);
        assert_eq!(token.outpoint_string(), "abc123.5");
    }

    #[test]
    fn test_kvstore_entry_serialization() {
        let entry = KVStoreEntry::new("test_key", "test_value", "02abc...", "kvstore")
            .with_tags(vec!["tag1".to_string()]);

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: KVStoreEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.key, "test_key");
        assert_eq!(decoded.value, "test_value");
        assert_eq!(decoded.controller, "02abc...");
        assert_eq!(decoded.protocol_id, "kvstore");
        assert_eq!(decoded.tags, vec!["tag1"]);
    }

    #[test]
    fn test_kvstore_query_default() {
        let query = KVStoreQuery::default();
        assert!(query.key.is_none());
        assert!(query.controller.is_none());
        assert!(query.protocol_id.is_none());
        assert!(query.tags.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_kvstore_query_builder() {
        let query = KVStoreQuery::new()
            .with_key("my_key")
            .with_controller("02abc...")
            .with_tags(vec!["important".to_string()])
            .with_tag_query_mode("all")
            .with_limit(10)
            .with_skip(5)
            .with_sort_order("desc");

        assert_eq!(query.key, Some("my_key".to_string()));
        assert_eq!(query.controller, Some("02abc...".to_string()));
        assert_eq!(query.tags, Some(vec!["important".to_string()]));
        assert_eq!(query.tag_query_mode, Some("all".to_string()));
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.skip, Some(5));
        assert_eq!(query.sort_order, Some("desc".to_string()));
    }

    #[test]
    fn test_kvstore_query_serialization() {
        let query = KVStoreQuery::new()
            .with_key("my_key")
            .with_tags(vec!["important".to_string()])
            .with_tag_query_mode("all")
            .with_limit(10);

        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("my_key"));
        assert!(json.contains("important"));
        assert!(json.contains("tagQueryMode"));

        // Verify skip_serializing_if works
        let minimal = KVStoreQuery::new();
        let json = serde_json::to_string(&minimal).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_kvstore_query_to_json() {
        let query = KVStoreQuery::new().with_key("test").with_limit(5);

        let json = query.to_json();
        assert_eq!(json["key"], "test");
        assert_eq!(json["limit"], 5);
    }

    #[test]
    fn test_kvstore_get_options() {
        let opts = KVStoreGetOptions::new()
            .with_history(true)
            .with_include_token(true)
            .with_service_name("ls_custom");

        assert!(opts.history);
        assert!(opts.include_token);
        assert_eq!(opts.service_name, Some("ls_custom".to_string()));
    }

    #[test]
    fn test_kvstore_set_options() {
        let opts = KVStoreSetOptions::new()
            .with_protocol_id("custom")
            .with_description("Test operation")
            .with_token_amount(100)
            .with_tags(vec!["tag1".to_string()]);

        assert_eq!(opts.protocol_id, Some("custom".to_string()));
        assert_eq!(opts.description, Some("Test operation".to_string()));
        assert_eq!(opts.token_amount, Some(100));
        assert_eq!(opts.tags, Some(vec!["tag1".to_string()]));
    }

    #[test]
    fn test_kvstore_remove_options() {
        let opts = KVStoreRemoveOptions::new()
            .with_protocol_id("custom")
            .with_description("Remove operation");

        assert_eq!(opts.protocol_id, Some("custom".to_string()));
        assert_eq!(opts.description, Some("Remove operation".to_string()));
    }

    #[test]
    fn test_lookup_value_result_not_found() {
        let result = LookupValueResult::not_found("default".to_string());
        assert_eq!(result.value, "default");
        assert!(!result.value_exists);
        assert!(result.outpoints.is_empty());
    }

    #[test]
    fn test_lookup_value_result_found() {
        let result = LookupValueResult::found(
            "my_value".to_string(),
            vec!["txid.0".to_string()],
            Some(vec![1, 2, 3]),
            vec![],
        );
        assert_eq!(result.value, "my_value");
        assert!(result.value_exists);
        assert_eq!(result.outpoints, vec!["txid.0"]);
        assert!(result.input_beef.is_some());
    }

    #[test]
    fn test_kv_protocol_fields() {
        assert_eq!(KvProtocolFields::PROTOCOL_ID, 0);
        assert_eq!(KvProtocolFields::KEY, 1);
        assert_eq!(KvProtocolFields::VALUE, 2);
        assert_eq!(KvProtocolFields::CONTROLLER, 3);
        assert_eq!(KvProtocolFields::TAGS, 4);
        assert_eq!(KvProtocolFields::SIGNATURE, 5);
        assert_eq!(KvProtocolFields::MIN_FIELDS_OLD, 5);
        assert_eq!(KvProtocolFields::MIN_FIELDS_NEW, 6);
    }
}
