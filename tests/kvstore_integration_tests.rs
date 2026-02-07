//! KVStore module integration tests.
//!
//! Tests for the key-value store module including LocalKVStore, GlobalKVStore,
//! KVStoreConfig, and KVStoreInterpreter. Tests use mock wallets to verify
//! the store operations without requiring a live wallet backend.

#![cfg(feature = "kvstore")]

use bsv_sdk::kvstore::{
    KVStoreConfig, KVStoreContext, KVStoreEntry, KVStoreFields, KVStoreGetOptions,
    KVStoreInterpreter, KVStoreQuery, KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
    LocalKVStore,
};
use bsv_sdk::primitives::{to_hex, PrivateKey, PublicKey};
use bsv_sdk::script::templates::PushDrop;
use bsv_sdk::script::LockingScript;
use bsv_sdk::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, Network, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
    SignActionArgs, SignActionResult, VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs,
    VerifySignatureResult, WalletCertificate, WalletInterface, WalletRevealCounterpartyArgs,
    WalletRevealSpecificArgs,
};
use bsv_sdk::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// =============================================================================
// Mock Wallet Implementation
// =============================================================================

/// A comprehensive mock wallet for testing KVStore operations.
/// Provides configurable behavior for success and error cases.
#[derive(Debug)]
struct MockWallet {
    /// If true, list_outputs returns an error.
    list_outputs_error: AtomicBool,
    /// If true, create_action returns an error.
    create_action_error: AtomicBool,
    /// Valid public key for testing.
    public_key_hex: String,
    /// The underlying private key (kept for potential future use).
    #[allow(dead_code)]
    private_key: PrivateKey,
    /// Counter for create_action calls.
    #[allow(dead_code)]
    create_action_count: AtomicU32,
    /// Counter for list_outputs calls.
    #[allow(dead_code)]
    list_outputs_count: AtomicU32,
}

impl MockWallet {
    fn new() -> Self {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();
        let pubkey_hex = to_hex(&pubkey.to_compressed());

        Self {
            list_outputs_error: AtomicBool::new(false),
            create_action_error: AtomicBool::new(false),
            public_key_hex: pubkey_hex,
            private_key: privkey,
            create_action_count: AtomicU32::new(0),
            list_outputs_count: AtomicU32::new(0),
        }
    }

    fn with_list_outputs_error(self) -> Self {
        self.list_outputs_error.store(true, Ordering::SeqCst);
        self
    }

    fn with_create_action_error(self) -> Self {
        self.create_action_error.store(true, Ordering::SeqCst);
        self
    }
}

#[async_trait::async_trait]
impl WalletInterface for MockWallet {
    // Key Operations
    async fn get_public_key(
        &self,
        _args: GetPublicKeyArgs,
        _originator: &str,
    ) -> Result<GetPublicKeyResult> {
        Ok(GetPublicKeyResult {
            public_key: self.public_key_hex.clone(),
        })
    }

    async fn encrypt(&self, args: EncryptArgs, _originator: &str) -> Result<EncryptResult> {
        // Mock encryption: just return the plaintext (no actual encryption)
        Ok(EncryptResult {
            ciphertext: args.plaintext,
        })
    }

    async fn decrypt(&self, args: DecryptArgs, _originator: &str) -> Result<DecryptResult> {
        // Mock decryption: just return the ciphertext (no actual decryption)
        Ok(DecryptResult {
            plaintext: args.ciphertext,
        })
    }

    async fn create_hmac(
        &self,
        _args: CreateHmacArgs,
        _originator: &str,
    ) -> Result<CreateHmacResult> {
        Ok(CreateHmacResult { hmac: [0u8; 32] })
    }

    async fn verify_hmac(
        &self,
        _args: VerifyHmacArgs,
        _originator: &str,
    ) -> Result<VerifyHmacResult> {
        Ok(VerifyHmacResult { valid: true })
    }

    async fn create_signature(
        &self,
        _args: CreateSignatureArgs,
        _originator: &str,
    ) -> Result<CreateSignatureResult> {
        Ok(CreateSignatureResult {
            signature: vec![0u8; 64],
        })
    }

    async fn verify_signature(
        &self,
        _args: VerifySignatureArgs,
        _originator: &str,
    ) -> Result<VerifySignatureResult> {
        Ok(VerifySignatureResult { valid: true })
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: WalletRevealCounterpartyArgs,
        _originator: &str,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: WalletRevealSpecificArgs,
        _originator: &str,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    // Action Operations
    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: &str,
    ) -> Result<CreateActionResult> {
        self.create_action_count.fetch_add(1, Ordering::SeqCst);
        if self.create_action_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("wallet error".to_string()));
        }
        Ok(CreateActionResult {
            txid: Some([0u8; 32]),
            tx: None,
            no_send_change: None,
            send_with_results: None,
            signable_transaction: None,
            input_type: None,
            inputs: None,
            reference_number: None,
        })
    }

    async fn sign_action(
        &self,
        _args: SignActionArgs,
        _originator: &str,
    ) -> Result<SignActionResult> {
        Ok(SignActionResult {
            txid: Some([0u8; 32]),
            tx: None,
            send_with_results: None,
        })
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _originator: &str,
    ) -> Result<AbortActionResult> {
        Ok(AbortActionResult { aborted: true })
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _originator: &str,
    ) -> Result<ListActionsResult> {
        Ok(ListActionsResult {
            actions: vec![],
            total_actions: 0,
        })
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _originator: &str,
    ) -> Result<InternalizeActionResult> {
        Ok(InternalizeActionResult { accepted: true })
    }

    // Output Operations
    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: &str,
    ) -> Result<ListOutputsResult> {
        self.list_outputs_count.fetch_add(1, Ordering::SeqCst);
        if self.list_outputs_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("wallet error".to_string()));
        }
        Ok(ListOutputsResult {
            outputs: vec![],
            total_outputs: 0,
            beef: None,
        })
    }

    async fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
        _originator: &str,
    ) -> Result<RelinquishOutputResult> {
        Ok(RelinquishOutputResult { relinquished: true })
    }

    // Certificate Operations
    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _originator: &str,
    ) -> Result<WalletCertificate> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _originator: &str,
    ) -> Result<ListCertificatesResult> {
        Ok(ListCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _originator: &str,
    ) -> Result<ProveCertificateResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _originator: &str,
    ) -> Result<RelinquishCertificateResult> {
        Ok(RelinquishCertificateResult { relinquished: true })
    }

    // Discovery Operations
    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _originator: &str,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _originator: &str,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    // Status Operations
    async fn is_authenticated(&self, _originator: &str) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(&self, _originator: &str) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _originator: &str) -> Result<GetHeightResult> {
        Ok(GetHeightResult { height: 800000 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _originator: &str,
    ) -> Result<GetHeaderResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn get_network(&self, _originator: &str) -> Result<GetNetworkResult> {
        Ok(GetNetworkResult {
            network: Network::Mainnet,
        })
    }

    async fn get_version(&self, _originator: &str) -> Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: "mock-1.0".to_string(),
        })
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates a test PushDrop token script for KVStore.
fn create_test_token(
    protocol_id: &str,
    key: &str,
    value: &str,
    controller: &PublicKey,
    tags: Option<Vec<String>>,
) -> LockingScript {
    let mut fields = vec![
        protocol_id.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.to_compressed().to_vec(),
    ];

    if let Some(tags) = tags {
        let tags_json = serde_json::to_string(&tags).unwrap();
        fields.push(tags_json.as_bytes().to_vec());
    }

    // Add signature placeholder
    fields.push(vec![0u8; 64]);

    PushDrop::new(controller.clone(), fields).lock()
}

// =============================================================================
// KVStoreConfig Tests
// =============================================================================

#[test]
fn test_kvstore_config_default_values() {
    let config = KVStoreConfig::default();
    assert_eq!(config.protocol_id, "kvstore");
    assert_eq!(config.service_name, "ls_kvstore");
    assert_eq!(config.token_amount, 1);
    assert_eq!(config.topics, vec!["tm_kvstore"]);
    assert!(config.originator.is_none());
    assert!(config.encrypt);
}

#[test]
fn test_kvstore_config_builder_all_fields() {
    let config = KVStoreConfig::new()
        .with_protocol_id("my_protocol")
        .with_service_name("ls_custom")
        .with_token_amount(100)
        .with_topics(vec!["tm_custom".to_string(), "tm_other".to_string()])
        .with_originator("myapp.example.com")
        .with_encrypt(false);

    assert_eq!(config.protocol_id, "my_protocol");
    assert_eq!(config.service_name, "ls_custom");
    assert_eq!(config.token_amount, 100);
    assert_eq!(
        config.topics,
        vec!["tm_custom".to_string(), "tm_other".to_string()]
    );
    assert_eq!(config.originator, Some("myapp.example.com".to_string()));
    assert!(!config.encrypt);
}

#[test]
fn test_kvstore_config_builder_partial() {
    let config = KVStoreConfig::new()
        .with_protocol_id("partial_proto")
        .with_token_amount(50);

    assert_eq!(config.protocol_id, "partial_proto");
    assert_eq!(config.token_amount, 50);
    // Defaults retained
    assert_eq!(config.service_name, "ls_kvstore");
    assert!(config.encrypt);
}

#[test]
fn test_kvstore_config_clone() {
    let config = KVStoreConfig::new()
        .with_protocol_id("cloneable")
        .with_originator("origin");

    let cloned = config.clone();
    assert_eq!(cloned.protocol_id, "cloneable");
    assert_eq!(cloned.originator, Some("origin".to_string()));
}

// =============================================================================
// KVStoreEntry Tests
// =============================================================================

#[test]
fn test_kvstore_entry_creation() {
    let entry = KVStoreEntry::new("my_key", "my_value", "02abc123", "kvstore");
    assert_eq!(entry.key, "my_key");
    assert_eq!(entry.value, "my_value");
    assert_eq!(entry.controller, "02abc123");
    assert_eq!(entry.protocol_id, "kvstore");
    assert!(entry.tags.is_empty());
    assert!(entry.token.is_none());
    assert!(entry.history.is_none());
}

#[test]
fn test_kvstore_entry_with_tags() {
    let tags = vec!["important".to_string(), "user-data".to_string()];
    let entry = KVStoreEntry::new("key", "value", "controller", "proto").with_tags(tags.clone());
    assert_eq!(entry.tags, tags);
}

#[test]
fn test_kvstore_entry_with_token() {
    let token = KVStoreToken::new("abc123def456", 0, 1000);
    let entry = KVStoreEntry::new("key", "value", "controller", "proto").with_token(token);
    assert!(entry.token.is_some());
    let t = entry.token.unwrap();
    assert_eq!(t.txid, "abc123def456");
    assert_eq!(t.output_index, 0);
    assert_eq!(t.satoshis, 1000);
}

#[test]
fn test_kvstore_entry_with_history() {
    let history = vec![
        "old_value".to_string(),
        "middle_value".to_string(),
        "current_value".to_string(),
    ];
    let entry =
        KVStoreEntry::new("key", "current_value", "ctrl", "proto").with_history(history.clone());
    assert_eq!(entry.history, Some(history));
}

#[test]
fn test_kvstore_entry_json_roundtrip() {
    let entry = KVStoreEntry::new("test_key", "test_value", "02abc", "kvstore")
        .with_tags(vec!["tag1".to_string(), "tag2".to_string()]);

    let json = serde_json::to_string(&entry).unwrap();
    let decoded: KVStoreEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.key, entry.key);
    assert_eq!(decoded.value, entry.value);
    assert_eq!(decoded.controller, entry.controller);
    assert_eq!(decoded.protocol_id, entry.protocol_id);
    assert_eq!(decoded.tags, entry.tags);
}

// =============================================================================
// KVStoreToken Tests
// =============================================================================

#[test]
fn test_kvstore_token_creation() {
    let token = KVStoreToken::new("abc123def456789", 2, 500);
    assert_eq!(token.txid, "abc123def456789");
    assert_eq!(token.output_index, 2);
    assert_eq!(token.satoshis, 500);
    assert!(token.beef.is_none());
}

#[test]
fn test_kvstore_token_with_beef() {
    let beef_data = vec![0xbe, 0xef, 0x01, 0x02, 0x03];
    let token = KVStoreToken::new("txid", 0, 1).with_beef(beef_data.clone());
    assert_eq!(token.beef, Some(beef_data));
}

#[test]
fn test_kvstore_token_outpoint_string() {
    let token = KVStoreToken::new("abc123", 5, 100);
    assert_eq!(token.outpoint_string(), "abc123.5");
}

#[test]
fn test_kvstore_token_json_roundtrip() {
    let token = KVStoreToken::new("abc123def456", 0, 1);
    let json = serde_json::to_string(&token).unwrap();

    assert!(json.contains("abc123def456"));
    assert!(json.contains("outputIndex")); // camelCase

    let decoded: KVStoreToken = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.txid, "abc123def456");
    assert_eq!(decoded.output_index, 0);
    assert_eq!(decoded.satoshis, 1);
}

// =============================================================================
// KVStoreQuery Tests
// =============================================================================

#[test]
fn test_kvstore_query_default() {
    let query = KVStoreQuery::default();
    assert!(query.key.is_none());
    assert!(query.controller.is_none());
    assert!(query.protocol_id.is_none());
    assert!(query.tags.is_none());
    assert!(query.tag_query_mode.is_none());
    assert!(query.limit.is_none());
    assert!(query.skip.is_none());
    assert!(query.sort_order.is_none());
}

#[test]
fn test_kvstore_query_builder_all_fields() {
    let query = KVStoreQuery::new()
        .with_key("my_key")
        .with_controller("02abc123def456")
        .with_protocol_id("custom_protocol")
        .with_tags(vec!["tag1".to_string(), "tag2".to_string()])
        .with_tag_query_mode("any")
        .with_limit(100)
        .with_skip(20)
        .with_sort_order("desc");

    assert_eq!(query.key, Some("my_key".to_string()));
    assert_eq!(query.controller, Some("02abc123def456".to_string()));
    assert_eq!(query.protocol_id, Some("custom_protocol".to_string()));
    assert_eq!(
        query.tags,
        Some(vec!["tag1".to_string(), "tag2".to_string()])
    );
    assert_eq!(query.tag_query_mode, Some("any".to_string()));
    assert_eq!(query.limit, Some(100));
    assert_eq!(query.skip, Some(20));
    assert_eq!(query.sort_order, Some("desc".to_string()));
}

#[test]
fn test_kvstore_query_to_json() {
    let query = KVStoreQuery::new()
        .with_key("test_key")
        .with_limit(10)
        .with_controller("02abc");

    let json = query.to_json();
    assert_eq!(json["key"], "test_key");
    assert_eq!(json["limit"], 10);
    assert_eq!(json["controller"], "02abc");
}

#[test]
fn test_kvstore_query_json_omits_none() {
    let query = KVStoreQuery::new();
    let json = serde_json::to_string(&query).unwrap();
    assert_eq!(json, "{}");

    let with_key = KVStoreQuery::new().with_key("only_key");
    let json = serde_json::to_string(&with_key).unwrap();
    assert!(json.contains("key"));
    assert!(!json.contains("controller"));
    assert!(!json.contains("limit"));
}

// =============================================================================
// KVStoreGetOptions Tests
// =============================================================================

#[test]
fn test_kvstore_get_options_default() {
    let opts = KVStoreGetOptions::default();
    assert!(!opts.history);
    assert!(!opts.include_token);
    assert!(opts.service_name.is_none());
}

#[test]
fn test_kvstore_get_options_builder() {
    let opts = KVStoreGetOptions::new()
        .with_history(true)
        .with_include_token(true)
        .with_service_name("ls_custom");

    assert!(opts.history);
    assert!(opts.include_token);
    assert_eq!(opts.service_name, Some("ls_custom".to_string()));
}

// =============================================================================
// KVStoreSetOptions Tests
// =============================================================================

#[test]
fn test_kvstore_set_options_default() {
    let opts = KVStoreSetOptions::default();
    assert!(opts.protocol_id.is_none());
    assert!(opts.description.is_none());
    assert!(opts.token_amount.is_none());
    assert!(opts.tags.is_none());
}

#[test]
fn test_kvstore_set_options_builder() {
    let opts = KVStoreSetOptions::new()
        .with_protocol_id("custom_proto")
        .with_description("Setting a value")
        .with_token_amount(100)
        .with_tags(vec!["urgent".to_string()]);

    assert_eq!(opts.protocol_id, Some("custom_proto".to_string()));
    assert_eq!(opts.description, Some("Setting a value".to_string()));
    assert_eq!(opts.token_amount, Some(100));
    assert_eq!(opts.tags, Some(vec!["urgent".to_string()]));
}

// =============================================================================
// KVStoreRemoveOptions Tests
// =============================================================================

#[test]
fn test_kvstore_remove_options_default() {
    let opts = KVStoreRemoveOptions::default();
    assert!(opts.protocol_id.is_none());
    assert!(opts.description.is_none());
}

#[test]
fn test_kvstore_remove_options_builder() {
    let opts = KVStoreRemoveOptions::new()
        .with_protocol_id("custom_proto")
        .with_description("Removing entry");

    assert_eq!(opts.protocol_id, Some("custom_proto".to_string()));
    assert_eq!(opts.description, Some("Removing entry".to_string()));
}

// =============================================================================
// KVStoreContext Tests
// =============================================================================

#[test]
fn test_kvstore_context_creation() {
    let ctx = KVStoreContext::new("my_key", "my_protocol");
    assert_eq!(ctx.key, "my_key");
    assert_eq!(ctx.protocol_id, "my_protocol");
}

#[test]
fn test_kvstore_context_cache_key() {
    let ctx = KVStoreContext::new("user:123", "app_storage");
    assert_eq!(ctx.cache_key(), "app_storage:user:123");
}

#[test]
fn test_kvstore_context_clone() {
    let ctx = KVStoreContext::new("key", "proto");
    let cloned = ctx.clone();
    assert_eq!(cloned.key, "key");
    assert_eq!(cloned.protocol_id, "proto");
}

// =============================================================================
// KVStoreInterpreter Tests
// =============================================================================

#[test]
fn test_interpreter_extract_basic_token() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert_eq!(entry.key, "my_key");
    assert_eq!(entry.value, "my_value");
    assert_eq!(entry.protocol_id, "kvstore");
    assert!(entry.tags.is_empty());
}

#[test]
fn test_interpreter_extract_token_with_tags() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["important".to_string(), "user-data".to_string()];
    let script = create_test_token("kvstore", "tagged_key", "tagged_value", &pubkey, Some(tags));

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert_eq!(entry.key, "tagged_key");
    assert_eq!(entry.value, "tagged_value");
    assert_eq!(
        entry.tags,
        vec!["important".to_string(), "user-data".to_string()]
    );
}

#[test]
fn test_interpreter_with_matching_context() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "ctx_key", "ctx_value", &pubkey, None);

    let ctx = KVStoreContext::new("ctx_key", "kvstore");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_some());
}

#[test]
fn test_interpreter_with_non_matching_context_key() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "actual_key", "value", &pubkey, None);

    let ctx = KVStoreContext::new("different_key", "kvstore");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_none());
}

#[test]
fn test_interpreter_with_non_matching_context_protocol() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "value", &pubkey, None);

    let ctx = KVStoreContext::new("key", "different_protocol");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_none());
}

#[test]
fn test_interpreter_extract_value() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "extracted_value", &pubkey, None);

    let value = KVStoreInterpreter::extract_value(&script);
    assert_eq!(value, Some("extracted_value".to_string()));
}

#[test]
fn test_interpreter_is_kvstore_token() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // Valid KVStore token
    let valid_script = create_test_token("kvstore", "key", "value", &pubkey, None);
    assert!(KVStoreInterpreter::is_kvstore_token(&valid_script));

    // Invalid: too few fields
    let small_pushdrop = PushDrop::new(pubkey.clone(), vec![b"only".to_vec(), b"two".to_vec()]);
    assert!(!KVStoreInterpreter::is_kvstore_token(
        &small_pushdrop.lock()
    ));
}

#[test]
fn test_interpreter_extract_fields() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["tag1".to_string()];
    let script = create_test_token("my_protocol", "my_key", "my_value", &pubkey, Some(tags));

    let fields = KVStoreInterpreter::extract_fields(&script);
    assert!(fields.is_some());

    let fields = fields.unwrap();
    assert_eq!(fields.protocol_id_string(), Some("my_protocol".to_string()));
    assert_eq!(fields.key_string(), Some("my_key".to_string()));
    assert_eq!(fields.value_string(), Some("my_value".to_string()));
    assert_eq!(fields.controller_hex(), to_hex(&pubkey.to_compressed()));
    assert!(fields.has_tags());
    assert_eq!(fields.tags_vec(), vec!["tag1".to_string()]);
}

#[test]
fn test_kvstore_fields_value_bytes() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("proto", "key", "binary_value", &pubkey, None);
    let fields = KVStoreInterpreter::extract_fields(&script).unwrap();

    assert_eq!(fields.value_bytes(), b"binary_value");
}

#[test]
fn test_kvstore_fields_empty_tags() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // Create a token with empty tags field (new format with empty tags)
    let fields = vec![
        b"proto".to_vec(),
        b"key".to_vec(),
        b"value".to_vec(),
        pubkey.to_compressed().to_vec(),
        vec![],        // Empty tags field
        vec![0u8; 64], // Signature at index 5 for new format
    ];

    let pushdrop = PushDrop::new(pubkey.clone(), fields);
    let script = pushdrop.lock();

    let extracted = KVStoreInterpreter::extract_fields(&script);
    assert!(extracted.is_some());

    let extracted = extracted.unwrap();
    // Empty tags means has_tags returns false
    assert!(!extracted.has_tags());
    assert!(extracted.tags_vec().is_empty());
}

#[test]
fn test_kvstore_fields_single_zero_byte_tags() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // Create a token with single zero byte tags (placeholder for no tags)
    let fields = vec![
        b"proto".to_vec(),
        b"key".to_vec(),
        b"value".to_vec(),
        pubkey.to_compressed().to_vec(),
        vec![0u8],     // Single zero byte tags (no tags marker)
        vec![0u8; 64], // Signature at index 5 for new format
    ];

    let pushdrop = PushDrop::new(pubkey.clone(), fields);
    let script = pushdrop.lock();

    let extracted = KVStoreInterpreter::extract_fields(&script);
    assert!(extracted.is_some());

    let extracted = extracted.unwrap();
    // Single zero byte is treated as no tags
    assert!(!extracted.has_tags());
    assert!(extracted.tags_vec().is_empty());
}

// =============================================================================
// Signature Verification Tests
// =============================================================================

#[test]
fn test_verify_signature_missing() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: pubkey.to_compressed().to_vec(),
        tags: None,
        signature: None,
        locking_public_key: pubkey.clone(),
    };

    // Should return false when signature is missing
    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

#[test]
fn test_verify_signature_empty() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: pubkey.to_compressed().to_vec(),
        tags: None,
        signature: Some(vec![]),
        locking_public_key: pubkey.clone(),
    };

    // Should return false when signature is empty
    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

#[test]
fn test_verify_signature_invalid_bytes() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: pubkey.to_compressed().to_vec(),
        tags: None,
        signature: Some(vec![1, 2, 3, 4, 5]), // Invalid DER signature
        locking_public_key: pubkey.clone(),
    };

    // Should return false for invalid signature
    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

#[test]
fn test_verify_signature_invalid_controller() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: vec![0u8; 33], // Invalid pubkey (all zeros)
        tags: None,
        signature: Some(vec![1, 2, 3, 4]),
        locking_public_key: pubkey,
    };

    // Should return false for invalid controller
    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

// =============================================================================
// LocalKVStore Constructor Tests
// =============================================================================

#[test]
fn test_local_kvstore_new_success() {
    let wallet = MockWallet::new();
    let config = KVStoreConfig::default();

    let result = LocalKVStore::new(wallet, config);
    assert!(result.is_ok());
}

#[test]
fn test_local_kvstore_new_empty_context_fails() {
    let wallet = MockWallet::new();
    let config = KVStoreConfig::new().with_protocol_id("");

    let result = LocalKVStore::new(wallet, config);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreEmptyContext));
}

#[test]
fn test_local_kvstore_new_custom_config() {
    let wallet = MockWallet::new();
    let config = KVStoreConfig::new()
        .with_protocol_id("custom_store")
        .with_token_amount(100)
        .with_originator("test-app");

    let store = LocalKVStore::new(wallet, config).unwrap();
    // Store was created successfully with custom config
    assert!(format!("{:?}", store).contains("LocalKVStore"));
}

// =============================================================================
// LocalKVStore Get Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_get_empty_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("", "default").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_kvstore_get_returns_default_when_not_found() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("nonexistent_key", "my_default_value").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "my_default_value");
}

#[tokio::test]
async fn test_local_kvstore_get_wallet_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("key", "default").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
}

#[tokio::test]
async fn test_local_kvstore_get_entry_empty_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get_entry("", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_kvstore_get_entry_not_found() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get_entry("nonexistent", None).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

// =============================================================================
// LocalKVStore Set Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_set_empty_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("", "value", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_kvstore_set_empty_value_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("key", "", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidValue));
}

#[tokio::test]
async fn test_local_kvstore_set_success() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("my_key", "my_value", None).await;
    assert!(result.is_ok());

    let outpoint = result.unwrap();
    // Should return an outpoint in the format "txid.0"
    assert!(outpoint.contains('.'));
}

#[tokio::test]
async fn test_local_kvstore_set_wallet_error() {
    let wallet = MockWallet::new().with_create_action_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("key", "value", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
}

#[tokio::test]
async fn test_local_kvstore_set_with_options() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let opts = KVStoreSetOptions::new()
        .with_description("Test set operation")
        .with_token_amount(50)
        .with_tags(vec!["test".to_string()]);

    let result = store
        .set("key_with_opts", "value_with_opts", Some(opts))
        .await;
    assert!(result.is_ok());
}

// =============================================================================
// LocalKVStore Remove Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_remove_empty_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_kvstore_remove_not_found_returns_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("nonexistent", None).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_local_kvstore_remove_wallet_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("key", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
}

// =============================================================================
// LocalKVStore Has Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_has_empty_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.has("").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_kvstore_has_not_found() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.has("nonexistent").await;
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

// =============================================================================
// LocalKVStore Keys/List/Count/Clear Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_keys_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.keys().await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_local_kvstore_list_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.list(None).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_local_kvstore_list_with_query() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let query = KVStoreQuery::new().with_key("specific_key").with_limit(10);

    let result = store.list(Some(query)).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_local_kvstore_count_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.count().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[tokio::test]
async fn test_local_kvstore_clear_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.clear().await;
    assert!(result.is_ok());
}

// =============================================================================
// Cross-SDK Compatibility Tests
// =============================================================================

#[test]
fn test_kvstore_config_matches_go_sdk_defaults() {
    // Verify our defaults match the Go SDK
    let config = KVStoreConfig::default();

    // Go SDK uses "kvstore" as default context/protocol_id
    assert_eq!(config.protocol_id, "kvstore");
    // Default token amount is 1 satoshi
    assert_eq!(config.token_amount, 1);
    // Default is to encrypt values
    assert!(config.encrypt);
}

#[test]
fn test_kvstore_entry_json_field_names_match_typescript() {
    // TypeScript SDK uses camelCase field names
    let entry = KVStoreEntry::new("key", "value", "controller", "proto");
    let json = serde_json::to_string(&entry).unwrap();

    // Verify camelCase for protocolId (not protocol_id)
    assert!(json.contains("protocolId"));
    assert!(!json.contains("protocol_id"));
}

#[test]
fn test_kvstore_query_json_field_names_match_typescript() {
    let query = KVStoreQuery::new()
        .with_tag_query_mode("all")
        .with_sort_order("desc");
    let json = serde_json::to_string(&query).unwrap();

    // Verify camelCase
    assert!(json.contains("tagQueryMode"));
    assert!(json.contains("sortOrder"));
}

#[test]
fn test_pushdrop_field_order_matches_spec() {
    // Verify field indices match the KVStore specification by testing the
    // interpreter extracts fields in the correct order
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // Create a token with all fields
    let tags = vec!["tag1".to_string()];
    let script = create_test_token("test_proto", "test_key", "test_value", &pubkey, Some(tags));

    let fields = KVStoreInterpreter::extract_fields(&script).unwrap();

    // Field 0: Protocol ID
    assert_eq!(fields.protocol_id_string(), Some("test_proto".to_string()));
    // Field 1: Key
    assert_eq!(fields.key_string(), Some("test_key".to_string()));
    // Field 2: Value
    assert_eq!(fields.value_string(), Some("test_value".to_string()));
    // Field 3: Controller (33-byte compressed pubkey)
    assert_eq!(fields.controller.len(), 33);
    // Field 4: Tags (present in new format)
    assert!(fields.has_tags());
    assert_eq!(fields.tags_vec(), vec!["tag1".to_string()]);
    // Field 5: Signature (present)
    assert!(fields.signature.is_some());
}

// =============================================================================
// Error Type Tests
// =============================================================================

#[test]
fn test_kvstore_error_types() {
    let empty_context = Error::KvStoreEmptyContext;
    assert!(format!("{}", empty_context).contains("empty"));

    let invalid_key = Error::KvStoreInvalidKey;
    assert!(format!("{}", invalid_key).contains("key"));

    let invalid_value = Error::KvStoreInvalidValue;
    assert!(format!("{}", invalid_value).contains("value"));

    let key_not_found = Error::KvStoreKeyNotFound("test_key".to_string());
    assert!(format!("{}", key_not_found).contains("test_key"));

    let general_error = Error::KvStoreError("custom error".to_string());
    assert!(format!("{}", general_error).contains("custom error"));

    let corrupted = Error::KvStoreCorruptedState("bad state".to_string());
    assert!(format!("{}", corrupted).contains("bad state"));
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

#[test]
fn test_kvstore_entry_with_unicode_values() {
    let entry = KVStoreEntry::new(
        "unicode_key_\u{1F600}",       // Emoji in key
        "value_with_\u{4E2D}\u{6587}", // Chinese characters
        "controller",
        "proto",
    );

    assert_eq!(entry.key, "unicode_key_\u{1F600}");
    assert_eq!(entry.value, "value_with_\u{4E2D}\u{6587}");

    // Verify JSON roundtrip preserves unicode
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: KVStoreEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.key, entry.key);
    assert_eq!(decoded.value, entry.value);
}

#[test]
fn test_kvstore_query_with_large_limit() {
    let query = KVStoreQuery::new().with_limit(u32::MAX).with_skip(u32::MAX);

    assert_eq!(query.limit, Some(u32::MAX));
    assert_eq!(query.skip, Some(u32::MAX));
}

#[test]
fn test_kvstore_token_with_large_values() {
    let large_txid = "a".repeat(64); // 64 hex chars = 32 bytes
    let token = KVStoreToken::new(&large_txid, u32::MAX, u64::MAX);

    assert_eq!(token.txid, large_txid);
    assert_eq!(token.output_index, u32::MAX);
    assert_eq!(token.satoshis, u64::MAX);
}

#[test]
fn test_kvstore_config_empty_topics() {
    let config = KVStoreConfig::new().with_topics(vec![]);
    assert!(config.topics.is_empty());
}

#[test]
fn test_kvstore_entry_empty_tags() {
    let entry = KVStoreEntry::new("key", "value", "ctrl", "proto").with_tags(vec![]);
    assert!(entry.tags.is_empty());
}
