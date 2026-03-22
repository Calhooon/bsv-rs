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
use bsv_sdk::wallet::{Outpoint, WalletOutput};
use bsv_sdk::{Error, Result};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;

// =============================================================================
// Mock Wallet Implementation
// =============================================================================

/// A stored output in the mock wallet.
#[derive(Clone, Debug)]
struct MockOutput {
    /// The locking script bytes.
    locking_script: Vec<u8>,
    /// The satoshi value.
    satoshis: u64,
    /// The basket this output belongs to.
    basket: String,
    /// Tags for this output.
    tags: Vec<String>,
    /// The mock transaction ID (unique per create_action call).
    txid: [u8; 32],
    /// The output index.
    vout: u32,
}

/// A comprehensive mock wallet for testing KVStore operations.
/// Provides configurable behavior for success and error cases.
/// Enhanced to store outputs created by create_action and return
/// them from list_outputs, enabling set/get roundtrip testing.
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
    /// Counter for create_action calls (also used to generate unique txids).
    create_action_count: AtomicU32,
    /// Counter for list_outputs calls.
    #[allow(dead_code)]
    list_outputs_count: AtomicU32,
    /// Stored outputs from create_action calls.
    outputs: Mutex<Vec<MockOutput>>,
}

impl std::fmt::Debug for MockWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockWallet")
            .field("public_key_hex", &self.public_key_hex)
            .field(
                "list_outputs_error",
                &self.list_outputs_error.load(Ordering::SeqCst),
            )
            .field(
                "create_action_error",
                &self.create_action_error.load(Ordering::SeqCst),
            )
            .field(
                "create_action_count",
                &self.create_action_count.load(Ordering::SeqCst),
            )
            .finish()
    }
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
            outputs: Mutex::new(Vec::new()),
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

    /// Generate a unique mock txid from the call counter.
    fn generate_txid(counter: u32) -> [u8; 32] {
        let mut txid = [0u8; 32];
        let bytes = counter.to_le_bytes();
        txid[0..4].copy_from_slice(&bytes);
        // Fill remaining bytes with a pattern for uniqueness
        for i in 4..32 {
            txid[i] = (counter as u8).wrapping_add(i as u8);
        }
        txid
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
        args: CreateActionArgs,
        _originator: &str,
    ) -> Result<CreateActionResult> {
        let counter = self.create_action_count.fetch_add(1, Ordering::SeqCst);
        if self.create_action_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("wallet error".to_string()));
        }

        let txid = Self::generate_txid(counter);

        // Store outputs if present
        if let Some(ref action_outputs) = args.outputs {
            let mut stored = self.outputs.lock().unwrap();

            // If there are inputs, remove the corresponding stored outputs
            // (simulates spending old outputs when updating a key)
            if let Some(ref inputs) = args.inputs {
                for input in inputs {
                    let input_txid_hex = to_hex(&input.outpoint.txid);
                    let input_vout = input.outpoint.vout;
                    stored.retain(|o| {
                        let o_txid_hex = to_hex(&o.txid);
                        !(o_txid_hex == input_txid_hex && o.vout == input_vout)
                    });
                }
            }

            for (idx, output) in action_outputs.iter().enumerate() {
                stored.push(MockOutput {
                    locking_script: output.locking_script.clone(),
                    satoshis: output.satoshis,
                    basket: output.basket.clone().unwrap_or_default(),
                    tags: output.tags.clone().unwrap_or_default(),
                    txid,
                    vout: idx as u32,
                });
            }
        } else if let Some(ref inputs) = args.inputs {
            // Remove only (no new outputs) - this is the remove() path
            let mut stored = self.outputs.lock().unwrap();
            for input in inputs {
                let input_txid_hex = to_hex(&input.outpoint.txid);
                let input_vout = input.outpoint.vout;
                stored.retain(|o| {
                    let o_txid_hex = to_hex(&o.txid);
                    !(o_txid_hex == input_txid_hex && o.vout == input_vout)
                });
            }
        }

        Ok(CreateActionResult {
            txid: Some(txid),
            tx: None,
            no_send_change: None,
            send_with_results: None,
            signable_transaction: None,
            input_type: None,
            inputs: None,
            reference_number: None,
            beef: None,
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
        args: ListOutputsArgs,
        _originator: &str,
    ) -> Result<ListOutputsResult> {
        self.list_outputs_count.fetch_add(1, Ordering::SeqCst);
        if self.list_outputs_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("wallet error".to_string()));
        }

        let stored = self.outputs.lock().unwrap();

        // Filter outputs by basket and tags
        let matching: Vec<&MockOutput> = stored
            .iter()
            .filter(|o| o.basket == args.basket)
            .filter(|o| {
                if let Some(ref required_tags) = args.tags {
                    // All required tags must be present on the output
                    required_tags.iter().all(|t| o.tags.contains(t))
                } else {
                    true // No tag filter
                }
            })
            .collect();

        // Apply limit
        let limited: Vec<&MockOutput> = if let Some(limit) = args.limit {
            matching.into_iter().take(limit as usize).collect()
        } else {
            matching
        };

        let wallet_outputs: Vec<WalletOutput> = limited
            .iter()
            .map(|o| WalletOutput {
                satoshis: o.satoshis,
                locking_script: Some(o.locking_script.clone()),
                spendable: true,
                custom_instructions: None,
                tags: Some(o.tags.clone()),
                outpoint: Outpoint::new(o.txid, o.vout),
                labels: None,
            })
            .collect();

        let total = wallet_outputs.len() as u32;
        Ok(ListOutputsResult {
            outputs: wallet_outputs,
            total_outputs: total,
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

// =============================================================================
// LocalKVStore Batch Operation Tests
// =============================================================================

#[tokio::test]
async fn test_local_batch_set_and_get() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Batch set multiple values (each calls set() under the hood)
    let entries = vec![("key1", "value1"), ("key2", "value2"), ("key3", "value3")];
    let result = store.batch_set(&entries).await;
    assert!(result.is_ok(), "batch_set should succeed: {:?}", result);

    // Batch get them back - with enhanced MockWallet, values should be found
    let keys = vec!["key1", "key2", "key3"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok(), "batch_get should succeed: {:?}", result);

    let values = result.unwrap();
    assert_eq!(values.len(), 3);
    // Enhanced MockWallet stores outputs, so batch_get should find the values
    assert_eq!(values[0], Some("value1".to_string()));
    assert_eq!(values[1], Some("value2".to_string()));
    assert_eq!(values[2], Some("value3".to_string()));
}

#[tokio::test]
async fn test_local_batch_remove() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Batch set then remove
    let entries = vec![("key1", "value1"), ("key2", "value2")];
    store.batch_set(&entries).await.unwrap();

    let keys = vec!["key1", "key2"];
    let result = store.batch_remove(&keys).await;
    assert!(result.is_ok(), "batch_remove should succeed: {:?}", result);
}

#[tokio::test]
async fn test_local_batch_get_missing_keys() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set only key1 - enhanced mock wallet now persists outputs
    store.set("key1", "value1", None).await.unwrap();

    // Batch get key1 (exists), key2 (missing), key3 (missing)
    let keys = vec!["key1", "key2", "key3"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok());

    let values = result.unwrap();
    assert_eq!(values.len(), 3);
    // key1 was set, so it should be found; key2 and key3 were not set
    assert_eq!(values[0], Some("value1".to_string()));
    assert!(values[1].is_none());
    assert!(values[2].is_none());
}

#[tokio::test]
async fn test_local_batch_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Empty batch operations should succeed with no-ops
    let empty_get: Vec<&str> = vec![];
    let result = store.batch_get(&empty_get).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());

    let empty_set: Vec<(&str, &str)> = vec![];
    let result = store.batch_set(&empty_set).await;
    assert!(result.is_ok());

    let empty_remove: Vec<&str> = vec![];
    let result = store.batch_remove(&empty_remove).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_local_batch_get_invalid_key_fails() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // batch_get with an empty key should return KvStoreInvalidKey error
    let keys = vec!["valid_key", ""];
    let result = store.batch_get(&keys).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_batch_set_wallet_error() {
    let wallet = MockWallet::new().with_create_action_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let entries = vec![("key1", "value1"), ("key2", "value2")];
    let result = store.batch_set(&entries).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
}

#[tokio::test]
async fn test_local_batch_remove_wallet_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let keys = vec!["key1", "key2"];
    let result = store.batch_remove(&keys).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
}

#[tokio::test]
async fn test_local_batch_get_single_key() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Single key batch with no prior set should return None
    let keys = vec!["single_key"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok());

    let values = result.unwrap();
    assert_eq!(values.len(), 1);
    assert!(values[0].is_none());

    // Now set it and get again
    store.set("single_key", "single_value", None).await.unwrap();
    let result = store.batch_get(&keys).await.unwrap();
    assert_eq!(result[0], Some("single_value".to_string()));
}

#[tokio::test]
async fn test_local_batch_set_single_entry() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Single entry batch should work
    let entries = vec![("only_key", "only_value")];
    let result = store.batch_set(&entries).await;
    assert!(result.is_ok());
}

// =============================================================================
// Enhanced MockWallet Roundtrip Tests
// =============================================================================

#[tokio::test]
async fn test_local_kvstore_set_get_roundtrip() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set a value
    let outpoint = store.set("greeting", "hello world", None).await;
    assert!(outpoint.is_ok(), "set should succeed: {:?}", outpoint);

    // Get it back
    let value = store.get("greeting", "not_found").await;
    assert!(value.is_ok(), "get should succeed: {:?}", value);
    assert_eq!(value.unwrap(), "hello world");
}

#[tokio::test]
async fn test_local_kvstore_set_overwrite() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set initial value
    store.set("color", "red", None).await.unwrap();
    let v1 = store.get("color", "").await.unwrap();
    assert_eq!(v1, "red");

    // Overwrite with new value
    store.set("color", "blue", None).await.unwrap();
    let v2 = store.get("color", "").await.unwrap();
    assert_eq!(v2, "blue");
}

#[tokio::test]
async fn test_local_kvstore_keys_and_count() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set 3 keys
    store.set("alpha", "1", None).await.unwrap();
    store.set("beta", "2", None).await.unwrap();
    store.set("gamma", "3", None).await.unwrap();

    // Verify count returns 3
    let count = store.count().await.unwrap();
    assert_eq!(count, 3, "Should have 3 entries");
}

#[tokio::test]
async fn test_local_kvstore_remove() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set a key
    store.set("ephemeral", "temporary", None).await.unwrap();

    // Verify it exists
    let exists = store.has("ephemeral").await.unwrap();
    assert!(exists, "Key should exist after set");

    // Remove it
    let removed = store.remove("ephemeral", None).await;
    assert!(removed.is_ok(), "remove should succeed: {:?}", removed);

    // Verify it no longer exists
    let exists_after = store.has("ephemeral").await.unwrap();
    assert!(!exists_after, "Key should not exist after remove");
}

#[tokio::test]
async fn test_local_kvstore_batch_operations() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Batch set 3 entries
    let entries = vec![("x", "10"), ("y", "20"), ("z", "30")];
    store.batch_set(&entries).await.unwrap();

    // Batch get returns all values
    let results = store.batch_get(&["x", "y", "z"]).await.unwrap();
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], Some("10".to_string()));
    assert_eq!(results[1], Some("20".to_string()));
    assert_eq!(results[2], Some("30".to_string()));
}

#[tokio::test]
async fn test_local_kvstore_concurrent_writes() {
    // Verify that multiple sequential writes to the same key don't panic
    // and the final value is the last one written.
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Write 5 values to the same key sequentially
    for i in 0..5 {
        let value = format!("value_{}", i);
        let result = store.set("contested", &value, None).await;
        assert!(result.is_ok(), "Write {} should succeed: {:?}", i, result);
    }

    // The final value should be the last one written
    let final_value = store.get("contested", "").await.unwrap();
    assert_eq!(final_value, "value_4", "Should have the last written value");
}

#[tokio::test]
async fn test_local_kvstore_get_default_when_not_set() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Get a key that was never set should return default
    let value = store.get("never_set", "default_val").await.unwrap();
    assert_eq!(value, "default_val");
}

#[tokio::test]
async fn test_local_kvstore_set_get_special_characters() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Test with special characters in the value
    let special_value = "hello\nworld\ttab\"quotes'apostrophe";
    store.set("special", special_value, None).await.unwrap();

    let retrieved = store.get("special", "").await.unwrap();
    assert_eq!(retrieved, special_value);
}

#[tokio::test]
async fn test_local_kvstore_multiple_independent_keys() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set different keys
    store.set("name", "Alice", None).await.unwrap();
    store.set("age", "30", None).await.unwrap();
    store.set("city", "Zurich", None).await.unwrap();

    // Each key should return its own value
    assert_eq!(store.get("name", "").await.unwrap(), "Alice");
    assert_eq!(store.get("age", "").await.unwrap(), "30");
    assert_eq!(store.get("city", "").await.unwrap(), "Zurich");
}

#[tokio::test]
async fn test_local_kvstore_remove_then_set_again() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Set, remove, then set again
    store.set("reusable", "first", None).await.unwrap();
    assert_eq!(store.get("reusable", "").await.unwrap(), "first");

    store.remove("reusable", None).await.unwrap();
    assert!(!store.has("reusable").await.unwrap());

    store.set("reusable", "second", None).await.unwrap();
    assert_eq!(store.get("reusable", "").await.unwrap(), "second");
}
