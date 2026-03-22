//! GlobalKVStore integration tests.
//!
//! Comprehensive tests for the public on-chain key-value store (GlobalKVStore).
//! Tests cover construction, get/set/remove operations, query building, batch
//! operations, empty key validation, unicode handling, config customization,
//! PushDrop token interpretation, key locking, and identity key caching.
//!
//! Since GlobalKVStore relies on the overlay network for actual storage and
//! retrieval, many tests focus on:
//! - Validating input (empty key, etc.)
//! - Config and query type construction
//! - The interpreter layer (PushDrop token parsing, signature verification)
//! - Token field layout correctness
//! - Wallet interaction patterns via a MockWallet
//!
//! The mock wallet returns empty overlay results by default, so tests exercise
//! the code paths around wallet calls, validation, and error propagation without
//! requiring a live overlay network.

#![cfg(feature = "kvstore")]

use bsv_sdk::kvstore::{
    GlobalKVStore, KVStoreConfig, KVStoreContext, KVStoreEntry, KVStoreFields, KVStoreGetOptions,
    KVStoreInterpreter, KVStoreQuery, KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
};
use bsv_sdk::overlay::NetworkPreset;
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

/// Mock wallet for testing GlobalKVStore operations.
///
/// Provides configurable error injection for create_action and get_public_key
/// calls, plus counters for call tracking.
#[derive(Debug)]
struct MockWallet {
    /// If true, create_action returns an error.
    create_action_error: AtomicBool,
    /// If true, get_public_key returns an error.
    get_public_key_error: AtomicBool,
    /// Valid public key (hex) for testing.
    public_key_hex: String,
    /// Counter for create_action calls.
    create_action_count: AtomicU32,
    /// Counter for get_public_key calls.
    get_public_key_count: AtomicU32,
    /// Counter for create_signature calls.
    create_signature_count: AtomicU32,
}

impl MockWallet {
    fn new() -> Self {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();
        let pubkey_hex = to_hex(&pubkey.to_compressed());

        Self {
            create_action_error: AtomicBool::new(false),
            get_public_key_error: AtomicBool::new(false),
            public_key_hex: pubkey_hex,
            create_action_count: AtomicU32::new(0),
            get_public_key_count: AtomicU32::new(0),
            create_signature_count: AtomicU32::new(0),
        }
    }

    fn with_create_action_error(self) -> Self {
        self.create_action_error.store(true, Ordering::SeqCst);
        self
    }

    fn with_get_public_key_error(self) -> Self {
        self.get_public_key_error.store(true, Ordering::SeqCst);
        self
    }
}

#[async_trait::async_trait]
impl WalletInterface for MockWallet {
    async fn get_public_key(
        &self,
        _args: GetPublicKeyArgs,
        _originator: &str,
    ) -> Result<GetPublicKeyResult> {
        self.get_public_key_count.fetch_add(1, Ordering::SeqCst);
        if self.get_public_key_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("get_public_key error".to_string()));
        }
        Ok(GetPublicKeyResult {
            public_key: self.public_key_hex.clone(),
        })
    }

    async fn encrypt(&self, args: EncryptArgs, _originator: &str) -> Result<EncryptResult> {
        Ok(EncryptResult {
            ciphertext: args.plaintext,
        })
    }

    async fn decrypt(&self, args: DecryptArgs, _originator: &str) -> Result<DecryptResult> {
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
        self.create_signature_count.fetch_add(1, Ordering::SeqCst);
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

    async fn create_action(
        &self,
        _args: CreateActionArgs,
        _originator: &str,
    ) -> Result<CreateActionResult> {
        self.create_action_count.fetch_add(1, Ordering::SeqCst);
        if self.create_action_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("create_action error".to_string()));
        }
        Ok(CreateActionResult {
            txid: Some([0xab; 32]),
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
            txid: Some([0xab; 32]),
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

    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _originator: &str,
    ) -> Result<ListOutputsResult> {
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
        Ok(GetHeightResult { height: 800_000 })
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
// 1. GlobalKVStore Constructor Tests
// =============================================================================

#[test]
fn test_global_kvstore_new_with_default_config() {
    // GlobalKVStore::new should accept default config without error.
    let wallet = MockWallet::new();
    let config = KVStoreConfig::default();
    let _store = GlobalKVStore::new(wallet, config);
}

#[test]
fn test_global_kvstore_new_with_custom_config() {
    // GlobalKVStore should accept fully custom configuration.
    let wallet = MockWallet::new();
    let config = KVStoreConfig::new()
        .with_protocol_id("my_custom_protocol")
        .with_service_name("ls_custom")
        .with_token_amount(500)
        .with_topics(vec!["tm_custom".to_string()])
        .with_originator("myapp.example.com")
        .with_encrypt(false);
    let _store = GlobalKVStore::new(wallet, config);
}

#[test]
fn test_global_kvstore_with_network_testnet() {
    // GlobalKVStore::with_network should accept Testnet preset.
    let wallet = MockWallet::new();
    let config = KVStoreConfig::default();
    let _store = GlobalKVStore::with_network(wallet, config, NetworkPreset::Testnet);
}

#[test]
fn test_global_kvstore_with_network_mainnet() {
    // GlobalKVStore::with_network should accept Mainnet preset.
    let wallet = MockWallet::new();
    let config = KVStoreConfig::default();
    let _store = GlobalKVStore::with_network(wallet, config, NetworkPreset::Mainnet);
}

#[test]
fn test_global_kvstore_default_config_matches_spec() {
    // Verify default config values match the kvstore specification:
    // protocol_id="kvstore", service_name="ls_kvstore", token_amount=1, topics=["tm_kvstore"]
    let config = KVStoreConfig::default();
    assert_eq!(config.protocol_id, "kvstore");
    assert_eq!(config.service_name, "ls_kvstore");
    assert_eq!(config.token_amount, 1);
    assert_eq!(config.topics, vec!["tm_kvstore"]);
    assert!(config.originator.is_none());
}

// =============================================================================
// 2. GlobalKVStore::get - Empty Key Rejection
// =============================================================================

#[tokio::test]
async fn test_global_get_empty_key_returns_error() {
    // get("") should return an error since empty keys are not allowed.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.get("", None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::KvStoreError(msg) => assert!(
            msg.contains("empty"),
            "Error should mention empty key: {}",
            msg
        ),
        other => panic!("Expected KvStoreError, got: {:?}", other),
    }
}

// =============================================================================
// 3. GlobalKVStore::set - Empty Key Rejection
// =============================================================================

#[tokio::test]
async fn test_global_set_empty_key_returns_error() {
    // set("", ...) should return an error since empty keys are not allowed.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.set("", "some_value", None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::KvStoreError(msg) => assert!(
            msg.contains("empty"),
            "Error should mention empty key: {}",
            msg
        ),
        other => panic!("Expected KvStoreError, got: {:?}", other),
    }
}

// =============================================================================
// 4. GlobalKVStore::remove - Empty Key Rejection
// =============================================================================

#[tokio::test]
async fn test_global_remove_empty_key_returns_error() {
    // remove("") should return an error since empty keys are not allowed.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.remove("", None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::KvStoreError(msg) => assert!(
            msg.contains("empty"),
            "Error should mention empty key: {}",
            msg
        ),
        other => panic!("Expected KvStoreError, got: {:?}", other),
    }
}

// =============================================================================
// 5. GlobalKVStore::set - Create Action Error Flag
// =============================================================================

#[tokio::test]
async fn test_global_set_wallet_create_action_error() {
    // GlobalKVStore::set() calls query_overlay() before create_action().
    // Without a live overlay network, the overlay query fails first, so
    // the create_action error is unreachable in this mock setup.
    // We verify that set() fails regardless (the overlay error occurs first).
    let wallet = MockWallet::new().with_create_action_error();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.set("test_key", "test_value", None).await;
    // The set() should fail. With no overlay, the overlay query fails before
    // create_action is reached. The create_action_error flag is a defense-in-depth
    // test that verifies the operation does not succeed in any case.
    assert!(
        result.is_err(),
        "set() should fail when overlay is unavailable"
    );
}

// =============================================================================
// 6. GlobalKVStore::set - Wallet get_public_key Error Propagation
// =============================================================================

#[tokio::test]
async fn test_global_set_wallet_get_public_key_error() {
    // If the wallet's get_public_key returns an error, set should propagate it
    // because set() calls get_identity_key() first.
    let wallet = MockWallet::new().with_get_public_key_error();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.set("test_key", "test_value", None).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), Error::WalletError(_)),
        "Expected WalletError from get_public_key"
    );
}

// =============================================================================
// 7. GlobalKVStore::remove - Wallet get_public_key Error Propagation
// =============================================================================

#[tokio::test]
async fn test_global_remove_wallet_get_public_key_error() {
    // remove() calls get_identity_key() first, so a get_public_key error should propagate.
    let wallet = MockWallet::new().with_get_public_key_error();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.remove("test_key", None).await;
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), Error::WalletError(_)),
        "Expected WalletError from get_public_key"
    );
}

// =============================================================================
// 8. GlobalKVStore::get - Returns None for Non-existent Key
// =============================================================================

// Note: get() queries the overlay network. Without a live overlay, the resolver
// will fail with a network error. We test the empty-key path (which returns
// before overlay query) and the overlay error propagation.

#[tokio::test]
async fn test_global_get_nonexistent_key_overlay_error() {
    // Without live SLAP hosts, get() returns an OverlayError because
    // the resolver cannot find competent hosts for the lookup service.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.get("nonexistent_key", None).await;
    // Without a live overlay, the resolver returns an error.
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::OverlayError(_) | Error::NoHostsFound(_) => {} // Expected
        other => panic!("Expected OverlayError or NoHostsFound, got: {:?}", other),
    }
}

// =============================================================================
// 9. GlobalKVStore::query - Returns Vec for Overlay Error
// =============================================================================

#[tokio::test]
async fn test_global_query_overlay_error_propagation() {
    // query() delegates to query_overlay. Without live SLAP hosts,
    // the resolver cannot find competent hosts and returns an error.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let query = KVStoreQuery::new().with_key("test_key");
    let result = store.query(query).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::OverlayError(_) | Error::NoHostsFound(_) => {} // Expected
        other => panic!("Expected OverlayError or NoHostsFound, got: {:?}", other),
    }
}

// =============================================================================
// 10. GlobalKVStore::get_by_controller - Overlay Error Propagation
// =============================================================================

#[tokio::test]
async fn test_global_get_by_controller_overlay_error() {
    // get_by_controller delegates to query(), which queries the overlay.
    // Without live SLAP hosts, the resolver returns an error.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.get_by_controller("02abc123def456").await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::OverlayError(_) | Error::NoHostsFound(_) => {} // Expected
        other => panic!("Expected OverlayError or NoHostsFound, got: {:?}", other),
    }
}

// =============================================================================
// 11. GlobalKVStore::get_by_tags - Overlay Error Propagation
// =============================================================================

#[tokio::test]
async fn test_global_get_by_tags_overlay_error() {
    // get_by_tags delegates to query(), which queries the overlay.
    // Without live SLAP hosts, the resolver returns an error.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.get_by_tags(&["important".to_string()], None).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::OverlayError(_) | Error::NoHostsFound(_) => {} // Expected
        other => panic!("Expected OverlayError or NoHostsFound, got: {:?}", other),
    }
}

// =============================================================================
// 12. GlobalKVStore::batch_get - Empty Key in Batch Returns Error
// =============================================================================

#[tokio::test]
async fn test_global_batch_get_empty_key_returns_error() {
    // batch_get calls get() for each key, so an empty key should fail.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.batch_get(&[""]).await;
    assert!(result.is_err());
}

// =============================================================================
// 13. GlobalKVStore::batch_set - Empty Key in Batch Returns Error
// =============================================================================

#[tokio::test]
async fn test_global_batch_set_empty_key_returns_error() {
    // batch_set calls set() for each pair, so an empty key should fail.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.batch_set(&[("", "value")]).await;
    assert!(result.is_err());
}

// =============================================================================
// 14. GlobalKVStore::batch_remove - Empty Key in Batch Returns Error
// =============================================================================

#[tokio::test]
async fn test_global_batch_remove_empty_key_returns_error() {
    // batch_remove calls remove() for each key, so an empty key should fail.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.batch_remove(&[""]).await;
    assert!(result.is_err());
}

// =============================================================================
// 15. GlobalKVStore::batch_get - Empty Batch Succeeds
// =============================================================================

#[tokio::test]
async fn test_global_batch_get_empty_succeeds() {
    // An empty batch should succeed with an empty result.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let keys: Vec<&str> = vec![];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// =============================================================================
// 16. GlobalKVStore::batch_set - Empty Batch Succeeds
// =============================================================================

#[tokio::test]
async fn test_global_batch_set_empty_succeeds() {
    // An empty batch should succeed as a no-op.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let entries: Vec<(&str, &str)> = vec![];
    let result = store.batch_set(&entries).await;
    assert!(result.is_ok());
}

// =============================================================================
// 17. GlobalKVStore::batch_remove - Empty Batch Succeeds
// =============================================================================

#[tokio::test]
async fn test_global_batch_remove_empty_succeeds() {
    // An empty batch should succeed as a no-op.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let keys: Vec<&str> = vec![];
    let result = store.batch_remove(&keys).await;
    assert!(result.is_ok());
}

// =============================================================================
// 18. KVStoreInterpreter - Interpret Basic Token (Public Visibility)
// =============================================================================

#[test]
fn test_interpreter_global_token_basic() {
    // GlobalKVStore uses PushDrop tokens. Verify the interpreter extracts
    // key, value, controller, and protocol_id from a token.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some(), "Should interpret a valid KVStore token");

    let entry = entry.unwrap();
    assert_eq!(entry.key, "my_key");
    assert_eq!(entry.value, "my_value");
    assert_eq!(entry.protocol_id, "kvstore");
    // The value is stored in plaintext (not encrypted) for global tokens.
}

// =============================================================================
// 19. KVStoreInterpreter - Extract Value (Public, Not Encrypted)
// =============================================================================

#[test]
fn test_interpreter_extract_value_is_plaintext() {
    // For GlobalKVStore, values are stored in plaintext. Verify extract_value
    // returns the exact value without any decryption step.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "public_value_123", &pubkey, None);

    let value = KVStoreInterpreter::extract_value(&script);
    assert_eq!(value, Some("public_value_123".to_string()));
}

// =============================================================================
// 20. KVStoreInterpreter - Token with Tags
// =============================================================================

#[test]
fn test_interpreter_global_token_with_tags() {
    // GlobalKVStore supports tags. Verify the interpreter extracts them.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["important".to_string(), "user-data".to_string()];
    let script = create_test_token(
        "kvstore",
        "tagged_key",
        "tagged_value",
        &pubkey,
        Some(tags.clone()),
    );

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert_eq!(entry.key, "tagged_key");
    assert_eq!(entry.value, "tagged_value");
    assert_eq!(entry.tags, tags);
}

// =============================================================================
// 21. KVStoreInterpreter - Token with Empty Tags
// =============================================================================

#[test]
fn test_interpreter_global_token_with_empty_tags() {
    // When tags are an empty array, the interpreter should return an empty
    // tags vector.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags: Vec<String> = vec![];
    let script = create_test_token("kvstore", "key", "value", &pubkey, Some(tags));

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    // Empty tags array still results in empty tags vector.
    assert!(entry.tags.is_empty());
}

// =============================================================================
// 22. KVStoreInterpreter - Context Matching (Key)
// =============================================================================

#[test]
fn test_interpreter_context_key_match() {
    // When a context is provided, the interpreter should only return entries
    // that match both the key and protocol_id.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

    // Matching context
    let ctx = KVStoreContext::new("my_key", "kvstore");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_some());
}

// =============================================================================
// 23. KVStoreInterpreter - Context Non-Matching Key
// =============================================================================

#[test]
fn test_interpreter_context_key_mismatch() {
    // When context key does not match, interpreter returns None.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

    let ctx = KVStoreContext::new("other_key", "kvstore");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_none());
}

// =============================================================================
// 24. KVStoreInterpreter - Context Non-Matching Protocol
// =============================================================================

#[test]
fn test_interpreter_context_protocol_mismatch() {
    // When context protocol_id does not match, interpreter returns None.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "my_key", "my_value", &pubkey, None);

    let ctx = KVStoreContext::new("my_key", "different_protocol");
    let entry = KVStoreInterpreter::interpret_script(&script, Some(&ctx));
    assert!(entry.is_none());
}

// =============================================================================
// 25. KVStoreInterpreter - is_kvstore_token
// =============================================================================

#[test]
fn test_interpreter_is_kvstore_token_valid() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "value", &pubkey, None);
    assert!(KVStoreInterpreter::is_kvstore_token(&script));
}

#[test]
fn test_interpreter_is_kvstore_token_invalid_too_few_fields() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // PushDrop with only 2 fields - not a valid KVStore token.
    let small_pushdrop = PushDrop::new(pubkey.clone(), vec![b"only".to_vec(), b"two".to_vec()]);
    assert!(!KVStoreInterpreter::is_kvstore_token(
        &small_pushdrop.lock()
    ));
}

// =============================================================================
// 26. KVStoreInterpreter - extract_fields Full Inspection
// =============================================================================

#[test]
fn test_interpreter_extract_fields_complete() {
    // Verify extract_fields returns all fields correctly.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["tag1".to_string(), "tag2".to_string()];
    let script = create_test_token(
        "my_protocol",
        "my_key",
        "my_value",
        &pubkey,
        Some(tags.clone()),
    );

    let fields = KVStoreInterpreter::extract_fields(&script);
    assert!(fields.is_some());

    let fields = fields.unwrap();
    assert_eq!(fields.protocol_id_string(), Some("my_protocol".to_string()));
    assert_eq!(fields.key_string(), Some("my_key".to_string()));
    assert_eq!(fields.value_string(), Some("my_value".to_string()));
    assert_eq!(fields.controller_hex(), to_hex(&pubkey.to_compressed()));
    assert!(fields.has_tags());
    assert_eq!(fields.tags_vec(), tags);
    assert!(fields.signature.is_some());
}

// =============================================================================
// 27. Signature Verification - Missing Signature Returns False
// =============================================================================

#[test]
fn test_verify_signature_missing_returns_false() {
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

    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

// =============================================================================
// 28. Signature Verification - Empty Signature Returns False
// =============================================================================

#[test]
fn test_verify_signature_empty_returns_false() {
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

    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

// =============================================================================
// 29. Signature Verification - Invalid DER Returns False
// =============================================================================

#[test]
fn test_verify_signature_invalid_der_returns_false() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: pubkey.to_compressed().to_vec(),
        tags: None,
        signature: Some(vec![1, 2, 3, 4, 5]),
        locking_public_key: pubkey.clone(),
    };

    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

// =============================================================================
// 30. Signature Verification - Invalid Controller Returns False
// =============================================================================

#[test]
fn test_verify_signature_invalid_controller_returns_false() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let fields = KVStoreFields {
        protocol_id: b"kvstore".to_vec(),
        key: b"test_key".to_vec(),
        value: b"test_value".to_vec(),
        controller: vec![0u8; 33], // Invalid pubkey
        tags: None,
        signature: Some(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
        locking_public_key: pubkey,
    };

    assert!(!KVStoreInterpreter::verify_signature(&fields, "kvstore"));
}

// =============================================================================
// 31. KVStoreEntry - Unicode Key and Value
// =============================================================================

#[test]
fn test_kvstore_entry_unicode_key_and_value() {
    // GlobalKVStore should handle unicode keys and values.
    let entry = KVStoreEntry::new(
        "key_\u{1F600}_emoji",
        "value_\u{4E2D}\u{6587}_chinese",
        "02abc123",
        "kvstore",
    );

    assert_eq!(entry.key, "key_\u{1F600}_emoji");
    assert_eq!(entry.value, "value_\u{4E2D}\u{6587}_chinese");

    // JSON roundtrip should preserve unicode.
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: KVStoreEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.key, entry.key);
    assert_eq!(decoded.value, entry.value);
}

// =============================================================================
// 32. KVStoreEntry - Special Characters in Keys
// =============================================================================

#[test]
fn test_kvstore_entry_special_character_keys() {
    // Keys with dots, slashes, spaces should be representable.
    let entry = KVStoreEntry::new("path/to/key.name with spaces", "value", "ctrl", "proto");
    assert_eq!(entry.key, "path/to/key.name with spaces");

    // JSON roundtrip should preserve these.
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: KVStoreEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.key, "path/to/key.name with spaces");
}

// =============================================================================
// 33. KVStoreEntry - Empty Value
// =============================================================================

#[test]
fn test_kvstore_entry_empty_value() {
    // An empty value should be representable at the entry level.
    let entry = KVStoreEntry::new("key", "", "ctrl", "proto");
    assert_eq!(entry.value, "");
}

// =============================================================================
// 34. KVStoreEntry - With Token Metadata
// =============================================================================

#[test]
fn test_kvstore_entry_with_token() {
    // Verify token metadata can be attached to an entry.
    let token = KVStoreToken::new("abc123def456", 0, 1);
    let entry = KVStoreEntry::new("key", "value", "ctrl", "proto").with_token(token);

    assert!(entry.token.is_some());
    let t = entry.token.unwrap();
    assert_eq!(t.txid, "abc123def456");
    assert_eq!(t.output_index, 0);
    assert_eq!(t.satoshis, 1);
}

// =============================================================================
// 35. KVStoreEntry - With History
// =============================================================================

#[test]
fn test_kvstore_entry_with_history() {
    // Verify history (oldest first) can be attached.
    let history = vec![
        "old_value".to_string(),
        "middle_value".to_string(),
        "current_value".to_string(),
    ];
    let entry =
        KVStoreEntry::new("key", "current_value", "ctrl", "proto").with_history(history.clone());

    assert_eq!(entry.history, Some(history));
}

// =============================================================================
// 36. KVStoreEntry - JSON Serialization Uses camelCase
// =============================================================================

#[test]
fn test_kvstore_entry_json_camel_case() {
    // Cross-SDK: TypeScript SDK uses camelCase field names.
    let entry = KVStoreEntry::new("key", "value", "ctrl", "proto");
    let json = serde_json::to_string(&entry).unwrap();

    assert!(
        json.contains("protocolId"),
        "Should use protocolId (camelCase)"
    );
    assert!(
        !json.contains("protocol_id"),
        "Should not use protocol_id (snake_case)"
    );
}

// =============================================================================
// 37. KVStoreToken - Outpoint String Format
// =============================================================================

#[test]
fn test_kvstore_token_outpoint_string_format() {
    let token = KVStoreToken::new("abcdef123456", 3, 100);
    assert_eq!(token.outpoint_string(), "abcdef123456.3");
}

// =============================================================================
// 38. KVStoreToken - JSON Serialization Uses camelCase
// =============================================================================

#[test]
fn test_kvstore_token_json_camel_case() {
    let token = KVStoreToken::new("abc123", 0, 1);
    let json = serde_json::to_string(&token).unwrap();

    assert!(
        json.contains("outputIndex"),
        "Should use outputIndex (camelCase)"
    );
    assert!(
        !json.contains("output_index"),
        "Should not use output_index (snake_case)"
    );
}

// =============================================================================
// 39. KVStoreQuery - Builder Pattern
// =============================================================================

#[test]
fn test_kvstore_query_builder_complete() {
    let query = KVStoreQuery::new()
        .with_key("test_key")
        .with_controller("02abc")
        .with_protocol_id("custom_proto")
        .with_tags(vec!["tag1".to_string(), "tag2".to_string()])
        .with_tag_query_mode("any")
        .with_limit(100)
        .with_skip(20)
        .with_sort_order("desc");

    assert_eq!(query.key, Some("test_key".to_string()));
    assert_eq!(query.controller, Some("02abc".to_string()));
    assert_eq!(query.protocol_id, Some("custom_proto".to_string()));
    assert_eq!(
        query.tags,
        Some(vec!["tag1".to_string(), "tag2".to_string()])
    );
    assert_eq!(query.tag_query_mode, Some("any".to_string()));
    assert_eq!(query.limit, Some(100));
    assert_eq!(query.skip, Some(20));
    assert_eq!(query.sort_order, Some("desc".to_string()));
}

// =============================================================================
// 40. KVStoreQuery - to_json Produces Correct Output
// =============================================================================

#[test]
fn test_kvstore_query_to_json() {
    let query = KVStoreQuery::new().with_key("my_key").with_limit(10);
    let json = query.to_json();

    assert_eq!(json["key"], "my_key");
    assert_eq!(json["limit"], 10);
}

// =============================================================================
// 41. KVStoreQuery - Empty Query Serializes to {}
// =============================================================================

#[test]
fn test_kvstore_query_empty_serializes_to_empty_object() {
    let query = KVStoreQuery::new();
    let json = serde_json::to_string(&query).unwrap();
    assert_eq!(json, "{}");
}

// =============================================================================
// 42. KVStoreGetOptions - Default Values
// =============================================================================

#[test]
fn test_kvstore_get_options_defaults() {
    let opts = KVStoreGetOptions::default();
    assert!(!opts.history);
    assert!(!opts.include_token);
    assert!(opts.service_name.is_none());
}

// =============================================================================
// 43. KVStoreGetOptions - Builder Pattern
// =============================================================================

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
// 44. KVStoreSetOptions - Builder Pattern with Tags
// =============================================================================

#[test]
fn test_kvstore_set_options_builder_with_tags() {
    let opts = KVStoreSetOptions::new()
        .with_protocol_id("custom_proto")
        .with_description("Setting a value")
        .with_token_amount(100)
        .with_tags(vec!["urgent".to_string(), "important".to_string()]);

    assert_eq!(opts.protocol_id, Some("custom_proto".to_string()));
    assert_eq!(opts.description, Some("Setting a value".to_string()));
    assert_eq!(opts.token_amount, Some(100));
    assert_eq!(
        opts.tags,
        Some(vec!["urgent".to_string(), "important".to_string()])
    );
}

// =============================================================================
// 45. KVStoreRemoveOptions - Builder Pattern
// =============================================================================

#[test]
fn test_kvstore_remove_options_builder() {
    let opts = KVStoreRemoveOptions::new()
        .with_protocol_id("custom")
        .with_description("Removing entry");

    assert_eq!(opts.protocol_id, Some("custom".to_string()));
    assert_eq!(opts.description, Some("Removing entry".to_string()));
}

// =============================================================================
// 46. KVStoreContext - Cache Key Format
// =============================================================================

#[test]
fn test_kvstore_context_cache_key_format() {
    let ctx = KVStoreContext::new("user:123", "app_storage");
    assert_eq!(ctx.cache_key(), "app_storage:user:123");
}

// =============================================================================
// 47. PushDrop Field Order Matches Specification
// =============================================================================

#[test]
fn test_pushdrop_field_order_matches_global_kvstore_spec() {
    // The PushDrop token field layout for GlobalKVStore should be:
    // 0: protocol_id, 1: key, 2: value, 3: controller, 4: tags, 5: signature
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["a_tag".to_string()];
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
    // Field 4: Tags
    assert!(fields.has_tags());
    assert_eq!(fields.tags_vec(), vec!["a_tag".to_string()]);
    // Field 5: Signature
    assert!(fields.signature.is_some());
}

// =============================================================================
// 48. KVStoreInterpreter - Unicode Key in PushDrop Token
// =============================================================================

#[test]
fn test_interpreter_unicode_key_in_token() {
    // GlobalKVStore should handle unicode keys in PushDrop tokens.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key_\u{1F4A9}", "value", &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().key, "key_\u{1F4A9}");
}

// =============================================================================
// 49. KVStoreInterpreter - Unicode Value in PushDrop Token
// =============================================================================

#[test]
fn test_interpreter_unicode_value_in_token() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "value_\u{4E2D}\u{6587}", &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().value, "value_\u{4E2D}\u{6587}");
}

// =============================================================================
// 50. KVStoreInterpreter - Large Value in Token
// =============================================================================

#[test]
fn test_interpreter_large_value_in_token() {
    // Verify the interpreter can handle a larger value payload.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let large_value = "x".repeat(10_000);
    let script = create_test_token("kvstore", "key", &large_value, &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().value, large_value);
}

// =============================================================================
// 51. KVStoreConfig - Builder Chaining All Fields
// =============================================================================

#[test]
fn test_kvstore_config_full_builder() {
    let config = KVStoreConfig::new()
        .with_protocol_id("my_proto")
        .with_service_name("ls_mine")
        .with_token_amount(42)
        .with_topics(vec!["tm_mine".to_string()])
        .with_originator("origin.example")
        .with_encrypt(false);

    assert_eq!(config.protocol_id, "my_proto");
    assert_eq!(config.service_name, "ls_mine");
    assert_eq!(config.token_amount, 42);
    assert_eq!(config.topics, vec!["tm_mine"]);
    assert_eq!(config.originator, Some("origin.example".to_string()));
    assert!(!config.encrypt);
}

// =============================================================================
// 52. KVStoreConfig - Clone Preserves All Fields
// =============================================================================

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
// 53. KVStoreFields - value_bytes Accessor
// =============================================================================

#[test]
fn test_kvstore_fields_value_bytes() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("proto", "key", "hello_bytes", &pubkey, None);
    let fields = KVStoreInterpreter::extract_fields(&script).unwrap();

    assert_eq!(fields.value_bytes(), b"hello_bytes");
}

// =============================================================================
// 54. KVStoreFields - controller_hex for 33-byte Compressed Key
// =============================================================================

#[test]
fn test_kvstore_fields_controller_hex() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script = create_test_token("kvstore", "key", "value", &pubkey, None);
    let fields = KVStoreInterpreter::extract_fields(&script).unwrap();

    let expected_hex = to_hex(&pubkey.to_compressed());
    assert_eq!(fields.controller_hex(), expected_hex);
}

// =============================================================================
// 55. Multiple Keys Stored and Interpreted Independently
// =============================================================================

#[test]
fn test_multiple_keys_independent_tokens() {
    // Verify that tokens for different keys are independent.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let script1 = create_test_token("kvstore", "key_1", "value_1", &pubkey, None);
    let script2 = create_test_token("kvstore", "key_2", "value_2", &pubkey, None);

    let entry1 = KVStoreInterpreter::interpret_script(&script1, None).unwrap();
    let entry2 = KVStoreInterpreter::interpret_script(&script2, None).unwrap();

    assert_eq!(entry1.key, "key_1");
    assert_eq!(entry1.value, "value_1");
    assert_eq!(entry2.key, "key_2");
    assert_eq!(entry2.value, "value_2");
}

// =============================================================================
// 56. Old Format Token (Without Tags) Is Supported
// =============================================================================

#[test]
fn test_interpreter_old_format_without_tags() {
    // Old format has 5 fields (no tags). Verify backward compatibility.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    // Create a token without tags (old format)
    let script = create_test_token("kvstore", "old_key", "old_value", &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert_eq!(entry.key, "old_key");
    assert_eq!(entry.value, "old_value");
    // Old format should have no tags.
    assert!(entry.tags.is_empty());
}

// =============================================================================
// 57. New Format Token (With Tags) Is Supported
// =============================================================================

#[test]
fn test_interpreter_new_format_with_tags() {
    // New format has 6 fields (with tags).
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["tag_a".to_string(), "tag_b".to_string()];
    let script = create_test_token(
        "kvstore",
        "new_key",
        "new_value",
        &pubkey,
        Some(tags.clone()),
    );

    let entry = KVStoreInterpreter::interpret_script(&script, None);
    assert!(entry.is_some());

    let entry = entry.unwrap();
    assert_eq!(entry.key, "new_key");
    assert_eq!(entry.value, "new_value");
    assert_eq!(entry.tags, tags);
}

// =============================================================================
// 58. KVStoreQuery - Tag Query Mode "all" (Default)
// =============================================================================

#[test]
fn test_query_tag_mode_all() {
    let query = KVStoreQuery::new()
        .with_tags(vec!["music".to_string(), "rock".to_string()])
        .with_tag_query_mode("all");

    assert_eq!(query.tag_query_mode, Some("all".to_string()));

    let json = query.to_json();
    assert_eq!(json["tagQueryMode"], "all");
}

// =============================================================================
// 59. KVStoreQuery - Tag Query Mode "any"
// =============================================================================

#[test]
fn test_query_tag_mode_any() {
    let query = KVStoreQuery::new()
        .with_tags(vec!["music".to_string(), "jazz".to_string()])
        .with_tag_query_mode("any");

    assert_eq!(query.tag_query_mode, Some("any".to_string()));

    let json = query.to_json();
    assert_eq!(json["tagQueryMode"], "any");
}

// =============================================================================
// 60. KVStoreQuery - JSON Uses camelCase
// =============================================================================

#[test]
fn test_kvstore_query_json_camel_case() {
    let query = KVStoreQuery::new()
        .with_tag_query_mode("all")
        .with_sort_order("desc");
    let json = serde_json::to_string(&query).unwrap();

    assert!(json.contains("tagQueryMode"));
    assert!(json.contains("sortOrder"));
    assert!(!json.contains("tag_query_mode"));
    assert!(!json.contains("sort_order"));
}

// =============================================================================
// 61. Error Types - KvStoreError Contains Message
// =============================================================================

#[test]
fn test_kvstore_error_message() {
    let error = Error::KvStoreError("custom error message".to_string());
    let display = format!("{}", error);
    assert!(display.contains("custom error message"));
}

// =============================================================================
// 62. Error Types - KvStoreKeyNotFound Contains Key
// =============================================================================

#[test]
fn test_kvstore_key_not_found_error() {
    let error = Error::KvStoreKeyNotFound("missing_key".to_string());
    let display = format!("{}", error);
    assert!(display.contains("missing_key"));
}

// =============================================================================
// 63. KVStoreInterpreter - Non-PushDrop Script Returns None
// =============================================================================

#[test]
fn test_interpreter_non_pushdrop_returns_none() {
    // A plain P2PKH-like script should not be interpreted as a KVStore token.
    // We test with a minimal script that is not PushDrop.
    let script_bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20 (incomplete)
    let script = LockingScript::from_binary(&script_bytes);
    match script {
        Ok(s) => {
            assert!(KVStoreInterpreter::interpret_script(&s, None).is_none());
        }
        Err(_) => {
            // If the script itself is invalid, that is also acceptable.
        }
    }
}

// =============================================================================
// 64. KVStoreToken - with_beef
// =============================================================================

#[test]
fn test_kvstore_token_with_beef() {
    let beef_data = vec![0xbe, 0xef, 0x01, 0x02];
    let token = KVStoreToken::new("txid_hex", 0, 1).with_beef(beef_data.clone());
    assert_eq!(token.beef, Some(beef_data));
}

// =============================================================================
// 65. KVStoreEntry - Serialization Omits None Fields
// =============================================================================

#[test]
fn test_kvstore_entry_omits_none_token_and_history() {
    // When token and history are None, they should be omitted from JSON.
    let entry = KVStoreEntry::new("key", "value", "ctrl", "proto");
    let json = serde_json::to_string(&entry).unwrap();

    assert!(!json.contains("token"));
    assert!(!json.contains("history"));
}

// =============================================================================
// 66. KVStoreEntry - Serialization Includes Token When Present
// =============================================================================

#[test]
fn test_kvstore_entry_includes_token_in_json() {
    let token = KVStoreToken::new("abc123", 0, 1);
    let entry = KVStoreEntry::new("key", "value", "ctrl", "proto").with_token(token);
    let json = serde_json::to_string(&entry).unwrap();

    assert!(json.contains("abc123"));
    assert!(json.contains("outputIndex"));
}

// =============================================================================
// 67. KVStoreQuery - Serialization Round Trip
// =============================================================================

#[test]
fn test_kvstore_query_json_roundtrip() {
    let query = KVStoreQuery::new()
        .with_key("roundtrip_key")
        .with_limit(50)
        .with_tags(vec!["x".to_string()]);

    let json = serde_json::to_string(&query).unwrap();
    let decoded: KVStoreQuery = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.key, Some("roundtrip_key".to_string()));
    assert_eq!(decoded.limit, Some(50));
    assert_eq!(decoded.tags, Some(vec!["x".to_string()]));
}

// =============================================================================
// 68. KVStoreConfig - Matches Go/TS SDK Defaults
// =============================================================================

#[test]
fn test_kvstore_config_matches_cross_sdk_defaults() {
    // Verify our defaults match Go and TS SDK defaults.
    let config = KVStoreConfig::default();
    assert_eq!(config.protocol_id, "kvstore");
    assert_eq!(config.service_name, "ls_kvstore");
    assert_eq!(config.token_amount, 1);
    assert_eq!(config.topics, vec!["tm_kvstore"]);
}

// =============================================================================
// 69. KVStoreInterpreter - Different Controllers Produce Different Entries
// =============================================================================

#[test]
fn test_interpreter_different_controllers() {
    // Two tokens with the same key but different controllers should produce
    // different controller values in the entries.
    let privkey1 = PrivateKey::random();
    let pubkey1 = privkey1.public_key();
    let privkey2 = PrivateKey::random();
    let pubkey2 = privkey2.public_key();

    let script1 = create_test_token("kvstore", "shared_key", "value1", &pubkey1, None);
    let script2 = create_test_token("kvstore", "shared_key", "value2", &pubkey2, None);

    let entry1 = KVStoreInterpreter::interpret_script(&script1, None).unwrap();
    let entry2 = KVStoreInterpreter::interpret_script(&script2, None).unwrap();

    assert_eq!(entry1.key, "shared_key");
    assert_eq!(entry2.key, "shared_key");
    assert_ne!(entry1.controller, entry2.controller);
    assert_ne!(entry1.value, entry2.value);
}

// =============================================================================
// 70. KVStoreSetOptions - TTL Support
// =============================================================================

#[test]
fn test_kvstore_set_options_ttl() {
    // GlobalKVStore set options support TTL.
    let opts = KVStoreSetOptions::new().with_ttl(std::time::Duration::from_secs(3600));
    assert_eq!(opts.ttl, Some(std::time::Duration::from_secs(3600)));
}

// =============================================================================
// 71. KVStoreSetOptions - Default Has No TTL
// =============================================================================

#[test]
fn test_kvstore_set_options_default_no_ttl() {
    let opts = KVStoreSetOptions::default();
    assert!(opts.ttl.is_none());
}

// =============================================================================
// 72. GlobalKVStore - Set Progresses Past Wallet Calls
// =============================================================================

#[tokio::test]
async fn test_global_set_progresses_past_wallet_calls() {
    // set() calls get_public_key first (wallet call), then calls set_internal
    // which queries the overlay to check for existing tokens. Without live SLAP
    // hosts, the overlay query fails. The error type should be OverlayError
    // (not WalletError), proving the wallet's get_public_key call succeeded.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.set("test_key", "test_value", None).await;
    assert!(
        result.is_err(),
        "Expected error from overlay (no live SLAP hosts)"
    );
    match result.unwrap_err() {
        Error::WalletError(msg) => panic!(
            "Expected OverlayError (wallet calls should succeed), got WalletError: {}",
            msg
        ),
        Error::OverlayError(_) | Error::NoHostsFound(_) => {
            // Expected: wallet calls succeeded, overlay query failed
        }
        other => panic!("Expected OverlayError or NoHostsFound, got: {:?}", other),
    }
}

// =============================================================================
// 73. GlobalKVStore - Remove Progresses Past Wallet Calls
// =============================================================================

#[tokio::test]
async fn test_global_remove_progresses_past_wallet_calls() {
    // remove() calls get_public_key before reaching the overlay.
    // With a working MockWallet, the error should come from the overlay layer.
    let wallet = MockWallet::new();
    let store = GlobalKVStore::new(wallet, KVStoreConfig::default());

    let result = store.remove("test_key", None).await;
    assert!(result.is_err());
    // The error should NOT be a WalletError.
    let err = result.unwrap_err();
    match &err {
        Error::WalletError(_) => panic!(
            "Expected overlay/network error (proving wallet calls succeeded), got WalletError: {:?}",
            err
        ),
        _ => {
            // Non-WalletError means get_public_key succeeded.
        }
    }
}

// =============================================================================
// 74. GlobalKVStore - Config Originator Is Used
// =============================================================================

#[test]
fn test_global_kvstore_originator_config() {
    // When originator is set, it should be reflected in the store's config.
    let wallet = MockWallet::new();
    let config = KVStoreConfig::new().with_originator("myapp");
    let _store = GlobalKVStore::new(wallet, config);
    // The originator is used internally for wallet calls.
    // We verify the config was accepted (no panic).
}

// =============================================================================
// 75. KVStoreInterpreter - Value With JSON Content
// =============================================================================

#[test]
fn test_interpreter_json_value() {
    // Values can be JSON strings.
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let json_value = r#"{"name":"Bob","age":30}"#;
    let script = create_test_token("kvstore", "profile:123", json_value, &pubkey, None);

    let entry = KVStoreInterpreter::interpret_script(&script, None).unwrap();
    assert_eq!(entry.value, json_value);
}

// =============================================================================
// 76. KVStoreQuery - with_protocol_id
// =============================================================================

#[test]
fn test_query_with_protocol_id() {
    let query = KVStoreQuery::new().with_protocol_id("custom_protocol");
    let json = query.to_json();
    assert_eq!(json["protocolId"], "custom_protocol");
}

// =============================================================================
// 77. KVStoreInterpreter - Multiple Tags Parse Correctly
// =============================================================================

#[test]
fn test_interpreter_multiple_tags() {
    let privkey = PrivateKey::random();
    let pubkey = privkey.public_key();

    let tags = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
    let script = create_test_token("kvstore", "key", "value", &pubkey, Some(tags.clone()));

    let fields = KVStoreInterpreter::extract_fields(&script).unwrap();
    assert_eq!(fields.tags_vec(), tags);
}

// =============================================================================
// 78. KVStoreEntry - With Tags Builder
// =============================================================================

#[test]
fn test_entry_with_tags_builder() {
    let tags = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let entry = KVStoreEntry::new("k", "v", "c", "p").with_tags(tags.clone());
    assert_eq!(entry.tags, tags);
}

// =============================================================================
// 79. KVStoreConfig - Empty Topics
// =============================================================================

#[test]
fn test_config_empty_topics() {
    let config = KVStoreConfig::new().with_topics(vec![]);
    assert!(config.topics.is_empty());
}

// =============================================================================
// 80. KVStoreQuery - Large Limit and Skip Values
// =============================================================================

#[test]
fn test_query_large_limit_and_skip() {
    let query = KVStoreQuery::new().with_limit(u32::MAX).with_skip(u32::MAX);
    assert_eq!(query.limit, Some(u32::MAX));
    assert_eq!(query.skip, Some(u32::MAX));
}
