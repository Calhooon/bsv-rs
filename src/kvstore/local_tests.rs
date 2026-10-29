//! Local store tests; excluded from production and wasm source scans.
#![cfg(test)]
use crate as sdk;
#[path = "../../tests/support/kvstore_mock_actions.rs"]
mod mock_actions;
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

// Import all wallet types needed for mock implementation
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureResult,
    DecryptResult, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult,
    EncryptResult, GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsResult, ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
    RelinquishCertificateResult, RelinquishOutputArgs, RelinquishOutputResult,
    RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult, SignActionArgs,
    SignActionResult, VerifyHmacArgs, VerifyHmacResult, WalletCertificate,
    WalletRevealCounterpartyArgs, WalletRevealSpecificArgs,
};

// =========================================================================
// Mock Wallet for Testing
// =========================================================================

/// Mock wallet for testing LocalKVStore.
/// Matches Go SDK's TestWallet pattern.
#[derive(Debug)]
pub(crate) struct MockWallet {
    /// If true, list_outputs returns an error.
    list_outputs_error: AtomicBool,
    /// If true, create_action returns an error.
    create_action_error: AtomicBool,
    /// Valid public key for testing.
    public_key_hex: String,
    actions: mock_actions::Actions,
    pub(crate) events: std::sync::Mutex<Vec<&'static str>>,
}

impl MockWallet {
    pub(crate) fn new() -> Self {
        // Generate a valid public key
        let privkey = crate::primitives::PrivateKey::random();
        let pubkey = privkey.public_key();
        let pubkey_hex = crate::primitives::to_hex(&pubkey.to_compressed());

        Self {
            list_outputs_error: AtomicBool::new(false),
            create_action_error: AtomicBool::new(false),
            public_key_hex: pubkey_hex,
            actions: Default::default(),
            events: Default::default(),
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
        _: Option<&str>,
    ) -> Result<GetPublicKeyResult> {
        Ok(GetPublicKeyResult {
            public_key: self.public_key_hex.clone(),
        })
    }

    async fn encrypt(&self, args: EncryptArgs, _: Option<&str>) -> Result<EncryptResult> {
        Ok(EncryptResult {
            ciphertext: args.plaintext,
        })
    }

    async fn decrypt(&self, args: DecryptArgs, _: Option<&str>) -> Result<DecryptResult> {
        Ok(DecryptResult {
            plaintext: args.ciphertext,
        })
    }

    async fn create_hmac(
        &self,
        _args: CreateHmacArgs,
        _: Option<&str>,
    ) -> Result<CreateHmacResult> {
        Ok(CreateHmacResult { hmac: [0u8; 32] })
    }

    async fn verify_hmac(
        &self,
        _args: VerifyHmacArgs,
        _: Option<&str>,
    ) -> Result<VerifyHmacResult> {
        Ok(VerifyHmacResult { valid: true })
    }

    async fn create_signature(
        &self,
        _args: crate::wallet::CreateSignatureArgs,
        _: Option<&str>,
    ) -> Result<CreateSignatureResult> {
        Ok(CreateSignatureResult {
            signature: vec![0u8; 64],
        })
    }

    async fn verify_signature(
        &self,
        _args: crate::wallet::VerifySignatureArgs,
        _: Option<&str>,
    ) -> Result<crate::wallet::VerifySignatureResult> {
        Ok(crate::wallet::VerifySignatureResult { valid: true })
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        _args: WalletRevealCounterpartyArgs,
        _: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn reveal_specific_key_linkage(
        &self,
        _args: WalletRevealSpecificArgs,
        _: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    // Action Operations
    async fn create_action(
        &self,
        args: CreateActionArgs,
        _: Option<&str>,
    ) -> Result<CreateActionResult> {
        if self.create_action_error.load(Ordering::SeqCst) {
            return Err(Error::WalletError("wallet error".to_string()));
        }
        self.events.lock().unwrap().push("createAction");
        Ok(self.actions.create(&args))
    }

    async fn sign_action(&self, args: SignActionArgs, _: Option<&str>) -> Result<SignActionResult> {
        self.events.lock().unwrap().push("signAction");
        Ok(self.actions.sign(args))
    }

    async fn abort_action(
        &self,
        _args: AbortActionArgs,
        _: Option<&str>,
    ) -> Result<AbortActionResult> {
        self.events.lock().unwrap().push("abortAction");
        Ok(AbortActionResult { aborted: true })
    }

    async fn list_actions(
        &self,
        _args: ListActionsArgs,
        _: Option<&str>,
    ) -> Result<ListActionsResult> {
        Ok(ListActionsResult {
            actions: vec![],
            total_actions: 0,
        })
    }

    async fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
        _: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        Ok(InternalizeActionResult { accepted: true })
    }

    // Output Operations
    async fn list_outputs(
        &self,
        _args: ListOutputsArgs,
        _: Option<&str>,
    ) -> Result<ListOutputsResult> {
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
        _: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        Ok(RelinquishOutputResult { relinquished: true })
    }

    // Certificate Operations
    async fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
        _: Option<&str>,
    ) -> Result<WalletCertificate> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
        _: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        Ok(ListCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
        _: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
        _: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        Ok(RelinquishCertificateResult { relinquished: true })
    }

    // Discovery Operations
    async fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    async fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
        _: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        Ok(DiscoverCertificatesResult {
            certificates: vec![],
            total_certificates: 0,
        })
    }

    // Status Operations
    async fn is_authenticated(&self, _: Option<&str>) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn wait_for_authentication(&self, _: Option<&str>) -> Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: true,
        })
    }

    async fn get_height(&self, _: Option<&str>) -> Result<GetHeightResult> {
        Ok(GetHeightResult { height: 0 })
    }

    async fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
        _: Option<&str>,
    ) -> Result<GetHeaderResult> {
        Err(Error::WalletError("not implemented".to_string()))
    }

    async fn get_network(&self, _: Option<&str>) -> Result<GetNetworkResult> {
        Ok(GetNetworkResult {
            network: crate::wallet::Network::Mainnet,
        })
    }

    async fn get_version(&self, _: Option<&str>) -> Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: "mock-1.0".to_string(),
        })
    }
}

// =========================================================================
// Config Tests
// =========================================================================

#[test]
fn test_local_kvstore_config() {
    let config = KVStoreConfig::default();
    assert_eq!(config.protocol_id, "kvstore");
    assert!(config.encrypt);
}

// =========================================================================
// Constructor Tests (matching Go: TestNewLocalKVStore_EmptyContext)
// =========================================================================

#[test]
fn test_new_local_kvstore_empty_context() {
    let wallet = MockWallet::new();
    let config = KVStoreConfig::new().with_protocol_id("");

    let result = LocalKVStore::new(wallet, config);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreEmptyContext));
}

#[test]
fn test_new_local_kvstore_success() {
    let wallet = MockWallet::new();
    let config = KVStoreConfig::default();

    let result = LocalKVStore::new(wallet, config);
    assert!(result.is_ok());
}

// =========================================================================
// Empty Key Tests (matching Go: TestLocalKVStore_EmptyKey)
// =========================================================================

#[tokio::test]
async fn test_get_empty_key() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("", "default").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_set_empty_key() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("", "value", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_remove_empty_key() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

// =========================================================================
// Empty Value Tests (matching Go: TestLocalKVStore_EmptyValue)
// =========================================================================

#[tokio::test]
async fn test_set_empty_value() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("key", "", None).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidValue));
}

// =========================================================================
// Get Tests (matching Go: TestLocalKVStoreGet_WalletError)
// =========================================================================

#[tokio::test]
async fn test_get_wallet_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("key", "default").await;
    assert!(result.is_err());
    // Error should propagate from wallet
    let err = result.unwrap_err();
    assert!(matches!(err, Error::WalletError(_)));
}

#[tokio::test]
async fn test_get_returns_default_when_not_found() {
    let wallet = MockWallet::new(); // Returns empty outputs
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.get("nonexistent_key", "my_default").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "my_default");
}

// =========================================================================
// Set Tests (matching Go: TestLocalKVStoreSet_Success, TestLocalKVStoreSet_WalletError)
// =========================================================================

#[tokio::test]
async fn test_set_success() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("key1", "value1", None).await;
    if let Err(ref e) = result {
        eprintln!("Set failed with error: {:?}", e);
    }
    assert!(result.is_ok(), "Set should succeed but got: {:?}", result);
}

#[tokio::test]
async fn test_set_wallet_error() {
    let wallet = MockWallet::new().with_create_action_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.set("key1", "value1", None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::WalletError(_)));
}

// =========================================================================
// Remove Tests (matching Go: TestLocalKVStoreRemove_ListOutputsError)
// =========================================================================

#[tokio::test]
async fn test_remove_list_outputs_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("key1", None).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, Error::WalletError(_)));
}

#[tokio::test]
async fn test_remove_not_found_returns_empty() {
    let wallet = MockWallet::new(); // Returns empty outputs
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let result = store.remove("nonexistent_key", None).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// =========================================================================
// Internal Type Tests
// =========================================================================

#[test]
fn test_lookup_value_result_not_found() {
    let result = LookupValueResult::not_found("default".to_string());
    assert!(!result.value_exists);
    assert_eq!(result.value, "default");
}

#[test]
fn test_lookup_value_result_found() {
    let result = LookupValueResult::found(
        "my_value".to_string(),
        vec!["txid.0".to_string()],
        None,
        vec![],
    );
    assert!(result.value_exists);
    assert_eq!(result.value, "my_value");
}

// =========================================================================
// Batch Operation Tests
// =========================================================================

#[tokio::test]
async fn test_local_batch_set_and_get() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Batch set multiple values
    let entries = vec![("key1", "value1"), ("key2", "value2"), ("key3", "value3")];
    let result = store.batch_set(&entries).await;
    assert!(result.is_ok(), "batch_set should succeed: {:?}", result);

    // Batch get them back - MockWallet returns empty outputs so all will be None
    let keys = vec!["key1", "key2", "key3"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok(), "batch_get should succeed: {:?}", result);

    let values = result.unwrap();
    assert_eq!(values.len(), 3);
    // With MockWallet returning empty list_outputs, get sees no existing values
    // so batch_get returns None for each key
    for v in &values {
        assert!(v.is_none());
    }
}

#[tokio::test]
async fn test_local_batch_remove() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Batch set then batch remove
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

    // Set only key1
    store.set("key1", "value1", None).await.unwrap();

    // Batch get key1 (exists but returns None from mock) and key2 (doesn't exist)
    let keys = vec!["key1", "key2", "key3"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_ok());

    let values = result.unwrap();
    assert_eq!(values.len(), 3);
    // MockWallet's list_outputs returns empty, so all are None
    assert!(values[0].is_none());
    assert!(values[1].is_none());
    assert!(values[2].is_none());
}

#[tokio::test]
async fn test_local_batch_empty() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // Empty batch operations should succeed
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
async fn test_local_batch_get_invalid_key() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    // batch_get with an empty key should fail
    let keys = vec!["valid_key", ""];
    let result = store.batch_get(&keys).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::KvStoreInvalidKey));
}

#[tokio::test]
async fn test_local_batch_get_wallet_error() {
    let wallet = MockWallet::new().with_list_outputs_error();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let keys = vec!["key1", "key2"];
    let result = store.batch_get(&keys).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::WalletError(_)));
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

// =========================================================================
// TTL Tests
// =========================================================================

#[test]
fn test_ttl_encode_decode_roundtrip() {
    use super::super::types::{decode_value_with_ttl, encode_value_with_ttl};

    // Encode with a large TTL (1 hour) - should not be expired
    let encoded = encode_value_with_ttl("hello", std::time::Duration::from_secs(3600));
    let (decoded, is_expired) = decode_value_with_ttl(&encoded);
    assert_eq!(decoded, "hello");
    assert!(!is_expired, "Entry with 1 hour TTL should not be expired");
}

#[test]
fn test_ttl_expired_value() {
    use super::super::types::decode_value_with_ttl;

    // Manually construct an expired envelope (expiration in the past)
    let envelope = r#"{"v":"old_value","e":1000000}"#;
    let (decoded, is_expired) = decode_value_with_ttl(envelope);
    assert_eq!(decoded, "old_value");
    assert!(is_expired, "Entry with past expiration should be expired");
}

#[test]
fn test_ttl_plain_value_not_expired() {
    use super::super::types::decode_value_with_ttl;

    // Plain string values (no TTL envelope) should never expire
    let (decoded, is_expired) = decode_value_with_ttl("plain_value");
    assert_eq!(decoded, "plain_value");
    assert!(!is_expired, "Plain values should never be expired");
}

#[test]
fn test_ttl_json_that_is_not_envelope() {
    use super::super::types::decode_value_with_ttl;

    // A JSON string that doesn't match the TtlEnvelope schema
    let (decoded, is_expired) = decode_value_with_ttl(r#"{"name":"Alice"}"#);
    assert_eq!(decoded, r#"{"name":"Alice"}"#);
    assert!(!is_expired, "Non-envelope JSON should not be expired");
}

#[test]
fn test_ttl_zero_duration() {
    use super::super::types::{decode_value_with_ttl, encode_value_with_ttl};

    // TTL of 0 seconds means the entry expires immediately
    let encoded = encode_value_with_ttl("ephemeral", std::time::Duration::from_secs(0));
    let (decoded, is_expired) = decode_value_with_ttl(&encoded);
    assert_eq!(decoded, "ephemeral");
    assert!(is_expired, "Zero-TTL entry should be expired immediately");
}

#[test]
fn test_ttl_set_options_builder() {
    let opts = KVStoreSetOptions::new().with_ttl(std::time::Duration::from_secs(300));
    assert_eq!(opts.ttl, Some(std::time::Duration::from_secs(300)));
}

#[test]
fn test_ttl_set_options_default_no_ttl() {
    let opts = KVStoreSetOptions::default();
    assert!(opts.ttl.is_none());
}

#[tokio::test]
async fn test_set_with_ttl_success() {
    let wallet = MockWallet::new();
    let store = LocalKVStore::new(wallet, KVStoreConfig::default()).unwrap();

    let opts = KVStoreSetOptions::new().with_ttl(std::time::Duration::from_secs(3600));
    let result = store.set("ttl_key", "ttl_value", Some(opts)).await;
    assert!(result.is_ok(), "Set with TTL should succeed: {:?}", result);
}

#[test]
fn test_ttl_value_with_special_characters() {
    use super::super::types::{decode_value_with_ttl, encode_value_with_ttl};

    // Value containing JSON-special characters
    let value = r#"{"key": "val\"ue", "num": 42}"#;
    let encoded = encode_value_with_ttl(value, std::time::Duration::from_secs(3600));
    let (decoded, is_expired) = decode_value_with_ttl(&encoded);
    assert_eq!(decoded, value);
    assert!(!is_expired);
}

#[test]
fn test_ttl_future_expiration() {
    use super::super::types::decode_value_with_ttl;

    // Manually construct an envelope with expiration far in the future
    let future_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 999_999;
    let envelope = format!(r#"{{"v":"future","e":{}}}"#, future_ts);
    let (decoded, is_expired) = decode_value_with_ttl(&envelope);
    assert_eq!(decoded, "future");
    assert!(!is_expired, "Future expiration should not be expired");
}
