//! LocalKVStore - Private key-value store backed by wallet transactions.
//!
//! Uses the wallet's basket system to store encrypted key-value pairs.
//! Only the wallet owner can read/write entries.

use crate::wallet::{
    Counterparty, CreateActionInput, DecryptArgs, EncryptArgs, GetPublicKeyArgs, ListOutputsArgs,
    Protocol, SecurityLevel, WalletInterface,
};
use crate::{Error, Result};

use super::action_options::ActionOptions;
#[path = "local_actions.rs"]
mod actions;
#[path = "local_list.rs"]
mod listing;
#[path = "local_lookup.rs"]
pub(super) mod lookup;
#[path = "local_token.rs"]
mod token;
use super::types::{
    decode_value_with_ttl, KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreQuery,
    KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
};
use lookup::LookupValueResult;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Private key-value store backed by wallet transactions.
///
/// LocalKVStore uses the wallet's basket system to store encrypted
/// key-value pairs. Only the wallet owner can read/write entries.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::kvstore::{LocalKVStore, KVStoreConfig};
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let config = KVStoreConfig::default();
/// let store = LocalKVStore::new(wallet, config)?;
///
/// store.set("key", "value", None).await?;
/// let value = store.get("key", "").await?;
/// ```
pub struct LocalKVStore<W: WalletInterface + std::fmt::Debug> {
    wallet: W,
    config: KVStoreConfig,
    action_options: ActionOptions,
    /// Mutex for atomic operations.
    state: Arc<Mutex<LocalKVStoreState>>,
}

impl<W: WalletInterface + std::fmt::Debug> std::fmt::Debug for LocalKVStore<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKVStore")
            .field("wallet", &self.wallet)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Default)]
struct LocalKVStoreState {
    /// Lock queue for atomic key operations.
    key_locks: HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>,
}

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    /// Create a new LocalKVStore.
    ///
    /// # Arguments
    ///
    /// * `wallet` - The wallet interface to use for operations
    /// * `config` - Configuration options
    ///
    /// # Errors
    ///
    /// Returns an error if the config's protocol_id (context) is empty.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let store = LocalKVStore::new(wallet, KVStoreConfig::default())?;
    /// ```
    pub fn new(wallet: W, config: KVStoreConfig) -> Result<Self> {
        if config.protocol_id.is_empty() {
            return Err(Error::KvStoreEmptyContext);
        }
        Ok(Self {
            wallet,
            config,
            action_options: ActionOptions::default(),
            state: Arc::new(Mutex::new(LocalKVStoreState::default())),
        })
    }

    /// Sets the wallet's `acceptDelayedBroadcast` option (default: false).
    #[must_use]
    pub fn with_accept_delayed_broadcast(mut self, accept: bool) -> Self {
        self.action_options.accept_delayed_broadcast = accept;
        self
    }

    /// Get a value by key.
    ///
    /// Returns the value associated with the key, or the default_value if not found.
    /// This matches the Go SDK signature: `Get(ctx, key, defaultValue string) (string, error)`
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    /// * `default_value` - Value to return if key is not found
    ///
    /// # Returns
    ///
    /// The value if found, or default_value if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if key is empty or if wallet operations fail.
    pub async fn get(&self, key: &str, default_value: &str) -> Result<String> {
        if key.is_empty() {
            return Err(Error::KvStoreInvalidKey);
        }

        let result = self.lookup_value(key, 5).await?;

        if !result.value_exists {
            return Ok(default_value.to_string());
        }

        // Check for TTL expiration
        let (value, is_expired) = decode_value_with_ttl(&result.value);
        if is_expired {
            return Ok(default_value.to_string());
        }

        Ok(value)
    }

    /// Get a value by key with additional options.
    ///
    /// Returns the full entry with metadata. Use this when you need
    /// access to token data or other metadata.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    /// * `options` - Retrieval options
    ///
    /// # Returns
    ///
    /// The entry if found, None otherwise.
    pub async fn get_entry(
        &self,
        key: &str,
        options: Option<KVStoreGetOptions>,
    ) -> Result<Option<KVStoreEntry>> {
        if key.is_empty() {
            return Err(Error::KvStoreInvalidKey);
        }

        let result = self.lookup_value(key, 5).await?;

        if !result.value_exists {
            return Ok(None);
        }

        // Check for TTL expiration
        let (value, is_expired) = decode_value_with_ttl(&result.value);
        if is_expired {
            return Ok(None);
        }

        let options = options.unwrap_or_default();
        let protocol_id = &self.config.protocol_id;

        // Get controller public key
        let pubkey_result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;

        // public_key is already a hex string
        let controller = pubkey_result.public_key.clone();

        let mut entry = KVStoreEntry::new(&value, &value, &controller, protocol_id);

        // Include token if requested
        if options.include_token && !result.outpoints.is_empty() {
            if let Some(output) = result.outputs.first() {
                let parts: Vec<&str> = output.outpoint.split('.').collect();
                if parts.len() == 2 {
                    let token =
                        KVStoreToken::new(parts[0], parts[1].parse().unwrap_or(0), output.satoshis)
                            .with_beef(result.input_beef.clone().unwrap_or_default());
                    entry = entry.with_token(token);
                }
            }
        }

        Ok(Some(entry))
    }

    /// Set a key-value pair.
    ///
    /// Creates or updates the entry. If the key exists, the old UTXO is spent.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set
    /// * `value` - The value to store
    /// * `options` - Optional operation options
    ///
    /// # Returns
    ///
    /// The outpoint string of the new UTXO.
    pub async fn set(
        &self,
        key: &str,
        value: &str,
        options: Option<KVStoreSetOptions>,
    ) -> Result<String> {
        if key.is_empty() {
            return Err(Error::KvStoreInvalidKey);
        }
        if value.is_empty() {
            return Err(Error::KvStoreInvalidValue);
        }

        let options = options.unwrap_or_default();
        let protocol_id = options
            .protocol_id
            .as_ref()
            .unwrap_or(&self.config.protocol_id);

        // Queue this operation atomically
        self.acquire_key_lock(key).await;

        let result = self.set_internal(key, value, protocol_id, &options).await;

        self.release_key_lock(key).await;

        result
    }

    /// Remove a key-value pair.
    ///
    /// Spends the UTXO backing the entry.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove
    /// * `options` - Optional operation options
    ///
    /// # Returns
    ///
    /// A list of transaction IDs that removed the outputs.
    pub async fn remove(
        &self,
        key: &str,
        options: Option<KVStoreRemoveOptions>,
    ) -> Result<Vec<String>> {
        if key.is_empty() {
            return Err(Error::KvStoreInvalidKey);
        }

        let options = options.unwrap_or_default();
        self.acquire_key_lock(key).await;
        let result = self.remove_internal(key, &options).await;
        self.release_key_lock(key).await;
        result
    }

    /// List all keys.
    ///
    /// # Returns
    ///
    /// A list of all keys in the store.
    pub async fn keys(&self) -> Result<Vec<String>> {
        let entries = self.list(None).await?;
        let keys: Vec<String> = entries.into_iter().map(|e| e.key).collect();
        Ok(keys)
    }

    /// List all entries matching a query.
    ///
    /// # Arguments
    ///
    /// * `query` - Optional query parameters
    ///
    /// # Returns
    ///
    /// A list of matching entries.
    pub async fn list(&self, query: Option<KVStoreQuery>) -> Result<Vec<KVStoreEntry>> {
        self.list_entries(query.unwrap_or_default()).await
    }

    /// Check if a key exists.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check
    ///
    /// # Returns
    ///
    /// true if the key exists.
    pub async fn has(&self, key: &str) -> Result<bool> {
        if key.is_empty() {
            return Err(Error::KvStoreInvalidKey);
        }

        let result = self.lookup_value(key, 1).await?;
        Ok(result.value_exists)
    }

    /// Get the entry count.
    ///
    /// # Returns
    ///
    /// The number of entries in the store.
    pub async fn count(&self) -> Result<usize> {
        let list_result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.protocol_id.clone(),
                    tags: None,
                    tag_query_mode: None,
                    include: None,
                    include_custom_instructions: None,
                    include_tags: None,
                    include_labels: None,
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;

        usize::try_from(list_result.total_outputs)
            .map_err(|_| lookup::refused("Wallet KVStore output total exceeds the platform"))
    }

    /// Get multiple values by key.
    ///
    /// Returns a vector of optional values, one per key. Keys that do not exist
    /// will have `None` in their position. This is equivalent to calling `get()`
    /// for each key, but conveniently returns `None` instead of a default value
    /// for missing keys.
    ///
    /// # Arguments
    ///
    /// * `keys` - The keys to retrieve
    ///
    /// # Returns
    ///
    /// A vector of `Option<String>` in the same order as the input keys.
    ///
    /// # Errors
    ///
    /// Returns an error if any key is empty or if wallet operations fail.
    pub async fn batch_get(&self, keys: &[&str]) -> Result<Vec<Option<String>>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if key.is_empty() {
                return Err(Error::KvStoreInvalidKey);
            }
            let lookup = self.lookup_value(key, 5).await?;
            if lookup.value_exists {
                results.push(Some(lookup.value));
            } else {
                results.push(None);
            }
        }
        Ok(results)
    }

    /// Set multiple key-value pairs.
    ///
    /// Creates or updates each entry. This is equivalent to calling `set()`
    /// for each key-value pair sequentially.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(key, value)` pairs to set
    ///
    /// # Errors
    ///
    /// Returns an error if any key or value is empty, or if wallet operations fail.
    /// If an error occurs partway through, earlier entries will already be set.
    pub async fn batch_set(&self, entries: &[(&str, &str)]) -> Result<()> {
        for (key, value) in entries {
            self.set(key, value, None).await?;
        }
        Ok(())
    }

    /// Remove multiple key-value pairs.
    ///
    /// Spends the UTXOs backing each entry. This is equivalent to calling
    /// `remove()` for each key sequentially.
    ///
    /// # Arguments
    ///
    /// * `keys` - The keys to remove
    ///
    /// # Errors
    ///
    /// Returns an error if any key is empty or if wallet operations fail.
    /// If an error occurs partway through, earlier entries will already be removed.
    pub async fn batch_remove(&self, keys: &[&str]) -> Result<()> {
        for key in keys {
            self.remove(key, None).await?;
        }
        Ok(())
    }

    /// Clear all entries.
    ///
    /// Spends all UTXOs backing entries.
    pub async fn clear(&self) -> Result<()> {
        let keys = self.keys().await?;

        for key in keys {
            self.remove(&key, None).await?;
        }

        Ok(())
    }

    // =========================================================================
    // Internal Helper Methods
    // =========================================================================

    fn originator(&self) -> Option<&str> {
        self.config.originator.as_deref()
    }

    fn get_protocol(&self, _key: &str) -> Protocol {
        Protocol::new(SecurityLevel::Counterparty, &self.config.protocol_id)
    }

    async fn encrypt_value(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .wallet
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.to_vec(),
                    protocol_id: self.get_protocol(key),
                    key_id: key.to_string(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;

        Ok(result.ciphertext)
    }

    async fn decrypt_value(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: ciphertext.to_vec(),
                    protocol_id: self.get_protocol(key),
                    key_id: key.to_string(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;

        Ok(result.plaintext)
    }

    fn build_inputs(&self, lookup_result: &LookupValueResult) -> Result<Vec<CreateActionInput>> {
        super::token_spends::inputs(
            lookup_result
                .outputs
                .iter()
                .map(|output| output.outpoint.clone()),
            "Previous key-value token",
        )
    }

    async fn acquire_key_lock(&self, key: &str) {
        let mut state = self.state.lock().await;
        if let Some(waiters) = state.key_locks.get_mut(key) {
            // Create a oneshot channel and wait
            let (tx, rx) = tokio::sync::oneshot::channel();
            waiters.push(tx);
            drop(state);
            let _ = rx.await;
        } else {
            state.key_locks.insert(key.to_string(), Vec::new());
        }
    }

    async fn release_key_lock(&self, key: &str) {
        let mut state = self.state.lock().await;
        if let Some(queue) = state.key_locks.get_mut(key) {
            if let Some(tx) = queue.pop() {
                let _ = tx.send(());
            } else {
                state.key_locks.remove(key);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "local_tests.rs"]
pub(crate) mod tests;
