//! GlobalKVStore - Public key-value store using overlay network.
//!
//! Stores entries on the overlay network where they can be discovered
//! by other users via lookup services.

use crate::overlay::{
    LookupAnswer, LookupResolver, LookupResolverConfig, NetworkPreset, TopicBroadcaster,
    TopicBroadcasterConfig,
};
use crate::transaction::Broadcaster;
use crate::transaction::Transaction;
use crate::wallet::{GetPublicKeyArgs, WalletInterface};
use crate::{Error, Result};

use super::action_options::ActionOptions;
#[path = "global_actions.rs"]
mod actions;
use super::interpreter::{KVStoreContext, KVStoreInterpreter};
use super::types::{
    KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreQuery, KVStoreRemoveOptions,
    KVStoreSetOptions, KVStoreToken,
};
use crate::overlay::SyncHistorian;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Public key-value store using overlay network.
///
/// GlobalKVStore stores entries on the overlay network where they
/// can be discovered by other users via lookup services.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig};
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let config = KVStoreConfig::default();
/// let store = GlobalKVStore::new(wallet, config);
///
/// store.set("key", "value", None).await?;
/// let entry = store.get("key", None).await?;
/// ```
pub struct GlobalKVStore<W: WalletInterface> {
    wallet: W,
    config: KVStoreConfig,
    action_options: ActionOptions,
    resolver: Arc<LookupResolver>,
    network_preset: NetworkPreset,
    /// Cached identity key.
    cached_identity_key: Arc<Mutex<Option<String>>>,
    /// Lock queue for atomic key operations.
    key_locks: Arc<Mutex<HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>>>,
}

impl<W: WalletInterface> GlobalKVStore<W> {
    /// Create a new GlobalKVStore.
    ///
    /// Uses the default network preset (Mainnet).
    pub fn new(wallet: W, config: KVStoreConfig) -> Self {
        Self::with_network(wallet, config, NetworkPreset::default())
    }

    /// Create with custom network preset.
    pub fn with_network(wallet: W, config: KVStoreConfig, network: NetworkPreset) -> Self {
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: network,
            ..Default::default()
        });
        Self::with_resolver(wallet, config, network, resolver)
    }

    /// Create with a caller-built [`LookupResolver`] (a custom facilitator,
    /// pinned SLAP trackers, host overrides, or a test double). `network` is
    /// what the store reports and broadcasts under; the resolver is used as
    /// given.
    pub fn with_resolver(
        wallet: W,
        config: KVStoreConfig,
        network: NetworkPreset,
        resolver: LookupResolver,
    ) -> Self {
        Self {
            wallet,
            config,
            action_options: ActionOptions::default(),
            resolver: Arc::new(resolver),
            network_preset: network,
            cached_identity_key: Arc::new(Mutex::new(None)),
            key_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Sets the wallet's `acceptDelayedBroadcast` option (default: false).
    #[must_use]
    pub fn with_accept_delayed_broadcast(mut self, accept: bool) -> Self {
        self.action_options.accept_delayed_broadcast = accept;
        self
    }

    /// Sets the wallet's `noSend` option (default: false).
    ///
    /// This is the reference global store's `overlayBroadcast` setting.
    #[must_use]
    pub fn with_no_send(mut self, no_send: bool) -> Self {
        self.action_options.no_send = no_send;
        self
    }

    /// Get a value by key.
    ///
    /// Queries the overlay lookup service for entries matching the key.
    /// If a controller is not specified in options, returns the first matching entry.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    /// * `options` - Optional retrieval options
    ///
    /// # Returns
    ///
    /// The entry if found, None otherwise.
    pub async fn get(
        &self,
        key: &str,
        options: Option<KVStoreGetOptions>,
    ) -> Result<Option<KVStoreEntry>> {
        if key.is_empty() {
            return Err(Error::KvStoreError("Key cannot be empty".to_string()));
        }

        let options = options.unwrap_or_default();
        let service_name = options
            .service_name
            .as_ref()
            .unwrap_or(&self.config.service_name);

        // Query overlay for the key
        let query = KVStoreQuery::new().with_key(key);
        let entries = self.query_overlay(&query, service_name, &options).await?;

        Ok(entries.into_iter().next())
    }

    /// Set a key-value pair.
    ///
    /// Creates a token and broadcasts to the overlay network.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set
    /// * `value` - The value to store
    /// * `options` - Optional operation options
    ///
    /// # Returns
    ///
    /// The outpoint string of the new token.
    pub async fn set(
        &self,
        key: &str,
        value: &str,
        options: Option<KVStoreSetOptions>,
    ) -> Result<String> {
        if key.is_empty() {
            return Err(Error::KvStoreError("Key cannot be empty".to_string()));
        }

        let options = options.unwrap_or_default();
        let controller = self.get_identity_key().await?;
        let protocol_id = options
            .protocol_id
            .clone()
            .unwrap_or_else(|| self.config.protocol_id.clone());

        // Acquire lock for this key
        self.acquire_key_lock(key).await;

        let result = self
            .set_internal(key, value, &controller, &protocol_id, &options)
            .await;

        self.release_key_lock(key).await;

        result
    }

    /// Remove a key-value pair.
    ///
    /// Spends the token, removing it from the overlay.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to remove
    /// * `options` - Optional operation options
    ///
    /// # Returns
    ///
    /// The transaction ID of the removal.
    pub async fn remove(&self, key: &str, options: Option<KVStoreRemoveOptions>) -> Result<String> {
        if key.is_empty() {
            return Err(Error::KvStoreError("Key cannot be empty".to_string()));
        }

        let controller = self.get_identity_key().await?;
        let options = options.unwrap_or_default();

        // Acquire lock
        self.acquire_key_lock(key).await;

        let result = self.remove_internal(key, &controller, &options).await;

        self.release_key_lock(key).await;

        result
    }

    /// Query entries from the overlay.
    ///
    /// Supports filtering by key, controller, protocol ID, and tags.
    ///
    /// # Arguments
    ///
    /// * `query` - Query parameters
    ///
    /// # Returns
    ///
    /// A list of matching entries.
    pub async fn query(&self, query: KVStoreQuery) -> Result<Vec<KVStoreEntry>> {
        self.query_overlay(
            &query,
            &self.config.service_name,
            &KVStoreGetOptions::default(),
        )
        .await
    }

    /// Get entries controlled by a specific key.
    ///
    /// # Arguments
    ///
    /// * `controller` - The controller public key (hex)
    ///
    /// # Returns
    ///
    /// A list of entries controlled by the specified key.
    pub async fn get_by_controller(&self, controller: &str) -> Result<Vec<KVStoreEntry>> {
        let query = KVStoreQuery::new().with_controller(controller);
        self.query(query).await
    }

    /// Get multiple values by key.
    ///
    /// Returns a vector of optional entries, one per key. Keys that do not exist
    /// will have `None` in their position. This is equivalent to calling `get()`
    /// for each key sequentially.
    ///
    /// # Arguments
    ///
    /// * `keys` - The keys to retrieve
    ///
    /// # Returns
    ///
    /// A vector of `Option<KVStoreEntry>` in the same order as the input keys.
    ///
    /// # Errors
    ///
    /// Returns an error if any key is empty or if overlay operations fail.
    pub async fn batch_get(&self, keys: &[&str]) -> Result<Vec<Option<KVStoreEntry>>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            let entry = self.get(key, None).await?;
            results.push(entry);
        }
        Ok(results)
    }

    /// Set multiple key-value pairs.
    ///
    /// Creates or updates each entry on the overlay network. This is equivalent
    /// to calling `set()` for each key-value pair sequentially.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(key, value)` pairs to set
    ///
    /// # Errors
    ///
    /// Returns an error if any key is empty, or if wallet/overlay operations fail.
    /// If an error occurs partway through, earlier entries will already be set.
    pub async fn batch_set(&self, entries: &[(&str, &str)]) -> Result<()> {
        for (key, value) in entries {
            self.set(key, value, None).await?;
        }
        Ok(())
    }

    /// Remove multiple key-value pairs.
    ///
    /// Spends the tokens backing each entry on the overlay network. This is
    /// equivalent to calling `remove()` for each key sequentially.
    ///
    /// # Arguments
    ///
    /// * `keys` - The keys to remove
    ///
    /// # Errors
    ///
    /// Returns an error if any key is empty or if wallet/overlay operations fail.
    /// If an error occurs partway through, earlier entries will already be removed.
    pub async fn batch_remove(&self, keys: &[&str]) -> Result<()> {
        for key in keys {
            self.remove(key, None).await?;
        }
        Ok(())
    }

    /// Get entries with specific tags.
    ///
    /// # Arguments
    ///
    /// * `tags` - Tags to filter by
    /// * `mode` - Tag query mode: "all" (default) or "any"
    ///
    /// # Returns
    ///
    /// A list of entries with matching tags.
    pub async fn get_by_tags(
        &self,
        tags: &[String],
        mode: Option<&str>,
    ) -> Result<Vec<KVStoreEntry>> {
        let query = KVStoreQuery::new()
            .with_tags(tags.to_vec())
            .with_tag_query_mode(mode.unwrap_or("all"));
        self.query(query).await
    }

    // =========================================================================
    // Internal Helper Methods
    // =========================================================================

    fn originator(&self) -> Option<&str> {
        self.config.originator.as_deref()
    }

    async fn get_identity_key(&self) -> Result<String> {
        let mut cache = self.cached_identity_key.lock().await;
        if let Some(key) = cache.as_ref() {
            return Ok(key.clone());
        }

        let result = self
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

        // public_key is already a hex string from GetPublicKeyResult
        *cache = Some(result.public_key.clone());
        Ok(result.public_key)
    }

    async fn query_overlay(
        &self,
        query: &KVStoreQuery,
        service_name: &str,
        options: &KVStoreGetOptions,
    ) -> Result<Vec<KVStoreEntry>> {
        let question = actions::lookup_question(service_name, query);

        let answer = self.resolver.query(&question, Some(5000)).await?;

        let mut entries = Vec::new();

        match answer {
            LookupAnswer::OutputList { outputs } => {
                for output in outputs {
                    // Parse BEEF to get transaction
                    let tx = match Transaction::from_beef(&output.beef, None) {
                        Ok(tx) => tx,
                        Err(_) => continue,
                    };

                    // Get the output's locking script
                    let locking_script = match tx.outputs.get(output.output_index as usize) {
                        Some(out) => &out.locking_script,
                        None => continue,
                    };

                    // Extract fields for signature verification
                    let fields = match KVStoreInterpreter::extract_fields(locking_script) {
                        Some(f) => f,
                        None => continue,
                    };

                    // Get protocol ID from fields or query
                    let protocol_id = fields
                        .protocol_id_string()
                        .unwrap_or_else(|| self.config.protocol_id.clone());

                    // Verify signature - skip invalid entries
                    if !KVStoreInterpreter::verify_signature(&fields, &protocol_id) {
                        continue;
                    }

                    // Interpret the output
                    let ctx = query.key.as_ref().map(|k| {
                        KVStoreContext::new(
                            k,
                            query
                                .protocol_id
                                .as_deref()
                                .unwrap_or(&self.config.protocol_id),
                        )
                    });

                    if let Some(mut entry) =
                        KVStoreInterpreter::interpret(&tx, output.output_index, ctx.as_ref())
                    {
                        // Add token data if requested
                        if options.include_token {
                            let txid = tx.id();
                            let token = KVStoreToken::new(
                                &txid,
                                output.output_index,
                                tx.outputs[output.output_index as usize]
                                    .satoshis
                                    .unwrap_or_default(),
                            )
                            .with_beef(output.beef.clone());
                            entry = entry.with_token(token);
                        }

                        // Build history if requested
                        if options.history {
                            let history = build_entry_history(&tx, &entry.key, &entry.protocol_id);
                            if !history.is_empty() {
                                entry = entry.with_history(history);
                            }
                        }

                        entries.push(entry);
                    }
                }
            }
            LookupAnswer::Freeform { result: _ } => {
                // Freeform responses not supported for kvstore
            }
            LookupAnswer::Formula { formulas: _ } => {
                // Formula responses not supported for kvstore
            }
        }

        Ok(entries)
    }

    async fn broadcast_to_overlay(&self, beef: &[u8]) -> Result<()> {
        let broadcaster = TopicBroadcaster::new(
            self.config.topics.clone(),
            TopicBroadcasterConfig {
                network_preset: self.network_preset,
                ..Default::default()
            },
        )?;

        // Parse transaction from BEEF
        let tx = Transaction::from_beef(beef, None)?;

        // Broadcast
        let result = broadcaster.broadcast(&tx).await;

        match result {
            Ok(_) => Ok(()),
            Err(f) => Err(Error::OverlayBroadcastFailed(f.description)),
        }
    }

    async fn acquire_key_lock(&self, key: &str) {
        let mut locks = self.key_locks.lock().await;
        if let Some(waiters) = locks.get_mut(key) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            waiters.push(tx);
            drop(locks);
            let _ = rx.await;
        } else {
            locks.insert(key.to_string(), Vec::new());
        }
    }

    async fn release_key_lock(&self, key: &str) {
        let mut locks = self.key_locks.lock().await;
        if let Some(queue) = locks.get_mut(key) {
            if let Some(tx) = queue.pop() {
                let _ = tx.send(());
            } else {
                locks.remove(key);
            }
        }
    }
}

// =============================================================================
// History Building
// =============================================================================

/// Build the history of values for a key from transaction ancestry.
///
/// Uses `SyncHistorian` to traverse the transaction's input ancestry and extract
/// all previous values for the same key/protocol combination.
///
/// # Arguments
///
/// * `tx` - The current transaction containing the entry
/// * `key` - The key to track history for
/// * `protocol_id` - The protocol ID to match
///
/// # Returns
///
/// A vector of historical values in chronological order (oldest first).
fn build_entry_history(tx: &Transaction, key: &str, protocol_id: &str) -> Vec<String> {
    let ctx = KVStoreContext::new(key, protocol_id);
    let protocol_id_owned = protocol_id.to_string();

    let historian = SyncHistorian::<String, KVStoreContext>::new(
        move |tx: &Transaction, output_idx: u32, ctx: Option<&KVStoreContext>| {
            ctx.and_then(|c| {
                let output = tx.outputs.get(output_idx as usize)?;
                let fields = KVStoreInterpreter::extract_fields(&output.locking_script)?;
                let field_protocol_id = fields.protocol_id_string()?;

                // Match key and protocol_id
                let field_key = fields.key_string()?;
                if field_key != c.key || field_protocol_id != c.protocol_id {
                    return None;
                }

                // Verify signature
                if !KVStoreInterpreter::verify_signature(&fields, &protocol_id_owned) {
                    return None;
                }

                // Return the value
                fields.value_string()
            })
        },
    );

    historian.build_history(tx, Some(&ctx))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_kvstore_config() {
        let config = KVStoreConfig::default();
        assert_eq!(config.service_name, "ls_kvstore");
        assert_eq!(config.topics, vec!["tm_kvstore"]);
    }

    #[test]
    fn test_kvstore_query_to_json() {
        let query = KVStoreQuery::new()
            .with_key("test_key")
            .with_controller("02abc...")
            .with_limit(10);

        let json = query.to_json();
        assert_eq!(json["key"], "test_key");
        assert_eq!(json["controller"], "02abc...");
        assert_eq!(json["limit"], 10);
    }

    #[test]
    fn test_network_preset_default() {
        let preset = NetworkPreset::default();
        assert_eq!(preset, NetworkPreset::Mainnet);
    }
}
