//! LocalKVStore - Private key-value store backed by wallet transactions.
//!
//! Uses the wallet's basket system to store encrypted key-value pairs.
//! Only the wallet owner can read/write entries.

use crate::primitives::{from_hex, to_hex, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOutput, DecryptArgs,
    EncryptArgs, GetPublicKeyArgs, ListOutputsArgs, Protocol, QueryMode, RelinquishOutputArgs,
    SecurityLevel, SignActionArgs, SignActionSpend, WalletInterface,
};
use crate::{Error, Result};

use super::interpreter::KVStoreInterpreter;
use super::types::{
    KVStoreConfig, KVStoreEntry, KVStoreGetOptions, KVStoreQuery, KVStoreRemoveOptions,
    KVStoreSetOptions, KVStoreToken, LookupValueResult, WalletOutput,
};

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
/// use bsv_sdk::kvstore::{LocalKVStore, KVStoreConfig};
/// use bsv_sdk::wallet::ProtoWallet;
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
            state: Arc::new(Mutex::new(LocalKVStoreState::default())),
        })
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

        Ok(result.value)
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
                    for_self: None,
                },
                self.originator(),
            )
            .await?;

        // public_key is already a hex string
        let controller = pubkey_result.public_key.clone();

        let mut entry = KVStoreEntry::new(&result.value, &result.value, &controller, protocol_id);

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

    async fn set_internal(
        &self,
        key: &str,
        value: &str,
        _protocol_id: &str,
        options: &KVStoreSetOptions,
    ) -> Result<String> {
        // Look up existing value
        let lookup_result = self.lookup_value(key, 10).await?;

        // Optimization: if value is the same, return existing outpoint
        if lookup_result.value_exists
            && lookup_result.value == value
            && !lookup_result.outpoints.is_empty()
        {
            return Ok(lookup_result.outpoints.last().unwrap().clone());
        }

        // Prepare value (encrypt if needed)
        let value_bytes = if self.config.encrypt {
            self.encrypt_value(key, value.as_bytes()).await?
        } else {
            value.as_bytes().to_vec()
        };

        // Create PushDrop locking script with encrypted value
        let locking_script = self.create_locking_script(key, &value_bytes).await?;

        // Build inputs from existing outputs (to collapse them)
        let inputs = self.build_inputs(&lookup_result);
        let input_beef = lookup_result.input_beef.clone();

        // Build output
        let token_amount = options.token_amount.unwrap_or(self.config.token_amount);
        let description = options
            .description
            .clone()
            .unwrap_or_else(|| format!("Update {} in {}", key, self.config.protocol_id));

        let tags = options
            .tags
            .clone()
            .unwrap_or_else(|| vec![key.to_string()]);

        let outputs = vec![CreateActionOutput {
            locking_script: locking_script.to_binary(),
            satoshis: token_amount,
            output_description: format!("KV entry: {}", key),
            basket: Some(self.config.protocol_id.clone()),
            custom_instructions: None,
            tags: Some(tags),
        }];

        // Create action
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description,
                    inputs: if inputs.is_empty() {
                        None
                    } else {
                        Some(inputs.clone())
                    },
                    outputs: Some(outputs),
                    input_beef: input_beef.clone(),
                    lock_time: None,
                    version: None,
                    labels: None,
                    options: None,
                },
                self.originator(),
            )
            .await?;

        // If we had inputs, we need to sign
        if let Some(signable) = create_result.signable_transaction.as_ref() {
            if !inputs.is_empty() {
                let reference_str = to_hex(&signable.reference);

                // Prepare spends (unlocking scripts)
                let spends = self
                    .prepare_spends(key, &lookup_result.outputs, &signable.tx, input_beef)
                    .await?;

                let sign_result = self
                    .wallet
                    .sign_action(
                        SignActionArgs {
                            reference: reference_str,
                            spends,
                            options: None,
                        },
                        self.originator(),
                    )
                    .await;

                if let Err(e) = sign_result {
                    // Relinquish inputs on failure
                    for input in &inputs {
                        let _ = self
                            .wallet
                            .relinquish_output(
                                RelinquishOutputArgs {
                                    basket: self.config.protocol_id.clone(),
                                    output: input.outpoint.clone(),
                                },
                                self.originator(),
                            )
                            .await;
                    }
                    return Err(e);
                }
            }
        }

        // Return outpoint of the new output
        match create_result.txid {
            Some(txid) => Ok(format!("{}.0", to_hex(&txid))),
            None => Err(Error::KvStoreError("No txid in result".to_string())),
        }
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
        let mut txids = Vec::new();

        loop {
            let lookup_result = self.lookup_value(key, 100).await?;

            if !lookup_result.value_exists || lookup_result.outputs.is_empty() {
                break;
            }

            let inputs = self.build_inputs(&lookup_result);
            let input_beef = lookup_result.input_beef.clone();

            if inputs.is_empty() {
                break;
            }

            let description = options
                .description
                .clone()
                .unwrap_or_else(|| format!("Remove {} from {}", key, self.config.protocol_id));

            // Create action with inputs but no outputs (spending only)
            let create_result = self
                .wallet
                .create_action(
                    CreateActionArgs {
                        description,
                        inputs: Some(inputs.clone()),
                        outputs: None, // No new outputs
                        input_beef: input_beef.clone(),
                        lock_time: None,
                        version: None,
                        labels: None,
                        options: None,
                    },
                    self.originator(),
                )
                .await?;

            if let Some(signable) = &create_result.signable_transaction {
                let reference_str = to_hex(&signable.reference);
                let spends = self
                    .prepare_spends(key, &lookup_result.outputs, &signable.tx, input_beef)
                    .await?;

                let sign_result = self
                    .wallet
                    .sign_action(
                        SignActionArgs {
                            reference: reference_str,
                            spends,
                            options: None,
                        },
                        self.originator(),
                    )
                    .await;

                if let Err(e) = sign_result {
                    // Relinquish on failure
                    for input in &inputs {
                        let _ = self
                            .wallet
                            .relinquish_output(
                                RelinquishOutputArgs {
                                    basket: self.config.protocol_id.clone(),
                                    output: input.outpoint.clone(),
                                },
                                self.originator(),
                            )
                            .await;
                    }
                    return Err(e);
                }
            }

            if let Some(txid) = create_result.txid {
                txids.push(to_hex(&txid));
            }

            // If we got fewer than 100 outputs, we're done
            if lookup_result.outputs.len() < 100 {
                break;
            }
        }

        Ok(txids)
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
        let query = query.unwrap_or_default();

        // Build list outputs args
        let tags = query.key.as_ref().map(|k| vec![k.clone()]);

        let list_result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.protocol_id.clone(),
                    tags,
                    tag_query_mode: Some(QueryMode::All),
                    include: Some(crate::wallet::OutputInclude::EntireTransactions),
                    include_custom_instructions: None,
                    include_tags: Some(true),
                    include_labels: None,
                    limit: query.limit,
                    offset: query.skip.map(|s| s as i32),
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;

        let mut entries = Vec::new();

        // Get identity key for controller
        let pubkey_result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    for_self: None,
                },
                self.originator(),
            )
            .await?;

        // public_key is already a hex string
        let controller = pubkey_result.public_key.clone();

        for output in &list_result.outputs {
            // Parse the locking script - it's Option<Vec<u8>>
            let locking_script_bytes = match &output.locking_script {
                Some(bytes) => bytes,
                None => continue,
            };
            let script = match LockingScript::from_binary(locking_script_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Extract fields
            if let Some(fields) = KVStoreInterpreter::extract_fields(&script) {
                let key = match fields.key_string() {
                    Some(k) => k,
                    None => continue,
                };

                // Decrypt value if encrypted
                let value_bytes = if self.config.encrypt {
                    match self.decrypt_value(&key, fields.value_bytes()).await {
                        Ok(v) => v,
                        Err(_) => continue,
                    }
                } else {
                    fields.value.clone()
                };

                let value = String::from_utf8(value_bytes).unwrap_or_default();
                let tags = fields.tags_vec();

                entries.push(
                    KVStoreEntry::new(&key, &value, &controller, &self.config.protocol_id)
                        .with_tags(tags),
                );
            }
        }

        // Apply tag filtering if specified
        if let Some(filter_tags) = &query.tags {
            let mode = query.tag_query_mode.as_deref().unwrap_or("all");
            entries.retain(|e| {
                if mode == "any" {
                    filter_tags.iter().any(|t| e.tags.contains(t))
                } else {
                    filter_tags.iter().all(|t| e.tags.contains(t))
                }
            });
        }

        Ok(entries)
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

        Ok(list_result.total_outputs as usize)
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

    fn originator(&self) -> &str {
        self.config.originator.as_deref().unwrap_or("kvstore")
    }

    fn get_protocol(&self, _key: &str) -> Protocol {
        Protocol::new(SecurityLevel::Counterparty, &self.config.protocol_id)
    }

    async fn encrypt_value(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let protocol = self.get_protocol(key);

        let result = self
            .wallet
            .encrypt(
                EncryptArgs {
                    plaintext: plaintext.to_vec(),
                    protocol_id: protocol,
                    key_id: key.to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                self.originator(),
            )
            .await?;

        Ok(result.ciphertext)
    }

    async fn decrypt_value(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let protocol = self.get_protocol(key);

        let result = self
            .wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: ciphertext.to_vec(),
                    protocol_id: protocol,
                    key_id: key.to_string(),
                    counterparty: Some(Counterparty::Self_),
                },
                self.originator(),
            )
            .await?;

        Ok(result.plaintext)
    }

    async fn create_locking_script(&self, key: &str, value: &[u8]) -> Result<LockingScript> {
        // Get public key for locking
        let pubkey_result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(self.get_protocol(key)),
                    key_id: Some(key.to_string()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(true),
                },
                self.originator(),
            )
            .await?;

        // Parse hex string to PublicKey
        let pubkey = PublicKey::from_hex(&pubkey_result.public_key)?;

        // Create PushDrop with single value field (LocalKVStore uses simple format)
        let fields = vec![value.to_vec()];
        let pushdrop = PushDrop::new(pubkey, fields);

        Ok(pushdrop.lock())
    }

    async fn lookup_value(&self, key: &str, limit: u32) -> Result<LookupValueResult> {
        // List outputs with the key tag
        let list_result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.protocol_id.clone(),
                    tags: Some(vec![key.to_string()]),
                    tag_query_mode: Some(QueryMode::All),
                    include: Some(crate::wallet::OutputInclude::EntireTransactions),
                    include_custom_instructions: None,
                    include_tags: Some(true),
                    include_labels: None,
                    limit: Some(limit),
                    offset: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;

        if list_result.outputs.is_empty() {
            return Ok(LookupValueResult::not_found(String::new()));
        }

        // Get the most recent output (last in the list)
        let last_output = list_result.outputs.last().unwrap();

        // Parse the locking script - it's Option<Vec<u8>>
        let locking_script_bytes = last_output
            .locking_script
            .as_ref()
            .ok_or_else(|| Error::KvStoreError("No locking script in output".to_string()))?;
        let script = LockingScript::from_binary(locking_script_bytes)?;

        // Decode PushDrop
        let pushdrop = PushDrop::decode(&script)?;

        if pushdrop.fields.is_empty() {
            return Err(Error::KvStoreError(
                "Invalid KVStore token: no fields".to_string(),
            ));
        }

        // Extract and decrypt value
        let value_bytes = &pushdrop.fields[0];
        let value = if self.config.encrypt {
            let decrypted = self.decrypt_value(key, value_bytes).await?;
            String::from_utf8(decrypted).map_err(|e| Error::KvStoreError(e.to_string()))?
        } else {
            String::from_utf8(value_bytes.clone())
                .map_err(|e| Error::KvStoreError(e.to_string()))?
        };

        // Collect outpoints
        let outpoints: Vec<String> = list_result
            .outputs
            .iter()
            .map(|o| format!("{}.{}", to_hex(&o.outpoint.txid), o.outpoint.vout))
            .collect();

        // Convert to internal wallet output format
        let outputs: Vec<WalletOutput> = list_result
            .outputs
            .iter()
            .filter_map(|o| {
                // Only include outputs with locking scripts
                o.locking_script.as_ref().map(|script| WalletOutput {
                    outpoint: format!("{}.{}", to_hex(&o.outpoint.txid), o.outpoint.vout),
                    satoshis: o.satoshis,
                    locking_script: script.clone(),
                    tags: o.tags.clone().unwrap_or_default(),
                })
            })
            .collect();

        Ok(LookupValueResult::found(
            value,
            outpoints,
            list_result.beef,
            outputs,
        ))
    }

    fn build_inputs(&self, lookup_result: &LookupValueResult) -> Vec<CreateActionInput> {
        lookup_result
            .outputs
            .iter()
            .map(|output| {
                let parts: Vec<&str> = output.outpoint.split('.').collect();
                let txid_bytes = from_hex(parts[0]).unwrap_or_default();
                let mut txid = [0u8; 32];
                if txid_bytes.len() == 32 {
                    txid.copy_from_slice(&txid_bytes);
                }
                let vout: u32 = parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);

                CreateActionInput {
                    outpoint: crate::wallet::Outpoint::new(txid, vout),
                    input_description: "KV entry input".to_string(),
                    unlocking_script: None,
                    unlocking_script_length: Some(107), // PushDrop unlock estimate
                    sequence_number: None,
                }
            })
            .collect()
    }

    async fn prepare_spends(
        &self,
        _key: &str,
        outputs: &[WalletOutput],
        _tx_bytes: &[u8],
        _input_beef: Option<Vec<u8>>,
    ) -> Result<HashMap<u32, SignActionSpend>> {
        let mut spends = HashMap::new();

        for (i, _output) in outputs.iter().enumerate() {
            // For PushDrop, the wallet will handle the actual signing
            // We provide an empty unlocking script that will be filled by the wallet
            spends.insert(
                i as u32,
                SignActionSpend {
                    unlocking_script: Vec::new(),
                    sequence_number: None,
                },
            );
        }

        Ok(spends)
    }

    async fn acquire_key_lock(&self, key: &str) {
        let mut state = self.state.lock().await;
        if state.key_locks.contains_key(key) {
            // Create a oneshot channel and wait
            let (tx, rx) = tokio::sync::oneshot::channel();
            state.key_locks.get_mut(key).unwrap().push(tx);
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Import all wallet types needed for mock implementation
    use crate::wallet::{
        AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
        CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureResult, DecryptResult,
        DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult,
        EncryptResult, GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult,
        GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
        ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
        ListOutputsResult, ProveCertificateArgs, ProveCertificateResult, RelinquishCertificateArgs,
        RelinquishCertificateResult, RelinquishOutputResult, RevealCounterpartyKeyLinkageResult,
        RevealSpecificKeyLinkageResult, SignActionResult, VerifyHmacArgs, VerifyHmacResult,
        WalletCertificate, WalletRevealCounterpartyArgs, WalletRevealSpecificArgs,
    };

    // =========================================================================
    // Mock Wallet for Testing
    // =========================================================================

    /// Mock wallet for testing LocalKVStore.
    /// Matches Go SDK's TestWallet pattern.
    #[derive(Debug)]
    struct MockWallet {
        /// If true, list_outputs returns an error.
        list_outputs_error: AtomicBool,
        /// If true, create_action returns an error.
        create_action_error: AtomicBool,
        /// Valid public key for testing.
        public_key_hex: String,
    }

    impl MockWallet {
        fn new() -> Self {
            // Generate a valid public key
            let privkey = crate::primitives::PrivateKey::random();
            let pubkey = privkey.public_key();
            let pubkey_hex = crate::primitives::to_hex(&pubkey.to_compressed());

            Self {
                list_outputs_error: AtomicBool::new(false),
                create_action_error: AtomicBool::new(false),
                public_key_hex: pubkey_hex,
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
            _args: crate::wallet::CreateSignatureArgs,
            _originator: &str,
        ) -> Result<CreateSignatureResult> {
            Ok(CreateSignatureResult {
                signature: vec![0u8; 64],
            })
        }

        async fn verify_signature(
            &self,
            _args: crate::wallet::VerifySignatureArgs,
            _originator: &str,
        ) -> Result<crate::wallet::VerifySignatureResult> {
            Ok(crate::wallet::VerifySignatureResult { valid: true })
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
            if self.create_action_error.load(Ordering::SeqCst) {
                return Err(Error::WalletError("wallet error".to_string()));
            }
            Ok(CreateActionResult {
                txid: Some([0u8; 32]),
                tx: None,
                no_send_change: None,
                send_with_results: None,
                signable_transaction: None,
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
            Ok(GetHeightResult { height: 0 })
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
                network: crate::wallet::Network::Mainnet,
            })
        }

        async fn get_version(&self, _originator: &str) -> Result<GetVersionResult> {
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
}
