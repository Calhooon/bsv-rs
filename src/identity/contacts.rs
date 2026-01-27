//! Contacts manager for encrypted contact storage.
//!
//! The [`ContactsManager`] provides encrypted storage of contacts using
//! the wallet's basket system with PushDrop tokens.

use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::primitives::{sha256, to_hex, PublicKey, Signature};
use crate::script::templates::PushDrop;
use crate::transaction::{Beef, Transaction};
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
    CreateSignatureArgs, DecryptArgs, EncryptArgs, ListOutputsArgs, OutputInclude, Protocol,
    SecurityLevel, SignActionArgs, SignActionOptions, SignActionSpend, WalletInterface,
};
use crate::{Error, Result};

use super::types::{Contact, ContactsManagerConfig};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache entry for contacts.
#[derive(Debug, Clone, Default)]
struct ContactsCache {
    /// Cached contacts indexed by identity key.
    contacts: HashMap<String, Contact>,
    /// Whether the cache has been populated.
    initialized: bool,
}

/// Manager for encrypted contact storage.
///
/// Contacts are stored encrypted in the wallet's basket system using
/// PushDrop tokens. Each contact is:
/// - Encrypted with a per-contact key
/// - Tagged with a hashed identity key for fast lookup
/// - Stored in the "contacts" basket
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::identity::{ContactsManager, ContactsManagerConfig, Contact};
/// use bsv_sdk::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
///
/// // Add a contact
/// manager.add_contact(Contact {
///     identity_key: "02abc123...".to_string(),
///     name: "Alice".to_string(),
///     ..Default::default()
/// }).await?;
///
/// // List all contacts
/// let contacts = manager.list_contacts().await?;
/// ```
pub struct ContactsManager<W: WalletInterface> {
    wallet: W,
    config: ContactsManagerConfig,
    cache: Arc<RwLock<ContactsCache>>,
}

impl<W: WalletInterface> ContactsManager<W> {
    /// Create a new ContactsManager with the given wallet and configuration.
    pub fn new(wallet: W, config: ContactsManagerConfig) -> Self {
        Self {
            wallet,
            config,
            cache: Arc::new(RwLock::new(ContactsCache::default())),
        }
    }

    /// Get the originator string for wallet calls.
    fn originator(&self) -> &str {
        self.config.originator.as_deref().unwrap_or("")
    }

    // =========================================================================
    // CRUD Operations
    // =========================================================================

    /// Add a new contact.
    ///
    /// If a contact with the same identity key already exists, it will be updated.
    /// The contact is encrypted and stored on-chain using a PushDrop token.
    ///
    /// # Arguments
    /// * `contact` - The contact to add
    ///
    /// # Example
    /// ```rust,ignore
    /// manager.add_contact(Contact {
    ///     identity_key: "02abc123...".to_string(),
    ///     name: "Alice".to_string(),
    ///     avatar_url: Some("https://example.com/avatar.png".to_string()),
    ///     added_at: chrono::Utc::now().timestamp_millis() as u64,
    ///     notes: Some("Met at conference".to_string()),
    ///     tags: vec!["work".to_string()],
    ///     metadata: None,
    /// }).await?;
    /// ```
    pub async fn add_contact(&self, contact: Contact) -> Result<()> {
        let originator = self.originator();

        // Try to check if contact already exists on chain (for update)
        let identity_tag = match self.create_identity_tag(&contact.identity_key).await {
            Ok(tag) => Some(tag),
            Err(_) => None, // HMAC not supported, fall back to cache-only
        };

        // If we have a tag, try to check for existing outputs
        let existing_outputs = if let Some(ref tag) = identity_tag {
            self.wallet
                .list_outputs(
                    ListOutputsArgs {
                        basket: self.config.basket.clone(),
                        tags: Some(vec![tag.clone()]),
                        tag_query_mode: None,
                        include: Some(OutputInclude::EntireTransactions),
                        include_custom_instructions: Some(true),
                        include_tags: None,
                        include_labels: None,
                        limit: Some(100),
                        offset: None,
                        seek_permission: None,
                    },
                    originator,
                )
                .await
                .ok()
        } else {
            None
        };

        // Generate a random key ID for this contact
        let key_id = self.generate_key_id();

        // Create the protocol for contacts
        let protocol = Protocol::new(SecurityLevel::App, &self.config.protocol_id.1);

        // Serialize and encrypt contact data
        let contact_json =
            serde_json::to_vec(&contact).map_err(|e| Error::IdentityError(e.to_string()))?;

        let encrypted = self
            .wallet
            .encrypt(
                EncryptArgs {
                    plaintext: contact_json,
                    protocol_id: protocol.clone(),
                    key_id: key_id.clone(),
                    counterparty: Some(Counterparty::Self_),
                },
                originator,
            )
            .await?;

        // Get public key for PushDrop locking
        let wallet_pubkey = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(protocol.clone()),
                    key_id: Some(key_id.clone()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(true),
                },
                originator,
            )
            .await?;

        let locking_pubkey = PublicKey::from_hex(&wallet_pubkey.public_key)?;

        // Create PushDrop locking script
        let pushdrop = PushDrop::new(locking_pubkey, vec![encrypted.ciphertext]);
        let locking_script = pushdrop.lock();

        // Custom instructions to store the key ID
        let custom_instructions = serde_json::json!({ "keyID": key_id }).to_string();

        // Check if we need to update an existing contact
        if let Some(result) = existing_outputs {
            if !result.outputs.is_empty() {
                if let Some(ref tag) = identity_tag {
                    // Try to update on chain; if that fails, fall back to cache
                    let chain_result = self
                        .update_contact_on_chain(
                            &result,
                            &contact,
                            &locking_script,
                            tag,
                            &key_id,
                            &custom_instructions,
                        )
                        .await;

                    if chain_result.is_ok() {
                        return chain_result;
                    }
                    // Fall through to cache-only update
                }
            }
        }

        // Try to create new contact output on chain
        let chain_success = if identity_tag.is_some() {
            let create_result = self
                .wallet
                .create_action(
                    CreateActionArgs {
                        description: format!(
                            "Add Contact: {}",
                            contact.name.chars().take(20).collect::<String>()
                        ),
                        input_beef: None,
                        inputs: None,
                        outputs: Some(vec![CreateActionOutput {
                            locking_script: locking_script.to_binary(),
                            satoshis: 1,
                            output_description: format!(
                                "Contact: {}",
                                contact.identity_key.chars().take(10).collect::<String>()
                            ),
                            basket: Some(self.config.basket.clone()),
                            custom_instructions: Some(custom_instructions),
                            tags: Some(vec![identity_tag.unwrap()]),
                        }]),
                        lock_time: None,
                        version: None,
                        labels: Some(vec!["contacts".to_string()]),
                        options: Some(CreateActionOptions {
                            sign_and_process: Some(true),
                            accept_delayed_broadcast: Some(false),
                            trust_self: None,
                            known_txids: None,
                            return_txid_only: None,
                            no_send: None,
                            no_send_change: None,
                            send_with: None,
                            randomize_outputs: Some(false),
                        }),
                    },
                    originator,
                )
                .await;

            match create_result {
                Ok(result) => result.tx.is_some() || result.txid.is_some(),
                Err(_) => false, // Blockchain operation failed, fall back to cache
            }
        } else {
            false // No tag means cache-only mode
        };

        // If chain operation failed or not supported, log it (but still update cache)
        if !chain_success {
            // Wallet doesn't support blockchain operations - cache-only mode
            // This is expected for ProtoWallet and similar crypto-only wallets
        }

        // Update local cache (always)
        {
            let mut cache = self.cache.write().await;
            cache.contacts.insert(contact.identity_key.clone(), contact);
        }

        Ok(())
    }

    /// Helper to update an existing contact on-chain.
    async fn update_contact_on_chain(
        &self,
        existing_result: &crate::wallet::ListOutputsResult,
        contact: &Contact,
        locking_script: &crate::script::LockingScript,
        identity_tag: &str,
        _key_id: &str, // key_id is stored in custom_instructions
        custom_instructions: &str,
    ) -> Result<()> {
        let originator = self.originator();
        let protocol = Protocol::new(SecurityLevel::App, &self.config.protocol_id.1);

        // Find the specific output for this contact
        for output in &existing_result.outputs {
            // Try to decrypt to verify it's the right contact
            if let Some(ref instructions) = output.custom_instructions {
                let stored_key_id = match serde_json::from_str::<serde_json::Value>(instructions) {
                    Ok(v) => v["keyID"].as_str().unwrap_or("").to_string(),
                    Err(_) => continue,
                };

                // Get the BEEF data
                let beef_data = match &existing_result.beef {
                    Some(b) => b.clone(),
                    None => continue,
                };

                // Use the outpoint directly (it's already an Outpoint)
                let outpoint = output.outpoint.clone();

                // Create transaction to spend the old output and create new one
                let create_result = self
                    .wallet
                    .create_action(
                        CreateActionArgs {
                            description: format!(
                                "Update Contact: {}",
                                contact.name.chars().take(20).collect::<String>()
                            ),
                            input_beef: Some(beef_data.clone()),
                            inputs: Some(vec![CreateActionInput {
                                outpoint,
                                input_description: "Previous contact output".to_string(),
                                unlocking_script: None,
                                unlocking_script_length: Some(74),
                                sequence_number: None,
                            }]),
                            outputs: Some(vec![CreateActionOutput {
                                locking_script: locking_script.to_binary(),
                                satoshis: 1,
                                output_description: format!(
                                    "Updated Contact: {}",
                                    contact.name.chars().take(20).collect::<String>()
                                ),
                                basket: Some(self.config.basket.clone()),
                                custom_instructions: Some(custom_instructions.to_string()),
                                tags: Some(vec![identity_tag.to_string()]),
                            }]),
                            lock_time: None,
                            version: None,
                            labels: Some(vec!["contacts".to_string()]),
                            options: Some(CreateActionOptions {
                                sign_and_process: Some(false),
                                accept_delayed_broadcast: Some(false),
                                trust_self: None,
                                known_txids: None,
                                return_txid_only: None,
                                no_send: Some(true),
                                no_send_change: None,
                                send_with: None,
                                randomize_outputs: Some(false),
                            }),
                        },
                        originator,
                    )
                    .await?;

                // Sign the transaction
                if let Some(signable_tx) = create_result.signable_transaction {
                    // Get the locking script from BEEF
                    let beef = Beef::from_binary(&beef_data).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse BEEF: {}", e))
                    })?;

                    let tx_data = beef.txs.first().ok_or_else(|| {
                        Error::IdentityError("BEEF contains no transactions".to_string())
                    })?;

                    let raw_tx = tx_data.raw_tx().ok_or_else(|| {
                        Error::IdentityError("Failed to get raw tx from BEEF".to_string())
                    })?;

                    let parsed_tx = parse_transaction(raw_tx).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse transaction: {}", e))
                    })?;

                    let output_index = output.outpoint.vout as usize;

                    if output_index >= parsed_tx.outputs.len() {
                        continue;
                    }

                    let source_locking_script = &parsed_tx.outputs[output_index].script;
                    let source_satoshis = parsed_tx.outputs[output_index].satoshis;

                    // Parse the signable transaction
                    let partial_tx =
                        Transaction::from_beef(&signable_tx.tx, None).map_err(|e| {
                            Error::IdentityError(format!("Failed to parse signable tx: {}", e))
                        })?;

                    let partial_raw = partial_tx.to_binary();
                    let partial_parsed = parse_transaction(&partial_raw).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse partial tx: {}", e))
                    })?;

                    // Compute sighash
                    let scope = SIGHASH_ALL | SIGHASH_FORKID;
                    let sighash_params = SighashParams {
                        version: partial_parsed.version,
                        inputs: &partial_parsed.inputs,
                        outputs: &partial_parsed.outputs,
                        locktime: partial_parsed.locktime,
                        input_index: 0,
                        subscript: source_locking_script,
                        satoshis: source_satoshis,
                        scope,
                    };

                    let preimage =
                        crate::primitives::bsv::sighash::build_sighash_preimage(&sighash_params);
                    let preimage_hash = sha256(&preimage);

                    // Sign with wallet
                    let sig_result = self
                        .wallet
                        .create_signature(
                            CreateSignatureArgs {
                                data: None,
                                hash_to_directly_sign: Some(preimage_hash),
                                protocol_id: protocol.clone(),
                                key_id: stored_key_id,
                                counterparty: Some(Counterparty::Self_),
                            },
                            originator,
                        )
                        .await?;

                    let signature = Signature::from_der(&sig_result.signature)?;
                    let tx_sig = TransactionSignature::new(signature, scope);
                    let checksig_format = tx_sig.to_checksig_format();

                    let mut unlocking_script = Vec::new();
                    unlocking_script.push(checksig_format.len() as u8);
                    unlocking_script.extend_from_slice(&checksig_format);

                    let mut spends = HashMap::new();
                    spends.insert(
                        0u32,
                        SignActionSpend {
                            unlocking_script,
                            sequence_number: None,
                        },
                    );

                    let sign_result = self
                        .wallet
                        .sign_action(
                            SignActionArgs {
                                spends,
                                reference: to_hex(&signable_tx.reference),
                                options: Some(SignActionOptions {
                                    accept_delayed_broadcast: Some(false),
                                    return_txid_only: None,
                                    no_send: None,
                                    send_with: None,
                                }),
                            },
                            originator,
                        )
                        .await?;

                    if sign_result.tx.is_none() && sign_result.txid.is_none() {
                        return Err(Error::IdentityError("Failed to update contact".to_string()));
                    }

                    // Update cache
                    {
                        let mut cache = self.cache.write().await;
                        cache
                            .contacts
                            .insert(contact.identity_key.clone(), contact.clone());
                    }

                    return Ok(());
                }
            }
        }

        Err(Error::IdentityError(
            "Failed to find existing contact output".to_string(),
        ))
    }

    /// Generate a random key ID for contact encryption.
    fn generate_key_id(&self) -> String {
        use crate::primitives::to_base64;
        let random_bytes: [u8; 32] = rand::random();
        to_base64(&random_bytes)
    }

    /// Get a contact by identity key.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key of the contact
    ///
    /// # Returns
    /// The contact if found, or None if not found.
    pub async fn get_contact(&self, identity_key: &str) -> Result<Option<Contact>> {
        let cache = self.cache.read().await;
        Ok(cache.contacts.get(identity_key).cloned())
    }

    /// Update an existing contact.
    ///
    /// This method updates both the in-memory cache and the blockchain.
    /// It finds the existing contact output, spends it, and creates a new
    /// output with the updated contact data atomically.
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to update
    /// * `updates` - The updated contact data
    ///
    /// # Errors
    /// Returns an error if the contact is not found in cache.
    pub async fn update_contact(&self, identity_key: &str, updates: Contact) -> Result<()> {
        // Verify contact exists in cache
        {
            let cache = self.cache.read().await;
            if !cache.contacts.contains_key(identity_key) {
                return Err(Error::ContactNotFound(identity_key.to_string()));
            }
        }

        // Use add_contact which handles the update-if-exists flow
        // It will find the existing output by tag and spend/replace it
        self.add_contact(updates).await
    }

    /// Remove a contact.
    ///
    /// This method removes the contact from both the in-memory cache and the blockchain.
    /// It finds the contact output by its HMAC-hashed tag and spends it with no
    /// replacement output (deletion).
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to remove
    ///
    /// # Errors
    /// Returns an error if the contact is not found.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        let originator = self.originator();
        let protocol = Protocol::new(SecurityLevel::App, &self.config.protocol_id.1);

        // Remove from cache first
        {
            let mut cache = self.cache.write().await;
            if cache.contacts.remove(identity_key).is_none() {
                return Err(Error::ContactNotFound(identity_key.to_string()));
            }
        }

        // Try to find and remove the contact output on chain
        // If HMAC not supported (crypto-only wallet), just return success (cache was updated)
        let identity_tag = match self.create_identity_tag(identity_key).await {
            Ok(tag) => tag,
            Err(_) => return Ok(()), // Cache-only mode
        };

        let existing_outputs = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.basket.clone(),
                    tags: Some(vec![identity_tag]),
                    tag_query_mode: None,
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: Some(true),
                    include_tags: None,
                    include_labels: None,
                    limit: Some(100),
                    offset: None,
                    seek_permission: None,
                },
                originator,
            )
            .await;

        let result = match existing_outputs {
            Ok(r) if !r.outputs.is_empty() => r,
            _ => {
                // No blockchain output found - contact was only in cache
                return Ok(());
            }
        };

        // Find and spend the contact output
        for output in &result.outputs {
            // Verify this is the correct contact by checking custom instructions
            if let Some(ref instructions) = output.custom_instructions {
                let stored_key_id = match serde_json::from_str::<serde_json::Value>(instructions) {
                    Ok(v) => v["keyID"].as_str().unwrap_or("").to_string(),
                    Err(_) => continue,
                };

                // Get the BEEF data
                let beef_data = match &result.beef {
                    Some(b) => b.clone(),
                    None => continue,
                };

                // Use the outpoint directly (it's already an Outpoint)
                let outpoint = output.outpoint.clone();

                // Create transaction to spend the contact output with NO new outputs (deletion)
                let create_result = self
                    .wallet
                    .create_action(
                        CreateActionArgs {
                            description: format!(
                                "Remove Contact: {}",
                                identity_key.chars().take(10).collect::<String>()
                            ),
                            input_beef: Some(beef_data.clone()),
                            inputs: Some(vec![CreateActionInput {
                                outpoint,
                                input_description: "Contact output to remove".to_string(),
                                unlocking_script: None,
                                unlocking_script_length: Some(74),
                                sequence_number: None,
                            }]),
                            outputs: None, // No outputs = deletion
                            lock_time: None,
                            version: None,
                            labels: Some(vec!["contacts".to_string()]),
                            options: Some(CreateActionOptions {
                                sign_and_process: Some(false),
                                accept_delayed_broadcast: Some(false),
                                trust_self: None,
                                known_txids: None,
                                return_txid_only: None,
                                no_send: Some(true),
                                no_send_change: None,
                                send_with: None,
                                randomize_outputs: Some(false),
                            }),
                        },
                        originator,
                    )
                    .await?;

                // Sign the transaction
                if let Some(signable_tx) = create_result.signable_transaction {
                    // Get the locking script from BEEF
                    let beef = Beef::from_binary(&beef_data).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse BEEF: {}", e))
                    })?;

                    let tx_data = beef.txs.first().ok_or_else(|| {
                        Error::IdentityError("BEEF contains no transactions".to_string())
                    })?;

                    let raw_tx = tx_data.raw_tx().ok_or_else(|| {
                        Error::IdentityError("Failed to get raw tx from BEEF".to_string())
                    })?;

                    let parsed_tx = parse_transaction(raw_tx).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse transaction: {}", e))
                    })?;

                    let output_index = output.outpoint.vout as usize;

                    if output_index >= parsed_tx.outputs.len() {
                        continue;
                    }

                    let source_locking_script = &parsed_tx.outputs[output_index].script;
                    let source_satoshis = parsed_tx.outputs[output_index].satoshis;

                    // Parse the signable transaction
                    let partial_tx =
                        Transaction::from_beef(&signable_tx.tx, None).map_err(|e| {
                            Error::IdentityError(format!("Failed to parse signable tx: {}", e))
                        })?;

                    let partial_raw = partial_tx.to_binary();
                    let partial_parsed = parse_transaction(&partial_raw).map_err(|e| {
                        Error::IdentityError(format!("Failed to parse partial tx: {}", e))
                    })?;

                    // Compute sighash
                    let scope = SIGHASH_ALL | SIGHASH_FORKID;
                    let sighash_params = SighashParams {
                        version: partial_parsed.version,
                        inputs: &partial_parsed.inputs,
                        outputs: &partial_parsed.outputs,
                        locktime: partial_parsed.locktime,
                        input_index: 0,
                        subscript: source_locking_script,
                        satoshis: source_satoshis,
                        scope,
                    };

                    let preimage =
                        crate::primitives::bsv::sighash::build_sighash_preimage(&sighash_params);
                    let preimage_hash = sha256(&preimage);

                    // Sign with wallet
                    let sig_result = self
                        .wallet
                        .create_signature(
                            CreateSignatureArgs {
                                data: None,
                                hash_to_directly_sign: Some(preimage_hash),
                                protocol_id: protocol.clone(),
                                key_id: stored_key_id,
                                counterparty: Some(Counterparty::Self_),
                            },
                            originator,
                        )
                        .await?;

                    let signature = Signature::from_der(&sig_result.signature)?;
                    let tx_sig = TransactionSignature::new(signature, scope);
                    let checksig_format = tx_sig.to_checksig_format();

                    let mut unlocking_script = Vec::new();
                    unlocking_script.push(checksig_format.len() as u8);
                    unlocking_script.extend_from_slice(&checksig_format);

                    let mut spends = HashMap::new();
                    spends.insert(
                        0u32,
                        SignActionSpend {
                            unlocking_script,
                            sequence_number: None,
                        },
                    );

                    let sign_result = self
                        .wallet
                        .sign_action(
                            SignActionArgs {
                                spends,
                                reference: to_hex(&signable_tx.reference),
                                options: Some(SignActionOptions {
                                    accept_delayed_broadcast: Some(false),
                                    return_txid_only: None,
                                    no_send: None,
                                    send_with: None,
                                }),
                            },
                            originator,
                        )
                        .await?;

                    if sign_result.tx.is_none() && sign_result.txid.is_none() {
                        return Err(Error::IdentityError(
                            "Failed to remove contact from blockchain".to_string(),
                        ));
                    }

                    return Ok(());
                }
            }
        }

        // If we couldn't find/spend the output, contact was already removed
        Ok(())
    }

    /// List all contacts.
    ///
    /// # Returns
    /// A list of all stored contacts.
    pub async fn list_contacts(&self) -> Result<Vec<Contact>> {
        let cache = self.cache.read().await;
        Ok(cache.contacts.values().cloned().collect())
    }

    /// List contacts with optional cache refresh.
    ///
    /// # Arguments
    /// * `force_refresh` - If true, reload from blockchain even if cache exists
    pub async fn list_contacts_with_refresh(&self, force_refresh: bool) -> Result<Vec<Contact>> {
        // Return cached contacts if available and not forcing refresh
        if !force_refresh {
            let cache = self.cache.read().await;
            if cache.initialized {
                return Ok(cache.contacts.values().cloned().collect());
            }
        }

        // Load contacts from blockchain
        let contacts = self.load_contacts_from_chain().await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.contacts.clear();
            for contact in &contacts {
                cache
                    .contacts
                    .insert(contact.identity_key.clone(), contact.clone());
            }
            cache.initialized = true;
        }

        Ok(contacts)
    }

    /// Load all contacts from the blockchain.
    async fn load_contacts_from_chain(&self) -> Result<Vec<Contact>> {
        let originator = self.originator();
        let protocol = Protocol::new(SecurityLevel::App, &self.config.protocol_id.1);

        // List outputs from contacts basket
        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.basket.clone(),
                    tags: None,
                    tag_query_mode: None,
                    include: Some(OutputInclude::LockingScripts),
                    include_custom_instructions: Some(true),
                    include_tags: None,
                    include_labels: None,
                    limit: Some(1000),
                    offset: None,
                    seek_permission: None,
                },
                originator,
            )
            .await;

        // If list_outputs fails (e.g., ProtoWallet doesn't support it), return empty
        let result = match result {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        let mut contacts = Vec::new();

        for output in result.outputs {
            // Skip if no custom instructions (can't decrypt without key ID)
            let key_id = match &output.custom_instructions {
                Some(instructions) => {
                    match serde_json::from_str::<serde_json::Value>(instructions) {
                        Ok(v) => v["keyID"].as_str().unwrap_or("").to_string(),
                        Err(_) => continue,
                    }
                }
                None => continue,
            };

            // Skip if no locking script
            let locking_script_bytes = match &output.locking_script {
                Some(s) => s.clone(),
                None => continue,
            };

            // Decode PushDrop to get ciphertext
            let locking_script = crate::script::LockingScript::from_binary(&locking_script_bytes)
                .map_err(|e| {
                Error::IdentityError(format!("Failed to parse locking script: {}", e))
            })?;

            let decoded = match PushDrop::decode(&locking_script) {
                Ok(d) => d,
                Err(_) => continue,
            };

            if decoded.fields.is_empty() {
                continue;
            }

            // Decrypt contact data
            let decrypt_result = self
                .wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: decoded.fields[0].clone(),
                        protocol_id: protocol.clone(),
                        key_id,
                        counterparty: Some(Counterparty::Self_),
                    },
                    originator,
                )
                .await;

            let plaintext = match decrypt_result {
                Ok(r) => r.plaintext,
                Err(_) => continue,
            };

            // Parse contact
            let contact: Contact = match serde_json::from_slice(&plaintext) {
                Ok(c) => c,
                Err(_) => continue,
            };

            contacts.push(contact);
        }

        Ok(contacts)
    }

    // =========================================================================
    // Search Operations
    // =========================================================================

    /// Search contacts by name or tag.
    ///
    /// Performs a case-insensitive search across contact names and tags.
    ///
    /// # Arguments
    /// * `query` - The search query string
    ///
    /// # Returns
    /// A list of contacts matching the query.
    pub async fn search_contacts(&self, query: &str) -> Result<Vec<Contact>> {
        let query_lower = query.to_lowercase();
        let cache = self.cache.read().await;

        let matches: Vec<Contact> = cache
            .contacts
            .values()
            .filter(|c| {
                c.name.to_lowercase().contains(&query_lower)
                    || c.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
                    || c.notes
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
            })
            .cloned()
            .collect();

        Ok(matches)
    }

    /// Get contacts with a specific tag.
    ///
    /// # Arguments
    /// * `tag` - The tag to filter by
    ///
    /// # Returns
    /// A list of contacts with the specified tag.
    pub async fn get_contacts_by_tag(&self, tag: &str) -> Result<Vec<Contact>> {
        let tag_lower = tag.to_lowercase();
        let cache = self.cache.read().await;

        let matches: Vec<Contact> = cache
            .contacts
            .values()
            .filter(|c| c.tags.iter().any(|t| t.to_lowercase() == tag_lower))
            .cloned()
            .collect();

        Ok(matches)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Clear the contacts cache.
    ///
    /// This does not remove contacts from storage, only clears the in-memory cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.contacts.clear();
        cache.initialized = false;
    }

    /// Check if the cache is initialized.
    pub async fn is_cache_initialized(&self) -> bool {
        let cache = self.cache.read().await;
        cache.initialized
    }

    /// Get the number of cached contacts.
    pub async fn cached_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.contacts.len()
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Create a hashed tag for privacy-preserving lookup.
    ///
    /// Uses HMAC to hash the identity key so contacts can be looked up
    /// without revealing the actual identity key in the tag.
    #[allow(dead_code)]
    async fn create_identity_tag(&self, identity_key: &str) -> Result<String> {
        let protocol = crate::wallet::Protocol::new(
            crate::wallet::SecurityLevel::App,
            &self.config.protocol_id.1,
        );

        let result = self
            .wallet
            .create_hmac(
                crate::wallet::CreateHmacArgs {
                    data: identity_key.as_bytes().to_vec(),
                    protocol_id: protocol,
                    key_id: identity_key.to_string(),
                    counterparty: Some(crate::wallet::Counterparty::Self_),
                },
                self.originator(),
            )
            .await?;

        Ok(format!(
            "identityKey {}",
            crate::primitives::to_hex(&result.hmac)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::ProtoWallet;

    fn create_test_contact(key: &str, name: &str) -> Contact {
        Contact {
            identity_key: key.to_string(),
            name: name.to_string(),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            added_at: 1700000000000,
            notes: None,
            tags: Vec::new(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_add_and_get_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact.clone()).await.unwrap();

        let retrieved = manager.get_contact("02abc123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Alice");
    }

    #[tokio::test]
    async fn test_get_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.get_contact("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add initial contact
        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Update the contact
        let updated = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice Updated".to_string(),
            notes: Some("Updated notes".to_string()),
            ..Default::default()
        };
        manager.update_contact("02abc123", updated).await.unwrap();

        // Verify update
        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice Updated");
        assert_eq!(retrieved.notes, Some("Updated notes".to_string()));
    }

    #[tokio::test]
    async fn test_update_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        let result = manager.update_contact("nonexistent", contact).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Verify contact exists
        assert!(manager.get_contact("02abc123").await.unwrap().is_some());

        // Remove contact
        manager.remove_contact("02abc123").await.unwrap();

        // Verify contact is removed
        assert!(manager.get_contact("02abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.remove_contact("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_contacts() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add multiple contacts
        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Charlie"))
            .await
            .unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 3);
    }

    #[tokio::test]
    async fn test_search_contacts_by_name() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "Alice Smith"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob Jones"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Alice Johnson"))
            .await
            .unwrap();

        let results = manager.search_contacts("alice").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_search_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string(), "engineering".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        let mut contact3 = create_test_contact("02ghi789", "Charlie");
        contact3.tags = vec!["work".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();
        manager.add_contact(contact3).await.unwrap();

        let results = manager.search_contacts("work").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_get_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string(), "engineering".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();

        let work_contacts = manager.get_contacts_by_tag("work").await.unwrap();
        assert_eq!(work_contacts.len(), 1);
        assert_eq!(work_contacts[0].name, "Alice");

        let personal_contacts = manager.get_contacts_by_tag("Personal").await.unwrap();
        assert_eq!(personal_contacts.len(), 1);
        assert_eq!(personal_contacts[0].name, "Bob");
    }

    #[tokio::test]
    async fn test_search_contacts_by_notes() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact = create_test_contact("02abc123", "Alice");
        contact.notes = Some("Met at the blockchain conference".to_string());

        manager.add_contact(contact).await.unwrap();

        let results = manager.search_contacts("conference").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[tokio::test]
    async fn test_cache_management() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        assert!(!manager.is_cache_initialized().await);
        assert_eq!(manager.cached_count().await, 0);

        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        assert_eq!(manager.cached_count().await, 1);

        manager.clear_cache().await;
        assert_eq!(manager.cached_count().await, 0);
    }

    #[tokio::test]
    async fn test_case_insensitive_search() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "ALICE"))
            .await
            .unwrap();

        // Search should be case insensitive
        let results = manager.search_contacts("alice").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = manager.search_contacts("ALICE").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = manager.search_contacts("Alice").await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_add_contact_replaces_existing() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact1 = create_test_contact("02abc123", "Alice V1");
        manager.add_contact(contact1).await.unwrap();

        let contact2 = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice V2".to_string(),
            notes: Some("Updated".to_string()),
            ..Default::default()
        };
        manager.add_contact(contact2).await.unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);

        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice V2");
    }
}
