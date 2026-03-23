//! Registry client implementation.
//!
//! Provides the `RegistryClient` for managing on-chain definitions
//! of baskets, protocols, and certificate types.
//!
//! ## Cross-SDK Compatibility
//!
//! This client matches the Go SDK's `RegistryClient` API:
//! - `register_definition(data)` - single method for all types
//! - `resolve_basket/protocol/certificate(query)` - separate resolve methods
//! - `list_own_registry_entries(definition_type)` - takes definition type
//! - `revoke_own_registry_entry(record)` - takes RegistryRecord

use crate::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, TopicBroadcaster, TopicBroadcasterConfig,
};
use crate::primitives::{from_hex, to_hex, PublicKey};
use crate::registry::types::{
    BasketDefinitionData, BasketQuery, BroadcastFailure, BroadcastSuccess,
    CertificateDefinitionData, CertificateQuery, DefinitionData, DefinitionType,
    ProtocolDefinitionData, ProtocolQuery, RegisterDefinitionResult, RegistryRecord,
    RevokeDefinitionResult, TokenData, UpdateDefinitionResult,
};
use crate::registry::REGISTRANT_TOKEN_AMOUNT;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::transaction::Transaction;
use crate::wallet::interface::WalletInterface;
use crate::wallet::{
    CreateActionArgs, CreateActionInput, CreateActionOutput, GetPublicKeyArgs, ListOutputsArgs,
    Outpoint, OutputInclude, SignActionArgs, SignActionSpend,
};
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for RegistryClient.
#[derive(Clone)]
pub struct RegistryClientConfig {
    /// Network preset (Mainnet, Testnet, Local).
    pub network_preset: NetworkPreset,
    /// Custom lookup resolver.
    pub resolver: Option<Arc<LookupResolver>>,
    /// Originator for wallet operations.
    pub originator: Option<String>,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: bool,
}

impl Default for RegistryClientConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            resolver: None,
            originator: None,
            accept_delayed_broadcast: false,
        }
    }
}

impl RegistryClientConfig {
    /// Creates a new configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the network preset.
    pub fn with_network(mut self, preset: NetworkPreset) -> Self {
        self.network_preset = preset;
        self
    }

    /// Sets a custom resolver.
    pub fn with_resolver(mut self, resolver: Arc<LookupResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Sets the originator.
    pub fn with_originator(mut self, originator: impl Into<String>) -> Self {
        self.originator = Some(originator.into());
        self
    }

    /// Sets whether to accept delayed broadcast.
    pub fn with_delayed_broadcast(mut self, accept: bool) -> Self {
        self.accept_delayed_broadcast = accept;
        self
    }
}

// =============================================================================
// Registry Client
// =============================================================================

/// Client for interacting with the BSV registry.
///
/// The registry client provides methods for:
/// - Registering new basket, protocol, and certificate definitions
/// - Resolving existing definitions by query
/// - Managing (listing, revoking) owned definitions
///
/// ## API Compatibility
///
/// This client matches the Go SDK's `RegistryClient` interface:
/// - `register_definition(data)` - single method for all definition types
/// - `resolve_basket/protocol/certificate(query)` - separate resolve methods
/// - `list_own_registry_entries(definition_type)` - takes definition type parameter
/// - `revoke_own_registry_entry(record)` - takes RegistryRecord
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::registry::{RegistryClient, RegistryClientConfig, BasketDefinitionData, DefinitionData};
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(Some(PrivateKey::random()));
/// let client = RegistryClient::new(wallet, RegistryClientConfig::default());
///
/// // Register a basket
/// let data = BasketDefinitionData::new("my_basket", "My Basket");
/// let result = client.register_definition(data.into()).await?;
/// ```
pub struct RegistryClient<W: WalletInterface> {
    wallet: W,
    config: RegistryClientConfig,
    resolver: Arc<LookupResolver>,
}

impl<W: WalletInterface> RegistryClient<W> {
    /// Creates a new RegistryClient.
    pub fn new(wallet: W, config: RegistryClientConfig) -> Self {
        let resolver = config.resolver.clone().unwrap_or_else(|| {
            Arc::new(LookupResolver::new(LookupResolverConfig {
                network_preset: config.network_preset,
                ..Default::default()
            }))
        });

        Self {
            wallet,
            config,
            resolver,
        }
    }

    /// Returns the originator string for wallet operations.
    fn originator(&self) -> &str {
        self.config
            .originator
            .as_deref()
            .unwrap_or("registry-client")
    }

    /// Gets the identity key for the wallet as hex string.
    async fn get_identity_key_hex(&self) -> Result<String> {
        let result = self
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

        Ok(result.public_key)
    }

    /// Gets the identity public key for the wallet.
    async fn get_identity_public_key(&self) -> Result<PublicKey> {
        let hex = self.get_identity_key_hex().await?;
        PublicKey::from_hex(&hex)
    }

    // =========================================================================
    // Registration Methods
    // =========================================================================

    /// Registers a new definition (basket, protocol, or certificate).
    ///
    /// Creates an on-chain PushDrop token containing the definition data.
    /// This matches the Go SDK's `RegisterDefinition` method.
    ///
    /// # Arguments
    ///
    /// * `data` - The definition data (registry_operator will be set automatically)
    ///
    /// # Returns
    ///
    /// A `RegisterDefinitionResult` with success or failure information.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let basket_data = BasketDefinitionData::new("my_basket", "My Basket");
    /// let result = client.register_definition(basket_data.into()).await?;
    /// if result.is_success() {
    ///     println!("Registered at txid: {}", result.success.unwrap().txid);
    /// }
    /// ```
    pub async fn register_definition(
        &self,
        mut data: DefinitionData,
    ) -> Result<RegisterDefinitionResult> {
        // Get identity key and set as registry operator
        let registry_operator = self.get_identity_key_hex().await?;
        data.set_registry_operator(registry_operator.clone());

        let def_type = data.get_definition_type();

        // Get identity public key for PushDrop locking
        let identity_pubkey = self.get_identity_public_key().await?;

        // Build PushDrop fields using the correct format (individual fields, not JSON blob)
        let fields = data.to_pushdrop_fields(&registry_operator)?;

        // Create PushDrop locking script
        let pushdrop = PushDrop::new(identity_pubkey, fields);
        let locking_script = pushdrop.lock();

        // Create the registration transaction
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!("Register a new {} item", def_type.as_str()),
                    inputs: None,
                    input_beef: None,
                    outputs: Some(vec![CreateActionOutput {
                        locking_script: locking_script.to_binary(),
                        satoshis: REGISTRANT_TOKEN_AMOUNT,
                        output_description: format!("New {} registration token", def_type.as_str()),
                        basket: Some(def_type.wallet_basket().to_string()),
                        custom_instructions: None,
                        tags: None,
                    }]),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["registry".to_string(), def_type.as_str().to_string()]),
                    options: None,
                },
                self.originator(),
            )
            .await?;

        // Check for transaction creation failure
        if create_result.tx.is_none() {
            return Err(Error::RegistryError(format!(
                "Failed to create {} registration transaction",
                def_type.as_str()
            )));
        }

        // Extract transaction details
        let txid = create_result.txid.ok_or_else(|| {
            Error::RegistryError("No transaction ID in create result".to_string())
        })?;

        // Broadcast to the appropriate topic
        let topic = def_type.broadcast_topic().to_string();
        let mut broadcast_success = None;
        let mut broadcast_failure = None;

        if let Some(ref tx_bytes) = create_result.tx {
            if let Ok(tx) = Transaction::from_beef(tx_bytes, None) {
                match TopicBroadcaster::new(
                    vec![topic],
                    TopicBroadcasterConfig {
                        network_preset: self.config.network_preset,
                        ..Default::default()
                    },
                ) {
                    Ok(broadcaster) => {
                        let result = broadcaster.broadcast_tx(&tx).await;
                        if result.is_ok() {
                            broadcast_success = Some(BroadcastSuccess {
                                txid: to_hex(&txid),
                                message: "success".to_string(),
                            });
                        } else {
                            broadcast_failure = Some(BroadcastFailure {
                                code: "BROADCAST_ERROR".to_string(),
                                description: "Failed to broadcast to overlay".to_string(),
                            });
                        }
                    }
                    Err(e) => {
                        broadcast_failure = Some(BroadcastFailure {
                            code: "BROADCASTER_ERROR".to_string(),
                            description: e.to_string(),
                        });
                    }
                }
            }
        }

        // Default to success if we got a txid
        if broadcast_success.is_none() && broadcast_failure.is_none() {
            broadcast_success = Some(BroadcastSuccess {
                txid: to_hex(&txid),
                message: "created".to_string(),
            });
        }

        Ok(RegisterDefinitionResult {
            success: broadcast_success,
            failure: broadcast_failure,
        })
    }

    // =========================================================================
    // Resolution Methods
    // =========================================================================

    /// Resolves basket definitions matching the query.
    ///
    /// # Arguments
    ///
    /// * `query` - Filter criteria for basket definitions
    ///
    /// # Returns
    ///
    /// List of matching basket definitions.
    pub async fn resolve_basket(&self, query: BasketQuery) -> Result<Vec<BasketDefinitionData>> {
        let service = DefinitionType::Basket.lookup_service();
        let query_json = serde_json::to_value(&query)
            .map_err(|e| Error::RegistryError(format!("Failed to serialize query: {}", e)))?;

        let question = LookupQuestion::new(service, query_json);
        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut results = Vec::new();
                for output in outputs {
                    if let Ok(Some(data)) = self.parse_basket_from_output(&output) {
                        results.push(data);
                    }
                }
                Ok(results)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Resolves protocol definitions matching the query.
    ///
    /// # Arguments
    ///
    /// * `query` - Filter criteria for protocol definitions
    ///
    /// # Returns
    ///
    /// List of matching protocol definitions.
    pub async fn resolve_protocol(
        &self,
        query: ProtocolQuery,
    ) -> Result<Vec<ProtocolDefinitionData>> {
        let service = DefinitionType::Protocol.lookup_service();
        let query_json = serde_json::to_value(&query)
            .map_err(|e| Error::RegistryError(format!("Failed to serialize query: {}", e)))?;

        let question = LookupQuestion::new(service, query_json);
        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut results = Vec::new();
                for output in outputs {
                    if let Ok(Some(data)) = self.parse_protocol_from_output(&output) {
                        results.push(data);
                    }
                }
                Ok(results)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Resolves certificate definitions matching the query.
    ///
    /// # Arguments
    ///
    /// * `query` - Filter criteria for certificate definitions
    ///
    /// # Returns
    ///
    /// List of matching certificate definitions.
    pub async fn resolve_certificate(
        &self,
        query: CertificateQuery,
    ) -> Result<Vec<CertificateDefinitionData>> {
        let service = DefinitionType::Certificate.lookup_service();
        let query_json = serde_json::to_value(&query)
            .map_err(|e| Error::RegistryError(format!("Failed to serialize query: {}", e)))?;

        let question = LookupQuestion::new(service, query_json);
        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut results = Vec::new();
                for output in outputs {
                    if let Ok(Some(data)) = self.parse_certificate_from_output(&output) {
                        results.push(data);
                    }
                }
                Ok(results)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Parses a basket definition from an overlay output.
    fn parse_basket_from_output(
        &self,
        output: &OutputListItem,
    ) -> Result<Option<BasketDefinitionData>> {
        let tx = Transaction::from_beef(&output.beef, None)
            .map_err(|e| Error::RegistryError(format!("Failed to parse BEEF: {}", e)))?;

        let tx_output = tx
            .outputs
            .get(output.output_index as usize)
            .ok_or_else(|| Error::RegistryError("Output index out of bounds".into()))?;

        let pushdrop = PushDrop::decode(&tx_output.locking_script)
            .map_err(|e| Error::RegistryError(format!("Failed to decode PushDrop: {}", e)))?;

        if pushdrop.fields.len() != 6 {
            return Ok(None);
        }

        BasketDefinitionData::from_pushdrop_fields(&pushdrop.fields).map(Some)
    }

    /// Parses a protocol definition from an overlay output.
    fn parse_protocol_from_output(
        &self,
        output: &OutputListItem,
    ) -> Result<Option<ProtocolDefinitionData>> {
        let tx = Transaction::from_beef(&output.beef, None)
            .map_err(|e| Error::RegistryError(format!("Failed to parse BEEF: {}", e)))?;

        let tx_output = tx
            .outputs
            .get(output.output_index as usize)
            .ok_or_else(|| Error::RegistryError("Output index out of bounds".into()))?;

        let pushdrop = PushDrop::decode(&tx_output.locking_script)
            .map_err(|e| Error::RegistryError(format!("Failed to decode PushDrop: {}", e)))?;

        if pushdrop.fields.len() != 6 {
            return Ok(None);
        }

        ProtocolDefinitionData::from_pushdrop_fields(&pushdrop.fields).map(Some)
    }

    /// Parses a certificate definition from an overlay output.
    fn parse_certificate_from_output(
        &self,
        output: &OutputListItem,
    ) -> Result<Option<CertificateDefinitionData>> {
        let tx = Transaction::from_beef(&output.beef, None)
            .map_err(|e| Error::RegistryError(format!("Failed to parse BEEF: {}", e)))?;

        let tx_output = tx
            .outputs
            .get(output.output_index as usize)
            .ok_or_else(|| Error::RegistryError("Output index out of bounds".into()))?;

        let pushdrop = PushDrop::decode(&tx_output.locking_script)
            .map_err(|e| Error::RegistryError(format!("Failed to decode PushDrop: {}", e)))?;

        if pushdrop.fields.len() != 7 {
            return Ok(None);
        }

        CertificateDefinitionData::from_pushdrop_fields(&pushdrop.fields).map(Some)
    }

    // =========================================================================
    // Management Methods
    // =========================================================================

    /// Lists registry entries owned by this wallet for the given definition type.
    ///
    /// This matches the Go SDK's `ListOwnRegistryEntries` method which takes
    /// a definition type parameter.
    ///
    /// # Arguments
    ///
    /// * `definition_type` - The type of definitions to list (Basket, Protocol, or Certificate)
    ///
    /// # Returns
    ///
    /// List of registry records owned by this wallet.
    pub async fn list_own_registry_entries(
        &self,
        definition_type: DefinitionType,
    ) -> Result<Vec<RegistryRecord>> {
        let basket = definition_type.wallet_basket().to_string();

        let list_result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket,
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: Some(true),
                    include_tags: Some(true),
                    include_labels: Some(true),
                    tags: None,
                    tag_query_mode: None,
                    limit: None,
                    offset: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;

        let mut records = Vec::new();

        for output in list_result.outputs {
            // Skip non-spendable outputs
            if !output.spendable {
                continue;
            }

            // Parse the locking script
            if let Some(ref script_bytes) = output.locking_script {
                if let Ok(script) = LockingScript::from_binary(script_bytes) {
                    // Decode PushDrop
                    if let Ok(pushdrop) = PushDrop::decode(&script) {
                        // Verify field count matches expected
                        if pushdrop.fields.len() != definition_type.expected_field_count() {
                            continue;
                        }

                        // Create token data
                        let token = TokenData::with_beef(
                            to_hex(&output.outpoint.txid),
                            output.outpoint.vout,
                            output.satoshis,
                            script.to_hex(),
                            list_result.beef.clone().unwrap_or_default(),
                        );

                        // Parse definition based on type
                        let record = match definition_type {
                            DefinitionType::Basket => {
                                BasketDefinitionData::from_pushdrop_fields(&pushdrop.fields)
                                    .ok()
                                    .map(|def| RegistryRecord::basket(def, token))
                            }
                            DefinitionType::Protocol => {
                                ProtocolDefinitionData::from_pushdrop_fields(&pushdrop.fields)
                                    .ok()
                                    .map(|def| RegistryRecord::protocol(def, token))
                            }
                            DefinitionType::Certificate => {
                                CertificateDefinitionData::from_pushdrop_fields(&pushdrop.fields)
                                    .ok()
                                    .map(|def| RegistryRecord::certificate(def, token))
                            }
                        };

                        if let Some(r) = record {
                            records.push(r);
                        }
                    }
                }
            }
        }

        Ok(records)
    }

    /// Revokes an existing registry entry.
    ///
    /// Spends the token to remove the definition from the registry.
    /// This matches the Go SDK's `RevokeOwnRegistryEntry` method.
    ///
    /// # Arguments
    ///
    /// * `record` - The registry record to revoke
    ///
    /// # Returns
    ///
    /// A `RevokeDefinitionResult` with success or failure information.
    pub async fn revoke_own_registry_entry(
        &self,
        record: &RegistryRecord,
    ) -> Result<RevokeDefinitionResult> {
        // Validate record
        if record.txid().is_empty() || record.token.locking_script.is_empty() {
            return Err(Error::RegistryError(
                "Invalid registry record - missing txid or lockingScript".to_string(),
            ));
        }

        // Verify ownership
        let identity_key = self.get_identity_key_hex().await?;
        if record.get_registry_operator() != identity_key {
            return Err(Error::RegistryError(
                "This registry token does not belong to the current wallet".to_string(),
            ));
        }

        let def_type = record.get_definition_type();

        // Get item identifier for description
        let item_identifier = match &record.definition {
            DefinitionData::Basket(d) => d.basket_id.clone(),
            DefinitionData::Protocol(d) => d.name.clone(),
            DefinitionData::Certificate(d) => {
                if !d.name.is_empty() {
                    d.name.clone()
                } else {
                    d.cert_type.clone()
                }
            }
        };

        // Parse outpoint
        let txid_bytes = from_hex(record.txid())
            .map_err(|e| Error::RegistryError(format!("Invalid txid: {}", e)))?;
        let mut txid_arr = [0u8; 32];
        if txid_bytes.len() != 32 {
            return Err(Error::RegistryError("Invalid txid length".to_string()));
        }
        txid_arr.copy_from_slice(&txid_bytes);

        // Create the revocation transaction (spend with no outputs)
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!("Revoke {} item: {}", def_type.as_str(), item_identifier),
                    inputs: Some(vec![CreateActionInput {
                        outpoint: Outpoint {
                            txid: txid_arr,
                            vout: record.output_index(),
                        },
                        unlocking_script: None,
                        unlocking_script_length: Some(74), // Estimated signature length (matches TypeScript SDK)
                        input_description: format!("Revoking {} token", def_type.as_str()),
                        sequence_number: None,
                    }]),
                    input_beef: record.token.beef.clone(),
                    outputs: None, // No outputs - just spending the token
                    lock_time: None,
                    version: None,
                    labels: Some(vec![
                        "registry".to_string(),
                        "revoke".to_string(),
                        def_type.as_str().to_string(),
                    ]),
                    options: None,
                },
                self.originator(),
            )
            .await?;

        // Check for signable transaction
        if create_result.signable_transaction.is_none() {
            return Err(Error::RegistryError(
                "Failed to create signable transaction".to_string(),
            ));
        }

        // Sign the transaction
        if let Some(ref signable_tx) = create_result.signable_transaction {
            let mut spends = HashMap::new();
            spends.insert(
                record.output_index(),
                SignActionSpend {
                    unlocking_script: vec![],
                    sequence_number: None,
                },
            );

            let sign_result = self
                .wallet
                .sign_action(
                    SignActionArgs {
                        reference: String::from_utf8(signable_tx.reference.clone())
                            .unwrap_or_default(),
                        spends,
                        options: None,
                    },
                    self.originator(),
                )
                .await?;

            if sign_result.tx.is_none() {
                return Err(Error::RegistryError(
                    "Failed to get signed transaction".to_string(),
                ));
            }

            // Broadcast the revocation to the appropriate topic
            let topic = def_type.broadcast_topic().to_string();
            let mut broadcast_success = None;
            let mut broadcast_failure = None;

            if let Some(ref tx_bytes) = sign_result.tx {
                if let Ok(tx) = Transaction::from_beef(tx_bytes, None) {
                    match TopicBroadcaster::new(
                        vec![topic],
                        TopicBroadcasterConfig {
                            network_preset: self.config.network_preset,
                            ..Default::default()
                        },
                    ) {
                        Ok(broadcaster) => {
                            let result = broadcaster.broadcast_tx(&tx).await;
                            if result.is_ok() {
                                broadcast_success = Some(BroadcastSuccess {
                                    txid: tx.id(),
                                    message: "success".to_string(),
                                });
                            } else {
                                broadcast_failure = Some(BroadcastFailure {
                                    code: "BROADCAST_ERROR".to_string(),
                                    description: "Failed to broadcast revocation".to_string(),
                                });
                            }
                        }
                        Err(e) => {
                            broadcast_failure = Some(BroadcastFailure {
                                code: "BROADCASTER_ERROR".to_string(),
                                description: e.to_string(),
                            });
                        }
                    }
                }
            }

            // Default to success if we got signed tx
            if broadcast_success.is_none() && broadcast_failure.is_none() {
                broadcast_success = Some(BroadcastSuccess {
                    txid: "signed".to_string(),
                    message: "created".to_string(),
                });
            }

            return Ok(RevokeDefinitionResult {
                success: broadcast_success,
                failure: broadcast_failure,
            });
        }

        Err(Error::RegistryError(
            "Failed to sign revocation transaction".to_string(),
        ))
    }

    /// Updates an existing registry entry by spending its UTXO and creating
    /// a new one with updated data in a single transaction.
    ///
    /// This matches the TypeScript SDK's `updateDefinition` method.
    ///
    /// # Arguments
    ///
    /// * `record` - The existing registry record to update
    /// * `updated_data` - The new definition data (must be same type as record)
    ///
    /// # Returns
    ///
    /// An `UpdateDefinitionResult` with success or failure information.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Get existing entry
    /// let entries = client.list_own_registry_entries(DefinitionType::Basket).await?;
    /// let record = &entries[0];
    ///
    /// // Create updated data
    /// let updated = BasketDefinitionData::new("my_basket", "Updated Basket Name")
    ///     .with_description("New description");
    ///
    /// // Update the entry
    /// let result = client.update_definition(record, updated.into()).await?;
    /// ```
    pub async fn update_definition(
        &self,
        record: &RegistryRecord,
        mut updated_data: DefinitionData,
    ) -> Result<UpdateDefinitionResult> {
        // Validate record has required fields
        if record.txid().is_empty() || record.token.locking_script.is_empty() {
            return Err(Error::RegistryError(
                "Invalid registry record - missing txid or lockingScript".to_string(),
            ));
        }

        // Verify the updated data matches the record type
        if record.get_definition_type() != updated_data.get_definition_type() {
            return Err(Error::RegistryError(format!(
                "Cannot change definition type from {} to {}",
                record.get_definition_type(),
                updated_data.get_definition_type()
            )));
        }

        // Verify ownership
        let identity_key = self.get_identity_key_hex().await?;
        if record.get_registry_operator() != identity_key {
            return Err(Error::RegistryError(
                "This registry token does not belong to the current wallet".to_string(),
            ));
        }

        let def_type = record.get_definition_type();

        // Get item identifier for description
        let item_identifier = match &record.definition {
            DefinitionData::Basket(d) => d.basket_id.clone(),
            DefinitionData::Protocol(d) => d.name.clone(),
            DefinitionData::Certificate(d) => {
                if !d.name.is_empty() {
                    d.name.clone()
                } else {
                    d.cert_type.clone()
                }
            }
        };

        // Set registry operator on updated data
        updated_data.set_registry_operator(identity_key.clone());

        // Get identity public key for PushDrop locking
        let identity_pubkey = self.get_identity_public_key().await?;

        // Build PushDrop fields for the new locking script
        let fields = updated_data.to_pushdrop_fields(&identity_key)?;

        // Create new PushDrop locking script
        let pushdrop = PushDrop::new(identity_pubkey, fields);
        let new_locking_script = pushdrop.lock();

        // Parse outpoint
        let txid_bytes = from_hex(record.txid())
            .map_err(|e| Error::RegistryError(format!("Invalid txid: {}", e)))?;
        let mut txid_arr = [0u8; 32];
        if txid_bytes.len() != 32 {
            return Err(Error::RegistryError("Invalid txid length".to_string()));
        }
        txid_arr.copy_from_slice(&txid_bytes);

        // Create the update transaction (spend old UTXO, create new one)
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: format!("Update {} item: {}", def_type.as_str(), item_identifier),
                    inputs: Some(vec![CreateActionInput {
                        outpoint: Outpoint {
                            txid: txid_arr,
                            vout: record.output_index(),
                        },
                        unlocking_script: None,
                        unlocking_script_length: Some(74), // Matches TypeScript SDK
                        input_description: format!("Updating {} token", def_type.as_str()),
                        sequence_number: None,
                    }]),
                    input_beef: record.token.beef.clone(),
                    outputs: Some(vec![CreateActionOutput {
                        locking_script: new_locking_script.to_binary(),
                        satoshis: REGISTRANT_TOKEN_AMOUNT,
                        output_description: format!(
                            "Updated {} registration token",
                            def_type.as_str()
                        ),
                        basket: Some(def_type.wallet_basket().to_string()),
                        custom_instructions: None,
                        tags: None,
                    }]),
                    lock_time: None,
                    version: None,
                    labels: Some(vec![
                        "registry".to_string(),
                        "update".to_string(),
                        def_type.as_str().to_string(),
                    ]),
                    options: None,
                },
                self.originator(),
            )
            .await?;

        // Check for signable transaction
        if create_result.signable_transaction.is_none() {
            return Err(Error::RegistryError(
                "Failed to create signable transaction".to_string(),
            ));
        }

        // Sign the transaction
        if let Some(ref signable_tx) = create_result.signable_transaction {
            let mut spends = HashMap::new();
            spends.insert(
                record.output_index(),
                SignActionSpend {
                    unlocking_script: vec![],
                    sequence_number: None,
                },
            );

            let sign_result = self
                .wallet
                .sign_action(
                    SignActionArgs {
                        reference: String::from_utf8(signable_tx.reference.clone())
                            .unwrap_or_default(),
                        spends,
                        options: None,
                    },
                    self.originator(),
                )
                .await?;

            if sign_result.tx.is_none() {
                return Err(Error::RegistryError(
                    "Failed to get signed transaction".to_string(),
                ));
            }

            // Broadcast the update to the appropriate topic
            let topic = def_type.broadcast_topic().to_string();
            let mut broadcast_success = None;
            let mut broadcast_failure = None;

            if let Some(ref tx_bytes) = sign_result.tx {
                if let Ok(tx) = Transaction::from_beef(tx_bytes, None) {
                    match TopicBroadcaster::new(
                        vec![topic],
                        TopicBroadcasterConfig {
                            network_preset: self.config.network_preset,
                            ..Default::default()
                        },
                    ) {
                        Ok(broadcaster) => {
                            let result = broadcaster.broadcast_tx(&tx).await;
                            if result.is_ok() {
                                broadcast_success = Some(BroadcastSuccess {
                                    txid: tx.id(),
                                    message: "success".to_string(),
                                });
                            } else {
                                broadcast_failure = Some(BroadcastFailure {
                                    code: "BROADCAST_ERROR".to_string(),
                                    description: "Failed to broadcast update".to_string(),
                                });
                            }
                        }
                        Err(e) => {
                            broadcast_failure = Some(BroadcastFailure {
                                code: "BROADCASTER_ERROR".to_string(),
                                description: e.to_string(),
                            });
                        }
                    }
                }
            }

            // Default to success if we got signed tx
            if broadcast_success.is_none() && broadcast_failure.is_none() {
                broadcast_success = Some(BroadcastSuccess {
                    txid: "signed".to_string(),
                    message: "created".to_string(),
                });
            }

            return Ok(UpdateDefinitionResult {
                success: broadcast_success,
                failure: broadcast_failure,
            });
        }

        Err(Error::RegistryError(
            "Failed to sign update transaction".to_string(),
        ))
    }

    /// Sets the network preset.
    ///
    /// This matches the Go SDK's `SetNetwork` method.
    pub fn set_network(&mut self, network: NetworkPreset) {
        self.config.network_preset = network;
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{Protocol as WalletProtocol, SecurityLevel};

    #[test]
    fn test_config_defaults() {
        let config = RegistryClientConfig::default();
        assert_eq!(config.network_preset, NetworkPreset::Mainnet);
        assert!(config.resolver.is_none());
        assert!(config.originator.is_none());
        assert!(!config.accept_delayed_broadcast);
    }

    #[test]
    fn test_config_builder() {
        let config = RegistryClientConfig::new()
            .with_network(NetworkPreset::Testnet)
            .with_originator("myapp.com")
            .with_delayed_broadcast(true);

        assert_eq!(config.network_preset, NetworkPreset::Testnet);
        assert_eq!(config.originator, Some("myapp.com".to_string()));
        assert!(config.accept_delayed_broadcast);
    }

    #[test]
    fn test_pushdrop_fields_format_basket() {
        // Verify the field format matches Go/TS SDKs
        // Basket: 6 fields (basketID, name, iconURL, description, documentationURL, registryOperator)
        let data = BasketDefinitionData::new("my_basket", "My Basket")
            .with_icon_url("icon.png")
            .with_description("desc")
            .with_documentation_url("docs.html");

        let fields = data.to_pushdrop_fields("02abc123");
        assert_eq!(fields.len(), 6);
        assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "my_basket");
        assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Basket");
        assert_eq!(String::from_utf8(fields[2].clone()).unwrap(), "icon.png");
        assert_eq!(String::from_utf8(fields[3].clone()).unwrap(), "desc");
        assert_eq!(String::from_utf8(fields[4].clone()).unwrap(), "docs.html");
        assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), "02abc123");
    }

    #[test]
    fn test_pushdrop_fields_format_protocol() {
        // Protocol: 6 fields (protocolID JSON, name, iconURL, description, documentationURL, registryOperator)
        let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
        let data = ProtocolDefinitionData::new(protocol, "My Protocol").with_description("desc");

        let fields = data.to_pushdrop_fields("02abc123").unwrap();
        assert_eq!(fields.len(), 6);

        // First field should be JSON serialized protocol
        let protocol_json = String::from_utf8(fields[0].clone()).unwrap();
        assert!(protocol_json.contains("my_protocol"));

        assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Protocol");
        assert_eq!(String::from_utf8(fields[5].clone()).unwrap(), "02abc123");
    }

    #[test]
    fn test_pushdrop_fields_format_certificate() {
        // Certificate: 7 fields (type, name, iconURL, description, documentationURL, fields JSON, registryOperator)
        use crate::registry::CertificateFieldDescriptor;

        let data = CertificateDefinitionData::new("cert_type", "My Cert")
            .with_description("desc")
            .with_field("email", CertificateFieldDescriptor::text("Email"));

        let fields = data.to_pushdrop_fields("02abc123").unwrap();
        assert_eq!(fields.len(), 7);

        assert_eq!(String::from_utf8(fields[0].clone()).unwrap(), "cert_type");
        assert_eq!(String::from_utf8(fields[1].clone()).unwrap(), "My Cert");

        // Field 5 should be JSON serialized fields map
        let fields_json = String::from_utf8(fields[5].clone()).unwrap();
        assert!(fields_json.contains("email"));

        assert_eq!(String::from_utf8(fields[6].clone()).unwrap(), "02abc123");
    }

    #[test]
    fn test_definition_data_conversion() {
        let basket = BasketDefinitionData::new("b", "Basket");
        let data: DefinitionData = basket.into();
        assert_eq!(data.get_definition_type(), DefinitionType::Basket);

        let protocol =
            ProtocolDefinitionData::new(WalletProtocol::new(SecurityLevel::App, "p"), "Protocol");
        let data: DefinitionData = protocol.into();
        assert_eq!(data.get_definition_type(), DefinitionType::Protocol);
    }

    #[test]
    fn test_update_definition_result() {
        use crate::registry::UpdateDefinitionResult;

        let success_result = UpdateDefinitionResult {
            success: Some(BroadcastSuccess {
                txid: "abc123".to_string(),
                message: "success".to_string(),
            }),
            failure: None,
        };
        assert!(success_result.is_success());
        assert!(!success_result.is_failure());

        let failure_result = UpdateDefinitionResult {
            success: None,
            failure: Some(BroadcastFailure {
                code: "ERR".to_string(),
                description: "Failed".to_string(),
            }),
        };
        assert!(!failure_result.is_success());
        assert!(failure_result.is_failure());
    }
}
