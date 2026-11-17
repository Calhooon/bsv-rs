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
use crate::primitives::{from_hex, to_base64, to_hex};
use crate::registry::types::{
    BasketDefinitionData, BasketQuery, BroadcastFailure, BroadcastSuccess,
    CertificateDefinitionData, CertificateQuery, DefinitionData, DefinitionType,
    ProtocolDefinitionData, ProtocolQuery, RegisterDefinitionResult, RegistryRecord,
    RevokeDefinitionResult, TokenData, UpdateDefinitionResult,
};
use crate::registry::{definition_checks, token, unlock, REGISTRANT_TOKEN_AMOUNT};
use crate::script::LockingScript;
use crate::transaction::Transaction;
use crate::wallet::interface::WalletInterface;
use crate::wallet::{
    CreateActionArgs, CreateActionInput, CreateActionOutput, GetPublicKeyArgs, ListOutputsArgs,
    Outpoint, OutputInclude, SignActionArgs,
};
use crate::{Error, Result};
use std::sync::Arc;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for RegistryClient.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::registry::RegistryClientConfig) -> bsv_rs::registry::RegistryClientConfig {
///     bsv_rs::registry::RegistryClientConfig { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::registry::RegistryClientConfig) -> bsv_rs::registry::RegistryClientConfig {
///     value
/// }
/// ```
#[derive(Clone)]
#[non_exhaustive]
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

crate::util::non_exhaustive::assert_no_drop!(
    RegistryClientConfig,
    bsv_rs::registry::RegistryClientConfig
);

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

    /// Returns the configured originator for wallet operations, `None` when
    /// none is configured, as the reference's `#originator` (#329).
    fn originator(&self) -> Option<&str> {
        self.config.originator.as_deref()
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
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;

        Ok(result.public_key)
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

        // The data fields, signed and locked as RegistryClient.ts:314-320 does (#543)
        let fields = data.to_pushdrop_fields(&registry_operator)?;
        let locking_script =
            token::lock_definition(&self.wallet, def_type, fields, self.originator()).await?;

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
    /// The basket definitions the lookup answered that pass the registry
    /// reader's checks and match the query.
    pub async fn resolve_basket(&self, query: BasketQuery) -> Result<Vec<BasketDefinitionData>> {
        let outputs = self.lookup(DefinitionType::Basket, &query).await?;
        Ok(read_definitions(
            outputs,
            DefinitionType::Basket,
            BasketDefinitionData::from_pushdrop_fields,
            |data| definition_checks::basket_answers(&query, data),
        ))
    }

    /// Resolves protocol definitions matching the query.
    ///
    /// # Arguments
    ///
    /// * `query` - Filter criteria for protocol definitions
    ///
    /// # Returns
    ///
    /// The protocol definitions the lookup answered that pass the registry
    /// reader's checks and match the query.
    pub async fn resolve_protocol(
        &self,
        query: ProtocolQuery,
    ) -> Result<Vec<ProtocolDefinitionData>> {
        let outputs = self.lookup(DefinitionType::Protocol, &query).await?;
        Ok(read_definitions(
            outputs,
            DefinitionType::Protocol,
            ProtocolDefinitionData::from_pushdrop_fields,
            |data| definition_checks::protocol_answers(&query, data),
        ))
    }

    /// Resolves certificate definitions matching the query.
    ///
    /// # Arguments
    ///
    /// * `query` - Filter criteria for certificate definitions
    ///
    /// # Returns
    ///
    /// The certificate definitions the lookup answered that pass the registry
    /// reader's checks and match the query.
    pub async fn resolve_certificate(
        &self,
        query: CertificateQuery,
    ) -> Result<Vec<CertificateDefinitionData>> {
        let outputs = self.lookup(DefinitionType::Certificate, &query).await?;
        Ok(read_definitions(
            outputs,
            DefinitionType::Certificate,
            CertificateDefinitionData::from_pushdrop_fields,
            |data| definition_checks::certificate_answers(&query, data),
        ))
    }

    /// The outputs the definition type's lookup service answers the query
    /// with; an answer of another kind is none.
    async fn lookup(
        &self,
        definition_type: DefinitionType,
        query: &impl serde::Serialize,
    ) -> Result<Vec<OutputListItem>> {
        let query_json = serde_json::to_value(query)
            .map_err(|e| Error::RegistryError(format!("Failed to serialize query: {}", e)))?;
        let question = LookupQuestion::new(definition_type.lookup_service(), query_json);
        match self.resolver.query(&question, None).await? {
            LookupAnswer::OutputList { outputs } => Ok(outputs),
            _ => Ok(Vec::new()),
        }
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
                    // registryTokenValidation.ts:57-64: lock-before (#537), signed (#543)
                    if let Ok(fields) = token::data_fields(definition_type, &script) {
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
                                BasketDefinitionData::from_pushdrop_fields(&fields)
                                    .ok()
                                    .map(|def| RegistryRecord::basket(def, token))
                            }
                            DefinitionType::Protocol => {
                                ProtocolDefinitionData::from_pushdrop_fields(&fields)
                                    .ok()
                                    .map(|def| RegistryRecord::protocol(def, token))
                            }
                            DefinitionType::Certificate => {
                                CertificateDefinitionData::from_pushdrop_fields(&fields)
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
            // The token's spend, unlocked as RegistryClient.ts:540-548 and :630-639 do (#548)
            let spends =
                unlock::token_spends(&self.wallet, &signable_tx.tx, record, self.originator())
                    .await?;

            let sign_result = self
                .wallet
                .sign_action(
                    SignActionArgs {
                        reference: to_base64(&signable_tx.reference),
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

        // The data fields, signed and locked as RegistryClient.ts:620-628 does (#543)
        let fields = updated_data.to_pushdrop_fields(&identity_key)?;
        let new_locking_script =
            token::lock_definition(&self.wallet, def_type, fields, self.originator()).await?;

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
            // The token's spend, unlocked as RegistryClient.ts:540-548 and :630-639 do (#548)
            let spends =
                unlock::token_spends(&self.wallet, &signable_tx.tx, record, self.originator())
                    .await?;

            let sign_result = self
                .wallet
                .sign_action(
                    SignActionArgs {
                        reference: to_base64(&signable_tx.reference),
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

/// The definitions a lookup answered, in its order: each output's token read
/// and verified (`token::data_fields`), its fields passing the registry
/// reader's checks (`definition_checks`), parsed, and kept when `answers`
/// says the query asked for it; any other output skipped.
fn read_definitions<T>(
    outputs: Vec<OutputListItem>,
    definition_type: DefinitionType,
    parse: fn(&[Vec<u8>]) -> Result<T>,
    answers: impl Fn(&T) -> bool,
) -> Vec<T> {
    let read = |output: &OutputListItem| {
        // Reads only this output's own locking script below; the input ancestry
        // is never used, so link nothing (#749 fold2 ruling 1, carried to the
        // release's relocated registry reader — fold3 ruling 5b). A linking
        // `from_beef` here would drop an honest high-fan registry answer for a
        // byte budget it never had to meet, and re-open the #749 door at this site.
        let tx = Transaction::from_beef_subject(&output.beef, None).ok()?;
        let tx_output = tx.outputs().get(output.output_index as usize)?;
        let fields = token::data_fields(definition_type, &tx_output.locking_script).ok()?;
        definition_checks::fields_admitted(definition_type, &fields)
            .then(|| parse(&fields).ok())
            .flatten()
            .filter(&answers)
    };
    outputs.iter().filter_map(read).collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
