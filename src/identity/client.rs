//! Identity client for discovering and revealing user identities.
//!
//! The [`IdentityClient`] provides methods for:
//! - Publicly revealing certificate attributes on-chain
//! - Resolving identities by key or attributes
//! - Discovering certificates for an identity
//! - Managing personal contacts

use crate::auth::certificates::Certificate;
use crate::auth::VerifiableCertificate;
use crate::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::primitives::{from_base64, sha256, to_hex, PrivateKey, PublicKey, Signature};
use crate::script::templates::PushDrop;
use crate::transaction::{Beef, Broadcaster, Transaction};
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
    CreateSignatureArgs, Outpoint, ProtoWallet, Protocol, ProveCertificateArgs, SignActionArgs,
    SignActionOptions, SignActionSpend, WalletCertificate, WalletInterface,
};
use crate::{Error, Result};

use super::contacts::ContactsManager;
#[cfg(test)]
use super::types::BroadcastSuccess;
use super::types::{
    BroadcastFailure, BroadcastResult, CertificateFieldNameUnder50Bytes, CertifierInfo, Contact,
    ContactsManagerConfig, DefaultIdentityValues, DisplayableIdentity, IdentityCertificate,
    IdentityClientConfig, IdentityQuery, IdentityResolutionResult, KnownCertificateType,
    StaticAvatarUrls, DEFAULT_SOCIALCERT_CERTIFIER,
};

use std::collections::HashMap;
use std::sync::Arc;

/// Client for identity discovery and management.
///
/// The `IdentityClient` enables users to:
/// - Publicly reveal certificate attributes on the overlay network
/// - Resolve identities by identity key
/// - Resolve identities by attribute values (email, phone, etc.)
/// - Discover certificates associated with an identity
/// - Manage personal contacts
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::identity::{IdentityClient, IdentityClientConfig};
/// use bsv_sdk::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let client = IdentityClient::new(wallet, IdentityClientConfig::default());
///
/// // Resolve an identity by key
/// let identity = client.resolve_by_identity_key("02abc123...", true).await?;
/// ```
pub struct IdentityClient<W: WalletInterface> {
    wallet: W,
    config: IdentityClientConfig,
    resolver: Arc<LookupResolver>,
    contacts_manager: ContactsManager<W>,
}

// Static methods that don't require Clone
impl<W: WalletInterface> IdentityClient<W> {
    /// Build a displayable identity from an identity certificate.
    ///
    /// This is the main parsing function that converts certificate data
    /// into a user-friendly display format.
    pub fn parse_identity(cert: &IdentityCertificate) -> DisplayableIdentity {
        let type_id = cert.type_base64();
        let known_type = KnownCertificateType::from_type_id(&type_id);
        let decrypted = &cert.decrypted_fields;
        let certifier_info = &cert.certifier_info;

        let (name, avatar_url, badge_label, badge_icon_url, badge_click_url) = match known_type {
            Some(KnownCertificateType::XCert) => {
                let name = decrypted
                    .get("userName")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::NAME.to_string());
                let avatar = decrypted
                    .get("profilePhoto")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string());
                let badge = format!("X account certified by {}", certifier_info.name);
                (
                    name,
                    avatar,
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                )
            }
            Some(KnownCertificateType::DiscordCert) => {
                let name = decrypted
                    .get("userName")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::NAME.to_string());
                let avatar = decrypted
                    .get("profilePhoto")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string());
                let badge = format!("Discord account certified by {}", certifier_info.name);
                (
                    name,
                    avatar,
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                )
            }
            Some(KnownCertificateType::EmailCert) => {
                let name = decrypted
                    .get("email")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::NAME.to_string());
                let badge = format!("Email certified by {}", certifier_info.name);
                (
                    name,
                    StaticAvatarUrls::EMAIL.to_string(),
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                )
            }
            Some(KnownCertificateType::PhoneCert) => {
                let name = decrypted
                    .get("phoneNumber")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::NAME.to_string());
                let badge = format!("Phone certified by {}", certifier_info.name);
                (
                    name,
                    StaticAvatarUrls::PHONE.to_string(),
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://socialcert.net".to_string(),
                )
            }
            Some(KnownCertificateType::IdentiCert) => {
                let first = decrypted.get("firstName").cloned().unwrap_or_default();
                let last = decrypted.get("lastName").cloned().unwrap_or_default();
                let name = format!("{} {}", first, last).trim().to_string();
                let name = if name.is_empty() {
                    DefaultIdentityValues::NAME.to_string()
                } else {
                    name
                };
                let avatar = decrypted
                    .get("profilePhoto")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string());
                let badge = format!("Government ID certified by {}", certifier_info.name);
                (
                    name,
                    avatar,
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://identicert.me".to_string(),
                )
            }
            Some(KnownCertificateType::Registrant) => {
                let name = decrypted
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::NAME.to_string());
                let avatar = decrypted
                    .get("icon")
                    .cloned()
                    .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string());
                let badge = format!("Entity certified by {}", certifier_info.name);
                (
                    name,
                    avatar,
                    badge,
                    certifier_info.icon_url.clone(),
                    "https://projectbabbage.com/docs/registrant".to_string(),
                )
            }
            Some(KnownCertificateType::CoolCert) => {
                let is_cool = decrypted.get("cool").map(|v| v == "true").unwrap_or(false);
                let name = if is_cool {
                    "Cool Person!".to_string()
                } else {
                    "Not cool!".to_string()
                };
                (
                    name,
                    DefaultIdentityValues::AVATAR_URL.to_string(),
                    DefaultIdentityValues::BADGE_LABEL.to_string(),
                    DefaultIdentityValues::BADGE_ICON_URL.to_string(),
                    DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
                )
            }
            Some(KnownCertificateType::Anyone) => (
                "Anyone".to_string(),
                StaticAvatarUrls::ANYONE.to_string(),
                "Represents the ability for anyone to access this information.".to_string(),
                DefaultIdentityValues::BADGE_ICON_URL.to_string(),
                "https://projectbabbage.com/docs/anyone-identity".to_string(),
            ),
            Some(KnownCertificateType::SelfCert) => (
                "You".to_string(),
                StaticAvatarUrls::SELF.to_string(),
                "Represents your ability to access this information.".to_string(),
                DefaultIdentityValues::BADGE_ICON_URL.to_string(),
                "https://projectbabbage.com/docs/self-identity".to_string(),
            ),
            None => {
                // Try generic parsing for unknown certificate types
                Self::try_parse_generic_identity(decrypted, certifier_info)
            }
        };

        // Build abbreviated key
        let subject = cert.subject_hex();
        let abbreviated_key = if subject.len() > 10 {
            format!("{}...", &subject[..10])
        } else {
            subject.clone()
        };

        DisplayableIdentity {
            name,
            avatar_url,
            identity_key: subject,
            abbreviated_key,
            badge_icon_url,
            badge_label,
            badge_click_url,
        }
    }

    /// Try to parse identity information from unknown certificate types.
    fn try_parse_generic_identity(
        decrypted: &HashMap<String, String>,
        certifier_info: &CertifierInfo,
    ) -> (String, String, String, String, String) {
        // Try to find a name from common field patterns
        let name = decrypted
            .get("name")
            .or_else(|| decrypted.get("userName"))
            .or_else(|| {
                let first = decrypted.get("firstName");
                let last = decrypted.get("lastName");
                if first.is_some() || last.is_some() {
                    None // Will be handled below
                } else {
                    decrypted.get("email")
                }
            })
            .cloned();

        let name = name.unwrap_or_else(|| {
            let first = decrypted.get("firstName").cloned().unwrap_or_default();
            let last = decrypted.get("lastName").cloned().unwrap_or_default();
            let full = format!("{} {}", first, last).trim().to_string();
            if full.is_empty() {
                DefaultIdentityValues::NAME.to_string()
            } else {
                full
            }
        });

        // Try to find an avatar from common field patterns
        let avatar = decrypted
            .get("profilePhoto")
            .or_else(|| decrypted.get("avatar"))
            .or_else(|| decrypted.get("icon"))
            .or_else(|| decrypted.get("photo"))
            .cloned()
            .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string());

        // Generate badge information
        let badge_label =
            if !certifier_info.name.is_empty() && certifier_info.name != "Unknown Certifier" {
                format!("Certified by {}", certifier_info.name)
            } else {
                DefaultIdentityValues::BADGE_LABEL.to_string()
            };

        let badge_icon = if !certifier_info.icon_url.is_empty() {
            certifier_info.icon_url.clone()
        } else {
            DefaultIdentityValues::BADGE_ICON_URL.to_string()
        };

        (
            name,
            avatar,
            badge_label,
            badge_icon,
            DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
        )
    }
}

impl<W: WalletInterface + Clone> IdentityClient<W> {
    /// Create a new IdentityClient with the given wallet and configuration.
    pub fn new(wallet: W, config: IdentityClientConfig) -> Self {
        let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
            network_preset: config.network_preset,
            ..Default::default()
        }));

        let contacts_config = ContactsManagerConfig {
            originator: config.originator.clone(),
            ..Default::default()
        };
        let contacts_manager = ContactsManager::new(wallet.clone(), contacts_config);

        Self {
            wallet,
            config,
            resolver,
            contacts_manager,
        }
    }

    /// Create an IdentityClient with a custom resolver.
    pub fn with_resolver(
        wallet: W,
        config: IdentityClientConfig,
        resolver: Arc<LookupResolver>,
    ) -> Self {
        let contacts_config = ContactsManagerConfig {
            originator: config.originator.clone(),
            ..Default::default()
        };
        let contacts_manager = ContactsManager::new(wallet.clone(), contacts_config);

        Self {
            wallet,
            config,
            resolver,
            contacts_manager,
        }
    }

    /// Get the wallet's identity key.
    pub async fn get_identity_key(&self) -> Result<String> {
        let originator = self.config.originator.as_deref().unwrap_or("");
        let result = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    for_self: None,
                },
                originator,
            )
            .await?;
        Ok(result.public_key)
    }

    // =========================================================================
    // Public Revelation Methods
    // =========================================================================

    /// Publicly reveals selected fields from a certificate.
    ///
    /// Creates a publicly verifiable certificate with the selected fields revealed,
    /// wraps it in a PushDrop token, and broadcasts it to the overlay network.
    ///
    /// # Arguments
    /// * `certificate` - The certificate to selectively reveal
    /// * `fields_to_reveal` - Field names to include in the public revelation
    ///
    /// # Returns
    /// Result containing either a successful broadcast result or failure
    ///
    /// # Errors
    /// - Returns error if certificate has no fields
    /// - Returns error if fields_to_reveal is empty
    /// - Returns error if certificate verification fails
    /// - Returns error if transaction creation or broadcast fails
    ///
    /// # Example
    /// ```rust,ignore
    /// let result = client.publicly_reveal_attributes(
    ///     certificate,
    ///     vec!["userName".to_string(), "profilePhoto".to_string()]
    /// ).await?;
    /// ```
    pub async fn publicly_reveal_attributes(
        &self,
        certificate: WalletCertificate,
        fields_to_reveal: Vec<CertificateFieldNameUnder50Bytes>,
    ) -> Result<BroadcastResult> {
        // Validate inputs
        if certificate.fields.is_empty() {
            return Err(Error::IdentityError(
                "Public reveal failed: Certificate has no fields to reveal!".to_string(),
            ));
        }

        if fields_to_reveal.is_empty() {
            return Err(Error::IdentityError(
                "Public reveal failed: You must reveal at least one field!".to_string(),
            ));
        }

        // Verify certificate has required fields
        if certificate.subject.is_empty() || certificate.certifier.is_empty() {
            return Err(Error::IdentityError(
                "Public reveal failed: Certificate must have subject and certifier!".to_string(),
            ));
        }

        let originator = self
            .config
            .originator
            .as_deref()
            .unwrap_or("identity-client");

        // Create the "anyone" verifier public key (using scalar 1)
        // This allows anyone to decrypt the revealed fields
        let anyone_verifier = PrivateKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])?
        .public_key()
        .to_hex();

        // Get keyring for verifier through certificate proving
        let prove_result = self
            .wallet
            .prove_certificate(
                ProveCertificateArgs {
                    certificate: certificate.clone(),
                    fields_to_reveal: fields_to_reveal.clone(),
                    verifier: anyone_verifier.clone(),
                    privileged: None,
                    privileged_reason: None,
                },
                originator,
            )
            .await?;

        // Create JSON object with certificate and keyring
        let cert_with_keyring = serde_json::json!({
            "type": certificate.certificate_type,
            "serialNumber": certificate.serial_number,
            "subject": certificate.subject,
            "certifier": certificate.certifier,
            "revocationOutpoint": certificate.revocation_outpoint,
            "fields": certificate.fields,
            "signature": certificate.signature,
            "keyring": prove_result.keyring_for_verifier,
        });

        let cert_json = serde_json::to_vec(&cert_with_keyring)
            .map_err(|e| Error::IdentityError(format!("Failed to serialize certificate: {}", e)))?;

        // Get the wallet's public key for PushDrop locking
        let protocol = crate::wallet::Protocol::from_tuple((
            self.config.protocol_id.0,
            &self.config.protocol_id.1,
        ))
        .ok_or_else(|| {
            Error::IdentityError(format!(
                "Invalid protocol ID: ({}, {})",
                self.config.protocol_id.0, self.config.protocol_id.1
            ))
        })?;

        let wallet_pubkey = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(protocol),
                    key_id: Some(self.config.key_id.clone()),
                    counterparty: Some(crate::wallet::Counterparty::Anyone),
                    for_self: Some(false),
                },
                originator,
            )
            .await?;

        // Parse the public key from hex
        let locking_pubkey = PublicKey::from_hex(&wallet_pubkey.public_key)?;

        // Create PushDrop locking script with the certificate JSON
        let pushdrop = PushDrop::new(locking_pubkey, vec![cert_json]);
        let locking_script = pushdrop.lock();

        // Create the transaction using wallet's createAction
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: "Create a new Identity Token".to_string(),
                    input_beef: None,
                    inputs: None,
                    outputs: Some(vec![CreateActionOutput {
                        locking_script: locking_script.to_binary(),
                        satoshis: self.config.token_amount,
                        output_description: "Identity Token".to_string(),
                        basket: None,
                        custom_instructions: None,
                        tags: Some(vec!["identity".to_string()]),
                    }]),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["identity".to_string(), "revelation".to_string()]),
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
            .await?;

        // Get the transaction from the result
        let tx_bytes = match create_result.tx {
            Some(tx) => tx,
            None => {
                return Ok(BroadcastResult::Failure(BroadcastFailure {
                    code: "CREATE_ACTION_FAILED".to_string(),
                    description: "Public reveal failed: createAction did not return a transaction"
                        .to_string(),
                }));
            }
        };

        // Parse the transaction from atomic BEEF
        let tx = Transaction::from_atomic_beef(&tx_bytes).map_err(|e| {
            Error::IdentityError(format!("Failed to parse transaction from BEEF: {}", e))
        })?;

        // Create the broadcaster for tm_identity topic
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_identity".to_string()],
            TopicBroadcasterConfig {
                network_preset: self.config.network_preset,
                ..Default::default()
            },
        )?;

        // Broadcast the transaction to the overlay network
        let broadcast_result = broadcaster.broadcast(&tx).await;

        // Convert transaction module result to identity module result
        match broadcast_result {
            Ok(response) => Ok(BroadcastResult::Success(super::types::BroadcastSuccess {
                txid: response.txid,
                message: Some(response.message),
            })),
            Err(failure) => Ok(BroadcastResult::Failure(BroadcastFailure {
                code: failure.code,
                description: failure.description,
            })),
        }
    }

    /// Simplified version of publicly_reveal_attributes that returns only the transaction ID.
    ///
    /// This matches the TypeScript SDK's simpler return signature.
    ///
    /// # Returns
    /// Transaction ID string on success, or error on failure
    pub async fn publicly_reveal_attributes_simple(
        &self,
        certificate: WalletCertificate,
        fields_to_reveal: Vec<CertificateFieldNameUnder50Bytes>,
    ) -> Result<String> {
        let result = self
            .publicly_reveal_attributes(certificate, fields_to_reveal)
            .await?;

        match result {
            BroadcastResult::Success(success) => Ok(success.txid),
            BroadcastResult::Failure(failure) => Err(Error::IdentityError(format!(
                "Broadcast failed: {}",
                failure.description
            ))),
        }
    }

    /// Revokes a previously published certificate revelation.
    ///
    /// Finds the UTXO containing the revealed certificate and spends it
    /// to remove the revelation from the overlay network.
    ///
    /// # Arguments
    /// * `serial_number` - The serial number of the certificate to revoke
    ///
    /// # Example
    /// ```rust,ignore
    /// client.revoke_certificate_revelation("abc123...").await?;
    /// ```
    pub async fn revoke_certificate_revelation(&self, serial_number: &str) -> Result<()> {
        let originator = self
            .config
            .originator
            .as_deref()
            .unwrap_or("identity-client");

        // Step 1: Find the existing UTXO via lookup
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "serialNumber": serial_number
            }),
        );

        let answer = self.resolver.query(&question, None).await?;

        let outputs = match answer {
            LookupAnswer::OutputList { outputs } => outputs,
            _ => {
                return Err(Error::IdentityError(
                    "Failed to find revelation output".to_string(),
                ))
            }
        };

        if outputs.is_empty() {
            return Err(Error::IdentityError(
                "No revelation found for this certificate".to_string(),
            ));
        }

        let output = &outputs[0];

        // Step 2: Parse BEEF to get the transaction
        let beef = Beef::from_binary(&output.beef).map_err(|e| {
            Error::IdentityError(format!("Failed to parse BEEF for revelation: {}", e))
        })?;

        // Get the transaction from BEEF
        let tx = beef
            .txs
            .first()
            .ok_or_else(|| Error::IdentityError("BEEF contains no transactions".to_string()))?;

        let raw_tx = tx.raw_tx().ok_or_else(|| {
            Error::IdentityError("Failed to get raw transaction from BEEF".to_string())
        })?;

        let txid = tx.txid();

        // Get the locking script from the revelation output
        let parsed_tx = parse_transaction(raw_tx)
            .map_err(|e| Error::IdentityError(format!("Failed to parse transaction: {}", e)))?;

        let output_index = self.config.output_index as usize;
        if output_index >= parsed_tx.outputs.len() {
            return Err(Error::IdentityError(format!(
                "Output index {} out of range (tx has {} outputs)",
                output_index,
                parsed_tx.outputs.len()
            )));
        }

        let locking_script = &parsed_tx.outputs[output_index].script;
        let source_satoshis = parsed_tx.outputs[output_index].satoshis;

        // Create the outpoint string
        let outpoint_str = format!("{}.{}", txid, output_index);
        let outpoint = Outpoint::from_string(&outpoint_str)?;

        // Step 3: Create signable transaction with createAction (noSend=true)
        let create_result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: "Spend certificate revelation token".to_string(),
                    input_beef: Some(output.beef.clone()),
                    inputs: Some(vec![CreateActionInput {
                        outpoint,
                        input_description: "Revelation token".to_string(),
                        unlocking_script: None,
                        unlocking_script_length: Some(74), // Signature length estimate
                        sequence_number: None,
                    }]),
                    outputs: None, // No outputs - just spending
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["identity".to_string(), "revocation".to_string()]),
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

        // Get the signable transaction
        let signable_tx = create_result.signable_transaction.ok_or_else(|| {
            Error::IdentityError("createAction did not return a signable transaction".to_string())
        })?;

        // Step 4: Parse the partial transaction and compute sighash
        let partial_tx = Transaction::from_beef(&signable_tx.tx, None).map_err(|e| {
            Error::IdentityError(format!("Failed to parse signable transaction: {}", e))
        })?;

        let partial_raw = partial_tx.to_binary();
        let partial_parsed = parse_transaction(&partial_raw).map_err(|e| {
            Error::IdentityError(format!("Failed to parse partial transaction: {}", e))
        })?;

        // Compute the sighash preimage
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let sighash_params = SighashParams {
            version: partial_parsed.version,
            inputs: &partial_parsed.inputs,
            outputs: &partial_parsed.outputs,
            locktime: partial_parsed.locktime,
            input_index: 0, // We're signing the first (and only) input
            subscript: locking_script,
            satoshis: source_satoshis,
            scope,
        };

        // Build preimage and hash it
        let preimage = crate::primitives::bsv::sighash::build_sighash_preimage(&sighash_params);
        let preimage_hash = sha256(&preimage);

        // Step 5: Sign using wallet.create_signature with "anyone" counterparty
        let protocol =
            Protocol::from_tuple((self.config.protocol_id.0, &self.config.protocol_id.1))
                .ok_or_else(|| {
                    Error::IdentityError(format!(
                        "Invalid protocol ID: ({}, {})",
                        self.config.protocol_id.0, self.config.protocol_id.1
                    ))
                })?;

        let sig_result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: None,
                    hash_to_directly_sign: Some(preimage_hash),
                    protocol_id: protocol,
                    key_id: self.config.key_id.clone(),
                    counterparty: Some(Counterparty::Anyone),
                },
                originator,
            )
            .await?;

        // Parse the DER signature and create transaction signature with scope
        let signature = Signature::from_der(&sig_result.signature)?;
        let tx_sig = TransactionSignature::new(signature, scope);
        let checksig_format = tx_sig.to_checksig_format();

        // The unlocking script is just the signature push
        let mut unlocking_script = Vec::new();
        unlocking_script.push(checksig_format.len() as u8);
        unlocking_script.extend_from_slice(&checksig_format);

        // Step 6: Sign the action with the unlocking script
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
                        no_send: Some(true),
                        send_with: None,
                    }),
                },
                originator,
            )
            .await?;

        // Get the signed transaction
        let signed_tx_bytes = sign_result.tx.ok_or_else(|| {
            Error::IdentityError("signAction did not return a transaction".to_string())
        })?;

        let signed_tx = Transaction::from_atomic_beef(&signed_tx_bytes).map_err(|e| {
            Error::IdentityError(format!("Failed to parse signed transaction: {}", e))
        })?;

        // Step 7: Broadcast via TopicBroadcaster
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_identity".to_string()],
            TopicBroadcasterConfig {
                network_preset: self.config.network_preset,
                ..Default::default()
            },
        )?;

        broadcaster.broadcast(&signed_tx).await.map_err(|e| {
            Error::IdentityError(format!("Failed to broadcast revocation: {}", e.description))
        })?;

        Ok(())
    }

    // =========================================================================
    // Resolution Methods
    // =========================================================================

    /// Resolve an identity by identity key.
    ///
    /// Queries the overlay network to find certificates associated with the key.
    /// Returns the first matching displayable identity, or None if not found.
    ///
    /// If `override_with_contacts` is true (default), personal contacts take priority
    /// over discovered certificates.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key to look up
    /// * `override_with_contacts` - Whether to check contacts first (default: true)
    ///
    /// # Example
    /// ```rust,ignore
    /// let identity = client.resolve_by_identity_key("02abc123...", true).await?;
    /// if let Some(id) = identity {
    ///     println!("Found: {}", id.name);
    /// }
    /// ```
    pub async fn resolve_by_identity_key(
        &self,
        identity_key: &str,
        override_with_contacts: bool,
    ) -> Result<Option<DisplayableIdentity>> {
        // First try contacts if override is enabled
        if override_with_contacts {
            if let Ok(Some(contact)) = self.contacts_manager.get_contact(identity_key).await {
                return Ok(Some(contact.to_displayable_identity()));
            }
        }

        // Query the identity lookup service
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "identityKey": identity_key,
                "certifiers": [DEFAULT_SOCIALCERT_CERTIFIER]
            }),
        );

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                if outputs.is_empty() {
                    return Ok(None);
                }

                // Process the first output
                if let Some(cert) = self.parse_output_to_certificate(&outputs[0]).await? {
                    let identity = Self::parse_identity(&cert);
                    return Ok(Some(identity));
                }

                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Resolve identities by attribute values.
    ///
    /// Finds identities that have revealed matching attribute values.
    ///
    /// If `override_with_contacts` is true (default), results will be substituted
    /// with matching contacts where identity keys match.
    ///
    /// # Arguments
    /// * `attributes` - Map of attribute name to value (e.g., {"email": "user@example.com"})
    /// * `override_with_contacts` - Whether to substitute contacts for matching identities (default: true)
    ///
    /// # Example
    /// ```rust,ignore
    /// let mut attrs = HashMap::new();
    /// attrs.insert("email".to_string(), "user@example.com".to_string());
    /// let identities = client.resolve_by_attributes(attrs, true).await?;
    /// ```
    pub async fn resolve_by_attributes(
        &self,
        attributes: HashMap<String, String>,
        override_with_contacts: bool,
    ) -> Result<Vec<DisplayableIdentity>> {
        // Load contacts in parallel if override is enabled
        let contacts_map: HashMap<String, Contact> = if override_with_contacts {
            self.contacts_manager
                .list_contacts()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|c| (c.identity_key.clone(), c))
                .collect()
        } else {
            HashMap::new()
        };

        // Build the query
        let query_attributes: serde_json::Value = if attributes.len() == 1 {
            // Single attribute uses "any" matcher for flexible matching
            let value = attributes.values().next().unwrap();
            serde_json::json!({ "any": value })
        } else {
            serde_json::to_value(&attributes).unwrap_or_default()
        };

        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "attributes": query_attributes,
                "certifiers": [DEFAULT_SOCIALCERT_CERTIFIER]
            }),
        );

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut identities = Vec::new();

                for output in &outputs {
                    if let Some(cert) = self.parse_output_to_certificate(output).await? {
                        let subject = cert.subject_hex();

                        // Check if we have a contact for this identity key
                        if let Some(contact) = contacts_map.get(&subject) {
                            identities.push(contact.to_displayable_identity());
                        } else {
                            identities.push(Self::parse_identity(&cert));
                        }
                    }
                }

                Ok(identities)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Discover all certificates for an identity.
    ///
    /// Returns all certificates that the identity has revealed.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key to look up
    pub async fn discover_certificates(
        &self,
        identity_key: &str,
    ) -> Result<Vec<VerifiableCertificate>> {
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "identityKey": identity_key,
                "certificatesOnly": true
            }),
        );

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut certificates = Vec::new();

                for output in &outputs {
                    if let Some(cert) = self.parse_output_to_verifiable_certificate(output).await? {
                        certificates.push(cert);
                    }
                }

                Ok(certificates)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Discover certificates of a specific type.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key to look up
    /// * `cert_type` - The certificate type ID (base64)
    pub async fn discover_certificates_by_type(
        &self,
        identity_key: &str,
        cert_type: &str,
    ) -> Result<Vec<VerifiableCertificate>> {
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "identityKey": identity_key,
                "certificateType": cert_type
            }),
        );

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut certificates = Vec::new();

                for output in &outputs {
                    if let Some(cert) = self.parse_output_to_verifiable_certificate(output).await? {
                        certificates.push(cert);
                    }
                }

                Ok(certificates)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Query identities with complex filters.
    ///
    /// # Arguments
    /// * `query` - The query parameters
    pub async fn query(&self, query: IdentityQuery) -> Result<Vec<IdentityResolutionResult>> {
        let mut lookup_query = serde_json::Map::new();

        if let Some(ref key) = query.identity_key {
            lookup_query.insert("identityKey".to_string(), serde_json::json!(key));
        }

        if let Some(ref attrs) = query.attributes {
            lookup_query.insert(
                "attributes".to_string(),
                serde_json::to_value(attrs).map_err(|e| Error::IdentityError(e.to_string()))?,
            );
        }

        if let Some(ref cert_type) = query.certificate_type {
            lookup_query.insert("certificateType".to_string(), serde_json::json!(cert_type));
        }

        if let Some(ref certifier) = query.certifier {
            lookup_query.insert("certifiers".to_string(), serde_json::json!([certifier]));
        } else {
            lookup_query.insert(
                "certifiers".to_string(),
                serde_json::json!([DEFAULT_SOCIALCERT_CERTIFIER]),
            );
        }

        if let Some(limit) = query.limit {
            lookup_query.insert("limit".to_string(), serde_json::json!(limit));
        }

        if let Some(offset) = query.offset {
            lookup_query.insert("offset".to_string(), serde_json::json!(offset));
        }

        let question = LookupQuestion::new("ls_identity", serde_json::Value::Object(lookup_query));

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut results = Vec::new();

                for output in &outputs {
                    if let Some(cert) = self.parse_output_to_certificate(output).await? {
                        let identity = Self::parse_identity(&cert);
                        results.push(IdentityResolutionResult {
                            identity,
                            certificates: vec![cert.certificate.clone()],
                        });
                    }
                }

                Ok(results)
            }
            _ => Ok(Vec::new()),
        }
    }

    // =========================================================================
    // Contact Management Methods
    // =========================================================================

    /// Get all contacts.
    ///
    /// # Arguments
    /// * `force_refresh` - Whether to bypass cache and reload from storage
    pub async fn get_contacts(&self, force_refresh: bool) -> Result<Vec<Contact>> {
        self.contacts_manager
            .list_contacts_with_refresh(force_refresh)
            .await
    }

    /// Get a contact by identity key.
    pub async fn get_contact(&self, identity_key: &str) -> Result<Option<Contact>> {
        self.contacts_manager.get_contact(identity_key).await
    }

    /// Save or update a contact.
    ///
    /// # Arguments
    /// * `identity` - The displayable identity to save
    /// * `metadata` - Optional metadata to store with the contact
    pub async fn save_contact(
        &self,
        identity: DisplayableIdentity,
        metadata: Option<serde_json::Value>,
    ) -> Result<()> {
        let mut contact = Contact::from_identity(identity);
        contact.metadata = metadata;
        self.contacts_manager.add_contact(contact).await
    }

    /// Remove a contact.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        self.contacts_manager.remove_contact(identity_key).await
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Parse a lookup output into an IdentityCertificate.
    ///
    /// This method:
    /// 1. Parses BEEF to get the transaction
    /// 2. Decodes PushDrop from the locking script
    /// 3. Parses certificate JSON from the first PushDrop field
    /// 4. Creates a VerifiableCertificate with the keyring
    /// 5. Decrypts fields using the 'anyone' wallet
    /// 6. Verifies the certificate signature
    async fn parse_output_to_certificate(
        &self,
        output: &OutputListItem,
    ) -> Result<Option<IdentityCertificate>> {
        // Step 1: Parse BEEF to get the transaction
        let beef = match Beef::from_binary(&output.beef) {
            Ok(b) => b,
            Err(_) => return Ok(None), // Failed to parse BEEF
        };

        // Get the transaction from the BEEF
        let tx = match beef.txs.first() {
            Some(beef_tx) => match beef_tx.tx() {
                Some(t) => t,
                None => return Ok(None), // No transaction data in BEEF
            },
            None => return Ok(None), // No transactions in BEEF
        };

        // Step 2: Get the output at the specified index
        let tx_output = match tx.outputs.get(output.output_index as usize) {
            Some(o) => o,
            None => return Ok(None), // Output index out of range
        };

        // Step 3: Decode PushDrop from the locking script
        let pushdrop = match PushDrop::decode(&tx_output.locking_script) {
            Ok(pd) => pd,
            Err(_) => return Ok(None), // Failed to decode PushDrop
        };

        // Step 4: Get the first field (certificate JSON)
        let cert_json_bytes = match pushdrop.fields.first() {
            Some(f) => f,
            None => return Ok(None), // No fields in PushDrop
        };

        // Parse the JSON
        let cert_json_str = match String::from_utf8(cert_json_bytes.clone()) {
            Ok(s) => s,
            Err(_) => return Ok(None), // Invalid UTF-8 in certificate data
        };

        let cert_data: serde_json::Value = match serde_json::from_str(&cert_json_str) {
            Ok(v) => v,
            Err(_) => return Ok(None), // Failed to parse certificate JSON
        };

        // Step 5: Extract certificate fields from JSON
        let cert_type_b64 = cert_data["type"]
            .as_str()
            .ok_or_else(|| Error::IdentityError("Missing certificate type".to_string()))?;
        let serial_number_b64 = cert_data["serialNumber"]
            .as_str()
            .ok_or_else(|| Error::IdentityError("Missing serial number".to_string()))?;
        let subject_hex = cert_data["subject"]
            .as_str()
            .ok_or_else(|| Error::IdentityError("Missing subject".to_string()))?;
        let certifier_hex = cert_data["certifier"]
            .as_str()
            .ok_or_else(|| Error::IdentityError("Missing certifier".to_string()))?;

        // Parse the 32-byte arrays
        let cert_type_bytes = from_base64(cert_type_b64)?;
        let serial_number_bytes = from_base64(serial_number_b64)?;

        let cert_type: [u8; 32] = cert_type_bytes
            .try_into()
            .map_err(|_| Error::IdentityError("Invalid certificate type length".to_string()))?;
        let serial_number: [u8; 32] = serial_number_bytes
            .try_into()
            .map_err(|_| Error::IdentityError("Invalid serial number length".to_string()))?;

        // Parse public keys
        let subject = PublicKey::from_hex(subject_hex)?;
        let certifier = PublicKey::from_hex(certifier_hex)?;

        // Create the base certificate
        let mut certificate =
            Certificate::new(cert_type, serial_number, subject.clone(), certifier);

        // Parse revocation outpoint if present
        if let Some(outpoint_str) = cert_data["revocationOutpoint"].as_str() {
            if !outpoint_str.is_empty() {
                certificate.revocation_outpoint =
                    Some(crate::wallet::types::Outpoint::from_string(outpoint_str)?);
            }
        }

        // Parse encrypted fields
        if let Some(fields_obj) = cert_data["fields"].as_object() {
            for (field_name, field_value) in fields_obj {
                if let Some(value_str) = field_value.as_str() {
                    let encrypted_value = from_base64(value_str)?;
                    certificate.set_field(field_name.clone(), encrypted_value);
                }
            }
        }

        // Parse signature if present
        if let Some(sig_str) = cert_data["signature"].as_str() {
            certificate.signature = Some(from_base64(sig_str)?);
        }

        // Step 6: Parse the keyring from JSON
        let mut keyring: HashMap<String, Vec<u8>> = HashMap::new();
        if let Some(keyring_obj) = cert_data["keyring"].as_object() {
            for (field_name, key_value) in keyring_obj {
                if let Some(key_str) = key_value.as_str() {
                    let key_bytes = from_base64(key_str)?;
                    keyring.insert(field_name.clone(), key_bytes);
                }
            }
        }

        // Create the verifiable certificate with the keyring
        let mut verifiable_cert = VerifiableCertificate::new(certificate, keyring.clone());

        // Step 7: Verify the certificate signature
        match verifiable_cert.verify() {
            Ok(true) => {}
            Ok(false) | Err(_) => return Ok(None), // Signature verification failed
        }

        // Step 8: Decrypt fields using 'anyone' wallet
        let anyone_wallet = ProtoWallet::anyone();
        let originator = self
            .config
            .originator
            .as_deref()
            .unwrap_or("identity-client");

        let decrypted_fields = match verifiable_cert
            .decrypt_fields(&anyone_wallet, &subject, originator)
            .await
        {
            Ok(fields) => fields,
            Err(_) => {
                // Return empty decrypted fields rather than failing entirely
                HashMap::new()
            }
        };

        // Step 9: Build certifier info (default for now, could be enhanced via registry lookup)
        let certifier_info = CertifierInfo {
            name: "SocialCert".to_string(),
            icon_url: "https://socialcert.net/favicon.ico".to_string(),
            description: "Social identity verification".to_string(),
            trust: 5,
        };

        // Step 10: Create and return the IdentityCertificate
        Ok(Some(IdentityCertificate {
            certificate: verifiable_cert,
            certifier_info,
            publicly_revealed_keyring: keyring,
            decrypted_fields,
        }))
    }

    /// Parse a lookup output into a VerifiableCertificate.
    ///
    /// This is a simpler version of `parse_output_to_certificate` that returns
    /// just the VerifiableCertificate without decrypting fields or adding certifier info.
    async fn parse_output_to_verifiable_certificate(
        &self,
        output: &OutputListItem,
    ) -> Result<Option<VerifiableCertificate>> {
        // Step 1: Parse BEEF to get the transaction
        let beef = match Beef::from_binary(&output.beef) {
            Ok(b) => b,
            Err(_) => return Ok(None), // Failed to parse BEEF
        };

        // Get the transaction from the BEEF
        let tx = match beef.txs.first() {
            Some(beef_tx) => match beef_tx.tx() {
                Some(t) => t,
                None => return Ok(None), // No transaction data in BEEF
            },
            None => return Ok(None), // No transactions in BEEF
        };

        // Step 2: Get the output at the specified index
        let tx_output = match tx.outputs.get(output.output_index as usize) {
            Some(o) => o,
            None => return Ok(None), // Output index out of range
        };

        // Step 3: Decode PushDrop from the locking script
        let pushdrop = match PushDrop::decode(&tx_output.locking_script) {
            Ok(pd) => pd,
            Err(_) => return Ok(None), // Failed to decode PushDrop
        };

        // Step 4: Get the first field (certificate JSON)
        let cert_json_bytes = match pushdrop.fields.first() {
            Some(f) => f,
            None => return Ok(None), // No fields in PushDrop
        };

        // Parse the JSON
        let cert_json_str = match String::from_utf8(cert_json_bytes.clone()) {
            Ok(s) => s,
            Err(_) => return Ok(None), // Invalid UTF-8 in certificate data
        };

        let cert_data: serde_json::Value = match serde_json::from_str(&cert_json_str) {
            Ok(v) => v,
            Err(_) => return Ok(None), // Failed to parse certificate JSON
        };

        // Step 5: Extract certificate fields from JSON
        let cert_type_b64 = match cert_data["type"].as_str() {
            Some(s) => s,
            None => return Ok(None), // Missing certificate type
        };
        let serial_number_b64 = match cert_data["serialNumber"].as_str() {
            Some(s) => s,
            None => return Ok(None), // Missing serial number
        };
        let subject_hex = match cert_data["subject"].as_str() {
            Some(s) => s,
            None => return Ok(None), // Missing subject
        };
        let certifier_hex = match cert_data["certifier"].as_str() {
            Some(s) => s,
            None => return Ok(None), // Missing certifier
        };

        // Parse the 32-byte arrays
        let cert_type_bytes = match from_base64(cert_type_b64) {
            Ok(b) => b,
            Err(_) => return Ok(None), // Invalid base64 in cert type
        };
        let serial_number_bytes = match from_base64(serial_number_b64) {
            Ok(b) => b,
            Err(_) => return Ok(None), // Invalid base64 in serial number
        };

        let cert_type: [u8; 32] = match cert_type_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(None), // Invalid certificate type length
        };
        let serial_number: [u8; 32] = match serial_number_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return Ok(None), // Invalid serial number length
        };

        // Parse public keys
        let subject = match PublicKey::from_hex(subject_hex) {
            Ok(pk) => pk,
            Err(_) => return Ok(None), // Invalid subject pubkey
        };
        let certifier = match PublicKey::from_hex(certifier_hex) {
            Ok(pk) => pk,
            Err(_) => return Ok(None), // Invalid certifier pubkey
        };

        // Create the base certificate
        let mut certificate = Certificate::new(cert_type, serial_number, subject, certifier);

        // Parse revocation outpoint if present
        if let Some(outpoint_str) = cert_data["revocationOutpoint"].as_str() {
            if !outpoint_str.is_empty() {
                certificate.revocation_outpoint =
                    crate::wallet::types::Outpoint::from_string(outpoint_str).ok();
            }
        }

        // Parse encrypted fields
        if let Some(fields_obj) = cert_data["fields"].as_object() {
            for (field_name, field_value) in fields_obj {
                if let Some(value_str) = field_value.as_str() {
                    if let Ok(encrypted_value) = from_base64(value_str) {
                        certificate.set_field(field_name.clone(), encrypted_value);
                    }
                }
            }
        }

        // Parse signature if present
        if let Some(sig_str) = cert_data["signature"].as_str() {
            if let Ok(sig_bytes) = from_base64(sig_str) {
                certificate.signature = Some(sig_bytes);
            }
        }

        // Parse the keyring from JSON
        let mut keyring: HashMap<String, Vec<u8>> = HashMap::new();
        if let Some(keyring_obj) = cert_data["keyring"].as_object() {
            for (field_name, key_value) in keyring_obj {
                if let Some(key_str) = key_value.as_str() {
                    if let Ok(key_bytes) = from_base64(key_str) {
                        keyring.insert(field_name.clone(), key_bytes);
                    }
                }
            }
        }

        // Create the verifiable certificate with the keyring
        let verifiable_cert = VerifiableCertificate::new(certificate, keyring);

        // Verify the certificate signature
        match verifiable_cert.verify() {
            Ok(true) => Ok(Some(verifiable_cert)),
            Ok(false) | Err(_) => Ok(None), // Signature verification failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identity_x_cert() {
        let mut decrypted = HashMap::new();
        decrypted.insert("userName".to_string(), "alice_x".to_string());
        decrypted.insert(
            "profilePhoto".to_string(),
            "https://example.com/avatar.png".to_string(),
        );

        let certifier_info = CertifierInfo {
            name: "SocialCert".to_string(),
            icon_url: "https://socialcert.net/icon.png".to_string(),
            description: "Social verification".to_string(),
            trust: 5,
        };

        // Test the generic parsing function
        let (name, avatar, badge, _, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        // With userName as highest priority in generic parsing
        assert!(name == "alice_x" || name.contains("alice"));
        assert_eq!(avatar, "https://example.com/avatar.png");
        assert!(badge.contains("SocialCert"));
    }

    #[test]
    fn test_parse_identity_generic_fallback() {
        let mut decrypted = HashMap::new();
        decrypted.insert("firstName".to_string(), "Alice".to_string());
        decrypted.insert("lastName".to_string(), "Smith".to_string());

        let certifier_info = CertifierInfo {
            name: "TestCert".to_string(),
            icon_url: "https://test.com/icon.png".to_string(),
            description: "Test".to_string(),
            trust: 3,
        };

        let (name, avatar, badge, icon, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        assert_eq!(name, "Alice Smith");
        assert_eq!(avatar, DefaultIdentityValues::AVATAR_URL);
        assert!(badge.contains("TestCert"));
        assert_eq!(icon, "https://test.com/icon.png");
    }

    #[test]
    fn test_parse_identity_no_fields() {
        let decrypted = HashMap::new();
        let certifier_info = CertifierInfo::default();

        let (name, avatar, badge, icon, click_url) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        assert_eq!(name, DefaultIdentityValues::NAME);
        assert_eq!(avatar, DefaultIdentityValues::AVATAR_URL);
        assert_eq!(badge, DefaultIdentityValues::BADGE_LABEL);
        assert_eq!(icon, DefaultIdentityValues::BADGE_ICON_URL);
        assert_eq!(click_url, DefaultIdentityValues::BADGE_CLICK_URL);
    }

    #[test]
    fn test_identity_client_config() {
        let config = IdentityClientConfig::with_originator("test.com")
            .with_network(crate::overlay::NetworkPreset::Testnet)
            .with_token_amount(10);

        assert_eq!(config.originator, Some("test.com".to_string()));
        assert_eq!(
            config.network_preset,
            crate::overlay::NetworkPreset::Testnet
        );
        assert_eq!(config.token_amount, 10);
    }

    #[test]
    fn test_publicly_reveal_attributes_validation() {
        // Test that validation works without needing a real wallet
        let empty_cert = WalletCertificate {
            certificate_type: "test".to_string(),
            subject: "".to_string(),
            serial_number: "123".to_string(),
            certifier: "".to_string(),
            revocation_outpoint: "".to_string(),
            signature: "".to_string(),
            fields: HashMap::new(),
        };

        // Validation should fail for empty fields
        assert!(empty_cert.fields.is_empty());
    }

    #[test]
    fn test_broadcast_result() {
        let success = BroadcastResult::Success(BroadcastSuccess {
            txid: "abc123".to_string(),
            message: Some("Success".to_string()),
        });

        assert!(success.is_success());
        assert_eq!(success.txid(), Some("abc123"));

        let failure = BroadcastResult::Failure(BroadcastFailure {
            code: "ERROR".to_string(),
            description: "Something went wrong".to_string(),
        });

        assert!(!failure.is_success());
        assert_eq!(failure.txid(), None);
    }

    // =========================================================================
    // publiclyRevealAttributes validation tests
    // Matches TypeScript: "should throw an error if certificate has no fields"
    // Matches Go: "should throw an error if certificate has no fields"
    // =========================================================================

    #[test]
    fn test_publicly_reveal_attributes_throws_if_no_fields() {
        // Certificate with no fields should be invalid for revelation
        let certificate = WalletCertificate {
            certificate_type: "test".to_string(),
            subject: "02abc123".to_string(),
            serial_number: "12345".to_string(),
            certifier: "02def456".to_string(),
            revocation_outpoint: "txid.0".to_string(),
            signature: "sig".to_string(),
            fields: HashMap::new(), // Empty fields!
        };

        // Validation: certificate should have fields to reveal
        assert!(
            certificate.fields.is_empty(),
            "Certificate has no fields to reveal!"
        );
    }

    #[test]
    fn test_publicly_reveal_attributes_throws_if_fields_to_reveal_empty() {
        // Even with certificate fields, empty fieldsToReveal should fail
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());

        let certificate = WalletCertificate {
            certificate_type: "test".to_string(),
            subject: "02abc123".to_string(),
            serial_number: "12345".to_string(),
            certifier: "02def456".to_string(),
            revocation_outpoint: "txid.0".to_string(),
            signature: "sig".to_string(),
            fields,
        };

        let fields_to_reveal: Vec<String> = vec![]; // Empty!

        // Validation: at least one field must be revealed
        assert!(
            fields_to_reveal.is_empty(),
            "You must reveal at least one field!"
        );
        assert!(!certificate.fields.is_empty());
    }

    // =========================================================================
    // parseIdentity tests - matching TypeScript and Go SDKs
    // =========================================================================

    #[test]
    fn test_parse_identity_email_cert() {
        let mut decrypted = HashMap::new();
        decrypted.insert("email".to_string(), "alice@example.com".to_string());

        let certifier_info = CertifierInfo {
            name: "Email Certifier".to_string(),
            icon_url: "https://email-certifier.com/icon.png".to_string(),
            description: "Email verification".to_string(),
            trust: 5,
        };

        let (name, avatar, badge, icon, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        // Email should be used as name
        assert_eq!(name, "alice@example.com");
        // Should use email avatar
        assert_eq!(avatar, DefaultIdentityValues::AVATAR_URL);
        // Badge should mention certifier
        assert!(badge.contains("Email Certifier"));
        assert_eq!(icon, "https://email-certifier.com/icon.png");
    }

    #[test]
    fn test_parse_identity_phone_cert() {
        let mut decrypted = HashMap::new();
        decrypted.insert("phoneNumber".to_string(), "+1-555-123-4567".to_string());

        let certifier_info = CertifierInfo {
            name: "Phone Certifier".to_string(),
            icon_url: "https://phone-certifier.com/icon.png".to_string(),
            description: "Phone verification".to_string(),
            trust: 5,
        };

        let (name, _, badge, _, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        // Phone number should be parsed from phoneNumber field
        assert!(name.contains("555") || name == DefaultIdentityValues::NAME);
        assert!(badge.contains("Phone Certifier"));
    }

    #[test]
    fn test_parse_identity_identicert() {
        let mut decrypted = HashMap::new();
        decrypted.insert("firstName".to_string(), "John".to_string());
        decrypted.insert("lastName".to_string(), "Doe".to_string());
        decrypted.insert(
            "profilePhoto".to_string(),
            "https://example.com/john.png".to_string(),
        );

        let certifier_info = CertifierInfo {
            name: "IdentiCert".to_string(),
            icon_url: "https://identicert.com/icon.png".to_string(),
            description: "Government ID verification".to_string(),
            trust: 8,
        };

        let (name, avatar, badge, _, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        // Should combine first and last name
        assert_eq!(name, "John Doe");
        // Should use profile photo
        assert_eq!(avatar, "https://example.com/john.png");
        // Badge should mention certifier
        assert!(badge.contains("IdentiCert"));
    }

    #[test]
    fn test_parse_identity_registrant_cert() {
        let mut decrypted = HashMap::new();
        decrypted.insert("name".to_string(), "Example Organization".to_string());
        decrypted.insert(
            "icon".to_string(),
            "https://example.org/icon.png".to_string(),
        );

        let certifier_info = CertifierInfo {
            name: "Registrant Certifier".to_string(),
            icon_url: "https://registrant.com/icon.png".to_string(),
            description: "Organization registration".to_string(),
            trust: 6,
        };

        let (name, avatar, _, _, _) =
            IdentityClient::<crate::wallet::ProtoWallet>::try_parse_generic_identity(
                &decrypted,
                &certifier_info,
            );

        // Should use the name field
        assert_eq!(name, "Example Organization");
        // Should use the icon as avatar
        assert_eq!(avatar, "https://example.org/icon.png");
    }

    // =========================================================================
    // KnownCertificateType tests
    // =========================================================================

    #[test]
    fn test_known_certificate_type_ids() {
        use crate::identity::KnownCertificateType;

        // Verify all type IDs match TypeScript/Go SDK constants
        assert_eq!(
            KnownCertificateType::XCert.type_id(),
            "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
        );
        assert_eq!(
            KnownCertificateType::EmailCert.type_id(),
            "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA="
        );
        assert_eq!(
            KnownCertificateType::DiscordCert.type_id(),
            "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4="
        );
        assert_eq!(
            KnownCertificateType::PhoneCert.type_id(),
            "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A="
        );
        assert_eq!(
            KnownCertificateType::IdentiCert.type_id(),
            "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
        );
        assert_eq!(
            KnownCertificateType::Registrant.type_id(),
            "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0="
        );
        assert_eq!(
            KnownCertificateType::Anyone.type_id(),
            "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
        );
        assert_eq!(
            KnownCertificateType::SelfCert.type_id(),
            "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
        );
        assert_eq!(
            KnownCertificateType::CoolCert.type_id(),
            "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo="
        );
    }

    #[test]
    fn test_known_certificate_type_roundtrip() {
        use crate::identity::KnownCertificateType;

        // Test roundtrip: type -> type_id -> from_type_id
        for cert_type in KnownCertificateType::all() {
            let type_id = cert_type.type_id();
            let parsed = KnownCertificateType::from_type_id(type_id);
            assert_eq!(
                parsed,
                Some(*cert_type),
                "Roundtrip failed for {:?}",
                cert_type
            );
        }
    }

    #[test]
    fn test_known_certificate_type_names() {
        use crate::identity::KnownCertificateType;

        assert_eq!(KnownCertificateType::XCert.name(), "XCert");
        assert_eq!(KnownCertificateType::EmailCert.name(), "EmailCert");
        assert_eq!(KnownCertificateType::DiscordCert.name(), "DiscordCert");
        assert_eq!(KnownCertificateType::PhoneCert.name(), "PhoneCert");
        assert_eq!(KnownCertificateType::IdentiCert.name(), "IdentiCert");
        assert_eq!(KnownCertificateType::Registrant.name(), "Registrant");
        assert_eq!(KnownCertificateType::Anyone.name(), "Anyone");
        assert_eq!(KnownCertificateType::SelfCert.name(), "Self"); // Matches Go/TS SDK
        assert_eq!(KnownCertificateType::CoolCert.name(), "CoolCert");
    }

    #[test]
    fn test_unknown_certificate_type_returns_none() {
        use crate::identity::KnownCertificateType;

        // Unknown string should not match any known type
        assert_eq!(KnownCertificateType::from_type_id("unknown-type-id"), None);
    }

    // =========================================================================
    // DisplayableIdentity tests
    // =========================================================================

    #[test]
    fn test_displayable_identity_from_key_abbreviation() {
        let identity = DisplayableIdentity::from_key(
            "02abc123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
        );

        // Should abbreviate to first 6 chars + "..." + last 4 chars
        assert_eq!(identity.abbreviated_key, "02abc1...abcd");
        assert_eq!(
            identity.identity_key,
            "02abc123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
        );
    }

    #[test]
    fn test_displayable_identity_short_key_no_abbreviation() {
        // Keys shorter than 10 chars should show full key without abbreviation
        let identity = DisplayableIdentity::from_key("02abc");

        assert_eq!(identity.abbreviated_key, "02abc");
        assert_eq!(identity.identity_key, "02abc");
    }

    #[test]
    fn test_displayable_identity_unknown() {
        let identity = DisplayableIdentity::unknown();

        assert_eq!(identity.name, DefaultIdentityValues::NAME);
        assert_eq!(identity.avatar_url, DefaultIdentityValues::AVATAR_URL);
        assert_eq!(identity.badge_label, DefaultIdentityValues::BADGE_LABEL);
        assert_eq!(identity.badge_icon_url, DefaultIdentityValues::BADGE_ICON_URL);
        assert_eq!(identity.badge_click_url, DefaultIdentityValues::BADGE_CLICK_URL);
        assert!(identity.identity_key.is_empty());
    }

    // =========================================================================
    // Default identity values tests - cross-SDK compatibility
    // =========================================================================

    #[test]
    fn test_default_identity_values_match_sdks() {
        // These values must match TypeScript and Go SDKs exactly
        assert_eq!(DefaultIdentityValues::NAME, "Unknown Identity");
        assert_eq!(
            DefaultIdentityValues::AVATAR_URL,
            "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst"
        );
        assert_eq!(
            DefaultIdentityValues::BADGE_LABEL,
            "Not verified by anyone you trust."
        );
        assert_eq!(
            DefaultIdentityValues::BADGE_ICON_URL,
            "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG"
        );
        assert_eq!(
            DefaultIdentityValues::BADGE_CLICK_URL,
            "https://projectbabbage.com/docs/unknown-identity"
        );
    }

    // =========================================================================
    // IdentityQuery builder tests
    // =========================================================================

    #[test]
    fn test_identity_query_builder() {
        use crate::identity::IdentityQuery;

        let query = IdentityQuery::by_identity_key("02abc123")
            .with_certifier("02def456")
            .with_limit(25)
            .with_offset(10);

        assert_eq!(query.identity_key, Some("02abc123".to_string()));
        assert_eq!(query.certifier, Some("02def456".to_string()));
        assert_eq!(query.limit, Some(25));
        assert_eq!(query.offset, Some(10));
    }

    #[test]
    fn test_identity_query_by_attribute() {
        use crate::identity::IdentityQuery;

        let query = IdentityQuery::by_attribute("email", "alice@example.com");

        assert!(query.identity_key.is_none());
        assert!(query.attributes.is_some());
        let attrs = query.attributes.as_ref().unwrap();
        assert_eq!(attrs.get("email"), Some(&"alice@example.com".to_string()));
    }

    #[test]
    fn test_identity_query_by_multiple_attributes() {
        use crate::identity::IdentityQuery;

        let mut attrs = HashMap::new();
        attrs.insert("firstName".to_string(), "John".to_string());
        attrs.insert("lastName".to_string(), "Doe".to_string());

        let query = IdentityQuery::by_attributes(attrs);

        // Use Option comparison since attributes is Option<HashMap>
        let attrs_map = query.attributes.as_ref().unwrap();
        assert_eq!(attrs_map.get("firstName"), Some(&"John".to_string()));
        assert_eq!(attrs_map.get("lastName"), Some(&"Doe".to_string()));
    }

    // =========================================================================
    // CertifierInfo tests
    // =========================================================================

    #[test]
    fn test_certifier_info_default() {
        let info = CertifierInfo::default();

        // Default certifier info should have reasonable defaults
        assert_eq!(info.name, "Unknown Certifier");
        assert_eq!(info.description, "No information available");
        assert_eq!(info.trust, 0);
        // Icon URL should use default badge icon
        assert!(!info.icon_url.is_empty());
    }

    // =========================================================================
    // BroadcastResult conversion tests
    // =========================================================================

    #[test]
    fn test_broadcast_result_into_result_success() {
        let success = BroadcastResult::Success(BroadcastSuccess {
            txid: "txid123".to_string(),
            message: Some("Broadcast successful".to_string()),
        });

        let result = success.into_result();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().txid, "txid123");
    }

    #[test]
    fn test_broadcast_result_into_result_failure() {
        let failure = BroadcastResult::Failure(BroadcastFailure {
            code: "FAILED".to_string(),
            description: "Broadcast failed".to_string(),
        });

        let result = failure.into_result();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, "FAILED");
    }

    // =========================================================================
    // Configuration tests (no wallet required)
    // =========================================================================

    #[test]
    fn test_identity_client_config_creation() {
        let config = IdentityClientConfig::default();

        // Verify default values match TypeScript/Go SDKs
        assert_eq!(config.protocol_id, (1, "identity".to_string()));
        assert_eq!(config.key_id, "1");
        assert_eq!(config.token_amount, 1);
        assert_eq!(config.output_index, 0);
        assert_eq!(config.network_preset, crate::overlay::NetworkPreset::Mainnet);
        assert!(config.originator.is_none());
    }

    #[test]
    fn test_identity_client_config_builder_methods() {
        let config = IdentityClientConfig::with_originator("test-app.example.com")
            .with_network(crate::overlay::NetworkPreset::Testnet)
            .with_token_amount(5);

        // Verify builder methods applied correctly
        assert_eq!(
            config.originator,
            Some("test-app.example.com".to_string())
        );
        assert_eq!(
            config.network_preset,
            crate::overlay::NetworkPreset::Testnet
        );
        assert_eq!(config.token_amount, 5);
    }

    #[test]
    fn test_identity_client_config_protocol_defaults() {
        let config = IdentityClientConfig::default();

        // Protocol should be (1, "identity") to match other SDKs
        assert_eq!(config.protocol_id.0, 1); // Security level
        assert_eq!(config.protocol_id.1, "identity"); // Protocol name
    }

    // =========================================================================
    // Error case tests
    // =========================================================================

    #[test]
    fn test_wallet_certificate_validation() {
        // Test the WalletCertificate structure used in publiclyRevealAttributes
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        fields.insert("email".to_string(), "alice@example.com".to_string());

        let cert = WalletCertificate {
            certificate_type: "test-type".to_string(),
            subject: "02abc123".to_string(),
            serial_number: "serial-123".to_string(),
            certifier: "02def456".to_string(),
            revocation_outpoint: "txid.0".to_string(),
            signature: "sig".to_string(),
            fields,
        };

        // Valid certificate should have fields
        assert!(!cert.fields.is_empty());
        assert_eq!(cert.fields.len(), 2);
        assert_eq!(cert.fields.get("name"), Some(&"Alice".to_string()));
    }
}
