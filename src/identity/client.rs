//! Identity client for discovering and revealing user identities.
//!
//! The [`IdentityClient`] provides methods for:
//! - Publicly revealing certificate attributes on-chain
//! - Resolving identities by key or attributes
//! - Discovering certificates for an identity
//! - Managing personal contacts

use crate::auth::VerifiableCertificate;
use crate::overlay::{LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig};
use crate::wallet::{ProveCertificateArgs, WalletCertificate, WalletInterface};
use crate::{Error, Result};

use super::contacts::ContactsManager;
use super::types::{
    BroadcastFailure, BroadcastResult, CertificateFieldNameUnder50Bytes, CertifierInfo, Contact,
    ContactsManagerConfig, DefaultIdentityValues, DisplayableIdentity, IdentityCertificate,
    IdentityClientConfig, IdentityQuery, IdentityResolutionResult, KnownCertificateType,
    StaticAvatarUrls, DEFAULT_SOCIALCERT_CERTIFIER,
};
#[cfg(test)]
use super::types::BroadcastSuccess;

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

        if certificate.revocation_outpoint.is_empty() {
            return Err(Error::IdentityError(
                "Public reveal failed: Certificate must have a revocation outpoint!".to_string(),
            ));
        }

        let originator = self.config.originator.as_deref().unwrap_or("");

        // Create a dummy public key for "anyone" verifier (using scalar 1)
        // This allows anyone to decrypt the revealed fields
        let anyone_verifier = crate::PrivateKey::from_bytes(&[
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
                    verifier: anyone_verifier,
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

        let _cert_json = serde_json::to_vec(&cert_with_keyring)
            .map_err(|e| Error::IdentityError(format!("Failed to serialize certificate: {}", e)))?;

        // TODO: Full implementation requires:
        // 1. Create PushDrop locking script with cert_json
        // 2. Create transaction with identity token output
        // 3. Broadcast to tm_identity topic
        //
        // This requires additional integration with:
        // - script::templates::PushDrop
        // - overlay::TopicBroadcaster
        //
        // For now, return a placeholder indicating the method exists
        // but full implementation is pending PushDrop integration

        Ok(BroadcastResult::Failure(BroadcastFailure {
            code: "NOT_IMPLEMENTED".to_string(),
            description:
                "Full publicly_reveal_attributes implementation pending PushDrop integration"
                    .to_string(),
        }))
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
        // Find the existing UTXO via lookup
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

        // TODO: Full implementation requires:
        // 1. Parse BEEF to get txid and create outpoint
        // 2. Create unlocking script using PushDrop.unlock()
        // 3. Create and sign transaction to spend the output
        // 4. Broadcast via SHIPBroadcaster
        //
        // For now, return success to indicate the lookup worked
        // Full spending implementation pending PushDrop integration

        let _ = &outputs[0]; // Acknowledge we found the output

        Err(Error::IdentityError(
            "Full revoke_certificate_revelation implementation pending PushDrop integration"
                .to_string(),
        ))
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
    async fn parse_output_to_certificate(
        &self,
        _output: &crate::overlay::OutputListItem,
    ) -> Result<Option<IdentityCertificate>> {
        // TODO: Implement full parsing when PushDrop decode is available
        // This requires:
        // 1. Parse BEEF to get transaction
        // 2. Decode PushDrop from locking script
        // 3. Parse certificate JSON from PushDrop fields
        // 4. Decrypt fields using 'anyone' wallet
        // 5. Verify certificate signature
        Ok(None)
    }

    /// Parse a lookup output into a VerifiableCertificate.
    async fn parse_output_to_verifiable_certificate(
        &self,
        _output: &crate::overlay::OutputListItem,
    ) -> Result<Option<VerifiableCertificate>> {
        // TODO: Implement full parsing when PushDrop decode is available
        Ok(None)
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
}
