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
    OverlayBroadcastFacilitator, TopicBroadcaster, TopicBroadcasterConfig,
};
use crate::primitives::PrivateKey;
use crate::script::templates::PushDrop;
use crate::transaction::{Broadcaster, Transaction};
use crate::wallet::{
    CreateActionArgs, CreateActionOptions, CreateActionOutput, ProtoWallet, ProveCertificateArgs,
    WalletCertificate, WalletInterface,
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

use indexmap::IndexMap;
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
/// use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let client = IdentityClient::new(wallet, IdentityClientConfig::default());
///
/// // Resolve the identities of a key
/// let identities = client.resolve_by_identity_key("02abc123...", true).await?;
/// ```
pub struct IdentityClient<W: WalletInterface> {
    wallet: W,
    config: IdentityClientConfig,
    resolver: Arc<LookupResolver>,
    contacts_manager: ContactsManager<W>,
    broadcast_facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>>,
    pub(super) hint_contradictions: super::evidence::HintContradictions,
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
        decrypted: &IndexMap<String, String>,
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
        Self::with_resolver(wallet, config, resolver)
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
            broadcast_facilitator: None,
            hint_contradictions: Default::default(),
        }
    }

    /// The facilitator the revocation's `tm_identity` broadcasts go
    /// through, in place of the HTTP one (#327): the
    /// [`TopicBroadcasterConfig::facilitator`] of its broadcaster.
    pub fn with_broadcast_facilitator(
        mut self,
        facilitator: Arc<dyn OverlayBroadcastFacilitator>,
    ) -> Self {
        self.broadcast_facilitator = Some(facilitator);
        self
    }

    /// The originator every wallet call carries: the configured one, or none
    /// (`None`), as the reference passes its constructor's (#318, #329;
    /// `IdentityClient.ts:369-377`).
    fn originator(&self) -> Option<&str> {
        self.config.originator.as_deref()
    }

    /// Get the wallet's identity key.
    pub async fn get_identity_key(&self) -> Result<String> {
        let originator = self.originator();
        let result = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    ..Default::default()
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
    /// - Returns error if certificate has no fields, a name to reveal is
    ///   not one of them, or its signature does not verify, before any
    ///   wallet call (the reference's checks, #307)
    /// - Returns error if transaction creation fails, or createAction
    ///   answers no transaction (`Public reveal failed: failed to create
    ///   action!`, the reference's, #310); a broadcast the overlay refuses
    ///   is a `BroadcastResult::Failure`, as the reference returns it
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
        // The reference's checks, the signature last, before any wallet call (#307)
        super::reveal::check_master_certificate(&certificate, &fields_to_reveal)?;

        let originator = self.originator();

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
        let keyring =
            super::reveal::check_keyring(&prove_result.keyring_for_verifier, &fields_to_reveal)?;

        // The PushDrop the subject signs, as the reference's (#310)
        let (level, ref name) = self.config.protocol_id;
        let locking_script = super::reveal::identity_token(
            &self.wallet,
            originator,
            (level, name),
            &self.config.key_id,
            &certificate,
            &keyring,
        )
        .await?;

        // The reference's arguments and no others (`IdentityClient.ts:513-528`,
        // #315): no label, tag, signAndProcess or acceptDelayedBroadcast, so
        // the wallet applies its own defaults
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
                        tags: None,
                    }]),
                    lock_time: None,
                    version: None,
                    labels: None,
                    options: Some(CreateActionOptions {
                        randomize_outputs: Some(false),
                        ..Default::default()
                    }),
                },
                originator,
            )
            .await?;

        // The reference throws when createAction answers no transaction
        // (`IdentityClient.ts:537`, #310)
        let tx_bytes = create_result.tx.ok_or_else(|| {
            Error::IdentityError("Public reveal failed: failed to create action!".to_string())
        })?;

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

    /// Revokes a previously published certificate revelation, as the
    /// reference's `revokeCertificateRevelation` does (`ts-stack@edf6e03`
    /// `IdentityClient.ts:705-950`; #327, the steps in `revoke.rs`): the
    /// serial number read as base64 of 32 bytes; the identity key and the
    /// revelation key; the `ls_identity` lookup (`Failed to get lookup
    /// result` for no output, at most 10000 outputs and 16 MiB of BEEF);
    /// each output's token authenticated (the subject, the serial number,
    /// the certificate's and the token's signatures), none: `No
    /// authenticated revelation output matches the requested
    /// certificate.`; every authenticated output spent at its own index on
    /// `tm_identity`, the action aborted when signing or broadcasting fails,
    /// and the spend retried on a wallet's double-spend evidence
    /// ([`Error::WalletReviewActions`]) after the competing transactions are
    /// broadcast, at most five attempts.
    ///
    /// # Example
    /// ```rust,ignore
    /// client.revoke_certificate_revelation("abc123...").await?;
    /// ```
    pub async fn revoke_certificate_revelation(&self, serial_number: &str) -> Result<()> {
        super::revoke::Revocation {
            wallet: &self.wallet,
            originator: self.originator(),
            config: &self.config,
            resolver: &self.resolver,
            facilitator: self.broadcast_facilitator.clone(),
        }
        .run(serial_number)
        .await
    }

    // =========================================================================
    // Resolution Methods
    // =========================================================================

    /// Resolve the identities of an identity key.
    ///
    /// Reads every output of the `ls_identity` answer in order before it
    /// answers, passing over one it skips (#737), keeps only certificates
    /// whose subject is `identity_key` (compared lower-cased, the reference's
    /// `filterCertificatesByIdentityKey`), and returns every one's
    /// displayable identity in the reference wallet's trust order: one per
    /// type, serial number and certifier, the most trusted certifier's ahead,
    /// ties in the answer's order (`client_trust.rs`), as the reference's
    /// `resolveByIdentityKey` returns its list (`IdentityClient.ts:559-591`).
    /// An answer with none admitted is the empty list. The trust is each
    /// certificate's `certifier_info.trust`; this crate holds no trust
    /// settings, so no certifier is dropped as untrusted (#737, the list).
    ///
    /// If `override_with_contacts` is true, a stored contact of the key
    /// answers alone, before any lookup.
    ///
    /// # Example
    /// ```rust,ignore
    /// let identities = client.resolve_by_identity_key("02abc123...", true).await?;
    /// if let Some(id) = identities.first() {
    ///     println!("Found: {}", id.name);
    /// }
    /// ```
    ///
    /// Fails with `Error::IdentityError("Transaction evidence: limit")` when any lookup output's evidence exceeds the reference's limits (#730), before or after an admitted one (#737); an output whose evidence the check refuses as invalid is skipped.
    pub async fn resolve_by_identity_key(
        &self,
        identity_key: &str,
        override_with_contacts: bool,
    ) -> Result<Vec<DisplayableIdentity>> {
        if override_with_contacts {
            if let Ok(Some(contact)) = self.contacts_manager.get_contact(identity_key).await {
                return Ok(vec![contact.to_displayable_identity()]);
            }
        }
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({
                "identityKey": identity_key,
                "certifiers": [DEFAULT_SOCIALCERT_CERTIFIER]
            }),
        );
        // Every output parsed before the answer (identityUtils.ts:671-707),
        // the asked subject's kept (:247-255), the trust step's order (:313-382)
        let LookupAnswer::OutputList { outputs } = self.resolver.query(&question, None).await?
        else {
            return Ok(Vec::new());
        };
        let mut certificates = Vec::new();
        for output in &outputs {
            if let Some(cert) = self.parse_output_to_certificate(output).await? {
                if is_asked_subject(cert.certificate.subject(), identity_key) {
                    certificates.push(cert);
                }
            }
        }
        Ok(trust::ordered_by_trust(certificates)
            .iter()
            .map(Self::parse_identity)
            .collect())
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
    /// let mut attrs = IndexMap::new();
    /// attrs.insert("email".to_string(), "user@example.com".to_string());
    /// let identities = client.resolve_by_attributes(attrs, true).await?;
    /// ```
    ///
    /// Only certificates whose decrypted fields match the map sent are kept
    /// (#751), the reference wallet's `filterCertificatesByAttributes`
    /// (`identityUtils.ts:140-293` at `ts-stack@edf6e03`, `Wallet.ts:1078`):
    /// a lone attribute is sent and judged as `any`, the overlay's
    /// all-fields search; an empty map keeps nothing.
    ///
    /// Fails with `Error::IdentityError("Transaction evidence: limit")` when a lookup output's evidence exceeds the reference's limits (#730); an output whose evidence the check refuses as invalid is skipped.
    pub async fn resolve_by_attributes(
        &self,
        attributes: IndexMap<String, String>,
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

        // A single attribute uses the "any" matcher; several are sent in insertion order (#394)
        let attributes = match attributes.values().next() {
            Some(value) if attributes.len() == 1 => IndexMap::from([("any".into(), value.clone())]),
            _ => attributes,
        };
        #[derive(serde::Serialize)]
        struct Query<'a> {
            attributes: &'a IndexMap<String, String>,
            certifiers: [&'static str; 1],
        }
        let query = Query {
            attributes: &attributes,
            certifiers: [DEFAULT_SOCIALCERT_CERTIFIER],
        };
        let answer = self
            .resolver
            .query_ordered("ls_identity", &query, None)
            .await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut identities = Vec::new();

                for output in &outputs {
                    if let Some(cert) = self.parse_output_to_certificate(output).await? {
                        // The map sent judged on the answer, as `discoverByAttributes` does (#751)
                        if !super::client_attributes::keeps(&attributes, &cert.decrypted_fields) {
                            continue;
                        }
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
    /// Returns the certificates the identity has revealed: every output of
    /// the lookup answer parsed in order, a skipped one passed over, and only
    /// certificates whose subject is `identity_key` kept (compared
    /// lower-cased, the rule [`Self::resolve_by_identity_key`] carries from
    /// the reference's `filterCertificatesByIdentityKey`; this door is the
    /// BRC-100 wallet's `discoverByIdentityKey`, whose trust step, page and
    /// argument check are not ported, #739).
    ///
    /// The question is `{ identityKey }`, the key the reference overlay's
    /// `ls_identity` allowlist admits (`IdentityLookupService.ts:74-82` at
    /// `ts-stack@edf6e03`); until #754 it carried `certificatesOnly: true`,
    /// a key that allowlist refuses for the whole question. The reference
    /// wallet adds `certifiers`, its trust settings' keys (`Wallet.ts:992,1004`);
    /// with no trust settings here, no certifier is named: the certifier
    /// narrowing is the wallet door's, by its trust settings, above this one,
    /// and the overlay answers the subject's certificates of every certifier,
    /// at most its default page of 10 (`IdentityLookupService.ts:83`),
    /// unpaged here.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key to look up
    ///
    /// Fails with `Error::IdentityError("Transaction evidence: limit")` when a lookup output's evidence exceeds the reference's limits (#730); an output whose evidence the check refuses as invalid is skipped.
    pub async fn discover_certificates(
        &self,
        identity_key: &str,
    ) -> Result<Vec<VerifiableCertificate>> {
        // The key alone, as the reference overlay admits it (#754)
        let query = serde_json::json!({ "identityKey": identity_key });
        self.discover_of_subject(identity_key, query).await
    }

    /// Discover certificates of a specific type.
    ///
    /// Keeps only certificates whose subject is `identity_key`, as
    /// [`Self::discover_certificates`] does (#739), and of those only the
    /// ones whose type is `cert_type` (#744): the type is sent in the
    /// `ls_identity` query and checked again on each certificate read, its
    /// canonical base64 text compared exactly with the asked text, so a host
    /// answering with another type's certificate is not believed. The
    /// reference has no by-type door (`DiscoverByIdentityKeyArgs` carries no
    /// type at `ts-stack@edf6e03`): this crate's own rule. The question is
    /// `{ identityKey, certificateTypes: [cert_type] }`, the keys the
    /// reference overlay's `ls_identity` allowlist admits and its by-type
    /// branch reads together (`IdentityLookupService.ts:74-82,136-143`); until
    /// #752 the type went as `certificateType`, a key that allowlist refuses.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key to look up
    /// * `cert_type` - The certificate type ID (base64 of 32 bytes, canonical)
    ///
    /// Fails with `Error::IdentityError("Transaction evidence: limit")` when a lookup output's evidence exceeds the reference's limits (#730); an output whose evidence the check refuses as invalid is skipped.
    pub async fn discover_certificates_by_type(
        &self,
        identity_key: &str,
        cert_type: &str,
    ) -> Result<Vec<VerifiableCertificate>> {
        // The type as the reference overlay reads it: `certificateTypes`, an
        // array, beside `identityKey` (#752)
        let query =
            serde_json::json!({ "identityKey": identity_key, "certificateTypes": [cert_type] });
        let mut certificates = self.discover_of_subject(identity_key, query).await?;
        // Every output parsed and the subject filtered, then only the asked
        // type's (#744): the token's type text is canonical base64 of 32
        // bytes (#553), so its re-encoding is the token's own text
        certificates.retain(|cert| cert.type_base64() == cert_type);
        Ok(certificates)
    }

    /// The two `discover_*` doors' walk: every output parsed in order, a
    /// limit anywhere the call's refusal (#730), then only the asked
    /// subject's certificates (#739).
    async fn discover_of_subject(
        &self,
        identity_key: &str,
        query: serde_json::Value,
    ) -> Result<Vec<VerifiableCertificate>> {
        let question = LookupQuestion::new("ls_identity", query);
        let LookupAnswer::OutputList { outputs } = self.resolver.query(&question, None).await?
        else {
            return Ok(Vec::new());
        };
        let mut certificates = Vec::new();
        for output in &outputs {
            if let Some(cert) = self.parse_output_to_verifiable_certificate(output).await? {
                certificates.push(cert);
            }
        }
        certificates.retain(|cert| is_asked_subject(cert.subject(), identity_key));
        Ok(certificates)
    }

    /// Query identities with complex filters.
    ///
    /// Every output of the `ls_identity` answer is parsed in order (a skipped
    /// one passed over, a limit anywhere the call's refusal), then only the
    /// certificates the question asked for are kept (#746), as the two
    /// `discover_*` doors keep theirs (#739, #744): with `identity_key` set,
    /// the subject's (lower-cased on both sides, `is_asked_subject`); with
    /// `certificate_type` set, the type's (the canonical base64 text,
    /// `type_base64()`, compared exactly with the asked text); with
    /// `certifier` set, the certifier's (the certificate's certifier key,
    /// lower-cased hex, against the asked text lower-cased). A field the
    /// question does not carry filters nothing: with `certifier` unset the
    /// lookup asks the default SocialCert certifier, but a certificate of
    /// another certifier is not dropped. With `attributes` set, the
    /// certificates whose decrypted fields match them (#751), as the
    /// reference wallet's `filterCertificatesByAttributes` judges them
    /// (`identityUtils.ts:140-293`); `limit` and `offset` page the overlay's
    /// answer before that filter: a short page is not its end. A
    /// `certificate_type` is sent as
    /// `certificateTypes: [type]`, the key and shape the reference overlay's
    /// `ls_identity` allowlist admits (`IdentityLookupService.ts:74-82`; that
    /// overlay reads the types only beside `identityKey` and with no
    /// `attributes` or `serialNumber` in the question, `:130-136`), where
    /// until #752 it went as `certificateType`. The door has no reference counterpart
    /// (`IdentityClient.ts`'s lookups are `resolveByIdentityKey` and
    /// `resolveByAttributes`): this crate's own rule.
    ///
    /// # Arguments
    /// * `query` - The query parameters
    ///
    /// Fails with `Error::IdentityError("Invalid lookup query: ...")`, nothing
    /// sent, for a question the reference overlay refuses whole (#756): a
    /// `limit` outside 1 to 100, an `offset` above 100000, an `identity_key`
    /// or `certifier` that is no `02`/`03` key of 64 hex digits on the curve,
    /// a `certificate_type` that is not base64 of 32 bytes (1 to 44 bytes, then
    /// `validateBase64String`), `attributes` of 0 or more than 32 fields, a
    /// name over 50 bytes or with `.`, `$` or NUL or one of `__proto__`,
    /// `constructor`, `prototype`, a value over 500 bytes.
    ///
    /// Fails with `Error::IdentityError("Transaction evidence: limit")` when a lookup output's evidence exceeds the reference's limits (#730); an output whose evidence the check refuses as invalid is skipped.
    pub async fn query(&self, query: IdentityQuery) -> Result<Vec<IdentityResolutionResult>> {
        super::query_bounds::check(&query)?;
        // The question's members in the order a `Value` writes them (sorted),
        // the attributes in insertion order, as `resolve_by_attributes` sends
        // its own (#394): the overlay walks them as `JSON.parse` holds that
        // text, the order `query_bounds::check` judges them in (#751's fold)
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Question<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            attributes: Option<&'a IndexMap<String, String>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            certificate_types: Option<[&'a str; 1]>,
            certifiers: [&'a str; 1],
            #[serde(skip_serializing_if = "Option::is_none")]
            identity_key: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            limit: Option<u32>,
            #[serde(skip_serializing_if = "Option::is_none")]
            offset: Option<u32>,
        }
        let question = Question {
            attributes: query.attributes.as_ref(),
            certificate_types: query.certificate_type.as_deref().map(|t| [t]),
            certifiers: [query
                .certifier
                .as_deref()
                .unwrap_or(DEFAULT_SOCIALCERT_CERTIFIER)],
            identity_key: query.identity_key.as_deref(),
            limit: query.limit,
            offset: query.offset,
        };
        let LookupAnswer::OutputList { outputs } = self
            .resolver
            .query_ordered("ls_identity", &question, None)
            .await?
        else {
            return Ok(Vec::new());
        };
        let mut certificates = Vec::new();
        for output in &outputs {
            if let Some(cert) = self.parse_output_to_certificate(output).await? {
                certificates.push(cert);
            }
        }
        // Every output parsed, then only what the question asked for (#746, #751)
        certificates.retain(|cert| super::client_attributes::is_asked(cert, &query));
        Ok(certificates
            .into_iter()
            .map(|cert| IdentityResolutionResult {
                identity: Self::parse_identity(&cert),
                certificates: vec![cert.certificate],
            })
            .collect())
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
        // Step 1: The BEEF's subject (#721) under the reference's evidence
        // check, a refused one skipped, a limit the discovery's refusal
        // (TransactionEvidence.ts:93-201, identityUtils.ts:600-634, #730)
        let Some(tx) = super::evidence::admit(output, &self.hint_contradictions)? else {
            return Ok(None);
        };

        // Step 2: Get the output at the specified index
        let tx_output = match tx.outputs().get(output.output_index as usize) {
            Some(o) => o,
            None => return Ok(None), // Output index out of range
        };

        // Step 3: Decode lock-before alone, as IdentityClient.ts:773 does (#537)
        let Some(pushdrop) = decode_token(&tx_output.locking_script) else {
            return Ok(None); // Failed to decode PushDrop
        };

        // Step 4: The toolbox's record checks and byte bounds, or skipped (#553)
        let Some(record) = record::read(&pushdrop.fields) else {
            return Ok(None);
        };
        // The subject's signed revelation, or skipped (#544)
        if !self.is_authenticated_token(&tx_output.locking_script, &pushdrop, &record.subject) {
            return Ok(None);
        }

        // Step 5: The certificate, each field held as its base64 text, as
        // BRC-52 signs it (#261), in the order of the token's text (#394)
        let mut certificate = Certificate::new(
            record.cert_type,
            record.serial_number,
            record.subject,
            record.certifier,
        );
        certificate.revocation_outpoint = record.revocation_outpoint;
        certificate.set_fields(record.maps.fields);
        certificate.signature = record.signature;

        // Step 6: Parse the keyring from JSON, each entry held as its base64
        // text and decoded only where the wallet decrypts (#268)
        let keyring = record.maps.keyring;

        // Create the verifiable certificate with the keyring
        let mut verifiable_cert = VerifiableCertificate::new(certificate, keyring.clone());

        // Step 7: Verify the certificate signature
        match verifiable_cert.verify() {
            Ok(true) => {}
            Ok(false) | Err(_) => return Ok(None), // Signature verification failed
        }

        // Step 8: Decrypt fields using 'anyone' wallet
        let anyone_wallet = ProtoWallet::anyone();
        let originator = self.originator();

        let decrypted_fields: IndexMap<String, String> = verifiable_cert
            .decrypt_fields(&anyone_wallet, None, None, originator)
            .await
            .unwrap_or_default();

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
        // Step 1: The BEEF's subject (#721) under the reference's evidence
        // check, a refused one skipped, a limit the discovery's refusal
        // (TransactionEvidence.ts:93-201, identityUtils.ts:600-634, #730)
        let Some(tx) = super::evidence::admit(output, &self.hint_contradictions)? else {
            return Ok(None);
        };

        // Step 2: Get the output at the specified index
        let tx_output = match tx.outputs().get(output.output_index as usize) {
            Some(o) => o,
            None => return Ok(None), // Output index out of range
        };

        // Step 3: Decode lock-before alone, as IdentityClient.ts:773 does (#537)
        let Some(pushdrop) = decode_token(&tx_output.locking_script) else {
            return Ok(None); // Failed to decode PushDrop
        };

        // Step 4: The toolbox's record checks and byte bounds, or skipped (#553)
        let Some(record) = record::read(&pushdrop.fields) else {
            return Ok(None);
        };
        // The subject's signed revelation, or skipped (#544)
        if !self.is_authenticated_token(&tx_output.locking_script, &pushdrop, &record.subject) {
            return Ok(None);
        }

        // The certificate, each field held as its base64 text, as
        // BRC-52 signs it (#261), in the order of the token's text (#394)
        let mut certificate = Certificate::new(
            record.cert_type,
            record.serial_number,
            record.subject,
            record.certifier,
        );
        certificate.revocation_outpoint = record.revocation_outpoint;
        certificate.set_fields(record.maps.fields);
        certificate.signature = record.signature;

        // Parse the keyring from JSON, each entry held as its base64 text and
        // decoded only where the wallet decrypts (#268)
        let keyring = record.maps.keyring;

        // Create the verifiable certificate with the keyring
        let verifiable_cert = VerifiableCertificate::new(certificate, keyring);

        // Verify the certificate signature
        match verifiable_cert.verify() {
            Ok(true) => Ok(Some(verifiable_cert)),
            Ok(false) | Err(_) => Ok(None), // Signature verification failed
        }
    }
}

/// Whether `subject` is the asked key, both lower-cased as the reference's
/// `filterCertificatesByIdentityKey` compares (`identityUtils.ts:247-255`,
/// `Wallet.ts:1012`): the one rule of the three by-key doors (#737, #739).
pub(super) fn is_asked_subject(subject: &crate::primitives::PublicKey, identity_key: &str) -> bool {
    subject.to_hex() == identity_key.to_lowercase()
}

/// The two `ls_identity` parsers' decode site: lock-before alone, as the
/// reference's `PushDrop.decode` at its default position reads a revelation
/// token (`ts-stack@edf6e03` `IdentityClient.ts:773`, #537). The token check
/// after it (#544, `is_canonical_signed_pushdrop`) also refuses every
/// lock-after layout, so the position is pinned here, at the call (#744).
fn decode_token(script: &crate::script::LockingScript) -> Option<PushDrop> {
    PushDrop::decode_before(script).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identity_x_cert() {
        let mut decrypted = IndexMap::new();
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
        let mut decrypted = IndexMap::new();
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
        let decrypted = IndexMap::new();
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

    #[tokio::test]
    async fn test_publicly_reveal_attributes_validation() {
        use crate::primitives::PrivateKey;
        use crate::wallet::ProtoWallet;

        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let client = IdentityClient::new(wallet, IdentityClientConfig::default());

        // Certificate with empty fields should be rejected
        let empty_cert = WalletCertificate {
            certificate_type: "test".to_string(),
            subject: "".to_string(),
            serial_number: "123".to_string(),
            certifier: "".to_string(),
            revocation_outpoint: "".to_string(),
            signature: "".to_string(),
            fields: indexmap::IndexMap::new(),
        };

        let result = client
            .publicly_reveal_attributes(empty_cert, vec!["field1".to_string()])
            .await;
        assert!(matches!(result, Err(Error::IdentityError(_))));

        // Certificate with fields but empty fields_to_reveal should be rejected
        let mut fields = indexmap::IndexMap::new();
        fields.insert("name".to_string(), "Alice".to_string());
        let cert_with_fields = WalletCertificate {
            certificate_type: "test".to_string(),
            subject: "subject".to_string(),
            serial_number: "123".to_string(),
            certifier: "certifier".to_string(),
            revocation_outpoint: "".to_string(),
            signature: "".to_string(),
            fields,
        };

        let result = client
            .publicly_reveal_attributes(cert_with_fields, vec![])
            .await;
        assert!(matches!(result, Err(Error::IdentityError(_))));
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
    // parseIdentity tests - matching TypeScript and Go SDKs
    // Note: publiclyRevealAttributes validation (empty fields, empty fields_to_reveal)
    // is covered by the async test_publicly_reveal_attributes_validation test above.
    // =========================================================================

    #[test]
    fn test_parse_identity_email_cert() {
        let mut decrypted = IndexMap::new();
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
        let mut decrypted = IndexMap::new();
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
        let mut decrypted = IndexMap::new();
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
        let mut decrypted = IndexMap::new();
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
        assert_eq!(
            identity.badge_icon_url,
            DefaultIdentityValues::BADGE_ICON_URL
        );
        assert_eq!(
            identity.badge_click_url,
            DefaultIdentityValues::BADGE_CLICK_URL
        );
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

        let mut attrs = IndexMap::new();
        attrs.insert("firstName".to_string(), "John".to_string());
        attrs.insert("lastName".to_string(), "Doe".to_string());

        let query = IdentityQuery::by_attributes(attrs);

        // Use Option comparison since attributes is Option<IndexMap>
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
        assert_eq!(
            config.network_preset,
            crate::overlay::NetworkPreset::Mainnet
        );
        assert!(config.originator.is_none());
    }

    #[test]
    fn test_identity_client_config_builder_methods() {
        let config = IdentityClientConfig::with_originator("test-app.example.com")
            .with_network(crate::overlay::NetworkPreset::Testnet)
            .with_token_amount(5);

        // Verify builder methods applied correctly
        assert_eq!(config.originator, Some("test-app.example.com".to_string()));
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
        let mut fields = indexmap::IndexMap::new();
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

#[cfg(test)]
#[path = "client_field_value_261_tests.rs"]
mod field_value_261_tests;

#[path = "client_token.rs"]
mod token;

#[cfg(test)]
#[path = "client_decode_token_744_tests.rs"]
mod decode_token_744_tests;

#[path = "client_record.rs"]
mod record;

#[path = "client_trust.rs"]
mod trust;
