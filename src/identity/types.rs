//! Core types for identity resolution and certificate-based discovery.
//!
//! This module defines types for representing displayable identities,
//! known certificate types, contacts, and query structures.

use crate::auth::VerifiableCertificate;
use crate::overlay::NetworkPreset;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Type Aliases (matching Go SDK)
// ============================================================================

/// Certificate field name with constraint of under 50 bytes.
/// Used when specifying which fields to reveal from a certificate.
pub type CertificateFieldNameUnder50Bytes = String;

/// Originator domain name string with constraint of under 250 bytes.
/// Used for audit trails and identifying the application.
pub type OriginatorDomainNameStringUnder250Bytes = String;

/// Public key in hex format (compressed, 33 bytes = 66 hex chars).
pub type PubKeyHex = String;

/// Base64-encoded string.
pub type Base64String = String;

// ============================================================================
// Known Certificate Types
// ============================================================================

/// Known certificate types for identity verification.
///
/// Each certificate type has a unique 32-byte type ID (base64-encoded)
/// that identifies the certificate schema and field structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KnownCertificateType {
    /// IdentiCert - Government ID verification.
    /// Fields: firstName, lastName, profilePhoto
    IdentiCert,
    /// DiscordCert - Discord account verification.
    /// Fields: userName, profilePhoto
    DiscordCert,
    /// PhoneCert - Phone number verification.
    /// Fields: phoneNumber
    PhoneCert,
    /// XCert - X (Twitter) account verification.
    /// Fields: userName, profilePhoto
    XCert,
    /// Registrant - Domain/entity registration.
    /// Fields: name, icon
    Registrant,
    /// EmailCert - Email address verification.
    /// Fields: email
    EmailCert,
    /// Anyone - Permissionless certificate (anyone can access).
    Anyone,
    /// Self - Self-issued certificate (only owner can access).
    SelfCert,
    /// CoolCert - Example/demo certificate type.
    /// Fields: cool (boolean)
    CoolCert,
}

impl KnownCertificateType {
    /// Get the certificate type ID as a base64-encoded string.
    ///
    /// These IDs are SHA-256 hashes of the type name, matching the
    /// TypeScript and Go SDK implementations.
    pub fn type_id(&self) -> &'static str {
        match self {
            Self::IdentiCert => "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=",
            Self::DiscordCert => "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=",
            Self::PhoneCert => "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=",
            Self::XCert => "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=",
            Self::Registrant => "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=",
            Self::EmailCert => "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=",
            Self::Anyone => "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=",
            Self::SelfCert => "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=",
            Self::CoolCert => "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=",
        }
    }

    /// Get the human-readable name of this certificate type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::IdentiCert => "IdentiCert",
            Self::DiscordCert => "DiscordCert",
            Self::PhoneCert => "PhoneCert",
            Self::XCert => "XCert",
            Self::Registrant => "Registrant",
            Self::EmailCert => "EmailCert",
            Self::Anyone => "Anyone",
            Self::SelfCert => "Self",
            Self::CoolCert => "CoolCert",
        }
    }

    /// Try to identify a certificate type from its base64 type ID.
    ///
    /// Returns `None` if the type ID doesn't match any known certificate type.
    pub fn from_type_id(type_id: &str) -> Option<Self> {
        match type_id {
            "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=" => Some(Self::IdentiCert),
            "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=" => Some(Self::DiscordCert),
            "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=" => Some(Self::PhoneCert),
            "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=" => Some(Self::XCert),
            "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=" => Some(Self::Registrant),
            "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=" => Some(Self::EmailCert),
            "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=" => Some(Self::Anyone),
            "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=" => Some(Self::SelfCert),
            "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=" => Some(Self::CoolCert),
            _ => None,
        }
    }

    /// Returns all known certificate types.
    pub fn all() -> &'static [Self] {
        &[
            Self::IdentiCert,
            Self::DiscordCert,
            Self::PhoneCert,
            Self::XCert,
            Self::Registrant,
            Self::EmailCert,
            Self::Anyone,
            Self::SelfCert,
            Self::CoolCert,
        ]
    }
}

// ============================================================================
// Displayable Identity
// ============================================================================

/// Default identity values for unverified or unknown identities.
pub struct DefaultIdentityValues;

impl DefaultIdentityValues {
    /// Default name for unknown identities.
    pub const NAME: &'static str = "Unknown Identity";
    /// Default avatar URL (UHRP hash).
    pub const AVATAR_URL: &'static str = "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst";
    /// Default badge icon URL (UHRP hash).
    pub const BADGE_ICON_URL: &'static str = "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG";
    /// Default badge label for unverified identities.
    pub const BADGE_LABEL: &'static str = "Not verified by anyone you trust.";
    /// Default badge click URL for documentation.
    pub const BADGE_CLICK_URL: &'static str = "https://projectbabbage.com/docs/unknown-identity";
}

/// A user-displayable identity representation.
///
/// This struct contains all the information needed to display an identity
/// in a user interface, including name, avatar, and verification badges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DisplayableIdentity {
    /// User's display name.
    pub name: String,
    /// Avatar URL (can be UHRP hash or full URL).
    pub avatar_url: String,
    /// Identity public key (hex-encoded compressed public key).
    pub identity_key: String,
    /// Abbreviation of identity key for display (e.g., "02abc1...f890").
    pub abbreviated_key: String,
    /// Badge icon URL for the certifier.
    pub badge_icon_url: String,
    /// Badge label describing the certification.
    pub badge_label: String,
    /// Badge link URL for more information.
    pub badge_click_url: String,
}

impl DisplayableIdentity {
    /// Create a minimal identity from just an identity key.
    ///
    /// Uses default values for all display fields.
    pub fn from_key(identity_key: &str) -> Self {
        let abbreviated = if identity_key.len() > 10 {
            format!(
                "{}...{}",
                &identity_key[..6],
                &identity_key[identity_key.len() - 4..]
            )
        } else {
            identity_key.to_string()
        };

        Self {
            name: abbreviated.clone(),
            avatar_url: DefaultIdentityValues::AVATAR_URL.to_string(),
            identity_key: identity_key.to_string(),
            abbreviated_key: abbreviated,
            badge_icon_url: DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            badge_label: DefaultIdentityValues::BADGE_LABEL.to_string(),
            badge_click_url: DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
        }
    }

    /// Create a default unknown identity.
    pub fn unknown() -> Self {
        Self {
            name: DefaultIdentityValues::NAME.to_string(),
            avatar_url: DefaultIdentityValues::AVATAR_URL.to_string(),
            identity_key: String::new(),
            abbreviated_key: String::new(),
            badge_icon_url: DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            badge_label: DefaultIdentityValues::BADGE_LABEL.to_string(),
            badge_click_url: DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
        }
    }
}

impl Default for DisplayableIdentity {
    fn default() -> Self {
        Self::unknown()
    }
}

// ============================================================================
// Contact
// ============================================================================

/// Contact entry for the contacts manager.
///
/// A contact is a displayable identity with optional metadata and tracking
/// information for when it was added.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    /// Contact's identity key (hex-encoded compressed public key).
    pub identity_key: String,
    /// Display name.
    pub name: String,
    /// Avatar URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// When the contact was added (Unix timestamp in milliseconds).
    #[serde(default)]
    pub added_at: u64,
    /// Custom notes about the contact (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Custom tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Contact {
    /// Create a new contact from a displayable identity.
    pub fn from_identity(identity: DisplayableIdentity) -> Self {
        Self {
            identity_key: identity.identity_key,
            name: identity.name,
            avatar_url: Some(identity.avatar_url),
            added_at: crate::auth::current_time_ms(),
            notes: None,
            tags: Vec::new(),
            metadata: None,
        }
    }

    /// Convert this contact to a displayable identity.
    pub fn to_displayable_identity(&self) -> DisplayableIdentity {
        let abbreviated = if self.identity_key.len() > 10 {
            format!(
                "{}...{}",
                &self.identity_key[..6],
                &self.identity_key[self.identity_key.len() - 4..]
            )
        } else {
            self.identity_key.clone()
        };

        DisplayableIdentity {
            name: self.name.clone(),
            avatar_url: self
                .avatar_url
                .clone()
                .unwrap_or_else(|| DefaultIdentityValues::AVATAR_URL.to_string()),
            identity_key: self.identity_key.clone(),
            abbreviated_key: abbreviated,
            badge_icon_url: DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            badge_label: "Personal contact".to_string(),
            badge_click_url: DefaultIdentityValues::BADGE_CLICK_URL.to_string(),
        }
    }
}

// ============================================================================
// Identity Query
// ============================================================================

/// Query parameters for discovering identities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityQuery {
    /// Filter by identity key (hex-encoded public key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    /// Filter by attribute name and value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
    /// Filter by certificate type (base64 type ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<String>,
    /// Filter by certifier (hex-encoded public key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifier: Option<String>,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Offset for pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

impl IdentityQuery {
    /// Create a query to find identity by key.
    pub fn by_identity_key(identity_key: impl Into<String>) -> Self {
        Self {
            identity_key: Some(identity_key.into()),
            ..Default::default()
        }
    }

    /// Create a query to find identities by attributes.
    pub fn by_attributes(attributes: HashMap<String, String>) -> Self {
        Self {
            attributes: Some(attributes),
            ..Default::default()
        }
    }

    /// Create a query to find identities by a single attribute.
    pub fn by_attribute(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut attributes = HashMap::new();
        attributes.insert(key.into(), value.into());
        Self {
            attributes: Some(attributes),
            ..Default::default()
        }
    }

    /// Set the maximum number of results.
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the offset for pagination.
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Filter by certifier.
    pub fn with_certifier(mut self, certifier: impl Into<String>) -> Self {
        self.certifier = Some(certifier.into());
        self
    }
}

// ============================================================================
// Identity Resolution Result
// ============================================================================

/// Result of identity resolution containing the identity and associated certificates.
#[derive(Debug, Clone)]
pub struct IdentityResolutionResult {
    /// The resolved displayable identity.
    pub identity: DisplayableIdentity,
    /// Associated certificates that contributed to this identity.
    pub certificates: Vec<VerifiableCertificate>,
}

// ============================================================================
// Certifier Info
// ============================================================================

/// Information about a certificate certifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertifierInfo {
    /// Certifier's display name.
    pub name: String,
    /// Certifier's icon URL.
    pub icon_url: String,
    /// Description of the certifier.
    pub description: String,
    /// Trust level (1-10).
    pub trust: u8,
}

impl Default for CertifierInfo {
    fn default() -> Self {
        Self {
            name: "Unknown Certifier".to_string(),
            icon_url: DefaultIdentityValues::BADGE_ICON_URL.to_string(),
            description: "No information available".to_string(),
            trust: 0,
        }
    }
}

// ============================================================================
// Identity Certificate (enriched)
// ============================================================================

/// An identity certificate with decrypted fields and certifier information.
///
/// This extends the base certificate with information needed for display.
#[derive(Debug, Clone)]
pub struct IdentityCertificate {
    /// The base verifiable certificate.
    pub certificate: VerifiableCertificate,
    /// Information about the certifier.
    pub certifier_info: CertifierInfo,
    /// Publicly revealed keyring for field decryption.
    pub publicly_revealed_keyring: HashMap<String, Vec<u8>>,
    /// Decrypted field values.
    pub decrypted_fields: HashMap<String, String>,
}

impl IdentityCertificate {
    /// Get the certificate type as a base64 string.
    pub fn type_base64(&self) -> String {
        self.certificate.certificate.type_base64()
    }

    /// Get the subject's public key as hex.
    pub fn subject_hex(&self) -> String {
        self.certificate.subject().to_hex()
    }

    /// Get the certifier's public key as hex.
    pub fn certifier_hex(&self) -> String {
        self.certificate.certifier().to_hex()
    }

    /// Check if this is a known certificate type.
    pub fn known_type(&self) -> Option<KnownCertificateType> {
        KnownCertificateType::from_type_id(&self.type_base64())
    }
}

// ============================================================================
// Client Configuration
// ============================================================================

/// Configuration for the IdentityClient.
#[derive(Debug, Clone)]
pub struct IdentityClientConfig {
    /// Network preset for overlay operations.
    pub network_preset: NetworkPreset,
    /// Protocol ID for identity operations.
    pub protocol_id: (u8, String),
    /// Key ID for derivation.
    pub key_id: String,
    /// Token amount for revelation outputs (satoshis).
    pub token_amount: u64,
    /// Output index for the identity token.
    pub output_index: u32,
    /// Originator domain for audit trails.
    pub originator: Option<String>,
}

impl Default for IdentityClientConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            protocol_id: (1, "identity".to_string()),
            key_id: "1".to_string(),
            token_amount: 1,
            output_index: 0,
            originator: None,
        }
    }
}

impl IdentityClientConfig {
    /// Create a new configuration with the given originator.
    pub fn with_originator(originator: impl Into<String>) -> Self {
        Self {
            originator: Some(originator.into()),
            ..Default::default()
        }
    }

    /// Set the network preset.
    pub fn with_network(mut self, network: NetworkPreset) -> Self {
        self.network_preset = network;
        self
    }

    /// Set the token amount for revelations.
    pub fn with_token_amount(mut self, amount: u64) -> Self {
        self.token_amount = amount;
        self
    }
}

// ============================================================================
// Contacts Manager Configuration
// ============================================================================

/// Configuration for the ContactsManager.
#[derive(Debug, Clone)]
pub struct ContactsManagerConfig {
    /// Protocol ID for contacts encryption.
    pub protocol_id: (u8, String),
    /// Basket name for contacts storage.
    pub basket: String,
    /// Originator domain for audit trails.
    pub originator: Option<String>,
}

impl Default for ContactsManagerConfig {
    fn default() -> Self {
        Self {
            protocol_id: (2, "contact".to_string()),
            basket: "contacts".to_string(),
            originator: None,
        }
    }
}

impl ContactsManagerConfig {
    /// Create a new configuration with the given originator.
    pub fn with_originator(originator: impl Into<String>) -> Self {
        Self {
            originator: Some(originator.into()),
            ..Default::default()
        }
    }
}

// ============================================================================
// Static Avatar URLs for specific certificate types
// ============================================================================

/// Static avatar URLs for certificate types without user avatars.
pub struct StaticAvatarUrls;

impl StaticAvatarUrls {
    /// Email certificate avatar (envelope icon).
    pub const EMAIL: &'static str = "XUTZxep7BBghAJbSBwTjNfmcsDdRFs5EaGEgkESGSgjJVYgMEizu";
    /// Phone certificate avatar (phone icon).
    pub const PHONE: &'static str = "XUTLxtX3ELNUwRhLwL7kWNGbdnFM8WG2eSLv84J7654oH8HaJWrU";
    /// Anyone certificate avatar.
    pub const ANYONE: &'static str = "XUT4bpQ6cpBaXi1oMzZsXfpkWGbtp2JTUYAoN7PzhStFJ6wLfoeR";
    /// Self certificate avatar.
    pub const SELF: &'static str = "XUT9jHGk2qace148jeCX5rDsMftkSGYKmigLwU2PLLBc7Hm63VYR";
}

// ============================================================================
// Default Certifier
// ============================================================================

/// Default SocialCert certifier for fallback resolution.
pub const DEFAULT_SOCIALCERT_CERTIFIER: &str =
    "02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17";

// ============================================================================
// Broadcast Result Types
// ============================================================================

/// Result of a successful broadcast to the overlay network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastSuccess {
    /// Transaction ID of the broadcast transaction.
    pub txid: String,
    /// Optional message from the overlay node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Result of a failed broadcast to the overlay network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastFailure {
    /// Error code.
    pub code: String,
    /// Human-readable description of the failure.
    pub description: String,
}

/// Result of a broadcast operation - either success or failure.
#[derive(Debug, Clone)]
pub enum BroadcastResult {
    /// Successful broadcast.
    Success(BroadcastSuccess),
    /// Failed broadcast.
    Failure(BroadcastFailure),
}

impl BroadcastResult {
    /// Returns true if the broadcast was successful.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns the transaction ID if successful.
    pub fn txid(&self) -> Option<&str> {
        match self {
            Self::Success(s) => Some(&s.txid),
            Self::Failure(_) => None,
        }
    }

    /// Converts to Result, returning an error for broadcast failures.
    pub fn into_result(self) -> Result<BroadcastSuccess, BroadcastFailure> {
        match self {
            Self::Success(s) => Ok(s),
            Self::Failure(f) => Err(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_certificate_type_names() {
        assert_eq!(KnownCertificateType::IdentiCert.name(), "IdentiCert");
        assert_eq!(KnownCertificateType::DiscordCert.name(), "DiscordCert");
        assert_eq!(KnownCertificateType::PhoneCert.name(), "PhoneCert");
        assert_eq!(KnownCertificateType::XCert.name(), "XCert");
        assert_eq!(KnownCertificateType::Registrant.name(), "Registrant");
        assert_eq!(KnownCertificateType::EmailCert.name(), "EmailCert");
        assert_eq!(KnownCertificateType::Anyone.name(), "Anyone");
        assert_eq!(KnownCertificateType::SelfCert.name(), "Self");
        assert_eq!(KnownCertificateType::CoolCert.name(), "CoolCert");
    }

    #[test]
    fn test_known_certificate_type_ids() {
        // Verify IDs match TypeScript/Go SDKs
        assert_eq!(
            KnownCertificateType::IdentiCert.type_id(),
            "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
        );
        assert_eq!(
            KnownCertificateType::XCert.type_id(),
            "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
        );
        assert_eq!(
            KnownCertificateType::Anyone.type_id(),
            "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
        );
        assert_eq!(
            KnownCertificateType::SelfCert.type_id(),
            "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
        );
    }

    #[test]
    fn test_known_certificate_type_from_id() {
        assert_eq!(
            KnownCertificateType::from_type_id("z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="),
            Some(KnownCertificateType::IdentiCert)
        );
        assert_eq!(
            KnownCertificateType::from_type_id("vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="),
            Some(KnownCertificateType::XCert)
        );
        assert_eq!(KnownCertificateType::from_type_id("unknown"), None);
    }

    #[test]
    fn test_known_certificate_type_roundtrip() {
        for cert_type in KnownCertificateType::all() {
            let type_id = cert_type.type_id();
            let parsed = KnownCertificateType::from_type_id(type_id);
            assert_eq!(parsed, Some(*cert_type));
        }
    }

    #[test]
    fn test_displayable_identity_from_key() {
        // 66 hex chars = 33 bytes compressed public key
        let identity = DisplayableIdentity::from_key(
            "02abc123def456789012345678901234567890123456789012345678901234abcd",
        );
        assert!(identity.abbreviated_key.contains("..."));
        assert_eq!(identity.identity_key.len(), 66);
        assert_eq!(identity.abbreviated_key, "02abc1...abcd");
    }

    #[test]
    fn test_displayable_identity_from_short_key() {
        let identity = DisplayableIdentity::from_key("short");
        assert_eq!(identity.abbreviated_key, "short");
        assert_eq!(identity.identity_key, "short");
    }

    #[test]
    fn test_displayable_identity_serialization() {
        let identity = DisplayableIdentity {
            name: "Alice".to_string(),
            avatar_url: "https://example.com/avatar.png".to_string(),
            identity_key: "02abc123".to_string(),
            abbreviated_key: "02ab...".to_string(),
            badge_icon_url: "https://example.com/badge.png".to_string(),
            badge_label: "Verified".to_string(),
            badge_click_url: "https://example.com/verify".to_string(),
        };

        let json = serde_json::to_string(&identity).unwrap();
        assert!(json.contains("\"name\":\"Alice\""));
        assert!(json.contains("\"avatarUrl\":")); // camelCase

        let decoded: DisplayableIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "Alice");
        assert_eq!(decoded.identity_key, "02abc123");
    }

    #[test]
    fn test_contact_serialization() {
        let contact = Contact {
            identity_key: "02abc123".to_string(),
            name: "Bob".to_string(),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            added_at: 1700000000000,
            notes: Some("Friend".to_string()),
            tags: vec!["work".to_string(), "friend".to_string()],
            metadata: None,
        };

        let json = serde_json::to_string(&contact).unwrap();
        assert!(json.contains("\"name\":\"Bob\""));
        assert!(json.contains("\"identityKey\":\"02abc123\"")); // camelCase

        let decoded: Contact = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "Bob");
        assert_eq!(decoded.tags.len(), 2);
    }

    #[test]
    fn test_contact_without_optional_fields() {
        let contact = Contact {
            identity_key: "02abc123".to_string(),
            name: "Charlie".to_string(),
            avatar_url: None,
            added_at: 0,
            notes: None,
            tags: Vec::new(),
            metadata: None,
        };

        let json = serde_json::to_string(&contact).unwrap();
        // Optional fields should not be serialized when None
        assert!(!json.contains("avatarUrl"));
        assert!(!json.contains("notes"));
        assert!(!json.contains("metadata"));
    }

    #[test]
    fn test_identity_query_default() {
        let query = IdentityQuery::default();
        assert!(query.identity_key.is_none());
        assert!(query.attributes.is_none());
        assert!(query.certificate_type.is_none());
        assert!(query.certifier.is_none());
        assert!(query.limit.is_none());
    }

    #[test]
    fn test_identity_query_by_identity_key() {
        let query = IdentityQuery::by_identity_key("02abc123");
        assert_eq!(query.identity_key, Some("02abc123".to_string()));
        assert!(query.attributes.is_none());
    }

    #[test]
    fn test_identity_query_by_attributes() {
        let mut attrs = HashMap::new();
        attrs.insert("email".to_string(), "test@example.com".to_string());

        let query = IdentityQuery::by_attributes(attrs);
        assert!(query.identity_key.is_none());
        assert!(query.attributes.is_some());
        assert_eq!(
            query.attributes.as_ref().unwrap().get("email"),
            Some(&"test@example.com".to_string())
        );
    }

    #[test]
    fn test_identity_query_builder() {
        let query = IdentityQuery::by_attribute("email", "test@example.com")
            .with_limit(10)
            .with_offset(5)
            .with_certifier("02certifier");

        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(5));
        assert_eq!(query.certifier, Some("02certifier".to_string()));
    }

    #[test]
    fn test_identity_query_serialization() {
        let query = IdentityQuery::by_attribute("email", "test@example.com").with_limit(10);

        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("\"limit\":10"));

        let decoded: IdentityQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.limit, Some(10));
    }

    #[test]
    fn test_identity_client_config_default() {
        let config = IdentityClientConfig::default();
        assert_eq!(config.network_preset, NetworkPreset::Mainnet);
        assert_eq!(config.protocol_id, (1, "identity".to_string()));
        assert_eq!(config.key_id, "1");
        assert_eq!(config.token_amount, 1);
        assert_eq!(config.output_index, 0);
        assert!(config.originator.is_none());
    }

    #[test]
    fn test_identity_client_config_builder() {
        let config = IdentityClientConfig::with_originator("myapp.com")
            .with_network(NetworkPreset::Testnet)
            .with_token_amount(100);

        assert_eq!(config.originator, Some("myapp.com".to_string()));
        assert_eq!(config.network_preset, NetworkPreset::Testnet);
        assert_eq!(config.token_amount, 100);
    }

    #[test]
    fn test_contacts_manager_config_default() {
        let config = ContactsManagerConfig::default();
        assert_eq!(config.protocol_id, (2, "contact".to_string()));
        assert_eq!(config.basket, "contacts");
        assert!(config.originator.is_none());
    }

    #[test]
    fn test_certifier_info_default() {
        let info = CertifierInfo::default();
        assert_eq!(info.name, "Unknown Certifier");
        assert_eq!(info.trust, 0);
    }

    #[test]
    fn test_contact_from_identity() {
        let identity = DisplayableIdentity::from_key("02abc123");
        let contact = Contact::from_identity(identity.clone());

        assert_eq!(contact.identity_key, identity.identity_key);
        assert_eq!(contact.name, identity.name);
        assert!(contact.added_at > 0);
    }

    #[test]
    fn test_contact_to_displayable_identity() {
        let contact = Contact {
            identity_key: "02abc123def456789012345678901234567890123456789012345678901234567890"
                .to_string(),
            name: "Test User".to_string(),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            added_at: 1700000000000,
            notes: None,
            tags: Vec::new(),
            metadata: None,
        };

        let identity = contact.to_displayable_identity();
        assert_eq!(identity.name, "Test User");
        assert_eq!(identity.avatar_url, "https://example.com/avatar.png");
        assert!(identity.abbreviated_key.contains("..."));
    }
}
