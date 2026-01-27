//! # Identity Module
//!
//! Certificate-based identity resolution and discovery for BSV.
//!
//! ## Overview
//!
//! This module provides identity discovery and management via certificates.
//! Users can:
//! - **Reveal attributes**: Publicly reveal certificate fields on-chain
//! - **Resolve identities**: Find identities by key or attributes
//! - **Manage contacts**: Store and search personal contacts
//!
//! ## Components
//!
//! - [`IdentityClient`] - Main client for identity operations
//! - [`ContactsManager`] - Encrypted contact storage
//! - [`DisplayableIdentity`] - User-displayable identity representation
//! - [`KnownCertificateType`] - Predefined certificate types
//!
//! ## Known Certificate Types
//!
//! | Type | Description | Key Fields |
//! |------|-------------|------------|
//! | IdentiCert | Government ID | firstName, lastName, profilePhoto |
//! | DiscordCert | Discord account | userName, profilePhoto |
//! | PhoneCert | Phone number | phoneNumber |
//! | XCert | X/Twitter account | userName, profilePhoto |
//! | Registrant | Entity registration | name, icon |
//! | EmailCert | Email address | email |
//! | Anyone | Permissionless | (none) |
//! | Self | Self-issued | (none) |
//! | CoolCert | Demo certificate | cool |
//!
//! ## Example
//!
//! ```rust,ignore
//! use bsv_sdk::identity::{IdentityClient, IdentityClientConfig};
//! use bsv_sdk::wallet::ProtoWallet;
//!
//! // Create client
//! let wallet = ProtoWallet::new(None);
//! let config = IdentityClientConfig::with_originator("myapp.com");
//! let client = IdentityClient::new(wallet, config);
//!
//! // Resolve an identity
//! if let Some(identity) = client.resolve_by_identity_key("02abc123...").await? {
//!     println!("Found: {} ({})", identity.name, identity.abbreviated_key);
//! }
//!
//! // Search by attribute
//! let mut attrs = std::collections::HashMap::new();
//! attrs.insert("email".to_string(), "user@example.com".to_string());
//! let identities = client.resolve_by_attributes(attrs).await?;
//!
//! // Manage contacts
//! let contacts = client.get_contacts(false).await?;
//! client.save_contact(identity, None).await?;
//! ```
//!
//! ## Integration with Auth Module
//!
//! The identity module uses [`VerifiableCertificate`](crate::auth::VerifiableCertificate)
//! from the auth module for certificate handling. Certificates are created and
//! signed using the auth module's certificate infrastructure.
//!
//! ## Integration with Overlay Module
//!
//! Identity resolution uses the overlay network:
//! - **ls_identity** - Lookup service for identity queries
//! - **tm_identity** - Topic for broadcasting identity revelations
//!
//! ## Cross-SDK Compatibility
//!
//! This module maintains API compatibility with:
//! - [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `IdentityClient`, `ContactsManager`
//! - [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `identity.Client`
//!
//! Certificate type IDs are consistent across all SDK implementations.

pub mod client;
pub mod contacts;
pub mod types;

// Re-exports
pub use client::IdentityClient;
pub use contacts::ContactsManager;
pub use types::{
    // Type aliases
    Base64String,
    // Broadcast types
    BroadcastFailure,
    BroadcastResult,
    BroadcastSuccess,
    CertificateFieldNameUnder50Bytes,
    // Core types
    CertifierInfo,
    Contact,
    ContactsManagerConfig,
    DefaultIdentityValues,
    DisplayableIdentity,
    IdentityCertificate,
    IdentityClientConfig,
    IdentityQuery,
    IdentityResolutionResult,
    KnownCertificateType,
    OriginatorDomainNameStringUnder250Bytes,
    PubKeyHex,
    StaticAvatarUrls,
    // Constants
    DEFAULT_SOCIALCERT_CERTIFIER,
};
