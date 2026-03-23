//! # Registry Module
//!
//! On-chain protocol and certificate type registration for BSV.
//!
//! ## Overview
//!
//! The registry module provides client-side support for managing on-chain definitions
//! of baskets, protocols, and certificate types. It uses the overlay network for
//! discovery (SLAP) and broadcasting (SHIP) of registry entries.
//!
//! ## Components
//!
//! - **RegistryClient**: Main client for registry operations
//! - **Definition Types**: Basket, Protocol, and Certificate definitions
//! - **Query Types**: Filters for resolving definitions
//!
//! ## Example
//!
//! ```rust,ignore
//! use bsv_rs::registry::{RegistryClient, RegistryClientConfig, BasketDefinitionData};
//! use bsv_rs::wallet::ProtoWallet;
//!
//! // Create a registry client
//! let wallet = ProtoWallet::new(Some(PrivateKey::random()));
//! let client = RegistryClient::new(wallet, RegistryClientConfig::default());
//!
//! // Register a new basket
//! let data = BasketDefinitionData {
//!     basket_id: "my_basket".to_string(),
//!     name: "My Basket".to_string(),
//!     icon_url: None,
//!     description: Some("A custom basket".to_string()),
//!     documentation_url: None,
//!     registry_operator: String::new(), // Will be set automatically
//! };
//!
//! let record = client.register_basket(data).await?;
//! ```
//!
//! ## Lookup Services
//!
//! Registry uses the following overlay lookup services:
//! - `ls_basketmap`: Basket definition lookups
//! - `ls_protomap`: Protocol definition lookups
//! - `ls_certmap`: Certificate definition lookups
//!
//! ## Topic Broadcasting
//!
//! Registry entries are broadcast to:
//! - `tm_basketmap`: Basket definition topic
//! - `tm_protomap`: Protocol definition topic
//! - `tm_certmap`: Certificate definition topic
//!
//! ## Feature Flag
//!
//! This module requires the `registry` feature flag:
//!
//! ```toml
//! [dependencies]
//! bsv-rs = { version = "0.3", features = ["registry"] }
//! ```

pub mod client;
pub mod types;

// Re-exports from types
pub use types::{
    BasketDefinitionData, BasketQuery, BroadcastFailure, BroadcastSuccess,
    CertificateDefinitionData, CertificateFieldDescriptor, CertificateQuery, DefinitionData,
    DefinitionType, ProtocolDefinitionData, ProtocolQuery, RegisterDefinitionResult,
    RegistryRecord, RevokeDefinitionResult, TokenData, UpdateDefinitionResult,
};

// Re-exports from client
pub use client::{RegistryClient, RegistryClientConfig};

// Constants for registry services
/// Lookup service for basket definitions.
pub const LS_BASKETMAP: &str = "ls_basketmap";
/// Lookup service for protocol definitions.
pub const LS_PROTOMAP: &str = "ls_protomap";
/// Lookup service for certificate definitions.
pub const LS_CERTMAP: &str = "ls_certmap";

/// Topic for basket definition broadcasts.
pub const TM_BASKETMAP: &str = "tm_basketmap";
/// Topic for protocol definition broadcasts.
pub const TM_PROTOMAP: &str = "tm_protomap";
/// Topic for certificate definition broadcasts.
pub const TM_CERTMAP: &str = "tm_certmap";

/// Satoshi value for registry tokens (1 satoshi).
pub const REGISTRANT_TOKEN_AMOUNT: u64 = 1;

/// Key ID used for PushDrop signing.
pub const REGISTRANT_KEY_ID: &str = "1";

/// Wallet protocol for basket registration.
pub const BASKETMAP_PROTOCOL: (u8, &str) = (1, "basketmap");
/// Wallet protocol for protocol registration.
pub const PROTOMAP_PROTOCOL: (u8, &str) = (1, "protomap");
/// Wallet protocol for certificate registration.
pub const CERTMAP_PROTOCOL: (u8, &str) = (1, "certmap");
