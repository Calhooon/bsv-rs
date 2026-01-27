//! Registry type definitions.
//!
//! This module provides all the type definitions for the registry module,
//! including definition types for baskets, protocols, and certificates,
//! as well as query types and token data structures.
//!
//! ## Cross-SDK Compatibility
//!
//! All types use specific JSON field names to match Go/TypeScript SDKs:
//! - `basketID` (not `basketId`)
//! - `iconURL` (not `iconUrl`)
//! - `documentationURL` (not `documentationUrl`)
//! - `protocolID` (not `protocolId`)

use crate::wallet::{Protocol as WalletProtocol, SecurityLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Definition Type
// =============================================================================

/// Type of registry definition.
///
/// Determines which registry service and topic are used for registration
/// and resolution of definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefinitionType {
    /// Basket definition (output categorization).
    Basket,
    /// Protocol definition (application protocol registration).
    Protocol,
    /// Certificate type definition (identity certificate schema).
    Certificate,
}

impl DefinitionType {
    /// Returns the definition type as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Basket => "basket",
            Self::Protocol => "protocol",
            Self::Certificate => "certificate",
        }
    }

    /// Parses a definition type from a string.
    ///
    /// Note: Prefer using `str::parse()` via the `FromStr` trait for a more
    /// idiomatic interface.
    pub fn try_from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "basket" => Some(Self::Basket),
            "protocol" => Some(Self::Protocol),
            "certificate" => Some(Self::Certificate),
            _ => None,
        }
    }

    /// Returns the lookup service name for this definition type.
    pub fn lookup_service(&self) -> &'static str {
        match self {
            Self::Basket => super::LS_BASKETMAP,
            Self::Protocol => super::LS_PROTOMAP,
            Self::Certificate => super::LS_CERTMAP,
        }
    }

    /// Returns the broadcast topic for this definition type.
    pub fn broadcast_topic(&self) -> &'static str {
        match self {
            Self::Basket => super::TM_BASKETMAP,
            Self::Protocol => super::TM_PROTOMAP,
            Self::Certificate => super::TM_CERTMAP,
        }
    }

    /// Returns the wallet basket name for this definition type.
    pub fn wallet_basket(&self) -> &'static str {
        match self {
            Self::Basket => "basketmap",
            Self::Protocol => "protomap",
            Self::Certificate => "certmap",
        }
    }

    /// Returns the wallet protocol tuple for this definition type.
    pub fn wallet_protocol(&self) -> (u8, &'static str) {
        match self {
            Self::Basket => super::BASKETMAP_PROTOCOL,
            Self::Protocol => super::PROTOMAP_PROTOCOL,
            Self::Certificate => super::CERTMAP_PROTOCOL,
        }
    }

    /// Returns the expected field count in the PushDrop script.
    pub fn expected_field_count(&self) -> usize {
        match self {
            Self::Basket => 6, // basketID, name, iconURL, description, documentationURL, registryOperator
            Self::Protocol => 6, // protocolID(JSON), name, iconURL, description, documentationURL, registryOperator
            Self::Certificate => 7, // type, name, iconURL, description, documentationURL, fields(JSON), registryOperator
        }
    }
}

impl std::fmt::Display for DefinitionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for DefinitionType {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from_str(s).ok_or_else(|| {
            crate::Error::InvalidDefinitionData(format!("Unknown definition type: {}", s))
        })
    }
}

// =============================================================================
// Token Data
// =============================================================================

/// Token data representing an on-chain UTXO.
///
/// Contains the transaction reference and locking script for a registry entry,
/// along with optional BEEF data for SPV verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenData {
    /// Transaction ID (hex string).
    pub txid: String,
    /// Output index in the transaction.
    pub output_index: u32,
    /// Satoshi value of the output.
    pub satoshis: u64,
    /// Locking script (hex string).
    pub locking_script: String,
    /// BEEF data for SPV verification (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beef: Option<Vec<u8>>,
}

impl TokenData {
    /// Creates a new TokenData instance.
    pub fn new(txid: String, output_index: u32, satoshis: u64, locking_script: String) -> Self {
        Self {
            txid,
            output_index,
            satoshis,
            locking_script,
            beef: None,
        }
    }

    /// Creates a new TokenData instance with BEEF data.
    pub fn with_beef(
        txid: String,
        output_index: u32,
        satoshis: u64,
        locking_script: String,
        beef: Vec<u8>,
    ) -> Self {
        Self {
            txid,
            output_index,
            satoshis,
            locking_script,
            beef: Some(beef),
        }
    }

    /// Returns the outpoint string (txid.outputIndex format).
    pub fn outpoint(&self) -> String {
        format!("{}.{}", self.txid, self.output_index)
    }
}

// =============================================================================
// Basket Definition
// =============================================================================

/// Basket definition data.
///
/// Defines a basket for categorizing transaction outputs. Baskets are used
/// by wallets to organize and filter outputs.
///
/// # PushDrop Fields (6 total)
/// 0: basketID
/// 1: name
/// 2: iconURL
/// 3: description
/// 4: documentationURL
/// 5: registryOperator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasketDefinitionData {
    /// Definition type (always "basket").
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,
    /// Unique basket identifier (e.g., "my_basket").
    #[serde(rename = "basketID")]
    pub basket_id: String,
    /// Human-readable name.
    pub name: String,
    /// Icon URL.
    #[serde(rename = "iconURL")]
    pub icon_url: String,
    /// Description.
    pub description: String,
    /// Documentation URL.
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,
    /// Registry operator public key (hex string).
    /// This is automatically set during registration.
    #[serde(
        rename = "registryOperator",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub registry_operator: String,
}

impl BasketDefinitionData {
    /// Creates a new BasketDefinitionData with required fields.
    pub fn new(basket_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            definition_type: DefinitionType::Basket,
            basket_id: basket_id.into(),
            name: name.into(),
            icon_url: String::new(),
            description: String::new(),
            documentation_url: String::new(),
            registry_operator: String::new(),
        }
    }

    /// Sets the icon URL.
    pub fn with_icon_url(mut self, url: impl Into<String>) -> Self {
        self.icon_url = url.into();
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the documentation URL.
    pub fn with_documentation_url(mut self, url: impl Into<String>) -> Self {
        self.documentation_url = url.into();
        self
    }

    /// Returns the identifier for this definition.
    pub fn identifier(&self) -> &str {
        &self.basket_id
    }

    /// Returns the definition type.
    pub fn get_definition_type(&self) -> DefinitionType {
        DefinitionType::Basket
    }

    /// Returns the registry operator.
    pub fn get_registry_operator(&self) -> &str {
        &self.registry_operator
    }

    /// Builds PushDrop fields for this definition.
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Vec<Vec<u8>> {
        vec![
            self.basket_id.as_bytes().to_vec(),
            self.name.as_bytes().to_vec(),
            self.icon_url.as_bytes().to_vec(),
            self.description.as_bytes().to_vec(),
            self.documentation_url.as_bytes().to_vec(),
            registry_operator.as_bytes().to_vec(),
        ]
    }

    /// Creates from PushDrop fields.
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> crate::Result<Self> {
        if fields.len() != 6 {
            return Err(crate::Error::InvalidDefinitionData(format!(
                "Expected 6 fields for basket, got {}",
                fields.len()
            )));
        }

        let basket_id = String::from_utf8(fields[0].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid basketID: {}", e)))?;
        let name = String::from_utf8(fields[1].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid name: {}", e)))?;
        let icon_url = String::from_utf8(fields[2].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid iconURL: {}", e)))?;
        let description = String::from_utf8(fields[3].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid description: {}", e))
        })?;
        let documentation_url = String::from_utf8(fields[4].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid documentationURL: {}", e))
        })?;
        let registry_operator = String::from_utf8(fields[5].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid registryOperator: {}", e))
        })?;

        Ok(Self {
            definition_type: DefinitionType::Basket,
            basket_id,
            name,
            icon_url,
            description,
            documentation_url,
            registry_operator,
        })
    }
}

// =============================================================================
// Protocol Definition
// =============================================================================

/// Protocol definition data.
///
/// Defines a wallet protocol with its security level and metadata.
/// Protocols are used for key derivation and data signing operations.
///
/// # PushDrop Fields (6 total)
/// 0: protocolID (JSON: [securityLevel, "protocolName"])
/// 1: name
/// 2: iconURL
/// 3: description
/// 4: documentationURL
/// 5: registryOperator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDefinitionData {
    /// Definition type (always "protocol").
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,
    /// Wallet protocol identifier (security level and protocol name).
    #[serde(rename = "protocolID")]
    pub protocol_id: WalletProtocol,
    /// Human-readable name.
    pub name: String,
    /// Icon URL.
    #[serde(rename = "iconURL")]
    pub icon_url: String,
    /// Description.
    pub description: String,
    /// Documentation URL.
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,
    /// Registry operator public key (hex string).
    /// This is automatically set during registration.
    #[serde(
        rename = "registryOperator",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub registry_operator: String,
}

impl ProtocolDefinitionData {
    /// Creates a new ProtocolDefinitionData with required fields.
    pub fn new(protocol_id: WalletProtocol, name: impl Into<String>) -> Self {
        Self {
            definition_type: DefinitionType::Protocol,
            protocol_id,
            name: name.into(),
            icon_url: String::new(),
            description: String::new(),
            documentation_url: String::new(),
            registry_operator: String::new(),
        }
    }

    /// Sets the icon URL.
    pub fn with_icon_url(mut self, url: impl Into<String>) -> Self {
        self.icon_url = url.into();
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the documentation URL.
    pub fn with_documentation_url(mut self, url: impl Into<String>) -> Self {
        self.documentation_url = url.into();
        self
    }

    /// Returns the identifier for this definition.
    /// Format: "[securityLevel, \"protocolName\"]"
    pub fn identifier(&self) -> String {
        format!(
            "[{}, \"{}\"]",
            self.protocol_id.security_level as u8, self.protocol_id.protocol_name
        )
    }

    /// Returns the definition type.
    pub fn get_definition_type(&self) -> DefinitionType {
        DefinitionType::Protocol
    }

    /// Returns the registry operator.
    pub fn get_registry_operator(&self) -> &str {
        &self.registry_operator
    }

    /// Builds PushDrop fields for this definition.
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> crate::Result<Vec<Vec<u8>>> {
        // Serialize protocolID as JSON: [securityLevel, "protocolName"]
        let protocol_json = serde_json::to_string(&self.protocol_id).map_err(|e| {
            crate::Error::RegistryError(format!("Failed to serialize protocolID: {}", e))
        })?;

        Ok(vec![
            protocol_json.as_bytes().to_vec(),
            self.name.as_bytes().to_vec(),
            self.icon_url.as_bytes().to_vec(),
            self.description.as_bytes().to_vec(),
            self.documentation_url.as_bytes().to_vec(),
            registry_operator.as_bytes().to_vec(),
        ])
    }

    /// Creates from PushDrop fields.
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> crate::Result<Self> {
        if fields.len() != 6 {
            return Err(crate::Error::InvalidDefinitionData(format!(
                "Expected 6 fields for protocol, got {}",
                fields.len()
            )));
        }

        let protocol_json = String::from_utf8(fields[0].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid protocolID JSON: {}", e))
        })?;
        let protocol_id = deserialize_wallet_protocol(&protocol_json)?;

        let name = String::from_utf8(fields[1].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid name: {}", e)))?;
        let icon_url = String::from_utf8(fields[2].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid iconURL: {}", e)))?;
        let description = String::from_utf8(fields[3].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid description: {}", e))
        })?;
        let documentation_url = String::from_utf8(fields[4].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid documentationURL: {}", e))
        })?;
        let registry_operator = String::from_utf8(fields[5].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid registryOperator: {}", e))
        })?;

        Ok(Self {
            definition_type: DefinitionType::Protocol,
            protocol_id,
            name,
            icon_url,
            description,
            documentation_url,
            registry_operator,
        })
    }
}

/// Deserializes a wallet protocol from JSON string.
/// Format: [securityLevel, "protocolName"]
pub fn deserialize_wallet_protocol(s: &str) -> crate::Result<WalletProtocol> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(s).map_err(|e| {
        crate::Error::InvalidDefinitionData(format!("Invalid wallet protocol format: {}", e))
    })?;

    if arr.len() != 2 {
        return Err(crate::Error::InvalidDefinitionData(
            "Invalid wallet protocol format, expected array of length 2".to_string(),
        ));
    }

    let security_level = arr[0]
        .as_u64()
        .ok_or_else(|| crate::Error::InvalidDefinitionData("Invalid security level".to_string()))?;

    if security_level > 2 {
        return Err(crate::Error::InvalidDefinitionData(
            "Security level must be 0, 1, or 2".to_string(),
        ));
    }

    let protocol = arr[1]
        .as_str()
        .ok_or_else(|| crate::Error::InvalidDefinitionData("Invalid protocol ID".to_string()))?;

    let sec_level = match security_level {
        0 => SecurityLevel::Silent,
        1 => SecurityLevel::App,
        2 => SecurityLevel::Counterparty,
        _ => unreachable!(),
    };

    Ok(WalletProtocol::new(sec_level, protocol))
}

// =============================================================================
// Certificate Field Descriptor
// =============================================================================

/// Describes a field in a certificate definition.
///
/// Used to define the schema for certificate fields with metadata
/// for UI display and validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateFieldDescriptor {
    /// User-friendly name for the field.
    #[serde(rename = "friendlyName")]
    pub friendly_name: String,
    /// Description of the field.
    pub description: String,
    /// Field type: "text", "imageURL", or "other".
    #[serde(rename = "type")]
    pub field_type: String,
    /// Icon identifier for the field.
    #[serde(rename = "fieldIcon")]
    pub field_icon: String,
}

impl CertificateFieldDescriptor {
    /// Creates a new text field descriptor.
    pub fn text(friendly_name: impl Into<String>) -> Self {
        Self {
            friendly_name: friendly_name.into(),
            description: String::new(),
            field_type: "text".to_string(),
            field_icon: String::new(),
        }
    }

    /// Creates a new imageURL field descriptor.
    pub fn image_url(friendly_name: impl Into<String>) -> Self {
        Self {
            friendly_name: friendly_name.into(),
            description: String::new(),
            field_type: "imageURL".to_string(),
            field_icon: String::new(),
        }
    }

    /// Creates a new field descriptor with custom type.
    pub fn new(friendly_name: impl Into<String>, field_type: impl Into<String>) -> Self {
        Self {
            friendly_name: friendly_name.into(),
            description: String::new(),
            field_type: field_type.into(),
            field_icon: String::new(),
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the field icon.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.field_icon = icon.into();
        self
    }
}

// =============================================================================
// Certificate Definition
// =============================================================================

/// Certificate type definition data.
///
/// Defines a certificate type with its fields and metadata.
/// Certificate types are used for identity verification and attestation.
///
/// # PushDrop Fields (7 total)
/// 0: type (certificate type identifier)
/// 1: name
/// 2: iconURL
/// 3: description
/// 4: documentationURL
/// 5: fields (JSON map of field descriptors)
/// 6: registryOperator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDefinitionData {
    /// Definition type (always "certificate").
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,
    /// Certificate type identifier (typically base64 of 32-byte type ID).
    #[serde(rename = "type")]
    pub cert_type: String,
    /// Human-readable name.
    pub name: String,
    /// Icon URL.
    #[serde(rename = "iconURL")]
    pub icon_url: String,
    /// Description.
    pub description: String,
    /// Documentation URL.
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,
    /// Certificate field definitions.
    pub fields: HashMap<String, CertificateFieldDescriptor>,
    /// Registry operator public key (hex string).
    /// This is automatically set during registration.
    #[serde(
        rename = "registryOperator",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub registry_operator: String,
}

impl CertificateDefinitionData {
    /// Creates a new CertificateDefinitionData with required fields.
    pub fn new(cert_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            definition_type: DefinitionType::Certificate,
            cert_type: cert_type.into(),
            name: name.into(),
            icon_url: String::new(),
            description: String::new(),
            documentation_url: String::new(),
            fields: HashMap::new(),
            registry_operator: String::new(),
        }
    }

    /// Sets the icon URL.
    pub fn with_icon_url(mut self, url: impl Into<String>) -> Self {
        self.icon_url = url.into();
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the documentation URL.
    pub fn with_documentation_url(mut self, url: impl Into<String>) -> Self {
        self.documentation_url = url.into();
        self
    }

    /// Adds a field descriptor.
    pub fn with_field(
        mut self,
        name: impl Into<String>,
        descriptor: CertificateFieldDescriptor,
    ) -> Self {
        self.fields.insert(name.into(), descriptor);
        self
    }

    /// Returns the identifier for this definition.
    pub fn identifier(&self) -> &str {
        &self.cert_type
    }

    /// Returns the definition type.
    pub fn get_definition_type(&self) -> DefinitionType {
        DefinitionType::Certificate
    }

    /// Returns the registry operator.
    pub fn get_registry_operator(&self) -> &str {
        &self.registry_operator
    }

    /// Builds PushDrop fields for this definition.
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> crate::Result<Vec<Vec<u8>>> {
        // Serialize fields map as JSON
        let fields_json = serde_json::to_string(&self.fields).map_err(|e| {
            crate::Error::RegistryError(format!("Failed to serialize fields: {}", e))
        })?;

        Ok(vec![
            self.cert_type.as_bytes().to_vec(),
            self.name.as_bytes().to_vec(),
            self.icon_url.as_bytes().to_vec(),
            self.description.as_bytes().to_vec(),
            self.documentation_url.as_bytes().to_vec(),
            fields_json.as_bytes().to_vec(),
            registry_operator.as_bytes().to_vec(),
        ])
    }

    /// Creates from PushDrop fields.
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> crate::Result<Self> {
        if fields.len() != 7 {
            return Err(crate::Error::InvalidDefinitionData(format!(
                "Expected 7 fields for certificate, got {}",
                fields.len()
            )));
        }

        let cert_type = String::from_utf8(fields[0].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid type: {}", e)))?;
        let name = String::from_utf8(fields[1].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid name: {}", e)))?;
        let icon_url = String::from_utf8(fields[2].clone())
            .map_err(|e| crate::Error::InvalidDefinitionData(format!("Invalid iconURL: {}", e)))?;
        let description = String::from_utf8(fields[3].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid description: {}", e))
        })?;
        let documentation_url = String::from_utf8(fields[4].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid documentationURL: {}", e))
        })?;

        let fields_json = String::from_utf8(fields[5].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid fields JSON: {}", e))
        })?;
        let cert_fields: HashMap<String, CertificateFieldDescriptor> =
            serde_json::from_str(&fields_json).unwrap_or_default();

        let registry_operator = String::from_utf8(fields[6].clone()).map_err(|e| {
            crate::Error::InvalidDefinitionData(format!("Invalid registryOperator: {}", e))
        })?;

        Ok(Self {
            definition_type: DefinitionType::Certificate,
            cert_type,
            name,
            icon_url,
            description,
            documentation_url,
            fields: cert_fields,
            registry_operator,
        })
    }
}

// =============================================================================
// Definition Data Enum
// =============================================================================

/// Union type for all definition data types.
///
/// This enum allows treating all definition types uniformly in the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DefinitionData {
    /// Basket definition.
    Basket(BasketDefinitionData),
    /// Protocol definition.
    Protocol(ProtocolDefinitionData),
    /// Certificate definition.
    Certificate(CertificateDefinitionData),
}

impl DefinitionData {
    /// Returns the definition type.
    pub fn get_definition_type(&self) -> DefinitionType {
        match self {
            Self::Basket(_) => DefinitionType::Basket,
            Self::Protocol(_) => DefinitionType::Protocol,
            Self::Certificate(_) => DefinitionType::Certificate,
        }
    }

    /// Returns the registry operator.
    pub fn get_registry_operator(&self) -> &str {
        match self {
            Self::Basket(d) => &d.registry_operator,
            Self::Protocol(d) => &d.registry_operator,
            Self::Certificate(d) => &d.registry_operator,
        }
    }

    /// Sets the registry operator.
    pub fn set_registry_operator(&mut self, operator: String) {
        match self {
            Self::Basket(d) => d.registry_operator = operator,
            Self::Protocol(d) => d.registry_operator = operator,
            Self::Certificate(d) => d.registry_operator = operator,
        }
    }

    /// Returns the identifier for this definition.
    pub fn identifier(&self) -> String {
        match self {
            Self::Basket(d) => d.basket_id.clone(),
            Self::Protocol(d) => d.identifier(),
            Self::Certificate(d) => d.cert_type.clone(),
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &str {
        match self {
            Self::Basket(d) => &d.name,
            Self::Protocol(d) => &d.name,
            Self::Certificate(d) => &d.name,
        }
    }

    /// Builds PushDrop fields for this definition.
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> crate::Result<Vec<Vec<u8>>> {
        match self {
            Self::Basket(d) => Ok(d.to_pushdrop_fields(registry_operator)),
            Self::Protocol(d) => d.to_pushdrop_fields(registry_operator),
            Self::Certificate(d) => d.to_pushdrop_fields(registry_operator),
        }
    }

    /// Returns as basket data if this is a basket definition.
    pub fn as_basket(&self) -> Option<&BasketDefinitionData> {
        match self {
            Self::Basket(d) => Some(d),
            _ => None,
        }
    }

    /// Returns as protocol data if this is a protocol definition.
    pub fn as_protocol(&self) -> Option<&ProtocolDefinitionData> {
        match self {
            Self::Protocol(d) => Some(d),
            _ => None,
        }
    }

    /// Returns as certificate data if this is a certificate definition.
    pub fn as_certificate(&self) -> Option<&CertificateDefinitionData> {
        match self {
            Self::Certificate(d) => Some(d),
            _ => None,
        }
    }
}

impl From<BasketDefinitionData> for DefinitionData {
    fn from(d: BasketDefinitionData) -> Self {
        Self::Basket(d)
    }
}

impl From<ProtocolDefinitionData> for DefinitionData {
    fn from(d: ProtocolDefinitionData) -> Self {
        Self::Protocol(d)
    }
}

impl From<CertificateDefinitionData> for DefinitionData {
    fn from(d: CertificateDefinitionData) -> Self {
        Self::Certificate(d)
    }
}

// =============================================================================
// Registry Record
// =============================================================================

/// A registry record combining definition data with on-chain token data.
///
/// This represents a complete registry entry including both the definition
/// information and the UTXO details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRecord {
    /// The definition data.
    #[serde(flatten)]
    pub definition: DefinitionData,
    /// The token data.
    #[serde(flatten)]
    pub token: TokenData,
}

impl RegistryRecord {
    /// Creates a new registry record.
    pub fn new(definition: DefinitionData, token: TokenData) -> Self {
        Self { definition, token }
    }

    /// Creates a basket registry record.
    pub fn basket(definition: BasketDefinitionData, token: TokenData) -> Self {
        Self {
            definition: DefinitionData::Basket(definition),
            token,
        }
    }

    /// Creates a protocol registry record.
    pub fn protocol(definition: ProtocolDefinitionData, token: TokenData) -> Self {
        Self {
            definition: DefinitionData::Protocol(definition),
            token,
        }
    }

    /// Creates a certificate registry record.
    pub fn certificate(definition: CertificateDefinitionData, token: TokenData) -> Self {
        Self {
            definition: DefinitionData::Certificate(definition),
            token,
        }
    }

    /// Returns the token data.
    pub fn token(&self) -> &TokenData {
        &self.token
    }

    /// Returns the definition type.
    pub fn get_definition_type(&self) -> DefinitionType {
        self.definition.get_definition_type()
    }

    /// Returns the registry operator.
    pub fn get_registry_operator(&self) -> &str {
        self.definition.get_registry_operator()
    }

    /// Returns the identifier.
    pub fn identifier(&self) -> String {
        self.definition.identifier()
    }

    /// Returns the transaction ID.
    pub fn txid(&self) -> &str {
        &self.token.txid
    }

    /// Returns the output index.
    pub fn output_index(&self) -> u32 {
        self.token.output_index
    }

    /// Returns the outpoint string.
    pub fn outpoint(&self) -> String {
        self.token.outpoint()
    }

    /// Returns as basket definition if this is a basket record.
    pub fn as_basket(&self) -> Option<&BasketDefinitionData> {
        self.definition.as_basket()
    }

    /// Returns as protocol definition if this is a protocol record.
    pub fn as_protocol(&self) -> Option<&ProtocolDefinitionData> {
        self.definition.as_protocol()
    }

    /// Returns as certificate definition if this is a certificate record.
    pub fn as_certificate(&self) -> Option<&CertificateDefinitionData> {
        self.definition.as_certificate()
    }
}

// =============================================================================
// Query Types
// =============================================================================

/// Query for basket definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasketQuery {
    /// Filter by basket ID.
    #[serde(rename = "basketID", skip_serializing_if = "Option::is_none")]
    pub basket_id: Option<String>,
    /// Filter by registry operators.
    #[serde(rename = "registryOperators", skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
    /// Filter by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl BasketQuery {
    /// Creates an empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a basket ID filter.
    pub fn with_basket_id(mut self, id: impl Into<String>) -> Self {
        self.basket_id = Some(id.into());
        self
    }

    /// Adds a registry operator filter.
    pub fn with_registry_operator(mut self, operator: impl Into<String>) -> Self {
        self.registry_operators = Some(vec![operator.into()]);
        self
    }

    /// Adds multiple registry operator filters.
    pub fn with_registry_operators(mut self, operators: Vec<String>) -> Self {
        self.registry_operators = Some(operators);
        self
    }

    /// Adds a name filter.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Query for protocol definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolQuery {
    /// Filter by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Filter by registry operators.
    #[serde(rename = "registryOperators", skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
    /// Filter by protocol ID.
    #[serde(rename = "protocolID", skip_serializing_if = "Option::is_none")]
    pub protocol_id: Option<WalletProtocol>,
}

impl ProtocolQuery {
    /// Creates an empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a name filter.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds a registry operator filter.
    pub fn with_registry_operator(mut self, operator: impl Into<String>) -> Self {
        self.registry_operators = Some(vec![operator.into()]);
        self
    }

    /// Adds multiple registry operator filters.
    pub fn with_registry_operators(mut self, operators: Vec<String>) -> Self {
        self.registry_operators = Some(operators);
        self
    }

    /// Adds a protocol ID filter.
    pub fn with_protocol_id(mut self, protocol_id: WalletProtocol) -> Self {
        self.protocol_id = Some(protocol_id);
        self
    }
}

/// Query for certificate definitions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateQuery {
    /// Filter by certificate type.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub cert_type: Option<String>,
    /// Filter by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Filter by registry operators.
    #[serde(rename = "registryOperators", skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
}

impl CertificateQuery {
    /// Creates an empty query.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a certificate type filter.
    pub fn with_cert_type(mut self, cert_type: impl Into<String>) -> Self {
        self.cert_type = Some(cert_type.into());
        self
    }

    /// Adds a name filter.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Adds a registry operator filter.
    pub fn with_registry_operator(mut self, operator: impl Into<String>) -> Self {
        self.registry_operators = Some(vec![operator.into()]);
        self
    }

    /// Adds multiple registry operator filters.
    pub fn with_registry_operators(mut self, operators: Vec<String>) -> Self {
        self.registry_operators = Some(operators);
        self
    }
}

// =============================================================================
// Result Types
// =============================================================================

/// Result of a register definition operation.
#[derive(Debug, Clone)]
pub struct RegisterDefinitionResult {
    /// Broadcast success information (if successful).
    pub success: Option<BroadcastSuccess>,
    /// Broadcast failure information (if failed).
    pub failure: Option<BroadcastFailure>,
}

impl RegisterDefinitionResult {
    /// Returns true if the registration was successful.
    pub fn is_success(&self) -> bool {
        self.success.is_some()
    }

    /// Returns true if the registration failed.
    pub fn is_failure(&self) -> bool {
        self.failure.is_some()
    }
}

/// Broadcast success information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastSuccess {
    /// Transaction ID.
    pub txid: String,
    /// Message from the broadcaster.
    pub message: String,
}

/// Broadcast failure information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastFailure {
    /// Error code.
    pub code: String,
    /// Error description.
    pub description: String,
}

/// Result of a revoke definition operation.
#[derive(Debug, Clone)]
pub struct RevokeDefinitionResult {
    /// Broadcast success information (if successful).
    pub success: Option<BroadcastSuccess>,
    /// Broadcast failure information (if failed).
    pub failure: Option<BroadcastFailure>,
}

impl RevokeDefinitionResult {
    /// Returns true if the revocation was successful.
    pub fn is_success(&self) -> bool {
        self.success.is_some()
    }

    /// Returns true if the revocation failed.
    pub fn is_failure(&self) -> bool {
        self.failure.is_some()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_definition_type_as_str() {
        assert_eq!(DefinitionType::Basket.as_str(), "basket");
        assert_eq!(DefinitionType::Protocol.as_str(), "protocol");
        assert_eq!(DefinitionType::Certificate.as_str(), "certificate");
    }

    #[test]
    fn test_definition_type_try_from_str() {
        assert_eq!(
            DefinitionType::try_from_str("basket"),
            Some(DefinitionType::Basket)
        );
        assert_eq!(
            DefinitionType::try_from_str("PROTOCOL"),
            Some(DefinitionType::Protocol)
        );
        assert_eq!(
            DefinitionType::try_from_str("Certificate"),
            Some(DefinitionType::Certificate)
        );
        assert_eq!(DefinitionType::try_from_str("invalid"), None);
    }

    #[test]
    fn test_definition_type_from_str() {
        assert_eq!(
            "basket".parse::<DefinitionType>().unwrap(),
            DefinitionType::Basket
        );
        assert_eq!(
            "PROTOCOL".parse::<DefinitionType>().unwrap(),
            DefinitionType::Protocol
        );
        assert!("invalid".parse::<DefinitionType>().is_err());
    }

    #[test]
    fn test_definition_type_display() {
        assert_eq!(format!("{}", DefinitionType::Basket), "basket");
        assert_eq!(format!("{}", DefinitionType::Protocol), "protocol");
        assert_eq!(format!("{}", DefinitionType::Certificate), "certificate");
    }

    #[test]
    fn test_definition_type_lookup_service() {
        assert_eq!(DefinitionType::Basket.lookup_service(), "ls_basketmap");
        assert_eq!(DefinitionType::Protocol.lookup_service(), "ls_protomap");
        assert_eq!(DefinitionType::Certificate.lookup_service(), "ls_certmap");
    }

    #[test]
    fn test_definition_type_broadcast_topic() {
        assert_eq!(DefinitionType::Basket.broadcast_topic(), "tm_basketmap");
        assert_eq!(DefinitionType::Protocol.broadcast_topic(), "tm_protomap");
        assert_eq!(DefinitionType::Certificate.broadcast_topic(), "tm_certmap");
    }

    #[test]
    fn test_definition_type_wallet_basket() {
        assert_eq!(DefinitionType::Basket.wallet_basket(), "basketmap");
        assert_eq!(DefinitionType::Protocol.wallet_basket(), "protomap");
        assert_eq!(DefinitionType::Certificate.wallet_basket(), "certmap");
    }

    #[test]
    fn test_definition_type_wallet_protocol() {
        assert_eq!(DefinitionType::Basket.wallet_protocol(), (1, "basketmap"));
        assert_eq!(DefinitionType::Protocol.wallet_protocol(), (1, "protomap"));
        assert_eq!(
            DefinitionType::Certificate.wallet_protocol(),
            (1, "certmap")
        );
    }

    #[test]
    fn test_definition_type_expected_field_count() {
        assert_eq!(DefinitionType::Basket.expected_field_count(), 6);
        assert_eq!(DefinitionType::Protocol.expected_field_count(), 6);
        assert_eq!(DefinitionType::Certificate.expected_field_count(), 7);
    }

    #[test]
    fn test_token_data_new() {
        let token = TokenData::new("abc123".to_string(), 0, 1000, "76a914...88ac".to_string());
        assert_eq!(token.txid, "abc123");
        assert_eq!(token.output_index, 0);
        assert_eq!(token.satoshis, 1000);
        assert!(token.beef.is_none());
    }

    #[test]
    fn test_token_data_with_beef() {
        let beef = vec![0xbe, 0xef];
        let token = TokenData::with_beef(
            "abc123".to_string(),
            1,
            500,
            "76a914...88ac".to_string(),
            beef,
        );
        assert_eq!(token.txid, "abc123");
        assert_eq!(token.output_index, 1);
        assert!(token.beef.is_some());
    }

    #[test]
    fn test_token_data_outpoint() {
        let token = TokenData::new("abc123".to_string(), 2, 1000, "script".to_string());
        assert_eq!(token.outpoint(), "abc123.2");
    }

    #[test]
    fn test_basket_definition_new() {
        let data = BasketDefinitionData::new("my_basket", "My Basket");
        assert_eq!(data.definition_type, DefinitionType::Basket);
        assert_eq!(data.basket_id, "my_basket");
        assert_eq!(data.name, "My Basket");
        assert_eq!(data.icon_url, "");
        assert_eq!(data.description, "");
        assert_eq!(data.documentation_url, "");
    }

    #[test]
    fn test_basket_definition_builder() {
        let data = BasketDefinitionData::new("my_basket", "My Basket")
            .with_icon_url("https://example.com/icon.png")
            .with_description("A test basket")
            .with_documentation_url("https://example.com/docs");

        assert_eq!(data.icon_url, "https://example.com/icon.png");
        assert_eq!(data.description, "A test basket");
        assert_eq!(data.documentation_url, "https://example.com/docs");
    }

    #[test]
    fn test_basket_definition_serialization() {
        let data = BasketDefinitionData::new("my_basket", "My Basket").with_description("Test");
        let json = serde_json::to_string(&data).unwrap();

        // Check correct JSON field names (not camelCase but specific capitalization)
        assert!(json.contains("\"basketID\":\"my_basket\""));
        assert!(json.contains("\"iconURL\":\"\""));
        assert!(json.contains("\"documentationURL\":\"\""));
        assert!(json.contains("\"definitionType\":\"basket\""));
    }

    #[test]
    fn test_basket_definition_pushdrop_fields() {
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
    fn test_basket_definition_from_pushdrop_fields() {
        let fields = vec![
            b"my_basket".to_vec(),
            b"My Basket".to_vec(),
            b"icon.png".to_vec(),
            b"desc".to_vec(),
            b"docs.html".to_vec(),
            b"02abc123".to_vec(),
        ];

        let data = BasketDefinitionData::from_pushdrop_fields(&fields).unwrap();
        assert_eq!(data.basket_id, "my_basket");
        assert_eq!(data.name, "My Basket");
        assert_eq!(data.icon_url, "icon.png");
        assert_eq!(data.description, "desc");
        assert_eq!(data.documentation_url, "docs.html");
        assert_eq!(data.registry_operator, "02abc123");
    }

    #[test]
    fn test_protocol_definition_new() {
        let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
        let data = ProtocolDefinitionData::new(protocol, "My Protocol");
        assert_eq!(data.definition_type, DefinitionType::Protocol);
        assert_eq!(data.protocol_id.protocol_name, "my_protocol");
        assert_eq!(data.name, "My Protocol");
    }

    #[test]
    fn test_protocol_definition_identifier() {
        let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
        let data = ProtocolDefinitionData::new(protocol, "My Protocol");
        assert_eq!(data.identifier(), "[1, \"my_protocol\"]");
    }

    #[test]
    fn test_protocol_definition_serialization() {
        let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
        let data = ProtocolDefinitionData::new(protocol, "My Protocol");
        let json = serde_json::to_string(&data).unwrap();

        assert!(json.contains("\"protocolID\""));
        assert!(json.contains("\"iconURL\":\"\""));
        assert!(json.contains("\"documentationURL\":\"\""));
        assert!(json.contains("\"definitionType\":\"protocol\""));
    }

    #[test]
    fn test_protocol_definition_pushdrop_fields() {
        let protocol = WalletProtocol::new(SecurityLevel::App, "my_protocol");
        let data = ProtocolDefinitionData::new(protocol, "My Protocol").with_description("desc");

        let fields = data.to_pushdrop_fields("02abc123").unwrap();
        assert_eq!(fields.len(), 6);
        // Field 0 should be JSON serialized protocol
        let protocol_json = String::from_utf8(fields[0].clone()).unwrap();
        assert!(protocol_json.contains("1")); // Security level
        assert!(protocol_json.contains("my_protocol"));
    }

    #[test]
    fn test_deserialize_wallet_protocol() {
        let protocol = deserialize_wallet_protocol("[1,\"my_protocol\"]").unwrap();
        assert_eq!(protocol.security_level, SecurityLevel::App);
        assert_eq!(protocol.protocol_name, "my_protocol");

        let protocol2 = deserialize_wallet_protocol("[0, \"silent_protocol\"]").unwrap();
        assert_eq!(protocol2.security_level, SecurityLevel::Silent);
        assert_eq!(protocol2.protocol_name, "silent_protocol");

        let protocol3 = deserialize_wallet_protocol("[2, \"counterparty_protocol\"]").unwrap();
        assert_eq!(protocol3.security_level, SecurityLevel::Counterparty);
    }

    #[test]
    fn test_deserialize_wallet_protocol_errors() {
        assert!(deserialize_wallet_protocol("invalid").is_err());
        assert!(deserialize_wallet_protocol("[1]").is_err());
        assert!(deserialize_wallet_protocol("[1, 2, 3]").is_err());
        assert!(deserialize_wallet_protocol("[3, \"proto\"]").is_err()); // Invalid security level
        assert!(deserialize_wallet_protocol("[1, 123]").is_err()); // Protocol not a string
    }

    #[test]
    fn test_certificate_field_descriptor() {
        let field = CertificateFieldDescriptor::text("Email")
            .with_description("User email")
            .with_icon("email-icon");

        assert_eq!(field.friendly_name, "Email");
        assert_eq!(field.field_type, "text");
        assert_eq!(field.description, "User email");
        assert_eq!(field.field_icon, "email-icon");
    }

    #[test]
    fn test_certificate_field_descriptor_image_url() {
        let field = CertificateFieldDescriptor::image_url("Avatar");
        assert_eq!(field.field_type, "imageURL");
    }

    #[test]
    fn test_certificate_field_descriptor_serialization() {
        let field = CertificateFieldDescriptor::text("Email").with_description("desc");
        let json = serde_json::to_string(&field).unwrap();

        assert!(json.contains("\"friendlyName\":\"Email\""));
        assert!(json.contains("\"fieldIcon\":\"\""));
    }

    #[test]
    fn test_certificate_definition_new() {
        let data = CertificateDefinitionData::new("cert_type_123", "My Certificate");
        assert_eq!(data.definition_type, DefinitionType::Certificate);
        assert_eq!(data.cert_type, "cert_type_123");
        assert_eq!(data.name, "My Certificate");
        assert!(data.fields.is_empty());
    }

    #[test]
    fn test_certificate_definition_with_fields() {
        let data = CertificateDefinitionData::new("cert_type", "Cert")
            .with_field("email", CertificateFieldDescriptor::text("Email"))
            .with_field("avatar", CertificateFieldDescriptor::image_url("Avatar"));

        assert_eq!(data.fields.len(), 2);
        assert!(data.fields.contains_key("email"));
        assert!(data.fields.contains_key("avatar"));
    }

    #[test]
    fn test_certificate_definition_pushdrop_fields() {
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
    }

    #[test]
    fn test_definition_data_enum() {
        let basket = DefinitionData::Basket(BasketDefinitionData::new("b", "Basket"));
        assert_eq!(basket.get_definition_type(), DefinitionType::Basket);
        assert!(basket.as_basket().is_some());
        assert!(basket.as_protocol().is_none());

        let protocol = DefinitionData::Protocol(ProtocolDefinitionData::new(
            WalletProtocol::new(SecurityLevel::App, "p"),
            "Protocol",
        ));
        assert_eq!(protocol.get_definition_type(), DefinitionType::Protocol);
        assert!(protocol.as_protocol().is_some());
    }

    #[test]
    fn test_definition_data_from() {
        let basket = BasketDefinitionData::new("b", "Basket");
        let data: DefinitionData = basket.into();
        assert_eq!(data.get_definition_type(), DefinitionType::Basket);
    }

    #[test]
    fn test_registry_record() {
        let basket = BasketDefinitionData::new("b", "Basket");
        let token = TokenData::new("txid".to_string(), 0, 1, "script".to_string());
        let record = RegistryRecord::basket(basket, token);

        assert_eq!(record.get_definition_type(), DefinitionType::Basket);
        assert_eq!(record.txid(), "txid");
        assert_eq!(record.output_index(), 0);
        assert_eq!(record.outpoint(), "txid.0");
        assert!(record.as_basket().is_some());
    }

    #[test]
    fn test_basket_query() {
        let query = BasketQuery::new()
            .with_basket_id("my_basket")
            .with_registry_operator("02abc...");

        assert_eq!(query.basket_id, Some("my_basket".to_string()));
        assert_eq!(query.registry_operators, Some(vec!["02abc...".to_string()]));
    }

    #[test]
    fn test_basket_query_serialization() {
        let query = BasketQuery::new().with_basket_id("test");
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("\"basketID\":\"test\""));
    }

    #[test]
    fn test_protocol_query() {
        let protocol = WalletProtocol::new(SecurityLevel::App, "proto");
        let query = ProtocolQuery::new()
            .with_protocol_id(protocol)
            .with_name("Protocol");

        assert!(query.protocol_id.is_some());
        assert_eq!(query.name, Some("Protocol".to_string()));
    }

    #[test]
    fn test_protocol_query_serialization() {
        let query = ProtocolQuery::new().with_name("test");
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("\"name\":\"test\""));
    }

    #[test]
    fn test_certificate_query() {
        let query = CertificateQuery::new()
            .with_cert_type("cert_type")
            .with_registry_operators(vec!["op1".to_string(), "op2".to_string()]);

        assert_eq!(query.cert_type, Some("cert_type".to_string()));
        assert_eq!(
            query.registry_operators,
            Some(vec!["op1".to_string(), "op2".to_string()])
        );
    }

    #[test]
    fn test_certificate_query_serialization() {
        let query = CertificateQuery::new().with_cert_type("test");
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("\"type\":\"test\""));
    }

    #[test]
    fn test_register_definition_result() {
        let success_result = RegisterDefinitionResult {
            success: Some(BroadcastSuccess {
                txid: "abc123".to_string(),
                message: "success".to_string(),
            }),
            failure: None,
        };
        assert!(success_result.is_success());
        assert!(!success_result.is_failure());

        let failure_result = RegisterDefinitionResult {
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
