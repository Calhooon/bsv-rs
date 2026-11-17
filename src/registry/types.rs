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

crate::util::non_exhaustive::non_exhaustive_enum! {
    path = bsv_rs::registry::DefinitionType;
/// Type of registry definition.
///
/// Determines which registry service and topic are used for registration
/// and resolution of definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DefinitionType {
    /// Basket definition (output categorization).
    Basket,
    /// Protocol definition (application protocol registration).
    Protocol,
    /// Certificate type definition (identity certificate schema).
    Certificate,
}
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

    /// The PushDrop script's field count, the operator's signature last
    /// (`registryTokenValidation.ts:13-17,29`; 6/6/7 before #543).
    pub fn expected_field_count(&self) -> usize {
        match self {
            Self::Basket => 7, // basketID, name, iconURL, description, documentationURL, registryOperator, signature
            Self::Protocol => 7, // protocolID(JSON), name, iconURL, description, documentationURL, registryOperator, signature
            Self::Certificate => 8, // type, name, iconURL, description, documentationURL, fields(JSON), registryOperator, signature
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
        // JSON.stringify(data.protocolID), `[1,"name"]` (RegistryClient.ts:697; #543)
        let protocol = &self.protocol_id;
        let protocol_json =
            serde_json::json!([protocol.security_level as u8, protocol.protocol_name]).to_string();

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

crate::util::non_exhaustive::non_exhaustive_enum! {
    path = bsv_rs::registry::DefinitionData;
/// Union type for all definition data types.
///
/// This enum allows treating all definition types uniformly in the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum DefinitionData {
    /// Basket definition.
    Basket(BasketDefinitionData),
    /// Protocol definition.
    Protocol(ProtocolDefinitionData),
    /// Certificate definition.
    Certificate(CertificateDefinitionData),
}
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

/// Result of an update definition operation.
///
/// Updates an existing registry entry by spending its UTXO and creating
/// a new one with updated data in a single transaction.
#[derive(Debug, Clone)]
pub struct UpdateDefinitionResult {
    /// Broadcast success information (if successful).
    pub success: Option<BroadcastSuccess>,
    /// Broadcast failure information (if failed).
    pub failure: Option<BroadcastFailure>,
}

impl UpdateDefinitionResult {
    /// Returns true if the update was successful.
    pub fn is_success(&self) -> bool {
        self.success.is_some()
    }

    /// Returns true if the update failed.
    pub fn is_failure(&self) -> bool {
        self.failure.is_some()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
