# BSV Registry Module
> On-chain protocol and certificate type registration for BSV

## Overview

The registry module provides client-side support for managing on-chain definitions of baskets, protocols, and certificate types. It uses the overlay network for discovery (SLAP) and broadcasting (SHIP) of registry entries.

Registry entries are stored as PushDrop tokens on-chain, allowing decentralized discovery and verification of definitions without requiring a centralized database.

**Cross-SDK Compatibility**: This module is 1:1 API compatible with the Go SDK `registry` package.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports and constants |
| `types.rs` | Definition types, queries, tokens, result types |
| `client.rs` | RegistryClient implementation |

## Key Exports

```rust
// Definition types
pub use types::{
    DefinitionType,              // Basket, Protocol, Certificate
    DefinitionData,              // Enum wrapping all definition types (Go SDK compatible)
    BasketDefinitionData,        // Basket definition
    ProtocolDefinitionData,      // Protocol definition
    CertificateDefinitionData,   // Certificate type definition
    CertificateFieldDescriptor,  // Certificate field schema
    TokenData,                   // On-chain UTXO reference
    RegistryRecord,              // Definition + token combined
};

// Result types (matching Go SDK transaction types)
pub use types::{
    RegisterDefinitionResult,    // Result from register_definition()
    RevokeDefinitionResult,      // Result from revoke_own_registry_entry()
    UpdateDefinitionResult,      // Result from update_definition()
    BroadcastSuccess,            // Success info with txid and message
    BroadcastFailure,            // Failure info with code and description
};

// Query types
pub use types::{
    BasketQuery,                 // Basket lookup filters
    ProtocolQuery,               // Protocol lookup filters
    CertificateQuery,            // Certificate lookup filters
};

// Client
pub use client::{
    RegistryClient,              // Main client for registry operations
    RegistryClientConfig,        // Client configuration
};

// Constants
pub const LS_BASKETMAP: &str = "ls_basketmap";   // Basket lookup service
pub const LS_PROTOMAP: &str = "ls_protomap";     // Protocol lookup service
pub const LS_CERTMAP: &str = "ls_certmap";       // Certificate lookup service
pub const TM_BASKETMAP: &str = "tm_basketmap";   // Basket broadcast topic
pub const TM_PROTOMAP: &str = "tm_protomap";     // Protocol broadcast topic
pub const TM_CERTMAP: &str = "tm_certmap";       // Certificate broadcast topic
pub const REGISTRANT_TOKEN_AMOUNT: u64 = 1;      // Token satoshi value
pub const REGISTRANT_KEY_ID: &str = "1";         // PushDrop key ID
```

## Core Types

### DefinitionType

Enumeration of registry definition types:

```rust
pub enum DefinitionType {
    Basket,      // Output categorization
    Protocol,    // Application protocol
    Certificate, // Identity certificate type
}

impl DefinitionType {
    pub fn as_str(&self) -> &'static str
    pub fn try_from_str(s: &str) -> Option<Self>
    pub fn lookup_service(&self) -> &'static str    // ls_basketmap, etc.
    pub fn broadcast_topic(&self) -> &'static str   // tm_basketmap, etc.
    pub fn wallet_basket(&self) -> &'static str     // basketmap, etc.
    pub fn wallet_protocol(&self) -> (u8, &'static str)
    pub fn expected_field_count(&self) -> usize     // 6 for basket/protocol, 7 for cert
}

// Also implements Display and FromStr traits
impl std::fmt::Display for DefinitionType { ... }
impl std::str::FromStr for DefinitionType { ... }  // Returns crate::Error on failure
```

### DefinitionData (Go SDK Compatible)

Enum wrapping all definition types - used as parameter to `register_definition()`:

```rust
pub enum DefinitionData {
    Basket(BasketDefinitionData),
    Protocol(ProtocolDefinitionData),
    Certificate(CertificateDefinitionData),
}

impl DefinitionData {
    pub fn get_definition_type(&self) -> DefinitionType
    pub fn get_registry_operator(&self) -> &str
    pub fn set_registry_operator(&mut self, operator: String)
    pub fn identifier(&self) -> String
    pub fn name(&self) -> &str
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Result<Vec<Vec<u8>>>
    pub fn as_basket(&self) -> Option<&BasketDefinitionData>
    pub fn as_protocol(&self) -> Option<&ProtocolDefinitionData>
    pub fn as_certificate(&self) -> Option<&CertificateDefinitionData>
}

// From implementations for easy conversion
impl From<BasketDefinitionData> for DefinitionData
impl From<ProtocolDefinitionData> for DefinitionData
impl From<CertificateDefinitionData> for DefinitionData
```

### BasketDefinitionData

Definition data for output baskets. **Fields are `String` not `Option<String>`** (empty string = not set):

```rust
pub struct BasketDefinitionData {
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,  // Always Basket
    #[serde(rename = "basketID")]
    pub basket_id: String,           // Unique identifier (e.g., "my_basket")
    pub name: String,                // Human-readable name
    #[serde(rename = "iconURL")]
    pub icon_url: String,            // Icon URL (empty string if not set)
    pub description: String,         // Description (empty string if not set)
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,   // Documentation URL (empty string if not set)
    #[serde(rename = "registryOperator")]
    pub registry_operator: String,   // Operator pubkey (auto-set)
}

impl BasketDefinitionData {
    pub fn new(basket_id: impl Into<String>, name: impl Into<String>) -> Self
    pub fn with_icon_url(self, url: impl Into<String>) -> Self
    pub fn with_description(self, desc: impl Into<String>) -> Self
    pub fn with_documentation_url(self, url: impl Into<String>) -> Self
    pub fn identifier(&self) -> &str  // Returns basket_id
    pub fn get_definition_type(&self) -> DefinitionType
    pub fn get_registry_operator(&self) -> &str
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Vec<Vec<u8>>
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> Result<Self>
}
```

### ProtocolDefinitionData

Definition data for wallet protocols:

```rust
pub struct ProtocolDefinitionData {
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,  // Always Protocol
    #[serde(rename = "protocolID")]
    pub protocol_id: WalletProtocol, // Security level + protocol name
    pub name: String,                // Human-readable name
    #[serde(rename = "iconURL")]
    pub icon_url: String,
    pub description: String,
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,
    #[serde(rename = "registryOperator")]
    pub registry_operator: String,   // Operator pubkey (auto-set)
}

impl ProtocolDefinitionData {
    pub fn new(protocol_id: WalletProtocol, name: impl Into<String>) -> Self
    pub fn with_icon_url(self, url: impl Into<String>) -> Self
    pub fn with_description(self, desc: impl Into<String>) -> Self
    pub fn with_documentation_url(self, url: impl Into<String>) -> Self
    pub fn identifier(&self) -> String  // "[secLevel, \"protocolName\"]"
    pub fn get_definition_type(&self) -> DefinitionType
    pub fn get_registry_operator(&self) -> &str
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Result<Vec<Vec<u8>>>
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> Result<Self>
}
```

### CertificateDefinitionData

Definition data for certificate types:

```rust
pub struct CertificateDefinitionData {
    #[serde(rename = "definitionType")]
    pub definition_type: DefinitionType,  // Always Certificate
    #[serde(rename = "type")]
    pub cert_type: String,           // Base64 of 32-byte type ID
    pub name: String,                // Human-readable name
    #[serde(rename = "iconURL")]
    pub icon_url: String,
    pub description: String,
    #[serde(rename = "documentationURL")]
    pub documentation_url: String,
    pub fields: HashMap<String, CertificateFieldDescriptor>,
    #[serde(rename = "registryOperator")]
    pub registry_operator: String,   // Operator pubkey (auto-set)
}

impl CertificateDefinitionData {
    pub fn new(cert_type: impl Into<String>, name: impl Into<String>) -> Self
    pub fn with_icon_url(self, url: impl Into<String>) -> Self
    pub fn with_description(self, desc: impl Into<String>) -> Self
    pub fn with_documentation_url(self, url: impl Into<String>) -> Self
    pub fn with_field(self, name: impl Into<String>, descriptor: CertificateFieldDescriptor) -> Self
    pub fn identifier(&self) -> &str  // Returns cert_type
    pub fn get_definition_type(&self) -> DefinitionType
    pub fn get_registry_operator(&self) -> &str
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Result<Vec<Vec<u8>>>
    pub fn from_pushdrop_fields(fields: &[Vec<u8>]) -> Result<Self>
}
```

### CertificateFieldDescriptor

Schema descriptor for certificate fields with `friendly_name`, `description`, `field_type` ("text", "imageURL", "other"), and `field_icon`. Builder methods: `text()`, `image_url()`, `new()`, `with_description()`, `with_icon()`.

### Result Types

All operation results (`RegisterDefinitionResult`, `RevokeDefinitionResult`, `UpdateDefinitionResult`) share the same structure:

```rust
pub struct RegisterDefinitionResult {
    pub success: Option<BroadcastSuccess>,  // txid, message
    pub failure: Option<BroadcastFailure>,  // code, description
}

impl RegisterDefinitionResult {
    pub fn is_success(&self) -> bool
    pub fn is_failure(&self) -> bool
}
```

### TokenData

On-chain UTXO reference with `txid`, `output_index`, `satoshis`, `locking_script`, and optional `beef` for SPV. Constructors: `new()`, `with_beef()`. Method: `outpoint()` returns "txid.outputIndex".

### RegistryRecord

Combined definition and token:

```rust
pub struct RegistryRecord {
    #[serde(flatten)]
    pub definition: DefinitionData,
    #[serde(flatten)]
    pub token: TokenData,
}

impl RegistryRecord {
    pub fn new(definition: DefinitionData, token: TokenData) -> Self
    pub fn basket(definition: BasketDefinitionData, token: TokenData) -> Self
    pub fn protocol(definition: ProtocolDefinitionData, token: TokenData) -> Self
    pub fn certificate(definition: CertificateDefinitionData, token: TokenData) -> Self
    pub fn token(&self) -> &TokenData
    pub fn get_definition_type(&self) -> DefinitionType
    pub fn get_registry_operator(&self) -> &str
    pub fn identifier(&self) -> String
    pub fn txid(&self) -> &str
    pub fn output_index(&self) -> u32
    pub fn outpoint(&self) -> String

    // Type-specific accessors
    pub fn as_basket(&self) -> Option<&BasketDefinitionData>
    pub fn as_protocol(&self) -> Option<&ProtocolDefinitionData>
    pub fn as_certificate(&self) -> Option<&CertificateDefinitionData>
}
```

## RegistryClient (Go SDK Compatible API)

Main client for registry operations. **Method signatures match the Go SDK exactly**:

```rust
pub struct RegistryClient<W: WalletInterface> {
    wallet: W,
    config: RegistryClientConfig,
    resolver: Arc<LookupResolver>,
}

impl<W: WalletInterface> RegistryClient<W> {
    // Construction
    pub fn new(wallet: W, config: RegistryClientConfig) -> Self

    // Single registration method (Go SDK: RegisterDefinition)
    pub async fn register_definition(&self, data: DefinitionData) -> Result<RegisterDefinitionResult>

    // Resolution methods (typed returns)
    pub async fn resolve_basket(&self, query: BasketQuery) -> Result<Vec<BasketDefinitionData>>
    pub async fn resolve_protocol(&self, query: ProtocolQuery) -> Result<Vec<ProtocolDefinitionData>>
    pub async fn resolve_certificate(&self, query: CertificateQuery) -> Result<Vec<CertificateDefinitionData>>

    // Management methods (Go SDK compatible signatures)
    pub async fn list_own_registry_entries(&self, definition_type: DefinitionType) -> Result<Vec<RegistryRecord>>
    pub async fn revoke_own_registry_entry(&self, record: &RegistryRecord) -> Result<RevokeDefinitionResult>

    // Update method (TypeScript SDK compatible)
    pub async fn update_definition(&self, record: &RegistryRecord, updated_data: DefinitionData) -> Result<UpdateDefinitionResult>

    // Network configuration
    pub fn set_network(&mut self, network: NetworkPreset)
}
```

### RegistryClientConfig

```rust
pub struct RegistryClientConfig {
    pub network_preset: NetworkPreset,    // Mainnet, Testnet, Local
    pub resolver: Option<Arc<LookupResolver>>,
    pub originator: Option<String>,
    pub accept_delayed_broadcast: bool,
}

impl RegistryClientConfig {
    pub fn new() -> Self
    pub fn with_network(self, preset: NetworkPreset) -> Self
    pub fn with_resolver(self, resolver: Arc<LookupResolver>) -> Self
    pub fn with_originator(self, originator: impl Into<String>) -> Self
    pub fn with_delayed_broadcast(self, accept: bool) -> Self
}
```

## Usage Examples

### Register a Definition

```rust
use bsv_rs::registry::{RegistryClient, RegistryClientConfig, BasketDefinitionData};
use bsv_rs::wallet::ProtoWallet;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let client = RegistryClient::new(wallet, RegistryClientConfig::default());

// Register basket (use .into() to convert to DefinitionData)
let data = BasketDefinitionData::new("my_basket", "My Basket")
    .with_description("Basket description");
let result = client.register_definition(data.into()).await?;

// Register protocol
let protocol = Protocol::new(SecurityLevel::App, "my_protocol");
let data = ProtocolDefinitionData::new(protocol, "My Protocol");
let result = client.register_definition(data.into()).await?;
```

### List, Revoke, and Update Entries

```rust
// List entries by type
let entries = client.list_own_registry_entries(DefinitionType::Basket).await?;

// Revoke an entry
if let Some(entry) = entries.first() {
    client.revoke_own_registry_entry(entry).await?;
}

// Update an entry
if let Some(entry) = entries.first() {
    let updated = BasketDefinitionData::new("my_basket", "New Name");
    client.update_definition(entry, updated.into()).await?;
}
```

## PushDrop Token Format

Registry entries use PushDrop tokens with individual fields (not JSON blobs):

- **Basket (6 fields)**: basketID, name, iconURL, description, documentationURL, registryOperator
- **Protocol (6 fields)**: protocolID (JSON: `[level, "name"]`), name, iconURL, description, documentationURL, registryOperator
- **Certificate (7 fields)**: type, name, iconURL, description, documentationURL, fields (JSON), registryOperator

## JSON Serialization

All types use **exact Go SDK field names** with specific capitalization: `basketID`, `iconURL`, `documentationURL`, `protocolID`, `definitionType`, `registryOperator` (not generic camelCase like `basketId`).

## Overlay Integration

- **Lookup Services**: `ls_basketmap`, `ls_protomap`, `ls_certmap`
- **Broadcast Topics**: `tm_basketmap`, `tm_protomap`, `tm_certmap`

## Error Types

| Error | Description |
|-------|-------------|
| `RegistryError(String)` | General registry operation error |
| `InvalidDefinitionData(String)` | Invalid or malformed definition data |

## Cross-SDK Compatibility

This module maintains **1:1 API compatibility** with the Go SDK `registry` package and TypeScript SDK `registry` module. Type and method names map directly between SDKs.

## Feature Flag

This module requires the `registry` feature:

```toml
[dependencies]
bsv-rs = { version = "0.3", features = ["registry"] }

# Or with all features
bsv-rs = { version = "0.3", features = ["full"] }
```

The `registry` feature automatically enables the `overlay` feature.

## Constants

`REGISTRANT_TOKEN_AMOUNT = 1` (satoshi value), `REGISTRANT_KEY_ID = "1"`, and wallet protocols: `BASKETMAP_PROTOCOL`, `PROTOMAP_PROTOCOL`, `CERTMAP_PROTOCOL` (all security level 1).

## Related Documentation

- `../overlay/CLAUDE.md` - Overlay module (lookup, broadcasting)
- `../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../script/templates/CLAUDE.md` - PushDrop template
- `../CLAUDE.md` - Root SDK documentation
