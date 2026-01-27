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
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Result<Vec<Vec<u8>>>
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
    pub fn to_pushdrop_fields(&self, registry_operator: &str) -> Result<Vec<Vec<u8>>>
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
```

### CertificateFieldDescriptor

Schema descriptor for certificate fields:

```rust
pub struct CertificateFieldDescriptor {
    #[serde(rename = "friendlyName")]
    pub friendly_name: String,       // User-friendly name
    pub description: String,         // Field description (empty if not set)
    #[serde(rename = "fieldType")]
    pub field_type: String,          // "text", "imageURL", "other"
    #[serde(rename = "fieldIcon")]
    pub field_icon: String,          // Icon identifier (empty if not set)
}

impl CertificateFieldDescriptor {
    pub fn text(friendly_name: impl Into<String>) -> Self
    pub fn image_url(friendly_name: impl Into<String>) -> Self
    pub fn new(friendly_name: impl Into<String>, field_type: impl Into<String>) -> Self
    pub fn with_description(self, desc: impl Into<String>) -> Self
    pub fn with_icon(self, icon: impl Into<String>) -> Self
}
```

### Result Types (Go SDK Compatible)

```rust
/// Result of a register definition operation.
pub struct RegisterDefinitionResult {
    pub success: Option<BroadcastSuccess>,
    pub failure: Option<BroadcastFailure>,
}

impl RegisterDefinitionResult {
    pub fn is_success(&self) -> bool
    pub fn is_failure(&self) -> bool
}

/// Result of a revoke definition operation.
pub struct RevokeDefinitionResult {
    pub success: Option<BroadcastSuccess>,
    pub failure: Option<BroadcastFailure>,
}

impl RevokeDefinitionResult {
    pub fn is_success(&self) -> bool
    pub fn is_failure(&self) -> bool
}

/// Result of an update definition operation.
pub struct UpdateDefinitionResult {
    pub success: Option<BroadcastSuccess>,
    pub failure: Option<BroadcastFailure>,
}

impl UpdateDefinitionResult {
    pub fn is_success(&self) -> bool
    pub fn is_failure(&self) -> bool
}

/// Broadcast success information (matches Go SDK transaction.BroadcastSuccess).
pub struct BroadcastSuccess {
    pub txid: String,    // Transaction ID
    pub message: String, // Success message
}

/// Broadcast failure information (matches Go SDK transaction.BroadcastFailure).
pub struct BroadcastFailure {
    pub code: String,        // Error code
    pub description: String, // Error description
}
```

### TokenData

On-chain UTXO reference:

```rust
pub struct TokenData {
    pub txid: String,            // Transaction ID (hex)
    pub output_index: u32,       // Output index
    pub satoshis: u64,           // UTXO value
    pub locking_script: String,  // Locking script (hex)
    pub beef: Option<Vec<u8>>,   // BEEF data for SPV
}
```

### RegistryRecord

Combined definition and token:

```rust
pub enum RegistryRecord {
    Basket { definition: BasketDefinitionData, token: TokenData },
    Protocol { definition: ProtocolDefinitionData, token: TokenData },
    Certificate { definition: CertificateDefinitionData, token: TokenData },
}

impl RegistryRecord {
    pub fn token(&self) -> &TokenData
    pub fn definition_type(&self) -> DefinitionType
    pub fn registry_operator(&self) -> &str
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
}
```

### Key API Differences from Previous Implementation

| Previous API | Go SDK Compatible API |
|-------------|----------------------|
| `register_basket(data)` | `register_definition(data.into())` |
| `register_protocol(data)` | `register_definition(data.into())` |
| `register_certificate(data)` | `register_definition(data.into())` |
| `list_own_entries()` | `list_own_registry_entries(definition_type)` |
| `revoke_entry(txid, output_index)` | `revoke_own_registry_entry(&record)` |
| (not available) | `update_definition(&record, new_data)` |

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

### Register a Basket (Go SDK Compatible)

```rust
use bsv_sdk::registry::{RegistryClient, RegistryClientConfig, BasketDefinitionData, DefinitionData};
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::primitives::PrivateKey;

let wallet = ProtoWallet::new(Some(PrivateKey::random()));
let client = RegistryClient::new(wallet, RegistryClientConfig::default());

let data = BasketDefinitionData::new("my_basket", "My Custom Basket")
    .with_description("A basket for organizing my outputs")
    .with_icon_url("https://example.com/icon.png");

// Use register_definition with .into() conversion
let result = client.register_definition(data.into()).await?;
if result.is_success() {
    println!("Registered: {}", result.success.unwrap().txid);
}
```

### Register a Protocol

```rust
use bsv_sdk::registry::{RegistryClient, ProtocolDefinitionData};
use bsv_sdk::wallet::{Protocol, SecurityLevel};

let protocol = Protocol::new(SecurityLevel::App, "my_protocol");
let data = ProtocolDefinitionData::new(protocol, "My Protocol")
    .with_description("A custom protocol for my application");

let result = client.register_definition(data.into()).await?;
```

### List Own Registry Entries (Go SDK Compatible)

```rust
use bsv_sdk::registry::{RegistryClient, DefinitionType};

// List only basket entries (takes definition_type parameter)
let basket_entries = client.list_own_registry_entries(DefinitionType::Basket).await?;

for entry in basket_entries {
    println!("{}: {} at {}",
        entry.definition_type(),
        entry.identifier(),
        entry.outpoint()
    );
}
```

### Revoke an Entry (Go SDK Compatible)

```rust
// Takes a RegistryRecord, not (txid, output_index)
let entries = client.list_own_registry_entries(DefinitionType::Basket).await?;
if let Some(entry) = entries.first() {
    let result = client.revoke_own_registry_entry(entry).await?;
    if result.is_success() {
        println!("Entry revoked");
    }
}
```

### Update an Entry (TypeScript SDK Compatible)

```rust
use bsv_sdk::registry::{RegistryClient, DefinitionType, BasketDefinitionData};

// Get existing entry
let entries = client.list_own_registry_entries(DefinitionType::Basket).await?;
if let Some(entry) = entries.first() {
    // Create updated data (must be same type as original)
    let updated_data = BasketDefinitionData::new("my_basket", "Updated Basket Name")
        .with_description("New description for my basket")
        .with_icon_url("https://example.com/new-icon.png");

    // Update the entry
    let result = client.update_definition(entry, updated_data.into()).await?;
    if result.is_success() {
        println!("Entry updated: {}", result.success.unwrap().txid);
    }
}
```

## PushDrop Token Format

Registry entries use PushDrop tokens with individual fields (not JSON blobs):

### Basket (6 fields)
| Index | Field | Description |
|-------|-------|-------------|
| 0 | basketID | Unique identifier |
| 1 | name | Human-readable name |
| 2 | iconURL | Icon URL |
| 3 | description | Description |
| 4 | documentationURL | Documentation URL |
| 5 | registryOperator | Public key hex of owner |

### Protocol (6 fields)
| Index | Field | Description |
|-------|-------|-------------|
| 0 | protocolID | JSON: `[securityLevel, "protocolName"]` |
| 1 | name | Human-readable name |
| 2 | iconURL | Icon URL |
| 3 | description | Description |
| 4 | documentationURL | Documentation URL |
| 5 | registryOperator | Public key hex of owner |

### Certificate (7 fields)
| Index | Field | Description |
|-------|-------|-------------|
| 0 | type | Certificate type identifier |
| 1 | name | Human-readable name |
| 2 | iconURL | Icon URL |
| 3 | description | Description |
| 4 | documentationURL | Documentation URL |
| 5 | fields | JSON map of field descriptors |
| 6 | registryOperator | Public key hex of owner |

## JSON Serialization

All types use **exact Go SDK field names** (not generic camelCase):

```json
{
  "definitionType": "basket",
  "basketID": "my_basket",
  "name": "My Basket",
  "iconURL": "https://...",
  "description": "...",
  "documentationURL": "...",
  "registryOperator": "02abc..."
}
```

**Note**: Field names use specific capitalization:
- `basketID` (not `basketId`)
- `iconURL` (not `iconUrl`)
- `documentationURL` (not `documentationUrl`)
- `protocolID` (not `protocolId`)
- `definitionType`
- `registryOperator`

## Overlay Integration

### Lookup Services

| Definition Type | Service |
|-----------------|---------|
| Basket | `ls_basketmap` |
| Protocol | `ls_protomap` |
| Certificate | `ls_certmap` |

### Broadcast Topics

| Definition Type | Topic |
|-----------------|-------|
| Basket | `tm_basketmap` |
| Protocol | `tm_protomap` |
| Certificate | `tm_certmap` |

## Error Types

| Error | Description |
|-------|-------------|
| `RegistryError(String)` | General registry operation error |
| `InvalidDefinitionData(String)` | Invalid or malformed definition data |

## Cross-SDK Compatibility

This module maintains **1:1 API compatibility** with:
- [Go SDK](https://github.com/bitcoin-sv/go-sdk) - `registry` package
- [TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `registry` module

### Type Mapping

| Go SDK | Rust SDK |
|--------|----------|
| `DefinitionType` | `DefinitionType` |
| `DefinitionData` (interface) | `DefinitionData` (enum) |
| `BasketDefinitionData` | `BasketDefinitionData` |
| `ProtocolDefinitionData` | `ProtocolDefinitionData` |
| `CertificateDefinitionData` | `CertificateDefinitionData` |
| `CertificateFieldDescriptor` | `CertificateFieldDescriptor` |
| `TokenData` | `TokenData` |
| `RegistryRecord` | `RegistryRecord` |
| `RegisterDefinitionResult` | `RegisterDefinitionResult` |
| `RevokeDefinitionResult` | `RevokeDefinitionResult` |
| (TypeScript: BroadcastResponse) | `UpdateDefinitionResult` |
| `transaction.BroadcastSuccess` | `BroadcastSuccess` |
| `transaction.BroadcastFailure` | `BroadcastFailure` |

### Method Mapping

| Go SDK Method | Rust SDK Method |
|---------------|-----------------|
| `RegisterDefinition(ctx, data)` | `register_definition(data)` |
| `ResolveBasket(ctx, query)` | `resolve_basket(query)` |
| `ResolveProtocol(ctx, query)` | `resolve_protocol(query)` |
| `ResolveCertificate(ctx, query)` | `resolve_certificate(query)` |
| `ListOwnRegistryEntries(ctx, defType)` | `list_own_registry_entries(def_type)` |
| `RevokeOwnRegistryEntry(ctx, record)` | `revoke_own_registry_entry(record)` |
| (TypeScript: updateDefinition) | `update_definition(record, data)` |

## Feature Flag

This module requires the `registry` feature:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["registry"] }

# Or with all features
bsv-sdk = { version = "0.2", features = ["full"] }
```

The `registry` feature automatically enables the `overlay` feature.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `REGISTRANT_TOKEN_AMOUNT` | 1 | Satoshi value for registry tokens |
| `REGISTRANT_KEY_ID` | "1" | PushDrop key derivation ID |
| `BASKETMAP_PROTOCOL` | (1, "basketmap") | Wallet protocol for baskets |
| `PROTOMAP_PROTOCOL` | (1, "protomap") | Wallet protocol for protocols |
| `CERTMAP_PROTOCOL` | (1, "certmap") | Wallet protocol for certificates |

## Related Documentation

- `../overlay/CLAUDE.md` - Overlay module (lookup, broadcasting)
- `../wallet/CLAUDE.md` - Wallet module (WalletInterface)
- `../script/templates/CLAUDE.md` - PushDrop template
- `../CLAUDE.md` - Root SDK documentation
