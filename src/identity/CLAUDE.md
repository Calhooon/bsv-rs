# Identity Module
> Certificate-based identity resolution and contact management for the BSV ecosystem

## Overview

The identity module provides certificate-based identity discovery and management for BSV applications. It enables users to:

- **Resolve identities** by public key or attribute values (email, phone, etc.)
- **Discover certificates** associated with an identity
- **Parse certificates** into user-friendly display formats
- **Manage contacts** with encrypted local storage
- **Reveal attributes** publicly on the overlay network

This module integrates with the `auth` module for certificate handling and the `overlay` module for network communication.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root with re-exports |
| `types.rs` | Core types: KnownCertificateType, DisplayableIdentity, Contact, configs |
| `client.rs` | IdentityClient for identity resolution and management |
| `contacts.rs` | ContactsManager for encrypted contact storage |

## Feature Flag

```toml
[features]
identity = ["auth", "overlay"]
```

The identity feature depends on both `auth` (for certificate types) and `overlay` (for network communication).

## Key Types

### Type Aliases

```rust
/// Certificate field name with constraint of under 50 bytes.
pub type CertificateFieldNameUnder50Bytes = String;

/// Originator domain name string with constraint of under 250 bytes.
pub type OriginatorDomainNameStringUnder250Bytes = String;

/// Public key in hex format (compressed, 33 bytes = 66 hex chars).
pub type PubKeyHex = String;

/// Base64-encoded string.
pub type Base64String = String;
```

### KnownCertificateType

Enum representing the 9 known certificate types in the BSV ecosystem:

| Variant | Type ID (Base64) | Key Fields |
|---------|------------------|------------|
| `IdentiCert` | `z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=` | firstName, lastName, profilePhoto |
| `DiscordCert` | `2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=` | userName, profilePhoto |
| `PhoneCert` | `mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=` | phoneNumber |
| `XCert` | `vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=` | userName, profilePhoto |
| `Registrant` | `YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=` | name, icon |
| `EmailCert` | `exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=` | email |
| `Anyone` | `mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=` | (none) |
| `SelfCert` | `Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=` | (none) |
| `CoolCert` | `AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=` | cool (boolean) |

```rust
use bsv_sdk::identity::KnownCertificateType;

// Get type ID for a certificate type
let type_id = KnownCertificateType::XCert.type_id();

// Get human-readable name
let name = KnownCertificateType::XCert.name(); // "XCert"

// Parse type ID back to enum
let cert_type = KnownCertificateType::from_type_id(type_id);

// Get all known types
let all_types = KnownCertificateType::all();
```

### DisplayableIdentity

User-friendly representation of an identity for UI display:

```rust
use bsv_sdk::identity::DisplayableIdentity;

let identity = DisplayableIdentity {
    name: "Alice".to_string(),
    avatar_url: "https://example.com/avatar.png".to_string(),
    identity_key: "02abc123...".to_string(),
    abbreviated_key: "02abc1...23".to_string(),
    badge_icon_url: "https://socialcert.net/icon.png".to_string(),
    badge_label: "X account certified by SocialCert".to_string(),
    badge_click_url: "https://socialcert.net".to_string(),
};

// Create from just an identity key (uses default values)
let identity = DisplayableIdentity::from_key("02abc123...");

// Create unknown/default identity
let unknown = DisplayableIdentity::unknown();
```

### Contact

Stored contact with identity information and metadata:

```rust
use bsv_sdk::identity::{Contact, DisplayableIdentity};

let contact = Contact {
    identity_key: "02abc123...".to_string(),
    name: "Alice".to_string(),
    avatar_url: Some("https://example.com/avatar.png".to_string()),
    added_at: 1706400000000,  // Unix timestamp in milliseconds
    notes: Some("Met at conference".to_string()),
    tags: vec!["friends".to_string(), "work".to_string()],
    metadata: None,
};

// Convert between Contact and DisplayableIdentity
let display = contact.to_displayable_identity();
let contact = Contact::from_identity(display);
```

### IdentityQuery

Query parameters for identity resolution with builder pattern:

```rust
use bsv_sdk::identity::IdentityQuery;
use std::collections::HashMap;

// Query by identity key
let query = IdentityQuery::by_identity_key("02abc123...");

// Query by single attribute
let query = IdentityQuery::by_attribute("email", "user@example.com");

// Query by multiple attributes
let mut attrs = HashMap::new();
attrs.insert("email".to_string(), "user@example.com".to_string());
let query = IdentityQuery::by_attributes(attrs);

// Builder pattern for complex queries
let query = IdentityQuery::by_attribute("email", "user@example.com")
    .with_certifier("02cf6cdf...")
    .with_limit(10)
    .with_offset(5);
```

### IdentityCertificate

Enriched certificate with decrypted fields and certifier information:

```rust
pub struct IdentityCertificate {
    pub certificate: VerifiableCertificate,
    pub certifier_info: CertifierInfo,
    pub publicly_revealed_keyring: HashMap<String, Vec<u8>>,
    pub decrypted_fields: HashMap<String, String>,
}

// Access methods
let type_id = cert.type_base64();
let subject = cert.subject_hex();
let certifier = cert.certifier_hex();
let known_type = cert.known_type(); // Option<KnownCertificateType>
```

### CertifierInfo

Information about a certificate certifier:

```rust
pub struct CertifierInfo {
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub trust: u8,  // Trust level 1-10
}
```

## IdentityClient

Main client for identity operations:

```rust
use bsv_sdk::identity::{IdentityClient, IdentityClientConfig};
use bsv_sdk::wallet::ProtoWallet;
use bsv_sdk::PrivateKey;

// Create a wallet
let private_key = PrivateKey::random();
let wallet = ProtoWallet::new(Some(private_key));

// Create client with default config
let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());

// Create client with custom config
let config = IdentityClientConfig::with_originator("myapp.example.com")
    .with_network(NetworkPreset::Mainnet)
    .with_token_amount(5);
let client = IdentityClient::new(wallet, config);
```

### Public Revelation Methods

```rust
// Publicly reveal certificate attributes
let result = client.publicly_reveal_attributes(
    certificate,
    vec!["userName".to_string(), "profilePhoto".to_string()]
).await?;

match result {
    BroadcastResult::Success(s) => println!("TXID: {}", s.txid),
    BroadcastResult::Failure(f) => println!("Failed: {}", f.description),
}

// Simplified version returning just txid
let txid = client.publicly_reveal_attributes_simple(certificate, fields).await?;

// Revoke a previous revelation
client.revoke_certificate_revelation("serial-number-123").await?;
```

### Resolution Methods

```rust
// Resolve by identity key (second param enables contact override)
let identity = client.resolve_by_identity_key("02abc123...", true).await?;
if let Some(id) = identity {
    println!("Found: {} ({})", id.name, id.abbreviated_key);
}

// Resolve by attributes (second param enables contact override)
let mut attrs = HashMap::new();
attrs.insert("email".to_string(), "user@example.com".to_string());
let identities = client.resolve_by_attributes(attrs, true).await?;

// Discover all certificates for an identity
let certs = client.discover_certificates("02abc123...").await?;

// Discover specific certificate type
let x_certs = client.discover_certificates_by_type(
    "02abc123...",
    KnownCertificateType::XCert.type_id()
).await?;

// Complex query returning IdentityResolutionResult
let query = IdentityQuery::by_identity_key("02abc123...").with_limit(10);
let results = client.query(query).await?;
for result in results {
    println!("{}: {} certificates", result.identity.name, result.certificates.len());
}
```

### Contact Management

```rust
// Get all contacts (pass true to force refresh from storage)
let contacts = client.get_contacts(false).await?;

// Get specific contact
if let Some(contact) = client.get_contact("02abc123...").await? {
    println!("Contact: {}", contact.name);
}

// Save a contact (with optional metadata)
let identity = DisplayableIdentity::from_key("02abc123...");
client.save_contact(identity, Some(serde_json::json!({"source": "import"}))).await?;

// Remove a contact
client.remove_contact("02abc123...").await?;
```

### Utility Methods

```rust
// Get the wallet's identity key
let my_key = client.get_identity_key().await?;

// Parse an identity certificate into displayable format (static method)
let displayable = IdentityClient::<ProtoWallet>::parse_identity(&cert);
```

## ContactsManager

Direct contact management with search, filtering, and caching:

```rust
use bsv_sdk::identity::{ContactsManager, ContactsManagerConfig, Contact};

let config = ContactsManagerConfig::with_originator("myapp.example.com");
let manager = ContactsManager::new(wallet, config);

// CRUD operations
manager.add_contact(contact).await?;
let contact = manager.get_contact("02abc123...").await?;
manager.update_contact("02abc123...", updated_contact).await?;
manager.remove_contact("02abc123...").await?;

// List and search
let all = manager.list_contacts().await?;
let refreshed = manager.list_contacts_with_refresh(true).await?;
let results = manager.search_contacts("alice").await?;  // Searches name, tags, notes
let tagged = manager.get_contacts_by_tag("friends").await?;

// Cache management
manager.clear_cache().await;
let is_init = manager.is_cache_initialized().await;
let count = manager.cached_count().await;
```

## Configuration Types

### IdentityClientConfig

```rust
pub struct IdentityClientConfig {
    pub network_preset: NetworkPreset,  // Mainnet or Testnet
    pub protocol_id: (u8, String),      // Default: (1, "identity")
    pub key_id: String,                 // Default: "1"
    pub token_amount: u64,              // Satoshis for revelation outputs
    pub output_index: u32,              // Output index for identity token
    pub originator: Option<String>,     // Application originator for audit trails
}

// Builder methods
let config = IdentityClientConfig::with_originator("myapp.com")
    .with_network(NetworkPreset::Testnet)
    .with_token_amount(100);
```

### ContactsManagerConfig

```rust
pub struct ContactsManagerConfig {
    pub protocol_id: (u8, String),  // Default: (2, "contact")
    pub basket: String,             // Default: "contacts"
    pub originator: Option<String>, // Application originator
}

let config = ContactsManagerConfig::with_originator("myapp.com");
```

## Broadcast Result Types

```rust
pub enum BroadcastResult {
    Success(BroadcastSuccess),
    Failure(BroadcastFailure),
}

pub struct BroadcastSuccess {
    pub txid: String,
    pub message: Option<String>,
}

pub struct BroadcastFailure {
    pub code: String,
    pub description: String,
}

// Helper methods
result.is_success();
result.txid();  // Option<&str>
result.into_result();  // Result<BroadcastSuccess, BroadcastFailure>
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_SOCIALCERT_CERTIFIER` | `02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17` | Default trusted certifier |

### Static Avatar URLs

```rust
use bsv_sdk::identity::StaticAvatarUrls;

StaticAvatarUrls::EMAIL;   // Email certificate avatar (envelope icon)
StaticAvatarUrls::PHONE;   // Phone certificate avatar (phone icon)
StaticAvatarUrls::ANYONE;  // Anyone certificate avatar
StaticAvatarUrls::SELF;    // Self certificate avatar
```

### Default Identity Values

```rust
use bsv_sdk::identity::DefaultIdentityValues;

DefaultIdentityValues::NAME;           // "Unknown Identity"
DefaultIdentityValues::AVATAR_URL;     // UHRP hash for default avatar
DefaultIdentityValues::BADGE_ICON_URL; // UHRP hash for default badge icon
DefaultIdentityValues::BADGE_LABEL;    // "Not verified by anyone you trust."
DefaultIdentityValues::BADGE_CLICK_URL; // Documentation link
```

## Error Handling

The module uses error variants from `crate::Error`:

```rust
// General identity error
Error::IdentityError(String)

// Contact not found
Error::ContactNotFound(String)
```

## Wire Format Compatibility

The identity module uses JSON serialization with camelCase field names for wire compatibility:

```rust
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayableIdentity {
    pub name: String,
    pub avatar_url: String,      // serializes as "avatarUrl"
    pub identity_key: String,    // serializes as "identityKey"
    // ...
}
```

## Overlay Network Integration

The identity module uses the overlay network for:
- **ls_identity** - Lookup service for identity queries
- **tm_identity** - Topic for broadcasting identity revelations

Queries are performed via the `LookupResolver` from the overlay module.

## Cross-SDK Compatibility

This module is designed for compatibility with:
- [TypeScript SDK identity module](https://github.com/bitcoin-sv/ts-sdk/tree/master/src/identity)
- [Go SDK identity module](https://github.com/bitcoin-sv/go-sdk/tree/master/identity)

Key compatibility points:
- Same certificate type IDs (base64-encoded SHA-256 hashes)
- Same default certifier public key
- Same overlay service/topic names
- Compatible JSON serialization format with camelCase

## Related Documentation

- `../auth/CLAUDE.md` - Authentication module with certificate types
- `../overlay/CLAUDE.md` - Overlay network module for resolution queries
- `../wallet/CLAUDE.md` - Wallet module for key operations
- `../../CLAUDE.md` - Project root documentation
