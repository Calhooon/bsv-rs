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

### KnownCertificateType

Enum representing the 9 known certificate types in the BSV ecosystem:

| Variant | Type ID (Base64) | Description |
|---------|------------------|-------------|
| `IdentiCert` | `AGfk/WrT1...` | Government ID verification |
| `DiscordCert` | `Z5zj/h1ku...` | Discord account verification |
| `PhoneCert` | `J+eCwYf8H...` | Phone number verification |
| `XCert` | `dWKL0K+1a...` | X (Twitter) account verification |
| `Registrant` | `x6nVjVbES...` | Business/entity registration |
| `EmailCert` | `z0Vg9aaQt...` | Email verification |
| `Anyone` | `tMC3u/rLe...` | Public access permission |
| `SelfCert` | `YGS4Nk7Yt...` | Self-issued certificate |
| `CoolCert` | `qxsdbMqLj...` | Demonstration certificate |

```rust
use bsv_sdk::identity::KnownCertificateType;

// Get type ID for a certificate type
let type_id = KnownCertificateType::XCert.type_id();

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

// Create from just an identity key
let identity = DisplayableIdentity::from_key("02abc123...");
```

### Contact

Stored contact with identity information and metadata:

```rust
use bsv_sdk::identity::{Contact, DisplayableIdentity};

let contact = Contact {
    identity_key: "02abc123...".to_string(),
    name: "Alice".to_string(),
    avatar_url: Some("https://example.com/avatar.png".to_string()),
    notes: Some("Met at conference".to_string()),
    tags: vec!["friends".to_string(), "work".to_string()],
    metadata: None,
    created_at: Some(1706400000000),
    updated_at: Some(1706400000000),
};

// Convert between Contact and DisplayableIdentity
let display = contact.to_displayable_identity();
let contact = Contact::from_identity(display);
```

### IdentityQuery

Query parameters for identity resolution:

```rust
use bsv_sdk::identity::IdentityQuery;

// Query by identity key
let query = IdentityQuery::by_identity_key("02abc123...");

// Query by attributes
let query = IdentityQuery::by_attributes(
    [("email".to_string(), "user@example.com".to_string())]
        .into_iter()
        .collect()
);

// Complex query with builder pattern
let query = IdentityQuery::default()
    .with_identity_key("02abc123...")
    .with_certificate_type("dWKL0K+1a...")
    .with_certifier("02cf6cdf...")
    .with_limit(10);
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
let client = IdentityClient::new(wallet, IdentityClientConfig::default());

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

// Simplified version returning just txid
let txid = client.publicly_reveal_attributes_simple(certificate, fields).await?;

// Revoke a previous revelation
client.revoke_certificate_revelation("serial-number-123").await?;
```

### Resolution Methods

```rust
// Resolve by identity key (with contact override)
let identity = client.resolve_by_identity_key("02abc123...", true).await?;
if let Some(id) = identity {
    println!("Found: {} ({})", id.name, id.abbreviated_key);
}

// Resolve by attributes (with contact override)
let mut attrs = HashMap::new();
attrs.insert("email".to_string(), "user@example.com".to_string());
let identities = client.resolve_by_attributes(attrs, true).await?;

// Discover certificates for an identity
let certs = client.discover_certificates("02abc123...").await?;

// Discover specific certificate type
let x_certs = client.discover_certificates_by_type(
    "02abc123...",
    KnownCertificateType::XCert.type_id()
).await?;

// Complex query
let query = IdentityQuery::default()
    .with_identity_key("02abc123...")
    .with_limit(10);
let results = client.query(query).await?;
```

### Contact Management

```rust
// Get all contacts
let contacts = client.get_contacts(false).await?;

// Get specific contact
if let Some(contact) = client.get_contact("02abc123...").await? {
    println!("Contact: {}", contact.name);
}

// Save a contact
let identity = DisplayableIdentity::from_key("02abc123...");
client.save_contact(identity, None).await?;

// Remove a contact
client.remove_contact("02abc123...").await?;
```

## ContactsManager

Direct contact management with search and filtering:

```rust
use bsv_sdk::identity::{ContactsManager, ContactsManagerConfig, Contact};

let config = ContactsManagerConfig {
    originator: Some("myapp.example.com".to_string()),
    ..Default::default()
};
let manager = ContactsManager::new(wallet, config);

// CRUD operations
manager.add_contact(contact).await?;
let contact = manager.get_contact("02abc123...").await?;
manager.update_contact(contact).await?;
manager.remove_contact("02abc123...").await?;

// List and search
let all = manager.list_contacts().await?;
let results = manager.search_contacts("alice").await?;
let tagged = manager.get_contacts_by_tag("friends").await?;

// Cache management
manager.invalidate_cache().await;
let refreshed = manager.list_contacts_with_refresh(true).await?;
```

## Configuration Types

### IdentityClientConfig

```rust
pub struct IdentityClientConfig {
    /// Application originator string for authentication
    pub originator: Option<String>,
    /// Network preset (mainnet/testnet)
    pub network_preset: NetworkPreset,
    /// Token amount for overlay operations
    pub token_amount: u64,
}
```

### ContactsManagerConfig

```rust
pub struct ContactsManagerConfig {
    /// Application originator string
    pub originator: Option<String>,
    /// Protocol for contacts storage basket
    pub protocol: String,
    /// Basket ID for contacts
    pub basket: String,
}
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_SOCIALCERT_CERTIFIER` | `02cf6cdf...` | Default trusted certifier for social certificates |
| `IDENTITY_SERVICE` | `"ls_identity"` | Overlay lookup service name |
| `IDENTITY_TOPIC` | `"tm_identity"` | Overlay topic for identity broadcasts |

## Error Handling

The module uses three error variants from `crate::Error`:

```rust
// General identity error
Error::IdentityError(String)

// Identity not found
Error::IdentityNotFound(String)

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

## Cross-SDK Compatibility

This module is designed for compatibility with:
- [TypeScript SDK identity module](https://github.com/bitcoin-sv/ts-sdk/tree/master/src/identity)
- [Go SDK identity module](https://github.com/bitcoin-sv/go-sdk/tree/master/identity)

Key compatibility points:
- Same certificate type IDs (base64-encoded 32-byte hashes)
- Same default certifier public key
- Same overlay service/topic names
- Compatible JSON serialization format

## Related Documentation

- `../auth/CLAUDE.md` - Authentication module with certificate types
- `../overlay/CLAUDE.md` - Overlay network module for resolution queries
- `../wallet/CLAUDE.md` - Wallet module for key operations
- `../../CLAUDE.md` - Project root documentation
