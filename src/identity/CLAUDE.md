# Identity Module
> Certificate-based identity resolution and contact management for the BSV ecosystem

## Overview

The identity module provides certificate-based identity discovery and management for BSV applications. It enables users to:

- **Resolve identities** by public key or attribute values (email, phone, etc.)
- **Discover certificates** associated with an identity
- **Parse certificates** into user-friendly display formats
- **Manage contacts** with encrypted local storage
- **Reveal attributes** publicly on the overlay network
- **Revoke revelations** by spending identity tokens

This module integrates with the `auth` module for certificate handling and the `overlay` module for network communication.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root with re-exports (112 lines) |
| `types.rs` | Core types: KnownCertificateType, DisplayableIdentity, Contact, configs (886 lines) |
| `client.rs` | IdentityClient for identity resolution, revelation, and management |
| `client_field_value_261_tests.rs` | The intake witnesses of #261 (`#[cfg(test)]`, included from `client.rs`): the reference-issued certificate of `tests/vectors/certificate_field_value_261.json`, published for anyone as the reference publishes it, parses, verifies and decrypts through both parsers; one output with a malformed signature among good ones is skipped and the resolution goes on (`IdentityClient.ts:823-825`); and #268's: a certificate signed over `<txid>.0`, published with its outpoint as the txid alone (the reference's default form), parses through both parsers to index 0 and verifies |
| `reveal.rs` | The checks `publicly_reveal_attributes` makes around its wallet calls (#307), the reference's in its order and words (`ts-stack@edf6e03` `IdentityClient.ts:420-499`): a field named `__proto__`, `constructor` or `prototype`, no fields, no names, more than 100, a name over 50 bytes or with a display control, empty or unsafe, repeated or absent from the certificate, then the master certificate's signature (read from the wallet certificate's JSON, `Certificate::verify`), all before any wallet call; after `proveCertificate`, a keyring carrying an unsafe name (`proof result keyringForVerifier contains an unsafe field`), then one naming other fields than those asked, then each value as `validateBase64String(.., 1, 2048)` reads it (trimmed as JavaScript trims, base64 by shape, 1 to 2048 bytes), the trimmed values judged and published in the wallet's key order (`:485`, #385). `IdentityError` in each case but the value's, `WalletRefusal` of the `InvalidParameter` class in `WERR_INVALID_PARAMETER`'s words; pinned by `tests/identity_reveal_verifies_307.rs`. Then `identity_token` (#310): the reference's `PushDrop.lock([json], protocolID, keyID, 'anyone', true, true)` (`IdentityClient.ts:502-509`, `PushDrop.ts:146-202`), getPublicKey for anyone with `for_self: true`, createSignature over the JSON for anyone, the JSON `{...certificate, keyring}` in `WalletCertificate`'s member order, the fields in the order held, the keyring in the wallet's (#385): the reference's bytes for its certificate and keyring, admitted by the overlay's identity reader; pinned by `tests/identity_reveal_rest_310.rs`. The createAction after it (in `client.rs`, #315) sends the reference's arguments alone (`IdentityClient.ts:513-528`): the description, one output of satoshis, locking script and output description, `randomizeOutputs: false`; no label, tag, `signAndProcess` or `acceptDelayedBroadcast`, left to the wallet; pinned by `tests/identity_reveal_create_action_315.rs`. The revocation (`revoke.rs` since #327) sends the reference's createAction (`IdentityClient.ts:845-863`: the description, `inputBEEF`, one input of description, outpoint and `unlockingScriptLength: 74`, `randomizeOutputs: false`, `acceptDelayedBroadcast: false`, `noSend: true`; no label, no `signAndProcess`) and signAction (`:896-911`: the reference as createAction answered it, its base64 text, and `returnTXIDOnly: false`), and every wallet call of the client carries the configured originator or none (`""`, `IdentityClient::originator`; the reference's `:369-377`); pinned by `tests/identity_wallet_calls_318.rs` |
| `revoke.rs` | `revoke_certificate_revelation`, the reference's `revokeCertificateRevelation` step by step in its words (#327; `ts-stack@edf6e03` `IdentityClient.ts:705-950`): the serial number as base64 of 32 bytes (`reveal::base64_parameter`, `WERR_INVALID_PARAMETER`), getPublicKey for the identity key and the token's key, the `ls_identity` answer (`Failed to get lookup result`; at most 10000 outputs and 16 MiB of BEEF), each output authenticated or skipped (the BEEF's subject, the output at the lookup's index, the canonical signed PushDrop locked to the token's key, the JSON's serial number and subject, `Certificate::verify` of its seven members, verifySignature over the token), none: `No authenticated revelation output matches the requested certificate.`; every authenticated output spent at its own index (the signable transaction's one matching input, `revelationInputOutpoint`), the signed transaction checked against the signable one (`assertRevelationTransactionTemplate`, the input, its script, the txid), broadcast on `tm_identity` (`IdentityClient::with_broadcast_facilitator` the seam), abortAction with the reference on any failure after createAction, the spend under `double_spend.rs`; pinned by `tests/identity_revocation_checks_327.rs` |
| `double_spend.rs` | The reference's `withDoubleSpendRetry` (#327; `overlay-tools/withDoubleSpendRetry.ts:8-165`): an attempt failing with `Error::WalletReviewActions` (which `HttpWalletJson` reads from a wallet's code-5 body since #339; the binary wire carries the class alone) carrying double-spend evidence (each `doubleSpend` result's 1 to 256 distinct txids and 1 byte to 64 MiB of BEEF; 256 results, 64 MiB and 256 txids in all) repeated after each competing transaction is read by txid and acknowledged by the broadcaster, five attempts in all; any other error, malformed evidence or a failed acknowledgement ends it. Not `overlay::with_double_spend_retry`, which matches words and synchronizes nothing |
| `token_maps.rs` | An identity token's `fields` and `keyring` read in the order of its JSON text (#394), where the `serde_json::Value` the parsers read the rest from sorts its keys: a member not an object empty, a value not a string skipped, as the `Value` reading did; both parsers (`parse_output_to_certificate`, `parse_output_to_verifiable_certificate`) take their maps from it |
| `contacts.rs` | ContactsManager for encrypted contact storage with caching (1267 lines); its update and removal send signAction the reference as the wallet answered it, its base64 text, and no options, as the reference's (`ts-stack@edf6e03` `ContactsManager.ts:813-834`, `:981-1001`; #326, where they sent the hex of its bytes with `acceptDelayedBroadcast: false`; `tests/contacts_signaction_326.rs`) |

## Feature Flag

```toml
[features]
identity = ["auth", "overlay"]
```

The identity feature depends on both `auth` (for certificate types) and `overlay` (for network communication); `indexmap` reaches it through `wallet` (#385), so it needs nothing of its own for its ordered maps (#394).

## Public Exports

```rust
// From mod.rs re-exports
pub use client::IdentityClient;
pub use contacts::ContactsManager;
pub use types::{
    // Type aliases
    Base64String,
    CertificateFieldNameUnder50Bytes,
    OriginatorDomainNameStringUnder250Bytes,
    PubKeyHex,
    // Broadcast types
    BroadcastFailure,
    BroadcastResult,
    BroadcastSuccess,
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
    StaticAvatarUrls,
    // Constants
    DEFAULT_SOCIALCERT_CERTIFIER,
};
```

## Key Types

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
use bsv_rs::identity::KnownCertificateType;

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
use bsv_rs::identity::DisplayableIdentity;

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
use bsv_rs::identity::{Contact, DisplayableIdentity};

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
use bsv_rs::identity::IdentityQuery;
use indexmap::IndexMap; // insertion order, the reference's `Record` (#394)

// Query by identity key
let query = IdentityQuery::by_identity_key("02abc123...");

// Query by single attribute
let query = IdentityQuery::by_attribute("email", "user@example.com");

// Query by multiple attributes
let mut attrs = IndexMap::new();
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
    pub publicly_revealed_keyring: IndexMap<String, String>, // base64 text (#268); the token's order (#394)
    pub decrypted_fields: IndexMap<String, String>,          // the keyring's order (#394)
}

// Access methods
let type_id = cert.type_base64();
let subject = cert.subject_hex();
let certifier = cert.certifier_hex();
let known_type = cert.known_type(); // Option<KnownCertificateType>
```

**Reading a published certificate** (#261): the parsers read the JSON the
reference's `publiclyRevealAttributes` publishes (`{...certificate, keyring}`,
`ts-stack@edf6e03` `IdentityClient.ts:503`). Each field is held as its base64
text, never decoded, as BRC-52 signs it (`brcs@5119a9b`
`peer-to-peer/0052.md:41,97`); the signature is hex, as the reference's
`WalletCertificate.signature` and this crate's `publicly_reveal_attributes`
write it, and one that is not skips its output, never the resolution
(`IdentityClient.ts:823-825`); the keyring's values are held as their base64
text (#268), decoded only where the anyone wallet decrypts; a `revocationOutpoint`
of the txid alone, the reference's default issuance's, reads as index 0
(`revocation_outpoint_from_str`, #268). `decrypted_fields` comes from
`VerifiableCertificate::decrypt_fields` with `ProtoWallet::anyone()`: each
field's text is decoded and decrypted there and nowhere earlier.

### CertifierInfo

Information about a certificate certifier:

```rust
pub struct CertifierInfo {
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub trust: u8,  // Trust level 0-10
}
```

## IdentityClient

Main client for identity operations. Generic over wallet implementation:

```rust
use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::PrivateKey;

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

// Create with custom resolver
let client = IdentityClient::with_resolver(wallet, config, custom_resolver);
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
// A certificate whose signature does not verify, or a name it does not
// carry, is refused before the wallet is called (`reveal.rs`, #307)
// The token is the subject's signed PushDrop, the reference's bytes; a
// createAction with no transaction is `Err(IdentityError("Public reveal
// failed: failed to create action!"))`, a refused broadcast a `Failure` (#310)

// Simplified version returning just txid
let txid = client.publicly_reveal_attributes_simple(certificate, fields).await?;

// Revoke a previous revelation by spending the identity token: the lookup's
// outputs authenticated, each matching one spent at its index, the action
// aborted on a failure, a double spend retried (`revoke.rs`, #327)
client.revoke_certificate_revelation(serial_number_base64).await?;
```

### Resolution Methods

```rust
// Resolve by identity key (second param enables contact override)
let identity = client.resolve_by_identity_key("02abc123...", true).await?;
if let Some(id) = identity {
    println!("Found: {} ({})", id.name, id.abbreviated_key);
}

// Resolve by attributes (second param enables contact override); the
// lookup body keeps the attributes' insertion order (#394)
let mut attrs = IndexMap::new();
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
    println!("{}: {} certs", result.identity.name, result.certificates.len());
}
```

### Contact Management via Client

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

Direct contact management with encrypted storage, search, and caching:

```rust
use bsv_rs::identity::{ContactsManager, ContactsManagerConfig, Contact};

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

### Storage Model

Contacts are stored as encrypted PushDrop tokens in the wallet's basket system:
- Each contact is encrypted with a per-contact key
- Tagged with HMAC-hashed identity key for privacy-preserving lookup
- Stored in the "contacts" basket
- Custom instructions store the key ID for decryption

## Configuration Types

### IdentityClientConfig

```rust
pub struct IdentityClientConfig {
    pub network_preset: NetworkPreset,  // Mainnet or Testnet
    pub protocol_id: (u8, String),      // Default: (1, "identity")
    pub key_id: String,                 // Default: "1"
    pub token_amount: u64,              // Satoshis for revelation outputs (default: 1)
    pub output_index: u32,              // Output index for identity token (default: 0)
    pub originator: Option<String>,     // Application originator; None: none to the wallet (#318, #329)
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
    pub originator: Option<String>, // Application originator; None: none to the wallet (#329)
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

| Constant | Value |
|----------|-------|
| `DEFAULT_SOCIALCERT_CERTIFIER` | `02cf6cdf466951d8dfc9e7c9367511d0007ed6fba35ed42d425cc412fd6cfd4a17` |

### StaticAvatarUrls

UHRP hashes for certificate type avatars:

```rust
use bsv_rs::identity::StaticAvatarUrls;

StaticAvatarUrls::EMAIL;   // Envelope icon
StaticAvatarUrls::PHONE;   // Phone icon
StaticAvatarUrls::ANYONE;  // Anyone certificate avatar
StaticAvatarUrls::SELF;    // Self certificate avatar
```

### DefaultIdentityValues

Constants for unverified/unknown identities:

```rust
use bsv_rs::identity::DefaultIdentityValues;

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

## Overlay Network Integration

The identity module uses the overlay network for discovery and broadcast:

| Service | Purpose |
|---------|---------|
| `ls_identity` | Lookup service for identity queries |
| `tm_identity` | Topic for broadcasting identity revelations |

Queries are performed via `LookupResolver`, broadcasts via `TopicBroadcaster`.

## Wire Format Compatibility

JSON serialization uses camelCase field names for cross-SDK compatibility:

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

This module maintains API compatibility with:
- [TypeScript SDK identity](https://github.com/bitcoin-sv/ts-sdk) - `IdentityClient`, `ContactsManager`
- [Go SDK identity](https://github.com/bitcoin-sv/go-sdk) - `identity.Client`

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
