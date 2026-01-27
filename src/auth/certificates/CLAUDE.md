# BSV Certificates Module
> BRC-52/53 identity certificates with selective attribute disclosure

## Overview

This module implements identity certificates for the BSV authentication system, enabling selective disclosure of encrypted attributes. Certificates bind identity attributes to public keys, signed by trusted certifiers. The three-tier certificate structure (base, master, verifiable) allows subjects to control exactly which fields are revealed to each verifier.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, re-exports, protocol constants | ~43 |
| `certificate.rs` | Base `Certificate` type with signing and binary serialization | ~490 |
| `master.rs` | `MasterCertificate` with field encryption and keyring management | ~322 |
| `verifiable.rs` | `VerifiableCertificate` with verifier-specific keyring | ~274 |

## Certificate Flow

The module implements a three-stage certificate lifecycle:

1. **Issuance**: Certifier creates a `MasterCertificate` for the subject
   - Fields are encrypted from certifier to subject using BRC-42
   - Master keyring stores encryption keys for all fields
   - Certificate is signed by the certifier

2. **Storage**: Subject stores the `MasterCertificate`
   - Can decrypt all fields using the master keyring
   - Retains full control over the certificate

3. **Proving**: Subject creates a `VerifiableCertificate` for a verifier
   - Creates verifier-specific keyring for selected fields only
   - Verifier can only decrypt fields in their keyring
   - Enables selective disclosure without revealing all attributes

## Key Exports

### Types

**Certificate** - Base certificate structure (BRC-52):
```rust
pub struct Certificate {
    pub cert_type: [u8; 32],           // Certificate schema identifier
    pub serial_number: [u8; 32],       // Unique certificate ID
    pub subject: PublicKey,            // Subject's identity key
    pub certifier: PublicKey,          // Certifier's public key
    pub revocation_outpoint: Option<Outpoint>,  // On-chain revocation
    pub fields: HashMap<String, Vec<u8>>,       // Encrypted field values
    pub signature: Option<Vec<u8>>,    // DER-encoded signature
}
```

**MasterCertificate** - Certificate with master keyring:
```rust
pub struct MasterCertificate {
    pub certificate: Certificate,
    pub master_keyring: HashMap<String, Vec<u8>>,  // field -> encrypted key
}
```

**VerifiableCertificate** - Certificate with verifier-specific keyring:
```rust
pub struct VerifiableCertificate {
    pub certificate: Certificate,
    pub keyring: HashMap<String, Vec<u8>>,  // field -> encrypted key for verifier
}
```

### Protocol Constants

```rust
pub const CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL: &str = "certificate field encryption";
pub const CERTIFICATE_SIGNATURE_PROTOCOL: &str = "certificate signature";
```

## Field Encryption

Fields are encrypted using BRC-42 key derivation with Security Level 2 (counterparty-specific):

**Master Certificate Key IDs:**
- Protocol: `"certificate field encryption"`
- Key ID: `"{field_name}"`
- Encrypts from certifier to subject

**Verifiable Certificate Key IDs:**
- Protocol: `"certificate field encryption"`
- Key ID: `"{serial_number_base64} {field_name}"`
- Re-encrypts from subject to verifier

## Key Methods

### Certificate

| Method | Purpose |
|--------|---------|
| `new()` | Create unsigned certificate with type, serial, subject, certifier |
| `sign()` | Sign with certifier's private key |
| `verify()` | Verify certificate signature |
| `to_binary()` | Serialize to deterministic binary format |
| `from_binary()` | Parse from binary format |
| `signing_hash()` | Get SHA-256 hash for signing |
| `get_field_encryption_key_id_master()` | Key ID for master encryption |
| `get_field_encryption_key_id_verifiable()` | Key ID for verifiable encryption |
| `to_wallet_certificate()` | Convert to wallet certificate format |

### MasterCertificate

| Method | Purpose |
|--------|---------|
| `new()` | Create from base certificate and keyring |
| `issue_for_subject()` | Issue new certificate (async) |
| `create_certificate_fields()` | Encrypt fields and create keyring (async) |
| `create_keyring_for_verifier()` | Create verifier-specific keyring (async) |
| `decrypt_field()` | Decrypt single field (async) |
| `decrypt_fields()` | Decrypt all fields (async) |

### VerifiableCertificate

| Method | Purpose |
|--------|---------|
| `new()` | Create from base certificate and keyring |
| `from_certificate()` | Create with empty keyring |
| `has_keyring()` | Check if keyring has any keys |
| `revealable_fields()` | List fields that can be decrypted |
| `decrypt_field()` | Decrypt single field (async) |
| `decrypt_fields()` | Decrypt all fields in keyring (async, cached) |
| `to_json_value()` | Convert to JSON with base64 encoding |

## Binary Format

The `Certificate::to_binary()` method produces a deterministic binary representation:

```
[cert_type: 32 bytes]
[serial_number: 32 bytes]
[subject_pubkey: 33 bytes compressed]
[certifier_pubkey: 33 bytes compressed]
[has_outpoint: 1 byte] [outpoint: 36 bytes if present]
[field_count: varint]
[for each field (sorted by name):
    [name_len: varint][name: bytes]
    [value_len: varint][value: bytes]
]
[signature_len: varint][signature: bytes if included]
```

Fields are sorted alphabetically by name for deterministic serialization across implementations.

## Usage Examples

### Issuing a Certificate

```rust
use bsv_sdk::auth::certificates::MasterCertificate;

// Certifier issues certificate to subject
let master_cert = MasterCertificate::issue_for_subject(
    &certifier_wallet,
    &certifier_private_key,
    subject_public_key,
    HashMap::from([
        ("name".to_string(), "Alice".to_string()),
        ("email".to_string(), "alice@example.com".to_string()),
    ]),
    cert_type,
    None,  // Generate random serial
    "app_originator",
).await?;
```

### Creating a Verifiable Certificate

```rust
use bsv_sdk::auth::certificates::{MasterCertificate, VerifiableCertificate};

// Subject creates keyring for verifier, revealing only "name"
let keyring = MasterCertificate::create_keyring_for_verifier(
    &subject_wallet,
    &certifier_public_key,
    &verifier_public_key,
    &["name".to_string()],  // Only reveal name, not email
    &master_cert.certificate.fields,
    &master_cert.certificate.serial_number,
    "app_originator",
).await?;

let verifiable = VerifiableCertificate::new(
    master_cert.certificate.clone(),
    keyring,
);
```

### Verifying and Decrypting

```rust
// Verifier receives certificate and decrypts revealed fields
assert!(verifiable_cert.verify()?);

let decrypted = verifiable_cert.decrypt_fields(
    &verifier_wallet,
    &subject_public_key,
    "app_originator",
).await?;

// Only "name" is available, "email" was not revealed
assert!(decrypted.contains_key("name"));
assert!(!decrypted.contains_key("email"));
```

## Deref Behavior

Both `MasterCertificate` and `VerifiableCertificate` implement `Deref<Target = Certificate>`, allowing direct access to base certificate fields:

```rust
let master_cert: MasterCertificate = /* ... */;

// Access Certificate fields directly
let subject = &master_cert.subject;
let cert_type = &master_cert.cert_type;
```

## Serialization

All certificate types support JSON serialization via serde:
- `cert_type` and `serial_number` are base64-encoded
- `fields` values are base64-encoded
- `signature` is base64-encoded when present
- Uses camelCase field naming

## Related Documentation

- `src/auth/CLAUDE.md` - Parent auth module
- `src/wallet/CLAUDE.md` - Wallet module (WalletInterface, encryption)
- `src/primitives/ec/CLAUDE.md` - Cryptographic primitives (PublicKey, PrivateKey, Signature)
