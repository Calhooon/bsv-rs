# BSV Certificates Module
> BRC-52/53 identity certificates with selective attribute disclosure

## Overview

This module implements identity certificates for the BSV authentication system, enabling selective disclosure of encrypted attributes. Certificates bind identity attributes to public keys, signed by trusted certifiers. The three-tier certificate structure (base, master, verifiable) allows subjects to control exactly which fields are revealed to each verifier.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root, re-exports, protocol constants | ~43 |
| `certificate.rs` | Base `Certificate` type with signing and binary serialization | ~786 |
| `collation.rs` | The reference's field-name order: `localeCompare` under ICU root for U+0000..U+00FF (#249); the table parsed at compile time from `collation_latin1.txt` | ~308 |
| `collation_latin1.txt` | The DUCET 13.0.0 rows of U+0000..U+00FF and the two `l·` contractions, ranked; written by `tests/support/certificate_collation_table_249.mjs`, never edited by hand (#249) | 264 |
| `master.rs` | `MasterCertificate` with field encryption and keyring management | ~336 |
| `verifiable.rs` | `VerifiableCertificate` with verifier-specific keyring | ~287 |

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

**Certificate** - Base certificate structure (BRC-52), `#[non_exhaustive]` since #249 (build with `new()` and the `with_*` methods):
```rust
pub struct Certificate {
    pub cert_type: [u8; 32],           // Certificate schema identifier
    pub serial_number: [u8; 32],       // Unique certificate ID
    pub subject: PublicKey,            // Subject's identity key
    pub certifier: PublicKey,          // Certifier's public key
    pub revocation_outpoint: Option<Outpoint>,  // On-chain revocation
    pub fields: HashMap<String, Vec<u8>>,       // Encrypted field values
    pub signature: Option<Vec<u8>>,    // DER-encoded signature
    #[serde(skip)]
    pub received_unsigned: Option<Vec<u8>>,  // the unsigned prefix as read or signed (#249)
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
| `with_revocation_outpoint()`, `with_fields()`, `with_signature()` | Chain onto `new()` for the fields a struct literal set (#249) |
| `set_revocation_outpoint()`, `set_fields()`, `set_signature()` | Change one after construction; the two that change the preimage clear `received_unsigned` (#249) |
| `sign()` | Sign with the certifier's BRC-52 child key: protocol `[2, "certificate signature"]`, keyID `signature_key_id()`, counterparty anyone (#251) |
| `verify()` | Verify against the certifier's public child (derived with the anyone key); a raw-key signature is `Ok(false)` (#251); over `received_unsigned` while it binds (#249) |
| `signature_key_id()` | `"<type base64> <serial base64>"`, one space (BRC-52 `0052.md:116`) |
| `to_binary()` | Serialize: `received_unsigned` while it parses to the current values, else the reference's field order (#249) |
| `from_binary()` | Parse, keeping the unsigned prefix in `received_unsigned`; a repeated field name refused (#249) |
| `signing_hash()` | Get SHA-256 hash for signing |
| `type_base64()` | Get certificate type as base64 string |
| `serial_number_base64()` | Get serial number as base64 string |
| `set_field()` | Set an encrypted field value; clears `received_unsigned` |
| `get_field()` | Get an encrypted field value |
| `field_names()` | Get all field names |
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
| `verify()` | Verify underlying certificate signature |

### VerifiableCertificate

| Method | Purpose |
|--------|---------|
| `new()` | Create from base certificate and keyring |
| `from_certificate()` | Create with empty keyring |
| `has_keyring()` | Check if keyring has any keys |
| `revealable_fields()` | List fields that can be decrypted |
| `decrypt_field()` | Decrypt single field (async) |
| `decrypt_fields()` | Decrypt all fields in keyring (async, cached) |
| `get_decrypted_fields()` | Get cached decrypted fields if available |
| `clear_decrypted_cache()` | Clear the cached decrypted fields |
| `verify()` | Verify underlying certificate signature |
| `subject()` | Get subject's public key |
| `certifier()` | Get certifier's public key |
| `cert_type()` | Get certificate type |
| `serial_number()` | Get serial number |
| `to_json_value()` | Convert to JSON with base64 encoding |

## Binary Format

The `Certificate::to_binary()` method produces a deterministic binary representation compatible with the TypeScript SDK:

```
[cert_type: 32 bytes]
[serial_number: 32 bytes]
[subject_pubkey: 33 bytes compressed]
[certifier_pubkey: 33 bytes compressed]
[revocation_txid: 32 bytes]     # All zeros if no outpoint
[revocation_index: varint]       # 0 if no outpoint
[field_count: varint]
[for each field (the reference's order, or as received):
    [name_len: varint][name: bytes]
    [value_len: varint][value: bytes]
]
[signature: raw DER bytes if included and present]  # No length prefix
```

**Notes:**
- Revocation outpoint uses a sentinel value: all-zeros TXID with index 0 means "no outpoint"
- Signature is appended as raw bytes without length prefix (matches TypeScript SDK)
- Fields are written in the reference's order, `a.localeCompare(b)` under Node's default ICU collation (`ts-stack@edf6e03` `Certificate.ts:282`), not by bytes: `a_b, a0, age, éa, f, Name` (`collation.rs`, U+0000..U+00FF; above that, code point order after the table, the residual). Go sorts by bytes (`go-sdk@2ca481c` `wallet/serializer/certificate.go:48`)
- A certificate read by `from_binary` (or signed by `sign`) keeps its unsigned prefix in `received_unsigned`; `verify`, `signing_hash` and `to_binary` use those bytes while they parse to the current values, so the issuer's order is kept (BRC-52 `0052.md:103`; #249). A value changed afterwards unbinds them

## Usage Examples

### Issuing a Certificate

```rust
use bsv_rs::auth::certificates::MasterCertificate;

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
use bsv_rs::auth::certificates::{MasterCertificate, VerifiableCertificate};

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

## Deref and Trait Implementations

Both `MasterCertificate` and `VerifiableCertificate` implement `Deref<Target = Certificate>`, allowing direct access to base certificate fields. `MasterCertificate` also implements `DerefMut` for mutable access.

```rust
let master_cert: MasterCertificate = /* ... */;

// Access Certificate fields directly via Deref
let subject = &master_cert.subject;
let cert_type = &master_cert.cert_type;
```

`VerifiableCertificate` additionally implements `From<Certificate>` for easy conversion:

```rust
let cert: Certificate = /* ... */;
let verifiable: VerifiableCertificate = cert.into();
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
