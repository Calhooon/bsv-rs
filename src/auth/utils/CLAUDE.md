# Auth Utilities
> Nonce creation/verification and certificate validation for BRC-31 authentication

## Overview

This submodule provides utility functions supporting the BRC-31 (Authrite) authentication protocol. It handles two critical aspects:

1. **Nonce Management**: Cryptographic nonce creation and verification to prevent replay attacks
2. **Certificate Validation**: Validation and retrieval of BRC-52/53 certificates

These utilities are used internally by the `Peer` implementation but are also exported for direct use.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module root with re-exports | ~16 |
| `nonce.rs` | Cryptographic nonce creation and verification | ~201 |
| `validation.rs` | Certificate validation, encoding checks, and retrieval | ~972 |

## Key Exports

### Nonce Functions

```rust
pub use nonce::{
    create_nonce,
    verify_nonce,
    validate_nonce_format,
    get_nonce_random,
    NONCE_PROTOCOL,
};
```

### Validation Functions

```rust
pub use validation::{
    validate_certificates,
    validate_certificate,
    validate_certificate_encoding,
    validate_requested_certificate_set,
    get_verifiable_certificates,
    certificates_match_request,
};
```

## Nonce Module

### Nonce Format

Nonces are 32 bytes encoded as base64:
- **First 16 bytes**: Cryptographically secure random data
- **Last 16 bytes**: HMAC of the random data (truncated from 32-byte HMAC)

The HMAC is computed using BRC-42 key derivation with:
- **Protocol**: `"server hmac"` (exported as `NONCE_PROTOCOL`)
- **Security Level**: App
- **Key ID**: base64-encoded random portion

### create_nonce

```rust
pub async fn create_nonce<W: WalletInterface>(
    wallet: &W,
    counterparty: Option<&PublicKey>,
    originator: &str,
) -> Result<String>
```

Creates a cryptographic nonce for authentication sessions.

**Parameters:**
- `wallet` - Wallet implementing `WalletInterface` for HMAC computation
- `counterparty` - Optional counterparty public key (None = self-authentication)
- `originator` - Application originator string (e.g., `"myapp.com"`)

**Returns:** Base64-encoded nonce string (44 characters for 32 bytes)

**Example:**
```rust
use bsv_rs::auth::utils::create_nonce;

let nonce = create_nonce(&wallet, Some(&peer_key), "myapp.com").await?;
// Returns something like: "Y3J5cHRvZ3JhcGhpY2FsbHlfc2VjdXJlX25vbmNl..."
```

### verify_nonce

```rust
pub async fn verify_nonce<W: WalletInterface>(
    nonce: &str,
    wallet: &W,
    counterparty: Option<&PublicKey>,
    originator: &str,
) -> Result<bool>
```

Verifies that a nonce was created by the expected party.

**Parameters:**
- `nonce` - Base64-encoded nonce to verify
- `wallet` - Wallet for HMAC verification
- `counterparty` - Optional counterparty who created the nonce
- `originator` - Application originator string

**Returns:** `true` if valid, `false` if HMAC doesn't match

**Errors:** Returns `Error::InvalidNonce` if nonce is too short (< 32 bytes)

**Example:**
```rust
use bsv_rs::auth::utils::verify_nonce;

let is_valid = verify_nonce(&peer_nonce, &wallet, Some(&peer_key), "myapp.com").await?;
if !is_valid {
    return Err(Error::AuthError("Invalid peer nonce".into()));
}
```

### validate_nonce_format

```rust
pub fn validate_nonce_format(nonce: &str) -> Result<()>
```

Quick format check without cryptographic verification. Validates:
- Valid base64 encoding
- At least 32 bytes when decoded

**Example:**
```rust
use bsv_rs::auth::utils::validate_nonce_format;

// Fast check before expensive verification
validate_nonce_format(&incoming_nonce)?;
```

### get_nonce_random

```rust
pub fn get_nonce_random(nonce: &str) -> Result<Vec<u8>>
```

Extracts the 16-byte random portion from a nonce. Useful for using the nonce as a session identifier.

**Example:**
```rust
use bsv_rs::auth::utils::get_nonce_random;

let random_bytes = get_nonce_random(&session_nonce)?;
let session_id = hex::encode(&random_bytes);
```

### NONCE_PROTOCOL

```rust
pub const NONCE_PROTOCOL: &str = "server hmac";
```

The BRC-42 protocol identifier used for nonce HMAC computation.

## Validation Module

### validate_certificates

```rust
pub async fn validate_certificates<W: WalletInterface>(
    verifier_wallet: &W,
    message: &AuthMessage,
    certificates_requested: Option<&RequestedCertificateSet>,
    originator: &str,
) -> Result<()>
```

Validates all certificates in an authentication message.

**Validation Steps:**
1. Certificate subject matches message sender (`identity_key`)
2. Certificate signature is valid (cryptographic verification)
3. Certifiers are in the trusted set (if `certificates_requested` specifies certifiers)
4. Certificate types match requested types (if specified)
5. Required fields are present in keyring
6. Field decryption succeeds with verifier's wallet

**Parameters:**
- `verifier_wallet` - Wallet for field decryption attempts
- `message` - The `AuthMessage` containing certificates
- `certificates_requested` - Optional `RequestedCertificateSet` with requirements
- `originator` - Application originator

**Errors:**
- `Error::AuthError("Required certificates not provided")` - Certificates requested but none in message
- `Error::AuthError("Certificate subject does not match message sender")` - Subject mismatch
- `Error::AuthError("Certificate signature invalid")` - Signature verification failed
- `Error::AuthError("Certificate from untrusted certifier: {hex}")` - Certifier not in trusted list
- `Error::AuthError("Certificate type not in requested set: {type}")` - Type not requested
- `Error::AuthError("Required field '{name}' not revealed in certificate")` - Missing keyring entry

**Example:**
```rust
use bsv_rs::auth::utils::validate_certificates;

validate_certificates(
    &my_wallet,
    &incoming_message,
    Some(&required_certs),
    "myapp.com"
).await?;
```

### validate_certificate

```rust
pub async fn validate_certificate<W: WalletInterface>(
    verifier_wallet: &W,
    cert: &VerifiableCertificate,
    sender_key: &PublicKey,
    certificates_requested: Option<&RequestedCertificateSet>,
    originator: &str,
) -> Result<()>
```

Validates a single certificate. Called by `validate_certificates` for each certificate, but can be used directly for granular control.

**Example:**
```rust
use bsv_rs::auth::utils::validate_certificate;

for cert in &message.certificates.unwrap_or_default() {
    validate_certificate(
        &wallet,
        cert,
        &message.identity_key,
        Some(&requirements),
        "myapp.com"
    ).await?;
}
```

### get_verifiable_certificates

```rust
pub async fn get_verifiable_certificates<W: WalletInterface>(
    wallet: &W,
    requested: &RequestedCertificateSet,
    verifier_identity_key: &PublicKey,
    originator: &str,
) -> Result<Vec<VerifiableCertificate>>
```

Retrieves certificates from wallet matching a request and creates verifiable versions with keyrings for the specified verifier.

**Process:**
1. Queries wallet via `list_certificates()` with certifiers and types from request
2. For each matching certificate, calls `prove_certificate()` to create keyring
3. Converts wallet certificate format to `VerifiableCertificate` with keyring
4. Skips malformed certificates (invalid type/serial length, invalid keys)

**Parameters:**
- `wallet` - Wallet containing certificates to retrieve
- `requested` - `RequestedCertificateSet` specifying which certificates and fields
- `verifier_identity_key` - Public key of the party who will verify (for keyring creation)
- `originator` - Application originator

**Example:**
```rust
use bsv_rs::auth::utils::get_verifiable_certificates;
use bsv_rs::auth::RequestedCertificateSet;

let mut requested = RequestedCertificateSet::new();
requested.add_certifier(certifier_hex);
requested.add_type(cert_type_base64, vec!["name".into(), "email".into()]);

let certs = get_verifiable_certificates(
    &wallet,
    &requested,
    &verifier_key,
    "myapp.com"
).await?;
```

### certificates_match_request

```rust
pub fn certificates_match_request(
    certs: &[VerifiableCertificate],
    requested: &RequestedCertificateSet,
) -> bool
```

Quick check if certificates satisfy a request without cryptographic verification.

**Checks:**
- Each requested type has a matching certificate
- Matching certificates have trusted certifiers (if certifiers specified)
- Required fields have keyring entries

**Use Case:** Fast pre-check before expensive cryptographic validation.

**Example:**
```rust
use bsv_rs::auth::utils::certificates_match_request;

if !certificates_match_request(&peer_certs, &my_requirements) {
    return Err(Error::AuthError("Certificates don't meet requirements".into()));
}
// Now do full cryptographic validation
validate_certificates(&wallet, &message, Some(&my_requirements), "myapp.com").await?;
```

### validate_certificate_encoding

```rust
pub fn validate_certificate_encoding(
    cert: &Certificate,
) -> Result<()>
```

Validates the structural encoding of a certificate without cryptographic verification. Analogous to the TypeScript SDK's `validationHelpers.ts`.

**Checks:**
- Certificate type is exactly 32 bytes (always valid by construction)
- Serial number is exactly 32 bytes (always valid by construction)
- Subject and certifier are valid compressed public keys (33 bytes, round-trip parse)
- All field names are non-empty and at most 50 bytes (UTF-8)
- If signature is present, it is non-empty and valid DER encoding
- If revocation outpoint is present, it is not the null sentinel (all-zero txid, vout 0)

**Errors:** Returns `Error::CertificateValidationError(String)` describing the first failure found.

**Example:**
```rust
use bsv_rs::auth::utils::validate_certificate_encoding;

let cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier);
validate_certificate_encoding(&cert)?;
```

### validate_requested_certificate_set

```rust
pub fn validate_requested_certificate_set(
    requested: &RequestedCertificateSet,
) -> Result<()>
```

Validates that a `RequestedCertificateSet` is well-formed. Analogous to the TypeScript SDK's validation of certificate-related arguments.

**Checks:**
- At least one type must be specified (empty types = error)
- All certifier entries are valid hex-encoded 33-byte compressed public keys (66 hex chars)
- All type IDs are valid base64 strings that decode to exactly 32 bytes
- All field names within each type are non-empty and at most 50 bytes (UTF-8)
- No certifiers is valid (any certifier accepted); no fields for a type is valid (just checks type exists)

**Errors:** Returns `Error::CertificateValidationError(String)` describing the first failure found.

**Example:**
```rust
use bsv_rs::auth::{RequestedCertificateSet, utils::validate_requested_certificate_set};

let mut req = RequestedCertificateSet::new();
req.add_certifier("02abc...".to_string());
req.add_type("base64_type_id".to_string(), vec!["name".into(), "email".into()]);

validate_requested_certificate_set(&req)?;
```

## Usage Patterns

### Session Nonce Flow

```rust
use bsv_rs::auth::utils::{create_nonce, verify_nonce};

// Initiator creates nonce
let my_nonce = create_nonce(&wallet, None, "myapp.com").await?;

// Send nonce to peer...

// Peer verifies initiator's nonce
let valid = verify_nonce(&initiator_nonce, &wallet, Some(&initiator_key), "myapp.com").await?;

// Peer creates response nonce
let peer_nonce = create_nonce(&wallet, Some(&initiator_key), "myapp.com").await?;
```

### Certificate Validation Flow

```rust
use bsv_rs::auth::utils::{certificates_match_request, validate_certificates};
use bsv_rs::auth::RequestedCertificateSet;

// Define what certificates we need
let mut required = RequestedCertificateSet::new();
required.add_certifier("02abc...".into());
required.add_type("base64_type".into(), vec!["email".into()]);

// Quick check
if let Some(ref certs) = message.certificates {
    if !certificates_match_request(certs, &required) {
        // Request certificates from peer
        peer.request_certificates(required.clone(), Some(&peer_key), None).await?;
    }
}

// Full validation
validate_certificates(&wallet, &message, Some(&required), "myapp.com").await?;
```

### Retrieving Certificates for Peer

```rust
use bsv_rs::auth::utils::get_verifiable_certificates;

// When peer requests certificates
let certs = get_verifiable_certificates(
    &my_wallet,
    &peer_requested,
    &peer_identity_key,
    "myapp.com"
).await?;

// Send certificates in response
peer.send_certificate_response(&peer_key_hex, certs).await?;
```

## Internal Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `NONCE_PROTOCOL` | `"server hmac"` | BRC-42 protocol for HMAC |
| `NONCE_RANDOM_SIZE` | `16` | Random bytes in nonce |
| `NONCE_TOTAL_SIZE` | `32` | Total nonce size (random + HMAC) |

## Error Handling

Both modules use the SDK's unified error types:

| Error | Description |
|-------|-------------|
| `Error::InvalidNonce(String)` | Nonce too short or malformed |
| `Error::AuthError(String)` | Certificate validation failures (runtime) |
| `Error::CertificateValidationError(String)` | Structural encoding / request set validation failures |
| `Error::Base64Error(String)` | Invalid base64 encoding |
| `Error::WalletError(String)` | Wallet operation failures |

## Testing

```bash
# Run utils tests
cargo test --features auth utils

# Run specific test files
cargo test --features auth nonce
cargo test --features auth validation
```

### Test Coverage

**nonce.rs tests (2 tests):**
- `test_validate_nonce_format` - Format validation (valid, too short, invalid base64)
- `test_get_nonce_random` - Random extraction from nonce bytes

**validation.rs tests (28 tests):**

*certificates_match_request:*
- `test_certificates_match_empty_request` - Empty request always matches
- `test_certificates_match_certifier` - Certifier matching
- `test_certificates_dont_match_wrong_certifier` - Wrong certifier rejection
- `test_certificates_dont_match_missing_fields` - Missing keyring fields
- `test_certificates_match_with_keyring` - Full keyring matching

*validate_certificate_encoding:*
- `test_validate_certificate_encoding_valid` - Signed cert with fields passes
- `test_validate_certificate_encoding_no_signature` - Unsigned cert passes
- `test_validate_certificate_encoding_empty_field_name` - Empty field name rejected
- `test_validate_certificate_encoding_long_field_name` - Field name >50 bytes rejected
- `test_validate_certificate_encoding_invalid_der_signature` - Invalid DER rejected
- `test_validate_certificate_encoding_empty_signature` - Empty signature bytes rejected
- `test_validate_certificate_encoding_with_revocation` - Valid revocation outpoint passes
- `test_validate_certificate_encoding_null_revocation_outpoint` - Null sentinel rejected
- `test_validate_certificate_encoding_50_byte_field_name` - Exactly 50 bytes passes
- `test_validate_certificate_encoding_multiple_fields` - Multiple fields pass

*validate_requested_certificate_set:*
- `test_validate_requested_certificate_set_valid` - Well-formed request passes
- `test_validate_requested_certificate_set_empty_types` - No types rejected
- `test_validate_requested_certificate_set_invalid_certifier_hex` - Bad hex rejected
- `test_validate_requested_certificate_set_wrong_length_certifier` - Short certifier rejected
- `test_validate_requested_certificate_set_empty_certifier` - Empty certifier rejected
- `test_validate_requested_certificate_set_invalid_type_base64` - Bad base64 type rejected
- `test_validate_requested_certificate_set_wrong_length_type` - Wrong-length type rejected
- `test_validate_requested_certificate_set_empty_field_name` - Empty field name rejected
- `test_validate_requested_certificate_set_long_field_name` - Long field name rejected
- `test_validate_requested_certificate_set_empty_type_id` - Empty type ID rejected
- `test_validate_requested_certificate_set_no_certifiers_valid` - No certifiers is valid
- `test_validate_requested_certificate_set_no_fields_valid` - No fields is valid
- `test_validate_requested_certificate_set_multiple_types` - Multiple types pass

## Dependencies

- `crate::primitives` - Base64 encoding, `PublicKey`
- `crate::wallet` - `WalletInterface`, HMAC operations, certificate queries
- `crate::auth::certificates` - `VerifiableCertificate`, `Certificate`
- `crate::auth::types` - `AuthMessage`, `RequestedCertificateSet`
- `rand` - Secure random generation

## Related Documentation

- `../CLAUDE.md` - Parent auth module
- `../certificates/CLAUDE.md` - Certificate types
- `../../wallet/CLAUDE.md` - WalletInterface and certificate operations
- `../../primitives/CLAUDE.md` - Cryptographic primitives
