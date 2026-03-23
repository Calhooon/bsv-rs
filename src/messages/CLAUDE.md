# Messages Module
> Peer-to-peer signed and encrypted messaging for BSV

## Overview

This module implements BRC-77 (signed messages) and BRC-78 (encrypted messages) protocols for secure peer-to-peer communication on BSV. Messages can be signed for a specific recipient or for "anyone" to verify. Encryption uses ECDH key derivation with AES-256-GCM symmetric encryption. Both protocols leverage BRC-42 key derivation to create unique derived keys per message, providing forward secrecy at the message level.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 131 | Module root with version constants, public re-exports, and integration tests |
| `signed.rs` | 463 | BRC-77 message signing and verification with comprehensive test suite |
| `encrypted.rs` | 442 | BRC-78 message encryption and decryption with cross-SDK test vectors |

## Key Exports

### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `sign` | `(message: &[u8], signer: &PrivateKey, verifier: Option<&PublicKey>) -> Result<Vec<u8>>` | Sign a message using BRC-77 protocol |
| `verify` | `(message: &[u8], sig: &[u8], recipient: Option<&PrivateKey>) -> Result<bool>` | Verify a BRC-77 signed message |
| `encrypt` | `(message: &[u8], sender: &PrivateKey, recipient: &PublicKey) -> Result<Vec<u8>>` | Encrypt a message using BRC-78 protocol |
| `decrypt` | `(ciphertext: &[u8], recipient: &PrivateKey) -> Result<Vec<u8>>` | Decrypt a BRC-78 encrypted message |

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SIGNED_VERSION` | `[0x42, 0x42, 0x33, 0x01]` | Version bytes for BRC-77 signed messages (`0x42423301`) |
| `ENCRYPTED_VERSION` | `[0x42, 0x42, 0x10, 0x33]` | Version bytes for BRC-78 encrypted messages (`0x42421033`) |

## Wire Formats

### Signed Message Format (BRC-77)

```text
[version: 4 bytes] [sender_pubkey: 33 bytes] [recipient: 1 or 33 bytes] [keyID: 32 bytes] [signature: DER]
```

| Field | Size | Description |
|-------|------|-------------|
| Version | 4 bytes | `0x42423301` identifies BRC-77 format |
| Sender PubKey | 33 bytes | Compressed public key of signer |
| Recipient | 1 or 33 bytes | `0x00` for "anyone", or 33-byte compressed public key |
| Key ID | 32 bytes | Random bytes for BRC-42 invoice number derivation |
| Signature | Variable | DER-encoded ECDSA signature |

### Encrypted Message Format (BRC-78)

```text
[version: 4 bytes] [sender_pubkey: 33 bytes] [recipient_pubkey: 33 bytes] [keyID: 32 bytes] [ciphertext]
```

| Field | Size | Description |
|-------|------|-------------|
| Version | 4 bytes | `0x42421033` identifies BRC-78 format |
| Sender PubKey | 33 bytes | Compressed public key of sender |
| Recipient PubKey | 33 bytes | Compressed public key of intended recipient |
| Key ID | 32 bytes | Random bytes for BRC-42 invoice number derivation |
| Ciphertext | Variable | `[IV: 32 bytes] [encrypted_data] [GCM_tag: 16 bytes]` |

## Key Derivation

Both protocols use BRC-42 key derivation with invoice numbers:

- **Signing**: `"2-message signing-{base64(keyID)}"`
- **Encryption**: `"2-message encryption-{base64(keyID)}"`

The keyID is 32 random bytes, ensuring unique derived keys per message.

### "Anyone" Key

For messages that anyone can verify (signed without a specific recipient), the SDK uses a deterministic "anyone" key accessed via `KeyDeriver::anyone_key()`:
- Private key scalar value: 1
- Public key: Generator point G

## Usage

### Sign for Specific Recipient

```rust
use bsv_rs::primitives::PrivateKey;
use bsv_rs::messages::{sign, verify};

let sender = PrivateKey::random();
let recipient = PrivateKey::random();
let message = b"Hello, BSV!";

// Sign for specific recipient
let signature = sign(message, &sender, Some(&recipient.public_key())).unwrap();

// Verify with recipient's private key
let valid = verify(message, &signature, Some(&recipient)).unwrap();
assert!(valid);
```

### Sign for Anyone

```rust
use bsv_rs::primitives::PrivateKey;
use bsv_rs::messages::{sign, verify};

let sender = PrivateKey::random();
let message = b"Public announcement";

// Sign for anyone to verify
let signature = sign(message, &sender, None).unwrap();

// Anyone can verify without a private key
let valid = verify(message, &signature, None).unwrap();
assert!(valid);
```

### Encrypt and Decrypt

```rust
use bsv_rs::primitives::PrivateKey;
use bsv_rs::messages::{encrypt, decrypt};

let sender = PrivateKey::random();
let recipient = PrivateKey::random();
let plaintext = b"Secret message";

// Encrypt
let ciphertext = encrypt(plaintext, &sender, &recipient.public_key()).unwrap();

// Decrypt
let decrypted = decrypt(&ciphertext, &recipient).unwrap();
assert_eq!(plaintext.to_vec(), decrypted);
```

## Cryptographic Details

### BRC-77 Signing Process

1. Generate a random 32-byte key ID
2. Create invoice number: `"2-message signing-{base64(keyID)}"`
3. Derive signing key using BRC-42: `signer.derive_child(verifier_pubkey, invoice_number)`
4. SHA-256 hash the message
5. Sign the hash with the derived key
6. Serialize to wire format

### BRC-77 Verification Process

1. Parse wire format to extract version, sender, recipient, keyID, and signature
2. Validate version bytes match `SIGNED_VERSION`
3. Determine if recipient-specific or "anyone" message
4. Derive expected signing public key using BRC-42
5. SHA-256 hash the message
6. Verify signature against derived public key

### BRC-78 Encryption Process

1. Generate a random 32-byte key ID
2. Create invoice number: `"2-message encryption-{base64(keyID)}"`
3. Derive sender's child private key: `sender.derive_child(recipient_pubkey, invoice_number)`
4. Derive recipient's child public key: `recipient_pubkey.derive_child(sender, invoice_number)`
5. Compute ECDH shared secret between derived keys
6. Derive symmetric key from shared secret (skip first byte of compressed point)
7. Encrypt with AES-256-GCM (32-byte IV, 16-byte auth tag)
8. Serialize to wire format

### BRC-78 Decryption Process

1. Parse wire format to extract version, sender, recipient, keyID, and ciphertext
2. Validate version bytes match `ENCRYPTED_VERSION`
3. Verify recipient public key matches the decrypting key
4. Re-derive ECDH shared secret using mirrored key derivation
5. Derive symmetric key from shared secret
6. Decrypt with AES-256-GCM (authenticates and decrypts)

## Error Handling

| Error | Description |
|-------|-------------|
| `MessageVersionMismatch { expected, actual }` | Version bytes don't match expected protocol version (includes hex of both) |
| `MessageError(String)` | General message format error (too short, missing recipient key) |
| `MessageRecipientMismatch { expected, actual }` | Provided recipient key doesn't match encrypted/signed recipient (hex public keys) |

### Error Examples

```rust
// Version mismatch (version bytes as hex)
Err(Error::MessageVersionMismatch {
    expected: "42423301".to_string(),
    actual: "01423301".to_string(),
})

// Missing recipient for recipient-specific message
Err(Error::MessageError(
    "this signature can only be verified with knowledge of a specific private key. The associated public key is: 02...".to_string()
))

// Wrong recipient (public keys as hex)
Err(Error::MessageRecipientMismatch {
    expected: "02abc...".to_string(),
    actual: "03def...".to_string(),
})
```

### Signature Verification Behavior

- Tampered messages return `Ok(false)`, not an error
- Format errors (version mismatch, missing recipient) return `Err`
- Wrong recipient returns `Err(MessageRecipientMismatch)`

## Security Properties

- **Confidentiality**: Encrypted messages can only be read by the intended recipient
- **Authenticity**: Both protocols ensure sender identity via key derivation
- **Integrity**: Signed messages detect tampering; encrypted messages use GCM authentication
- **Forward Secrecy**: Random key IDs per message prevent key reuse at the message level
- **Recipient Binding**: Specific-recipient signatures cannot be verified by others

### BRC-78 Security Notes

The encrypted message protocol does NOT provide:
- **Forward secrecy at the identity level** (compromised long-term keys compromise past messages)
- **Replay protection** (messages can be re-sent, though each encryption produces unique ciphertext)
- **Explicit authentication** (no identity binding beyond key possession)

The protocol DOES provide:
- **Per-message key uniqueness**: Random keyID ensures each message uses different derived keys
- **Ciphertext indistinguishability**: Same plaintext encrypted twice produces different ciphertext (random keyID + IV)

## Cross-SDK Compatibility

This implementation is byte-compatible with:
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) - `src/messages/`
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk) - `message/`

Key compatibility points:
- Same version bytes
- Same wire format byte ordering
- Same invoice number format for key derivation
- Same 32-byte IV for AES-GCM (non-standard, but consistent across SDKs)
- Same DER encoding for signatures
- Same compressed public key format (33 bytes)
- Same error message format for version mismatch and recipient mismatch

### Cross-SDK Test Vectors

The test suite includes vectors from other SDK implementations to ensure compatibility:

- **Deterministic key tests**: Use fixed scalar values (sender=15, recipient=21) matching Go/TS SDKs
- **Edge case handling**: Test vector for rare key lengths (leading zeros in BigNumber arrays)
- **Error format tests**: Verify error messages match Go/TS format (hex-encoded version bytes, public keys)

Example cross-SDK test (`encrypted.rs:416-441`):
```rust
// Test vector from TypeScript SDK - handles edge case with rare key lengths
let encrypted: Vec<u8> = vec![66, 66, 16, 51, /* ... */];
let result = decrypt(&encrypted, &recipient);
assert!(result.is_ok());
```

## Dependencies

This module depends on:
- `crate::primitives` - `PrivateKey`, `PublicKey`, `SymmetricKey`, `Signature`, `sha256`, `to_base64`
- `crate::wallet::KeyDeriver` - BRC-42 key derivation and `anyone_key()`
- `crate::error::{Error, Result}` - Unified error types
- `rand` - Random key ID generation
- `hex` - Error message formatting

## Testing

Run tests with:
```bash
cargo test messages
```

The test suite covers:
- Round-trip signing/verification for specific recipients and "anyone"
- Round-trip encryption/decryption
- Version mismatch detection
- Missing recipient key errors
- Wrong recipient key errors
- Message tampering detection
- Empty and large message handling
- Deterministic key derivation (matching Go/TS SDKs)
- Cross-SDK test vectors for edge cases

## Related Documentation

- `../CLAUDE.md` - Source root and error handling
- `../primitives/CLAUDE.md` - Cryptographic primitives (EC, AES-256-GCM)
- `../primitives/ec/CLAUDE.md` - Elliptic curve operations and key derivation
- `../wallet/CLAUDE.md` - Wallet module with BRC-42 KeyDeriver
