# BSV SDK Source Root
> Crate entry point and unified error handling

## Overview

This directory contains the crate root (`lib.rs`) and the shared error types (`error.rs`) for the BSV SDK. It serves as the entry point that declares feature-gated modules and provides convenience re-exports for the most commonly used types across the SDK.

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root with module declarations and re-exports |
| `error.rs` | Unified `Error` enum and `Result` type alias |

## Subdirectories

| Directory | Feature Flag | Status | Description |
|-----------|--------------|--------|-------------|
| `primitives/` | `primitives` | Complete | Cryptographic primitives (hash, EC, encoding, AES-256-GCM) |
| `script/` | `script` | Complete | Script parsing, execution, and templates (P2PKH, RPuzzle, PushDrop) |
| `transaction/` | `transaction` | Complete | Transaction construction, signing, BEEF/MerklePath SPV proofs |
| `wallet/` | `wallet` | Complete | BRC-42 key derivation, ProtoWallet, WalletClient |
| `messages/` | `messages` | Complete | BRC-78 message signing, encryption, and verification |
| `compat/` | `compat` | Complete | BIP-39/BIP-32 mnemonic and HD key compatibility (legacy wallet support) |
| `totp/` | `totp` | Complete | RFC 6238 Time-based One-Time Passwords for 2FA |
| `auth/` | `auth` | Complete | Mutual authentication, certificates, and peer sessions |
| `overlay/` | `overlay` | Complete | Overlay network lookup, topic broadcasting, and STEAK protocol |

## Key Exports

### Crate Root (`lib.rs`)

The crate root provides:

**Module declarations** (feature-gated):
```rust
#[cfg(feature = "primitives")]
pub mod primitives;

#[cfg(feature = "script")]
pub mod script;

#[cfg(feature = "transaction")]
pub mod transaction;

#[cfg(feature = "wallet")]
pub mod wallet;

#[cfg(feature = "messages")]
pub mod messages;

#[cfg(feature = "compat")]
pub mod compat;

#[cfg(feature = "totp")]
pub mod totp;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "overlay")]
pub mod overlay;
```

**Convenience re-exports** from `primitives`:
- `PrivateKey` - Secp256k1 private key
- `PublicKey` - Secp256k1 public key
- `Signature` - ECDSA signature
- `SymmetricKey` - AES symmetric encryption key
- `BigNumber` - Arbitrary precision integer
- `sha256` - SHA-256 hash function
- `sha256d` - Double SHA-256 (SHA-256 of SHA-256)
- `hash160` - RIPEMD-160 of SHA-256
- `to_hex` - Convert bytes to hex string
- `from_hex` - Parse hex string to bytes

**Convenience re-exports** from `script`:
- `Script` - Bitcoin Script representation
- `ScriptChunk` - Individual script element (opcode or data push)
- `LockingScript` - Output script (scriptPubKey)
- `UnlockingScript` - Input script (scriptSig)

**Convenience re-exports** from `transaction`:
- `Transaction` - Bitcoin transaction with inputs, outputs, and metadata
- `TransactionInput` - Transaction input referencing a previous output
- `TransactionOutput` - Transaction output with value and locking script
- `ChangeDistribution` - Strategy for distributing change across outputs

**Convenience re-exports** from `wallet`:
- `KeyDeriver` - BRC-42 key derivation implementation
- `KeyDeriverApi` - Trait for key derivation operations
- `CachedKeyDeriver` - Key deriver with LRU caching for performance
- `CacheConfig` - Configuration for key derivation cache
- `ProtoWallet` - Protocol-aware wallet wrapper
- `Protocol` - BRC-43 protocol identifier (security level, protocol ID, key ID)
- `Counterparty` - Key derivation counterparty (self or public key)
- `SecurityLevel` - Security level for key derivation (0, 1, or 2)

**Convenience re-exports** from `messages`:
- `sign` - Sign a message with a private key
- `verify` - Verify a signed message
- `encrypt` - Encrypt a message for a recipient
- `decrypt` - Decrypt a message from a sender

**Convenience re-exports** from `compat`:
- `Mnemonic` - BIP-39 mnemonic phrase for seed generation
- `Language` - Wordlist language for mnemonic phrases
- `WordCount` - Number of words in mnemonic (12, 15, 18, 21, or 24)

**Convenience re-exports** from `totp`:
- `Totp` - TOTP generation and validation
- `TotpAlgorithm` - HMAC algorithm selection (Sha1, Sha256, Sha512)
- `TotpOptions` - Configuration for TOTP generation
- `TotpValidateOptions` - Configuration for TOTP validation with skew

**Convenience re-exports** from `auth`:
- `AuthMessage` - Authenticated message for peer communication
- `Certificate` - Identity certificate for authentication
- `MasterCertificate` - Master certificate for issuing other certificates
- `VerifiableCertificate` - Certificate with verification capabilities
- `MessageType` - Type discriminator for auth protocol messages
- `Peer` - Authenticated peer connection
- `PeerOptions` - Configuration options for peer creation
- `PeerSession` - Active session with an authenticated peer
- `RequestedCertificateSet` - Set of certificates requested during handshake
- `SessionManager` - Manager for multiple peer sessions
- `SimplifiedFetchTransport` - HTTP-based transport implementation
- `Transport` - Trait for message transport abstraction

**Convenience re-exports** from `overlay`:
- `LookupAnswer` - Response from overlay network lookup
- `LookupQuestion` - Query for overlay network lookup
- `LookupResolver` - Resolver for overlay network queries
- `NetworkPreset` - Predefined network configurations (mainnet, testnet)
- `Steak` - STEAK (Simplified Transaction Envelope with Attestation Keys) protocol
- `TaggedBEEF` - BEEF transaction with topic tags for overlay routing
- `TopicBroadcaster` - Broadcaster for topic-based overlay networks

Note: `overlay::Protocol` is a separate type from `wallet::Protocol` and is not re-exported to avoid name collision.

### Error Types (`error.rs`)

The `Error` enum provides unified error handling across all modules. It uses `thiserror` for derive-based error messages and implements `Clone`, `PartialEq`, and `Eq` for easy comparison in tests:

**Primitives errors** (always available):
| Variant | Fields | Description |
|---------|--------|-------------|
| `InvalidKeyLength` | `{ expected, actual }` | Wrong key size for cryptographic operation |
| `InvalidDataLength` | `{ expected, actual }` | Wrong data size for operation |
| `InvalidHex` | `(String)` | Malformed hex string |
| `InvalidBase58` | `(String)` | Malformed Base58 string |
| `InvalidBase64` | `(String)` | Malformed Base64 string |
| `CryptoError` | `(String)` | Generic cryptographic failure |
| `InvalidSignature` | `(String)` | Signature verification failed |
| `InvalidPublicKey` | `(String)` | Malformed or invalid public key |
| `InvalidPrivateKey` | `(String)` | Malformed or invalid private key |
| `PointAtInfinity` | — | EC point at infinity (invalid) |
| `DecryptionFailed` | — | Decryption operation failed |
| `InvalidNonce` | `(String)` | Invalid nonce for encryption |
| `InvalidTag` | — | Invalid authentication tag (AEAD) |
| `InvalidUtf8` | `(String)` | Invalid UTF-8 sequence |
| `ReaderUnderflow` | `{ needed, available }` | Not enough bytes to read |
| `InvalidChecksum` | — | Checksum validation failed |

**Script errors** (requires `script` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `ScriptParseError` | `(String)` | Failed to parse script |
| `ScriptExecutionError` | `(String)` | Script execution failed |
| `InvalidOpcode` | `(u8)` | Unknown opcode value (displays as hex) |
| `DisabledOpcode` | `(u8)` | Opcode is disabled (displays as hex) |
| `StackUnderflow` | — | Stack has insufficient items |
| `StackOverflow` | — | Stack exceeded limit |

**Transaction errors** (requires `transaction` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `TransactionError` | `(String)` | General transaction-related error |
| `MerklePathError` | `(String)` | Invalid or malformed Merkle path |
| `BeefError` | `(String)` | BEEF format parsing or validation error |
| `FeeModelError` | `(String)` | Fee calculation or model error |

**Wallet errors** (requires `wallet` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `WalletError` | `(String)` | General wallet-related error |
| `KeyDerivationError` | `(String)` | BRC-42 key derivation failed |
| `ProtocolValidationError` | `(String)` | Invalid BRC-43 protocol specification |
| `InvalidCounterparty` | `(String)` | Invalid counterparty for key derivation |

**Messages errors** (requires `messages` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `MessageVersionMismatch` | `{ expected, actual }` | Message version does not match expected |
| `MessageError` | `(String)` | General message-related error |
| `MessageRecipientMismatch` | `{ expected, actual }` | Message recipient does not match expected |

**Compat errors** (requires `compat` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `InvalidMnemonic` | `(String)` | Invalid BIP-39 mnemonic phrase |
| `InvalidEntropyLength` | `{ expected, actual }` | Wrong entropy length for mnemonic generation |
| `InvalidMnemonicWord` | `(String)` | Unknown word in mnemonic phrase |
| `InvalidExtendedKey` | `(String)` | Invalid BIP-32 extended key format |
| `HardenedFromPublic` | — | Cannot derive hardened child from public key |
| `InvalidDerivationPath` | `(String)` | Invalid BIP-32 derivation path |
| `EciesDecryptionFailed` | `(String)` | ECIES decryption operation failed |
| `EciesHmacMismatch` | — | ECIES HMAC verification failed |

**Auth errors** (requires `auth` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `AuthError` | `(String)` | General authentication error |
| `SessionNotFound` | `(String)` | Requested session does not exist |
| `CertificateValidationError` | `(String)` | Certificate validation failed |
| `TransportError` | `(String)` | Transport layer error (network, encoding) |

**Overlay errors** (requires `overlay` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `OverlayError` | `(String)` | General overlay network error |
| `NoHostsFound` | `(String)` | No hosts found for the specified service |
| `OverlayBroadcastFailed` | `(String)` | Failed to broadcast to overlay network |

**Result alias**:
```rust
pub type Result<T> = std::result::Result<T, Error>;
```

## Usage

### Basic Import Pattern

```rust
// Import error types
use bsv_sdk::{Error, Result};

// Import primitives directly from crate root
use bsv_sdk::{PrivateKey, PublicKey, sha256};

// Or import from module
use bsv_sdk::primitives::{PrivateKey, sha256};

// Import script types
use bsv_sdk::{Script, LockingScript};

// Import transaction types (requires feature)
#[cfg(feature = "transaction")]
use bsv_sdk::{Transaction, TransactionInput, TransactionOutput};
```

### Quick Start Example

```rust
use bsv_sdk::{PrivateKey, sha256};

// Generate a key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Hash some data
let hash = sha256(b"Hello, BSV!");

// Sign a message
let signature = private_key.sign(&hash).unwrap();
assert!(public_key.verify(&hash, &signature));
```

### Error Handling

```rust
use bsv_sdk::{from_hex, Error, Result};

fn parse_key(hex: &str) -> Result<Vec<u8>> {
    from_hex(hex).map_err(|_| Error::InvalidHex(hex.to_string()))
}

// Match on specific error variants
match result {
    Ok(data) => println!("Success"),
    Err(Error::InvalidHex(s)) => println!("Bad hex: {}", s),
    Err(Error::InvalidKeyLength { expected, actual }) => {
        println!("Expected {} bytes, got {}", expected, actual);
    }
    Err(e) => println!("Other error: {}", e),
}
```

## Feature Flag Architecture

Features follow a dependency hierarchy:

```
full
 ├── wallet
 │    └── transaction
 │         └── script
 │              └── primitives
 ├── messages
 │    └── wallet
 ├── compat
 │    └── primitives
 ├── auth
 │    └── wallet
 └── overlay
      └── transaction
```

The `script` feature automatically enables `primitives`, `transaction` enables `script`, `wallet` enables `transaction`, and `messages` enables `wallet`. The `compat` and `totp` features only require `primitives`. The `auth` feature requires `wallet`, and `overlay` requires `transaction`.

Default features include `primitives` and `script`:
```rust
// These are available by default
use bsv_sdk::primitives;
use bsv_sdk::script;

// These require explicit feature flags
#[cfg(feature = "transaction")]
use bsv_sdk::transaction;

#[cfg(feature = "wallet")]
use bsv_sdk::wallet;

#[cfg(feature = "messages")]
use bsv_sdk::messages;

#[cfg(feature = "compat")]
use bsv_sdk::compat;

#[cfg(feature = "totp")]
use bsv_sdk::totp;

#[cfg(feature = "auth")]
use bsv_sdk::auth;

#[cfg(feature = "overlay")]
use bsv_sdk::overlay;
```

Additional optional features:
- **`http`** - Enables HTTP clients for ARC broadcaster, WhatsOnChain chain tracker, and WalletClient substrate
- **`wasm`** - Enables WebAssembly support via `getrandom/js`
- **`full`** - Enables all modules: `primitives`, `script`, `transaction`, `wallet`, `messages`, `compat`, `totp`, `auth`, `overlay`

## Adding New Errors

When adding errors for a new module:

1. Add a section comment in `error.rs`
2. Define variants with `#[error("...")]` messages
3. Gate with `#[cfg(feature = "module_name")]` if feature-specific
4. Follow the existing naming pattern: `ModuleSpecificError(String)` or structured variants

Example:
```rust
// ===================
// New module errors
// ===================
#[cfg(feature = "new_module")]
#[error("new module error: {0}")]
NewModuleError(String),
```

## Dependencies

The `error.rs` module uses `thiserror` for ergonomic error definitions:

```toml
[dependencies]
thiserror = "1.0"
```

## Related Documentation

- `primitives/CLAUDE.md` - Cryptographic primitives module
- `primitives/ec/CLAUDE.md` - Elliptic curve submodule
- `script/CLAUDE.md` - Script module documentation
- `transaction/CLAUDE.md` - Transaction module documentation
- `wallet/CLAUDE.md` - Wallet module documentation
- `messages/CLAUDE.md` - Messages module documentation
- `compat/CLAUDE.md` - Compatibility module documentation
- `totp/CLAUDE.md` - TOTP module documentation
- `auth/CLAUDE.md` - Authentication module documentation
- `overlay/CLAUDE.md` - Overlay network module documentation
- `../CLAUDE.md` - Project root documentation
