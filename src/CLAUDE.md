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
| `storage/` | `storage` | Complete | UHRP file storage via overlay network |
| `registry/` | `registry` | Complete | Definition registry for baskets, certificates, and protocols |
| `kvstore/` | `kvstore` | Complete | Key-value store with global and local implementations |
| `identity/` | `identity` | Complete | Identity resolution and contacts management |

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

#[cfg(feature = "storage")]
pub mod storage;

#[cfg(feature = "registry")]
pub mod registry;

#[cfg(feature = "kvstore")]
pub mod kvstore;

#[cfg(feature = "identity")]
pub mod identity;
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

**Convenience re-exports** from `storage`:
- `get_hash_from_url` - Extract UHRP hash from a storage URL
- `get_url_for_file` - Generate UHRP URL for file content
- `is_valid_url` - Validate UHRP URL format
- `DownloadResult` - Result of a file download operation
- `StorageDownloader` - Client for downloading files from UHRP storage
- `StorageUploader` - Client for uploading files to UHRP storage
- `UploadFileResult` - Result of a file upload operation
- `UploadableFile` - File prepared for upload to storage

**Convenience re-exports** from `registry`:
- `BasketDefinitionData` - Data for basket definitions
- `BasketQuery` - Query parameters for basket lookups
- `BroadcastFailure` - Information about a failed broadcast
- `BroadcastSuccess` - Information about a successful broadcast
- `CertificateDefinitionData` - Data for certificate definitions
- `CertificateFieldDescriptor` - Descriptor for certificate fields
- `CertificateQuery` - Query parameters for certificate lookups
- `DefinitionData` - Union type for all definition data types
- `DefinitionType` - Discriminator for definition types (basket, certificate, protocol)
- `ProtocolDefinitionData` - Data for protocol definitions
- `ProtocolQuery` - Query parameters for protocol lookups
- `RegisterDefinitionResult` - Result of registering a definition
- `RegistryClient` - Client for interacting with the definition registry
- `RegistryClientConfig` - Configuration for registry client
- `RegistryRecord` - Record stored in the registry
- `RevokeDefinitionResult` - Result of revoking a definition
- `TokenData` - Token data associated with definitions

**Convenience re-exports** from `kvstore`:
- `GlobalKVStore` - Global key-value store backed by overlay network
- `KVStoreConfig` - Configuration for KVStore instances
- `KVStoreEntry` - Entry stored in the key-value store
- `KVStoreGetOptions` - Options for get operations
- `KVStoreQuery` - Query parameters for listing entries
- `KVStoreRemoveOptions` - Options for remove operations
- `KVStoreSetOptions` - Options for set operations
- `KVStoreToken` - Token for KVStore authentication
- `LocalKVStore` - Local in-memory key-value store

**Convenience re-exports** from `identity`:
- `Contact` - Contact information for an identity
- `ContactsManager` - Manager for contact list operations
- `ContactsManagerConfig` - Configuration for contacts manager
- `DisplayableIdentity` - Identity with display-friendly fields
- `IdentityClient` - Client for identity resolution
- `IdentityClientConfig` - Configuration for identity client
- `IdentityQuery` - Query parameters for identity lookups
- `KnownCertificateType` - Well-known certificate types for identity

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

**Registry errors** (requires `registry` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `RegistryError` | `(String)` | General registry error |
| `DefinitionNotFound` | `(String)` | Definition not found in registry |
| `InvalidDefinitionData` | `(String)` | Invalid definition data format |

**KVStore errors** (requires `kvstore` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `KvStoreError` | `(String)` | General kvstore error |
| `KvStoreKeyNotFound` | `(String)` | Key not found in kvstore |
| `KvStoreCorruptedState` | `(String)` | Corrupted kvstore state |
| `KvStoreEmptyContext` | — | Empty context (protocol_id) provided |
| `KvStoreInvalidKey` | — | Invalid key provided (empty) |
| `KvStoreInvalidValue` | — | Invalid value provided (empty) |

**Identity errors** (requires `identity` feature):
| Variant | Fields | Description |
|---------|--------|-------------|
| `IdentityError` | `(String)` | General identity error |
| `IdentityNotFound` | `(String)` | Identity not found |
| `ContactNotFound` | `(String)` | Contact not found |

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
 ├── totp
 │    └── primitives
 ├── auth
 │    └── wallet
 ├── overlay
 │    └── wallet
 ├── storage
 │    └── overlay
 ├── registry
 │    └── overlay
 ├── kvstore
 │    └── overlay
 └── identity
      └── overlay
```

The `script` feature automatically enables `primitives`, `transaction` enables `script`, `wallet` enables `transaction`, and `messages` enables `wallet`. The `compat` and `totp` features only require `primitives`. The `auth` feature requires `wallet`. The `overlay` feature requires `wallet`. The `storage`, `registry`, `kvstore`, and `identity` features all require `overlay`.

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

#[cfg(feature = "storage")]
use bsv_sdk::storage;

#[cfg(feature = "registry")]
use bsv_sdk::registry;

#[cfg(feature = "kvstore")]
use bsv_sdk::kvstore;

#[cfg(feature = "identity")]
use bsv_sdk::identity;
```

Additional optional features:
- **`http`** - Enables HTTP clients for ARC broadcaster, WhatsOnChain chain tracker, and WalletClient substrate
- **`wasm`** - Enables WebAssembly support via `getrandom/js`
- **`full`** - Enables all modules: `primitives`, `script`, `transaction`, `wallet`, `messages`, `compat`, `totp`, `auth`, `overlay`, `storage`, `registry`, `kvstore`, `identity`

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
- `storage/CLAUDE.md` - Storage module documentation
- `registry/CLAUDE.md` - Registry module documentation
- `kvstore/CLAUDE.md` - KVStore module documentation
- `identity/CLAUDE.md` - Identity module documentation
- `../CLAUDE.md` - Project root documentation
