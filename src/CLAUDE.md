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

| Directory | Feature Flag | Description |
|-----------|--------------|-------------|
| `primitives/` | `primitives` | Cryptographic primitives (hash, EC, encoding, AES-256-GCM) |
| `script/` | `script` | Script parsing, execution, and templates (P2PKH, RPuzzle, PushDrop) |
| `transaction/` | `transaction` | Transaction construction, signing, BEEF/MerklePath SPV proofs |
| `wallet/` | `wallet` | BRC-42 key derivation, ProtoWallet, WalletClient |
| `messages/` | `messages` | BRC-77/78 message signing, encryption, and verification |
| `compat/` | `compat` | BIP-39/BIP-32 mnemonic and HD key compatibility |
| `totp/` | `totp` | RFC 6238 Time-based One-Time Passwords for 2FA |
| `auth/` | `auth` | Mutual authentication, certificates, and peer sessions |
| `overlay/` | `overlay` | Overlay network lookup, topic broadcasting, STEAK protocol |
| `storage/` | `storage` | UHRP file storage via overlay network |
| `registry/` | `registry` | Definition registry for baskets, certificates, and protocols |
| `kvstore/` | `kvstore` | Key-value store with global and local implementations |
| `identity/` | `identity` | Identity resolution and contacts management |

## Key Exports

### Convenience Re-exports by Module

The crate root re-exports commonly used types for ergonomic imports:

| Module | Re-exports |
|--------|------------|
| `primitives` | `PrivateKey`, `PublicKey`, `Signature`, `SymmetricKey`, `BigNumber`, `sha256`, `sha256d`, `hash160`, `to_hex`, `from_hex` |
| `script` | `Script`, `ScriptChunk`, `Address`, `LockingScript`, `UnlockingScript` |
| `transaction` | `Transaction`, `TransactionInput`, `TransactionOutput`, `ChangeDistribution` |
| `wallet` | `KeyDeriver`, `KeyDeriverApi`, `CachedKeyDeriver`, `CacheConfig`, `ProtoWallet`, `Protocol`, `Counterparty`, `SecurityLevel` |
| `messages` | `sign`, `verify`, `encrypt`, `decrypt` |
| `compat` | `Mnemonic`, `Language`, `WordCount` |
| `totp` | `Totp`, `TotpAlgorithm`, `TotpOptions`, `TotpValidateOptions` |
| `auth` | `AuthMessage`, `Certificate`, `MasterCertificate`, `VerifiableCertificate`, `MessageType`, `Peer`, `PeerOptions`, `PeerSession`, `RequestedCertificateSet`, `SessionManager`, `SimplifiedFetchTransport`, `Transport` |
| `websocket` | `WebSocketTransport`, `WebSocketTransportOptions` (requires `websocket` feature flag) |
| `overlay` | `LookupAnswer`, `LookupQuestion`, `LookupResolver`, `NetworkPreset`, `Steak`, `TaggedBEEF`, `TopicBroadcaster` |
| `storage` | `get_hash_from_url`, `get_url_for_file`, `is_valid_url`, `DownloadResult`, `StorageDownloader`, `StorageUploader`, `UploadFileResult`, `UploadableFile` |
| `registry` | `BasketDefinitionData`, `BasketQuery`, `BroadcastFailure`, `BroadcastSuccess`, `CertificateDefinitionData`, `CertificateFieldDescriptor`, `CertificateQuery`, `DefinitionData`, `DefinitionType`, `ProtocolDefinitionData`, `ProtocolQuery`, `RegisterDefinitionResult`, `RegistryClient`, `RegistryClientConfig`, `RegistryRecord`, `RevokeDefinitionResult`, `TokenData` |
| `kvstore` | `GlobalKVStore`, `KVStoreConfig`, `KVStoreEntry`, `KVStoreGetOptions`, `KVStoreQuery`, `KVStoreRemoveOptions`, `KVStoreSetOptions`, `KVStoreToken`, `LocalKVStore` |
| `identity` | `Contact`, `ContactsManager`, `ContactsManagerConfig`, `DisplayableIdentity`, `IdentityClient`, `IdentityClientConfig`, `IdentityQuery`, `KnownCertificateType` |

Note: `overlay::Protocol` is a separate type from `wallet::Protocol` and is not re-exported to avoid name collision.

### Error Types (`error.rs`)

The `Error` enum provides unified error handling across all modules using `thiserror`. It implements `Clone`, `PartialEq`, and `Eq` for easy comparison in tests.

**Error categories by feature:**

| Feature | Error Variants |
|---------|----------------|
| (core) | `InvalidKeyLength`, `InvalidDataLength`, `InvalidHex`, `InvalidBase58`, `InvalidBase64`, `CryptoError`, `InvalidSignature`, `InvalidPublicKey`, `InvalidPrivateKey`, `PointAtInfinity`, `DecryptionFailed`, `InvalidNonce`, `InvalidTag`, `InvalidUtf8`, `ReaderUnderflow`, `InvalidChecksum` |
| `script` | `ScriptParseError`, `ScriptExecutionError`, `InvalidOpcode`, `DisabledOpcode`, `StackUnderflow`, `StackOverflow`, `Bip276Error`, `InvalidAddress`, `InvalidAddressLength`, `UnsupportedAddress` |
| `transaction` | `TransactionError`, `MerklePathError`, `BeefError`, `FeeModelError` |
| `wallet` | `WalletError`, `KeyDerivationError`, `ProtocolValidationError`, `InvalidCounterparty` |
| `messages` | `MessageVersionMismatch`, `MessageError`, `MessageRecipientMismatch` |
| `compat` | `InvalidMnemonic`, `InvalidEntropyLength`, `InvalidMnemonicWord`, `InvalidExtendedKey`, `HardenedFromPublic`, `InvalidDerivationPath`, `EciesDecryptionFailed`, `EciesHmacMismatch` |
| `auth` | `AuthError`, `SessionNotFound`, `CertificateValidationError`, `TransportError` |
| `overlay` | `OverlayError`, `NoHostsFound`, `OverlayBroadcastFailed` |
| `registry` | `RegistryError`, `DefinitionNotFound`, `InvalidDefinitionData` |
| `kvstore` | `KvStoreError`, `KvStoreKeyNotFound`, `KvStoreCorruptedState`, `KvStoreEmptyContext`, `KvStoreInvalidKey`, `KvStoreInvalidValue` |
| `identity` | `IdentityError`, `IdentityNotFound`, `ContactNotFound` |

**Result alias**: `pub type Result<T> = std::result::Result<T, Error>;`

## Usage

### Basic Import Pattern

```rust
// Import error types
use bsv_rs::{Error, Result};

// Import primitives directly from crate root
use bsv_rs::{PrivateKey, PublicKey, sha256};

// Or import from module
use bsv_rs::primitives::{PrivateKey, sha256};

// Feature-gated imports
#[cfg(feature = "transaction")]
use bsv_rs::{Transaction, TransactionInput, TransactionOutput};
```

### Quick Start Example

```rust
use bsv_rs::{PrivateKey, sha256};

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
use bsv_rs::{from_hex, Error, Result};

fn parse_key(hex: &str) -> Result<Vec<u8>> {
    from_hex(hex).map_err(|_| Error::InvalidHex(hex.to_string()))
}

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
 ├── primitives (no dependencies)
 ├── script → primitives
 ├── transaction → script
 ├── wallet → transaction
 ├── messages → wallet
 ├── compat → primitives
 ├── totp → primitives
 ├── auth → wallet + messages + tokio
 ├── overlay → wallet + tokio
 ├── storage → overlay
 ├── registry → overlay
 ├── kvstore → overlay
 └── identity → auth + overlay

websocket (opt-in, not in full)
 └── auth transport via tokio-tungstenite
```

**Default features**: `primitives`, `script`

**Optional features**:
- `http` - HTTP clients for ARC broadcaster, WhatsOnChain, WalletClient substrate
- `wasm` - WebAssembly support via `getrandom/js`
- `websocket` - WebSocket auth transport via `tokio-tungstenite` (opt-in, not included in `full`)
- `full` - All modules enabled
- `dhat-profiling` - Memory profiling support for benchmarks

## Adding New Errors

When adding errors for a new module:

1. Add a section comment in `error.rs`
2. Define variants with `#[error("...")]` messages
3. Gate with `#[cfg(feature = "module_name")]` if feature-specific
4. Follow naming pattern: `ModuleSpecificError(String)` or structured variants

```rust
// ===================
// New module errors
// ===================
#[cfg(feature = "new_module")]
#[error("new module error: {0}")]
NewModuleError(String),
```

## Dependencies

```toml
[dependencies]
thiserror = "1.0"
```

## Related Documentation

- `primitives/CLAUDE.md` - Cryptographic primitives module
- `script/CLAUDE.md` - Script module
- `transaction/CLAUDE.md` - Transaction module
- `wallet/CLAUDE.md` - Wallet module
- `messages/CLAUDE.md` - Messages module
- `compat/CLAUDE.md` - Compatibility module
- `totp/CLAUDE.md` - TOTP module
- `auth/CLAUDE.md` - Authentication module
- `overlay/CLAUDE.md` - Overlay network module
- `storage/CLAUDE.md` - Storage module
- `registry/CLAUDE.md` - Registry module
- `kvstore/CLAUDE.md` - KVStore module
- `identity/CLAUDE.md` - Identity module
- `../CLAUDE.md` - Project root documentation
