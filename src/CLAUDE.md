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
| `primitives/` | `primitives` | Complete | Cryptographic primitives (hash, EC, encoding) |
| `script/` | `script` | Complete | Script parsing and execution |
| `transaction/` | `transaction` | Complete | Transaction construction, signing, BEEF format |
| `wallet/` | `wallet` | Complete | BRC-42 key derivation and wallet types |

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
- `ScriptChunk` - Individual opcode or data push
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
 └── wallet
      └── transaction
           └── script
                └── primitives
```

The `script` feature automatically enables `primitives`, and `transaction` enables `script`, etc.

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
```

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
- `../CLAUDE.md` - Project root documentation
