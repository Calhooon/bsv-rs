# BSV SDK for Rust

A comprehensive Rust SDK for building BSV (Bitcoin SV) blockchain applications.

## Features

- **Primitives**: Cryptographic primitives (SHA-256, RIPEMD-160, secp256k1, AES-GCM)
- **Script**: Bitcoin Script parsing, execution, and templates (P2PKH, RPuzzle) *(coming soon)*
- **Transaction**: Transaction construction, signing, and serialization *(coming soon)*
- **Wallet**: HD wallets, BIP-32/39/44 key derivation *(coming soon)*

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
bsv-sdk = "0.2"
```

Or with specific features:

```toml
[dependencies]
bsv-sdk = { version = "0.2", features = ["primitives", "script"] }
```

## Quick Start

### Cryptographic Primitives

```rust
use bsv_sdk::primitives::{PrivateKey, PublicKey, sha256, hash160};

// Generate a key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Get the address
let address = public_key.to_address();
println!("Address: {}", address);

// Sign a message
let msg_hash = sha256(b"Hello, BSV!");
let signature = private_key.sign(&msg_hash).unwrap();

// Verify
assert!(public_key.verify(&msg_hash, &signature));
```

### Script Operations (Coming Soon)

```rust,ignore
use bsv_sdk::script::{Script, LockingScript, P2PKH};
use bsv_sdk::primitives::PrivateKey;

// Create a P2PKH locking script
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

let p2pkh = P2PKH::new();
let locking_script = p2pkh.lock(&public_key.hash160());

// Parse a script from hex
let script = Script::from_hex("76a914...88ac").unwrap();
println!("ASM: {}", script.to_asm());
```

## Module Overview

### Primitives (`bsv_sdk::primitives`)

| Component | Description |
|-----------|-------------|
| `sha256`, `sha512`, `ripemd160` | Hash functions |
| `sha256d`, `hash160` | Bitcoin-specific composite hashes |
| `PrivateKey`, `PublicKey` | secp256k1 key pairs |
| `Signature` | ECDSA signatures (low-S enforced) |
| `SymmetricKey` | AES-256-GCM encryption |
| `BigNumber` | Arbitrary-precision integers |
| `to_hex`, `from_hex`, `to_base58` | Encoding utilities |

### Script (`bsv_sdk::script`) - Coming Soon

| Component | Description |
|-----------|-------------|
| `Script` | Base script class |
| `LockingScript` | Output locking scripts |
| `UnlockingScript` | Input unlocking scripts |
| `Spend` | Script interpreter/validator |
| `P2PKH` | Pay-to-Public-Key-Hash template |
| `RPuzzle` | R-puzzle template |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `primitives` | Yes | Cryptographic primitives |
| `script` | Yes | Script parsing and execution |
| `transaction` | No | Transaction building (coming soon) |
| `wallet` | No | HD wallet support (coming soon) |
| `wasm` | No | WebAssembly support |
| `full` | No | All features |

## Compatibility

This SDK is designed for cross-platform compatibility with:
- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk)
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk)

## Development

```bash
# Build
cargo build

# Test
cargo test

# Lint
cargo clippy --all-targets --all-features

# Format
cargo fmt

# Docs
cargo doc --open
```

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT license

at your option.
